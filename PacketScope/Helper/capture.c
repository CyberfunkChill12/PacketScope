// packetscope-capture — bundled capture helper for PacketScope.
// Opens BPF with elevated privileges, then drops to the invoking user's
// UID/GID/groups before creating any output files. Passive capture only.
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#define MAX_BYTES_LIMIT 104857600LL
static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void json_escape(FILE *out, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"': fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (*p < 0x20) fprintf(out, "\\u%04x", *p);
                else fputc(*p, out);
        }
    }
}

static int list_interfaces(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL;
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    printf("[");
    int first = 1;
    for (pcap_if_t *d = devs; d; d = d->next) {
        if (!first) printf(",");
        first = 0;
        printf("{\"name\":\"");
        json_escape(stdout, d->name ? d->name : "");
        printf("\",\"description\":\"");
        json_escape(stdout, d->description ? d->description : "");
        printf("\"}");
    }
    printf("]\n");
    pcap_freealldevs(devs);
    return 0;
}

static int valid_interface(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n >= 128) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.' || c == ':' || c == '-')) return 0;
        if (c == ',') return 0;
    }
    return 1;
}

static long long parse_ll(const char *s, int *ok) {
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || !end || *end != '\0') { *ok = 0; return 0; }
    *ok = 1;
    return v;
}

static double monotonic_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// Write status.json atomically inside the (already validated) session dir fd.
static int write_status(int dirfd, const char *state, long long packets, long long bytes,
                        double elapsed, long long dropped, const char *message) {
    char tmpname[64];
    snprintf(tmpname, sizeof(tmpname), "status.json.tmp.%ld", (long)getpid());
    // Remove a stale temp from a previous publish, if any.
    unlinkat(dirfd, tmpname, 0);
    int fd = openat(dirfd, tmpname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlinkat(dirfd, tmpname, 0); return -1; }
    fprintf(f, "{\"state\":\"%s\",\"packets\":%lld,\"bytes\":%lld,\"elapsed\":%.3f,\"dropped\":%lld,\"message\":\"",
            state, packets, bytes, elapsed, dropped);
    json_escape(f, message ? message : "");
    fprintf(f, "\"}\n");
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    if (renameat(dirfd, tmpname, dirfd, "status.json") != 0) { unlinkat(dirfd, tmpname, 0); return -1; }
    return 0;
}

static void log_line(int dirfd, const char *msg) {
    int fd = openat(dirfd, "capture.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    dprintf(fd, "%s\n", msg);
    close(fd);
}

// Stop request is honoured only when it is a regular file owned by the user, not a symlink.
static int stop_requested(int dirfd, uid_t uid) {
    struct stat st;
    if (fstatat(dirfd, "stop.request", &st, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) return 0;
    if (st.st_uid != uid || st.st_nlink < 1) return 0;
    return 1;
}

typedef int (*want_pktap_fn)(pcap_t *, int);

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--interfaces") == 0) {
        if (argc != 2) { fprintf(stderr, "usage: --interfaces takes no extra arguments\n"); return 2; }
        return list_interfaces();
    }

    const char *iface = NULL, *dir = NULL;
    long long uid_ll = -1, gid_ll = -1, duration = -1, maxbytes = -1, watchpid = -1, attribution = -1;
    unsigned seen = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        unsigned bit; const char **sp = NULL; long long *lp = NULL;
        if (strcmp(a, "--interface") == 0) { bit = 1; sp = &iface; }
        else if (strcmp(a, "--directory") == 0) { bit = 2; sp = &dir; }
        else if (strcmp(a, "--uid") == 0) { bit = 4; lp = &uid_ll; }
        else if (strcmp(a, "--gid") == 0) { bit = 8; lp = &gid_ll; }
        else if (strcmp(a, "--duration") == 0) { bit = 16; lp = &duration; }
        else if (strcmp(a, "--max-bytes") == 0) { bit = 32; lp = &maxbytes; }
        else if (strcmp(a, "--watch-pid") == 0) { bit = 64; lp = &watchpid; }
        else if (strcmp(a, "--attribution") == 0) { bit = 128; lp = &attribution; }
        else { fprintf(stderr, "unknown option: %s\n", a); return 2; }
        if (seen & bit) { fprintf(stderr, "repeated option: %s\n", a); return 2; }
        seen |= bit;
        if (i + 1 >= argc) { fprintf(stderr, "missing value for %s\n", a); return 2; }
        const char *v = argv[++i];
        if (sp) { *sp = v; }
        else {
            int ok = 0;
            long long parsed = parse_ll(v, &ok);
            if (!ok) { fprintf(stderr, "invalid numeric value for %s: %s\n", a, v); return 2; }
            *lp = parsed;
        }
    }
    if (seen != 255) { fprintf(stderr, "all of --interface --directory --uid --gid --duration --max-bytes --watch-pid --attribution are required\n"); return 2; }
    if (!valid_interface(iface)) { fprintf(stderr, "invalid interface name\n"); return 2; }
    if (uid_ll <= 0 || uid_ll > 60000) { fprintf(stderr, "invalid uid\n"); return 2; }
    if (gid_ll <= 0 || gid_ll > 60000) { fprintf(stderr, "invalid gid\n"); return 2; }
    if (duration < 1 || duration > 900) { fprintf(stderr, "duration must be 1..900 seconds\n"); return 2; }
    if (maxbytes < 1024 || maxbytes > MAX_BYTES_LIMIT) { fprintf(stderr, "max-bytes out of range\n"); return 2; }
    if (watchpid <= 1) { fprintf(stderr, "invalid watch pid\n"); return 2; }
    if (attribution != 0 && attribution != 1) { fprintf(stderr, "attribution must be 0 or 1\n"); return 2; }

    uid_t uid = (uid_t)uid_ll;
    gid_t gid = (gid_t)gid_ll;
    struct passwd *pw = getpwuid(uid);
    if (!pw) { fprintf(stderr, "unknown uid\n"); return 2; }
    if (pw->pw_gid != gid) { fprintf(stderr, "gid is not the target user's primary group\n"); return 2; }

    // Validate session directory: user-owned, mode 0700, not a symlink.
    struct stat dst;
    if (lstat(dir, &dst) != 0) { fprintf(stderr, "session directory: %s\n", strerror(errno)); return 2; }
    if (S_ISLNK(dst.st_mode) || !S_ISDIR(dst.st_mode)) { fprintf(stderr, "session directory is a symlink or not a directory\n"); return 2; }
    if (dst.st_uid != uid) { fprintf(stderr, "session directory is not owned by the target user\n"); return 2; }
    if ((dst.st_mode & 0777) != 0700) { fprintf(stderr, "session directory must have mode 0700\n"); return 2; }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    // --- Open/configure BPF while still privileged. ---
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int attribution_active = 0;
    char source[256];
    const char *fail_message = NULL;

    if (attribution) {
        snprintf(source, sizeof(source), "pktap,%s", iface);
        handle = pcap_create(source, errbuf);
        if (handle) {
            pcap_set_snaplen(handle, 65535);
            pcap_set_promisc(handle, 0);
            pcap_set_timeout(handle, 100);
            pcap_set_immediate_mode(handle, 1);
            pcap_set_buffer_size(handle, 4 * 1024 * 1024);
            want_pktap_fn want = (want_pktap_fn)dlsym(RTLD_DEFAULT, "pcap_set_want_pktap");
            if (!want || want(handle, 1) != 0) { pcap_close(handle); handle = NULL; }
        }
        if (handle) {
            if (pcap_activate(handle) != 0) { pcap_close(handle); handle = NULL; }
            else {
                int lt = pcap_datalink(handle);
                // On macOS DLT_PKTAP is 149; saved files use LINKTYPE 258 but the live
                // link type must be the PKTAP value, not an ordinary interface type.
                if (lt == 149 || lt == 258) attribution_active = 1;
                else { pcap_close(handle); handle = NULL; }
            }
        }
        if (!handle) fail_message = "PKTAP attribution unavailable; continuing without process attribution (ownership will be Unknown).";
    }
    if (!handle) {
        handle = pcap_create(iface, errbuf);
        if (handle) {
            pcap_set_snaplen(handle, 65535);
            pcap_set_promisc(handle, 0);
            pcap_set_timeout(handle, 100);
            pcap_set_immediate_mode(handle, 1);
            pcap_set_buffer_size(handle, 4 * 1024 * 1024);
            if (pcap_activate(handle) != 0) { pcap_close(handle); handle = NULL; }
        }
    }

    // --- Drop privileges before creating any output files. ---
    if (initgroups(pw->pw_name, gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
        fprintf(stderr, "failed to drop privileges: %s\n", strerror(errno));
        if (handle) pcap_close(handle);
        return 1;
    }
    if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
        fprintf(stderr, "privilege drop verification failed\n");
        if (handle) pcap_close(handle);
        return 1;
    }

    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) { fprintf(stderr, "open session directory: %s\n", strerror(errno)); if (handle) pcap_close(handle); return 1; }

    if (!handle) {
        write_status(dirfd, "failed", 0, 0, 0, 0, "Could not open the selected interface for capture. Check that it exists and is up.");
        log_line(dirfd, "capture open failed");
        close(dirfd);
        return 1;
    }
    if (pcap_setnonblock(handle, 1, errbuf) != 0) {
        write_status(dirfd, "failed", 0, 0, 0, 0, "Could not configure nonblocking capture.");
        pcap_close(handle); close(dirfd);
        return 1;
    }

    int pcapfd = openat(dirfd, "traffic.pcap", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (pcapfd < 0) {
        write_status(dirfd, "failed", 0, 0, 0, 0, "Could not create the capture file in the session directory.");
        pcap_close(handle); close(dirfd);
        return 1;
    }
    FILE *pcapfile = fdopen(pcapfd, "w");
    if (!pcapfile) { close(pcapfd); pcap_close(handle); close(dirfd); return 1; }
    pcap_dumper_t *dumper = pcap_dump_fopen(handle, pcapfile);
    if (!dumper) {
        fclose(pcapfile);
        write_status(dirfd, "failed", 0, 0, 0, 0, "Could not open the capture file for writing.");
        pcap_close(handle); close(dirfd);
        return 1;
    }

    char startmsg[512];
    snprintf(startmsg, sizeof(startmsg), "%s on %s (attribution %s)",
             attribution_active ? "Capturing with PKTAP process attribution" : "Capturing without process attribution",
             iface, attribution_active ? "on" : "off");
    if (fail_message) log_line(dirfd, fail_message);
    log_line(dirfd, startmsg);
    write_status(dirfd, "capturing", 0, 0, 0, 0, attribution_active ? "" : (fail_message ? fail_message : "Process attribution is off; ownership will be Unknown."));

    long long packets = 0, bytes = 0; // captured packet bytes, excluding file headers
    long long filebytes = 24;         // PCAP global header
    double start = monotonic_now();
    double last_publish = 0;
    const char *endstate = "complete";
    char endmsg[256] = "";
    int selectable = pcap_get_selectable_fd(handle);

    while (!g_stop) {
        double elapsed = monotonic_now() - start;
        if (elapsed >= (double)duration) { snprintf(endmsg, sizeof(endmsg), "Time limit reached."); break; }
        if (filebytes >= maxbytes) { snprintf(endmsg, sizeof(endmsg), "Size limit reached."); break; }
        if (stop_requested(dirfd, uid)) { snprintf(endmsg, sizeof(endmsg), "Stopped by user."); break; }
        if (kill((pid_t)watchpid, 0) != 0 && errno == ESRCH) { snprintf(endmsg, sizeof(endmsg), "PacketScope quit; capture stopped."); break; }

        struct pcap_pkthdr *hdr = NULL;
        const u_char *pkt = NULL;
        int rc = pcap_next_ex(handle, &hdr, &pkt);
        if (rc == 1 && hdr && pkt) {
            long long record = 16LL + (long long)hdr->caplen;
            if (filebytes + record > maxbytes) { snprintf(endmsg, sizeof(endmsg), "Size limit reached."); break; }
            hdr->ts.tv_sec = hdr->ts.tv_sec; // recorded as captured
            pcap_dump((u_char *)dumper, hdr, pkt);
            filebytes += record;
            bytes += (long long)hdr->caplen;
            packets++;
        } else if (rc == 0) {
            // timeout: brief wait on the selectable fd to avoid spinning
            if (selectable >= 0) {
                fd_set rf; FD_ZERO(&rf); FD_SET(selectable, &rf);
                struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 50000;
                select(selectable + 1, &rf, NULL, NULL, &tv);
            } else {
                struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 50000000;
                nanosleep(&ts, NULL);
            }
        } else if (rc == -1) {
            endstate = "failed";
            snprintf(endmsg, sizeof(endmsg), "Capture error: %s", pcap_geterr(handle));
            break;
        }
        double now = monotonic_now();
        if (now - last_publish >= 1.0) {
            last_publish = now;
            write_status(dirfd, "capturing", packets, bytes, now - start, 0,
                         attribution_active ? "" : "Process attribution is off; ownership will be Unknown.");
        }
    }

    // Flush and close the PCAP before publishing terminal status.
    pcap_dump_flush(dumper);
    struct pcap_stat stats;
    long long dropped = 0;
    if (pcap_stats(handle, &stats) == 0) dropped = (long long)stats.ps_drop;
    pcap_dump_close(dumper); // also closes the FILE*
    pcap_close(handle);
    write_status(dirfd, endstate, packets, bytes, monotonic_now() - start, dropped, endmsg);
    char donemsg[256];
    snprintf(donemsg, sizeof(donemsg), "finished state=%s packets=%lld bytes=%lld dropped=%lld %s", endstate, packets, bytes, dropped, endmsg);
    log_line(dirfd, donemsg);
    close(dirfd);
    return strcmp(endstate, "failed") == 0 ? 1 : 0;
}
