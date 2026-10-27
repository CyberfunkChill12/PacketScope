using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;

namespace PacketScope.Windows;

// Minimal libpcap interop against Npcap's wpcap.dll — no third-party packages.
// Live capture requires Npcap (https://npcap.com) to be installed; importing
// and analyzing capture files works without it.

public static class PcapNative
{
    public const string Dll = "wpcap.dll";

    [StructLayout(LayoutKind.Sequential)]
    public struct Timeval { public int TvSec; public int TvUsec; }

    [StructLayout(LayoutKind.Sequential)]
    public struct Pkthdr
    {
        public Timeval Ts;
        public uint Caplen;
        public uint Len;
    }

    public delegate void PacketHandler(IntPtr user, IntPtr header, IntPtr packet);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_freealldevs(IntPtr alldevs);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int toMs, StringBuilder errbuf);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr pcap_dump_open(IntPtr pcap, string filename);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_dump(IntPtr dumper, ref Pkthdr header, IntPtr packet);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_dump_close(IntPtr dumper);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_close(IntPtr pcap);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_loop(IntPtr pcap, int count, PacketHandler callback, IntPtr user);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_breakloop(IntPtr pcap);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_stats(IntPtr pcap, ref PcapStat stats);

    [StructLayout(LayoutKind.Sequential)]
    public struct PcapStat { public uint Recv; public uint Drop; public uint IfDrop; }

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapIf
    {
        public IntPtr Next;
        public IntPtr Name;
        public IntPtr Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    public static bool IsAvailable
    {
        get
        {
            try { _ = pcap_findalldevs(ref UnsafeNull, new StringBuilder(256)); return true; }
            catch { return false; }
        }
    }
    private static IntPtr UnsafeNull = IntPtr.Zero;

    public static List<(string Name, string Description)> ListDevices()
    {
        var devices = new List<(string, string)>();
        IntPtr all = IntPtr.Zero;
        var err = new StringBuilder(256);
        if (pcap_findalldevs(ref all, err) != 0 || all == IntPtr.Zero) return devices;
        try
        {
            IntPtr current = all;
            while (current != IntPtr.Zero)
            {
                var iface = Marshal.PtrToStructure<PcapIf>(current);
                string name = iface.Name != IntPtr.Zero ? Marshal.PtrToStringAnsi(iface.Name) ?? "" : "";
                string desc = iface.Description != IntPtr.Zero ? Marshal.PtrToStringAnsi(iface.Description) ?? "" : "";
                if (name.Length > 0) devices.Add((name, desc));
                current = iface.Next;
            }
        }
        finally { pcap_freealldevs(all); }
        return devices;
    }
}

// Process attribution on Windows has no PKTAP. Instead we snapshot the TCP/UDP
// connection tables while capturing and attribute packets by endpoint match.
// This is labeled approximate in the UI: a shared or reused socket can differ.
public static class ProcessMap
{
    private const int AfInet = 2;
    private enum TcpTableClass { OwnerPidAll = 5 }
    private enum UdpTableClass { OwnerPid = 1 }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPid
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UdpRowOwnerPid { public uint LocalAddr, LocalPort, OwningPid; }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int ipVersion, TcpTableClass tableClass, uint reserved);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int ipVersion, UdpTableClass tableClass, uint reserved);

    public static Dictionary<string, (int Pid, string Name)> Snapshot()
    {
        var map = new Dictionary<string, (int, string)>();
        var nameCache = new Dictionary<int, string>();
        string NameFor(uint pid)
        {
            if (nameCache.TryGetValue((int)pid, out var cached)) return cached;
            string name = "Unknown";
            try { name = Process.GetProcessById((int)pid).ProcessName; } catch { /* process exited */ }
            nameCache[(int)pid] = name;
            return name;
        }
        try
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableClass.OwnerPidAll, 0);
            if (size > 0)
            {
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableClass.OwnerPidAll, 0) == 0)
                    {
                        int count = Marshal.ReadInt32(buffer);
                        int rowSize = Marshal.SizeOf<TcpRowOwnerPid>();
                        for (int i = 0; i < count; i++)
                        {
                            var row = Marshal.PtrToStructure<TcpRowOwnerPid>(buffer + 4 + i * rowSize);
                            string local = new System.Net.IPAddress(row.LocalAddr).ToString();
                            string remote = new System.Net.IPAddress(row.RemoteAddr).ToString();
                            int localPort = ((int)row.LocalPort >> 8 & 0xFF) | ((int)row.LocalPort << 8 & 0xFF00);
                            int remotePort = ((int)row.RemotePort >> 8 & 0xFF) | ((int)row.RemotePort << 8 & 0xFF00);
                            map[$"{local}:{localPort}|{remote}:{remotePort}"] = ((int)row.OwningPid, NameFor(row.OwningPid));
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }
        catch { /* attribution is best-effort */ }
        return map;
    }
}

public sealed class CaptureService
{
    private IntPtr _pcap = IntPtr.Zero;
    private IntPtr _dumper = IntPtr.Zero;
    private Thread? _thread;
    private PcapNative.PacketHandler? _handler;
    public bool Running { get; private set; }
    public long Packets { get; private set; }
    public long Bytes { get; private set; }
    public long Dropped { get; private set; }
    public string? Error { get; private set; }

    public void Start(string device, string pcapPath, int durationSec)
    {
        if (!PcapNative.IsAvailable)
            throw new InvalidOperationException("Npcap was not found. Install Npcap from npcap.com (free) to capture live traffic, or import an existing capture file instead.");
        var err = new StringBuilder(256);
        _pcap = PcapNative.pcap_open_live(device, 65535, 0, 250, err);
        if (_pcap == IntPtr.Zero)
            throw new InvalidOperationException($"Could not open {device} for capture: {err}. Try running PacketScope as administrator, and check that Npcap is installed.");
        _dumper = PcapNative.pcap_dump_open(_pcap, pcapPath);
        if (_dumper == IntPtr.Zero)
        {
            PcapNative.pcap_close(_pcap);
            _pcap = IntPtr.Zero;
            throw new InvalidOperationException("Could not create the capture file in the session folder.");
        }
        Running = true;
        Error = null;
        var started = DateTimeOffset.Now;
        _handler = (user, header, packet) =>
        {
            var hdr = Marshal.PtrToStructure<PcapNative.Pkthdr>(header);
            PcapNative.pcap_dump(_dumper, ref hdr, packet);
            Packets++;
            Bytes += hdr.Caplen;
            if (durationSec > 0 && (DateTimeOffset.Now - started).TotalSeconds >= durationSec) Stop();
        };
        _thread = new Thread(() =>
        {
            try { PcapNative.pcap_loop(_pcap, -1, _handler, IntPtr.Zero); }
            catch (Exception ex) { Error = ex.Message; }
            finally
            {
                try
                {
                    var stats = new PcapNative.PcapStat();
                    if (PcapNative.pcap_stats(_pcap, ref stats) == 0) Dropped = stats.Drop;
                }
                catch { /* stats are best-effort */ }
                Cleanup();
            }
        }) { IsBackground = true };
        _thread.Start();
    }

    public void Stop()
    {
        if (_pcap != IntPtr.Zero)
        {
            try { PcapNative.pcap_breakloop(_pcap); } catch { /* already closing */ }
        }
    }

    private void Cleanup()
    {
        try { if (_dumper != IntPtr.Zero) PcapNative.pcap_dump_close(_dumper); } catch { }
        try { if (_pcap != IntPtr.Zero) PcapNative.pcap_close(_pcap); } catch { }
        _dumper = IntPtr.Zero;
        _pcap = IntPtr.Zero;
        Running = false;
    }

    public void WaitForExit(int milliseconds) => _thread?.Join(milliseconds);
}
