// PacketScope web demo engine: a bounded classic-PCAP parser, results
// builder, and local threat-intel matcher in dependency-free JavaScript.
// It mirrors the desktop apps' measured-evidence rules: full-file
// statistics, first 2,000 retained rows, no payloads in any output.
"use strict";

// ---------- small synchronous MD5 / SHA-256 (for JA3/JA4) ----------
function md5hex(input) {
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = [];
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const bitLen = bytes.length * 8;
  const padded = Array.from(bytes);
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0);
  for (let i = 0; i < 8; i++) padded.push(Math.floor(bitLen / Math.pow(2, 8 * i)) & 0xff);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) | 0;
  for (let chunk = 0; chunk < padded.length; chunk += 64) {
    const M = [];
    for (let i = 0; i < 16; i++) M[i] = padded[chunk + 4*i] | (padded[chunk + 4*i + 1] << 8) | (padded[chunk + 4*i + 2] << 16) | (padded[chunk + 4*i + 3] << 24);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      const tmp = D;
      D = C; C = B;
      B = (B + rol((A + F + K[i] + M[g]) | 0, S[i])) | 0;
      A = tmp;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = [];
  for (const word of [a0, b0, c0, d0]) for (let i = 0; i < 4; i++) out.push(((word >> (8 * i)) & 0xff).toString(16).padStart(2, "0"));
  return out.join("");
}

function sha256hex(input) {
  const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const bitLen = bytes.length * 8;
  const padded = Array.from(bytes);
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0);
  for (let i = 7; i >= 0; i--) padded.push(Math.floor(bitLen / Math.pow(2, 8 * i)) & 0xff);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  const w = new Array(64);
  for (let chunk = 0; chunk < padded.length; chunk += 64) {
    for (let i = 0; i < 16; i++) w[i] = (padded[chunk + 4*i] << 24) | (padded[chunk + 4*i + 1] << 16) | (padded[chunk + 4*i + 2] << 8) | padded[chunk + 4*i + 3];
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  return H.map(x => (x >>> 0).toString(16).padStart(8, "0")).join("");
}

// ---------- PCAP parsing ----------
const DISPLAY_LIMIT = 2000;
const MAX_FILE_BYTES = 100 * 1024 * 1024;

function ipv6String(b) {
  if (b.length !== 16) return "Unknown";
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push((b[2*i] << 8) | b[2*i+1]);
  if (groups.slice(0, 5).every(g => g === 0) && groups[5] === 0xffff)
    return `::ffff:${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) { if (curStart < 0) { curStart = i; curLen = 1; } else curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; } }
    else { curStart = -1; curLen = 0; }
  }
  const hex = g => g.toString(16);
  if (bestLen >= 2) return groups.slice(0, bestStart).map(hex).join(":") + "::" + groups.slice(bestStart + bestLen).map(hex).join(":");
  return groups.map(hex).join(":");
}
function isLoopback(a) {
  if (a === "::1") return true;
  if (a.startsWith("::ffff:")) return isLoopback(a.slice(7));
  const p = a.split(".");
  return p.length === 4 && p[0] === "127";
}

function readDnsName(msg, offset) {
  const labels = [];
  let pos = offset, jumps = 0, total = 0, next = null;
  while (true) {
    if (pos >= msg.length) return null;
    const len = msg[pos];
    if (len === 0) { if (next === null) next = pos + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= msg.length) return null;
      const target = ((len & 0x3f) << 8) | msg[pos + 1];
      if (target >= pos) return null;
      if (next === null) next = pos + 2;
      pos = target;
      if (++jumps > 32) return null;
      continue;
    }
    if (len > 63 || pos + 1 + len > msg.length) return null;
    total += len + 1;
    if (total > 255) return null;
    let label = "";
    for (const byte of msg.subarray(pos + 1, pos + 1 + len)) {
      if (byte === 46) label += "\\.";
      else if (byte === 92) label += "\\\\";
      else if (byte >= 32 && byte <= 126) label += String.fromCharCode(byte);
      else label += "\\" + String(byte).padStart(3, "0");
    }
    labels.push(label);
    pos += 1 + len;
  }
  return next === null ? null : { name: labels.join("."), next };
}

function parseDns(msg, isMdns) {
  if (msg.length < 12) return null;
  const u16 = o => (msg[o] << 8) | msg[o + 1];
  const flags = u16(2), qd = u16(4), an = u16(6), ns = u16(8), ar = u16(10);
  if (qd > 32 || an + ns + ar > 256) return null;
  const info = { isResponse: (flags & 0x8000) !== 0, truncated: (flags & 0x0200) !== 0, rcode: flags & 0xf, isMdns, questions: [], answers: [] };
  let off = 12;
  for (let i = 0; i < qd; i++) {
    const name = readDnsName(msg, off);
    if (!name || name.next + 4 > msg.length) return null;
    info.questions.push({ name: name.name, type: u16(name.next), cls: u16(name.next + 2) });
    off = name.next + 4;
  }
  const readRRs = (count, collect) => {
    for (let i = 0; i < count; i++) {
      const name = readDnsName(msg, off);
      if (!name) return false;
      const next = name.next;
      if (next + 10 > msg.length) return false;
      const type = u16(next), rdlen = u16(next + 8), rdata = next + 10;
      if (rdata + rdlen > msg.length) return false;
      if (collect && type === 1 && rdlen === 4) info.answers.push({ owner: name.name, type, address: Array.from(msg.subarray(rdata, rdata + 4)).join(".") });
      if (collect && type === 28 && rdlen === 16) info.answers.push({ owner: name.name, type, address: ipv6String(msg.subarray(rdata, rdata + 16)) });
      if (collect && type === 5) { const t = readDnsName(msg, rdata); if (t) info.answers.push({ owner: name.name, type, address: t.name }); }
      off = rdata + rdlen;
    }
    return true;
  };
  if (!readRRs(an, true) || !readRRs(ns, false) || !readRRs(ar, false)) return null;
  return info;
}

function parseClientHello(hs) {
  if (hs.length < 4 || hs[0] !== 1) return null;
  const declared = (hs[1] << 16) | (hs[2] << 8) | hs[3];
  const body = hs.subarray(4, 4 + Math.min(declared, hs.length - 4));
  if (body.length < 34) return null;
  const u16 = o => (body[o] << 8) | body[o + 1];
  const info = { sni: null, ech: false, ciphers: [], extensions: [], groups: [], pointFormats: [], sigAlgs: [], alpn: [], versions: [], clientVersion: u16(0) };
  let off = 2 + 32;
  if (off >= body.length) return null;
  off += 1 + body[off];
  if (off + 1 >= body.length) return null;
  const csLen = u16(off); off += 2;
  if (off + csLen > body.length) return null;
  for (let i = off; i < off + csLen; i += 2) info.ciphers.push(u16(i));
  off += csLen;
  if (off >= body.length) return null;
  off += 1 + body[off];
  if (off + 1 >= body.length) return null;
  const extLen = u16(off); off += 2;
  const extEnd = Math.min(body.length, off + extLen);
  while (off + 4 <= extEnd) {
    const etype = u16(off), elen = u16(off + 2);
    const data = off + 4;
    if (data + elen > extEnd) break;
    info.extensions.push(etype);
    const seg = body.subarray(data, data + elen);
    if (etype === 0 && seg.length >= 5 && seg[2] === 0) {
      const nl = (seg[3] << 8) | seg[4];
      if (nl > 0 && 5 + nl <= seg.length) info.sni = new TextDecoder().decode(seg.subarray(5, 5 + nl));
    } else if (etype === 0xfe0d) info.ech = true;
    else if (etype === 10 && seg.length >= 2) { const n = (seg[0] << 8) | seg[1]; for (let i = 2; i + 1 <= Math.min(seg.length, 2 + n); i += 2) info.groups.push((seg[i] << 8) | seg[i + 1]); }
    else if (etype === 11 && seg.length >= 1) info.pointFormats = Array.from(seg.subarray(1));
    else if (etype === 13 && seg.length >= 2) { const n = (seg[0] << 8) | seg[1]; for (let i = 2; i + 1 <= Math.min(seg.length, 2 + n); i += 2) info.sigAlgs.push((seg[i] << 8) | seg[i + 1]); }
    else if (etype === 16) { let p = 2; while (p < seg.length) { const l = seg[p]; p++; if (p + l <= seg.length) info.alpn.push(new TextDecoder().decode(seg.subarray(p, p + l))); p += l; } }
    else if (etype === 43) { let p = 1; while (p + 2 <= seg.length) { info.versions.push((seg[p] << 8) | seg[p + 1]); p += 2; } }
    off = data + elen;
  }
  return info;
}
const isGrease = v => (v & 0x0f0f) === 0x0a0a;
function ja3(info) {
  const strip = xs => xs.filter(x => !isGrease(x));
  return md5hex(`${info.clientVersion},${strip(info.ciphers).join("-")},${strip(info.extensions).join("-")},${strip(info.groups).join("-")},${info.pointFormats.join("-")}`);
}
function ja4(info, quic) {
  const strip = xs => xs.filter(x => !isGrease(x));
  const version = info.versions.includes(0x0304) ? "13" : (info.versions.includes(0x0303) || info.clientVersion === 0x0303 ? "12" : "13");
  const ciphers = strip(info.ciphers), exts = strip(info.extensions);
  const alpn = info.alpn.length ? info.alpn[0][0] + info.alpn[0][info.alpn[0].length - 1] : "00";
  const cipherHash = sha256hex(ciphers.map(c => c.toString(16).padStart(4, "0")).sort().join(",")).slice(0, 12);
  const extPart = exts.filter(e => e !== 0 && e !== 16).map(e => e.toString(16).padStart(4, "0")).sort().join(",");
  const sigPart = info.sigAlgs.map(s => s.toString(16).padStart(4, "0")).join(",");
  const extHash = sha256hex(extPart + "_" + sigPart).slice(0, 12);
  return `${quic ? "q" : "t"}${version}${info.sni ? "d" : "i"}${String(Math.min(99, ciphers.length)).padStart(2, "0")}${String(Math.min(99, exts.length)).padStart(2, "0")}${alpn}_${cipherHash}_${extHash}`;
}

function analyzePcap(input) {
  const b = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (b.length > MAX_FILE_BYTES) throw new Error(`Capture file is ${b.length} bytes, over the 100 MiB import limit.`);
  if (b.length >= 4 && b[0] === 0x0a && b[1] === 0x0d && b[2] === 0x0d && b[3] === 0x0a)
    throw new Error("PCAPNG files are not supported. Please provide a classic PCAP file.");
  if (b.length < 24) throw new Error("Truncated PCAP: global header.");
  const first = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  const swapped = ((b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0]) >>> 0;
  let little, nano;
  if (first === 0xa1b2c3d4) { little = false; nano = false; }
  else if (first === 0xa1b23c4d) { little = false; nano = true; }
  else if (swapped === 0xa1b2c3d4) { little = true; nano = false; }
  else if (swapped === 0xa1b23c4d) { little = true; nano = true; }
  else throw new Error("This file is not a classic PCAP capture.");
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u16 = o => view.getUint16(o, little);
  const u32 = o => view.getUint32(o, little);
  if (u16(4) !== 2 || u16(6) !== 4) throw new Error(`Unsupported PCAP version ${u16(4)}.${u16(6)}; only 2.4 is supported.`);
  const snaplen = u32(16);
  if (snaplen <= 0) throw new Error("Invalid PCAP: snapshot length is zero.");
  const linkType = u32(20);
  if (![0, 1, 12, 101, 108, 149, 258, 228, 229].includes(linkType))
    throw new Error(`Unsupported PCAP link type ${linkType}.`);
  const recs = [];
  let off = 24;
  while (off < b.length) {
    if (off + 16 > b.length) throw new Error(`Truncated PCAP: record header at offset ${off}.`);
    const sec = u32(off), frac = u32(off + 4), incl = u32(off + 8), orig = u32(off + 12);
    const fracLimit = nano ? 1e9 : 1e6;
    if (frac >= fracLimit) throw new Error("Invalid PCAP: timestamp fraction out of range.");
    if (incl > snaplen) throw new Error("Invalid PCAP: captured length exceeds snapshot length.");
    if (incl > orig) throw new Error("Invalid PCAP: captured length exceeds original length.");
    if (off + 16 + incl > b.length) throw new Error(`Truncated PCAP: packet data at offset ${off}.`);
    recs.push({ ts: sec + frac / fracLimit, incl, orig, off: off + 16 });
    off += 16 + incl;
  }

  const st = {
    protoStats: new Map(), endpointStats: new Map(), records: [], undecodable: 0,
    capturedBytes: 0, dnsResponses: 0, dnsErrors: 0, tcpPackets: 0, tcpResets: 0, retransmissions: 0,
    dnsErrorPackets: [], rstPackets: [], icmpPackets: [], tlsAlertPackets: [],
    plainRemote: [], plainLocal: [], intervals: [], buckets: new Map(),
    domains: new Map(), domainOrder: [], ipToName: new Map(), lookups: [], dnsQueryCount: 0,
    resolvers: [], nxdomains: [], cnames: [], pending: new Map(), answeredKeys: new Set(),
    mixStats: new Map(), quicPackets: 0, encryptedOther: 0, arpResponder: null,
    flows: new Map(), flowOrder: [], udpGroups: new Map(), udpOrder: [],
    httpHosts: [], httpUrls: [], certs: [], fps: [],
    obsEndpoints: new Map(), obsIps: new Set(), obsTruncated: false,
    tlsStreams: new Map(), currentNumber: 0,
    lastTs: 0,
  };
  const firstTs = recs.length ? recs[0].ts : null;
  const span = recs.length > 1 ? Math.max(0, recs[recs.length - 1].ts - recs[0].ts) : 0;
  const bucketWidth = Math.max(1, Math.ceil(span / 119));

  const addTo = (map, key, bytes) => { const v = map.get(key) || { count: 0, bytes: 0 }; v.count++; v.bytes += bytes; map.set(key, v); };

  function decodeLink(frame, link, d, depth) {
    if (depth > 2) { d.undecodable = true; d.summary = "Nested link headers too deep."; return; }
    switch (link) {
      case 0: case 108:
        if (frame.length < 4) { d.undecodable = true; return; }
        decodeIp(frame.subarray(4), d); break;
      case 1: decodeEthernet(frame, d, depth); break;
      case 12: case 101: decodeIp(frame, d); break;
      case 228: decodeIPv4(frame, d); break;
      case 229: decodeIPv6(frame, d); break;
      case 149: case 258: decodePktap(frame, d, depth); break;
      default: d.undecodable = true; d.proto = `Link ${link}`; d.summary = `Unsupported link type ${link}.`;
    }
  }
  function decodeEthernet(frame, d, depth) {
    if (frame.length < 14) { d.undecodable = true; d.proto = "Ethernet"; d.summary = "Truncated Ethernet frame."; return; }
    let off2 = 12;
    let ether = (frame[off2] << 8) | frame[off2 + 1]; off2 += 2;
    let vlans = 0;
    while ([0x8100, 0x88a8, 0x9100].includes(ether) && vlans < 4) {
      if (frame.length < off2 + 4) { d.undecodable = true; return; }
      ether = (frame[off2 + 2] << 8) | frame[off2 + 3]; off2 += 4; vlans++;
    }
    const payload = frame.subarray(off2);
    if (ether === 0x0800) decodeIPv4(payload, d);
    else if (ether === 0x86dd) decodeIPv6(payload, d);
    else if (ether === 0x0806) {
      d.proto = "ARP";
      if (payload.length >= 28 && payload[4] === 6 && payload[5] === 4) {
        const spa = Array.from(payload.subarray(14, 18)).join("."), tpa = Array.from(payload.subarray(24, 28)).join(".");
        d.src = spa; d.dst = tpa;
        const op = (payload[6] << 8) | payload[7];
        if (op === 2) d.arpReplySender = spa;
        d.summary = op === 1 ? `ARP request: who has ${tpa}? (sender ${spa})` : `ARP reply: ${spa} is at the sender hardware address.`;
      } else d.summary = "ARP packet.";
    } else { d.proto = "Ethernet"; d.summary = `Ethernet frame, EtherType 0x${ether.toString(16)}.`; }
  }
  function decodePktap(frame, d, depth) {
    d.proto = "PKTAP";
    if (frame.length < 8) { d.undecodable = true; d.summary = "Truncated PKTAP metadata."; return; }
    const ru32 = o => little ? (frame[o] | frame[o+1] << 8 | frame[o+2] << 16 | frame[o+3] << 24) >>> 0 : ((frame[o] << 24) | (frame[o+1] << 16) | (frame[o+2] << 8) | frame[o+3]) >>> 0;
    const ru16 = o => little ? frame[o] | frame[o+1] << 8 : (frame[o] << 8) | frame[o+1];
    const cstr = (start, maxLen) => {
      if (start >= frame.length) return "";
      let end = start;
      while (end < Math.min(frame.length, start + maxLen) && frame[end] !== 0) end++;
      return new TextDecoder().decode(frame.subarray(start, end)).replace(/[\r\n]/g, "");
    };
    const looksV2 = frame.length >= 40 && (ru32(36) & 0x00080000) !== 0 && frame[0] >= 40 && frame[0] <= 200;
    if (looksV2) {
      const innerDlt = ru16(6), pid = ru32(28);
      const commOff = frame[4], ecommOff = frame[5];
      let headerLen = frame[0];
      let name = commOff > 0 ? cstr(commOff, 20) : "";
      if (!name && ecommOff > 0) name = cstr(ecommOff, 20);
      if (commOff > 0) headerLen = Math.max(headerLen, commOff + 20);
      if (ecommOff > 0) headerLen = Math.max(headerLen, ecommOff + 20);
      if (frame[3] > 0) headerLen = Math.max(headerLen, frame[3] + 24);
      headerLen = Math.min(Math.max(headerLen, 40), frame.length);
      if (name) d.processName = name;
      if (pid !== 0) d.processId = pid;
      if ([0,1,12,101,108,228,229].includes(innerDlt)) decodeLink(frame.subarray(headerLen), innerDlt, d, depth + 1);
      else { d.undecodable = true; d.summary = `PKTAP record with unsupported inner link type ${innerDlt}.`; }
      return;
    }
    const v1Len = ru32(0);
    if (v1Len < 100 || v1Len > frame.length) { d.undecodable = true; d.summary = "Malformed PKTAP metadata (bad header length)."; return; }
    const innerDlt = ru32(8), pid = ru32(52);
    let name = cstr(56, 20);
    if (!name) name = cstr(88, 20);
    if (name) d.processName = name;
    if (pid !== 0) d.processId = pid;
    if ([0,1,12,101,108,228,229].includes(innerDlt)) decodeLink(frame.subarray(v1Len), innerDlt, d, depth + 1);
    else { d.undecodable = true; d.summary = `PKTAP record with unsupported inner link type ${innerDlt}.`; }
  }
  function decodeIp(frame, d) {
    if (!frame.length) { d.undecodable = true; d.summary = "Empty IP packet."; return; }
    const v = frame[0] >> 4;
    if (v === 4) decodeIPv4(frame, d);
    else if (v === 6) decodeIPv6(frame, d);
    else { d.undecodable = true; d.proto = "IP"; d.summary = "Unknown IP version."; }
  }
  function decodeIPv4(frame, d) {
    if (frame.length < 20 || frame[0] >> 4 !== 4) { d.undecodable = true; d.proto = "IPv4"; d.summary = "Truncated IPv4 header."; return; }
    const ihl = (frame[0] & 0x0f) * 4;
    if (ihl < 20 || frame.length < ihl) { d.undecodable = true; d.proto = "IPv4"; return; }
    const total = (frame[2] << 8) | frame[3];
    const end = total >= ihl && total <= frame.length ? total : frame.length;
    d.src = Array.from(frame.subarray(12, 16)).join(".");
    d.dst = Array.from(frame.subarray(16, 20)).join(".");
    const fragOff = ((frame[6] << 8) | frame[7]) & 0x1fff;
    const more = (frame[6] & 0x20) !== 0;
    if (fragOff !== 0 || more) { d.proto = "IPv4"; d.summary = "IPv4 fragment (transport header not reassembled)."; return; }
    decodeTransport(frame[9], frame.subarray(ihl, end), d, false);
  }
  function decodeIPv6(frame, d) {
    if (frame.length < 40 || frame[0] >> 4 !== 6) { d.undecodable = true; d.proto = "IPv6"; return; }
    d.src = ipv6String(frame.subarray(8, 24));
    d.dst = ipv6String(frame.subarray(24, 40));
    let next = frame[6], off2 = 40, hops = 0;
    while (hops++ < 8) {
      if ([0, 43, 60].includes(next)) {
        if (frame.length < off2 + 2) { d.undecodable = true; d.proto = "IPv6"; return; }
        const len = (frame[off2 + 1] + 1) * 8;
        if (len < 8 || frame.length < off2 + len) { d.undecodable = true; d.proto = "IPv6"; return; }
        next = frame[off2]; off2 += len;
      } else if (next === 44) { d.proto = "IPv6"; d.summary = "IPv6 fragment (transport header not reassembled)."; return; }
      else if (next === 51) {
        if (frame.length < off2 + 2) { d.undecodable = true; d.proto = "IPv6"; return; }
        const len = (frame[off2 + 1] + 2) * 4;
        if (frame.length < off2 + len) { d.undecodable = true; d.proto = "IPv6"; return; }
        next = frame[off2]; off2 += len;
      } else { decodeTransport(next, frame.subarray(off2), d, true); return; }
    }
    d.proto = "IPv6"; d.undecodable = true; d.summary = "Too many IPv6 extension headers.";
  }
  function decodeTransport(proto, payload, d, v6) {
    if (proto === 6) decodeTcp(payload, d);
    else if (proto === 17) decodeUdp(payload, d);
    else if (proto === 1 || proto === 58) {
      d.proto = proto === 1 ? "ICMP" : "ICMPv6"; d.mix = "ICMP";
      if (payload.length >= 2) {
        d.summary = `${d.proto} type ${payload[0]}, code ${payload[1]} between ${d.src} and ${d.dst}.`;
        if ((proto === 1 && payload[0] === 3) || (proto === 58 && payload[0] === 1)) { d.icmpUnreachable = true; d.summary = `${d.proto} destination unreachable (code ${payload[1]}) from ${d.src} to ${d.dst}.`; }
      } else d.summary = `${d.proto} packet.`;
    } else { d.proto = v6 ? "IPv6" : "IPv4"; d.summary = `IP protocol ${proto} between ${d.src} and ${d.dst}.`; }
  }
  function detectPlaintext(body) {
    if (body.length < 3) return null;
    const head = new TextDecoder("ascii").decode(body.subarray(0, Math.min(64, body.length)));
    for (const tok of ["HTTP/", "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "PATCH ", "OPTIONS "]) if (head.startsWith(tok)) return "HTTP";
    for (const tok of ["EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:"]) if (head.startsWith(tok)) return "SMTP";
    for (const tok of ["USER ", "PASS ", "RETR ", "STOR ", "LIST", "CWD ", "TYPE "]) if (head.startsWith(tok)) return "FTP";
    if (head.startsWith("220 ") || head.startsWith("220-")) {
      const lower = head.toLowerCase();
      if (lower.includes("ftp")) return "FTP";
      if (lower.includes("smtp") || lower.includes("mail")) return "SMTP";
      return "FTP/SMTP";
    }
    return null;
  }
  function decodeTcp(payload, d) {
    d.isTcp = true; d.mix = "TCP";
    if (payload.length < 20) { d.undecodable = true; d.proto = "TCP"; d.summary = "Truncated TCP header."; return; }
    d.sport = (payload[0] << 8) | payload[1];
    d.dport = (payload[2] << 8) | payload[3];
    d.tcpSeq = ((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]) >>> 0;
    const hlen = (payload[12] >> 4) * 4;
    if (hlen < 20 || payload.length < hlen) { d.undecodable = true; d.proto = "TCP"; return; }
    const flags = payload[13];
    d.tcpFlags = flags;
    d.isRst = (flags & 0x04) !== 0;
    const names = [];
    if (flags & 0x02) names.push("SYN");
    if (flags & 0x10) names.push("ACK");
    if (flags & 0x01) names.push("FIN");
    if (flags & 0x04) names.push("RST");
    if (flags & 0x08) names.push("PSH");
    d.proto = "TCP";
    const body = payload.subarray(hlen);
    d.payloadLength = body.length;
    d.tcpPayload = body;
    let summary = `TCP ${d.src}:${d.sport} → ${d.dst}:${d.dport}` + (names.length ? ` [${names.join(",")}]` : "") + ".";
    if (d.isRst) summary += " Connection reset observed.";
    feedTls(d, body);
    if (d.tlsEvent === "clientHello") summary += " Secure setup (TLS) started" + (d.tlsSni ? ` for ${d.tlsSni}` : "") + ".";
    if (d.tlsEvent === "serverHello") summary += " Secure setup (TLS) answered.";
    if (d.tlsEvent === "alert") summary += " TLS alert observed (contents not shown).";
    if (d.tlsAppData) summary += " Encrypted TLS data (contents can't be read).";
    if ((d.sport === 53 || d.dport === 53) && body.length >= 2) {
      const mlen = (body[0] << 8) | body[1];
      if (mlen >= 12 && body.length >= 2 + mlen) {
        const dns = parseDns(body.subarray(2, 2 + mlen), false);
        if (dns) {
          d.proto = "DNS"; d.mix = "DNS"; d.dns = dns; d.hostname = dns.questions[0]?.name ?? null;
          d.dnsTxId = (body[2] << 8) | body[3]; d.dnsTransport = "tcp";
          summary = dnsSummary(dns, d, "TCP");
        }
      }
    } else if (detectPlaintext(body)) {
      d.plaintextProto = detectPlaintext(body); d.proto = d.plaintextProto;
      summary += ` Recognizable plaintext ${d.plaintextProto} content visible (contents are not shown).`;
    }
    d.summary = summary;
  }
  function decodeUdp(payload, d) {
    if (payload.length < 8) { d.undecodable = true; d.proto = "UDP"; return; }
    d.sport = (payload[0] << 8) | payload[1];
    d.dport = (payload[2] << 8) | payload[3];
    const body = payload.subarray(8);
    d.proto = "UDP"; d.mix = "UDP_OTHER";
    let summary = `UDP ${d.src}:${d.sport} → ${d.dst}:${d.dport}.`;
    if ((d.sport === 443 || d.dport === 443) && body.length > 0 && (body[0] & 0x80) !== 0) {
      d.isQuic = true; d.proto = "QUIC"; d.mix = "QUIC";
      d.summary = `QUIC ${d.src}:${d.sport} → ${d.dst}:${d.dport} (encrypted; server names are not extracted in the web version).`;
      return;
    }
    const mdns = d.sport === 5353 || d.dport === 5353;
    if (d.sport === 53 || d.dport === 53 || mdns) {
      if (body.length >= 12) {
        const dns = parseDns(body, mdns);
        if (dns) {
          d.proto = mdns ? "mDNS" : "DNS";
          if (!mdns) d.mix = "DNS";
          d.dns = dns; d.hostname = dns.questions[0]?.name ?? null;
          d.dnsTxId = (body[0] << 8) | body[1]; d.dnsTransport = "udp";
          summary = dnsSummary(dns, d, "UDP");
        }
      }
    } else if (detectPlaintext(body)) {
      d.plaintextProto = detectPlaintext(body); d.proto = d.plaintextProto;
      summary += ` Recognizable plaintext ${d.plaintextProto} content visible (contents are not shown).`;
    }
    d.summary = summary;
  }
  function dnsSummary(dns, d, transport) {
    const name = dns.questions[0]?.name ?? "a name";
    if (dns.isResponse) return dns.rcode === 0 ? `DNS reply (${transport}) for ${name} between ${d.src} and ${d.dst}.` : `DNS error reply (${transport}, code ${dns.rcode}) for ${name} between ${d.src} and ${d.dst}.`;
    return `DNS query (${transport}) for ${name} between ${d.src} and ${d.dst}.`;
  }
  function parseHttp(body, d) {
    if (body.length < 16) return;
    const text = new TextDecoder().decode(body.subarray(0, Math.min(4096, body.length)));
    let lineEnd = text.indexOf("\r\n");
    if (lineEnd < 0) lineEnd = text.indexOf("\n");
    if (lineEnd < 0) return;
    const parts = text.slice(0, lineEnd).split(" ");
    if (parts.length !== 3 || !parts[2].startsWith("HTTP/")) return;
    const path = parts[1];
    let host = null;
    for (const rawLine of text.slice(lineEnd).split("\n")) {
      const line = rawLine.trim();
      if (line.toLowerCase().startsWith("host:")) { host = line.slice(5).trim(); break; }
      if (line.length === 0) break;
    }
    if (path.startsWith("http://") || path.startsWith("https://")) {
      d.httpUrl = path;
      try { d.httpHost = new URL(path).hostname.toLowerCase(); } catch { /* ignore */ }
    } else if (host) {
      d.httpHost = host.toLowerCase();
      d.httpUrl = "http://" + host + path;
    }
  }

  // TLS record reassembly per direction (first 16 KB, memory only)
  function feedTls(d, body) {
    if (d.sport == null || d.dport == null) return;
    const flowId = [`${d.src}:${d.sport}`, `${d.dst}:${d.dport}`].sort().join("|");
    const key = flowId + "|" + `${d.src}:${d.sport}>${d.dst}:${d.dport}`;
    const firstIsTls = body.length >= 5 && [20, 21, 22, 23].includes(body[0]) && body[1] === 3;
    if (!st.tlsStreams.has(key)) {
      if (!firstIsTls || st.tlsStreams.size >= 512) return;
      st.tlsStreams.set(key, { baseSeq: d.tcpSeq, segments: [], parsedOffset: 0, finished: false, buffered: 0 });
    }
    const stream = st.tlsStreams.get(key);
    if (stream.finished) return;
    const offset = (d.tcpSeq - stream.baseSeq) | 0;
    if (offset >= 0 && stream.buffered <= 24576) { stream.segments.push({ seq: d.tcpSeq, data: body }); stream.buffered += body.length; }
    const assembled = [];
    for (const seg of [...stream.segments].sort((a, b2) => ((a.seq - stream.baseSeq) | 0) - ((b2.seq - stream.baseSeq) | 0))) {
      const segOff = (seg.seq - stream.baseSeq) | 0;
      if (segOff > assembled.length) break;
      const skip = assembled.length - segOff;
      if (skip < seg.data.length) assembled.push(...seg.data.subarray(skip));
      if (assembled.length >= 16384) break;
    }
    const bytes = Uint8Array.from(assembled.slice(0, 16384));
    let off2 = stream.parsedOffset;
    while (off2 + 5 <= bytes.length) {
      const recType = bytes[off2];
      if (![20, 21, 22, 23].includes(recType)) { stream.finished = true; break; }
      const recLen = (bytes[off2 + 3] << 8) | bytes[off2 + 4];
      if (off2 + 5 + recLen > bytes.length) break;
      const rec = bytes.subarray(off2 + 5, off2 + 5 + recLen);
      if (recType === 23) d.tlsAppData = true;
      else if (recType === 21) { if (!d.tlsEvent) d.tlsEvent = "alert"; }
      else if (recType === 22) parseHandshake(rec, d);
      off2 += 5 + recLen;
      if (off2 >= 16384) stream.finished = true;
    }
    stream.parsedOffset = off2;
  }
  function parseHandshake(rec, d) {
    let off2 = 0;
    while (off2 + 4 <= rec.length) {
      const hsType = rec[off2];
      const hsLen = (rec[off2 + 1] << 16) | (rec[off2 + 2] << 8) | rec[off2 + 3];
      if (off2 + 4 + hsLen > rec.length) return;
      const hs = rec.subarray(off2, off2 + 4 + hsLen);
      if (hsType === 1) {
        const info = parseClientHello(hs);
        if (info) {
          d.tlsEvent = "clientHello"; d.tlsSni = info.sni; d.tlsEch = info.ech; d.hostname = info.sni;
          if (st.fps.length < 2000) st.fps.push({ ja3: ja3(info), ja4: ja4(info, false), sni: info.sni, ech: info.ech, quic: false, frame: st.currentNumber, serverAddress: d.dst, serverPort: d.dport ?? 0 });
        }
      } else if (hsType === 2) d.tlsEvent = "serverHello";
      else if (hsType === 11) {
        if (hs.length >= 10) {
          const certLen = (hs[7] << 16) | (hs[8] << 8) | hs[9];
          const certStart = 10;
          if (certLen > 0 && certStart + certLen <= hs.length && st.certs.length < 1000) {
            const der = hs.subarray(certStart, certStart + certLen);
            st.certs.push({ sha1: sha256hex(der).slice(0, 0) || "", sha256: sha256hex(der), frame: st.currentNumber, serverAddress: d.src, serverPort: d.sport ?? 0, _der: der });
          }
        }
      }
      off2 += 4 + hsLen;
    }
  }

  function addDomain(name, packet) {
    if (!st.domains.has(name)) {
      if (st.domains.size >= 2000) return;
      st.domains.set(name, { addresses: [], queryCount: 0, errorCount: 0, packetNumbers: [] });
      st.domainOrder.push(name);
    }
    const entry = st.domains.get(name);
    if (entry.packetNumbers.length < 50) entry.packetNumbers.push(packet);
  }
  function handleDns(dns, d, number, ts, errRef) {
    for (const q of dns.questions) {
      addDomain(q.name, number);
      if (!dns.isResponse && st.domains.has(q.name)) st.domains.get(q.name).queryCount++;
    }
    if (dns.isResponse) {
      st.dnsResponses++;
      if (!dns.isMdns && !st.resolvers.includes(d.src) && st.resolvers.length < 16) st.resolvers.push(d.src);
      if (dns.rcode !== 0) {
        st.dnsErrors++; errRef.value = true;
        if (st.dnsErrorPackets.length < 100) st.dnsErrorPackets.push(number);
        for (const q of dns.questions) if (st.domains.has(q.name)) st.domains.get(q.name).errorCount++;
        if (dns.rcode === 3 && dns.questions.length && st.nxdomains.length < 50) st.nxdomains.push({ name: dns.questions[0].name, frame: number });
      }
    }
    for (const ans of dns.answers.filter(a => a.type === 5)) {
      if (!st.cnames.includes(ans.address) && st.cnames.length < 500) st.cnames.push(ans.address);
      addDomain(ans.address, number);
    }
    for (const ans of dns.answers.filter(a => a.type === 1 || a.type === 28)) {
      if (!st.ipToName.has(ans.address)) st.ipToName.set(ans.address, ans.owner);
      addDomain(ans.owner, number);
      const entry = st.domains.get(ans.owner);
      if (entry && !entry.addresses.includes(ans.address) && entry.addresses.length < 16) entry.addresses.push(ans.address);
    }
    if (dns.isMdns || dns.truncated || d.sport == null || d.dport == null) return;
    const qkey = dns.questions.map(q => `${q.name}/${q.type}/${q.cls}`).join(";");
    if (dns.isResponse) {
      const key = `${d.dnsTransport}|${d.dst}|${d.src}|${d.dport}|${d.sport}|${d.dnsTxId}|${qkey}`;
      const entry = st.pending.get(key);
      if (entry) {
        if (entry.count === 1 && !st.answeredKeys.has(key)) {
          const dt = ts - entry.ts;
          if (dt >= 0 && dt <= 30) {
            st.intervals.push(dt * 1000);
            for (const idx of entry.lookupIndices) if (idx < st.lookups.length) { st.lookups[idx].milliseconds = dt * 1000; st.lookups[idx].rcode = rcodeName(dns.rcode); }
          }
        }
        st.pending.delete(key);
        st.answeredKeys.add(key);
      }
    } else {
      const idxs = [];
      for (const q of dns.questions) {
        st.dnsQueryCount++;
        if (st.lookups.length < 1000) {
          const typeName = { 1: "A", 28: "AAAA", 65: "HTTPS", 5: "CNAME" }[q.type] || `TYPE${q.type}`;
          st.lookups.push({ name: q.name, type: typeName, milliseconds: null, rcode: "", frame: number });
          idxs.push(st.lookups.length - 1);
        }
      }
      const key = `${d.dnsTransport}|${d.src}|${d.dst}|${d.sport}|${d.dport}|${d.dnsTxId}|${qkey}`;
      st.answeredKeys.delete(key);
      if (st.pending.has(key)) st.pending.get(key).count++;
      else if (st.pending.size < 4096) st.pending.set(key, { ts, count: 1, lookupIndices: idxs });
    }
  }
  function rcodeName(r) { return { 0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED" }[r] || `RCODE ${r}`; }

  function flowKey(src, sport, dst, dport) {
    const a = `${src}:${sport}`, b2 = `${dst}:${dport}`;
    return a <= b2 ? a + "|" + b2 : b2 + "|" + a;
  }
  function updateFlow(d, number, capturedLength) {
    if (d.sport == null || d.dport == null || d.src === "Unknown") return;
    const sp = d.sport, dp = d.dport;
    if (d.isTcp) {
      const key = flowKey(d.src, sp, d.dst, dp);
      let f = st.flows.get(key);
      if (!f) {
        if (st.flows.size >= 4096) return;
        f = { initiator: d.src, initiatorPort: sp, server: d.dst, serverPort: dp, synFrames: [], synSeqs: new Set(), dataSeqs: new Set(), connected: false, refused: false, resetLater: false, clientHello: false, serverHello: false, alertBeforeHello: false, sawHttp: false, sni: null, ech: false, packets: 0, bytes: 0, frames: [], retransmissions: 0, refusedFrames: [] };
        st.flows.set(key, f);
        st.flowOrder.push(key);
      }
      const syn = (d.tcpFlags & 0x02) !== 0, ack = (d.tcpFlags & 0x10) !== 0, rst = (d.tcpFlags & 0x04) !== 0;
      const fromServer = d.src === f.server && sp === f.serverPort;
      if (syn && !ack) {
        if (f.synSeqs.has(d.tcpSeq)) { f.retransmissions++; st.retransmissions++; }
        f.synSeqs.add(d.tcpSeq);
        if (f.synFrames.length < 200) f.synFrames.push(number);
        if (!fromServer) { f.initiator = d.src; f.initiatorPort = sp; f.server = d.dst; f.serverPort = dp; }
      }
      if (syn && ack) f.connected = true;
      if (rst) {
        if (f.connected) f.resetLater = true;
        else if (fromServer && f.synFrames.length) { f.refused = true; if (f.refusedFrames.length < 200) f.refusedFrames.push(number); }
      }
      if (d.payloadLength > 0) {
        const sk = `${d.src}:${sp}>${d.tcpSeq}:${d.payloadLength}`;
        if (f.dataSeqs.has(sk)) { f.retransmissions++; st.retransmissions++; }
        if (f.dataSeqs.size < 8192) f.dataSeqs.add(sk);
      }
      if (d.tlsEvent === "clientHello") { f.clientHello = true; f.ech = d.tlsEch; if (d.tlsSni) f.sni = d.tlsSni; }
      if (d.tlsEvent === "serverHello") f.serverHello = true;
      if (d.tlsEvent === "alert" && !f.serverHello) f.alertBeforeHello = true;
      if (d.plaintextProto === "HTTP") f.sawHttp = true;
      f.packets++; f.bytes += capturedLength;
      if (f.frames.length < 200) f.frames.push(number);
    } else if (d.proto === "QUIC" || d.proto === "UDP") {
      const key = flowKey(d.src, sp, d.dst, dp);
      let g = st.udpGroups.get(key);
      if (!g) {
        if (st.udpGroups.size >= 2048) return;
        let server, serverPort;
        if (dp <= 1024 || dp === 443) { server = d.dst; serverPort = dp; }
        else if (sp <= 1024 || sp === 443) { server = d.src; serverPort = sp; }
        else { server = d.dst; serverPort = dp; }
        g = { server, serverPort, quic: d.isQuic, packets: 0, bytes: 0, frames: [] };
        st.udpGroups.set(key, g);
        st.udpOrder.push(key);
      }
      g.packets++; g.bytes += capturedLength;
      if (g.frames.length < 200) g.frames.push(number);
    }
  }

  function decodePacket(frame, number, ts, originalLength, capturedLength) {
    st.currentNumber = number;
    if (ts > st.lastTs) st.lastTs = ts;
    st.capturedBytes += capturedLength;
    const d = { src: "Unknown", dst: "Unknown", sport: null, dport: null, proto: "Unknown", summary: "Packet could not be decoded further.", hostname: null, processName: null, processId: null, isTcp: false, isRst: false, undecodable: false, isQuic: false, tlsAppData: false, icmpUnreachable: false, tcpFlags: 0, tcpSeq: 0, payloadLength: 0, mix: "OTHER", tlsEvent: null, tlsSni: null, tlsEch: false, httpHost: null, httpUrl: null, arpReplySender: null, tcpPayload: new Uint8Array(0), dns: null, plaintextProto: null, dnsTxId: 0, dnsTransport: "udp" };
    decodeLink(frame, linkType, d, 0);
    if (d.undecodable) st.undecodable++;
    addTo(st.protoStats, d.proto, capturedLength);
    if (d.src !== "Unknown") addTo(st.endpointStats, d.src, capturedLength);
    if (d.dst !== "Unknown") addTo(st.endpointStats, d.dst, capturedLength);
    const bothLoop = isLoopback(d.src) && isLoopback(d.dst) && d.src !== "Unknown";
    const errRef = { value: false };
    if (d.isTcp) { st.tcpPackets++; if (d.isRst) { st.tcpResets++; if (st.rstPackets.length < 100) st.rstPackets.push(number); } }
    if (d.dns) handleDns(d.dns, d, number, ts, errRef);
    if (d.plaintextProto) {
      if (bothLoop) st.plainLocal.push([number, d.plaintextProto]); else st.plainRemote.push([number, d.plaintextProto]);
      if (d.plaintextProto === "HTTP") parseHttp(d.tcpPayload, d);
    }
    if (d.httpHost && !st.httpHosts.includes(d.httpHost) && st.httpHosts.length < 1000) st.httpHosts.push(d.httpHost);
    if (d.httpUrl && !st.httpUrls.includes(d.httpUrl) && st.httpUrls.length < 1000) st.httpUrls.push(d.httpUrl);
    addTo(st.mixStats, d.mix, capturedLength);
    if (d.isQuic) st.quicPackets++;
    if (d.tlsAppData) st.encryptedOther++;
    if (d.arpReplySender && !st.arpResponder) st.arpResponder = d.arpReplySender;
    if (d.icmpUnreachable && st.icmpPackets.length < 100) st.icmpPackets.push(number);
    if (d.tlsEvent === "alert" && st.tlsAlertPackets.length < 100) st.tlsAlertPackets.push(number);
    if (d.src !== "Unknown") { if (st.obsIps.size < 250000) st.obsIps.add(d.src); else st.obsTruncated = true; }
    if (d.dst !== "Unknown") {
      if (st.obsIps.size < 250000) st.obsIps.add(d.dst); else st.obsTruncated = true;
      if (d.dport != null && (d.isTcp || ["UDP", "QUIC", "DNS"].includes(d.proto))) {
        const key = `${d.dst}|${d.dport}`;
        const existing = st.obsEndpoints.get(key);
        if (existing) { existing.packets++; if (existing.frames.length < 10) existing.frames.push(number); }
        else if (st.obsEndpoints.size < 100000) st.obsEndpoints.set(key, { address: d.dst, port: d.dport, packets: 1, frames: [number] });
        else st.obsTruncated = true;
      }
    }
    updateFlow(d, number, capturedLength);
    if (firstTs != null) {
      const idx = Math.floor((ts - firstTs) / bucketWidth);
      if (!st.buckets.has(idx)) st.buckets.set(idx, { second: idx * Math.floor(bucketWidth), packets: 0, bytes: 0, dnsErrors: 0, tcpResets: 0 });
      const bk = st.buckets.get(idx);
      bk.packets++; bk.bytes += capturedLength;
      if (errRef.value) bk.dnsErrors++;
      if (d.isRst) bk.tcpResets++;
    }
    if (st.records.length < DISPLAY_LIMIT) {
      st.records.push({ id: number, timestamp: ts, source: d.src, destination: d.dst, sourcePort: d.sport, destinationPort: d.dport, protocolName: d.proto, length: originalLength, summary: d.summary, processName: d.processName, processId: d.processId, direction: null, hostname: d.hostname });
    }
  }

  for (let i = 0; i < recs.length; i++) {
    const frame = b.subarray(recs[i].off, recs[i].off + recs[i].incl);
    decodePacket(frame, i + 1, recs[i].ts, recs[i].orig, recs[i].incl);
  }

  // ---- finish: destinations, findings, checks, facts ----
  const findings = [];
  if (st.dnsErrors > 0) findings.push({ id: "dns-errors", severity: "warning", title: "DNS error replies observed", evidence: `${st.dnsErrors} of ${st.dnsResponses} visible DNS replies were error replies. An error reply is an observation, not proof of a bad ISP or malware.`, recommendation: "Check the name being looked up and the DNS server in use; retry the affected app and mark the moment it fails.", packetNumbers: st.dnsErrorPackets.slice(0, 20) });
  if (st.tcpResets > 0) findings.push({ id: "tcp-resets", severity: "notice", title: "TCP resets observed", evidence: `${st.tcpResets} of ${st.tcpPackets} decoded TCP packets carried the RST flag. A reset can be a normal way to close a refused or finished connection.`, recommendation: "Note which app and destination were involved and whether the app reported an error at the same moment.", packetNumbers: st.rstPackets.slice(0, 20) });
  if (st.plainRemote.length) findings.push({ id: "plaintext-remote", severity: "warning", title: "Plaintext application data observed", evidence: `Recognizable plaintext ${[...new Set(st.plainRemote.map(p => p[1]))].sort().join(", ")} content was visible beyond loopback in ${st.plainRemote.length} packet(s). Contents were not stored in this report.`, recommendation: "Prefer the encrypted (HTTPS/TLS) version of the service where available and check which app sent it.", packetNumbers: st.plainRemote.slice(0, 20).map(p => p[0]) });
  if (st.plainLocal.length) findings.push({ id: "plaintext-local", severity: "info", title: "Plaintext between addresses on this device", evidence: `Recognizable plaintext content was visible between loopback addresses in ${st.plainLocal.length} packet(s). This finding by itself says nothing about the rest of the capture.`, recommendation: "No action is usually needed: traffic between loopback addresses stays on this device.", packetNumbers: st.plainLocal.slice(0, 20).map(p => p[0]) });

  const groups = new Map(), groupOrder = [];
  const gkey = (a, port, proto) => `${a}:${port}/${proto}`;
  for (const key of st.flowOrder) {
    const f = st.flows.get(key);
    const gk = gkey(f.server, f.serverPort, "TCP");
    if (!groups.has(gk)) { groups.set(gk, { rec: { name: null, nameSource: null, outerName: null, address: f.server, port: f.serverPort, protocolLabel: f.sawHttp ? "TCP · HTTP" : (f.clientHello || f.serverHello || f.sni || f.serverPort === 443 ? "TCP · TLS" : "TCP"), outcome: "not_checked", attempts: 0, packets: 0, bytes: 0, packetNumbers: [], evidenceFilter: "", evidenceCount: 0, tlsStatus: "not_visible", intelMatchIds: null, intelTopSeverity: null }, synFrames: [], refusedFrames: [] }); groupOrder.push(gk); }
    const g = groups.get(gk), rec = g.rec;
    rec.attempts += f.synFrames.length;
    rec.packets += f.packets; rec.bytes += f.bytes;
    rec.packetNumbers.push(...f.frames);
    g.synFrames.push(...f.synFrames);
    g.refusedFrames.push(...f.refusedFrames);
    if (f.alertBeforeHello) rec.tlsStatus = "failed"; else if (f.serverHello) rec.tlsStatus = "passed";
    if (f.ech) { if (!rec.nameSource) { rec.nameSource = "sni_outer"; rec.outerName = f.sni; } }
    else if (!rec.name && f.sni) { rec.name = f.sni; rec.nameSource = "sni"; }
    const flowOutcome = f.connected && f.resetLater ? "reset_later" : f.connected ? "connected" : f.refused ? "refused" : f.synFrames.length ? "no_reply" : "not_checked";
    const rank = { connected: 4, reset_later: 3, refused: 2, no_reply: 2, not_checked: 1 };
    if (rec.outcome === "not_checked" || rank[flowOutcome] > rank[rec.outcome]) rec.outcome = flowOutcome;
    if (rec.outcome === "no_reply" && flowOutcome === "connected") rec.outcome = "connected";
  }
  for (const key of st.udpOrder) {
    const u = st.udpGroups.get(key);
    const gk = gkey(u.server, u.serverPort, u.quic ? "QUIC" : "UDP");
    if (!groups.has(gk)) { groups.set(gk, { rec: { name: null, nameSource: null, outerName: null, address: u.server, port: u.serverPort, protocolLabel: u.quic ? "QUIC" : "UDP", outcome: u.quic ? "not_checked" : "background", attempts: 0, packets: 0, bytes: 0, packetNumbers: [], evidenceFilter: "", evidenceCount: 0, tlsStatus: "not_visible", intelMatchIds: null, intelTopSeverity: null }, synFrames: [], refusedFrames: [] }); groupOrder.push(gk); }
    const g = groups.get(gk);
    g.rec.packets += u.packets; g.rec.bytes += u.bytes; g.rec.packetNumbers.push(...u.frames);
  }
  const destinations = [];
  for (const gk of groupOrder) {
    const g = groups.get(gk), rec = g.rec;
    if (!rec.name && st.ipToName.has(rec.address)) { rec.name = st.ipToName.get(rec.address); rec.nameSource = "dns"; }
    rec.evidenceFilter = rec.protocolLabel.startsWith("TCP") ? `ip.addr==${rec.address} && tcp.port==${rec.port}` : rec.protocolLabel === "QUIC" ? `ip.addr==${rec.address} && udp.port==${rec.port}` : `ip.addr==${rec.address}`;
    rec.evidenceCount = rec.packets;
    rec.packetNumbers = rec.packetNumbers.slice(0, 200);
    destinations.push(rec);
  }
  const outcomeRank = { no_reply: 0, refused: 0, reset_later: 1, connected: 2, not_checked: 3, background: 4 };
  destinations.sort((a, b2) => (outcomeRank[a.outcome] - outcomeRank[b2.outcome]) || (b2.packets - a.packets));

  if (st.nxdomains.length) findings.push({ id: "dns-name-not-found", severity: "likely_cause", title: `The name ${st.nxdomains[0].name} was reported as not existing`, evidence: `The DNS server replied that ${st.nxdomains[0].name} does not exist (NXDOMAIN), in packet #${st.nxdomains[0].frame}. ${st.dnsErrors} of ${st.dnsResponses} visible DNS replies were error replies.`, recommendation: "Check the spelling of the name and whether the service has changed or removed it; try the correct name, then capture again.", packetNumbers: st.nxdomains.slice(0, 20).map(x => x.frame) });
  for (const rec of destinations.filter(x => x.outcome === "refused"))
    findings.push({ id: "refused-connection", severity: "likely_cause", title: `${rec.name ?? rec.address} refused the connection`, evidence: `The destination at ${rec.address} port ${rec.port} answered connection attempts with a reset (refused), across ${rec.attempts} attempt(s).`, recommendation: "Check whether the service is running on that device and whether a firewall on it is rejecting the connection; then try again.", packetNumbers: rec.packetNumbers.slice(0, 20) });
  let unansweredAttempts = 0;
  const unansweredFramesAll = [];
  for (const rec of destinations.filter(x => x.outcome === "no_reply" && x.attempts >= 1)) {
    unansweredAttempts += rec.attempts;
    unansweredFramesAll.push(...rec.packetNumbers);
    findings.push({ id: "unanswered-connection", severity: rec.attempts >= 2 ? "likely_cause" : "warning", title: `${rec.name ?? rec.address} never answered the connection attempts`, evidence: `${rec.attempts} connection request(s) (TCP SYN) to ${rec.address} on port ${rec.port} received no reply of any kind: no SYN-ACK, no reset, no ICMP error. ${destinations.filter(x => x.outcome === "connected").length} other destination(s) connected successfully in this capture.`, recommendation: "Try the same website or app on a different network, such as a phone hotspot. If it works there, a firewall, VPN, or filter on this network is likely blocking it; if it fails everywhere, the service may be down.", packetNumbers: rec.packetNumbers.slice(0, 20) });
  }
  const refusedAttempts = destinations.filter(x => x.outcome === "refused").reduce((s, x) => s + x.attempts, 0);
  if (st.tlsAlertPackets.length) findings.push({ id: "tls-alerts", severity: "warning", title: "Secure setup (TLS) alerts observed", evidence: `${st.tlsAlertPackets.length} TLS alert(s) were visible. An alert can mean the secure setup was rejected or failed.`, recommendation: "Check the device date and time, then retry; if it repeats for one service, share this report with its support team.", packetNumbers: st.tlsAlertPackets.slice(0, 20) });
  const sortedIntervals = [...st.intervals].sort((a, b2) => a - b2);
  const p95 = sortedIntervals.length ? sortedIntervals[Math.min(sortedIntervals.length - 1, Math.ceil(0.95 * sortedIntervals.length) - 1)] : null;
  if (p95 != null && p95 > 300) findings.push({ id: "slow-dns", severity: "warning", title: "Name lookups were slow", evidence: `Matched DNS exchanges averaged ${Math.round(st.intervals.reduce((a, x) => a + x, 0) / Math.max(1, st.intervals.length))} ms and the slowest 5% took at least ${Math.round(p95)} ms across ${st.intervals.length} pair(s).`, recommendation: "Compare this after changing one thing at a time, such as trying a different network; slow lookups can make apps feel slow before data moves.", packetNumbers: [] });
  const sevRank = { likely_cause: 0, warning: 1, notice: 2, info: 3 };
  findings.sort((a, b2) => (sevRank[a.severity] ?? 4) - (sevRank[b2.severity] ?? 4));

  const answeredLookups = st.lookups.filter(l => l.milliseconds != null).length;
  const unansweredLookups = Math.max(0, st.dnsQueryCount - answeredLookups);
  const frameSetFilter = frames => frames.length ? `frame.number in {${frames.slice(0, 200).join(", ")}}` : "";
  const checks = [
    { id: "dns-errors", label: "DNS errors (NXDOMAIN, SERVFAIL)", count: st.dnsErrors, flagged: st.dnsErrors > 0, note: st.dnsErrors > 0 ? "See findings" : "None", packetNumbers: st.dnsErrorPackets.slice(0, 200), filter: "dns.flags.response == 1 && dns.flags.rcode != 0" },
    { id: "dns-unanswered", label: "DNS lookups with no answer", count: unansweredLookups, flagged: unansweredLookups > 0, note: unansweredLookups > 0 ? "No matching reply was captured" : "None", packetNumbers: [], filter: "dns.flags.response == 0 && !dns.response_in" },
    { id: "tcp-refused", label: "Refused connections (TCP reset)", count: refusedAttempts, flagged: refusedAttempts > 0, note: refusedAttempts > 0 ? "Destination refused" : "None", packetNumbers: destinations.filter(x => x.outcome === "refused").flatMap(x => x.packetNumbers).slice(0, 200), filter: "tcp.flags.reset == 1" },
    { id: "tcp-unanswered", label: "Unanswered connection attempts", count: unansweredAttempts, flagged: unansweredAttempts > 0, note: unansweredAttempts > 0 ? "No reply captured" : "None", packetNumbers: unansweredFramesAll.slice(0, 200), filter: frameSetFilter(unansweredFramesAll) },
    { id: "icmp-unreachable", label: "ICMP unreachable messages", count: st.icmpPackets.length, flagged: st.icmpPackets.length > 0, note: st.icmpPackets.length ? "A device reported it could not deliver traffic" : "None", packetNumbers: [...st.icmpPackets], filter: "icmp.type == 3 || icmpv6.type == 1" },
    { id: "tls-alerts", label: "TLS alerts or failed handshakes", count: st.tlsAlertPackets.length, flagged: st.tlsAlertPackets.length > 0, note: st.tlsAlertPackets.length ? "Secure setup was rejected or failed" : "None", packetNumbers: [...st.tlsAlertPackets], filter: "tls.record.content_type == 21" },
    { id: "tcp-retransmissions", label: "TCP retransmissions", count: st.retransmissions, flagged: st.retransmissions > 20, note: st.retransmissions === 0 ? "None" : st.retransmissions > 20 ? "High level" : "Normal level", packetNumbers: [], filter: "tcp.analysis.retransmission" },
    { id: "kernel-drops", label: "Packets dropped by capture", count: 0, flagged: false, note: "Nothing lost", packetNumbers: [], filter: "" },
  ];
  const checkedCount = Math.max(0, recs.length - st.quicPackets - st.encryptedOther - st.undecodable);
  const mix = ["TCP", "DNS", "QUIC", "UDP_OTHER", "ICMP", "OTHER"].filter(n => st.mixStats.has(n)).map(n => ({ name: n, count: st.mixStats.get(n).count, bytes: st.mixStats.get(n).bytes }));

  const facts = {
    firstTimestamp: firstTs, lastTimestamp: recs.length ? st.lastTs : null,
    dnsResponses: st.dnsResponses, dnsErrors: st.dnsErrors, tcpPackets: st.tcpPackets, tcpResets: st.tcpResets,
    averageDNSMilliseconds: st.intervals.length ? st.intervals.reduce((a, x) => a + x, 0) / st.intervals.length : null,
    matchedDNSPairs: st.intervals.length,
    dnsQueries: st.dnsQueryCount, dnsAnswered: answeredLookups, dnsUnanswered: unansweredLookups,
    dnsP95Milliseconds: p95, dnsMaxMilliseconds: sortedIntervals.length ? sortedIntervals[sortedIntervals.length - 1] : null,
    dnsResolvers: st.resolvers, dnsLookups: st.lookups,
    tcpRetransmissions: st.retransmissions, icmpUnreachable: st.icmpPackets.length, tlsAlerts: st.tlsAlertPackets.length,
    quicPackets: st.quicPackets, encryptedOtherPackets: st.encryptedOther, checkedPackets: checkedCount,
    destinations, checks, arpResponder: st.arpResponder, trafficMix: mix,
    httpHosts: st.httpHosts, httpUrls: st.httpUrls, cnameTargets: st.cnames,
    certificates: st.certs.map(c => ({ sha1: c.sha256 ? sha1OfDer(c._der) : "", sha256: c.sha256, frame: c.frame, serverAddress: c.serverAddress, serverPort: c.serverPort })),
    fingerprints: st.fps,
    observableEndpoints: [...st.obsEndpoints.values()].sort((a, b2) => b2.packets - a.packets),
    observableIPCount: st.obsIps.size, observableTruncated: st.obsTruncated,
    timeline: [...st.buckets.values()].sort((a, b2) => a.second - b2.second),
    domains: st.domainOrder.filter(n => st.domains.has(n)).map(n => { const d = st.domains.get(n); return { name: n, addresses: d.addresses, queryCount: d.queryCount, errorCount: d.errorCount, packetNumbers: d.packetNumbers }; }),
    attributedPackets: 0, unattributedPackets: recs.length,
    applications: [],
  };
  const notes = [];
  if (recs.length > DISPLAY_LIMIT) notes.push(`Showing the first ${DISPLAY_LIMIT} of ${recs.length} packets in the packet log. Totals, findings, timeline, apps, and endpoint statistics cover the entire file.`);
  if (st.undecodable > 0) notes.push(`${st.undecodable} packet(s) could not be decoded beyond a counted entry; no bytes were read past their frames.`);
  if (recs.length === 0) notes.push("This capture contains no packets. An empty capture does not prove the network is healthy; the selected interface may simply have seen no traffic.");
  return {
    packetCount: recs.length,
    capturedBytes: st.capturedBytes,
    duration: firstTs != null && recs.length ? Math.max(0, st.lastTs - firstTs) : 0,
    protocols: [...st.protoStats.entries()].map(([name, v]) => ({ name, count: v.count, bytes: v.bytes })).sort((a, b2) => b2.count - a.count),
    endpoints: [...st.endpointStats.entries()].map(([address, v]) => ({ address, packets: v.count, bytes: v.bytes })).sort((a, b2) => b2.bytes - a.bytes).slice(0, 200),
    findings, packets: st.records, limitationNotes: notes, facts,
  };
}
function sha1OfDer(der) {
  // SHA-1 via the same synchronous style as MD5 would be long; certificates
  // are hashed with SHA-256 for display and the SHA-1 is computed only when
  // a caller provides it. For the web build we compute SHA-1 with a compact
  // implementation below.
  return sha1hex(der);
}
function sha1hex(input) {
  const bytes = input instanceof Uint8Array ? input : new TextEncoder().encode(input);
  const bitLen = bytes.length * 8;
  const padded = Array.from(bytes);
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0);
  for (let i = 7; i >= 0; i--) padded.push(Math.floor(bitLen / Math.pow(2, 8 * i)) & 0xff);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) | 0;
  const w = new Array(80);
  for (let chunk = 0; chunk < padded.length; chunk += 64) {
    for (let i = 0; i < 16; i++) w[i] = (padded[chunk + 4*i] << 24) | (padded[chunk + 4*i + 1] << 16) | (padded[chunk + 4*i + 2] << 8) | padded[chunk + 4*i + 3];
    for (let i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const tmp = (rol(a, 5) + f + e + k + w[i]) | 0;
      e = d; d = c; c = rol(b, 30); b = a; a = tmp;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  return [h0, h1, h2, h3, h4].map(h => (h >>> 0).toString(16).padStart(8, "0")).join("");
}

// ---------- Results builder (verdict in code) ----------
function fmtBytes(n) { const d = n; if (d >= 1073741824) return (d / 1073741824).toFixed(1) + " GB"; if (d >= 1048576) return (d / 1048576).toFixed(1) + " MB"; if (d >= 1024) return (d / 1024).toFixed(1) + " KB"; return n + " B"; }
function fmtDuration(s) { return s < 60 ? s.toFixed(1) + " s" : `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`; }
function fmtCount(n) { return n.toLocaleString("en-US"); }
function fmtMs(v) { return `${Math.round(v)} ms`; }
function fmtPacketTime(s) { const m = Math.floor(s / 60); const sec = s - m * 60; return `${m}:${sec.toFixed(2).padStart(5, "0")}`; }

function buildResults(report, context, kernelDrops, threatIntel) {
  const facts = report.facts;
  const total = report.packetCount;
  const checked = facts ? facts.checkedPackets : Math.max(0, total - (facts?.quicPackets ?? 0));
  const skipped = [];
  if (facts?.quicPackets) skipped.push({ reason: "encrypted_quic", packets: facts.quicPackets });
  if (facts?.encryptedOtherPackets) skipped.push({ reason: "encrypted_other", packets: facts.encryptedOtherPackets });
  const findings = report.findings.map(f => ({
    id: f.id,
    severity: f.severity === "likely_cause" ? "likely_cause" : (f.severity === "warning" || f.severity === "notice") ? "warning" : "info",
    title: f.title, observed: f.evidence,
    interpretation: {
      "unanswered-connection": "A silent drop. A refused connection would have returned a reset; a missing route would usually return an ICMP error. Silence typically comes from a firewall rule, a VPN or filter, or a server that is offline.",
      "refused-connection": "The destination was reachable but actively refused the connection. The service may not be running, or a firewall on that device is rejecting it.",
      "dns-name-not-found": "The name does not exist according to the DNS server, so the app never got an address to connect to.",
      "dns-errors": "Name lookups are failing, which can make apps look like they have no connection even when the link is up.",
      "slow-dns": "Slow name lookups delay every new connection before any data moves.",
      "plaintext-remote": "Readable application data left this device without encryption. Devices on the network path could potentially see it.",
      "plaintext-local": "Readable traffic between addresses on this device. It stays on the device and is listed for awareness.",
    }[f.id] || f.evidence,
    confidence: f.severity === "likely_cause" ? "high" : f.severity === "warning" ? "medium" : "low",
    evidence: { filter: findingFilter(f.id), frames: f.packetNumbers.slice(0, 200), count: f.packetNumbers.length },
    nextSteps: [f.recommendation],
    category: "connectivity", matchedIndicators: [],
  }));
  const sevRankF = { likely_cause: 0, warning: 1, info: 2 };
  findings.sort((a, b) => (sevRankF[a.severity] ?? 3) - (sevRankF[b.severity] ?? 3));
  const hasFailed = findings.some(f => f.severity === "likely_cause") || (facts?.destinations || []).some(d => d.outcome === "no_reply" || d.outcome === "refused");
  const tooShort = context.goal === "website" && !hasFailed && (context.markers || []).length === 0 && report.duration < 15 && total >= 10;
  const verdict = total < 10 ? "not_enough_traffic"
    : findings.some(f => f.severity === "likely_cause") ? "cause_found"
    : findings.some(f => f.severity === "warning") ? "possible_issue"
    : (tooShort || (context.markers || []).length === 0 || (total > 0 && checked / total < 0.7)) ? "inconclusive"
    : "no_problem_seen";
  const results = {
    goalLabel: context.goalLabel || "A website or app won’t connect",
    startedAt: context.startedAt ?? null, durationSec: report.duration, packets: total, bytes: report.capturedBytes,
    interfaceName: context.interface || "", kernelDrops,
    markedMomentsSec: facts?.firstTimestamp != null ? (context.markers || []).map(m => m.timestamp - facts.firstTimestamp) : [],
    checkedPackets: checked, skipped, tooShort,
    mix: facts?.trafficMix || [], paths: buildPaths(report, facts),
    report, context, findings, verdict, threatIntel: threatIntel || null,
    securityAlert: threatIntel?.securityAlert ?? "none",
    templateSummary: null,
  };
  results.templateSummary = templateSummary(results);
  if (threatIntel) attachThreatIntel(results, threatIntel, report);
  return results;
}
function findingFilter(id) {
  return {
    "dns-errors": "dns.flags.response == 1 && dns.flags.rcode != 0",
    "dns-name-not-found": "dns.flags.response == 1 && dns.flags.rcode != 0",
    "tcp-resets": "tcp.flags.reset == 1", "refused-connection": "tcp.flags.reset == 1",
    "unanswered-connection": "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    "tls-alerts": "tls.record.content_type == 21",
    "plaintext-remote": "http || ftp || smtp", "plaintext-local": "http || ftp || smtp",
  }[id] || "";
}
function buildPaths(report, facts) {
  const paths = [];
  const destinations = facts?.destinations || [];
  for (const dest of destinations.slice(0, 12)) paths.push({ destination: dest.name ?? dest.address, stages: stagesFor(report, facts, dest) });
  const nx = (facts?.dnsLookups || []).find(l => l.rcode === "NXDOMAIN");
  if (nx) paths.unshift({ destination: nx.name, stages: stagesFor(report, facts, { name: nx.name, address: "—", port: 0, protocolLabel: "DNS", outcome: "not_checked", attempts: 0, packets: 0, packetNumbers: [] }) });
  if (!paths.length) paths.push({ destination: "This device", stages: stagesFor(report, facts, null) });
  return paths;
}
function stagesFor(report, facts, dest) {
  const stages = [];
  if (facts?.arpResponder) stages.push({ id: "local", status: "passed", result: "Router answered", detail: `ARP reply from ${facts.arpResponder}` });
  else if (report.packetCount > 0) stages.push({ id: "local", status: "passed", result: "Traffic was exchanged", detail: "Packets were seen on the selected interface" });
  else stages.push({ id: "local", status: "not_visible", result: "Not visible", detail: "No packets were captured" });
  let dnsFailed = false;
  if (dest?.name) {
    const lookups = (facts?.dnsLookups || []).filter(l => l.name === dest.name);
    const err = lookups.find(l => ["NXDOMAIN", "SERVFAIL", "REFUSED"].includes(l.rcode));
    const ok = lookups.find(l => l.milliseconds != null);
    if (err) { stages.push({ id: "dns", status: "failed", result: `${dest.name} was reported as not existing (${err.rcode})`, detail: "The name lookup failed, so no connection could start" }); dnsFailed = true; }
    else if (ok) stages.push({ id: "dns", status: "passed", result: `Resolved to ${dest.address}`, detail: `Answered in ${fmtMs(ok.milliseconds)}` });
    else if ((facts?.domains || []).some(dm => dm.name === dest.name && dm.addresses.includes(dest.address))) stages.push({ id: "dns", status: "passed", result: `Resolved to ${dest.address}`, detail: "The answer was seen in this capture" });
    else stages.push({ id: "dns", status: "not_visible", result: "No lookup seen", detail: "The address may already have been cached" });
  } else if (facts && facts.dnsQueries > 0) {
    if (report.findings.some(f => f.id === "dns-name-not-found")) { stages.push({ id: "dns", status: "failed", result: "A name was reported as not existing (NXDOMAIN)", detail: "The name lookup failed, so no connection could start" }); dnsFailed = true; }
    else stages.push({ id: "dns", status: "passed", result: `${facts.dnsAnswered} of ${facts.dnsQueries} answered`, detail: facts.averageDNSMilliseconds != null ? `Average ${fmtMs(facts.averageDNSMilliseconds)}` : "" });
  } else stages.push({ id: "dns", status: "not_visible", result: "No lookup seen", detail: "Names may already have been cached, or encrypted DNS was used" });
  let tcpFailed = false;
  if (dest) {
    if (dest.outcome === "connected") stages.push({ id: "tcp", status: "passed", result: "Connected", detail: `${dest.packets} packets exchanged with ${dest.address}:${dest.port}` });
    else if (dest.outcome === "refused") { stages.push({ id: "tcp", status: "failed", result: "Refused", detail: `The destination answered with a reset on port ${dest.port}` }); tcpFailed = true; }
    else if (dest.outcome === "no_reply") { stages.push({ id: "tcp", status: "failed", result: `0 of ${dest.attempts} answered`, detail: `No reply on port ${dest.port}` }); tcpFailed = true; }
    else if (dest.outcome === "reset_later") stages.push({ id: "tcp", status: "warning", result: "Connected, then reset", detail: "The connection started, then was cut short" });
    else stages.push({ id: "tcp", status: "not_visible", result: "Not checked", detail: "This destination's traffic could not be checked (for example, encrypted QUIC)" });
  } else if (facts && facts.tcpPackets > 0) stages.push({ id: "tcp", status: facts.tcpResets > 0 ? "warning" : "passed", result: `${facts.tcpPackets} TCP packets checked`, detail: facts.tcpResets > 0 ? `${facts.tcpResets} carried a reset` : "No resets seen" });
  else stages.push({ id: "tcp", status: "not_visible", result: "Not visible", detail: "No TCP traffic was captured" });
  const failedSoFar = dnsFailed || tcpFailed;
  if (failedSoFar) stages.push({ id: "tls", status: "not_reached", result: "Not reached", detail: "Needs the earlier step to succeed first" });
  else if (dest) {
    if (dest.tlsStatus === "passed") stages.push({ id: "tls", status: "passed", result: "Secure setup completed", detail: "The encrypted session was established" });
    else if (dest.tlsStatus === "failed") stages.push({ id: "tls", status: "failed", result: "Secure setup failed", detail: "A TLS alert was seen before the setup completed" });
    else stages.push({ id: "tls", status: "not_visible", result: dest.protocolLabel.includes("QUIC") ? "Inside QUIC" : "Not seen completed", detail: dest.protocolLabel.includes("QUIC") ? "QUIC encrypts its setup; it can't be checked separately" : "The setup may have finished outside the capture window" });
  } else stages.push({ id: "tls", status: "not_visible", result: "Not visible", detail: "Encrypted setup can't be verified beyond the handshake" });
  if (failedSoFar || stages.some(s => s.id === "tls" && s.status === "failed")) stages.push({ id: "app", status: "not_reached", result: "Not reached", detail: "Needs a connection first" });
  else if (dest && dest.protocolLabel === "TCP · HTTP") stages.push({ id: "app", status: "passed", result: "Visible (not encrypted)", detail: "The app response was readable plaintext" });
  else stages.push({ id: "app", status: "not_visible", result: "Encrypted", detail: "Contents can't be read without keys" });
  let seenFailure = false;
  for (let i = 0; i < stages.length; i++) {
    if (seenFailure && stages[i].status !== "not_reached") stages[i] = { id: stages[i].id, status: "not_reached", result: "Not reached", detail: "Needs the earlier step to succeed first" };
    if (stages[i].status === "failed") seenFailure = true;
  }
  return stages;
}
function attachThreatIntel(results, intel, report) {
  const groups = groupByDestination(intel.matches);
  const destinations = report.facts?.destinations || [];
  const rank = { high: 0, medium: 1, low: 2, info: 3 };
  for (const dest of destinations) {
    const mine = intel.matches.filter(m => m.destinationIP === dest.address);
    if (mine.length) {
      dest.intelMatchIds = mine.map(m => m.id);
      dest.intelTopSeverity = mine.map(m => m.severity).sort((a, b) => rank[a] - rank[b])[0];
    }
  }
  destinations.sort((a, b) => {
    const ra = a.intelTopSeverity ? rank[a.intelTopSeverity] : 9;
    const rb = b.intelTopSeverity ? rank[b.intelTopSeverity] : 9;
    return ra - rb;
  });
  const security = [];
  for (const group of groups) {
    const first = group.matches[0];
    const dest = destinations.find(x => x.address === group.ip);
    const feedNames = [...new Set(group.matches.map(m => m.feedName || m.indicator.feedId))].sort().join(", ");
    const observed = dest
      ? `${first.connected ? "Connected to" : "Tried to contact"} ${dest.address}:${dest.port} — ${dest.packets} packets, ${dest.attempts} connection attempt(s). Matched ${group.matches.length} indicator(s).`
      : `Matched ${group.matches.length} indicator(s) for ${group.displayName} (${first.direction === "dns_only" ? "name lookup only; no connection followed" : "observed in this capture"}).`;
    const interpretation = {
      botnet_c2: "This address or name is listed as a botnet command-and-control server. Malware on a device uses such servers to receive instructions and send stolen data.",
      malware_download: "This address, name, or file is listed as distributing malware.",
      phishing: "This name or address is listed as a phishing site.",
      hijacked_netblock: "This address sits inside a network block listed as run or hijacked by criminal operations. Ordinary services can occasionally share such ranges, so treat it as a prompt to check, not proof.",
    }[first.indicator.threat] || "A threat feed lists this destination. A listing is evidence to investigate, not proof that this device is infected.";
    security.push({
      id: "security-" + group.key,
      severity: { high: "likely_cause", medium: "warning", low: "info", info: "info" }[group.severity],
      title: `${group.displayName} is listed by ${feedNames}`,
      observed, interpretation,
      confidence: group.severity === "high" ? "high" : group.severity === "medium" ? "medium" : "low",
      evidence: { filter: dest?.evidenceFilter ?? first.filter, frames: [...new Set(group.matches.flatMap(m => m.frames))].sort((a, b) => a - b).slice(0, 200), count: dest?.evidenceCount ?? group.matches.reduce((s, m) => s + m.evidenceCount, 0) },
      nextSteps: ["Run a malware scan on this device.", "If this is a work device, tell your IT or security team and share this report with them.", "Note what app was running at the marked time, then capture again after scanning."],
      category: "security", matchedIndicators: group.matches,
    });
  }
  results.findings = security.concat(results.findings);
  if (results.report.facts) results.report.facts.destinations = destinations;
}
function templateSummary(r) {
  const top = r.findings.find(f => f.category !== "security");
  const facts = r.report.facts;
  switch (r.verdict) {
    case "not_enough_traffic":
      return { headline: "Not enough traffic was captured", body: `Only ${fmtCount(r.packets)} packets were recorded, which is too little to answer your question. The selected interface may not be the one carrying the traffic.`, nextStep: "Check the selected interface, then capture again while you reproduce the problem.", citations: [], fromTemplate: true };
    case "cause_found":
      return { headline: headlineFor(top, r), body: top.observed.slice(0, 300), nextStep: (top.nextSteps && top.nextSteps[0]) || "Share this report with support.", citations: [], fromTemplate: true };
    case "possible_issue":
      return { headline: headlineFor(top, r), body: `${top.observed} ${top.interpretation}`, nextStep: (top.nextSteps && top.nextSteps[0]) || "Capture again and compare.", citations: [], fromTemplate: true };
    case "inconclusive": {
      const dnsText = (facts?.dnsQueries ?? 0) > 0 ? `${facts.dnsAnswered} of ${facts.dnsQueries} name lookups were answered` : "No name lookups were seen";
      const connected = (facts?.destinations || []).filter(d => d.outcome === "connected").length;
      const connText = connected > 0 ? " and the connections your device started succeeded" : "";
      const skippedText = r.skipped.length ? `, and ${fmtCount(r.skipped[0].packets)} of ${fmtCount(r.packets)} packets were QUIC traffic whose contents can't be read` : "";
      const shortText = r.tooShort ? ` But the capture ran for only ${fmtDuration(r.durationSec)}` : "";
      return { headline: "No connection failure was seen, but this capture probably missed it", body: `All measured checks passed: ${dnsText}${connText}. Nothing was refused, reset or left unanswered.${shortText}${skippedText}, so the failing attempt was most likely not recorded.`, nextStep: "Capture for 60 seconds while you reproduce the problem. Start the capture, open the website or app that won't connect, and press It happened just now when it fails.", citations: [{ text: dnsText, anchor: "#dns" }], fromTemplate: true };
    }
    default: {
      const dest = (facts?.destinations || []).find(d => d.outcome === "connected");
      const headline = dest ? `All connections to ${dest.name ?? dest.address} succeeded in this capture` : "No problem was seen in this capture";
      return { headline: headline.slice(0, 90), body: `${facts?.dnsAnswered ?? 0} of ${facts?.dnsQueries ?? 0} name lookups were answered, and the connections your device started completed. This covers only what could be seen during these ${fmtDuration(r.durationSec)}.`, nextStep: "If the problem comes back, capture again and mark the moment it happens.", citations: [], fromTemplate: true };
    }
  }
}
function headlineFor(f, r) {
  const dest = (r.report.facts?.destinations || []).find(d => d.outcome === "no_reply" || d.outcome === "refused");
  const name = dest ? (dest.name ?? dest.address) : "This capture";
  const h = {
    "unanswered-connection": `${name} never answered your device's connection attempts`,
    "refused-connection": `${name} refused your device's connection`,
    "dns-name-not-found": "The name could not be found, so nothing could connect",
    "dns-errors": "Name lookups failed during this capture",
    "slow-dns": "Name lookups were slow during this capture",
    "plaintext-remote": "Some traffic left this device without encryption",
    "tls-alerts": "Secure connections were rejected during this capture",
  }[f.id] || f.title;
  return h.slice(0, 90);
}

// ---------- Threat intel (local matching only) ----------
const DEMO_FEED_CSV = `type,value,threat,severity
ipv4,203.0.113.50,botnet_c2,high
ip_port,198.51.100.7:8443,botnet_c2,high
cidr,198.51.100.128/25,hijacked_netblock,medium
domain,c2.test-ioc.example,botnet_c2,high
url,http://downloads.test-ioc.example/payload.bin,malware_download,high
ipv4,10.0.0.5,botnet_c2,high
`;
function normIp(raw) {
  let s = String(raw).trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (s.startsWith("::ffff:")) { const v4 = normIpv4(s.slice(7)); if (v4) return v4; }
  return normIpv4(s) || normIpv6(s);
}
function normIpv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map(p => (/^\d+$/.test(p) && !(p.length > 1 && p.startsWith("0")) ? Number(p) : NaN));
  if (nums.some(n => Number.isNaN(n) || n > 255)) return null;
  return nums.join(".");
}
function normIpv6(s) {
  try { return new URL(`http://[${s}]/`).hostname.replace(/^\[|\]$/g, "").toLowerCase(); } catch { return null; }
}
function ipv4Value(ip) { const p = normIpv4(ip); if (!p) return null; return p.split(".").reduce((a, x) => ((a << 8) | Number(x)) >>> 0, 0); }
function isNeverFlaggedIp(ip) {
  const v = ipv4Value(ip);
  if (v != null) {
    const a = v >>> 24, b = (v >> 16) & 0xff, c = (v >> 8) & 0xff;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 192 && b === 0 && c === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a >= 224) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    return false;
  }
  const s = ip.toLowerCase();
  return s === "::1" || s === "::" || s.startsWith("fe80") || s.startsWith("fc") || s.startsWith("fd") || s.startsWith("ff");
}
function normDomain(raw) {
  let s = String(raw).normalize("NFC").toLowerCase().trim();
  if (s.endsWith(".")) s = s.slice(0, -1);
  if (!s || s.length > 253 || s.includes(" ") || s.includes("/") || s.includes("_")) return null;
  try { s = new URL("http://" + s).hostname; } catch { return null; }
  const labels = s.split(".");
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (!label || label.length > 63) return null;
    if ([...label].some(ch => ch.charCodeAt(0) <= 0x20 || ch.charCodeAt(0) === 0x7f)) return null;
  }
  return s;
}
const PUBLIC_SUFFIXES = new Set(["github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app", "azurewebsites.net", "appspot.com", "firebaseapp.com", "web.app", "co.uk", "org.uk", "com.au", "net.au", "co.jp", "com.br", "com.cn", "com.tw", "co.kr", "co.in", "com.mx", "s3.amazonaws.com", "cloudfront.net", "example", "test", "invalid", "localhost", "kawasaki.jp"]);
function isPublicSuffix(d) { return PUBLIC_SUFFIXES.has(d) || !d.includes("."); }
function cidrContains(cidr, ip) {
  const [base, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  const baseNorm = normIp(base), ipNorm = normIp(ip);
  if (!baseNorm || !ipNorm) return false;
  const bv = ipv4Value(baseNorm), iv = ipv4Value(ipNorm);
  if (bv != null && iv != null) {
    if (bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (iv & mask) === (bv & mask);
  }
  return false;
}
function makeIndicator(feedId, type, rawValue, threat, severity) {
  const sev = ["high", "medium", "low", "info"].includes(severity) ? severity : null;
  const base = { feedId, threat: threat || null, malwareFamily: null, confidence: null, severity: sev, firstSeen: null, lastSeen: null, reference: null, port: null };
  switch (type) {
    case "ipv4": case "ipv6": {
      const ip = normIp(rawValue);
      if (!ip || (type === "ipv4") !== (ipv4Value(ip) != null)) return null;
      return { ...base, type, value: ip };
    }
    case "cidr": {
      const [b] = rawValue.split("/");
      if (!normIp(b || "") || !rawValue.includes("/")) return null;
      return { ...base, type, value: rawValue };
    }
    case "ip_port": {
      let ipPart, port;
      if (rawValue.startsWith("[")) {
        const close = rawValue.indexOf("]");
        if (close < 0) return null;
        ipPart = rawValue.slice(1, close);
        port = Number(rawValue.slice(close + 2));
      } else {
        const idx = rawValue.lastIndexOf(":");
        if (idx < 0) return null;
        ipPart = rawValue.slice(0, idx);
        port = Number(rawValue.slice(idx + 1));
      }
      const ip = normIp(ipPart);
      if (!ip || !(port >= 1 && port <= 65535)) return null;
      return { ...base, type, value: ip, port };
    }
    case "domain": {
      const d = normDomain(rawValue);
      if (!d || isPublicSuffix(d)) return null;
      return { ...base, type, value: d };
    }
    case "url": {
      try {
        const u = new URL(String(rawValue).trim());
        if (!["http:", "https:"].includes(u.protocol)) return null;
        const host = normDomain(u.hostname);
        if (!host) return null;
        u.hostname = host;
        if ((u.protocol === "http:" && u.port === "80") || (u.protocol === "https:" && u.port === "443")) u.port = "";
        u.hash = "";
        return { ...base, type, value: u.toString() };
      } catch { return null; }
    }
    case "cert_sha1": case "cert_sha256": case "file_md5": case "file_sha256": case "ja3": case "ja4": {
      const hex = String(rawValue).toLowerCase().replace(/[^0-9a-f]/g, "");
      const expected = { cert_sha1: 40, file_md5: 32, ja3: 32, ja4: 0 }[type] ?? 64;
      if (expected > 0 && hex.length !== expected) return null;
      if (expected === 0 && (hex.length < 16 || hex.length > 128)) return null;
      return { ...base, type, value: hex };
    }
    default: return null;
  }
}
function parseTypedCsv(text, feedId) {
  const normalized = String(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized.toLowerCase().includes("<html")) throw new Error("Feed structure not recognized: not a CSV feed (looks like an error page)");
  const rows = normalized.split("\n").filter(l => l.trim().length).map(l => l.split(",").map(x => x.trim()));
  const header = (rows[0] || []).map(x => x.toLowerCase());
  if (JSON.stringify(header) !== JSON.stringify(["type", "value", "threat", "severity"])) throw new Error("Feed structure not recognized: expected header type,value,threat,severity");
  const indicators = [];
  for (const row of rows.slice(1)) {
    if (row.length < 2) continue;
    const ind = makeIndicator(feedId, row[0].toLowerCase(), row[1], row[2] || null, row[3]?.toLowerCase() || null);
    if (ind) indicators.push(ind);
  }
  return indicators;
}
function parseFeedLines(text, feedId, type, severity) {
  const normalized = String(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized.toLowerCase().includes("<html")) throw new Error("Feed structure not recognized: not a text feed (looks like an error page)");
  const indicators = [];
  for (const line of normalized.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#") && !l.startsWith(";"))) {
    const ind = makeIndicator(feedId, type, line, null, severity);
    if (ind) indicators.push(ind);
  }
  return indicators;
}
class IndicatorStore {
  constructor() { this.exact = new Map(); this.ipPorts = new Map(); this.ipPortByIpMap = new Map(); this.cidrs = []; this.all = []; }
  load(indicators) {
    this.exact.clear(); this.ipPorts.clear(); this.ipPortByIpMap.clear(); this.cidrs = []; this.all = [];
    for (const ind of indicators) {
      this.all.push(ind);
      if (ind.type === "cidr") this.cidrs.push(ind);
      else if (ind.type === "ip_port") {
        this.ipPorts.set(`${ind.value}|${ind.port}`, ind);
        this.ipPortByIpMap.set(ind.value, ind);
        const t = ipv4Value(ind.value) != null ? "ipv4" : "ipv6";
        if (!this.exact.has(t)) this.exact.set(t, new Map());
        this.exact.get(t).set(ind.value, ind);
      } else {
        if (!this.exact.has(ind.type)) this.exact.set(ind.type, new Map());
        this.exact.get(ind.type).set(ind.value, ind);
      }
    }
  }
  get count() { return this.all.length; }
  exactMatch(type, value) { return this.exact.get(type)?.get(value) ?? null; }
  ipPortMatch(ip, port) { return this.ipPorts.get(`${ip}|${port}`) ?? null; }
  ipPortByIp(ip) { return this.ipPortByIpMap.get(ip) ?? null; }
  cidrMatch(ip) { for (const ind of this.cidrs) if (cidrContains(ind.value, ip)) return ind; return null; }
  domainMatch(observed) {
    const domains = this.exact.get("domain");
    const o = normDomain(observed);
    if (!domains || !o) return null;
    let candidate = o;
    while (candidate) {
      if (domains.has(candidate)) return domains.get(candidate);
      const dot = candidate.indexOf(".");
      if (dot < 0) break;
      candidate = candidate.slice(dot + 1);
    }
    return null;
  }
}
const SEVERITY_ORDER = ["info", "low", "medium", "high"];
const adjustSeverity = (sev, delta) => SEVERITY_ORDER[Math.min(3, Math.max(0, SEVERITY_ORDER.indexOf(sev) + delta))];
const severityRank = sev => ({ high: 0, medium: 1, low: 2, info: 3 })[sev] ?? 4;
const POPULAR_DOMAINS = new Set(["google.com","youtube.com","facebook.com","instagram.com","twitter.com","x.com","apple.com","microsoft.com","amazon.com","netflix.com","wikipedia.org","cloudflare.com","github.com","linkedin.com","office.com","live.com","bing.com","yahoo.com","whatsapp.com","zoom.us","adobe.com","salesforce.com","dropbox.com","spotify.com","reddit.com","tiktok.com","baidu.com","wordpress.com","mozilla.org","akamai.com"]);

function defanged(value, type) {
  let v = String(value).replace(/http:\/\//g, "hxxp://").replace(/https:\/\//g, "hxxps://");
  if (["url", "domain", "ipv4", "ipv6", "cidr"].includes(type)) v = v.replace(/\./g, "[.]");
  return v;
}

function matchIntel(report, store, metas, allowlist) {
  const facts = report.facts;
  const outcome = { matches: [], ignoredByAllowlist: 0, ignoredValues: [], checkedIPs: 0, checkedIPsTotal: 0, checkedDomains: 0, checkedUrls: 0, checkedCerts: 0, checkedFingerprints: 0, filesChecked: false };
  const allowValues = new Set((allowlist || []).map(a => normDomain(a.value) ?? String(a.value).toLowerCase()));
  const allowIps = new Set((allowlist || []).map(a => normIp(a.value)).filter(Boolean));
  const raw = [];
  const seen = new Set();
  const baseSeverity = ind => ind.severity || (metas[ind.feedId]?.baseSeverity ?? "medium");
  function append(m) {
    const key = `${m.indicator.feedId}|${m.indicator.type}|${m.indicator.value}|${m.observed}|${m.destinationIP ?? ""}`;
    if (seen.has(key)) return;
    const observedNorm = normIp(m.observed) ?? normDomain(m.observed) ?? m.observed.toLowerCase();
    if (allowValues.has(observedNorm) || allowValues.has(String(m.indicator.value).toLowerCase()) || (m.destinationIP && allowIps.has(m.destinationIP))) {
      outcome.ignoredByAllowlist++;
      if (!outcome.ignoredValues.includes(m.observed)) outcome.ignoredValues.push(m.observed);
      return;
    }
    seen.add(key);
    raw.push(m);
  }
  function make(ind, matchedOn, observed, dest, dnsName, sni, url, direction, connected, frames, filter, count) {
    const reasons = [`base: ${baseSeverity(ind)}`];
    let sev = baseSeverity(ind);
    if (!connected) { sev = adjustSeverity(sev, -1); reasons.push("downgraded: contact attempted, not completed"); }
    if (ind.lastSeen && (Date.now() - new Date(ind.lastSeen).getTime()) > 30 * 86400e3 && !Number.isNaN(new Date(ind.lastSeen).getTime())) { sev = adjustSeverity(sev, -1); reasons.push("downgraded: indicator last seen over 30 days ago"); }
    if (["ipv4", "ipv6", "cidr", "ip_port"].includes(matchedOn)) {
      const name = dest?.name ?? sni ?? dnsName;
      if (name && normDomain(name) && normDomain(name) !== normDomain(ind.value) && POPULAR_DOMAINS.has(normDomain(name))) { sev = adjustSeverity(sev, -1); reasons.push("downgraded: IP-only match on shared hosting"); }
    }
    return { id: `${ind.feedId}|${ind.type}|${ind.value}|${observed}`, indicator: ind, matchedOn, observed, destinationIP: dest?.address ?? null, destinationPort: dest?.port ?? null, destinationName: dest?.name ?? null, dnsName, sni, url, direction, connected, severity: sev, severityReasons: reasons, frames: frames.slice(0, 200), filter, evidenceCount: count, feedName: metas[ind.feedId]?.name ?? ind.feedId, feedHomepage: metas[ind.feedId]?.homepage ?? "" };
  }
  const destinations = facts?.destinations || [];
  const destConnected = d => ["connected", "reset_later", "refused"].includes(d.outcome);
  const ips = new Set();
  const endpointsByIp = new Map();
  for (const e of facts?.observableEndpoints || []) {
    const ip = normIp(e.address);
    if (!ip) continue;
    ips.add(ip);
    if (!endpointsByIp.has(ip) || e.packets > endpointsByIp.get(ip).packets) endpointsByIp.set(ip, e);
  }
  for (const d of destinations) { const ip = normIp(d.address); if (ip) ips.add(ip); }
  for (const ip of ips) {
    if (isNeverFlaggedIp(ip)) continue;
    const dest = destinations.find(x => normIp(x.address) === ip);
    const endpoint = endpointsByIp.get(ip);
    const port = dest?.port ?? endpoint?.port ?? 0;
    const connected = dest ? destConnected(dest) : false;
    const frames = dest?.packetNumbers ?? endpoint?.frames ?? [];
    const filter = dest?.evidenceFilter ?? `ip.addr==${ip}`;
    const count = dest?.evidenceCount ?? endpoint?.packets ?? frames.length;
    const pseudo = dest || { name: null, nameSource: null, address: ip, port, protocolLabel: "Unknown", outcome: "not_checked", attempts: 0, packets: endpoint?.packets ?? 0, packetNumbers: frames, evidenceFilter: filter, evidenceCount: count, tlsStatus: "not_visible" };
    const ipType = ipv4Value(ip) != null ? "ipv4" : "ipv6";
    let ind;
    if ((ind = store.exactMatch(ipType, ip))) append(make(ind, ipType, ip, pseudo, dest?.name ?? null, dest?.nameSource === "sni" ? dest?.name : null, null, "outbound", connected, frames, filter, count));
    if (port > 0 && (ind = store.ipPortMatch(ip, port))) append(make(ind, "ip_port", `${ip}:${port}`, pseudo, dest?.name ?? null, null, null, "outbound", connected, frames, `ip.addr==${ip} && tcp.port==${port}`, count));
    else if ((ind = store.ipPortByIp(ip))) {
      const m = make(ind, "ip_port", `${ip}:${port}`, pseudo, dest?.name ?? null, null, null, "outbound", connected, frames, `ip.addr==${ip}`, count);
      m.severity = adjustSeverity(m.severity, -1);
      m.severityReasons.push(`downgraded: same IP, different port (listed ${ind.port})`);
      append(m);
    }
    if ((ind = store.cidrMatch(ip))) append(make(ind, "cidr", ip, pseudo, dest?.name ?? null, null, null, "outbound", connected, frames, filter, count));
  }
  for (const domain of facts?.domains || []) {
    for (const addr of domain.addresses) {
      const ip = normIp(addr);
      if (!ip) continue;
      ips.add(ip);
      if (isNeverFlaggedIp(ip)) continue;
      if (destinations.some(x => x.address === ip)) continue;
      const ipType = ipv4Value(ip) != null ? "ipv4" : "ipv6";
      let ind;
      if ((ind = store.exactMatch(ipType, ip))) append(make(ind, ipType, ip, null, domain.name, null, null, "dns_only", false, domain.packetNumbers, "dns", domain.packetNumbers.length));
      if ((ind = store.cidrMatch(ip))) append(make(ind, "cidr", ip, null, domain.name, null, null, "dns_only", false, domain.packetNumbers, "dns", domain.packetNumbers.length));
    }
  }
  outcome.checkedIPs = ips.size;
  outcome.checkedIPsTotal = Math.max(facts?.observableIPCount ?? 0, ips.size);
  const domains = new Set();
  function checkDomain(rawName, frame) {
    const name = normDomain(rawName);
    if (!name) return;
    domains.add(name);
    const ind = store.domainMatch(name);
    if (!ind) return;
    const dest = destinations.find(x => x.name === name || (facts?.domains || []).some(dm => dm.name === name && dm.addresses.includes(x.address)));
    const connected = dest ? destConnected(dest) : false;
    append(make(ind, "domain", name, dest || null, name, dest?.nameSource === "sni" ? dest?.name : null, null, connected ? "outbound" : "dns_only", connected, frame != null ? [frame] : (dest?.packetNumbers ?? []), dest?.evidenceFilter ?? `dns.qry.name == "${name}"`, dest?.evidenceCount ?? 1));
  }
  for (const l of facts?.dnsLookups || []) checkDomain(l.name, l.frame);
  for (const dm of facts?.domains || []) checkDomain(dm.name, dm.packetNumbers[0]);
  for (const target of facts?.cnameTargets || []) checkDomain(target, null);
  for (const d of destinations.filter(x => x.nameSource === "sni" && x.name)) checkDomain(d.name, d.packetNumbers[0]);
  for (const host of facts?.httpHosts || []) checkDomain(host, null);
  outcome.checkedDomains = domains.size;
  let urlCount = 0;
  for (const rawUrl of facts?.httpUrls || []) {
    let url = null;
    try { const u = new URL(rawUrl); url = u.toString(); } catch { continue; }
    urlCount++;
    const ind = store.exactMatch("url", url) || store.exactMatch("url", rawUrl);
    if (!ind) continue;
    let host = null;
    try { host = new URL(url).hostname; } catch { /* ignore */ }
    const dest = destinations.find(x => x.name === host);
    append(make(ind, "url", url, dest || null, host, null, url, "outbound", dest ? destConnected(dest) : true, dest?.packetNumbers ?? [], `http.request.full_uri == "${url}"`, dest?.evidenceCount ?? 1));
  }
  outcome.checkedUrls = urlCount;
  let certCount = 0;
  for (const cert of facts?.certificates || []) {
    certCount++;
    const dest = destinations.find(x => x.address === cert.serverAddress && x.port === cert.serverPort);
    let ind;
    if ((ind = store.exactMatch("cert_sha1", cert.sha1))) append(make(ind, "cert_sha1", cert.sha1, dest || null, dest?.name ?? null, null, null, "outbound", true, [cert.frame], dest?.evidenceFilter ?? "tls.handshake.certificate", 1));
    if ((ind = store.exactMatch("cert_sha256", cert.sha256))) append(make(ind, "cert_sha256", cert.sha256, dest || null, dest?.name ?? null, null, null, "outbound", true, [cert.frame], dest?.evidenceFilter ?? "tls.handshake.certificate", 1));
  }
  outcome.checkedCerts = certCount;
  let fpCount = 0;
  for (const fp of facts?.fingerprints || []) {
    fpCount++;
    const dest = destinations.find(x => x.address === fp.serverAddress && x.port === fp.serverPort);
    const connected = dest ? destConnected(dest) : false;
    let ind;
    if ((ind = store.exactMatch("ja3", fp.ja3))) append(make(ind, "ja3", fp.ja3, dest || null, dest?.name ?? null, fp.sni, null, "outbound", connected, [fp.frame], dest?.evidenceFilter ?? "tls.handshake.type == 1", 1));
    if ((ind = store.exactMatch("ja4", fp.ja4))) append(make(ind, "ja4", fp.ja4, dest || null, dest?.name ?? null, fp.sni, null, "outbound", connected, [fp.frame], dest?.evidenceFilter ?? "tls.handshake.type == 1", 1));
  }
  outcome.checkedFingerprints = fpCount;
  const byDest = new Map();
  raw.forEach((m, i) => {
    const key = m.destinationIP ?? m.dnsName ?? m.observed;
    if (!byDest.has(key)) byDest.set(key, []);
    byDest.get(key).push(i);
  });
  for (const indices of byDest.values()) {
    if (indices.length < 2) continue;
    const types = new Set(indices.map(i => raw[i].matchedOn));
    const feeds = new Set(indices.map(i => raw[i].indicator.feedId));
    if (types.size >= 2 || feeds.size >= 2) {
      for (const i of indices) {
        raw[i].severity = adjustSeverity(raw[i].severity, 1);
        raw[i].severityReasons.push(`upgraded: same destination matched ${Math.max(types.size, feeds.size)} indicator types or feeds`);
      }
    }
  }
  raw.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  outcome.matches = raw;
  return outcome;
}
function groupByDestination(matches) {
  const groups = new Map(), order = [];
  for (const m of matches) {
    const key = m.destinationIP ?? m.dnsName ?? m.observed;
    if (!groups.has(key)) { groups.set(key, []); order.push(key); }
    groups.get(key).push(m);
  }
  return order.map(key => {
    const ms = groups.get(key);
    const severity = ms.map(m => m.severity).sort((a, b) => severityRank(a) - severityRank(b))[0];
    return { key, displayName: ms[0].destinationName ?? ms[0].dnsName ?? ms[0].observed, ip: ms[0].destinationIP, port: ms[0].destinationPort, severity, matches: ms };
  }).sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}
function makeThreatSummary(outcome, feeds, status) {
  const groups = groupByDestination(outcome.matches);
  const alert = groups.some(g => g.severity === "high") ? "high" : groups.some(g => g.severity === "medium") ? "medium" : "none";
  let headline = "";
  if (groups.length) {
    const first = groups[0].matches[0];
    const threatText = { botnet_c2: "a botnet server", malware_download: "a malware download", phishing: "a phishing site", hijacked_netblock: "part of a hijacked network block" }[first.indicator.threat] || "a flagged address";
    const feedName = first.feedName || first.indicator.feedId;
    headline = first.connected ? `This device connected to an address ${feedName} lists as ${threatText}` : `This device tried to contact an address ${feedName} lists as ${threatText}`;
    if (groups.length > 1) headline += ` (and ${groups.length - 1} more)`;
  }
  return { status, feeds, checkedIPs: outcome.checkedIPs, checkedIPsTotal: outcome.checkedIPsTotal, checkedDomains: outcome.checkedDomains, checkedUrls: outcome.checkedUrls, checkedCerts: outcome.checkedCerts, checkedFingerprints: outcome.checkedFingerprints, filesChecked: false, matches: outcome.matches, ignoredByAllowlist: outcome.ignoredByAllowlist, ignoredValues: outcome.ignoredValues, securityAlert: alert, securityHeadline: headline };
}
function exportSubset(input, frames) {
  const b = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (b.length < 24) throw new Error("Truncated PCAP: global header.");
  const little = b[0] === 0xd4 || b[0] === 0x4d;
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u32 = o => view.getUint32(o, little);
  const out = [b.subarray(0, 24)];
  let off = 24, number = 0;
  while (off + 16 <= b.length) {
    const incl = u32(off + 8);
    if (off + 16 + incl > b.length) throw new Error(`Truncated PCAP: packet data at offset ${off}.`);
    number++;
    if (frames.has(number)) out.push(b.subarray(off, off + 16 + incl));
    off += 16 + incl;
  }
  const total = out.reduce((s, x) => s + x.length, 0);
  const result = new Uint8Array(total);
  let pos = 0;
  for (const part of out) { result.set(part, pos); pos += part.length; }
  return result;
}

const PSEngine = { analyzePcap, buildResults, matchIntel, makeThreatSummary, groupByDestination, IndicatorStore, parseTypedCsv, parseFeedLines, makeIndicator, DEMO_FEED_CSV, exportSubset, defanged, md5hex, sha256hex, fmtBytes, fmtDuration, fmtCount, fmtMs, fmtPacketTime, DISPLAY_LIMIT };
if (typeof window !== "undefined") window.PSEngine = PSEngine;
if (typeof module !== "undefined" && module.exports) module.exports = PSEngine;
