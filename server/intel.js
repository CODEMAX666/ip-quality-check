import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "data", "intel.json");

let serverIndex = new Map();
let vpnRanges = [];
let vpnRangesV6 = [];
let dcRanges = [];
let dcRangesV6 = [];
let relayRanges = [];
let relayRangesV6 = [];
let hostingAsns = new Map();
let meta = { loaded: false };

load();

export function load() {
  if (!fs.existsSync(FILE)) {
    meta = { loaded: false, reason: "data/intel.json missing — run npm run update-intel" };
    return meta;
  }
  const intel = JSON.parse(fs.readFileSync(FILE, "utf8"));

  serverIndex = new Map();
  for (const [provider, ips] of Object.entries(intel.vpnServers || {})) {
    for (const ip of ips) {
      const list = serverIndex.get(ip);
      if (list) {
        if (!list.includes(provider)) list.push(provider);
      } else {
        serverIndex.set(ip, [provider]);
      }
    }
  }

  vpnRanges = buildRanges(intel.vpnCidrs);
  vpnRangesV6 = buildRangesV6(intel.vpnCidrsV6 || intel.vpnCidrs);
  dcRanges = buildRanges(intel.datacenterCidrs);
  dcRangesV6 = buildRangesV6(intel.datacenterCidrsV6 || intel.datacenterCidrs);
  relayRanges = buildRanges(intel.relayCidrs);
  relayRangesV6 = buildRangesV6(intel.relayCidrsV6 || intel.relayCidrs);
  hostingAsns = new Map(
    Object.entries(intel.hostingAsns || {}).map(([asn, name]) => [Number(asn), name])
  );

  meta = {
    loaded: true,
    generatedAt: intel.generatedAt,
    vpnServerIps: serverIndex.size,
    vpnRanges: vpnRanges.length + vpnRangesV6.length,
    vpnRangesV4: vpnRanges.length,
    vpnRangesV6: vpnRangesV6.length,
    datacenterRanges: dcRanges.length + dcRangesV6.length,
    datacenterRangesV4: dcRanges.length,
    datacenterRangesV6: dcRangesV6.length,
    relayRanges: relayRanges.length + relayRangesV6.length,
    relayRangesV4: relayRanges.length,
    relayRangesV6: relayRangesV6.length,
    hostingAsns: hostingAsns.size,
  };
  return meta;
}

export function intelMeta() {
  return meta;
}

export function vpnServerProviders(ip) {
  return serverIndex.get(ip) || null;
}

export function inVpnRange(ip) {
  return ip && ip.includes(":") ? containsV6(vpnRangesV6, ip) : contains(vpnRanges, ip);
}

export function inDatacenterRange(ip) {
  return ip && ip.includes(":") ? containsV6(dcRangesV6, ip) : contains(dcRanges, ip);
}

export function inPrivateRelay(ip) {
  return ip && ip.includes(":") ? containsV6(relayRangesV6, ip) : contains(relayRanges, ip);
}

export function hostingAsnName(asn) {
  if (asn == null) return null;
  return hostingAsns.has(Number(asn)) ? hostingAsns.get(Number(asn)) || "listed hosting ASN" : null;
}

function buildRanges(cidrs = []) {
  const ranges = [];
  for (const cidr of cidrs) {
    const [base, bitsRaw] = cidr.split("/");
    const start = toInt(base);
    if (start == null) continue;
    const bits = bitsRaw == null ? 32 : Number(bitsRaw);
    const size = 2 ** (32 - bits);
    const first = start - (start % size);
    ranges.push([first, first + size - 1]);
  }
  ranges.sort((a, b) => a[0] - b[0]);

  const merged = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range[0] <= last[1] + 1) {
      last[1] = Math.max(last[1], range[1]);
    } else {
      merged.push([range[0], range[1]]);
    }
  }
  return merged;
}

function contains(ranges, ip) {
  const n = toInt(ip);
  if (n == null || !ranges.length) return false;
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end] = ranges[mid];
    if (n < start) hi = mid - 1;
    else if (n > end) lo = mid + 1;
    else return true;
  }
  return false;
}

function toInt(ip) {
  if (typeof ip !== "string" || ip.includes(":")) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const v = Number(part);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function buildRangesV6(cidrs = []) {
  const ranges = [];
  for (const item of cidrs) {
    if (Array.isArray(item) && item.length === 2) {
      ranges.push([BigInt("0x" + item[0]), BigInt("0x" + item[1])]);
      continue;
    }
    if (typeof item !== "string" || !item.includes(":")) continue;
    const [base, bitsRaw] = item.split("/");
    const start = toBigIntV6(base);
    if (start == null) continue;
    const bits = bitsRaw == null ? 128 : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 128) continue;
    const shift = BigInt(128 - bits);
    const first = shift === 128n ? 0n : (start >> shift) << shift;
    const size = shift === 128n ? (1n << 128n) : (1n << shift);
    ranges.push([first, first + size - 1n]);
  }
  ranges.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const merged = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range[0] <= last[1] + 1n) {
      if (range[1] > last[1]) last[1] = range[1];
    } else {
      merged.push([range[0], range[1]]);
    }
  }
  return merged;
}

function containsV6(ranges, ip) {
  const n = toBigIntV6(ip);
  if (n == null || !ranges.length) return false;
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end] = ranges[mid];
    if (n < start) hi = mid - 1;
    else if (n > end) lo = mid + 1;
    else return true;
  }
  return false;
}

function toBigIntV6(ip) {
  if (typeof ip !== "string" || !ip.includes(":")) return null;
  const zone = ip.indexOf("%");
  const clean = (zone !== -1 ? ip.slice(0, zone) : ip).toLowerCase().trim();
  const parts = clean.split("::");
  if (parts.length > 2) return null;
  const expand = (s) => {
    if (!s) return [];
    const out = [];
    for (const g of s.split(":")) {
      if (g.includes(".")) {
        const v4 = g.split(".").map(Number);
        if (v4.length !== 4 || v4.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
        out.push(((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16));
      } else {
        out.push(g);
      }
    }
    return out;
  };
  const left = expand(parts[0]);
  const right = parts.length === 2 ? expand(parts[1]) : [];
  if (!left || !right) return null;
  const missing = 8 - (left.length + right.length);
  if (parts.length === 1 ? missing !== 0 : missing < 1) return null;
  const full = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right];
  if (full.length !== 8) return null;
  let n = 0n;
  for (const h of full) {
    if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
    n = (n << 16n) | BigInt(parseInt(h, 16));
  }
  return n;
}
