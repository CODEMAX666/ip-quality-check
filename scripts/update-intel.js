import fs from "node:fs/promises";
import { resolve4 } from "node:dns/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ANONYMIZER_ASNS } from "../server/lists.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(root, "data", "intel.json");

const GLUETUN = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers";
const GLUETUN_PROVIDERS = [
  ["airvpn", "AirVPN"],
  ["cyberghost", "CyberGhost"],
  ["expressvpn", "ExpressVPN"],
  ["fastestvpn", "FastestVPN"],
  ["giganews", "Giganews VyprVPN"],
  ["hidemyass", "HideMyAss"],
  ["ipvanish", "IPVanish"],
  ["ivpn", "IVPN"],
  ["mullvad", "Mullvad"],
  ["nordvpn", "NordVPN"],
  ["ovpn", "OVPN"],
  ["privado", "PrivadoVPN"],
  ["private internet access", "Private Internet Access"],
  ["privatevpn", "PrivateVPN"],
  ["protonvpn", "Proton VPN"],
  ["purevpn", "PureVPN"],
  ["slickvpn", "SlickVPN"],
  ["surfshark", "Surfshark"],
  ["torguard", "TorGuard"],
  ["vpn unlimited", "VPN Unlimited"],
  ["vpnsecure", "VPNSecure"],
  ["vyprvpn", "VyprVPN"],
  ["windscribe", "Windscribe"],
];

async function get(url, as = "text", init = {}) {
  const res = await fetch(url, {
    ...init,
    headers: {
      "user-agent": "handshake-geo/1.0 intel-updater",
      ...(init.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return as === "json" ? res.json() : res.text();
}

function collectIps(node, out) {
  if (!node) return;
  if (Array.isArray(node)) {
    node.forEach((n) => collectIps(n, out));
    return;
  }
  if (typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    if ((key === "ips" || key === "ipv4_addr_in" || key === "ips_exit") && Array.isArray(value)) {
      value.forEach((ip) => isV4(ip) && out.add(ip));
    } else if (
      (key === "ip" ||
        key === "ip2" ||
        key === "ip3" ||
        key === "ipv4_addr_in" ||
        key === "station" ||
        key === "ip_address" ||
        key === "exit_ip" ||
        key === "entry_ip" ||
        key === "ip_v4_in1" ||
        key === "ip_v4_in2" ||
        key === "ip_v4_in3" ||
        key === "ip_v4_in4") &&
      isV4(value)
    ) {
      out.add(value);
    } else if (typeof value === "object") {
      collectIps(value, out);
    }
  }
}

function addProviderIps(vpnServers, name, ips) {
  const set = new Set(vpnServers[name] || []);
  for (const ip of ips) {
    if (isV4(ip)) set.add(ip);
  }
  if (set.size) vpnServers[name] = [...set];
}

function isV4(value) {
  return typeof value === "string" && /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

function parseAsnLines(text) {
  const map = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*AS?(\d+)\s*(?:#\s*(.*))?$/i);
    if (m) map[m[1]] = (m[2] || "").trim();
  }
  return map;
}

function parseBadAsnCsv(text) {
  const map = {};
  for (const line of text.split(/\r?\n/).slice(1)) {
    const m = line.match(/^(\d+),"?(.*?)"?$/);
    if (m) map[m[1]] = m[2];
  }
  return map;
}

function cidrLines(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.split("#")[0].trim())
    .filter((l) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(l));
}

function cidrLinesV6(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.split("#")[0].trim())
    .filter((l) => l.includes(":") && /^[0-9a-f:]+\/\d{1,3}$/i.test(l));
}

function collectHostFields(node, out) {
  if (!node) return;
  if (Array.isArray(node)) {
    node.forEach((item) => collectHostFields(item, out));
    return;
  }
  if (typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    if ((key === "host" || key === "hostname" || key === "connectionName") && typeof value === "string") {
      const host = value.split(":")[0].trim().toLowerCase();
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host) && !host.endsWith(".png")) out.add(host);
    } else if (value && typeof value === "object") {
      collectHostFields(value, out);
    }
  }
}

async function resolveHosts(hosts) {
  const ips = [];
  const pending = [...hosts];
  async function worker() {
    while (pending.length) {
      const host = pending.pop();
      try {
        for (const ip of await resolve4(host)) {
          if (isV4(ip)) ips.push(ip);
        }
      } catch {
        // one dead hostname must not lose the rest
      }
    }
  }
  const workers = Math.min(24, Math.max(1, pending.length));
  await Promise.all(Array.from({ length: workers }, () => worker()));
  return ips;
}

async function announcedPrefixesForAsns(asns) {
  const list = [...asns];
  const v4 = [];
  const v6 = [];
  let failures = 0;
  let cursor = 0;
  async function worker() {
    while (cursor < list.length) {
      const asn = list[cursor++];
      try {
        const data = await get(
          `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`,
          "json"
        );
        for (const row of data?.data?.prefixes || []) {
          const prefix = row?.prefix;
          if (typeof prefix !== "string") continue;
          if (prefix.includes(":")) {
            if (/^[0-9a-f:]+\/\d{1,3}$/i.test(prefix)) v6.push(prefix);
          } else if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(prefix)) {
            const bits = Number(prefix.split("/")[1]);
            if (bits >= 8 && bits <= 32) v4.push(prefix);
          }
        }
      } catch (error) {
        failures++;
        console.warn(`fail ripestat AS${asn}: ${error.message}`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(6, Math.max(1, list.length)) }, () => worker()));
  if (list.length && failures === list.length) {
    throw new Error(`all ${list.length} RIPEstat prefix lookups failed`);
  }
  return { v4, v6 };
}

function ipLines(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const clean = line.split("#")[0].trim();
    if (!clean) continue;
    const m = clean.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/32)?$/);
    if (m && isV4(m[1])) out.push(m[1]);
  }
  return out;
}

function geofeedV4(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.split("#")[0].split(",")[0].trim())
    .filter((c) => /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(c));
}

function geofeedV6(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.split("#")[0].split(",")[0].trim())
    .filter((c) => c.includes(":") && /^[0-9a-f:]+\/\d{1,3}$/i.test(c));
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

function mergeV6ToHexPairs(cidrs) {
  const ranges = [];
  for (const cidr of cidrs) {
    if (!cidr || !cidr.includes(":")) continue;
    const [base, bitsRaw] = cidr.split("/");
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
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1n) {
      if (r[1] > last[1]) last[1] = r[1];
    } else {
      merged.push([r[0], r[1]]);
    }
  }
  return merged.map(([a, b]) => [a.toString(16), b.toString(16)]);
}

async function step(label, fn) {
  try {
    const value = await fn();
    console.log(`ok   ${label}`);
    return value;
  } catch (error) {
    console.warn(`fail ${label}: ${error.message}`);
    return null;
  }
}

const vpnServers = {};
for (const [file, name] of GLUETUN_PROVIDERS) {
  const data = await step(`gluetun ${name}`, () =>
    get(`${GLUETUN}/${encodeURIComponent(file)}.json`, "json")
  );
  if (!data) continue;
  const ips = new Set();
  collectIps(data, ips);
  addProviderIps(vpnServers, name, ips);
}

// Direct Mullvad relay API
const mullvad = await step("mullvad relay list", () =>
  get("https://api.mullvad.net/www/relays/all/", "json")
);
if (mullvad) {
  const ips = new Set();
  collectIps(mullvad, ips);
  addProviderIps(vpnServers, "Mullvad", ips);
}

// Direct NordVPN server API
const nordApi = await step("nordvpn server api", () =>
  get("https://api.nordvpn.com/v1/servers?limit=20000", "json")
);
if (nordApi) {
  const ips = new Set();
  collectIps(nordApi, ips);
  addProviderIps(vpnServers, "NordVPN", ips);
}

// Direct Windscribe server list API
const windscribeApi = await step("windscribe server list", () =>
  get("https://assets.windscribe.com/serverlist/openvpn/1/1", "json")
);
if (windscribeApi) {
  const ips = new Set();
  collectIps(windscribeApi, ips);
  addProviderIps(vpnServers, "Windscribe", ips);
}

// Direct Private Internet Access (PIA) v6 server list
const piaApi = await step("pia v6 server list", async () => {
  const text = await get("https://serverlist.piaservers.net/vpninfo/servers/v6");
  return JSON.parse(text.split(/\r?\n/)[0]);
});
if (piaApi) {
  const ips = new Set();
  collectIps(piaApi, ips);
  addProviderIps(vpnServers, "Private Internet Access", ips);
}

// Direct AirVPN status API
const airvpnApi = await step("airvpn status api", () =>
  get("https://airvpn.org/api/status/", "json")
);
if (airvpnApi) {
  const ips = new Set();
  collectIps(airvpnApi, ips);
  addProviderIps(vpnServers, "AirVPN", ips);
}

// Direct IVPN v4 servers API
const ivpnApi = await step("ivpn v4 servers", () =>
  get("https://api.ivpn.net/v4/servers.json", "json")
);
if (ivpnApi) {
  const ips = new Set();
  collectIps(ivpnApi, ips);
  addProviderIps(vpnServers, "IVPN", ips);
}

// Direct OVPN v2 client entry API
const ovpnApi = await step("ovpn v2 servers", () =>
  get("https://www.ovpn.com/v2/api/client/entry", "json")
);
if (ovpnApi) {
  const ips = new Set();
  collectIps(ovpnApi, ips);
  addProviderIps(vpnServers, "OVPN", ips);
}

// Direct Riseup VPN LEAP eip-service API
const riseupApi = await step("riseup eip-service", () =>
  get("https://api.black.riseup.net/3/config/eip-service.json", "json")
);
if (riseupApi) {
  const ips = new Set();
  collectIps(riseupApi, ips);
  addProviderIps(vpnServers, "Riseup VPN", ips);
}

// Direct SoftEther / VPN Gate iPhone relay CSV API
const vpngateCsv = await step("softether vpngate csv", () =>
  get("http://www.vpngate.net/api/iphone/")
);
if (vpngateCsv) {
  const ips = [];
  for (const line of vpngateCsv.split(/\r?\n/)) {
    if (!line || line.startsWith("*") || line.startsWith("#")) continue;
    const cols = line.split(",");
    if (cols[1] && isV4(cols[1])) ips.push(cols[1]);
  }
  addProviderIps(vpnServers, "SoftEther / VPN Gate", ips);
}

// Direct Urban VPN anonymous entrypoint API
const urbanVpn = await step("urban vpn entrypoints", async () => {
  const reg = await get(
    "https://api-pro.falais.com/rest/v1/registrations/clientApps/URBAN_VPN_BROWSER_EXTENSION/users/anonymous",
    "json",
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "chrome-extension://eppiocemhmnlbhjplcgkofciiegomcon",
      },
      body: JSON.stringify({
        clientApp: { name: "URBAN_VPN_BROWSER_EXTENSION", browser: "CHROME" },
      }),
    }
  );
  const accs = await get(
    "https://api-pro.falais.com/rest/v1/security/tokens/accs",
    "json",
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${reg.value}`,
      },
      body: JSON.stringify({
        type: "accs",
        clientApp: { name: "URBAN_VPN_BROWSER_EXTENSION" },
      }),
    }
  );
  return get("https://stats.falais.com/api/rest/v2/entrypoints/countries", "json", {
    headers: {
      authorization: `Bearer ${accs.value}`,
      "x-client-app": "URBAN_VPN_BROWSER_EXTENSION",
    },
  });
});
if (urbanVpn) {
  const ips = new Set();
  collectIps(urbanVpn, ips);
  addProviderIps(vpnServers, "Urban VPN", ips);
}

// TunnelBear: official PolarBear API (api.polargrizzly.com/vpns) needs an account
// token, so use the public TTL-managed mirror harvested from that API.
// Also covers McAfee Safe Connect, which runs on the same PolarBear backend
// (carrier_id "mcafee_pps_partner" in Cure53's TunnelBear pentest report).
// https://github.com/tn3w/TunnelBear-IPs
const tunnelBear = await step("tunnelbear ip list (tn3w mirror)", () =>
  get("https://raw.githubusercontent.com/tn3w/TunnelBear-IPs/master/tunnelbear_ips.txt")
);
if (tunnelBear) addProviderIps(vpnServers, "TunnelBear", ipLines(tunnelBear));

// hide.me: official API publishes hostnames, not IPs (used by the official
// Linux client https://github.com/eventure/hide.client.linux) — resolve A records.
// https://api.hide.me/v1/network/paid/en
const hideMe = await step("hide.me server list (dns resolved)", async () => {
  const hosts = new Set();
  const walk = (node) => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === "object") {
      if (typeof node.hostname === "string") hosts.add(node.hostname);
      Object.values(node).forEach(walk);
    }
  };
  for (const kind of ["paid", "free"]) {
    walk(await get(`https://api.hide.me/v1/network/${kind}/en`, "json"));
  }
  const ips = [];
  for (const host of hosts) {
    try {
      ips.push(...(await resolve4(host)));
    } catch {
      // one dead hostname must not lose the rest
    }
  }
  return ips;
});
if (hideMe) addProviderIps(vpnServers, "hide.me", hideMe);

// Surfshark publishes cluster hostnames, not IPs.
// https://api.surfshark.com/v4/server/clusters/{generic,double,static,obfuscated}
const surfsharkIps = await step("surfshark cluster api (dns resolved)", async () => {
  const hosts = new Set();
  let ok = 0;
  for (const kind of ["generic", "double", "static", "obfuscated"]) {
    try {
      collectHostFields(await get(`https://api.surfshark.com/v4/server/clusters/${kind}`, "json"), hosts);
      ok++;
    } catch (error) {
      console.warn(`fail surfshark ${kind}: ${error.message}`);
    }
  }
  if (!ok) throw new Error("all surfshark cluster feeds failed");
  return resolveHosts(hosts);
});
if (surfsharkIps) addProviderIps(vpnServers, "Surfshark", surfsharkIps);

// Browsec extension server list (hostnames). https://browsec.com/api/v1/servers
const browsecIps = await step("browsec server api (dns resolved)", async () => {
  const hosts = new Set();
  collectHostFields(await get("https://browsec.com/api/v1/servers", "json"), hosts);
  return resolveHosts(hosts);
});
if (browsecIps) addProviderIps(vpnServers, "Browsec", browsecIps);

// Prefixes announced by anonymizer-operated ASNs (RIPEstat). Any address in
// that space is the service, same rule as ANONYMIZER_ASNS. One dead ASN does
// not drop the rest. Hosting ASNs are intentionally not expanded here.
const anonPrefixes = await step("ripestat anonymizer announced prefixes", () =>
  announcedPrefixesForAsns(ANONYMIZER_ASNS.keys())
);

// Conticop ProtonVPN Logicals mirror (Proton's direct /vpn/logicals now requires auth)
const protonLogicals = await step("protonvpn logicals mirror", () =>
  get("https://raw.githubusercontent.com/Conticop/bad-asn-list/master/ProtonVPN-Logicals.json", "json")
);
if (protonLogicals) {
  const ips = new Set();
  collectIps(protonLogicals, ips);
  addProviderIps(vpnServers, "Proton VPN", ips);
}

// az0/vpn_ip direct static provider IP lists
const AZ0_IP_FILES = [
  ["expressvpn.txt", "ExpressVPN"],
  ["hideme.txt", "hide.me"],
  ["hideme_api.txt", "hide.me"],
  ["hoxx_api.txt", "Hoxx VPN"],
  ["setupvpn_api.txt", "SetupVPN"],
  ["network_dd_vpn_api.txt", "WorkingVPN"],
  ["nordvpn.txt", "NordVPN"],
  ["nordvpn_api.txt", "NordVPN"],
  ["pia.txt", "Private Internet Access"],
];
for (const [file, provider] of AZ0_IP_FILES) {
  const text = await step(`az0/vpn_ip ${file}`, () =>
    get(`https://raw.githubusercontent.com/az0/vpn_ip/main/data/input/ip/${file}`)
  );
  if (text) addProviderIps(vpnServers, provider, ipLines(text));
}

// az0/vpn_ip daily resolved VPN server feed (filtered to verified VPN brands, excluding CDNs & AT&T 12/8)
const az0Daily = await step("az0/vpn_ip daily feed", () =>
  get("https://az0-vpnip-public.oooninja.com/ip.txt")
);
if (az0Daily) {
  // Tags are comma-separated domain/brand sets per IP. Match on individual
  // tags only — never on bare CDN tags (cloudfront.net etc. stay unmatched),
  // and keep the AT&T 12/8 exclusion below.
  const providerForTags = (tags) => {
    if (tags.has("nordvpn")) return "NordVPN";
    if (tags.has("pia") || tags.has("privateinternetaccess.com") || tags.has("privacy.network"))
      return "Private Internet Access";
    if (tags.has("cyberghost")) return "CyberGhost";
    if (tags.has("windscribe")) return "Windscribe";
    if (tags.has("protonvpn.net") || tags.has("protonvpn.com") || tags.has("proton.me"))
      return "Proton VPN";
    if (tags.has("pointtoserver.com")) return "PureVPN";
    if (tags.has("expressvpn")) return "ExpressVPN";
    if (tags.has("hideme") || tags.has("hide.me")) return "hide.me";
    if (tags.has("hola")) return "Hola VPN";
    if (tags.has("hoxx")) return "Hoxx VPN";
    if (tags.has("browsec") || tags.has("browsec.com")) return "Browsec";
    if (tags.has("setupvpn.com")) return "SetupVPN";
    if (tags.has("workingvpn.com")) return "WorkingVPN";
    if (tags.has("tlsext.com") || tags.has("maxxxcdn.com")) return "VeePN";
    if (tags.has("protect-my-ip.com") || tags.has("my-safe-net.com")) return "Hotspot Shield";
    if (tags.has("npvu.me") || tags.has("uvpn.me")) return "uVPN";
    if (tags.has("telleport.me")) return "Telleport";
    if (tags.has("1clickvpn.net")) return "1ClickVPN";
    return null;
  };
  for (const line of az0Daily.split(/\r?\n/)) {
    const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*#\s*(.*)$/);
    if (!m) continue;
    const [, ip, rawTag] = m;
    if (ip.startsWith("12.")) continue;
    const tags = new Set(
      rawTag.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean)
    );
    const provider = providerForTags(tags);
    if (provider && isV4(ip)) {
      addProviderIps(vpnServers, provider, [ip]);
    }
  }
}

const x4bAsn = await step("X4BNet datacenter ASNs", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt")
);
const badAsn = await step("brianhama bad-asn-list", () =>
  get("https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv")
);
const x4bVpn = await step("X4BNet VPN CIDRs (IPv4)", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt")
);
const x4bVpnV6 = await step("X4BNet VPN CIDRs (IPv6)", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt")
);
const x4bProtonInput = await step("X4BNet ProtonVPN input CIDRs", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ips/protonvpn.txt")
);
const x4bPiaInput = await step("X4BNet PIA input CIDRs", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ips/pia.txt")
);
const x4bMullvadInput = await step("X4BNet Mullvad input CIDRs", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ips/mullvadvpn.txt")
);
const operaRanges = await step("Opera VPN IP ranges", () =>
  get("https://ipranges.opera.com/mini/operaranges/opera_ip_ranges.txt")
);
const x4bDc = await step("X4BNet datacenter CIDRs (IPv4)", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt")
);
const x4bDcV6 = await step("X4BNet datacenter CIDRs (IPv6)", () =>
  get("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt")
);
const jhassineDc = await step("jhassine cloud datacenter CIDRs", () =>
  get("https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt")
);
const icloud = await step("iCloud Private Relay egress", () =>
  get("https://mask-api.icloud.com/egress-ip-ranges.csv")
);
const googleVpn = await step("Google VPN (Pixel / Google One) geofeed", () =>
  get("https://www.gstatic.com/vpn/geofeed")
);
const googleFiVpn = await step("Google Fi VPN geofeed", () =>
  get("https://www.gstatic.com/fi/bridge/ipgeofeed.txt")
);

if (x4bProtonInput) addProviderIps(vpnServers, "Proton VPN", ipLines(x4bProtonInput));
if (x4bPiaInput) addProviderIps(vpnServers, "Private Internet Access", ipLines(x4bPiaInput));
if (x4bMullvadInput) addProviderIps(vpnServers, "Mullvad", ipLines(x4bMullvadInput));

const hostingAsns = {
  ...(badAsn ? parseBadAsnCsv(badAsn) : {}),
  ...(x4bAsn ? parseAsnLines(x4bAsn) : {}),
};

const vpnCidrs = [
  ...new Set([
    ...(x4bVpn ? cidrLines(x4bVpn) : []),
    ...(x4bProtonInput ? cidrLines(x4bProtonInput) : []),
    ...(x4bPiaInput ? cidrLines(x4bPiaInput) : []),
    ...(operaRanges ? cidrLines(operaRanges) : []),
    ...(anonPrefixes?.v4 || []),
  ]),
];

const vpnCidrsV6 = mergeV6ToHexPairs([
  ...(x4bVpnV6 ? cidrLinesV6(x4bVpnV6) : []),
  ...(operaRanges ? cidrLinesV6(operaRanges) : []),
  ...(anonPrefixes?.v6 || []),
]);

const datacenterCidrs = [
  ...(x4bDc ? cidrLines(x4bDc) : []),
  ...(jhassineDc ? cidrLines(jhassineDc) : []),
];

const datacenterCidrsV6 = mergeV6ToHexPairs(x4bDcV6 ? cidrLinesV6(x4bDcV6) : []);

const relayCidrs = [
  ...(icloud ? geofeedV4(icloud) : []),
  ...(googleVpn ? geofeedV4(googleVpn) : []),
  ...(googleFiVpn ? geofeedV4(googleFiVpn) : []),
];

const relayCidrsV6 = mergeV6ToHexPairs([
  ...(icloud ? geofeedV6(icloud) : []),
  ...(googleVpn ? geofeedV6(googleVpn) : []),
  ...(googleFiVpn ? geofeedV6(googleFiVpn) : []),
]);

const intel = {
  generatedAt: new Date().toISOString(),
  sources: {
    gluetun: "https://github.com/qdm12/gluetun-servers",
    mullvad: "https://api.mullvad.net/www/relays/all/",
    nordvpn: "https://api.nordvpn.com/v1/servers?limit=20000",
    windscribe: "https://assets.windscribe.com/serverlist/openvpn/1/1",
    pia: "https://serverlist.piaservers.net/vpninfo/servers/v6",
    airvpn: "https://airvpn.org/api/status/",
    ivpn: "https://api.ivpn.net/v4/servers.json",
    ovpn: "https://www.ovpn.com/v2/api/client/entry",
    riseup: "https://api.black.riseup.net/3/config/eip-service.json",
    vpngate: "http://www.vpngate.net/api/iphone/",
    urbanvpn: "https://stats.falais.com/api/rest/v2/entrypoints/countries",
    tunnelbear: "https://github.com/tn3w/TunnelBear-IPs (Apache-2.0 mirror of authenticated api.polargrizzly.com/vpns; official API needs account token)",
    hideme: "https://api.hide.me/v1/network/paid/en (+ /free/en, hostnames DNS-resolved)",
    surfshark: "https://api.surfshark.com/v4/server/clusters/{generic,double,static,obfuscated} (hostnames DNS-resolved)",
    browsec: "https://browsec.com/api/v1/servers (hostnames DNS-resolved)",
    ripestatPrefixes: "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<anonymizer> (ANONYMIZER_ASNS only)",
    notAdded: "Cloudflare does not publish WARP/Edge Secure Network egress (CDN ips-v4 is not WARP). firehol_anonymous and firehol_proxies are open-proxy feeds that include compromised residential hosts. ipsum is attacker IPs, not anonymizers. Mysterium/Hola/Lantern exits observed on consumer ISPs are not ingested by ASN.",
    protonLogicals: "https://raw.githubusercontent.com/Conticop/bad-asn-list/master/ProtonVPN-Logicals.json",
    az0VpnIp: "https://github.com/az0/vpn_ip",
    x4bnet: "https://github.com/X4BNet/lists_vpn",
    jhassineDatacenters: "https://github.com/jhassine/server-ip-addresses",
    operaRanges: "https://ipranges.opera.com/mini/operaranges/opera_ip_ranges.txt",
    badAsn: "https://github.com/brianhama/bad-asn-list",
    icloud: "https://mask-api.icloud.com/egress-ip-ranges.csv",
    googleVpn: "https://www.gstatic.com/vpn/geofeed",
    googleFiVpn: "https://www.gstatic.com/fi/bridge/ipgeofeed.txt",
  },
  vpnServers,
  vpnCidrs,
  vpnCidrsV6,
  datacenterCidrs,
  datacenterCidrsV6,
  relayCidrs,
  relayCidrsV6,
  hostingAsns,
};

await fs.mkdir(path.dirname(OUT), { recursive: true });
await fs.writeFile(OUT, JSON.stringify(intel));

const serverCount = Object.values(vpnServers).reduce((n, list) => n + list.length, 0);
console.log(
  `\nwrote ${path.relative(root, OUT)}: ${serverCount} VPN server IPs across ${Object.keys(vpnServers).length} providers, ` +
    `${intel.vpnCidrs.length} VPN v4 CIDRs (${intel.vpnCidrsV6.length} merged v6 ranges), ` +
    `${intel.datacenterCidrs.length} datacenter v4 CIDRs (${intel.datacenterCidrsV6.length} merged v6 ranges), ` +
    `${intel.relayCidrs.length} private-relay v4 CIDRs (${intel.relayCidrsV6.length} merged v6 ranges), ` +
    `${Object.keys(hostingAsns).length} hosting ASNs`
);
