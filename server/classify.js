import {
  inDatacenterRange,
  inPrivateRelay,
  inVpnRange,
  hostingAsnName,
  vpnServerProviders,
} from "./intel.js";
import {
  ANONYMIZER_ASNS,
  DATACENTER_ASNS,
  VPN_HEAVY_HOST_ASNS,
  haystack,
  isHostingName,
  isRelayName,
  isVpnName,
  matchVpnService,
} from "./lists.js";
import { foreignOrgInCountry, orgAsnConflict, rirGeoMismatch } from "./rir.js";
import { isTorExit } from "./tor.js";

export function classify({ enrichment, client = {}, handshake = {} }) {
  const text = haystack([
    enrichment.as?.organization,
    enrichment.organization,
    enrichment.isp,
    enrichment.hostname,
    enrichment.vpn?.service,
    enrichment.datacenter?.name,
  ]);

  const signals = [];
  const risks = [];
  const services = [];
  const tunnels = [];

  const asn = enrichment.as?.number ? Number(enrichment.as.number) : null;
  const anonAsn = asn ? ANONYMIZER_ASNS.get(asn) : null;

  const tor = isTorExit(enrichment.ip) || enrichment.flags.tor || anonAsn?.type === "TOR";
  push(signals, {
    id: "tor_exit",
    layer: "observation",
    label: "Tor exit node",
    matched: tor,
    weight: tor ? 0.95 : 0,
    detail: tor
      ? anonAsn?.type === "TOR"
        ? `AS${asn} is run by ${anonAsn.name}.`
        : "Address is on the current Tor bulk exit list (or flagged by an enricher)."
      : "Not present on the loaded Tor exit snapshot.",
  });

  const listedProviders = vpnServerProviders(enrichment.ip);
  push(signals, {
    id: "known_vpn_server",
    layer: "service",
    label: "Published VPN server IP",
    matched: Boolean(listedProviders),
    weight: listedProviders ? 0.98 : 0,
    detail: listedProviders
      ? `Exact match in the server list ${listedProviders.join(", ")} publishes for its own apps.`
      : "Not in any published provider server list (NordVPN, Proton, Surfshark, ExpressVPN, PIA, Mullvad, TunnelBear, hide.me, Hola, …).",
  });

  const vpnRange = inVpnRange(enrichment.ip);
  push(signals, {
    id: "vpn_range",
    layer: "service",
    label: "Known VPN netblock",
    matched: vpnRange,
    weight: vpnRange ? 0.85 : 0,
    detail: vpnRange
      ? "Inside a netblock X4BNet attributes to commercial VPN providers."
      : "Not inside a known VPN netblock.",
  });

  const anonVpnAsn = anonAsn && anonAsn.type === "VPN";
  const anonProxyAsn = anonAsn && anonAsn.type === "PROXY";
  const namedVpn =
    enrichment.vpn?.service ||
    listedProviders?.[0] ||
    (anonVpnAsn ? anonAsn.name : null) ||
    matchVpnService(text);
  const genericVpn = /\bvpn\b|virtual private/i.test(text) && !namedVpn;
  const vpnName = Boolean(namedVpn) || isVpnName(text);
  const ipqs = enrichment.ipqs || {};
  const vpnFlag = Boolean(enrichment.flags.vpn);
  const vpnDetected = Boolean(listedProviders || vpnRange || anonVpnAsn || vpnName || vpnFlag);
  push(signals, {
    id: "vpn_service",
    layer: "service",
    label: "VPN operator network",
    matched: Boolean(anonAsn && anonAsn.type !== "TOR"),
    weight: anonAsn && anonAsn.type !== "TOR" ? 0.9 : 0,
    detail: anonAsn && anonAsn.type !== "TOR"
      ? `AS${asn} is announced by ${anonAsn.name} itself (${anonAsn.type}).`
      : namedVpn
        ? `Organization string names ${namedVpn}.`
        : "ASN is not run by a VPN or proxy operator.",
  });
  push(signals, {
    id: "vpn_keyword",
    layer: "service",
    label: "Generic VPN keyword",
    matched: Boolean(genericVpn),
    weight: genericVpn ? 0.35 : 0,
    detail: genericVpn
      ? "Organization/ISP string contains “VPN” but no named consumer brand. Weak prior only."
      : "No generic VPN keyword without a brand match.",
  });
  if (namedVpn && namedVpn !== "Unnamed VPN keyword") services.push(namedVpn);

  const icloudRelay = inPrivateRelay(enrichment.ip);
  const relay =
    icloudRelay || isRelayName(text) || /warp|private relay|google vpn|google one services|google fi vpn/i.test(namedVpn || "");
  push(signals, {
    id: "privacy_relay",
    layer: "service",
    label: "Privacy relay",
    matched: relay,
    weight: relay ? 0.8 : 0,
    detail: relay
      ? icloudRelay
        ? "Inside published privacy relay egress ranges (Apple iCloud Private Relay, Google VPN, or Cloudflare WARP)."
        : "Looks like Cloudflare WARP, Google VPN, or a similar OS/browser relay — anonymizing, but not a classic commercial VPN exit."
      : "Not in published privacy relay egress ranges; no relay operator string found.",
  });

  const heavyHostName = asn ? VPN_HEAVY_HOST_ASNS.get(asn) : null;
  push(signals, {
    id: "vpn_heavy_host",
    layer: "routing",
    label: "VPN-heavy hosting ASN",
    matched: Boolean(heavyHostName && !anonAsn),
    weight: heavyHostName && !anonAsn ? 0.4 : 0,
    detail: heavyHostName && !anonAsn
      ? `AS${asn} ${heavyHostName} rents servers to most commercial VPN brands. A strong prior, not proof this IP is an exit.`
      : "ASN is not on the VPN-heavy hosting list.",
  });

  const hostingFlag = Boolean(enrichment.flags.hosting);
  const hostingName = isHostingName(text);
  const hostingAsn = asn ? DATACENTER_ASNS.get(asn) || hostingAsnName(asn) : null;
  const dcRange = inDatacenterRange(enrichment.ip);
  const datacenter = Boolean(
    hostingFlag || hostingName || hostingAsn || dcRange || heavyHostName || enrichment.datacenter
  );
  push(signals, {
    id: "datacenter",
    layer: "infrastructure",
    label: "Datacenter / hosting network",
    matched: datacenter,
    weight: datacenter && !vpnDetected ? 0.28 : datacenter ? 0.12 : 0,
    detail: datacenter
      ? `Hosting network${hostingAsn ? ` (AS${asn} ${hostingAsn})` : dcRange ? " (X4BNet datacenter netblock)" : ""}. Spur treats this as infrastructure=DATACENTER; VPN still needs a tunnel/service signal.`
      : "Not a listed hosting ASN or datacenter netblock.",
  });

  const proxy = Boolean(enrichment.flags.proxy || anonProxyAsn);
  const flaggedBy = enrichment.flaggedBy || [];
  push(signals, {
    id: "proxy_flag",
    layer: "observation",
    label: "Open proxy / anonymizer flag",
    matched: proxy,
    weight: proxy ? 0.72 : 0,
    detail: proxy
      ? flaggedBy.length
        ? `Flagged as proxy/VPN by ${flaggedBy.join(", ")}.`
        : `AS${asn} is run by a proxy network.`
      : "No source flagged this IP as a proxy or VPN.",
  });

  const ipqsHit = Boolean(ipqs.vpn || ipqs.proxy || (ipqs.fraudScore != null && ipqs.fraudScore >= 75));
  push(signals, {
    id: "ipqs_reputation",
    layer: "observation",
    label: "IPQS VPN / proxy / fraud",
    matched: ipqsHit,
    weight: 0,
    detail: ipqsHit
      ? `IPQS: ${ipqs.type || "anonymizer"}${ipqs.vpn ? " · VPN" : ""}${ipqs.proxy ? " · Proxy" : ""}${
          ipqs.fraudScore != null ? ` · fraud ${ipqs.fraudScore}` : ""
        }.`
      : ipqs.fraudScore != null
        ? `IPQS fraud score ${ipqs.fraudScore}; no VPN/proxy flag.`
        : "No IPQS VPN, proxy, or high fraud score.",
  });

  const proxycheckHit = Boolean(enrichment.proxycheck?.proxy || enrichment.proxycheck?.vpn);
  push(signals, {
    id: "proxycheck",
    layer: "observation",
    label: "proxycheck.io reputation",
    matched: proxycheckHit,
    weight: 0,
    detail: enrichment.proxycheck
      ? proxycheckHit
        ? `proxycheck.io: ${enrichment.proxycheck.type || "proxy"} · risk ${enrichment.proxycheck.risk ?? "—"}.`
        : `proxycheck.io: ${enrichment.proxycheck.type || "clear"} · risk ${enrichment.proxycheck.risk ?? 0}; not a proxy/VPN.`
      : "proxycheck.io was not queried.",
  });

  const mobile = Boolean(enrichment.flags.mobile);
  push(signals, {
    id: "mobile_cgnat",
    layer: "infrastructure",
    label: "Mobile / CGNAT",
    matched: mobile,
    weight: 0,
    detail: mobile
      ? "Mobile carrier space. Many subscribers share one public IP, so one bad actor can taint the address — same caveat Spur documents for CGNAT."
      : "Not classified as mobile carrier space.",
  });

  const satellite = Boolean(enrichment.flags.satellite);
  push(signals, {
    id: "satellite",
    layer: "infrastructure",
    label: "Satellite ISP",
    matched: satellite,
    weight: 0,
    detail: satellite
      ? "Satellite egress. The registered geo is often far from the user."
      : "Not classified as satellite.",
  });

  const rir = rirGeoMismatch(
    enrichment.ip,
    enrichment.location?.countryCode,
    text
  );
  push(signals, {
    id: "rir_geo_mismatch",
    layer: "routing",
    label: "RIR vs claimed country",
    matched: rir.matched,
    weight: rir.matched ? 0.52 : 0,
    detail: rir.detail,
  });

  const orgConflict = orgAsnConflict(
    enrichment.as?.organization,
    enrichment.organization,
    enrichment.isp
  );
  push(signals, {
    id: "org_asn_mismatch",
    layer: "routing",
    label: "ASN vs allocated org",
    matched: orgConflict.matched,
    weight: orgConflict.matched ? 0.48 : 0,
    detail: orgConflict.detail,
  });

  const foreignOrg = foreignOrgInCountry(text, enrichment.location?.countryCode);
  push(signals, {
    id: "foreign_org_geo",
    layer: "routing",
    label: "Foreign operator on local geo",
    matched: foreignOrg.matched,
    weight: foreignOrg.matched ? 0.55 : 0,
    detail: foreignOrg.detail,
  });

  const ispProxy = rir.matched && (orgConflict.matched || foreignOrg.matched);
  if (vpnDetected || (proxy && datacenter) || ispProxy) {
    tunnels.push({
      anonymous: true,
      operator:
        namedVpn ||
        (ispProxy ? "ISP_PROXY" : null) ||
        (anonAsn ? anonAsn.name : "VPN"),
      type: "VPN",
    });
  }

  const geo = geoMismatch(client.timezone, enrichment.location?.timezone);
  push(signals, {
    id: "geo_mismatch",
    layer: "client",
    label: "Timezone vs IP geo",
    matched: geo.matched,
    weight: geo.matched ? 0.22 : 0,
    detail: geo.detail,
  });

  const webrtc = webrtcLeak(client.webrtcIps, [
    enrichment.ip,
    handshake.ip,
    handshake.publicIp,
    client.browserPublicIp,
  ]);
  push(signals, {
    id: "webrtc_leak",
    layer: "client",
    label: "WebRTC IP divergence",
    matched: webrtc.matched,
    weight: webrtc.matched ? 0.48 : 0,
    detail: webrtc.detail,
  });

  const lang = languageMismatch(client.languages, enrichment.location?.countryCode);
  push(signals, {
    id: "lang_mismatch",
    layer: "client",
    label: "Language vs IP country",
    matched: lang.matched,
    weight: lang.matched ? 0.08 : 0,
    detail: lang.detail,
  });

  const rtt = rttAnomaly(client.tcpRttMs, client.tlsRttMs);
  push(signals, {
    id: "handshake_rtt",
    layer: "handshake",
    label: "TCP vs TLS handshake timing",
    matched: rtt.matched,
    weight: rtt.matched ? 0.1 : 0,
    detail: rtt.detail,
  });

  const score = Math.min(
    1,
    signals.reduce((sum, s) => sum + (s.matched ? s.weight : 0), 0)
  );

  if (tor) risks.push("TOR");
  if (vpnDetected || proxy || relay || ispProxy) risks.push("TUNNEL");
  if (geo.matched || rir.matched || foreignOrg.matched) risks.push("GEO_MISMATCH");
  if ((proxy && heavyHostName) || ispProxy || anonProxyAsn) risks.push("CALLBACK_PROXY");
  if (datacenter) risks.push("HOSTING");
  if (ipqs.fraudScore != null && ipqs.fraudScore >= 75) risks.push("FRAUD");

  let infrastructure = "ISP";
  if (satellite) infrastructure = "SATELLITE";
  else if (mobile) infrastructure = "MOBILE";
  else if (datacenter) infrastructure = "DATACENTER";

  let verdict = "residential";
  if (tor) verdict = "tor";
  else if (listedProviders || anonVpnAsn) verdict = "vpn";
  else if (icloudRelay || relay) verdict = "privacy_relay";
  else if (vpnDetected || (proxy && heavyHostName) || ispProxy) verdict = "vpn";
  else if (proxy) verdict = "proxy";
  else if (rir.matched) verdict = "suspicious";
  else if (datacenter && (geo.matched || webrtc.matched || heavyHostName)) verdict = "suspicious";
  else if (datacenter) verdict = "datacenter";
  else if (geo.matched && webrtc.matched) verdict = "suspicious";

  const confidence =
    verdict === "residential"
      ? round(Math.min(1, 0.55 + (enrichment.sources.filter((s) => s.ok).length || 0) * 0.08))
      : round(Math.max(score, verdict === "datacenter" ? 0.62 : 0.7));

  return {
    ip: enrichment.ip,
    verdict,
    confidence,
    score: round(score),
    as: enrichment.as,
    organization: enrichment.organization,
    isp: enrichment.isp,
    hostname: enrichment.hostname,
    infrastructure,
    location: enrichment.location,
    risks,
    services,
    tunnels,
    ipqs: enrichment.ipqs || null,
    proxycheck: enrichment.proxycheck || null,
    client: {
      behaviors: behaviors(tor, proxy, vpnDetected),
      types: client.platform ? [client.platform] : [],
    },
    signals,
    sources: enrichment.sources,
    note: residentialProxyCaveat(verdict),
  };
}

function push(list, signal) {
  list.push({
    ...signal,
    weight: round(signal.weight),
  });
}

function round(n) {
  return Math.round(n * 1000) / 1000;
}

function geoMismatch(browserTz, ipTz) {
  if (!browserTz && !ipTz) {
    return { matched: false, detail: "No timezone from the browser or the IP." };
  }
  if (!browserTz) {
    return { matched: false, detail: `IP timezone ${ipTz}; browser timezone not provided.` };
  }
  if (!ipTz) {
    return { matched: false, detail: `Browser timezone ${browserTz}; IP timezone unknown.` };
  }
  if (browserTz === ipTz) {
    return { matched: false, detail: `Browser and IP both report ${browserTz}.` };
  }
  try {
    const diff = Math.abs(offsetMinutes(browserTz) - offsetMinutes(ipTz));
    if (diff >= 180) {
      return {
        matched: true,
        detail: `${browserTz} vs ${ipTz} (${Math.round(diff / 60)}h apart). Spur calls this GEO_MISMATCH: users of a datacenter IP clustered far from the advertised city.`,
      };
    }
    return {
      matched: false,
      detail: `${browserTz} vs ${ipTz}, but UTC offsets are within 3 hours — treated as same region.`,
    };
  } catch {
    return { matched: false, detail: `Could not compare ${browserTz} with ${ipTz}.` };
  }
}

function offsetMinutes(timeZone) {
  const now = new Date();
  const a = new Date(now.toLocaleString("en-US", { timeZone: "UTC" }));
  const b = new Date(now.toLocaleString("en-US", { timeZone }));
  return (b - a) / 60000;
}

function webrtcLeak(webrtcIps = [], known = []) {
  const discovered = unique(webrtcIps.map(cleanIp).filter(Boolean));
  const publicDiscovered = discovered.filter((ip) => isPublicV4(ip) || ip.includes(":"));
  const knownSet = new Set(unique(known.map(cleanIp).filter(Boolean)));
  const extra = publicDiscovered.filter((ip) => !knownSet.has(ip));
  if (!discovered.length) {
    return {
      matched: false,
      detail: "No WebRTC ICE candidates were collected (blocked STUN, mDNS-only, or timeout).",
    };
  }
  if (extra.length) {
    return {
      matched: true,
      detail: `WebRTC advertised public IP ${extra.join(", ")} which differs from the HTTP handshake IP. One path is likely relayed.`,
    };
  }
  return {
    matched: false,
    detail: `WebRTC candidates (${discovered.join(", ")}) match the handshake/public IP.`,
  };
}

function languageMismatch(languages = [], countryCode) {
  if (!languages.length || !countryCode) {
    return { matched: false, detail: "Not enough language/country data to compare." };
  }
  const primary = String(languages[0] || "").toLowerCase();
  const region = primary.split("-")[1]?.toUpperCase();
  if (region && region !== countryCode && !["EN", "US", "GB"].includes(region)) {
    return {
      matched: true,
      detail: `Primary language tag ${languages[0]} does not line up with IP country ${countryCode}. Soft signal only.`,
    };
  }
  return {
    matched: false,
    detail: `Language ${languages[0]} is compatible with IP country ${countryCode}.`,
  };
}

function rttAnomaly(tcp, tls) {
  if (tcp == null || tls == null) {
    return { matched: false, detail: "No navigation timing available for this page load." };
  }
  if (tcp > 40 && tls > tcp * 2.8) {
    return {
      matched: true,
      detail: `TLS handshake ${Math.round(tls)}ms vs TCP ${Math.round(tcp)}ms. Large gaps can appear on tunneled paths; this is a weak SNITCH-style prior, not proof.`,
    };
  }
  return {
    matched: false,
    detail: `TCP ${Math.round(tcp)}ms / TLS ${Math.round(tls)}ms look consistent.`,
  };
}

function behaviors(tor, proxy, vpn) {
  const out = [];
  if (tor) out.push("TOR_PROXY_USER");
  if (proxy) out.push("PROXY_USER");
  if (vpn) out.push("VPN_USER");
  return out;
}

function residentialProxyCaveat(verdict) {
  if (verdict === "residential" || verdict === "suspicious") {
    return "Residential proxies sit on real ISP addresses. Spur catches them from observed relay behavior over time; this first pass cannot see that traffic, so a clean ISP result is not a guarantee.";
  }
  return "This is a first-pass context object. Spur still has a deeper observation network for rotating exits and residential proxy pools.";
}

function unique(list) {
  return [...new Set(list.filter(Boolean))];
}

function cleanIp(value) {
  if (!value) return null;
  return String(value).replace(/^\[|\]$/g, "").replace(/^::ffff:/, "").trim();
}

function isPublicV4(ip) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  return true;
}
