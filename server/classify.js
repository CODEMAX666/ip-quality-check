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
    label: "Tor exit",
    matched: tor,
    weight: tor ? 0.95 : 0,
    detail: tor
      ? anonAsn?.type === "TOR"
        ? `AS${asn} is run by ${anonAsn.name}.`
        : "On the current Tor exit list."
      : "Not on the Tor exit list.",
  });

  const listedProviders = vpnServerProviders(enrichment.ip);
  push(signals, {
    id: "known_vpn_server",
    layer: "service",
    label: "Known VPN server",
    matched: Boolean(listedProviders),
    weight: listedProviders ? 0.98 : 0,
    detail: listedProviders
      ? `Listed as a ${listedProviders.join(", ")} server.`
      : "Not on any VPN provider's server list.",
  });

  const vpnRange = inVpnRange(enrichment.ip);
  push(signals, {
    id: "vpn_range",
    layer: "service",
    label: "VPN address range",
    matched: vpnRange,
    weight: vpnRange ? 0.85 : 0,
    detail: vpnRange
      ? "Inside an address range used by VPN providers."
      : "Not in a known VPN address range.",
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

  const proxy = Boolean(enrichment.flags.proxy || anonProxyAsn);
  const flaggedBy = (enrichment.flaggedBy || []).map((source) => {
    if (source === "IPQS") {
      const kinds = [ipqs.vpn && "VPN", ipqs.proxy && "proxy"].filter(Boolean);
      return kinds.length ? `IPQS (${kinds.join(", ")})` : "IPQS";
    }
    if (source === "proxycheck.io" && enrichment.proxycheck?.type) {
      return `proxycheck.io (${enrichment.proxycheck.type})`;
    }
    return source;
  });
  push(signals, {
    id: "proxy_flag",
    layer: "observation",
    label: "Proxy or VPN flag",
    matched: proxy,
    weight: proxy ? 0.72 : 0,
    detail: proxy
      ? flaggedBy.length
        ? `Flagged by ${flaggedBy.join(" and ")}.`
        : `AS${asn} belongs to ${anonAsn?.name || "a proxy network"}.`
      : "No lookup service flagged it as a proxy or VPN.",
  });

  const highFraud = ipqs.fraudScore != null && ipqs.fraudScore >= 75;
  push(signals, {
    id: "fraud_score",
    layer: "observation",
    label: "High fraud score",
    matched: highFraud,
    weight: 0,
    detail:
      ipqs.fraudScore != null
        ? `IPQS fraud score ${ipqs.fraudScore} out of 100.`
        : "No fraud score available.",
  });

  push(signals, {
    id: "vpn_service",
    layer: "service",
    label: "VPN provider network",
    matched: Boolean(anonAsn && anonAsn.type !== "TOR"),
    weight: anonAsn && anonAsn.type !== "TOR" ? 0.9 : 0,
    detail: anonAsn && anonAsn.type !== "TOR"
      ? `AS${asn} belongs to ${anonAsn.name}.`
      : namedVpn
        ? `Network name mentions ${namedVpn}.`
        : "Not run by a VPN or proxy company.",
  });
  push(signals, {
    id: "vpn_keyword",
    layer: "service",
    label: "“VPN” in network name",
    matched: Boolean(genericVpn),
    weight: genericVpn ? 0.35 : 0,
    detail: genericVpn
      ? "The network name contains “VPN”."
      : "No “VPN” in the network name.",
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
        ? "Apple Private Relay, Google VPN, or Cloudflare WARP address."
        : "Looks like Cloudflare WARP, Google VPN, or a similar relay."
      : "Not a privacy relay address.",
  });

  const heavyHostName = asn ? VPN_HEAVY_HOST_ASNS.get(asn) : null;
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
    label: "Hosting network",
    matched: datacenter,
    weight: datacenter && !vpnDetected ? 0.28 : datacenter ? 0.12 : 0,
    detail: datacenter
      ? `${enrichment.as?.organization || hostingAsn || "This network"} is a datacenter, not a home or mobile ISP.`
      : "Not a datacenter or hosting network.",
  });
  push(signals, {
    id: "vpn_heavy_host",
    layer: "routing",
    label: "VPN-friendly host",
    matched: Boolean(heavyHostName && !anonAsn),
    weight: heavyHostName && !anonAsn ? 0.4 : 0,
    detail: heavyHostName && !anonAsn
      ? `${enrichment.as?.organization || heavyHostName} rents servers to many VPN services.`
      : "Not a host known for VPN servers.",
  });

  const mobile = Boolean(enrichment.flags.mobile);
  push(signals, {
    id: "mobile_cgnat",
    layer: "infrastructure",
    label: "Mobile network",
    matched: mobile,
    weight: 0,
    detail: mobile
      ? "Mobile carrier address, often shared by many people at once."
      : "Not a mobile carrier address.",
  });

  const satellite = Boolean(enrichment.flags.satellite);
  push(signals, {
    id: "satellite",
    layer: "infrastructure",
    label: "Satellite ISP",
    matched: satellite,
    weight: 0,
    detail: satellite
      ? "Satellite internet. The listed location can be far from the user."
      : "Not a satellite ISP.",
  });

  const rir = rirGeoMismatch(
    enrichment.ip,
    enrichment.location?.countryCode,
    text
  );
  push(signals, {
    id: "rir_geo_mismatch",
    layer: "routing",
    label: "Registry vs location",
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
    label: "Owner mismatch",
    matched: orgConflict.matched,
    weight: orgConflict.matched ? 0.48 : 0,
    detail: orgConflict.detail,
  });

  const foreignOrg = foreignOrgInCountry(text, enrichment.location?.countryCode);
  push(signals, {
    id: "foreign_org_geo",
    layer: "routing",
    label: "Foreign operator",
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
    label: "Time zone mismatch",
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
    label: "WebRTC leak",
    matched: webrtc.matched,
    weight: webrtc.matched ? 0.48 : 0,
    detail: webrtc.detail,
  });

  const lang = languageMismatch(client.languages, enrichment.location?.countryCode);
  push(signals, {
    id: "lang_mismatch",
    layer: "client",
    label: "Language vs country",
    matched: lang.matched,
    weight: lang.matched ? 0.08 : 0,
    detail: lang.detail,
  });

  const rtt = rttAnomaly(client.tcpRttMs, client.tlsRttMs);
  push(signals, {
    id: "connection_timing",
    layer: "client",
    label: "Connection timing",
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
  if (!browserTz || !ipTz) {
    return { matched: false, detail: "No time zone to compare." };
  }
  if (browserTz === ipTz) {
    return { matched: false, detail: `Browser and IP both use ${browserTz}.` };
  }
  try {
    const diff = Math.abs(offsetMinutes(browserTz) - offsetMinutes(ipTz));
    if (diff >= 180) {
      return {
        matched: true,
        detail: `Browser is on ${browserTz}, but the IP is in ${ipTz} (${Math.round(diff / 60)} hours apart).`,
      };
    }
    return {
      matched: false,
      detail: `Browser ${browserTz} and IP ${ipTz} are within 3 hours.`,
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
    return { matched: false, detail: "No WebRTC addresses collected." };
  }
  if (extra.length) {
    return {
      matched: true,
      detail: `The browser also exposed ${extra.join(", ")}, so traffic may be relayed.`,
    };
  }
  return { matched: false, detail: "WebRTC addresses match this IP." };
}

function languageMismatch(languages = [], countryCode) {
  if (!languages.length || !countryCode) {
    return { matched: false, detail: "No language and country to compare." };
  }
  const primary = String(languages[0] || "").toLowerCase();
  const region = primary.split("-")[1]?.toUpperCase();
  if (region && region !== countryCode && !["EN", "US", "GB"].includes(region)) {
    return {
      matched: true,
      detail: `Browser language ${languages[0]} doesn't match ${countryCode}.`,
    };
  }
  return {
    matched: false,
    detail: `Browser language ${languages[0]} fits ${countryCode}.`,
  };
}

function rttAnomaly(tcp, tls) {
  if (tcp == null || tls == null) {
    return { matched: false, detail: "No timing data for this page load." };
  }
  if (tcp > 40 && tls > tcp * 2.8) {
    return {
      matched: true,
      detail: `Secure setup took ${Math.round(tls)}ms vs ${Math.round(tcp)}ms to connect. Big gaps can mean a tunnel.`,
    };
  }
  return {
    matched: false,
    detail: `Connection timing looks normal (${Math.round(tcp)}ms / ${Math.round(tls)}ms).`,
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
