import { parseAsn } from "./ip.js";

const cache = new Map();
const TTL_MS = 5 * 60 * 1000;

async function fetchJson(url, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "user-agent": "handshake-geo/1.0 (local ip context)" },
    });
    if (!res.ok) throw new Error(`${res.status} ${url}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function fetchText(url, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "user-agent": "handshake-geo/1.0 (local ip context)" },
    });
    if (!res.ok) throw new Error(`${res.status} ${url}`);
    return (await res.text()).trim();
  } finally {
    clearTimeout(timer);
  }
}

async function settled(label, promise) {
  try {
    return { label, ok: true, data: await promise };
  } catch (error) {
    return { label, ok: false, error: error.message || String(error) };
  }
}

export async function publicEgressIp() {
  const probes = [
    () => fetchJson("https://api.ipify.org?format=json").then((d) => d.ip),
    () => fetchText("https://icanhazip.com"),
    () => fetchJson("https://ipwho.is/").then((d) => d.ip),
  ];
  for (const probe of probes) {
    try {
      const ip = String(await probe()).trim();
      if (ip) return ip;
    } catch {
      // try the next echo service
    }
  }
  return null;
}

export async function enrichIp(ip) {
  const cached = cache.get(ip);
  if (cached && Date.now() - cached.at < TTL_MS) return cached.value;

  const ipApiUrl =
    `http://ip-api.com/json/${encodeURIComponent(ip)}` +
    "?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query";

  const jobs = [
    settled("ip-api", fetchJson(ipApiUrl)),
    settled("ipwho", fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`)),
    settled("ipinfo", fetchJson(`https://ipinfo.io/${encodeURIComponent(ip)}/json`)),
    settled("ipapi.co", fetchJson(`https://ipapi.co/${encodeURIComponent(ip)}/json/`)),
    settled("ipqs", fetchIpqs(ip)),
    settled("proxycheck", fetchProxycheck(ip)),
  ];

  if (process.env.IPAPI_IS_KEY) {
    jobs.push(
      settled(
        "ipapi.is",
        fetchJson(
          `https://api.ipapi.is/?q=${encodeURIComponent(ip)}&key=${encodeURIComponent(process.env.IPAPI_IS_KEY)}`
        )
      )
    );
  }

  const results = await Promise.all(jobs);
  const byLabel = Object.fromEntries(results.map((r) => [r.label, r]));

  const ipApi = byLabel["ip-api"]?.ok ? byLabel["ip-api"].data : null;
  const ipwho = byLabel.ipwho?.ok ? byLabel.ipwho.data : null;
  const ipinfo = byLabel.ipinfo?.ok ? byLabel.ipinfo.data : null;
  const ipapiCo = byLabel["ipapi.co"]?.ok && !byLabel["ipapi.co"].data?.error ? byLabel["ipapi.co"].data : null;
  const ipapiIs = byLabel["ipapi.is"]?.ok ? byLabel["ipapi.is"].data : null;
  const ipqs = byLabel.ipqs?.ok ? byLabel.ipqs.data : null;
  const proxycheck = byLabel.proxycheck?.ok ? byLabel.proxycheck.data : null;

  const asnFromIpApi = parseAsn(ipApi?.as);
  const asnNumber =
    ipapiIs?.asn?.asn ||
    ipwho?.connection?.asn ||
    asnFromIpApi.number ||
    parseAsn(ipinfo?.org).number;
  const asnOrg =
    ipapiIs?.asn?.org ||
    ipapiIs?.asn?.name ||
    ipwho?.connection?.org ||
    ipApi?.asname ||
    asnFromIpApi.organization ||
    parseAsn(ipinfo?.org).organization ||
    ipApi?.org ||
    null;

  const loc = ipinfo?.loc?.split(",") || [];
  const location = mergeLocation([
    report("ipapi.is", {
      city: ipapiIs?.location?.city,
      region: ipapiIs?.location?.state,
      country: ipapiIs?.location?.country,
      countryCode: ipapiIs?.location?.country_code,
      zip: ipapiIs?.location?.zip || ipapiIs?.location?.postal,
      lat: ipapiIs?.location?.latitude,
      lon: ipapiIs?.location?.longitude,
      timezone: ipapiIs?.location?.timezone,
    }),
    report("ip-api", {
      city: ipApi?.city,
      region: ipApi?.regionName,
      country: ipApi?.country,
      countryCode: ipApi?.countryCode,
      zip: ipApi?.zip,
      lat: ipApi?.lat,
      lon: ipApi?.lon,
      timezone: ipApi?.timezone,
    }),
    report("ipwho", {
      city: ipwho?.city,
      region: ipwho?.region,
      country: ipwho?.country,
      countryCode: ipwho?.country_code,
      zip: ipwho?.postal,
      lat: ipwho?.latitude,
      lon: ipwho?.longitude,
      timezone: ipwho?.timezone?.id,
    }),
    report("ipinfo", {
      city: ipinfo?.city,
      region: ipinfo?.region,
      country: null,
      countryCode: ipinfo?.country,
      zip: ipinfo?.postal,
      lat: loc[0],
      lon: loc[1],
      timezone: ipinfo?.timezone,
    }),
    report("ipapi.co", {
      city: ipapiCo?.city,
      region: ipapiCo?.region,
      country: ipapiCo?.country_name,
      countryCode: ipapiCo?.country_code || ipapiCo?.country,
      zip: ipapiCo?.postal,
      lat: ipapiCo?.latitude,
      lon: ipapiCo?.longitude,
      timezone: ipapiCo?.timezone,
    }),
    report("IPQS", {
      city: ipqs?.city,
      region: ipqs?.region,
      country: ipqs?.country,
      countryCode: ipqs?.country_code,
      zip: ipqs?.zip || ipqs?.zip_code,
      lat: ipqs?.latitude,
      lon: ipqs?.longitude,
      timezone: ipqs?.timezone,
      family: "fraud",
    }),
  ]);

  const value = {
    ip,
    as: {
      number: asnNumber ? Number(asnNumber) : null,
      organization: asnOrg,
    },
    organization: ipapiIs?.company?.name || ipApi?.org || ipwho?.connection?.org || ipinfo?.org || null,
    isp: ipApi?.isp || ipwho?.connection?.isp || ipinfo?.org || null,
    hostname: ipinfo?.hostname || null,
    location,
    flags: {
      hosting: Boolean(ipApi?.hosting || ipapiIs?.is_datacenter),
      proxy: Boolean(
        ipApi?.proxy ||
          ipapiIs?.is_proxy ||
          ipqs?.proxy ||
          ipqs?.vpn ||
          proxycheck?.proxy ||
          proxycheck?.vpn
      ),
      mobile: Boolean(ipApi?.mobile || ipapiIs?.is_mobile),
      vpn: truthy(ipapiIs?.is_vpn),
      tor: Boolean(ipapiIs?.is_tor || ipqs?.tor),
      anycast: Boolean(ipapiIs?.is_anycast),
      satellite: Boolean(ipapiIs?.is_satellite),
      bogon: Boolean(ipapiIs?.is_bogon),
    },
    flaggedBy: [
      ipApi?.proxy && "ip-api",
      (ipapiIs?.is_proxy || truthy(ipapiIs?.is_vpn)) && "ipapi.is",
      (ipqs?.proxy || ipqs?.vpn) && "IPQS",
      (proxycheck?.proxy || proxycheck?.vpn) && "proxycheck.io",
    ].filter(Boolean),
    vpn: ipapiIs?.vpn || null,
    datacenter: ipapiIs?.datacenter || null,
    ipqs: ipqs
      ? {
          vpn: Boolean(ipqs.vpn),
          proxy: Boolean(ipqs.proxy),
          tor: Boolean(ipqs.tor),
          fraudScore: num(ipqs.fraudScore),
          recentAbuse: Boolean(ipqs.recentAbuse),
          type: clean(ipqs.type),
        }
      : null,
    proxycheck: proxycheck
      ? {
          proxy: Boolean(proxycheck.proxy),
          vpn: Boolean(proxycheck.vpn),
          type: clean(proxycheck.type),
          risk: num(proxycheck.risk),
        }
      : null,
    sources: results.map((r) => ({
      name: r.label,
      ok: r.ok,
      error: r.ok ? undefined : r.error,
    })),
    raw: {
      ipApi: summarize(ipApi),
      ipwho: summarize(ipwho),
      ipinfo: summarize(ipinfo),
      ipapiIs: summarize(ipapiIs),
      ipapiCo: summarize(ipapiCo),
      ipqs: summarize(ipqs),
      proxycheck: summarize(proxycheck),
    },
  };

  cache.set(ip, { at: Date.now(), value });
  return value;
}

function report(source, loc) {
  const city = clean(loc.city);
  const region = clean(loc.region);
  const country = clean(loc.country);
  const countryCode = clean(loc.countryCode)?.toUpperCase() || null;
  const latitude = num(loc.lat);
  const longitude = num(loc.lon);
  const timezone = clean(loc.timezone);
  const zip = cleanZip(loc.zip);
  if (!city && !region && latitude == null) return null;
  const family = loc.family || "geo";
  const fallback = isNycDefault(latitude, longitude);
  return {
    source,
    family,
    fallback,
    city,
    region: region || (city === "New York" ? "New York" : null),
    country,
    countryCode,
    zip,
    lat: latitude,
    lon: longitude,
    timezone,
  };
}

function mergeLocation(reports) {
  const usable = reports.filter(Boolean);
  if (!usable.length) {
    return {
      city: null,
      region: null,
      country: null,
      countryCode: null,
      zip: null,
      lat: null,
      lon: null,
      timezone: null,
      agreement: 0,
      reports: [],
    };
  }

  let located = usable.filter((row) => row.lat != null && row.lon != null && !row.fallback);
  if (!located.length) located = usable.filter((row) => row.lat != null && row.lon != null);
  const clusters = [];
  for (const point of located) {
    const hit = clusters.find((cluster) => km(cluster[0], point) <= 160);
    if (hit) hit.push(point);
    else clusters.push([point]);
  }
  clusters.sort((a, b) => b.length - a.length);
  const cluster = clusters[0]?.length ? clusters[0] : usable;
  const lat = avg(cluster.map((row) => row.lat));
  const lon = avg(cluster.map((row) => row.lon));
  const city = mode(cluster.map((row) => row.city), { lat, lon, cluster, field: "city" });

  return {
    city,
    region: mode(cluster.map((row) => row.region)),
    country: mode(cluster.map((row) => row.country)),
    countryCode: mode(cluster.map((row) => row.countryCode)),
    zip: zipFor(cluster, city),
    lat,
    lon,
    timezone: mode(cluster.map((row) => row.timezone)),
    agreement: usable.length ? cluster.length / usable.length : 0,
    reports: usable,
  };
}

function mode(values, geo) {
  const counted = new Map();
  for (const value of values.filter(Boolean)) {
    const key = value.toLowerCase();
    const row = counted.get(key) || { n: 0, sample: value };
    row.n += 1;
    counted.set(key, row);
  }
  const ranked = [...counted.values()].sort((a, b) => b.n - a.n);
  if (!ranked.length) return null;
  if (!geo || ranked.length === 1 || ranked[0].n > ranked[1].n) return ranked[0].sample;
  const tied = ranked.filter((row) => row.n === ranked[0].n).map((row) => row.sample.toLowerCase());
  let best = ranked[0].sample;
  let bestKm = Infinity;
  for (const row of geo.cluster || []) {
    if (!tied.includes((row[geo.field] || "").toLowerCase())) continue;
    if (row.lat == null || geo.lat == null) continue;
    const distance = km(row, { lat: geo.lat, lon: geo.lon });
    if (distance < bestKm) {
      bestKm = distance;
      best = row[geo.field];
    }
  }
  return best;
}

function avg(values) {
  const nums = values.filter((value) => Number.isFinite(value));
  if (!nums.length) return null;
  return Math.round((nums.reduce((sum, n) => sum + n, 0) / nums.length) * 10000) / 10000;
}

function km(a, b) {
  const toRad = (n) => (n * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const s =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 12742 * Math.asin(Math.sqrt(s));
}

function clean(value) {
  if (value == null) return null;
  const text = String(value).trim();
  return text && text !== "undefined" ? text : null;
}

function zipFor(cluster, city) {
  const named = city
    ? cluster.filter((row) => (row.city || "").toLowerCase() === city.toLowerCase() && row.zip)
    : [];
  return mode(named.map((row) => row.zip)) || mode(cluster.map((row) => row.zip));
}

function cleanZip(value) {
  const text = clean(value);
  if (!text) return null;
  const us = text.match(/\b(\d{5})(?:-\d{4})?\b/);
  return us ? us[1] : text;
}

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function isNycDefault(lat, lon) {
  if (lat == null || lon == null) return false;
  return km({ lat, lon }, { lat: 40.7128, lon: -74.006 }) < 8;
}

async function fetchIpqs(ip) {
  const key = process.env.IPQS_KEY;
  if (key) {
    const data = await fetchJson(
      `https://www.ipqualityscore.com/api/json/ip/${encodeURIComponent(key)}/${encodeURIComponent(ip)}`
    );
    if (data?.success === false) throw new Error(data.message || "IPQS failed");
    return {
      city: data.city,
      region: data.region,
      country: data.country,
      country_code: data.country_code,
      latitude: data.latitude,
      longitude: data.longitude,
      timezone: data.timezone,
      zip: data.zip_code || data.zip,
      proxy: Boolean(data.proxy),
      vpn: Boolean(data.vpn),
      tor: Boolean(data.tor),
      fraudScore: num(data.fraud_score),
      recentAbuse: Boolean(data.recent_abuse),
      type: data.connection_type || (data.vpn ? "VPN" : data.proxy ? "Proxy" : null),
    };
  }

  const html = await fetchText(`https://ipscore.me/check/${encodeURIComponent(ip)}`, 7000);
  return parseIpscore(html);
}

function parseIpscore(html) {
  const field = (label) => {
    const match = html.match(
      new RegExp(`dash-label">${label}</span><span class="dash-value[^"]*">([^<]+)`)
    );
    return match?.[1]?.replace(/\s+/g, " ").trim() || null;
  };
  const flag = (label) => {
    const match = html.match(
      new RegExp(
        `ip-flag-label">${label}</div>\\s*<div class="ip-flag-value([^"]*)">\\s*([^<]+)`,
        "i"
      )
    );
    const text = match?.[2]?.replace(/\s+/g, " ").trim() || "";
    const warn = /warn|bad|danger/i.test(match?.[1] || "");
    return warn || (/detected/i.test(text) && !/\bnot\b/i.test(text));
  };
  const city = field("City");
  const countryRaw = field("Country") || "";
  const type = field("Type") || "";
  const proxyVpn = flag("Proxy / VPN");
  const torFlag = flag("Tor Network");
  const abuse = flag("Abuse / Blacklist");
  const coord = html.match(/(-?\d+\.\d+)°E,\s*(-?\d+\.\d+)°N/);
  const vpn = /vpn/i.test(type) || proxyVpn;
  const proxy = /proxy/i.test(type) || proxyVpn;
  return {
    city,
    region: city === "New York" ? "New York" : field("Region"),
    country: countryRaw.replace(/^\[US\]\s*/i, "") || "United States",
    country_code: /\[US\]|\bUS\b/i.test(countryRaw) ? "US" : null,
    latitude: coord ? Number(coord[2]) : null,
    longitude: coord ? Number(coord[1]) : null,
    timezone: field("Timezone"),
    zip: field("Zip") || field("Postal") || field("ZIP"),
    proxy,
    vpn,
    tor: torFlag,
    fraudScore: num(html.match(/ip-risk-score[^"]*">\s*(\d{1,3})/)?.[1]),
    recentAbuse: abuse,
    type,
  };
}

async function fetchProxycheck(ip) {
  const data = await fetchJson(
    `https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1&risk=1`
  );
  const row = data?.[ip];
  if (!row || typeof row !== "object") throw new Error("proxycheck empty");
  return {
    proxy: String(row.proxy || "").toLowerCase() === "yes",
    vpn: /vpn/i.test(row.type || ""),
    type: row.type || null,
    risk: num(row.risk),
  };
}

function truthy(value) {
  return Boolean(value) && value !== "false";
}

function summarize(data) {
  if (!data || typeof data !== "object") return data ?? null;
  const skip = new Set(["readme"]);
  const out = {};
  for (const [k, v] of Object.entries(data)) {
    if (!skip.has(k)) out[k] = v;
  }
  return out;
}
