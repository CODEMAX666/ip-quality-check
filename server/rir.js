// Coarse IPv4 RIR from the first octet. Good enough to catch leased
// European/Asia space sold as "US residential" — the pattern Spur flags
// as GEO_MISMATCH on ISP proxies.
const RIPE = new Set([
  2, 5, 31, 37, 46, 51, 53, 57, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
  88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193,
  194, 195, 212, 213, 217,
]);
const APNIC = new Set([
  1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112,
  113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150,
  153, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221,
  222, 223,
]);
const LACNIC = new Set([177, 179, 181, 186, 187, 189, 190, 191, 200, 201]);
const AFRINIC = new Set([41, 102, 105, 154, 196, 197]);

const ARIN_COUNTRIES = new Set(["US", "CA", "PR", "GU", "VI", "AS", "UM", "MX"]);
const ANYCAST_ORGS = /cloudflare|fastly|akamai|incapsula|cloudfront|google|amazon|microsoft/i;

export function rirForIp(ip) {
  if (!ip || ip.includes(":")) return null;
  const octet = Number(String(ip).split(".")[0]);
  if (!Number.isFinite(octet)) return null;
  if (RIPE.has(octet)) return "RIPE";
  if (APNIC.has(octet)) return "APNIC";
  if (LACNIC.has(octet)) return "LACNIC";
  if (AFRINIC.has(octet)) return "AFRINIC";
  return "ARIN";
}

export function rirGeoMismatch(ip, countryCode, orgText = "") {
  const rir = rirForIp(ip);
  const cc = String(countryCode || "").toUpperCase();
  if (!rir || !cc) {
    return { matched: false, rir, detail: "Not enough data to compare registry and location." };
  }
  if (ANYCAST_ORGS.test(orgText)) {
    return { matched: false, rir, detail: "CDN network, so registry and location are not compared." };
  }
  if (rir !== "ARIN" && ARIN_COUNTRIES.has(cc)) {
    return {
      matched: true,
      rir,
      detail: `Registered with ${rir}, outside North America, but placed in ${cc}. Common for leased proxy and VPN addresses.`,
    };
  }
  if (rir === "ARIN" && !ARIN_COUNTRIES.has(cc) && !["BR", "AR", "CL", "CO"].includes(cc)) {
    return {
      matched: true,
      rir,
      detail: `Registered in North America, but placed in ${cc}.`,
    };
  }
  return {
    matched: false,
    rir,
    detail: `Registry (${rir}) fits ${cc}.`,
  };
}

const GENERIC = new Set([
  "llc", "ltd", "inc", "corp", "co", "sa", "ag", "bv", "gmbh", "as", "asn",
  "the", "and", "of", "communications", "communication", "cable", "internet",
  "services", "service", "network", "networks", "telecom", "telecommunications",
  "holdings", "group", "limited", "company",
]);

const BRAND_ALIASES = [
  ["spectrum", "charter", "twc", "timewarner"],
  ["comcast", "xfinity"],
  ["rcn", "astound"],
  ["att", "atandt"],
  ["verizon", "frontier", "fios"],
];

export function orgAsnConflict(asnOrg, organization, isp) {
  const a = fold(asnOrg);
  const b = fold(organization);
  const c = fold(isp);
  const other = [b, c].filter((x) => x && x !== a);
  if (!a || !other.length) {
    return { matched: false, detail: "Network and owner match." };
  }
  for (const candidate of other) {
    if (a === candidate || a.includes(candidate) || candidate.includes(a)) continue;
    if (sameBrand(a, candidate)) continue;
    const overlap = tokens(a).filter((t) => tokens(candidate).includes(t));
    if (overlap.length) continue;
    return {
      matched: true,
      detail: `Network is ${asnOrg}, but the address is registered to ${organization || isp}.`,
    };
  }
  return { matched: false, detail: "Network and owner match." };
}

function sameBrand(a, b) {
  const left = new Set(expandBrands(tokens(a)));
  return expandBrands(tokens(b)).some((t) => left.has(t));
}

function expandBrands(list) {
  const out = new Set(list);
  for (const group of BRAND_ALIASES) {
    if (group.some((alias) => out.has(alias))) group.forEach((alias) => out.add(alias));
  }
  return [...out];
}

const FOREIGN_HINTS = [
  { country: "TR", re: /turknet|turkcell|turk telekom|ttnet|superonline|iletisim|telekomunikasyon|\.tr\b/i },
  { country: "DE", re: /deutsche telekom|telekom deutschland|1und1|1&1|3xk tech|drei-k-tech|plainproxies|1337 services|services-1337/i },
  { country: "FR", re: /orange france|free sas|\bsfr\b/i },
  { country: "NL", re: /worldstream|leaseweb|serverius|serverion|des capital|ipxo|nforce|global layer|altushost|eweka|base ip|worktitans/i },
  { country: "GB", re: /datacamp|m247|packethub|clouvider|amarutu|secfirewall|hydra communications|uk dedicated|global connectivity solutions/i },
  { country: "RU", re: /rostelecom|ertelecom|mts pjsc|selectel|timeweb|aeza|petersburg internet|goodline|ipmen/i },
  { country: "IN", re: /hostroyale|bharti airtel|reliance jio/i },
  { country: "LT", re: /melbikomas|melbicom|cherry servers|oxylabs|bacloud|code200|itproximus/i },
  { country: "MD", re: /alexhost|trabia/i },
  { country: "AE", re: /flash edge|asn-feit|iproyal/i },
  { country: "PA", re: /cyberzone s\.a|tefincom|private layer/i },
];

export function foreignOrgInCountry(text, countryCode) {
  const cc = String(countryCode || "").toUpperCase();
  if (!text || !cc) {
    return { matched: false, detail: "No operator and country to compare." };
  }
  for (const hint of FOREIGN_HINTS) {
    if (hint.country !== cc && hint.re.test(text)) {
      return {
        matched: true,
        detail: `Operator looks based in ${hint.country}, but the IP is placed in ${cc}.`,
      };
    }
  }
  return { matched: false, detail: "Operator fits the IP's country." };
}

function fold(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/&/g, "")
    .replace(/as\d+/g, " ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function tokens(folded) {
  return folded.split(/\s+/).filter((t) => t.length > 2 && !GENERIC.has(t));
}
