const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

export function normalizeIp(raw) {
  if (!raw) return null;
  let ip = String(raw).trim().replace(/^\[|\]$/g, "");
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);
  if (!isValidIp(ip)) return null;
  return ip;
}

export function isValidIp(ip) {
  if (!ip) return false;
  if (IPV4.test(ip)) {
    return ip.split(".").every((octet) => {
      const n = Number(octet);
      return n >= 0 && n <= 255 && String(n) === String(Number(octet));
    });
  }
  return ip.includes(":") && IPV6.test(ip);
}

export function isPrivateIp(ip) {
  const n = normalizeIp(ip);
  if (!n) return true;
  if (n.includes(":")) {
    const compact = n.toLowerCase();
    return (
      compact === "::1" ||
      compact.startsWith("fc") ||
      compact.startsWith("fd") ||
      compact.startsWith("fe80")
    );
  }
  const [a, b] = n.split(".").map(Number);
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

export function clientIpFromRequest(req) {
  const headers = [
    "cf-connecting-ip",
    "true-client-ip",
    "x-real-ip",
    "x-forwarded-for",
    "x-client-ip",
    "forwarded",
  ];

  for (const name of headers) {
    const value = req.headers[name];
    if (!value) continue;
    if (name === "forwarded") {
      const match = String(value).match(/for=(?:"?\[?)([0-9a-f.:]+)/i);
      const parsed = normalizeIp(match?.[1]);
      if (parsed) return { ip: parsed, source: "forwarded" };
      continue;
    }
    const first = String(value).split(",")[0];
    const parsed = normalizeIp(first);
    if (parsed) return { ip: parsed, source: name };
  }

  const socketIp = normalizeIp(req.socket?.remoteAddress);
  return {
    ip: socketIp,
    source: "socket",
  };
}

export function parseAsn(value) {
  if (value == null) return { number: null, organization: null };
  if (typeof value === "number") return { number: value, organization: null };
  const text = String(value);
  const match = text.match(/AS(\d+)\s*(.*)/i);
  if (!match) return { number: null, organization: text || null };
  return {
    number: Number(match[1]),
    organization: match[2]?.trim() || null,
  };
}
