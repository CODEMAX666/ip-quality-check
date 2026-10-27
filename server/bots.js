const BOT_AGENT =
  /(?<!cu)bot\b|crawl|spider|slurp|headless|phantomjs|selenium|puppeteer|playwright|curl|wget|python|httpx|aiohttp|scrapy|go-http-client|java\/|okhttp|libwww|perl|node-fetch|undici|axios|postman|insomnia|^node$/i;

const WINDOW_MS = 60 * 1000;
const MAX_LOOKUPS = 20;
const lookups = new Map();

export function botReason(req) {
  const agent = String(req.headers["user-agent"] || "").trim();
  if (!agent) return "missing user agent";
  if (BOT_AGENT.test(agent)) return "automated user agent";
  if (req.body?.client?.webdriver === true) return "browser automation";
  if (req.method === "POST" && !fromThisPage(req)) return "not sent from this page";
  return null;
}

export function overLimit(key, now = Date.now()) {
  const entry = lookups.get(key);
  if (!entry || now >= entry.resetAt) {
    if (lookups.size > 10000) {
      for (const [k, v] of lookups) if (now >= v.resetAt) lookups.delete(k);
    }
    lookups.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_LOOKUPS;
}

function fromThisPage(req) {
  if (req.headers["sec-fetch-site"] === "same-origin") return true;
  const origin = req.headers.origin;
  if (!origin) return false;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}
