const TOR_URL = "https://check.torproject.org/torbulkexitlist";
const REFRESH_MS = 6 * 60 * 60 * 1000;

let exits = new Set();
let loadedAt = 0;
let loading = null;

export async function ensureTorList() {
  if (exits.size && Date.now() - loadedAt < REFRESH_MS) return exits;
  if (loading) return loading;
  loading = refresh().finally(() => {
    loading = null;
  });
  return loading;
}

async function refresh() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch(TOR_URL, {
      signal: ctrl.signal,
      headers: { "user-agent": "handshake-geo/1.0" },
    });
    if (!res.ok) throw new Error(`tor list ${res.status}`);
    const text = await res.text();
    const next = new Set(
      text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"))
    );
    if (next.size) {
      exits = next;
      loadedAt = Date.now();
    }
  } catch {
    // Keep the last successful snapshot, if any.
  } finally {
    clearTimeout(timer);
  }
  return exits;
}

export function isTorExit(ip) {
  return exits.has(ip);
}

export function torMeta() {
  return { count: exits.size, loadedAt: loadedAt || null };
}
