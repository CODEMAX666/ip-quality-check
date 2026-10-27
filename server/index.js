import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classify } from "./classify.js";
import { enrichIp, publicEgressIp } from "./enrich.js";
import { clientIpFromRequest, isPrivateIp, isValidIp, normalizeIp } from "./ip.js";
import { intelMeta } from "./intel.js";
import { ensureTorList, torMeta } from "./tor.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadEnv(path.join(__dirname, "..", ".env"));

const app = express();
const PORT = Number(process.env.PORT) || 3780;

app.set("trust proxy", true);
app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "..", "public")));

ensureTorList().catch(() => {});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    spurConfigured: Boolean(process.env.SPUR_TOKEN),
    ipapiIsConfigured: Boolean(process.env.IPAPI_IS_KEY),
    tor: torMeta(),
    intel: intelMeta(),
  });
});

app.get("/api/ip", async (req, res) => {
  try {
    const handshake = clientIpFromRequest(req);
    const privateHandshake = isPrivateIp(handshake.ip);
    let publicIp = null;
    if (privateHandshake) publicIp = await publicEgressIp();
    const classifyIp = privateHandshake ? publicIp || handshake.ip : handshake.ip;

    res.json({
      phase: "handshake",
      ip: handshake.ip,
      source: handshake.source,
      privateHandshake,
      publicIp,
      classifyIp,
      note: privateHandshake
        ? "The HTTP handshake arrived from a private address (localhost/LAN). Classifying this host's public egress IP — that is the address Spur would see."
        : "The connecting IP was taken from the HTTP request before any VPN intelligence lookup.",
      headers: visibleHeaders(req),
      at: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({ error: error.message || "handshake failed" });
  }
});

app.post("/api/classify", async (req, res) => {
  try {
    const handshake = clientIpFromRequest(req);
    const requested = normalizeIp(req.body?.ip);
    const ip = requested || handshake.ip;
    if (!isValidIp(ip)) {
      return res.status(400).json({ error: "No valid IP to classify." });
    }

    const privateTarget = isPrivateIp(ip);
    const target = privateTarget ? (await publicEgressIp()) || ip : ip;
    const enrichment = await enrichIp(target);
    const context = classify({
      enrichment,
      client: req.body?.client || {},
      handshake: {
        ip: handshake.ip,
        publicIp: privateTarget ? target : handshake.ip,
      },
    });

    res.json({
      phase: "first_pass",
      handshake: {
        ip: handshake.ip,
        source: handshake.source,
        lookedUp: target,
        usedPublicEgress: privateTarget && target !== handshake.ip,
      },
      context,
      spur: {
        configured: Boolean(process.env.SPUR_TOKEN),
        queried: false,
        hint: "Run /api/spur after this first pass. Spur is the observation network; this app is the handshake + open-signal analog.",
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message || "classify failed" });
  }
});

app.post("/api/spur", async (req, res) => {
  const token = process.env.SPUR_TOKEN;
  const ip = normalizeIp(req.body?.ip);
  if (!token) {
    return res.status(501).json({
      error: "SPUR_TOKEN is not set. This app is meant to classify the IP first; Spur is the optional second hop.",
      docs: "https://docs.spur.us/context-api",
    });
  }
  if (!isValidIp(ip) || isPrivateIp(ip)) {
    return res.status(400).json({ error: "A public IP is required for Spur." });
  }
  try {
    const response = await fetch(`https://api.spur.us/v2/context/${encodeURIComponent(ip)}`, {
      headers: { Token: token, "user-agent": "handshake-geo/1.0" },
    });
    const remaining = response.headers.get("x-balance-remaining");
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(response.status).json({
        error: body?.error || body?.message || `Spur returned ${response.status}`,
        remaining,
      });
    }
    res.json({ ip, remaining, context: body });
  } catch (error) {
    res.status(502).json({ error: error.message || "Spur request failed" });
  }
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const badJson = err instanceof SyntaxError && err.status === 400 && "body" in err;
  res.status(badJson ? 400 : err.status || 500).json({
    error: badJson ? "Invalid JSON body." : err.message || "Request failed.",
  });
});

app.listen(PORT, () => {
  console.log(`handshake-geo on http://127.0.0.1:${PORT}`);
});

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim().replace(/^['"]|['"]$/g, "");
    if (!process.env[key]) process.env[key] = value;
  }
}

function visibleHeaders(req) {
  const names = [
    "cf-connecting-ip",
    "true-client-ip",
    "x-real-ip",
    "x-forwarded-for",
    "forwarded",
    "via",
    "user-agent",
    "accept-language",
  ];
  const out = {};
  for (const name of names) {
    if (req.headers[name]) out[name] = req.headers[name];
  }
  return out;
}
