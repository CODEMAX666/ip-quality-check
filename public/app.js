const $ = (id) => document.getElementById(id);

const state = {
  handshake: null,
  result: null,
  client: null,
  map: null,
  marker: null,
  circle: null,
};

const CLEAR_SUMMARY = ["proxy_flag", "known_vpn_server", "tor_exit", "datacenter"];

boot().catch(showError);

$("lookup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const ip = $("lookup-ip").value.trim();
  if (!ip) return;
  await classifyIp(ip, state.client || (await collectClientSignals()));
});

window.addEventListener("resize", () => state.map?.invalidateSize());

async function boot() {
  initMap();
  const handshake = await getJson("/api/ip");
  state.handshake = handshake;
  renderHandshake(handshake);

  const client = await collectClientSignals();
  state.client = client;
  await classifyIp(handshake.classifyIp, client);
}

function initMap() {
  const map = L.map("map", {
    zoomControl: false,
    attributionControl: true,
    worldCopyJump: true,
  }).setView([20, 8], 2);

  L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
    {
      attribution: "Tiles &copy; Esri",
      maxZoom: 16,
    }
  ).addTo(map);
  L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
    {
      attribution: false,
      maxZoom: 16,
    }
  ).addTo(map);

  L.control.zoom({ position: "bottomright" }).addTo(map);
  state.map = map;
  requestAnimationFrame(() => map.invalidateSize());
}

async function classifyIp(ip, client) {
  $("verdict-label").textContent = "Checking…";
  try {
    const result = await postJson("/api/classify", { ip, client });
    state.result = result;
    renderResult(result);
  } catch (error) {
    showError(error, ip);
  }
}

function showError(error, ip) {
  if (ip) $("ip-display").textContent = ip;
  $("place").textContent = "";
  $("facts").innerHTML = "";
  $("signals").innerHTML = "";
  setTone($("map"));
  setTone(document.querySelector(".card"));
  drawMap({});
  $("verdict").className = "verdict";
  $("verdict-label").textContent = "Check failed";
  $("verdict-score").textContent = error?.message || "Try again in a moment.";
}

function setTone(el, tone) {
  for (const name of [...el.classList]) {
    if (name.startsWith("tone-")) el.classList.remove(name);
  }
  if (tone) el.classList.add(`tone-${tone}`);
}

function renderHandshake(data) {
  $("ip-display").textContent = data.classifyIp || data.ip || "unknown";
}

function renderResult(result) {
  const ctx = result.context;
  const loc = ctx.location || {};
  const verdict = ctx.verdict || "unknown";
  const tone = toneFor(verdict);
  const box = $("verdict");
  box.className = `verdict ${verdict}`;
  $("verdict-label").textContent = labelFor(verdict);
  $("verdict-score").textContent = `Confidence ${pct(ctx.confidence)} · ${(ctx.infrastructure || "unknown").toUpperCase()}`;
  $("ip-display").textContent = result.handshake?.lookedUp || ctx.ip;
  $("place").textContent = placeLine(loc) || "Location unknown";
  $("place").title = placeAlt(loc);
  setTone($("map"), tone);
  setTone(document.querySelector(".card"), tone);

  const risks = ctx.risks || [];
  const ipqs = ctx.ipqs || {};
  const ipqsDown = (ctx.sources || []).some((source) => source.name === "ipqs" && !source.ok);
  const ipqsBits = [
    ipqs.vpn ? "VPN" : null,
    ipqs.proxy ? "Proxy" : null,
    ipqs.tor ? "TOR" : null,
  ].filter(Boolean);
  if (ctx.ipqs && !ipqsBits.length) ipqsBits.push("Clean");
  if (ipqs.fraudScore != null) ipqsBits.push(String(ipqs.fraudScore));
  const ipqsHot = Boolean(ipqs.vpn || ipqs.proxy || ipqs.tor || (ipqs.fraudScore != null && ipqs.fraudScore >= 75));
  $("facts").innerHTML = [
    item("ASN", ctx.as?.number ? `AS${ctx.as.number}` : "—"),
    item("Org", ctx.organization || ctx.isp || "—"),
    item("IPQS", ipqsBits.join(" · ") || (ipqsDown ? "Unavailable" : "—"), ipqsHot ? "hot" : ""),
    item("Risks", risks.join(", ") || "None", risks.length ? "hot" : "ok"),
  ].join("");

  const signals = ctx.signals || [];
  const matched = signals.filter((signal) => signal.matched);
  const shown = matched.length
    ? matched
    : signals.filter((signal) => CLEAR_SUMMARY.includes(signal.id));
  $("signals").innerHTML = shown
    .map(
      (signal) => `
      <li class="signal ${signal.matched ? "hit" : "clear"}">
        <p class="signal-label">${escapeHtml(signal.label)}</p>
        <p class="signal-detail">${escapeHtml(signal.detail)}</p>
      </li>`
    )
    .join("");

  drawMap(loc, tone);
}

function drawMap(loc, tone = "warn") {
  const map = state.map;
  if (!map) return;

  if (state.marker) {
    map.removeLayer(state.marker);
    state.marker = null;
  }
  if (state.circle) {
    map.removeLayer(state.circle);
    state.circle = null;
  }

  const lat = Number(loc?.lat);
  const lon = Number(loc?.lon);
  const hasPoint = Number.isFinite(lat) && Number.isFinite(lon);
  $("map-empty").classList.toggle("hidden", hasPoint);

  if (!hasPoint) {
    map.setView([20, 8], 2);
    map.invalidateSize();
    return;
  }

  const hex = toneHex(tone);
  const latlng = [lat, lon];
  const label = pinLabel(loc);
  const icon = L.divIcon({
    className: `pin ${tone}`,
    html: `<span class="dot"></span><span class="pin-label">${label}</span>`,
    iconSize: [260, 52],
    iconAnchor: [10, 26],
  });

  state.marker = L.marker(latlng, { icon, keyboard: false }).addTo(map);

  state.circle = L.circle(latlng, {
    radius: 28000,
    color: hex,
    weight: 2,
    fillColor: hex,
    fillOpacity: 0.18,
  }).addTo(map);

  const card = document.querySelector(".card");
  const padLeft =
    getComputedStyle(card).position === "absolute"
      ? card.getBoundingClientRect().right - map.getContainer().getBoundingClientRect().left + 24
      : 20;
  map.flyToBounds(L.latLng(latlng).toBounds(120000), {
    paddingTopLeft: [padLeft, 24],
    paddingBottomRight: [48, 48],
    maxZoom: 7,
    duration: 0.85,
  });
  map.invalidateSize();
}

async function collectClientSignals() {
  const nav = performance.getEntriesByType("navigation")[0];
  const tcpRttMs = nav ? nav.connectEnd - nav.connectStart : null;
  const tlsRttMs =
    nav && nav.secureConnectionStart > 0 ? nav.connectEnd - nav.secureConnectionStart : null;

  const [webrtcIps, browserPublicIp] = await Promise.all([
    collectWebRtcIps(),
    fetchBrowserPublicIp(),
  ]);

  return {
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    languages: [...(navigator.languages || [navigator.language])].filter(Boolean),
    userAgent: navigator.userAgent,
    platform: navigator.userAgentData?.platform || navigator.platform,
    webdriver: navigator.webdriver === true,
    webrtcIps,
    browserPublicIp,
    tcpRttMs: finite(tcpRttMs),
    tlsRttMs: finite(tlsRttMs),
  };
}

function collectWebRtcIps() {
  return new Promise((resolve) => {
    const ips = new Set();
    const done = () => resolve([...ips]);
    const timer = setTimeout(done, 3500);

    try {
      const pc = new RTCPeerConnection({
        iceServers: [{ urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"] }],
      });
      pc.createDataChannel("handshake-geo");
      pc.onicecandidate = (event) => {
        if (!event.candidate) {
          clearTimeout(timer);
          pc.close();
          done();
          return;
        }
        const found = event.candidate.candidate.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/g);
        (found || []).forEach((ip) => ips.add(ip));
      };
      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(() => {
          clearTimeout(timer);
          done();
        });
    } catch {
      clearTimeout(timer);
      done();
    }
  });
}

async function fetchBrowserPublicIp() {
  try {
    const data = await fetch("https://api.ipify.org?format=json", { cache: "no-store" }).then((r) =>
      r.json()
    );
    return data.ip || null;
  } catch {
    return null;
  }
}

function item(label, value, tone = "") {
  return `<div class="${tone}"><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value ?? "—"))}</dd></div>`;
}

function toneFor(verdict) {
  if (verdict === "residential") return "ok";
  if (verdict === "privacy_relay") return "relay";
  if (verdict === "datacenter") return "warn";
  if (["vpn", "proxy", "tor", "suspicious"].includes(verdict)) return "bad";
  return "warn";
}

function toneHex(tone) {
  return {
    ok: "#22c55e",
    bad: "#ef4444",
    warn: "#f59e0b",
    relay: "#a855f7",
  }[tone] || "#f59e0b";
}

function placeLine(loc) {
  const cityState = [loc?.city, loc?.region].filter(Boolean).join(", ");
  const zip = loc?.zip ? ` · ${loc.zip}` : "";
  return `${cityState}${zip}`.trim();
}

function pinLabel(loc) {
  const cityState = [loc?.city, loc?.region].filter(Boolean).join(", ") || "Unknown place";
  const zip = loc?.zip ? `<b>${escapeHtml(loc.zip)}</b>` : "";
  return `<strong>${escapeHtml(cityState)}</strong>${zip}`;
}

function placeAlt(loc) {
  const reports = loc?.reports || [];
  if (reports.length < 2) return "";
  const unique = [];
  for (const row of reports) {
    const line = [row.city, row.region].filter(Boolean).join(", ");
    if (!line) continue;
    const key = line.toLowerCase();
    if (unique.some((item) => item.key === key)) continue;
    unique.push({ key, line, source: row.source });
  }
  if (unique.length < 2) return `${reports.length} sources agree`;
  return unique.map((item) => `${item.source}: ${item.line}`).join(" · ");
}

function labelFor(verdict) {
  return {
    vpn: "VPN exit",
    proxy: "Proxy / VPN",
    tor: "Tor exit",
    privacy_relay: "Privacy relay",
    datacenter: "Datacenter IP",
    suspicious: "Suspicious",
    residential: "Residential / ISP",
  }[verdict] || verdict;
}

function pct(n) {
  if (n == null || Number.isNaN(Number(n))) return "—";
  return `${Math.round(Number(n) * 100)}%`;
}

function finite(n) {
  return Number.isFinite(n) ? n : null;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function getJson(url) {
  const res = await fetch(url);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
