import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";

const PORT = 3799;
const BASE = `http://127.0.0.1:${PORT}`;
const BROWSER = {
  "content-type": "application/json",
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
  origin: BASE,
};

test("server serves the page and API", async (t) => {
  const server = spawn(process.execPath, ["server.js"], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: ["ignore", "pipe", "inherit"],
  });
  t.after(() => server.kill());

  await new Promise((resolve, reject) => {
    server.stdout.on("data", (chunk) => {
      if (String(chunk).includes(`:${PORT}`)) resolve();
    });
    server.once("exit", (code) => reject(new Error(`server exited with code ${code}`)));
  });

  const health = await fetch(`${BASE}/api/health`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).ok, true);

  const page = await fetch(BASE);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /IP Quality Check/);

  const badJson = await fetch(`${BASE}/api/classify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{",
  });
  assert.equal(badJson.status, 400);

  const scripted = await fetch(`${BASE}/api/classify`, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "curl/8.4.0" },
    body: JSON.stringify({ ip: "8.8.8.8" }),
  });
  assert.equal(scripted.status, 403);

  const notAnIp = await fetch(`${BASE}/api/classify`, {
    method: "POST",
    headers: BROWSER,
    body: JSON.stringify({ ip: "not-an-ip" }),
  });
  assert.equal(notAnIp.status, 400);
  assert.equal((await notAnIp.json()).error, "That isn't a valid IP address.");
});
