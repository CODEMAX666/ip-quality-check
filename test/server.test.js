import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";

const PORT = 3799;
const BASE = `http://127.0.0.1:${PORT}`;

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
});
