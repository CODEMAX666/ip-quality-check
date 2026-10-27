import assert from "node:assert/strict";
import test from "node:test";
import { botReason, overLimit } from "../server/bots.js";

const chrome =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

function request({ agent = chrome, method = "POST", site = "same-origin", origin, body = {} } = {}) {
  return {
    method,
    headers: {
      "user-agent": agent,
      "sec-fetch-site": site,
      origin,
      host: "ip-quality-check.vercel.app",
    },
    body,
  };
}

test("real browsers pass", () => {
  assert.equal(botReason(request()), null);
  assert.equal(
    botReason(request({ agent: "Mozilla/5.0 (Linux; Android 11; CUBOT X30) Chrome/141.0 Mobile Safari/537.36" })),
    null
  );
  assert.equal(
    botReason(request({ site: null, origin: "https://ip-quality-check.vercel.app" })),
    null
  );
});

test("script and crawler user agents are rejected", () => {
  for (const agent of [
    "",
    "curl/8.4.0",
    "python-requests/2.32.3",
    "node",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/141.0.0.0 Safari/537.36",
  ]) {
    assert.ok(botReason(request({ agent })), `should reject "${agent}"`);
  }
});

test("lookups from other sites are rejected", () => {
  assert.ok(botReason(request({ site: "cross-site", origin: "https://example.com" })));
  assert.ok(botReason(request({ site: null })));
});

test("automated browsers are rejected", () => {
  assert.ok(botReason(request({ body: { client: { webdriver: true } } })));
});

test("more than 20 lookups a minute from one IP are rejected", () => {
  const ip = "203.0.113.9";
  for (let i = 0; i < 20; i += 1) assert.equal(overLimit(ip, 0), false);
  assert.equal(overLimit(ip, 0), true);
  assert.equal(overLimit(ip, 60_001), false);
});
