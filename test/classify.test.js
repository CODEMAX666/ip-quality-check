import assert from "node:assert/strict";
import test from "node:test";
import { classify } from "../server/classify.js";

function enrichment(overrides = {}) {
  return {
    ip: "73.162.12.34",
    as: { number: 7922, organization: "Comcast Cable Communications, LLC" },
    organization: "Comcast Cable Communications, LLC",
    isp: "Comcast Cable Communications, LLC",
    hostname: null,
    location: { countryCode: "US", timezone: "America/Los_Angeles" },
    flags: {},
    flaggedBy: [],
    ipqs: null,
    proxycheck: null,
    sources: [],
    ...overrides,
  };
}

const att = {
  ip: "12.78.118.162",
  as: { number: 7018, organization: "AT&T Enterprises, LLC" },
  organization: "AT&T Enterprises, LLC",
  isp: "AT&T Enterprises, LLC",
};

const wholesaleHost = {
  ip: "69.197.177.10",
  as: { number: 32097, organization: "WholeSale Internet, Inc." },
  organization: "Aklweb Host LLC",
  isp: "WholeSale Internet, Inc.",
};

test("clean ISP address is residential with no risks", () => {
  const ctx = classify({ enrichment: enrichment() });
  assert.equal(ctx.verdict, "residential");
  assert.equal(ctx.infrastructure, "ISP");
  assert.deepEqual(ctx.risks, []);
});

test("any source flagging proxy makes the verdict proxy", () => {
  const ctx = classify({
    enrichment: enrichment({
      ...att,
      flags: { proxy: true },
      flaggedBy: ["IPQS"],
      ipqs: { vpn: true, proxy: true, tor: false, fraudScore: 75 },
    }),
  });
  assert.equal(ctx.verdict, "proxy");
  assert.ok(ctx.risks.includes("TUNNEL"));
  assert.ok(ctx.risks.includes("FRAUD"));
});

test("hosting network reports the HOSTING risk", () => {
  const ctx = classify({ enrichment: enrichment(wholesaleHost) });
  assert.equal(ctx.infrastructure, "DATACENTER");
  assert.ok(ctx.risks.includes("HOSTING"));
});

test("proxy flag on a VPN-heavy host is a VPN exit", () => {
  const ctx = classify({
    enrichment: enrichment({
      ...wholesaleHost,
      flags: { proxy: true },
      flaggedBy: ["proxycheck.io"],
    }),
  });
  assert.equal(ctx.verdict, "vpn");
  assert.ok(ctx.risks.includes("TUNNEL"));
});
