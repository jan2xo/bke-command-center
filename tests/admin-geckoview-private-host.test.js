import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createGeckoViewPrivateHostAdapter } from "../src/admin-geckoview-private-host.js";

const PIN = Object.freeze({ kty: "EC", crv: "P-256", x: "A".repeat(43), y: "A".repeat(43) });

test("default-off adapter never resolves or opens a native link", async () => {
  let resolves = 0, signs = 0;
  const adapter = createGeckoViewPrivateHostAdapter({
    env: {}, pinnedPublicKey: PIN,
    trustedHost: {
      async resolveExclusiveLink() { resolves++; return {}; },
      async requestSignedBinding() { signs++; return {}; },
    },
    describeResources: async () => ({}),
    cryptoImpl: webcrypto,
  });
  assert.deepEqual(await adapter.stage({}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_LOCKED",
  });
  assert.equal(resolves, 0);
  assert.equal(signs, 0);
});

test("enabled adapter fails closed when trusted server host is absent", async () => {
  const adapter = createGeckoViewPrivateHostAdapter({
    env: { BKE_GECKOVIEW_PRIVATE_HOST_ENABLED: "true" },
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await adapter.stage({}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_ADAPTER_REQUIRED",
  });
});

test("enabled adapter refuses missing or invalid server-pinned attestor key", async () => {
  let resolves = 0;
  const trustedHost = {
    async resolveExclusiveLink() { resolves++; return {}; },
    async requestSignedBinding() { return {}; },
  };
  const adapter = createGeckoViewPrivateHostAdapter({
    env: { BKE_GECKOVIEW_PRIVATE_HOST_ENABLED: "true" },
    trustedHost, pinnedPublicKey: undefined,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await adapter.stage({}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_ATTESTOR_NOT_CONFIGURED",
  });
  assert.equal(resolves, 0);
});

test("resolver failure and malformed private links fail closed without retry", async () => {
  let resolves = 0;
  const adapter = createGeckoViewPrivateHostAdapter({
    env: { BKE_GECKOVIEW_PRIVATE_HOST_ENABLED: "true" },
    trustedHost: {
      async resolveExclusiveLink() { resolves++; throw Error("private host detail"); },
      async requestSignedBinding() { throw Error("must not run"); },
    },
    pinnedPublicKey: PIN,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await adapter.stage({}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_UNAVAILABLE",
  });
  assert.equal(resolves, 1);
  assert.doesNotMatch(JSON.stringify(await adapter.stage({})), /private host detail/u);
  assert.equal(resolves, 2);

  const malformed = createGeckoViewPrivateHostAdapter({
    env: { BKE_GECKOVIEW_PRIVATE_HOST_ENABLED: "true" },
    trustedHost: {
      async resolveExclusiveLink() { return { worker_id: "claimed-by-client" }; },
      async requestSignedBinding() { throw Error("must not run"); },
    },
    pinnedPublicKey: PIN,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await malformed.stage({ worker_id: "attacker" }), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_LINK_INVALID",
  });
});


test("a disabled adapter cannot be enabled by mutating its environment later", async () => {
  const env = {};
  let resolves = 0;
  const adapter = createGeckoViewPrivateHostAdapter({
    env,
    trustedHost: {
      async resolveExclusiveLink() { resolves++; return {}; },
      async requestSignedBinding() { throw Error("must not run"); },
    },
    pinnedPublicKey: PIN,
    describeResources: async () => ({}),
    cryptoImpl: webcrypto,
  });
  env.BKE_GECKOVIEW_PRIVATE_HOST_ENABLED = "true";
  assert.deepEqual(await adapter.stage({}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_LOCKED",
  });
  assert.equal(resolves, 0);
});

test("adapter serializes admission attempts while a private link is resolving", async () => {
  let enterResolver;
  let releaseResolver;
  const entered = new Promise(resolve => { enterResolver = resolve; });
  const hold = new Promise(resolve => { releaseResolver = resolve; });
  let resolves = 0;
  const adapter = createGeckoViewPrivateHostAdapter({
    env: { BKE_GECKOVIEW_PRIVATE_HOST_ENABLED: "true" },
    trustedHost: {
      async resolveExclusiveLink() {
        resolves++;
        enterResolver();
        await hold;
        return {};
      },
      async requestSignedBinding() { throw Error("must not run"); },
    },
    pinnedPublicKey: PIN,
    describeResources: async () => ({}),
    cryptoImpl: webcrypto,
  });
  const first = adapter.stage({});
  await entered;
  assert.deepEqual(await adapter.stage({}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_BUSY",
  });
  assert.equal(resolves, 1);
  releaseResolver();
  assert.deepEqual(await first, {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_LINK_INVALID",
  });
  assert.equal(resolves, 1);
});
\ntest("module stays disconnected from public routes and Cloudflare bindings", () => {
  const source = readFileSync(new URL("../src/admin-geckoview-private-host.js", import.meta.url), "utf8");
  const entry = readFileSync(new URL("../src/cloudflare-worker-entry.js", import.meta.url), "utf8");
  const index = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  assert.match(source, /BKE_GECKOVIEW_PRIVATE_HOST_ENABLED === "true"/u);
  assert.doesNotMatch(entry, /admin-geckoview-private-host/u);
  assert.doesNotMatch(index, /admin-geckoview-private-host/u);
  assert.doesNotMatch(source, /fetch\s*\(/u);
});
