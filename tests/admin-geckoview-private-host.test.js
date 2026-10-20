import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { createGeckoViewPrivateHostAdapter } from "../src/admin-geckoview-private-host.js";
import { PRIVATE_ATTESTOR_AUDIENCE, privateAttestorMessage } from "../src/admin-pinned-device-attestor.js";

const attestorKeys = await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"}, true, ["sign","verify"]);
const exportedPin = await webcrypto.subtle.exportKey("jwk", attestorKeys.publicKey);
const PIN = Object.freeze({kty:"EC",crv:"P-256",x:exportedPin.x,y:exportedPin.y});
const ACCESS = {access:{aud:"0123456789abcdef0123456789abcdef",async getIdentity(){return {email:"admin@example.test"};}}};
const enabledEnv = (extra={}) => ({
  BKE_GECKOVIEW_PRIVATE_HOST_ENABLED:"true",
  BKE_PREPRODUCTION:"true", BKE_ACCESS_POLICY_VERIFIED:"true",
  BKE_ADMIN_DISCOVERY_ENABLED:"true",
  BKE_ADMIN_ACCESS_ISSUER:"https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD:ACCESS.access.aud, BKE_ADMIN_EMAILS:"admin@example.test",
  BKE_ADMIN_PR_INVENTORY_ENABLED:"true", BKE_ADMIN_PAIRING_ACTIONS_ENABLED:"true",
  BKE_ADMIN_PAIRING_REVIEW_ENABLED:"true", BKE_ADMIN_PROPOSAL_CONSENT_ENABLED:"true",
  BKE_ADMIN_DEVICE_PREPARATION_ENABLED:"true", BKE_NATIVE_DEVICE_ADMISSION_ENABLED:"true",
  ...extra,
});
const hash = char => char.repeat(64);
function signedHost(source, counters={}) {
  const binding = {
    audience:"bke-command-center/preproduction/native-device-admission/v1",
    source, worker_id:"worker-a",
    identity_public_key_sha256:hash("1"), session_binding_sha256:hash("2"),
    chatgpt_target_sha256:hash("3"), browser_profile_sha256:hash("4"),
    bridge_identity_sha256:hash("5"), expires_at_ms:Date.now()+20_000,
  };
  const link = {
    async readCandidate() { counters.reads=(counters.reads||0)+1; throw Error("intentional downstream stop"); },
    async exchangeProof() { throw Error("must not run"); },
  };
  return {
    link,
    trustedHost:{
      async resolveExclusiveLink(){counters.resolves=(counters.resolves||0)+1;return link;},
      async requestSignedBinding(_link,challenge){
        counters.signs=(counters.signs||0)+1;
        const bytes=await webcrypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},attestorKeys.privateKey,
          new TextEncoder().encode(privateAttestorMessage(challenge.request_nonce,binding)));
        return {version:1,request_nonce:challenge.request_nonce,binding,signature:Buffer.from(bytes).toString("base64url")};
      },
    },
  };
}

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
  assert.deepEqual(await adapter.stage({executionCtx: ACCESS}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_LOCKED",
  });
  assert.equal(resolves, 0);
  assert.equal(signs, 0);
});

test("enabled adapter fails closed when trusted server host is absent", async () => {
  const adapter = createGeckoViewPrivateHostAdapter({
    env: enabledEnv(),
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await adapter.stage({executionCtx: ACCESS}), {
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
    env: enabledEnv(),
    trustedHost, pinnedPublicKey: undefined,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await adapter.stage({executionCtx: ACCESS}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_ATTESTOR_NOT_CONFIGURED",
  });
  assert.equal(resolves, 0);
});

test("resolver failure and malformed private links fail closed without retry", async () => {
  let resolves = 0;
  const adapter = createGeckoViewPrivateHostAdapter({
    env: enabledEnv(),
    trustedHost: {
      async resolveExclusiveLink() { resolves++; throw Error("private host detail"); },
      async requestSignedBinding() { throw Error("must not run"); },
    },
    pinnedPublicKey: PIN,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await adapter.stage({executionCtx: ACCESS}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_UNAVAILABLE",
  });
  assert.equal(resolves, 1);
  assert.doesNotMatch(JSON.stringify(await adapter.stage({executionCtx: ACCESS})), /private host detail/u);
  assert.equal(resolves, 2);

  const malformed = createGeckoViewPrivateHostAdapter({
    env: enabledEnv(),
    trustedHost: {
      async resolveExclusiveLink() { return { worker_id: "claimed-by-client" }; },
      async requestSignedBinding() { throw Error("must not run"); },
    },
    pinnedPublicKey: PIN,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  assert.deepEqual(await malformed.stage({ executionCtx: ACCESS, worker_id: "attacker" }), {
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
  assert.deepEqual(await adapter.stage({executionCtx: ACCESS}), {
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
    env: enabledEnv(),
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
  const first = adapter.stage({executionCtx: ACCESS});
  await entered;
  assert.deepEqual(await adapter.stage({executionCtx: ACCESS}), {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_BUSY",
  });
  assert.equal(resolves, 1);
  releaseResolver();
  assert.deepEqual(await first, {
    state: "BLOCKED", code: "GECKOVIEW_PRIVATE_HOST_LINK_INVALID",
  });
  assert.equal(resolves, 1);
});


test("missing, forged, or non-allowlisted Admin Access cannot touch the private host", async () => {
  const counters = {};
  const host = signedHost("GECKOVIEW_EXTENSION_NATIVE", counters);
  const adapter = createGeckoViewPrivateHostAdapter({
    env: enabledEnv(), trustedHost: host.trustedHost, pinnedPublicKey: PIN,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  for (const executionCtx of [
    undefined, {},
    {access:{aud:ACCESS.access.aud,async getIdentity(){return {email:"attacker@example.test"};}}},
    {access:{aud:"wrong",async getIdentity(){return {email:"admin@example.test"};}}},
  ]) {
    assert.deepEqual(await adapter.stage({executionCtx}), {
      state:"BLOCKED",code:"GECKOVIEW_PRIVATE_HOST_ADMIN_DENIED",
    });
  }
  assert.equal(counters.resolves||0,0);
  assert.equal(counters.signs||0,0);
});

test("real pinned P-256 desktop attestation is rejected by GeckoView adapter", async () => {
  const counters = {};
  const host = signedHost("DESKTOP_EXTENSION_NATIVE", counters);
  const adapter = createGeckoViewPrivateHostAdapter({
    env: enabledEnv(), trustedHost: host.trustedHost, pinnedPublicKey: PIN,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  const result = await adapter.stage({executionCtx:ACCESS});
  assert.equal(result.state,"BLOCKED");
  assert.equal(counters.resolves,1);
  assert.equal(counters.signs,1);
  assert.equal(counters.reads||0,0);
});

test("real pinned P-256 GeckoView attestation passes origin gate to nonprivileged downstream blocker", async () => {
  const counters = {};
  const host = signedHost("GECKOVIEW_EXTENSION_NATIVE", counters);
  const adapter = createGeckoViewPrivateHostAdapter({
    env: enabledEnv(), trustedHost: host.trustedHost, pinnedPublicKey: PIN,
    describeResources: async () => ({}), cryptoImpl: webcrypto,
  });
  const result = await adapter.stage({executionCtx:ACCESS});
  assert.equal(result.state,"BLOCKED");
  assert.ok(counters.signs >= 1);
  assert.ok(counters.reads >= 1);
  assert.equal(result.pairing_authority,undefined);
});

test("module stays disconnected from public routes and Cloudflare bindings", () => {
  const source = readFileSync(new URL("../src/admin-geckoview-private-host.js", import.meta.url), "utf8");
  const entry = readFileSync(new URL("../src/cloudflare-worker-entry.js", import.meta.url), "utf8");
  const index = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  assert.match(source, /BKE_GECKOVIEW_PRIVATE_HOST_ENABLED === "true"/u);
  assert.doesNotMatch(entry, /admin-geckoview-private-host/u);
  assert.doesNotMatch(index, /admin-geckoview-private-host/u);
  assert.doesNotMatch(source, /fetch\s*\(/u);
});
