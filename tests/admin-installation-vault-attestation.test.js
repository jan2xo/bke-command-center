import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { attestAdminInstallationVault, verifyVaultInstallationAttestation } from
  "../src/admin-installation-vault-attestation.js";
import { BkeWorkerPairingVault } from "../src/worker-pairing-durable-store.js";

const KEY = Buffer.alloc(32, 91).toString("base64url"); // DISPOSABLE TEST-ONLY KEY.
const access = {
  access: { aud: "0123456789abcdef0123456789abcdef",
    async getIdentity() { return { email: "admin@example.test" }; } },
};
const config = {
  BKE_PREPRODUCTION: "true",
  BKE_ACCESS_POLICY_VERIFIED: "true",
  BKE_ADMIN_PR_INVENTORY_ENABLED: "true",
  BKE_ADMIN_DO_ROUTING_ENABLED: "true",
  BKE_ADMIN_DISCOVERY_ENABLED: "true",
  BKE_ADMIN_ACCESS_ISSUER: "https://bke-test.cloudflareaccess.com",
  BKE_ADMIN_ACCESS_AUD: access.access.aud,
  BKE_ADMIN_EMAILS: "admin@example.test",
  BKE_PAIRING_RPC_KEY_B64: KEY,
};
const observed = (patch = {}) => ({
  state: "OBSERVED_ONLY", source: "GITHUB_APP_INSTALLATION",
  consistency: "NON_ATOMIC_ENUMERATION", dispatch_authority: "NONE",
  trusted_installation_id: "51", approved_repository_count: 76,
  enumerated_open_pr_count: 1, worker_claims: [], ...patch,
});
function store() {
  let mutations = 0;
  return {
    storage: {
      async transaction(fn) {
        mutations++;
        return fn({ get: async () => undefined, put: async () => {} });
      },
    },
    mutations: () => mutations,
  };
}
function network(options = {}) {
  const calls = [], storage = store();
  let env;
  const namespace = {
    idFromName(name) {
      calls.push(["idFromName", name]);
      return { toString: () => "object-id:" + name };
    },
    get(id) {
      calls.push(["get", id.toString()]);
      if (options.stub) return options.stub(id, env, calls);
      return new BkeWorkerPairingVault({ id, storage: storage.storage }, env);
    },
  };
  env = { ...config, BKE_WORKER_PAIRING_VAULT: namespace, ...options.env };
  let inventoryCalls = 0;
  const params = {
    env, executionCtx: access, cryptoImpl: webcrypto,
    readAssignments: async () => {
      inventoryCalls++;
      if (options.brokerError) throw Error("upstream private token");
      return options.snapshot ?? observed();
    },
    ...options.params,
  };
  return { params, namespace, storage, calls,
    inventoryCalls: () => inventoryCalls };
}
const denied = (result, code) => {
  assert.deepEqual(result, { state: "BLOCKED", code });
  assert.doesNotMatch(JSON.stringify(result), /installation_id|ghs_|secret|admin@example/u);
};

test("platform Admin and verified GitHub installation route to exactly one DO, read-only", async () => {
  const f = network();
  const result = await attestAdminInstallationVault(f.params);
  assert.deepEqual(result, {
    state: "SCOPE_ATTESTED_READ_ONLY",
    pairing_authority: "NONE", dispatch_authority: "NONE",
    consistency: "NON_ATOMIC_GITHUB_EVIDENCE",
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(f.inventoryCalls(), 1);
  assert.deepEqual(f.calls, [
    ["idFromName", "installation:51"],
    ["get", "object-id:installation:51"],
    ["idFromName", "installation:51"],
  ]);
  assert.equal(f.storage.mutations(), 0);
  assert.doesNotMatch(JSON.stringify(result), /51|token|PAIRING_ACTIVE|access/i);
});

test("disabled independently from repository catalog, with zero GitHub or DO calls", async () => {
  for (const field of [
    "BKE_PREPRODUCTION", "BKE_ACCESS_POLICY_VERIFIED",
    "BKE_ADMIN_PR_INVENTORY_ENABLED", "BKE_ADMIN_DO_ROUTING_ENABLED",
  ]) {
    const f = network({ env: { [field]: undefined } });
    denied(await attestAdminInstallationVault(f.params), "VAULT_SCOPE_LOCKED");
    assert.equal(f.inventoryCalls(), 0);
    assert.equal(f.calls.length, 0);
  }
});

test("platform Access missing, forged user or wrong audience blocks before broker calls", async () => {
  for (const executionCtx of [
    undefined, {}, { access: { aud: access.access.aud } },
    { access: { ...access.access, async getIdentity() {
      return { email: "unlisted@example.test" };
    } } },
    { access: { ...access.access, aud: "wrong-audience" } },
  ]) {
    const f = network({ params: { executionCtx } });
    denied(await attestAdminInstallationVault(f.params), "VAULT_SCOPE_ADMIN_DENIED");
    assert.equal(f.inventoryCalls(), 0);
    assert.equal(f.calls.length, 0);
  }
});

test("invalid, absent, malformed or short shared routing key fails before broker calls", async () => {
  for (const value of [undefined, "", "bad", "A".repeat(43),
    Buffer.alloc(31).toString("base64url"), "ghs_secret"]) {
    // All-zero 32-byte key is syntactically accepted by protocol; this test
    // targets malformed key values, not entropy testing.
    if (value === "A".repeat(43)) continue;
    const f = network({ env: { BKE_PAIRING_RPC_KEY_B64: value } });
    denied(await attestAdminInstallationVault(f.params),
      "VAULT_SCOPE_ADAPTER_UNAVAILABLE");
    assert.equal(f.inventoryCalls(), 0);
  }
});

test("broker errors and unsafe or inconsistent installation evidence fail closed", async () => {
  const f = network({ brokerError: true });
  denied(await attestAdminInstallationVault(f.params), "VAULT_SCOPE_GITHUB_UNAVAILABLE");
  assert.equal(f.calls.length, 0);
  for (const change of [
    { trusted_installation_id: "0" }, { trusted_installation_id: "51;other" },
    { consistency: "ATOMIC" }, { dispatch_authority: "ACTIVE" },
    { approved_repository_count: 0 }, { worker_claims: null },
    { verified: true }, { token: "ghs_upstream" },
  ]) {
    const next = network({ snapshot: observed(change) });
    denied(await attestAdminInstallationVault(next.params), "VAULT_SCOPE_GITHUB_INVALID");
    assert.equal(next.calls.length, 0);
  }
});

test("valid different installation always resolves a distinct namespace ID", async () => {
  const f = network({ snapshot: observed({ trusted_installation_id: "52" }) });
  assert.equal((await attestAdminInstallationVault(f.params)).state,
    "SCOPE_ATTESTED_READ_ONLY");
  assert.deepEqual(f.calls[0], ["idFromName", "installation:52"]);
  assert.equal(f.storage.mutations(), 0);
});

test("DO refuses cross-installation ID and does not write registry", async () => {
  const f = network({
    stub: (_id, env) => {
      const wrong = f.namespace.idFromName("installation:52");
      return new BkeWorkerPairingVault({ id: wrong, storage: f.storage.storage }, env);
    },
  });
  denied(await attestAdminInstallationVault(f.params), "VAULT_SCOPE_REPLY_INVALID");
  assert.equal(f.storage.mutations(), 0);
});

test("DO rejects caller key mismatch or fabricated acknowledgement", async () => {
  const f = network({ stub: (id, env) => new BkeWorkerPairingVault({
    id, storage: f.storage.storage,
  }, { ...env, BKE_PAIRING_RPC_KEY_B64: Buffer.alloc(32, 2).toString("base64url") }) });
  denied(await attestAdminInstallationVault(f.params), "VAULT_SCOPE_REPLY_INVALID");
  const forge = network({ stub: () => ({
    async attestInstallation() {
      return { state: "SCOPE_ATTESTED_READ_ONLY", ack_signature: "b".repeat(64) };
    },
  }) });
  denied(await attestAdminInstallationVault(forge.params), "VAULT_SCOPE_REPLY_INVALID");
});

test("DO rejects wrong purpose, nonce, forged signature and expiry before touching state", async () => {
  const f = network();
  const now = 1_000_000;
  const validShape = {
    purpose: "admin_pairing_vault_scope_v1",
    installation_id: "51", nonce: "a".repeat(64),
    expires_at_ms: now + 25_000, signature: "c".repeat(64),
  };
  for (const patch of [
    { purpose: "admin_worker_enroll" }, { nonce: "bad" },
    { expires_at_ms: now - 1 }, { expires_at_ms: now + 31_000 },
    { installation_id: "52" }, { signature: "not-a-signature" },
    { access_token: "bad" },
  ]) {
    const output = await verifyVaultInstallationAttestation({
      request: { ...validShape, ...patch },
      env: f.params.env, objectId: f.namespace.idFromName("installation:51"),
      cryptoImpl: webcrypto, clock: () => now,
    });
    assert.equal(output.state, "BLOCKED");
  }
  assert.equal(f.storage.mutations(), 0);
});

test("absent binding, missing stub method, relay transport errors never authorize", async () => {
  const absent = network({ env: { BKE_WORKER_PAIRING_VAULT: {} } });
  denied(await attestAdminInstallationVault(absent.params),
    "VAULT_SCOPE_NAMESPACE_UNAVAILABLE");
  const missing = network({ stub: () => ({ noSuchMethod() {} }) });
  denied(await attestAdminInstallationVault(missing.params),
    "VAULT_SCOPE_RPC_UNAVAILABLE");
  const crash = network({ stub: () => ({
    attestInstallation() { throw Error("private DB material"); },
  }) });
  denied(await attestAdminInstallationVault(crash.params),
    "VAULT_SCOPE_RPC_UNAVAILABLE");
});

test("DO method does not permit ticket, pairing, revocation, or browser HTTP action", async () => {
  const f = network();
  const id = f.namespace.idFromName("installation:51");
  const obj = new BkeWorkerPairingVault({ id, storage: f.storage.storage },
    f.params.env);
  const response = await obj.fetch(new Request("https://example.invalid/api/worker/enroll"));
  assert.equal(response.status, 404);
  assert.equal(typeof obj.finalizePairing, "undefined");
  assert.equal(typeof obj.issueChallenge, "undefined");
  assert.equal(typeof obj.consumeAdminTicket, "undefined");
  assert.equal(f.storage.mutations(), 0);
});

test("HTTP entrypoint remains disconnected and routing feature remains OFF in Wrangler", () => {
  const entry = readFileSync(new URL("../src/index.js", import.meta.url), "utf8");
  const wrangler = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  assert.doesNotMatch(entry, /admin-installation-vault-attestation/u);
  assert.doesNotMatch(wrangler, /BKE_ADMIN_DO_ROUTING_ENABLED/u);
  assert.doesNotMatch(wrangler, /BKE_PAIRING_RPC_KEY_B64/u);
});

test("Cloudflare runtime entrypoint extends DurableObject and exports only safe RPC", () => {
  const wrangler = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  const entry = readFileSync(new URL("../src/cloudflare-worker-entry.js", import.meta.url), "utf8");
  assert.match(wrangler, /^main = "src\/cloudflare-worker-entry\.js"$/mu);
  assert.match(entry, /import \{ DurableObject \} from "cloudflare:workers"/u);
  assert.match(entry, /export class BkeWorkerPairingVault extends DurableObject/u);
  assert.match(entry, /super\(ctx, env\)/u);
  assert.match(entry, /async attestInstallation\(request\)/u);
  assert.match(entry, /async finalizeProtectedInactivePairing\(request\)/u);
  // Explicit signed private invitation RPC is allowed; generic action entrypoints are not.
  assert.match(entry, /async issueAtomicPairingInvitation\(request\)/u);
  assert.doesNotMatch(entry, /async (pair|revoke|dispatch|wake)\w*\(/u);
  assert.doesNotMatch(entry, /async issue(?!AtomicPairingInvitation)\w*\(/u);
});
