// LOCAL-ONLY Cloudflare runtime fixture. Never import or deploy from the
// production/preproduction Wrangler configuration. Contains no credentials.
import { DurableObject } from "cloudflare:workers";
import { createPairingAtomicStore } from "../../src/worker-pairing-durable-store.js";

const fixed = (status, data) => Response.json(data, {
  status, headers: { "cache-control": "no-store" },
});
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const requireCondition = (condition, code) => {
  if (!condition) throw Error(code);
};

export class SmokeVault extends DurableObject {
  #store;
  constructor(ctx, env) {
    super(ctx, env);
    this.#store = createPairingAtomicStore(ctx.storage);
  }

  async reset() {
    return this.#store.atomic(async tx => {
      for (const key of ["paired", "pending", "admin_actions", "consents", "prepared"]) {
        await tx.put(key, []);
      }
      return "RESET";
    });
  }
  async record(label) {
    if (!["a", "b", "c", "d"].includes(label)) throw Error("SMOKE_INPUT");
    return this.#store.atomic(async tx => {
      const before = (await tx.get("paired")) ?? [];
      await tx.put("paired", [...before, { id: label }]);
      return before.length + 1;
    });
  }
  async commitAll() {
    return this.#store.atomic(async tx => {
      const existing = (await tx.get("paired")) ?? [];
      await tx.put("paired", existing);
      await tx.put("pending", [{ id: "challenge" }]);
      await tx.put("admin_actions", [{ id: "ticket" }]);
      await tx.put("consents", [{ id: "human-proposal" }]);
      await tx.put("prepared", [{ id: "signed-device-offer" }]);
      return "COMMITTED_THREE";
    });
  }
  async failAll() {
    try {
      await this.#store.atomic(async tx => {
        await tx.put("paired", [{ id: "CORRUPT" }]);
        await tx.put("pending", [{ id: "CORRUPT" }]);
        await tx.put("admin_actions", [{ id: "CORRUPT" }]);
        await tx.put("consents", [{ id: "CORRUPT" }]);
        await tx.put("prepared", [{ id: "CORRUPT" }]);
        throw Error("INTENTIONAL_ROLLBACK");
      });
    } catch (error) {
      return error.message === "PAIRING_STORAGE_UNAVAILABLE"
        ? "ROLLED_BACK" : "BAD_ERROR_CODE";
    }
    return "PARTIAL_COMMIT";
  }
  async inspect() {
    return this.#store.atomic(async tx => ({
      paired: (await tx.get("paired")) ?? [],
      pending: (await tx.get("pending")) ?? [],
      admin_actions: (await tx.get("admin_actions")) ?? [],
      consents: (await tx.get("consents")) ?? [],
      prepared: (await tx.get("prepared")) ?? [],
    }));
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "GET" || env?.BKE_SQLITE_SMOKE_FIXTURE !== "true" ||
        !["127.0.0.1", "localhost"].includes(url.hostname)) {
      return fixed(404, { state: "LOCKED" });
    }
    const aId = env.SMOKE_VAULT.idFromName("installation:local-test-a");
    const bId = env.SMOKE_VAULT.idFromName("installation:local-test-b");
    const a = env.SMOKE_VAULT.get(aId);
    const b = env.SMOKE_VAULT.get(bId);
    if (url.pathname === "/health") {
      return fixed(200, { state: "READY", fixture: "LOCAL_SQLITE_DO_ONLY" });
    }
    if (url.pathname === "/verify") {
      // A separate HTTP invocation and newly obtained stubs must observe the
      // same durable records. Never expose any secret or external profile.
      const [one, other] = await Promise.all([a.inspect(), b.inspect()]);
      return fixed(200, {
        state: "OBSERVED",
        a_paired_count: one.paired.length,
        b_paired_count: other.paired.length,
        pending_count: one.pending.length,
        admin_actions_count: one.admin_actions.length,
        consent_count: one.consents.length,
        prepared_count: one.prepared.length,
      });
    }
    if (url.pathname !== "/smoke") return fixed(404, { state: "LOCKED" });
    try {
      requireCondition(await a.reset() === "RESET", "RESET_A");
      requireCondition(await b.reset() === "RESET", "RESET_B");
      const count1 = await a.record("a");
      const count2 = await a.record("b");
      requireCondition(count1 === 1 && count2 === 2, "SEQUENTIAL_PERSIST");
      const isolate = await b.inspect();
      requireCondition(isolate.paired.length === 0, "INSTALLATION_ISOLATION");
      requireCondition(await a.commitAll() === "COMMITTED_THREE", "FIVE_KEY_COMMIT");
      const before = await a.inspect();
      requireCondition(before.paired.length === 2 && before.pending.length === 1 &&
        before.admin_actions.length === 1 &&
        before.consents.length === 1 &&
        before.prepared.length === 1, "FIVE_KEY_VISIBILITY");
      requireCondition(await a.failAll() === "ROLLED_BACK", "TRANSACTION_ROLLBACK");
      requireCondition(same(before, await a.inspect()), "ATOMIC_NO_PARTIAL_WRITE");
      const values = await Promise.all([a.record("c"), a.record("d")]);
      requireCondition(values.every(x => Number.isInteger(x)), "CONCURRENCY_RESULT");
      const after = await a.inspect();
      requireCondition(after.paired.length === 4 &&
        new Set(after.paired.map(x => x.id)).size === 4, "CONCURRENT_ATOMICITY");
      return fixed(200, {
        state: "PASS", checks: [
          "installation_isolation", "sequential_sqlite_persistence",
          "five_key_commit", "five_key_rollback",
          "concurrent_transaction_serialization",
        ],
      });
    } catch {
      return fixed(500, { state: "FAIL", code: "LOCAL_SQLITE_SMOKE_FAILURE" });
    }
  },
};
