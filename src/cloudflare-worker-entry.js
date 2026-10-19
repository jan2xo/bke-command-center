// Cloudflare-only runtime bridge. Keep Node's source/test entrypoint free
// of cloudflare:workers imports; Wrangler bundles this module for PREPRODUCTION.
// No public pairing HTTP route, worker wake, lease, or active-worker method.
import { DurableObject } from "cloudflare:workers";
import commandCenter from "./index.js";
import { BkeWorkerPairingVault as VaultLogic } from "./worker-pairing-durable-store.js";

export default commandCenter;

export class BkeWorkerPairingVault extends DurableObject {
  #logic;
  constructor(ctx, env) {
    super(ctx, env);
    this.#logic = new VaultLogic(ctx, env);
  }

  // Read-only routing attestation; distinct from the guarded inactive finalizer.
  async attestInstallation(request) {
    return this.#logic.attestInstallation(request);
  }

  // This named RPC is unreachable without the separate HMAC secret and
  // protected pairing feature flag; no public HTTP route invokes it.
  async finalizeProtectedInactivePairing(request) {
    return this.#logic.finalizeProtectedInactivePairing(request);
  }

  async fetch(request) {
    return this.#logic.fetch(request);
  }
}
