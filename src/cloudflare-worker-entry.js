// Cloudflare-only runtime bridge. Keep Node's source/test entrypoint free
// of cloudflare:workers imports; Wrangler bundles this module for PREPRODUCTION.
// No pairing RPC, worker wake, lease, or other sensitive mutable method here.
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

  // ONLY named RPC exported to callers. Authenticated and read-only.
  async attestInstallation(request) {
    return this.#logic.attestInstallation(request);
  }

  async fetch(request) {
    return this.#logic.fetch(request);
  }
}
