// Cloudflare-only runtime bridge; no public pairing/proof-challenge HTTP route.
import { DurableObject } from "cloudflare:workers";
import commandCenter from "./index.js";
import { BkeWorkerPairingVault as VaultLogic } from "./worker-pairing-durable-store.js";
export default commandCenter;
export class BkeWorkerPairingVault extends DurableObject {
  #logic;
  constructor(ctx,env){super(ctx,env);this.#logic=new VaultLogic(ctx,env);}
  async attestInstallation(request){return this.#logic.attestInstallation(request);}
  async finalizeProtectedInactivePairing(request){return this.#logic.finalizeProtectedInactivePairing(request);}
  async issueAtomicPairingInvitation(request){return this.#logic.issueAtomicPairingInvitation(request);}
  async reviewPairingConsent(command){return this.#logic.reviewPairingConsent(command);}
  async managePreparedDeviceProposal(command){return this.#logic.managePreparedDeviceProposal(command);}
  async issueProofChallenge(command){return this.#logic.issueProofChallenge(command);}
  async claimProofChallenge(command){return this.#logic.claimProofChallenge(command);}
  async finalizeProofChallenge(command){return this.#logic.finalizeProofChallenge(command);}
  async fetch(request){return this.#logic.fetch(request);}
}