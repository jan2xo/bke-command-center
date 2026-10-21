import { verifyVaultInstallationAttestation } from "./admin-installation-vault-attestation.js";
import { receiveProtectedInactivePairing } from "./admin-protected-pairing-rpc.js";
import { receiveAdminPairingInvitation } from "./admin-invitation-rpc.js";
import { receiveAdminPairingConsent } from "./admin-pairing-review-rpc.js";
import { receivePreparedDeviceProposal } from "./admin-device-proposal-preparation.js";
import { receiveDeviceAttestationChallenge } from "./admin-device-attestation-challenge-rpc.js";
// Cloudflare Durable Object transaction adapter for inactive pairing identity.
// GitHub remains the PR/task ledger. This only stores bounded enrollment state.
// The adapter MUST run *inside* one installation-scoped SQLite-backed DO.
const KEY = Object.freeze({
  paired: "bke:pairing:v1:paired",
  pending: "bke:pairing:v1:pending",
  admin_actions: "bke:pairing:v1:admin_actions",
  consents: "bke:pairing:v1:consents",
  prepared: "bke:pairing:v1:prepared",
  attestation_challenges: "bke:pairing:v1:attestation_challenges",
  attestation_challenge_clock: "bke:pairing:v1:attestation_challenge_clock",
});
const MAX_ROWS = 100;
const MAX_SERIALIZED_BYTES = 262_144;
const invalid = () => new Error("PAIRING_STORAGE_CONTRACT_INVALID");

function path(key) {
  if (typeof key !== "string" || !Object.hasOwn(KEY, key)) throw invalid();
  return KEY[key];
}
function safeCopy(value) {
  if (!Array.isArray(value) || value.length > MAX_ROWS) throw invalid();
  // Only JSON storage shapes are allowed. Reject null-prototypes, cycles and
  // unsupported values rather than silently dropping non-JSON fields.
  let json;
  try {
    json = JSON.stringify(value);
    if (typeof json !== "string" ||
        new TextEncoder().encode(json).byteLength > MAX_SERIALIZED_BYTES) throw invalid();
    const clone = structuredClone(value);
    if (JSON.stringify(clone) !== json) throw invalid();
    return clone;
  } catch { throw invalid(); }
}

// No transaction callbacks may cross a Durable Object RPC boundary.
// The caller of this function is code executing inside the SAME DO instance.
export function createPairingAtomicStore(storage) {
  if (!storage || typeof storage.transaction !== "function") throw invalid();
  return Object.freeze({
    async atomic(operation) {
      if (typeof operation !== "function") throw invalid();
      try {
        return await storage.transaction(async transaction => {
          if (!transaction || typeof transaction.get !== "function" ||
              typeof transaction.put !== "function") throw invalid();
          const scoped = Object.freeze({
            async get(key) {
              const value = await transaction.get(path(key));
              return value === undefined ? undefined : safeCopy(value);
            },
            async put(key, value) {
              await transaction.put(path(key), safeCopy(value));
            },
          });
          // Cloudflare storage.transaction promises atomic commit or rollback
          // of these paired/pending writes, including async callbacks.
          return await operation(scoped);
        });
      } catch {
        // No provider errors, storage values, key material or stack traces cross
        // the pairing boundary.
        throw new Error("PAIRING_STORAGE_UNAVAILABLE");
      }
    },
  });
}

// Deployable logic: fetch always returns 404. Two private named RPCs only:
// read-only tenant attestation and guarded atomic INACTIVE pairing finalizer.
// Neither provides device transport, worker leases or public enrollment.
export class BkeWorkerPairingVault {
  #store;
  #objectId;
  #env;
  constructor(ctx, env) {
    this.#store = createPairingAtomicStore(ctx?.storage);
    this.#objectId = ctx?.id;
    this.#env = env;
  }

  // Pure read-only installation scope attestation;
  // no ticket/device command, nonce persistence, or registry read/write.
  async attestInstallation(request) {
    return verifyVaultInstallationAttestation({
      request, env: this.#env, objectId: this.#objectId,
    });
  }

  // Authenticated private mutation: the RPC adapter verifies the scoped
  // HMAC, actual installation object, human binding and live broker scope.
  // The atomic finalizer stores ONLY an INACTIVE worker registration.
  async finalizeProtectedInactivePairing(request) {
    return receiveProtectedInactivePairing({
      request, env: this.#env, objectId: this.#objectId, store: this.#store,
    });
  }

  // Private, separately locked signed Admin invitation RPC. Never an HTTP route.
  async issueAtomicPairingInvitation(request) {
    return receiveAdminPairingInvitation({
      request, env:this.#env, objectId:this.#objectId, store:this.#store,
    });
  }

  // Signed and installation-scoped proposal present/confirm; HTTP fetch stays 404.
  async reviewPairingConsent(command) {
    return receiveAdminPairingConsent({
      command,env:this.#env,objectId:this.#objectId,store:this.#store,
    });
  }

  // Default-OFF private device proposal staging/observation, never HTTP.
  async managePreparedDeviceProposal(command) {
    return receivePreparedDeviceProposal({
      command, env:this.#env, objectId:this.#objectId, store:this.#store,
    });
  }

  // Default-OFF server-only challenge/replay ledger. No HTTP route invokes this RPC.
  async manageDeviceAttestationChallenge(request) {
    return receiveDeviceAttestationChallenge({
      request, env: this.#env, objectId: this.#objectId, store: this.#store,
    });
  }

  async fetch(_request) {
    return new Response(null, { status: 404, headers: { "Cache-Control": "no-store" } });
  }
}
