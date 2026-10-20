// Default-OFF server-private GeckoView host composition for Issue #60.
// This is not an OS attestor. The configured host must independently verify the
// real Android/GeckoView/native-port peer before signing any session binding.
// Never import this module from an HTTP route or derive trustedHost from request data.
import { createPinnedDevicePeerAuthorizer } from "./admin-pinned-device-attestor.js";
import { stageDeviceFromPrivateTransport } from "./admin-private-device-admission.js";

const block = code => Object.freeze({ state: "BLOCKED", code });
const enabled = env => env?.BKE_GECKOVIEW_PRIVATE_HOST_ENABLED === "true";

// TrustedHost is server-owned configuration supplied at process composition,
// not a device/client value. Its resolver must return an exclusive private link
// and requestSignedBinding must be implemented by the OS/browser peer attestor.
// This factory does not make arbitrary callbacks trustworthy.
export function createGeckoViewPrivateHostAdapter({
  env, trustedHost, pinnedPublicKey, describeResources, readAssignments,
  cryptoImpl = crypto, clock = () => Date.now(), timeoutMs = 10_000,
} = {}) {
  // Enabling is latched at construction: mutating a previously-off environment\n  // object later cannot turn this adapter on. Runtime disable remains immediate.\n  const enabledAtConstruction = enabled(env);\n  if (!enabledAtConstruction) return Object.freeze({
    async stage() { return block("GECKOVIEW_PRIVATE_HOST_LOCKED"); },
  });

  if (!trustedHost || typeof trustedHost.resolveExclusiveLink !== "function" ||
      typeof trustedHost.requestSignedBinding !== "function" ||
      typeof describeResources !== "function") {
    return Object.freeze({
      async stage() { return block("GECKOVIEW_PRIVATE_HOST_ADAPTER_REQUIRED"); },
    });
  }

  let authorizePeer;
  try {
    authorizePeer = createPinnedDevicePeerAuthorizer({
      pinnedPublicKey,
      requestSignedBinding: (link, challenge) =>
        trustedHost.requestSignedBinding(link, challenge),
      cryptoImpl, clock, timeoutMs,
    });
  } catch {
    return Object.freeze({
      async stage() { return block("GECKOVIEW_PRIVATE_HOST_ATTESTOR_NOT_CONFIGURED"); },
    });
  }

  let busy = false;
  const adapter = {
    async stage({ executionCtx } = {}) {
      if (!enabledAtConstruction || !enabled(env)) return block("GECKOVIEW_PRIVATE_HOST_LOCKED");
      if (busy) return block("GECKOVIEW_PRIVATE_HOST_BUSY");
      busy = true;
      try {
        // The resolver is private server code. No request-supplied worker,
        // profile, installation, target, link or authorization is accepted.
        let link;
        try { link = await trustedHost.resolveExclusiveLink(); }
        catch { return block("GECKOVIEW_PRIVATE_HOST_UNAVAILABLE"); }
        if (!link || typeof link !== "object" ||
            typeof link.readCandidate !== "function" ||
            typeof link.exchangeProof !== "function") {
          return block("GECKOVIEW_PRIVATE_HOST_LINK_INVALID");
        }
        let result;
        try {
          const args = {
            env, executionCtx, link, authorizePeer, describeResources,
            cryptoImpl, clock,
          };
          if (readAssignments !== undefined) args.readAssignments = readAssignments;
          result = await stageDeviceFromPrivateTransport(args);
        } catch {
          return block("GECKOVIEW_PRIVATE_HOST_OUTCOME_UNCERTAIN");
        }
        if (result?.state === "BLOCKED") return result;
        if (result?.state !== "PREPARED_FOR_HUMAN_REVIEW" ||
            result.pairing_authority !== "NONE" ||
            result.dispatch_authority !== "NONE") {
          return block("GECKOVIEW_PRIVATE_HOST_OUTCOME_UNCERTAIN");
        }
        return Object.freeze({ ...result });
      } finally {
        // Unknown link/challenge delivery is never retried by this adapter.
        busy = false;
      }
    },
  };
  return Object.freeze(adapter);
}
