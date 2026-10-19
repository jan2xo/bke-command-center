// Inert, server-only pairing-action admission. No route imports this module.
// Only Cloudflare's platform-verified executionCtx.access may prove Admin identity.
// Intent confirmation and browser-origin checks are NOT a pairing grant, nonce,
// idempotency proof, or permission to deliver a command to a Durable Object.
import { inspectAdminRuntimeAccess } from "./admin-access.js";

const ADMIN_ORIGIN = "https://cc.jl-bke.com";
const ACTIONS = Object.freeze({
  pair: "ENROLL_WORKER",
  revoke: "REVOKE_WORKER",
});
const WORKER_ID = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const MAX_JSON_BYTES = 1024;
const reject = code => Object.freeze({ state: "BLOCKED", code });

async function readBoundedJson(request) {
  if (!request.body || typeof request.body.getReader !== "function") return null;
  const reader = request.body.getReader();
  const parts = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) return null;
      length += value.byteLength;
      if (length > MAX_JSON_BYTES) {
        await reader.cancel().catch(() => {});
        return null;
      }
      parts.push(value);
    }
    if (length === 0) return null;
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
      bytes.set(part, offset);
      offset += part.byteLength;
    }
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return value;
  } catch {
    return null;
  } finally {
    try { reader.releaseLock(); } catch { /* input aborted */ }
  }
}

export async function inspectPairingAdminAction(request, env, executionCtx) {
  // This independent OFF switch must not be inferred from source discovery.
  // No Wrangler environment currently enables it. Even explicit ON is not
  // sufficient: caller must still prove PREPRODUCTION and verified Access.
  if (env?.BKE_ADMIN_PAIRING_ACTIONS_ENABLED !== "true") {
    return reject("PAIRING_ACTIONS_LOCKED");
  }
  if (env?.BKE_PREPRODUCTION !== "true" ||
      env?.BKE_ACCESS_POLICY_VERIFIED !== "true") {
    return reject("PAIRING_ENVIRONMENT_LOCKED");
  }
  if (!(request instanceof Request)) return reject("PAIRING_REQUEST_INVALID");
  let target;
  try { target = new URL(request.url); } catch {
    return reject("PAIRING_REQUEST_INVALID");
  }
  if (target.origin !== ADMIN_ORIGIN || target.username || target.password ||
      target.search || target.hash) return reject("PAIRING_ORIGIN_REJECTED");
  if (request.method !== "POST") return reject("PAIRING_METHOD_REJECTED");
  // Origin + Fetch Metadata are both browser-owned, not trustworthy custom
  // headers. They defend cookie-attached cross-site requests; they do not
  // replace signed Access identity or a future one-use action challenge.
  if (request.headers.get("origin") !== ADMIN_ORIGIN ||
      request.headers.get("sec-fetch-site") !== "same-origin" ||
      !["cors", "same-origin"].includes(request.headers.get("sec-fetch-mode"))) {
    return reject("PAIRING_BROWSER_ORIGIN_REJECTED");
  }
  if (request.headers.get("content-type") !== "application/json" ||
      request.headers.has("content-encoding") ||
      (request.headers.has("content-length") &&
        (!/^[0-9]{1,6}$/u.test(request.headers.get("content-length")) ||
         Number(request.headers.get("content-length")) > MAX_JSON_BYTES))) {
    return reject("PAIRING_CONTENT_TYPE_REJECTED");
  }
  // Platform Access identity MUST be proved before reading user payloads.
  const auth = await inspectAdminRuntimeAccess(executionCtx, env);
  if (auth !== "AUTHORIZED") return reject("PAIRING_ADMIN_DENIED");

  const input = await readBoundedJson(request);
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).sort().join(",") !== "action,confirm_worker_id,worker_id" ||
      typeof input.worker_id !== "string" || !WORKER_ID.test(input.worker_id) ||
      typeof input.action !== "string" ||
      !Object.hasOwn(ACTIONS, input.action) ||
      input.confirm_worker_id !== input.worker_id ||
      request.headers.get("x-bke-admin-action") !== input.action) {
    return reject("PAIRING_INTENT_INVALID");
  }
  // Inert result intentionally carries no identity/Access token and is NOT
  // a device enrollment grant. Future callers must independently verify
  // per-action single-use server nonce, install/PR scope and DO authorization.
  return Object.freeze({
    state: "AUTHORIZED_FOR_PREFLIGHT",
    action: input.action,
    worker_id: input.worker_id,
  });
}
