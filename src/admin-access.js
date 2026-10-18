// Dedicated human ADMIN boundary for sensitive discovery.
// Cloudflare Access *routing* alone is not authorization: verify JWT signature,
// issuer, application audience, expiration, identity and explicit admin allowlist.
const utf8 = new TextDecoder();
const encoder = new TextEncoder();
const ADMIN_FLAGS = ["BKE_ADMIN_DISCOVERY_ENABLED", "BKE_ADMIN_ACCESS_ISSUER", "BKE_ADMIN_ACCESS_AUD", "BKE_ADMIN_EMAILS"];

function decode(segment) {
  if (!/^[A-Za-z0-9_-]+$/u.test(segment) || segment.length > 8192) return null;
  try {
    const raw = atob(segment.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  } catch { return null; }
}

function parseJson(bytes) {
  if (!bytes) return null;
  try { return JSON.parse(utf8.decode(bytes)); } catch { return null; }
}

function accessIssuer(env) {
  const raw = String(env?.BKE_ADMIN_ACCESS_ISSUER || "");
  let u;
  try { u = new URL(raw); } catch { return null; }
  // Prevent remote JWKS key-source injection and SSRF through config.
  if (u.protocol !== "https:" || u.username || u.password || u.port ||
      u.pathname !== "/" || u.search || u.hash ||
      !/^[a-z0-9-]+\.cloudflareaccess\.com$/u.test(u.hostname)) return null;
  return u.origin;
}

export function adminAccessConfigured(env) {
  if (ADMIN_FLAGS.some((key) => !String(env?.[key] || "").trim())) return false;
  if (env.BKE_ADMIN_DISCOVERY_ENABLED !== "true") return false;
  if (!accessIssuer(env)) return false;
  if (!/^[a-zA-Z0-9]{16,128}$/u.test(env.BKE_ADMIN_ACCESS_AUD)) return false;
  return String(env.BKE_ADMIN_EMAILS).split(",").some((x) => /^[^\s@,]+@[^\s@,]+$/u.test(x.trim()));
}

// Only enumerated diagnostic stages may leave this module. Never reflect
// JWT bytes, key material, email, audience, issuer, fetched payloads or errors.
export async function inspectAdminAccess(request, env, fetchImpl = fetch, cryptoImpl = crypto) {
  if (!adminAccessConfigured(env)) return "CONFIG_REJECTED";
  const token = request.headers.get("cf-access-jwt-assertion") || "";
  if (!token) return "EDGE_JWT_MISSING";
  if (token.length > 10000) return "JWT_MALFORMED";
  const parts = token.split(".");
  if (parts.length !== 3) return "JWT_MALFORMED";
  const header = parseJson(decode(parts[0]));
  const payload = parseJson(decode(parts[1]));
  const signature = decode(parts[2]);
  if (!header || !payload || !signature || !signature.length) return "JWT_MALFORMED";
  if (header.alg !== "RS256" || !/^[a-zA-Z0-9_-]{1,180}$/u.test(String(header.kid || ""))) return "JWT_HEADER_REJECTED";
  const now = Math.floor(Date.now() / 1000);
  const emails = String(env.BKE_ADMIN_EMAILS).split(",").map((x) => x.trim().toLowerCase());
  if (payload.type !== "app" || payload.iss !== accessIssuer(env) ||
      !([payload.aud].flat().includes(env.BKE_ADMIN_ACCESS_AUD)) ||
      !Number.isInteger(payload.exp) || payload.exp <= now ||
      !Number.isInteger(payload.iat) || payload.iat > now + 60 ||
      (payload.nbf !== undefined && (!Number.isInteger(payload.nbf) || payload.nbf > now + 60)) ||
      typeof payload.sub !== "string" || !payload.sub ||
      typeof payload.email !== "string" || !emails.includes(payload.email.trim().toLowerCase())) return "JWT_CLAIMS_REJECTED";
  try {
    const response = await fetchImpl(accessIssuer(env) + "/cdn-cgi/access/certs", { redirect: "error" });
    if (!response.ok || Number(response.headers.get("content-length") || 0) > 65536) return "JWKS_UNAVAILABLE";
    const jwks = await response.json();
    if (!Array.isArray(jwks?.keys) || jwks.keys.length > 16) return "JWKS_UNAVAILABLE";
    const key = jwks.keys.find((item) =>
      item && item.kid === header.kid && item.kty === "RSA" &&
      (!item.alg || item.alg === "RS256") && (!item.use || item.use === "sig"));
    if (!key) return "JWKS_KEY_NOT_FOUND";
    // Invalid JWK is a separate server-side verification failure. Never
    // substitute an unverified header or browser cookie for signature proof.
    let verified = false;
    try {
      const publicKey = await cryptoImpl.subtle.importKey("jwk", key, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      verified = await cryptoImpl.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, encoder.encode(parts[0] + "." + parts[1]));
    } catch {
      return "JWKS_KEY_INVALID";
    }
    return verified ? "AUTHORIZED" : "JWT_SIGNATURE_INVALID";
  } catch {
    // No upstream URLs, error messages or token/claim details are exposed.
    return "JWKS_UNAVAILABLE";
  }
}

export async function authorizeAdminAccess(request, env, fetchImpl = fetch, cryptoImpl = crypto) {
  return (await inspectAdminAccess(request, env, fetchImpl, cryptoImpl)) === "AUTHORIZED";
}


// ctx.access is a Cloudflare-provided, platform-verified authentication
// context for a DIRECT Access-authenticated Worker invocation. It is not a
// client-supplied header and is NOT forwarded across Service Binding RPCs.
// This runtime boundary intentionally has NO fallback to an unverified header
// or the legacy remote-JWKS path when ctx.access is absent.
export async function inspectAdminRuntimeAccess(ctx, env) {
  if (!adminAccessConfigured(env)) return "CONFIG_REJECTED";
  const access = ctx?.access;
  if (!access || typeof access.getIdentity !== "function") {
    return "EDGE_ACCESS_CONTEXT_MISSING";
  }
  if (typeof access.aud !== "string" ||
      access.aud !== env.BKE_ADMIN_ACCESS_AUD) {
    return "ACCESS_AUDIENCE_REJECTED";
  }
  let identity;
  try {
    identity = await access.getIdentity();
  } catch {
    return "ACCESS_IDENTITY_UNAVAILABLE";
  }
  const email = identity?.email;
  if (typeof email !== "string" ||
      !/^[^\s@,]+@[^\s@,]+$/u.test(email)) {
    return "ACCESS_IDENTITY_REJECTED";
  }
  const allowlist = String(env.BKE_ADMIN_EMAILS)
    .split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
  if (!allowlist.includes(email.trim().toLowerCase())) {
    return "ACCESS_IDENTITY_REJECTED";
  }
  return "AUTHORIZED";
}
