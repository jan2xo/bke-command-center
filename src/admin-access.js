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

export async function authorizeAdminAccess(request, env, fetchImpl = fetch, cryptoImpl = crypto) {
  if (!adminAccessConfigured(env)) return false;
  const token = request.headers.get("cf-access-jwt-assertion") || "";
  if (token.length > 10000) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const header = parseJson(decode(parts[0]));
  const payload = parseJson(decode(parts[1]));
  const signature = decode(parts[2]);
  if (!header || !payload || !signature || !signature.length) return false;
  if (header.alg !== "RS256" || !/^[a-zA-Z0-9_-]{1,180}$/u.test(String(header.kid || ""))) return false;
  const now = Math.floor(Date.now() / 1000);
  const emails = String(env.BKE_ADMIN_EMAILS).split(",").map((x) => x.trim().toLowerCase());
  if (payload.type !== "app" || payload.iss !== accessIssuer(env) ||
      !([payload.aud].flat().includes(env.BKE_ADMIN_ACCESS_AUD)) ||
      !Number.isInteger(payload.exp) || payload.exp <= now ||
      !Number.isInteger(payload.iat) || payload.iat > now + 60 ||
      (payload.nbf !== undefined && (!Number.isInteger(payload.nbf) || payload.nbf > now + 60)) ||
      typeof payload.sub !== "string" || !payload.sub ||
      typeof payload.email !== "string" || !emails.includes(payload.email.trim().toLowerCase())) return false;
  try {
    const response = await fetchImpl(accessIssuer(env) + "/cdn-cgi/access/certs", { redirect: "error" });
    if (!response.ok || Number(response.headers.get("content-length") || 0) > 65536) return false;
    const jwks = await response.json();
    if (!Array.isArray(jwks?.keys) || jwks.keys.length > 16) return false;
    const key = jwks.keys.find((item) =>
      item && item.kid === header.kid && item.kty === "RSA" &&
      (!item.alg || item.alg === "RS256") && (!item.use || item.use === "sig"));
    if (!key) return false;
    const publicKey = await cryptoImpl.subtle.importKey("jwk", key, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return await cryptoImpl.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, encoder.encode(parts[0] + "." + parts[1]));
  } catch {
    // Do not reflect JWT, JWKS errors, Access identity or upstream URLs.
    return false;
  }
}
