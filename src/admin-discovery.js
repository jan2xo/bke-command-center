// Read-only on-demand GitHub source discovery for the authorized Admin.
// The credential never reaches the client; GitHub remains engineering truth.
// No secondary task database, worker assignment, secret rotation or mutation.
const API = "https://api.github.com";
const MAX_PAGES = 5;
const PER_PAGE = 100;

export class AdminDiscoveryError extends Error {
  constructor(code) {
    super(code);
    this.name = "AdminDiscoveryError";
    this.code = code;
  }
}

function safeGitHubRepo(item) {
  if (!item || !Number.isSafeInteger(item.id) ||
      !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(String(item.full_name || "")) ||
      (!["public", "private", "internal"].includes(item.visibility) && typeof item.private !== "boolean")) {
    throw new AdminDiscoveryError("GITHUB_REPOSITORY_RESPONSE_INVALID");
  }
  const [owner, name] = item.full_name.split("/");
  // GitHub path components are never dot-navigation tokens; fail closed.
  if (owner === "." || owner === ".." || name === "." || name === ".." ||
      owner.includes("..") || name.includes("..")) {
    throw new AdminDiscoveryError("GITHUB_REPOSITORY_RESPONSE_INVALID");
  }
  // Construct GitHub URLs from validated full_name, not arbitrary upstream links.
  return {
    id: item.id,
    full_name: owner + "/" + name,
    default_branch: typeof item.default_branch === "string" && /^[A-Za-z0-9_./-]{1,250}$/u.test(item.default_branch)
      ? item.default_branch : null,
    visibility: ["public", "private", "internal"].includes(item.visibility)
      ? item.visibility : item.private ? "private" : "public",
    archived: item.archived === true,
    disabled: item.disabled === true,
    url: "https://github.com/" + owner + "/" + name,
  };
}

const BROKER_PURPOSE = Object.freeze({
  purpose: "admin_source_discovery",
  repository: "jan2xo/bke-worker",
});

// The catalog RPC returns *metadata only*: no installation bearer ever
// crosses from the relay into this Command Center process.
const CATALOG_PURPOSE = Object.freeze({ purpose: "admin_installation_repository_catalog" });

// RPC exceptions may cross a Cloudflare Worker boundary. Map *only* exact
// known non-sensitive broker error codes into Admin diagnostics; never copy
// upstream errors, provider bodies, credentials or stack details into HTML/JSON.
const SAFE_CATALOG_FAILURES = Object.freeze({
  ADMIN_BROKER_LOCKED: "GITHUB_CATALOG_DISABLED",
  ADMIN_CATALOG_LOCKED: "GITHUB_CATALOG_DISABLED",
  ADMIN_CATALOG_PURPOSE_INVALID: "GITHUB_CATALOG_REQUEST_REJECTED",
  GITHUB_APP_ID_UNCONFIGURED: "GITHUB_CATALOG_APP_CONFIGURATION_UNAVAILABLE",
  GITHUB_APP_PRIVATE_KEY_UNCONFIGURED: "GITHUB_CATALOG_APP_CONFIGURATION_UNAVAILABLE",
  GITHUB_APP_INSTALLATION_RESPONSE_INVALID: "GITHUB_CATALOG_INSTALLATION_UNAVAILABLE",
  ADMIN_CATALOG_TOKEN_REJECTED: "GITHUB_CATALOG_TOKEN_ISSUANCE_REJECTED",
  ADMIN_CATALOG_TOKEN_SCOPE_INVALID: "GITHUB_CATALOG_TOKEN_PERMISSION_REJECTED",
  ADMIN_CATALOG_REPOSITORIES_UNAVAILABLE: "GITHUB_CATALOG_PROVIDER_UNAVAILABLE",
  ADMIN_CATALOG_REPOSITORIES_INVALID: "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID",
  ADMIN_CATALOG_DUPLICATE_REPOSITORY: "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID",
  ADMIN_CATALOG_PAGINATION_INCOMPLETE: "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID",
  ADMIN_CATALOG_REPOSITORY_INVALID: "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID",
  ADMIN_CATALOG_RESULT_INVALID: "GITHUB_CATALOG_PROVIDER_RESPONSE_INVALID",
});

export function safeCatalogBrokerFailure(error) {
  const raw = typeof error?.message === "string" ? error.message : "";
  if (!raw || raw.length > 200) return "GITHUB_CATALOG_BROKER_UNAVAILABLE";
  const code = raw.startsWith("Error: ") ? raw.slice(7) : raw;
  if (Object.hasOwn(SAFE_CATALOG_FAILURES, code)) return SAFE_CATALOG_FAILURES[code];
  if (/^GITHUB_APP_INSTALLATION_RESOLUTION_FAILED:(?:401|403|404|422|429|500|502|503)$/u.test(code)) {
    return "GITHUB_CATALOG_INSTALLATION_UNAVAILABLE";
  }
  if (/^GITHUB_APP_PERMISSION_REQUIRED:(?:contents|issues|pull_requests)=(?:read|write);granted=(?:none|read|write)$/u.test(code)) {
    return "GITHUB_CATALOG_INSTALLATION_SCOPE_REJECTED";
  }
  return "GITHUB_CATALOG_BROKER_UNAVAILABLE";
}

async function discoverInstalledCatalog(env) {
  const rpc = env?.BKE_GITHUB_READ_BROKER?.listApprovedGitHubRepositories;
  if (typeof rpc !== "function") throw new AdminDiscoveryError("GITHUB_CATALOG_BROKER_UNAVAILABLE");
  let payload;
  try {
    payload = await env.BKE_GITHUB_READ_BROKER.listApprovedGitHubRepositories(CATALOG_PURPOSE);
  } catch (error) {
    throw new AdminDiscoveryError(safeCatalogBrokerFailure(error));
  }
  if (!payload || payload.principal !== "github_app_installation" ||
      payload.authority !== "EXISTING_GITHUB_APP_INSTALLATION" ||
      payload.repository_scope !== "INSTALLATION_APPROVED_ONLY" ||
      !Number.isSafeInteger(payload.total_visible) ||
      payload.total_visible < 0 || payload.total_visible > 500 ||
      !Array.isArray(payload.repositories) ||
      payload.repositories.length !== payload.total_visible) {
    throw new AdminDiscoveryError("GITHUB_CATALOG_RESPONSE_INVALID");
  }
  const repositories = [];
  const ids = new Set();
  const names = new Set();
  for (const raw of payload.repositories) {
    if (!raw || typeof raw.private !== "boolean" ||
        typeof raw.archived !== "boolean" ||
        (raw.default_branch !== null &&
          (typeof raw.default_branch !== "string" ||
           !/^[A-Za-z0-9_./-]{1,250}$/u.test(raw.default_branch)))) {
      throw new AdminDiscoveryError("GITHUB_CATALOG_RESPONSE_INVALID");
    }
    const safe = safeGitHubRepo(raw);
    if (raw.html_url !== safe.url ||
        !Number.isSafeInteger(safe.id) || safe.id <= 0 ||
        ids.has(safe.id) || names.has(safe.full_name)) {
      throw new AdminDiscoveryError("GITHUB_CATALOG_RESPONSE_INVALID");
    }
    ids.add(safe.id);
    names.add(safe.full_name);
    repositories.push(safe);
  }
  return {
    provider: "github",
    principal: "installation",
    state: "DISCOVERED",
    total_visible: repositories.length,
    repositories: repositories.sort((a, b) => a.full_name.localeCompare(b.full_name)),
    credential: {
      provider: "github",
      credential: "BROKER_CONNECTED",
      token_lifecycle: "ON_DEMAND_SHORT_LIVED",
      auto_rotation: true,
      scope_verified: true,
    },
    scope: "INSTALLATION_APPROVED_ONLY",
    worker_liveness: "UNKNOWN",
    sources_authority: "GITHUB",
  };
}

async function resolveDiscoveryCredential(env) {
  const authMode = String(env?.GITHUB_DISCOVERY_AUTH_MODE || "legacy_pat");
  if (authMode === "legacy_pat") {
    const token = typeof env?.GITHUB_TOKEN === "string" ? env.GITHUB_TOKEN.trim() : "";
    if (!token) throw new AdminDiscoveryError("GITHUB_CREDENTIAL_NOT_CONFIGURED");
    const principal = String(env.GITHUB_DISCOVERY_PRINCIPAL || "user");
    if (!["user", "installation"].includes(principal)) {
      throw new AdminDiscoveryError("GITHUB_PRINCIPAL_MODE_INVALID");
    }
    return {
      token, principal,
      summary: {
        provider: "github", credential: "SERVER_CONFIGURED",
        token_lifecycle: "EXTERNAL_OR_MANUAL", auto_rotation: false,
        scope_verified: false,
      },
    };
  }
  if (authMode !== "broker") throw new AdminDiscoveryError("GITHUB_DISCOVERY_AUTH_MODE_INVALID");
  if (typeof env?.BKE_GITHUB_READ_BROKER?.mintReadOnlyGitHubToken !== "function") {
    throw new AdminDiscoveryError("GITHUB_BROKER_UNAVAILABLE");
  }
  let tokenInfo;
  try {
    tokenInfo = await env.BKE_GITHUB_READ_BROKER.mintReadOnlyGitHubToken(BROKER_PURPOSE);
  } catch {
    // Never silently downgrade to GITHUB_TOKEN if broker fails.
    throw new AdminDiscoveryError("GITHUB_BROKER_UNAVAILABLE");
  }
  const permissions = tokenInfo?.permissions;
  const expiry = typeof tokenInfo?.expires_at === "string" ? Date.parse(tokenInfo.expires_at) : NaN;
  const remaining = expiry - Date.now();
  if (!tokenInfo || tokenInfo.principal !== "github_app_installation" ||
      tokenInfo.repository !== BROKER_PURPOSE.repository ||
      typeof tokenInfo.token !== "string" ||
      !/^ghs_[A-Za-z0-9_]+$/u.test(tokenInfo.token) ||
      Object.keys(permissions || {}).sort().join(",") !== "contents,issues,pull_requests" ||
      permissions.contents !== "read" || permissions.issues !== "read" ||
      permissions.pull_requests !== "read" ||
      !Number.isFinite(remaining) || remaining < 120000 || remaining > 3660000) {
    throw new AdminDiscoveryError("GITHUB_BROKER_RESPONSE_INVALID");
  }
  return {
    token: tokenInfo.token, principal: "installation",
    summary: {
      provider: "github", credential: "BROKER_CONNECTED",
      token_lifecycle: "ON_DEMAND_SHORT_LIVED", auto_rotation: true,
      scope_verified: false,
    },
  };
}

export function summarizeCredential(env) {
  return {
    provider: "github",
    credential: typeof env?.GITHUB_TOKEN === "string" && env.GITHUB_TOKEN.trim() ? "SERVER_CONFIGURED" : "MISSING",
    token_lifecycle: "EXTERNAL_OR_MANUAL",
    auto_rotation: false,
    scope_verified: false,
  };
}

export async function discoverGitHubRepositories(env, fetchImpl = fetch) {
  if (env?.GITHUB_DISCOVERY_AUTH_MODE === "catalog") return discoverInstalledCatalog(env);
  const { token, principal: mode, summary: credential } = await resolveDiscoveryCredential(env);
  const path = mode === "installation" ? "/installation/repositories" : "/user/repos";
  const repos = [];
  const seen = new Set();
  for (let page = 1; page <= MAX_PAGES; page++) {
    const qs = new URLSearchParams({ per_page: String(PER_PAGE), page: String(page) });
    if (mode === "user") qs.set("affiliation", "owner,collaborator,organization_member");
    const url = API + path + "?" + qs.toString();
    let response;
    try {
      response = await fetchImpl(url, {
        headers: {
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "bke-command-center-admin-discovery",
          Authorization: "Bearer " + token,
        },
        redirect: "error",
      });
    } catch {
      throw new AdminDiscoveryError("GITHUB_DISCOVERY_TRANSPORT");
    }
    if (response.status === 401 || response.status === 403) {
      throw new AdminDiscoveryError("GITHUB_DISCOVERY_AUTH_UNAVAILABLE");
    }
    if (!response.ok) throw new AdminDiscoveryError("GITHUB_DISCOVERY_UPSTREAM_UNAVAILABLE");
    let data;
    try { data = await response.json(); } catch { throw new AdminDiscoveryError("GITHUB_DISCOVERY_INVALID_RESPONSE"); }
    const items = mode === "installation" ? data?.repositories : data;
    if (!Array.isArray(items) || items.length > PER_PAGE) {
      throw new AdminDiscoveryError("GITHUB_DISCOVERY_INVALID_RESPONSE");
    }
    for (const item of items) {
      const repository = safeGitHubRepo(item);
      if (seen.has(repository.id)) continue;
      seen.add(repository.id);
      repos.push(repository);
    }
    const link = response.headers.get("link") || "";
    const more = /<[^>]+>;\s*rel="next"/u.test(link);
    if (!more) {
      return {
        provider: "github",
        principal: mode,
        state: "DISCOVERED",
        total_visible: repos.length,
        repositories: repos.sort((a, b) => a.full_name.localeCompare(b.full_name)),
        credential,
        scope: "CREDENTIAL_VISIBLE_ONLY",
        worker_liveness: "UNKNOWN",
        sources_authority: "GITHUB",
      };
    }
    if (page === MAX_PAGES) {
      throw new AdminDiscoveryError("GITHUB_DISCOVERY_PAGINATION_LIMIT");
    }
  }
  throw new AdminDiscoveryError("GITHUB_DISCOVERY_PAGINATION_LIMIT");
}
