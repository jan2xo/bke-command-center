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
  const credential = summarizeCredential(env);
  if (credential.credential !== "SERVER_CONFIGURED") {
    throw new AdminDiscoveryError("GITHUB_CREDENTIAL_NOT_CONFIGURED");
  }
  // Existing Command Center fine-grained GITHUB_TOKEN uses "user" mode.
  // Short-lived installation tokens from a future broker use installation mode.
  const mode = String(env.GITHUB_DISCOVERY_PRINCIPAL || "user");
  if (!["user", "installation"].includes(mode)) {
    throw new AdminDiscoveryError("GITHUB_PRINCIPAL_MODE_INVALID");
  }
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
          Authorization: "Bearer " + env.GITHUB_TOKEN,
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
