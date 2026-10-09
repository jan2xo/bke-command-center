// The GitHub API may reject a read for many different reasons. Never echo
// upstream response bodies, URLs, personal data, headers or credential values.
const CATEGORIES = new Set([
  "RATE_LIMIT", "ACCESS_DENIED", "NOT_FOUND", "UPSTREAM_5XX",
  "UPSTREAM_REJECTED", "TRANSPORT", "INVALID_RESPONSE", "UNKNOWN",
]);
const BOUNDARIES = new Set([
  "REPOSITORY", "OPEN_PRS", "CLOSED_PRS", "PR_DETAIL", "PR_COMMITS",
  "PR_COMMENTS", "COMMIT_CHECKS", "WORKFLOW_RUNS", "WORKFLOW_JOBS",
  "RECENT_WORKFLOWS", "RATE_LIMIT_PROBE", "UNKNOWN",
]);
const safe = (value, allowed) => allowed.has(value) ? value : "UNKNOWN";

export class GitHubEvidenceError extends Error {
  constructor(category = "UNKNOWN", boundary = "UNKNOWN") {
    super("GITHUB_EVIDENCE_UNAVAILABLE");
    this.name = "GitHubEvidenceError";
    this.category = safe(category, CATEGORIES);
    this.boundary = safe(boundary, BOUNDARIES);
  }
}

export function statusFailure(status, remaining, boundary) {
  const category =
    status === 429 || (status === 403 && remaining === "0") ? "RATE_LIMIT" :
    status === 401 || status === 403 ? "ACCESS_DENIED" :
    status === 404 ? "NOT_FOUND" :
    status >= 500 && status <= 599 ? "UPSTREAM_5XX" : "UPSTREAM_REJECTED";
  return new GitHubEvidenceError(category, boundary);
}

export function evidenceFailure(error) {
  return error instanceof GitHubEvidenceError
    ? { failure_class: error.category, boundary: error.boundary }
    : { failure_class: "UNKNOWN", boundary: "UNKNOWN" };
}
