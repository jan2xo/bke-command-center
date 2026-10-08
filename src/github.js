const API = "https://api.github.com";

async function github(path, env) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "bke-command-center-preproduction",
  };
  if (env.GITHUB_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  const response = await fetch(`${API}${path}`, { headers });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`GitHub ${response.status}: ${body.message || "request failed"}`);
  return body;
}

export function createGitHubAdapter(env) {
  const owner = env.GITHUB_OWNER || "jan2xo";
  const repo = env.GITHUB_REPO || "bke-worker";
  return {
    async repo() {
      return github(`/repos/${owner}/${repo}`, env);
    },
    async pullRequest(number) {
      return github(`/repos/${owner}/${repo}/pulls/${number}`, env);
    },
    async checks(ref) {
      return github(`/repos/${owner}/${repo}/commits/${ref}/check-runs?per_page=100`, env);
    },
    async workflowRuns() {
      return github(`/repos/${owner}/${repo}/actions/runs?per_page=100`, env);
    },
    async issueComments(number) {
      return github(`/repos/${owner}/${repo}/issues/${number}/comments?per_page=100`, env);
    },
  };
}

export function assignmentFromPullRequest(pr) {
  const worker = (pr.labels || []).map((x) => x.name).find((name) => name.startsWith("bke-worker:"));
  return {
    worker_id: worker ? worker.slice("bke-worker:".length) : null,
    state: pr.state === "open" ? "OPEN" : "CLOSED",
    pr_number: pr.number,
    exact_head: pr.head?.sha || null,
    branch: pr.head?.ref || null,
  };
}
