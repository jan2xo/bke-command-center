const MAX_OPEN_PAGE = 100;
const RECENT_CLOSED_LIMIT = 12;
const ID = /^[a-z0-9][a-z0-9-]{0,62}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA = /^[0-9a-f]{40}$/;
const escapeText = (value) => String(value ?? "")
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");

function requirePullRequest(value, expectedState) {
  if (!value || !Number.isSafeInteger(value.number) || value.number < 1 ||
      value.state !== expectedState || !value.head || !SHA.test(value.head.sha) ||
      !Array.isArray(value.labels) || typeof value.title !== "string" ||
      value.labels.some((label) => !label || typeof label.name !== "string")) {
    throw new Error("GITHUB_DASHBOARD_PR_EVIDENCE_INVALID");
  }
  return value;
}

export function normalizeDashboardData(repository, open, recent) {
  if (!repository || !REPO.test(repository.full_name || "") ||
      typeof repository.default_branch !== "string" || !repository.default_branch) {
    throw new Error("GITHUB_DASHBOARD_REPOSITORY_INVALID");
  }
  if (!Array.isArray(open) || !Array.isArray(recent) ||
      open.length >= MAX_OPEN_PAGE || recent.length > RECENT_CLOSED_LIMIT) {
    throw new Error("GITHUB_DASHBOARD_COLLECTION_AMBIGUOUS");
  }

  const seenNumbers = new Set();
  const ownerNumbers = new Map();
  const openPullRequests = open.map((raw) => {
    const pr = requirePullRequest(raw, "open");
    if (seenNumbers.has(pr.number)) throw new Error("GITHUB_DASHBOARD_DUPLICATE_PR");
    seenNumbers.add(pr.number);
    const labels = pr.labels.filter((item) => item.name.toLowerCase().startsWith("bke-worker:"));
    const names = labels.map((label) => label.name.slice("bke-worker:".length).toLowerCase());
    const idValid = names.every((name) => ID.test(name));
    const unique = new Set(names);
    const conflict = !idValid || unique.size !== labels.length || labels.length > 1;
    const owner = !conflict && labels.length === 1 ? names[0] : null;
    // Every label is a potential claim, even on an already-conflicted PR.
    // Otherwise a second PR sharing one of those labels could false-green.
    for (const name of unique) {
      if (ID.test(name)) ownerNumbers.set(name, (ownerNumbers.get(name) || 0) + 1);
    }
    return {
      number: pr.number,
      title: pr.title,
      draft: Boolean(pr.draft),
      updated_at: pr.updated_at || null,
      exact_head: pr.head.sha,
      branch: typeof pr.head.ref === "string" ? pr.head.ref : null,
      worker_id: owner,
      assignment_state: conflict ? "CONFLICT" : owner ? "ASSIGNED" : "UNASSIGNED",
      conflict_reason: conflict ? "AMBIGUOUS_PR_LABELS" : null,
    };
  });

  for (const pr of openPullRequests) {
    if (pr.worker_id && ownerNumbers.get(pr.worker_id) > 1) {
      pr.assignment_state = "CONFLICT";
      pr.conflict_reason = "WORKER_OWNS_MULTIPLE_OPEN_PRS";
    }
  }
  const recentlyMerged = recent.map((raw) => requirePullRequest(raw, "closed"))
    .filter((pr) => typeof pr.merged_at === "string" && pr.merged_at)
    .map((pr) => ({
      number: pr.number, title: pr.title, merged_at: pr.merged_at,
      exact_head: pr.head.sha,
    }));
  const assigned = openPullRequests.filter((pr) => pr.assignment_state === "ASSIGNED").length;
  const conflicts = openPullRequests.filter((pr) => pr.assignment_state === "CONFLICT").length;
  return {
    source: "github",
    authority: "read_only_derived",
    repository: {
      full_name: repository.full_name,
      default_branch: repository.default_branch,
    },
    collection_scope: {
      open_prs: "complete_if_under_100",
      recent_closed_prs: RECENT_CLOSED_LIMIT,
    },
    liveness: "UNKNOWN",
    metrics: {
      open_prs: openPullRequests.length,
      assigned_prs: assigned,
      unassigned_prs: openPullRequests.filter((pr) => pr.assignment_state === "UNASSIGNED").length,
      ownership_conflicts: conflicts,
    },
    open_pull_requests: openPullRequests.sort((a, b) => b.number - a.number),
    recently_merged_sample: recentlyMerged,
  };
}

export async function dashboardState(gh) {
  const [repo, open, recent] = await Promise.all([
    gh.repo(), gh.openPullRequests(), gh.recentClosedPullRequests(),
  ]);
  return normalizeDashboardData(repo, open, recent);
}

const css = `
<style>
.dashboard .eyebrow{font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#8faef8}
.dashboard h1{font-size:clamp(30px,5vw,48px);margin:12px 0 8px;letter-spacing:-.04em}
.dashboard .lead{max-width:70ch;line-height:1.65;color:#b9c6da}
.dashboard .overview-head{padding:26px 0 15px}
.dashboard .metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
.dashboard .metric{background:#182437;border:1px solid #34445c;border-radius:14px;padding:22px;min-width:0}
.dashboard .metric strong{display:block;font-size:36px;font-variant-numeric:tabular-nums;letter-spacing:-.04em}
.dashboard .metric small{display:block;color:#aebdd0;margin-top:4px;font-size:12px;letter-spacing:.03em}
.dashboard .split{display:grid;grid-template-columns:minmax(0,2fr) minmax(240px,1fr);gap:18px;align-items:start}
.dashboard .item{padding:14px 0;border-bottom:1px solid #2c3a51;display:flex;justify-content:space-between;align-items:flex-start;gap:14px}
.dashboard .item:last-child{border-bottom:0}
.dashboard .item a{font-weight:650;text-decoration:none;color:#f1f5ff}
.dashboard .item a:hover{text-decoration:underline}
.dashboard .muted,.dashboard .item small{color:#aebdd0}
.dashboard .pill{display:inline-block;border:1px solid #516482;border-radius:999px;padding:4px 9px;font-size:11px;font-weight:700;white-space:nowrap}
.dashboard .pill.bad{border-color:#b26b65;color:#ffb4ab}
.dashboard .pill.good{border-color:#4c987c;color:#9de6c3}
.dashboard h2{font-size:18px;letter-spacing:-.02em}
.dashboard .footnote{font-size:13px;line-height:1.6;color:#acbdd4}
.dashboard code{overflow-wrap:anywhere}
@media(max-width:760px){.dashboard .metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.dashboard .split{grid-template-columns:1fr}}
</style>`;

const localPr = (number) => "/pr/" + encodeURIComponent(number);
const repoUrl = (name) => "https://github.com/" + name;
const labelFor = (pr) => pr.assignment_state === "CONFLICT"
  ? "CONFLICT" : pr.worker_id ? pr.worker_id : "UNASSIGNED";
const pillFor = (pr) => pr.assignment_state === "CONFLICT" ? "bad" :
  pr.assignment_state === "ASSIGNED" ? "good" : "";

function openItem(pr) {
  return '<div class="item"><div><a href="' + localPr(pr.number) + '">#' +
    escapeText(pr.number) + " " + escapeText(pr.title) + "</a>" +
    '<div><small>head ' + escapeText(pr.exact_head.slice(0, 12)) +
    (pr.draft ? " · Draft" : "") +
    (pr.conflict_reason ? " · " + escapeText(pr.conflict_reason) : "") +
    '</small></div></div><span class="pill ' + pillFor(pr) + '">' +
    escapeText(labelFor(pr)) + "</span></div>";
}

function mergeItem(pr, fullName) {
  const target = repoUrl(fullName) + "/pull/" + pr.number;
  return '<div class="item"><div><a href="' + escapeText(target) +
    '" target="_blank" rel="noopener noreferrer">#' + escapeText(pr.number) +
    " " + escapeText(pr.title) + '</a><div><small>Merged ' +
    escapeText(pr.merged_at.slice(0, 10)) + " · head " +
    escapeText(pr.exact_head.slice(0, 12)) + "</small></div></div></div>";
}

function countBlock(value, label) {
  return '<div class="metric"><strong>' + escapeText(value) +
    '</strong><small>' + escapeText(label) + "</small></div>";
}

export function renderDashboard(state) {
  const m = state.metrics;
  const open = state.open_pull_requests;
  const recent = state.recently_merged_sample;
  const repositoryUrl = repoUrl(state.repository.full_name);
  return css + '<div class="dashboard">' +
    '<div class="overview-head"><span class="eyebrow">GitHub authority · Read-only</span>' +
    '<h1>Engineering overview</h1>' +
    '<p class="lead">A live GitHub-derived view of pull request ownership and engineering progress. ' +
    'Worker process liveness is <strong>UNKNOWN</strong> until separately proven. ' +
    'Certification and first causal failure evidence are available by opening each PR.</p></div>' +
    '<div class="metric-grid">' +
      countBlock(m.open_prs, "OPEN PRs") +
      countBlock(m.assigned_prs, "SINGLY ASSIGNED PRs") +
      countBlock(m.unassigned_prs, "UNASSIGNED PRs") +
      countBlock(m.ownership_conflicts, "OWNERSHIP CONFLICTS") +
    '</div><div class="split">' +
      '<section><h2>Open pull requests</h2>' +
      (open.length ? open.map(openItem).join("") :
        '<p class="muted">No open PRs were returned by GitHub.</p>') +
      '</section><div><section><h2>Recent merges</h2>' +
      '<p class="footnote">Sampled from the 12 most recently closed PRs, not total history.</p>' +
      (recent.length ? recent.map((item) => mergeItem(item, state.repository.full_name)).join("") :
        '<p class="muted">No merges in the sampled recent closed PRs.</p>') +
      '</section><section><h2>Source and boundaries</h2>' +
      '<p class="footnote">Repository: <a href="' + escapeText(repositoryUrl) +
        '" target="_blank" rel="noopener noreferrer">' +
        escapeText(state.repository.full_name) + '</a></p>' +
      '<p class="footnote">Assignment labels are GitHub ownership metadata, not proof a worker is online. ' +
      'This dashboard does not dispatch, certify, merge, or store task state.</p>' +
      '<p><a href="/worker">Configured worker assignment view →</a></p>' +
      '</section></div></div></div>';
}
