export const SYSTEM_REGISTRY = Object.freeze({
  worker: Object.freeze({ slug: "worker", repo: "jan2xo/bke-worker", label: "BKE Worker" }),
});
const FAILURE_STATES = new Set(["failure","cancelled","timed_out","action_required"]);
const PENDING_STATES = new Set(["queued","in_progress","waiting","requested","pending"]);
const POSITIVE_STATES = new Set(["success","passed","neutral"]);

export function normalizeStatus(value) {
  return String(value || "").toLowerCase().replaceAll(" ","_");
}

export function evidenceMatchesHead(item, exactHead) {
  if (!exactHead) return false;
  const heads = [
    item?.sha,item?.head_sha,item?.source_sha,item?.resolved_sha,item?.pr_head_sha,item?.exact_head,
    item?.pull_request?.head?.sha,
    ...(Array.isArray(item?.pull_requests) ? item.pull_requests.map(x => x?.head?.sha) : [])
  ].filter(Boolean);
  return heads.includes(exactHead);
}

export function certificationSummary({exactHead,checks=[],workflowRuns=[],proof=[],requiredProof=[]}) {
  const relevant=[...checks,...workflowRuns,...proof].filter(x=>evidenceMatchesHead(x,exactHead));
  const required=requiredProof.filter(x=>evidenceMatchesHead(x,exactHead));
  const failures=required.filter(x=>FAILURE_STATES.has(normalizeStatus(x.conclusion||x.status)));
  const pending=required.filter(x=>PENDING_STATES.has(normalizeStatus(x.conclusion||x.status)));
  const positive=required.filter(x=>POSITIVE_STATES.has(normalizeStatus(x.conclusion||x.status)));
  const observedFailures=relevant.filter(x=>FAILURE_STATES.has(normalizeStatus(x.conclusion||x.status)));
  return {
    exact_head:exactHead,checks_seen:checks.filter(x=>evidenceMatchesHead(x,exactHead)).length,
    workflow_runs_seen:workflowRuns.filter(x=>evidenceMatchesHead(x,exactHead)).length,
    proof_seen:proof.filter(x=>evidenceMatchesHead(x,exactHead)).length,
    required_seen:required.length,failures:failures.length,pending:pending.length,positive:positive.length,
    observed_failures:observedFailures.length,
    state:failures.length?"FAILED":pending.length?"PENDING":positive.length?"PASSED":"UNKNOWN",
    reason:failures.length?"REQUIRED_CERTIFICATION_FAILED":pending.length?"REQUIRED_CERTIFICATION_PENDING":positive.length?null:"NO_REQUIRED_CERTIFICATION_PROOF"
  };
}

export function reduceFirstCausalFailure(evidence=[]) {
  const failures=evidence.filter(x=>FAILURE_STATES.has(normalizeStatus(x.conclusion||x.status)));
  const positive=evidence.filter(x=>POSITIVE_STATES.has(normalizeStatus(x.conclusion||x.status)));
  if(!failures.length) return {causal:null,downstream:[],unaffected:[...new Set(positive.map(x=>x.boundary).filter(Boolean))]};
  const ordered=[...failures].sort((a,b)=>String(a.occurred_at||"").localeCompare(String(b.occurred_at||"")));
  const causal=ordered.find(x=>x.causal===true)||ordered[0];
  return {
    causal:{...causal,classification:"CAUSAL"},
    downstream:ordered.filter(x=>x!==causal).map(x=>({...x,classification:"DOWNSTREAM"})),
    unaffected:[...new Set(positive.map(x=>x.boundary).filter(Boolean))]
  };
}

export function buildPostRunSummary(state) {
  const f=state.first_causal_failure?.causal;
  if(f) return `First causal failure: ${f.summary}. Next: ${f.next_action||"inspect the causal evidence"}`;
  if(state.certification?.state==="PENDING") return "Required certification is still in progress.";
  if(state.certification?.state==="PASSED") return "Required certification passed for the exact PR head.";
  if(state.certification?.state==="FAILED") return "Required certification failed for the exact PR head.";
  return "Current engineering state is UNKNOWN.";
}

export function buildFailureCapsule({repo,pr_number,exact_head,worker_id,evidence}) {
  const reduced=reduceFirstCausalFailure(evidence), causal=reduced.causal;
  return {
    repo,pr_number,exact_head,worker_id:worker_id||null,
    occurred_at:causal?.occurred_at||null,host:causal?.host||null,boundary:causal?.boundary||null,
    stage:causal?.stage||null,classification:causal?"CAUSAL":null,summary:causal?.summary||null,
    evidence_run_ids:causal?.evidence_run_ids||[],evidence:causal?.evidence||[],downstream:reduced.downstream,
    unaffected_boundaries:reduced.unaffected,next_owner:causal?.next_owner||null,next_action:causal?.next_action||null
  };
}
