const API="https://api.github.com";

async function github(path,env){
  const headers={Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"bke-command-center-preproduction"};
  if(env.GITHUB_TOKEN) headers.Authorization=`Bearer ${env.GITHUB_TOKEN}`;
  const response=await fetch(`${API}${path}`,{headers});
  const body=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(`GitHub ${response.status}: ${body.message||"request failed"}`);
  return body;
}

export function createGitHubAdapter(env){
  const owner=env.GITHUB_OWNER||"jan2xo",repo=env.GITHUB_REPO||"bke-worker";
  return {
    async repo(){return github(`/repos/${owner}/${repo}`,env);},
    async pullRequest(number){return github(`/repos/${owner}/${repo}/pulls/${number}`,env);},
    async openPullRequests(){return github(`/repos/${owner}/${repo}/pulls?state=open&per_page=100`,env);},
    async checks(ref){return github(`/repos/${owner}/${repo}/commits/${ref}/check-runs?per_page=100`,env);},
    async workflowRuns(event=null){return github(`/repos/${owner}/${repo}/actions/runs?per_page=100${event?`&event=${encodeURIComponent(event)}`:""}`,env);},
    async workflowJobs(runId){return github(`/repos/${owner}/${repo}/actions/runs/${runId}/jobs?per_page=100`,env);},
    async issueComments(number){return github(`/repos/${owner}/${repo}/issues/${number}/comments?per_page=100`,env);}
  };
}

export function assignmentFromPullRequest(pr){
  const worker=(pr.labels||[]).map(x=>x.name).find(name=>name.startsWith("bke-worker:"));
  return {worker_id:worker?worker.slice("bke-worker:".length):null,state:pr.state==="open"?"OPEN":"CLOSED",pr_number:pr.number,exact_head:pr.head?.sha||null,branch:pr.head?.ref||null};
}

export function evidenceFromJob(job,run){
  const text=(job.steps||[]).map(s=>`${s.name} ${s.conclusion||s.status||""}`).join(" ");
  const source=job.source_sha||job.resolved_sha||job.pr_head_sha||run.source_sha||run.resolved_sha||run.pull_requests?.[0]?.head?.sha||run.head_sha;
  return {
    status:job.conclusion||job.status,conclusion:job.conclusion,source_sha:source,
    occurred_at:job.completed_at||job.started_at||run.updated_at||run.created_at,
    host:"github_actions",boundary:job.name||run.name||"github_actions",
    stage:/test/i.test(text)?"test":/build/i.test(text)?"build":"workflow",
    summary:job.conclusion==="failure"?`${job.name}: failed`:`${job.name}: ${job.conclusion||job.status}`,
    evidence_run_ids:[String(run.id)],evidence:[{type:"job",id:String(job.id),url:job.html_url||run.html_url}],
    url:job.html_url||run.html_url,causal:false
  };
}

export function commentEvidence(comments,exactHead){
  return comments.filter(c=>c.body?.includes(exactHead)).map(c=>({
    source_sha:exactHead,
    status:/FAIL|FAILED|failure/i.test(c.body)?"failure":/PASS|PASSED|success/i.test(c.body)?"success":"neutral",
    occurred_at:c.updated_at||c.created_at,host:"github",boundary:"github_pr",stage:"certification",
    summary:c.body.split("\n")[0],evidence_run_ids:[String(c.id)],
    evidence:[{type:"comment",id:String(c.id),url:c.html_url||c.url}],url:c.html_url||c.url
  }));
}

export async function collectEvidence(gh,pr,exactHead){
  const [checkData,runData,comments]=await Promise.all([gh.checks(exactHead),gh.workflowRuns(),gh.issueComments(pr.number)]);
  const checks=checkData.check_runs||[],runs=runData.workflow_runs||[];
  const jobs=await Promise.all(runs.slice(0,100).map(async run=>{try{return [run,(await gh.workflowJobs(run.id)).jobs||[]];}catch{return [run,[]];}}));
  const jobEvidence=jobs.flatMap(([run,js])=>js.map(job=>evidenceFromJob(job,run)));
  const commentsEvidence=commentEvidence(comments,exactHead);
  return {checks,workflowRuns:runs,jobs:jobEvidence,comments:commentsEvidence,all:[...checks,...jobEvidence,...commentsEvidence]};
}
