import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseNitroComment, runNitroCommentGate } from "../scripts/nitro-comment-gate.mjs";

const REPO = "jan2xo/bke-command-center";
const HEAD = "a".repeat(40), OLD = "b".repeat(40), MAIN = "c".repeat(40);
const event = () => ({
  action: "created", repository: { full_name: REPO },
  issue: { number: 13, pull_request: { url: "https://api.github.com/repos/" + REPO + "/pulls/13" } },
  comment: { user: { login: "jan2xo" }, author_association: "OWNER",
    body: "/nitro-certify " + HEAD },
});
const pr = () => ({
  number: 13, state: "open", merged: false,
  base: { ref: "main", repo: { full_name: REPO } },
  head: { ref: "nitro/failure-visibility", sha: HEAD, repo: { full_name: REPO } },
  labels: [{ name: "bke-ci:nitro" }],
  body: "**Engineering mode:** " + String.fromCharCode(96) + "NITRO" + String.fromCharCode(96),
});
const commits = () => [
  { sha: OLD, commit: { message: "feat: start [skip ci]" } },
  { sha: HEAD, commit: { message: "feat: done [skip ci]" } },
];

test("owner exact-head comment is accepted", () => {
  assert.deepEqual(parseNitroComment(event()), { prNumber:13, expectedHead:HEAD });
});
for (const [name, mutate, code] of [
  ["edited comment", x => { x.action = "edited"; }, "NOT_AUTHORIZED"],
  ["wrong repository", x => { x.repository.full_name = "other/repo"; }, "NOT_AUTHORIZED"],
  ["ordinary issue", x => { delete x.issue.pull_request; }, "NOT_AUTHORIZED"],
  ["other author", x => { x.comment.user.login = "other"; }, "NOT_AUTHORIZED"],
  ["collaborator", x => { x.comment.author_association = "COLLABORATOR"; }, "NOT_AUTHORIZED"],
  ["wrong command", x => { x.comment.body = "/certify " + HEAD; }, "FORMAT_INVALID"],
  ["newlines after SHA", x => { x.comment.body += "\nsecond-command"; }, "FORMAT_INVALID"],
  ["invalid SHA", x => { x.comment.body = "/nitro-certify " + "BAD"; }, "FORMAT_INVALID"],
  ["missing PR number", x => { x.issue.number = 0; }, "NOT_AUTHORIZED"],
]) {
  test("reject "+name, () => {
    const e = event(); mutate(e);
    assert.throws(() => parseNitroComment(e), new RegExp(code));
  });
}
async function run({ payload = event(), pull = pr(), history = commits(), phase = "preflight",
  certifiedHead = HEAD, overrides = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "cc-nitro-comment-"));
  try {
    const eventPath = join(dir,"event.json"), outputPath = join(dir,"outputs");
    writeFileSync(eventPath,JSON.stringify(payload)); writeFileSync(outputPath,"");
    const env = {
      GITHUB_EVENT_NAME:"issue_comment",GITHUB_REPOSITORY:REPO,
      GITHUB_REF:"refs/heads/main",GITHUB_SHA:MAIN,
      GITHUB_TOKEN:"TEST_TOKEN",GITHUB_EVENT_PATH:eventPath,
      GITHUB_OUTPUT:outputPath,NITRO_PHASE:phase,
      NITRO_CERTIFIED_HEAD:certifiedHead,...overrides,
    };
    const calls=[];
    const fetcher=async (url,options)=>{
      calls.push(url);
      assert.equal(options.headers.Authorization,"Bearer TEST_TOKEN");
      assert.match(url,/^https:\/\/api\.github\.com\/repos\/jan2xo\/bke-command-center\/pulls\/13/);
      return {ok:true,json:async()=>url.includes("/commits?")?history:pull};
    };
    let result=null,error=null;
    try {result=await runNitroCommentGate(env,fetcher);} catch(ex){error=ex;}
    return {result,error,calls,output:readFileSync(outputPath,"utf8")};
  } finally {rmSync(dir,{recursive:true,force:true});}
}
test("preflight validates exact HEAD and only then emits the SHA",async()=>{
  const x=await run();
  assert.equal(x.error,null);
  assert.equal(x.result.expectedHead,HEAD);
  assert.equal(x.calls.length,2);
  assert.equal(x.output,"source_sha="+HEAD+"\npr_number=13\n");
});
test("postflight checks same PR head again and emits no new artifact",async()=>{
  const x=await run({phase:"postflight"});
  assert.equal(x.error,null);
  assert.equal(x.calls.length,2);
  assert.equal(x.output,"");
});
for(const [name,args,code] of [
  ["PR HEAD moved",{pull:{...pr(),head:{...pr().head,sha:OLD}}},"STALE_EXACT_HEAD"],
  ["wrong label",{pull:{...pr(),labels:[{name:"bke-ci:normal"}]}},"NITRO_MODE_NOT_EXPLICIT"],
  ["wrong PR base",{pull:{...pr(),base:{...pr().base,ref:"develop"}}},"PR_REPOSITORY_OR_BASE_INVALID"],
  ["commit lacked skip",{history:[{sha:OLD,commit:{message:"oops"}},commits()[1]]},"NITRO_SKIP_COMMIT_CHAIN_INVALID"],
  ["postflight changed target",{phase:"postflight",certifiedHead:OLD},"POSTFLIGHT_STALE"],
  ["not trusted main ref",{overrides:{GITHUB_REF:"refs/pull/13/merge"}},"ENV_INVALID"],
  ["not issue comment",{overrides:{GITHUB_EVENT_NAME:"pull_request"}},"ENV_INVALID"],
  ["untrusted owner",{payload:{...event(),comment:{...event().comment,user:{login:"other"}}}},"NOT_AUTHORIZED"],
]) {
  test("fail closed "+name,async()=>{
    const x=await run(args);
    assert.ok(x.error);
    assert.match(x.error.message,new RegExp(code));
    assert.equal(x.output,"");
  });
}
test("workflow: only comment event, fully gated runner and exact-head proof",()=>{
  const y=readFileSync(new URL("../.github/workflows/nitro-certify.yml",import.meta.url),"utf8");
  assert.match(y,/^  issue_comment:\n    types: \[created\]$/m);
  assert.doesNotMatch(y,/^  pull_request:|^  pull_request_target:|^  push:/m);
  assert.match(y,/github\.event\.comment\.user\.login == 'jan2xo'/);
  assert.match(y,/author_association == 'OWNER'/);
  assert.match(y,/startsWith\(github\.event\.comment\.body, '\/nitro-certify '\)/);
  assert.match(y,/NITRO_PHASE: preflight/);
  assert.match(y,/NITRO_PHASE: postflight/);
  assert.match(y,/ref: \$\{\{ steps\.gate\.outputs\.source_sha \}\}/);
  assert.equal((y.match(/persist-credentials: false/g)||[]).length,3);
  for(const command of ["npm ci","npm test","npm run check","npm run cloudflare:dry-run"]){
    assert.ok(y.includes("run: "+command));
  }
  assert.doesNotMatch(y,/cloudflare:deploy:preproduction|contents: write|actions: write/);
});
