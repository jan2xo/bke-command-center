import test from "node:test";
import assert from "node:assert/strict";
import { discoverGitHubRepositories } from "../src/admin-discovery.js";

const scope = {
  purpose: "admin_source_discovery",
  repository: "jan2xo/bke-worker",
};
function mint(token="ghs_readfixture") {
  return {
    token, principal: "github_app_installation", repository: scope.repository,
    expires_at: new Date(Date.now() + 40 * 60000).toISOString(),
    permissions: { contents: "read", issues: "read", pull_requests: "read" },
  };
}
function fixture(options={}) {
  const calls=[];
  const env={
    GITHUB_DISCOVERY_AUTH_MODE:"broker",
    GITHUB_TOKEN:"ghp_HIGH_PRIVILEGE_LEGACY_TOKEN",
    GITHUB_DISCOVERY_PRINCIPAL:"user",
    BKE_GITHUB_READ_BROKER:{
      async mintReadOnlyGitHubToken(args) {
        calls.push(args);
        return options.response || mint();
      },
    },
  };
  return { env, calls };
}
const repo = {
  id:1354026486,full_name:"jan2xo/bke-worker",default_branch:"main",
  visibility:"private",private:true,archived:false,
};

test("read-only private RPC is used for every Admin discovery request without a PAT fallback",async()=>{
  const {env,calls}=fixture();
  const gitHubReads=[];
  const result=await discoverGitHubRepositories(env,async (url,options)=>{
    gitHubReads.push({url,options});
    assert.match(url,/https:\/\/api\.github\.com\/installation\/repositories\?/);
    assert.equal(options.headers.Authorization,"Bearer ghs_readfixture");
    assert.doesNotMatch(JSON.stringify(options.headers),/HIGH_PRIVILEGE/);
    return Response.json({total_count:1,repositories:[repo]});
  });
  assert.deepEqual(calls,[scope]);
  assert.equal(gitHubReads.length,1);
  assert.equal(result.principal,"installation");
  assert.deepEqual(result.repositories.map(x=>x.full_name),["jan2xo/bke-worker"]);
  assert.equal(result.credential.auto_rotation,true);
  assert.equal(result.credential.credential,"BROKER_CONNECTED");
  assert.equal(result.credential.token_lifecycle,"ON_DEMAND_SHORT_LIVED");
  assert.equal(result.credential.scope_verified,false);
  assert.doesNotMatch(JSON.stringify(result),/ghs_readfixture|HIGH_PRIVILEGE/);
});

test("broker is called anew rather than caching token across requests",async()=>{
  let sequence=0;
  const {env}=fixture();
  env.BKE_GITHUB_READ_BROKER.mintReadOnlyGitHubToken=async ()=>mint("ghs_rotation"+(++sequence));
  const seen=[];
  for(let i=0;i<2;i++){
    await discoverGitHubRepositories(env,async (_url,options)=>{
      seen.push(options.headers.Authorization);
      return Response.json({total_count:1,repositories:[repo]});
    });
  }
  assert.deepEqual(seen,["Bearer ghs_rotation1","Bearer ghs_rotation2"]);
  assert.equal(sequence,2);
});

test("broker missing/unreachable never downgrades to even a configured GitHub PAT",async()=>{
  let outgoing=0;
  const fetchImpl=async()=>{outgoing++;return Response.json({repositories:[]});};
  const missing=fixture().env;
  delete missing.BKE_GITHUB_READ_BROKER;
  await assert.rejects(()=>discoverGitHubRepositories(missing,fetchImpl),/GITHUB_BROKER_UNAVAILABLE/);
  const refused=fixture().env;
  refused.BKE_GITHUB_READ_BROKER.mintReadOnlyGitHubToken=async()=>{throw new Error("secret raw upstream");};
  await assert.rejects(()=>discoverGitHubRepositories(refused,fetchImpl),/GITHUB_BROKER_UNAVAILABLE/);
  assert.equal(outgoing,0);
});

test("broker token scope and TTL deviations fail closed before any GitHub API call",async()=>{
  let outgoing=0;
  const fetchImpl=async()=>{outgoing++;throw Error("must not fetch");};
  const samples=[
    {principal:"user"},
    {repository:"jan2xo/other"},
    {token:"ghp_userPAT"},
    {expires_at:new Date(Date.now()-1000).toISOString()},
    {expires_at:new Date(Date.now()+120*60000).toISOString()},
    {permissions:{contents:"write",issues:"read",pull_requests:"read"}},
    {permissions:{contents:"read",issues:"read",pull_requests:"read",administration:"write"}},
  ];
  for(const bad of samples){
    const {env}=fixture({response:{...mint(),...bad}});
    await assert.rejects(()=>discoverGitHubRepositories(env,fetchImpl),/GITHUB_BROKER_RESPONSE_INVALID/);
  }
  assert.equal(outgoing,0);
});

test("unknown credential mode cannot default to a powerful PAT",async()=>{
  const {env}=fixture();
  env.GITHUB_DISCOVERY_AUTH_MODE="magic_broker";
  await assert.rejects(()=>discoverGitHubRepositories(env,async()=>{throw Error("must not fetch");}),/GITHUB_DISCOVERY_AUTH_MODE_INVALID/);
});
