// Run a REAL local Cloudflare Workerd SQLite Durable Object (not a mock).
// Only localhost, isolated fixture Wrangler config, disposable test state.
import { spawn } from "node:child_process";
import assert from "node:assert/strict";

const ENDPOINT = "http://127.0.0.1:8977";
const TIME_LIMIT_MS = 90_000;
const TICK_MS = 350;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let output = "";
const command = spawn("npx", [
  "--yes", "wrangler@4.148.0", "dev",
  "--local", "--config", "scripts/pairing-sqlite-smoke/wrangler.toml",
  "--ip", "127.0.0.1", "--port", "8977",
], {
  cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"],
  detached: true, env: { ...process.env, CI: "true", BROWSER: "none" },
});
for (const stream of [command.stdout, command.stderr]) {
  stream.on("data", chunk => {
    output = (output + String(chunk)).slice(-4500);
  });
}
let exited = false;
command.on("exit", () => { exited = true; });
command.on("error", () => { exited = true; });

async function response(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const res = await fetch(ENDPOINT + path, {
      signal: controller.signal, redirect: "error",
      headers: { accept: "application/json" },
    });
    const payload = await res.json();
    return { status: res.status, data: payload };
  } finally { clearTimeout(timer); }
}
try {
  const start = Date.now();
  let ready = false;
  while (Date.now() - start < TIME_LIMIT_MS && !exited) {
    try {
      const health = await response("/health");
      if (health.status === 200 &&
          health.data?.fixture === "LOCAL_SQLITE_DO_ONLY" &&
          health.data?.state === "READY") {
        ready = true;
        break;
      }
    } catch { /* Wrangler not listening yet */ }
    await sleep(TICK_MS);
  }
  assert.equal(ready, true, "LOCAL_DO_WORKER_NEVER_READY");
  const execution = await response("/smoke");
  assert.equal(execution.status, 200, "LOCAL_DO_SMOKE_HTTP_FAILURE");
  assert.deepEqual(execution.data, {
    state: "PASS", checks: [
      "installation_isolation", "sequential_sqlite_persistence",
      "three_key_commit", "three_key_rollback",
      "concurrent_transaction_serialization",
    ],
  });
  const later = await response("/verify");
  assert.equal(later.status, 200, "LOCAL_DO_SECOND_REQUEST_FAILURE");
  assert.deepEqual(later.data, {
    state: "OBSERVED", a_paired_count: 4, b_paired_count: 0,
    pending_count: 1, admin_actions_count: 1,
  });
  const denied = await response("/unknown");
  assert.equal(denied.status, 404, "LOCAL_DO_UNKNOWN_PATH_NOT_DENIED");
  process.stdout.write("BKE LOCAL SQLITE DURABLE OBJECT SMOKE: PASS\n");
  process.stdout.write("isolation, persistence, three-key rollback, concurrency, HTTP deny\n");
} catch (error) {
  process.stderr.write("BKE LOCAL SQLITE DURABLE OBJECT SMOKE: FAIL\n");
  process.stderr.write(String(error?.message || "UNKNOWN") + "\n");
  process.stderr.write(output.slice(-1800) + "\n");
  process.exitCode = 1;
} finally {
  // Kill the entire local Wrangler process group, including workerd child.
  try { process.kill(-command.pid, "SIGTERM"); }
  catch { try { command.kill("SIGTERM"); } catch { /* already stopped */ } }
}
