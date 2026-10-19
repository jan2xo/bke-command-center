# Device-origin prepared proposals — source-only

Parent: Command Center issue #30. Builds on merged PRs #51–54. New named installation Durable Object method: managePreparedDeviceProposal. No live HTTP ingress, credentials, Cloudflare activation or production action.

## Trust and mechanics

A new device signing with P-256 proves control of one device key, not that the worker is authorized. A separately certified native-messaging or extension ingress is still needed. The source-only stageDeviceOriginProposal accepts a trusted in-process device bridge containing readCandidate() and a non-serializable signChallenge(message) function. The server validates the Access platform human, determines installation from the private GitHub App inventory and validates worker identity, canonical P-256 public key and the three exact resource fingerprints. It creates a fresh 256-bit random challenge and 30s expiry. The device signs a domain-separated challenge binding human keyed subject, worker, installation, canonical proposal hash, nonce and expiry. WebCrypto checks the signature.

The server signs a separate private 30s HMAC request for the correct installation DO and validates the DO's HMAC acknowledgment. The receiver confirms its actual ctx.id, time, signature, proposal digest and fresh strict GitHub inventory. It transactionally checks paired, pending, prepared and consent registries for duplicate worker/resource, ambiguous evidence or corruption. One proposal at a time can be prepared per installation under new 90-second bounded fifth SQLite key: prepared. Retrying a signed stage command cannot create a second active proposal.

An Admin can only read a prepared proposal through Access and fresh private GitHub-App scope. The private read independently checks that the proposal still matches the public key, fingerprints and tenant; that no GitHub worker assignment appeared; and that paired/pending resources did not become occupied. The createAdminPreparedProposalServer factory supplies the existing PR #54 human-review adapter with only the server-prepared offer. There is no client-controlled installation, worker selection, status or Admin identity field. Neither staging nor review grants a worker lease or GitHub PR ownership.

## Certification and locks

Full exact-head Command Center CI: Node tests, syntax check, Wrangler PREPRODUCTION dry-run and real local Workerd/SQLite FIVE-key commit, rollback, isolation and concurrent persistence smoke. Adversarial Node cases include forged Access, missing bridge, wrong device key, altered fingerprints, tampered HMAC, wrong tenant, stale/duplicate command, competing worker, provider outage, concurrent staging, changed GitHub ownership, storage rollback, and no public endpoint.

This proves source and local runtime only. The actual authenticated device transport is not implemented, device challenge delivery is not implemented, PREPRODUCTION and production activation are locked, no secrets or permissions are changed, and parked Worker PR #90 is untouched.

Human-readable descriptions are instead supplied by a separate required server-owned describeResources callback. An unpaired device cannot provide those labels to the Admin review page.
