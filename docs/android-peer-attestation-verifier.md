# Android peer attestation verifier — SOURCE ONLY

Parent: [Command Center #30](https://github.com/jan2xo/bke-command-center/issues/30), [GeckoView trust seam #60](https://github.com/jan2xo/bke-command-center/issues/60), Worker device evidence [PR #144](https://github.com/jan2xo/bke-worker/pull/144).

## What this module verifies

`src/android-peer-attestation-verifier.js` is a private, non-routed verification primitive for the evidence schema emitted by Worker PR #144. It fails closed unless the trusted caller supplies exact server-owned worker/session/profile/bridge bindings, the original enrollment challenge, an exclusively claimed fresh proof nonce, approved package and app-signing-certificate pins, an approved X.509 root fingerprint set, and a fresh revocation status snapshot.

The verifier checks:
- Exact v1 evidence schema, 32-byte canonical base64url challenges, UUID / worker shape and exact ChatGPT target origin.
- The complete leaf-first attestation certificate chain, validity window, issuer linkage, signatures, CA roles and configured root fingerprint; the leaf key must be EC P-256 and match the public key in the payload.
- The Android key-attestation extension OID `1.3.6.1.4.1.11129.2.1.17`, matching TEE or StrongBox security levels, and the key's embedded original challenge against the server-side enrollment record.
- A unique hardware-enforced `rootOfTrust [704]` record requiring `deviceLocked=true` and `verifiedBootState=Verified (0)`; absent, software-only, conflicting/duplicate, unlocked, self-signed, unverified, or failed boot records fail closed. `attestationApplicationId [709]` must be unique and software-enforced, and is accepted as a trusted app identity only alongside that hardware boot-state evidence.
- The X.509 DER KeyUsage BIT STRING directly: leaf must include `digitalSignature`; each supplied issuer must include `keyCertSign`. Node's `X509Certificate.keyUsage` (Extended Key Usage) is not used for these checks.
- The attested Android application package name and app-signing certificate SHA-256 digest against server-owned pins.
- Every certificate serial against a fresh revocation snapshot and the signature over the exact length-prefixed protocol-v1 payload (version, proof challenge, worker ID, session ID, profile ID, bridge ID, target origin).

The local `hardwareBacked` evidence flag is explicitly treated as untrusted. Only parsed certificate evidence controls the hardware-security-level result.

## Trust boundaries and remaining blockers

This module is not a completed enrollment integration and **does not itself authorize pairing or dispatch**. Every successful result still declares `pairing_authority: NONE` and `dispatch_authority: NONE`.

Before any caller can use this result, separate work must:
1. Provision the approved Google Android attestation root fingerprint list, APK package name and application signing digest through the human-approved server trust process. The code intentionally contains no implicit root pins or default-accept configuration.
2. Implement and maintain a server-owned loader/cache for the official revocation status endpoint, `https://android.googleapis.com/attestation/status`, honoring its cache policy; this PR only validates a fresh cache snapshot passed by the private caller.
3. Atomically claim a server-issued, single-use proof challenge before calling the verifier and durably finalize/consume it on both success and failure. The verifier requires the caller's record to be in the exclusive `CLAIMED` state but does not own that storage transaction.
4. Provide a genuinely trusted, OS/native-channel GeckoView peer and exclusive live session/profile/bridge/target attestor, with human-admin pin provisioning and revocation. This is still absent; device-supplied data and injectable callbacks are not proof of OS peer authenticity.
5. Integrate the verifier only through a later private server path that rechecks Admin authorization, current installation/worker assignment, session binding and owner consent, with independent security review before activation.

No public HTTP/WebSocket route imports this module. No Worker or Command Center runtime entrypoint was wired, no feature flag was enabled, and no credential issuance/rotation, live pairing, GitHub assignment, Android wake, Cloudflare mutation, PREPRODUCTION deployment or production action was performed.

## Certification

The Node tests create a temporary ECDSA root and Android-attestation-shaped certificate chain with OpenSSL, then exercise valid signatures and negative cases for unpinned roots, wrong worker/profile/target, mismatch of proof or original enrollment challenge, incorrect app signer, altered proof signatures, stale revocation data, revoked certificates, software-level attestation, missing/software-only/duplicate rootOfTrust, unlocked boot, non-Verified boot states, issuer without keyCertSign, unclaimed/expired proof challenges and malformed chain input.

These fixtures prove the verifier's deterministic cryptographic and policy behavior against generated certificates; they **do not** establish trust in an actual Google production attestation root, physical Android hardware, the deployed APK signer, an authenticated GeckoView native channel, or the live Cloudflare caller. Android's published verifier guidance requires a validated root chain, hardware-backed attestation security level and revocation checking before trusting the key. See the [Android key-attestation guidance](https://developer.android.com/privacy-and-security/security-key-attestation) and [ASN.1 attestation schema](https://source.android.com/docs/security/features/keystore/attestation).
