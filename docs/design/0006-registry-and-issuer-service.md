# 0006 — Registry and Issuer Service (production design)

- **Status:** Draft
- **Date:** 2026-10-18
- **Working position (draft, not decided):** The registry is built to production standards from the first line, not as a prototype to be rewritten. Staging and production run the same binary; they differ only in configuration, keys and data. Every trust decision uses standard formats (SD-JWT VC, IETF Token Status List, an RFC 9162-style Merkle log), so the service can be replaced or federated later without changing verifiers.

## Scope

The registry is the **Issuer Service** from 0002 plus the **trust anchors** verifiers need. It covers:

1. Device enrollment with platform attestation (iOS App Attest first, Android Key Attestation later).
2. Issuing the **Attested User Key credential** (0002), later also the **Verified Human Credential** (0003).
3. Publishing issuer keys and a signed **trust list**.
4. **Revocation** via Token Status List.
5. The **transparency log** of enrollments, mandates and revocations.
6. Later: relaying DelegationRequests, the usage ledger, the evidence store.

It does **not** verify mandates for relying parties. That remains the verifier's job (aap-verifier-service or any AP2 verifier).

## Requirements

**Functional**

- F1 Enroll a device key only with a valid platform attestation and proof of possession of the key.
- F2 Issue credentials bound to that key (`cnf`), with assurance level and status reference.
- F3 Let a user add further devices *only* with approval from an existing device, and revoke any device or credential from any of their devices.
- F4 Publish issuer keys, the trust list and status lists at stable URLs, cacheable by verifiers.
- F5 Append enrollments, mandate hashes and revocations to the log; serve inclusion and consistency proofs.

**Security**

- S1 No private key of a *user* ever exists on the server (0002).
- S2 Issuer signing keys live in an HSM or KMS in production; no service process can export them.
- S3 Every key has exactly one purpose (credential issuance, status lists, log tree heads, trust list, API responses). Compromise of one does not imply the others.
- S4 Every state-changing call is authenticated with a signature from a device key, not with a bearer token. A stolen request cannot be replayed.
- S5 Fail closed: if attestation, status or log cannot be verified, the answer is "no".
- S6 The log and the revocation state are append-only at the database level, not only in application code.
- S7 All parsers of untrusted input (attestation objects, SD-JWTs, JWS, CBOR) are fuzzed before production.

**Privacy**

- P1 No names, e-mail addresses or phone numbers. A user is an internal random ID plus a set of device keys.
- P2 Log entries contain only hashes and per-user pseudonymous IDs.
- P3 Status lists are large and indices are allocated randomly, so fetching a list reveals nothing about which credential a verifier is checking.
- P4 Identity-related data for AL3 (uniqueness tags, 0003) lives in a separate store and HSM, not in the registry database.

**Operations**

- O1 Same binary for staging and production; differences only in configuration (for example, staging accepts the App Attest *development* environment, production does not).
- O2 Infrastructure as code; reproducible CI builds (static musl, as for the verifier); signed releases; SBOM, `cargo audit` and `cargo deny` in CI.
- O3 Postgres with point-in-time recovery, encrypted backups, restore tested regularly.
- O4 Least-privilege database roles: the application role cannot `UPDATE` or `DELETE` log entries or revocations; triggers reject it as a second line.
- O5 Monitoring and alerting on error rates, attestation failures, unusual enrollment volume and log consistency; runbooks for key compromise, log fork and database loss.
- O6 Rate limiting per IP and per device; enrollment challenges single-use with a short lifetime.

## Trust model

```
 Root key (offline, HSM, key ceremony)
   ├─ signs → Trust list  (which issuers verifiers should accept, which credential types, max assurance level)
   └─ signs → certificates for the online keys below
        ├─ Credential issuing key   (HSM/KMS, online)  → Attested User Key / Verified Human credentials
        ├─ Status list key          (HSM/KMS, online)  → Token Status Lists
        ├─ Log key                  (HSM/KMS, online)  → signed tree heads
        └─ API key                  (KMS or software)  → signed API responses where needed
```

- Verifiers discover issuer keys via **SD-JWT VC issuer metadata** (`/.well-known/jwt-vc-issuer` with a `jwks`). This is what AP2's User Credential model expects, so an AP2 verifier needs no AAP-specific discovery.
- The **trust list** is a signed JSON document, versioned, short-lived (re-signed daily), with entries: issuer identifier, metadata URL, allowed `vct`s, highest assurance level the issuer may assert. v1 contains one issuer (us). Federation (e.g. OpenID Federation) is a later option once there are other issuers.
- The **root key** is used only in a documented ceremony: initial setup, signing new online-key certificates, emergency rotation. It is never on a networked machine.

## Data model (sketch)

| Table | Content | Notes |
|---|---|---|
| `users` | `user_id` (random UUID), `log_pseudonym`, `created_at` | No personal data |
| `devices` | `device_id`, `user_id`, public JWK, JWK thumbprint, platform, attestation summary (type, environment, app id, key id), App Attest assertion counter, state (`active`/`revoked`), timestamps | Raw attestation objects kept for audit, access-restricted |
| `enrollment_challenges` | challenge, expiry, used flag | Single use, minutes TTL |
| `credentials` | `credential_id`, `device_id`, `vct`, assurance level, status list + index, `iat`/`exp` | The credential itself is returned to the device, not stored in full |
| `status_lists` | list id, bit array, version, last signed token | Random index allocation |
| `revocations` | what, when, by which device, reason code | Append-only |
| `log_entries` | index, leaf hash, entry type, timestamp | Append-only |
| `log_tree_heads` | size, root hash, signature, timestamp | Append-only |

## API (v1, sketch)

All state-changing requests are signed by a device key: HTTP Message Signatures (RFC 9421) over method, path, body digest and a timestamp, or DPoP (RFC 9449). Which of the two is still open (see below).

| Endpoint | Purpose |
|---|---|
| `POST /v1/enrollment/challenge` | Fresh single-use challenge |
| `POST /v1/enrollment` | Attestation + public JWK + signature over the challenge with the new key → device record, Attested User Key credential, log entry |
| `POST /v1/devices` | Add a device: request from the new device, **approval signed by an existing device** of the same user |
| `POST /v1/revocations` | Revoke a device or credential; signed by any active device of the user |
| `POST /v1/log/entries` | The Issuer App submits the hash of a mandate it signed |
| `GET /v1/log/tree-head`, `/v1/log/proof/...` | Signed tree head, inclusion and consistency proofs |
| `GET /v1/status-lists/{id}` | Token Status List JWT, cacheable |
| `GET /.well-known/jwt-vc-issuer` | Issuer metadata and keys |
| `GET /v1/trust-list` | Signed trust list |

Relay endpoints for DelegationRequests and push notifications follow in a later phase (0002).

## App Attest specifics

- The enrollment challenge goes into `clientDataHash` together with the JWK thumbprint of the Secure Enclave signing key (as in spike S1). The registry thereby learns that a genuine instance of the Issuer App vouches for that key.
- The registry stores the App Attest key ID and **assertion counter** per device. Later requests carry App Attest assertions; a counter that does not increase indicates a cloned or replayed key and blocks the device.
- Development-environment attestations are accepted **only** with the staging configuration.
- What iOS cannot prove (the Secure Enclave key's access-control flags) is recorded honestly in the credential: `attestation: "app_attest"` and assurance level `AL2-A` (0002), not a claim the platform did not make.
- Findings from spike S1 that the implementation must handle:
  - The attestation leaf certificate is valid for only about three days. Verify the chain once at enrollment, store the App Attest public key, and never re-validate the certificate later.
  - Assertions carry a bare 37-byte `authenticatorData` with the AT flag set but no credential data (observed on iOS 27). A WebAuthn-style parser that trusts the flag rejects every assertion.
  - `keyId` arrives as standard base64 from iOS, while JOSE uses base64url.
  - Every mandate signed on iOS comes with an App Attest assertion over `SHA256(mandate)`; the registry checks it against the stored key and requires the counter to increase.

## Transparency log

- Merkle tree in the style of RFC 9162 (Certificate Transparency 2.0): leaf hashes, signed tree heads, inclusion and consistency proofs.
- Entry types: `enrollment` (device key thumbprint + user log pseudonym), `mandate` (hash of the signed mandate + pseudonym), `revocation`.
- The user's devices fetch the entries for their pseudonym and alert on anything they did not produce (0002).
- **Independent witnesses** that co-sign tree heads make a split view (showing different logs to different parties) detectable. Not in the first release, but the tree-head format must allow cosignatures from the start.
- Build or adopt: an existing tile-based log implementation would save work but brings a second language and stack. Decision open (see below).

## Status lists

- IETF Token Status List, 1 bit per credential, at least 100,000 entries per list, indices allocated at random.
- Re-signed on every change and at least every few hours, with a `ttl` so verifiers know how long to cache.
- Revocation takes effect for verifiers within that `ttl`. The value is a trade-off between load and revocation speed, set per risk class (0005).

## Staging versus production

| | Staging | Production |
|---|---|---|
| Binary | Same CI release | Same CI release |
| Database | Own Postgres DB, may be reset | Own Postgres, PITR, backups |
| Keys | Software keys from a secret store, clearly marked as staging | HSM/KMS, root key offline |
| App Attest | Development and production environment | Production environment only |
| Trust list | Separate staging trust list; never contains production issuers | Production trust list |
| Data | Test devices only | Real users |

A staging credential must never be accepted by a production verifier. This is guaranteed by separate issuer identifiers, keys and trust lists, not by convention.

## Phases

| Phase | Content | Depends on |
|---|---|---|
| R1 | Enrollment challenge, App Attest verification, device registry | S1 results |
| R2 | Attested User Key credential (SD-JWT VC), issuer metadata, key hierarchy (software keys in staging) | `aap-sdjwt` (M1/M2, done) |
| R3 | Token Status List, revocation from devices | R2 |
| R4 | Transparency log, monitoring by the app | R2 |
| R5 | Relay + push, multiple devices, usage ledger | R3, R4, use-case catalogue (0005) |
| Gate | Production readiness: HSM in place, key ceremony done, fuzzing, external penetration test, backup restore drill, runbooks | R1–R4 |

The attack scenarios of 0005 that concern the registry become integration tests run against staging on every release.

## Open questions

1. **HSM or KMS** for production: a hardware HSM attached to our own server (e.g. YubiHSM, Nitrokey HSM) or a cloud KMS? This depends on where production runs.
2. **Hosting** for production and for a second, independent log operator.
3. **Request authentication:** HTTP Message Signatures (RFC 9421) or DPoP (RFC 9449)?
4. **Transparency log:** our own Rust implementation in the same stack, or an existing tile-based log?
5. **Code location:** a new crate in this public repository (reference implementation, auditable) with configuration and keys elsewhere, or a separate private repository? Recommendation: public, as `crates/issuer-service`.
6. **Domain names** for issuer, status lists and log (e.g. a dedicated subdomain), fixed before the first credential is issued, because they end up in credentials.
