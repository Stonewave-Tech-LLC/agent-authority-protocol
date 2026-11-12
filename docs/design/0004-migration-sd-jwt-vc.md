# 0004 — Migration to SD-JWT VC and the AP2 mandate model

- **Status:** Draft
- **Date:** 2026-10-18
- **Working position (draft, not decided):** aap-core moves from its own JWS envelope to SD-JWT (RFC 9901) with Delegate SD-JWT chains, using AP2's open/closed mandate structure and Mandate Receipts. AAP-specific semantics become constraint types and mandate types that plug into AP2's extension points. The four verifier bugs found in the v0 code are fixed in v0 first, because the v0 verifier-service is deployed.

## Goals

- A mandate chain that an AP2 verifier can parse with its existing SD-JWT stack.
- Every AAP rule (scope, chains, freshness, receipts) expressed through AP2 extension points, not by forking the format.
- The guarantees of v0 kept: deterministic evaluation, fail-closed defaults, and the Rust typestate rule that unverified data cannot reach authorization code.

Non-goals: implementing UCP/ACP checkout, OpenID4VP wallet flows in the core crate (that belongs in the Issuer App, 0002), BBS signatures (0003, v2).

## Target token shape

A presentation is one Delegate SD-JWT chain (compact serialization, see the Delegate SD-JWT draft):

```
<User credential: SD-JWT VC>~<disclosures>~                 iss = Issuer Service, cnf = user's hardware key   (0002/0003)
 ~<KB-SD-JWT+KB, signed by user key>~<disclosures>~          open mandate: constraints, cnf = agent key, exp, status
 ~<KB-SD-JWT+KB, signed by agent key>~<disclosures>~         optional sub-delegation: constraints, cnf = sub-agent key
 ~<KB-SD-JWT, signed by the leaf agent key>~<disclosures>~   closed mandate: the concrete action, aud, nonce, iat, sd_hash
```

- The **root** is whichever user credential the verifier requests: the Attested User Key credential (AL2) or the Verified Human Credential (AL3). Both are bound to the same hardware key.
- The **principal** is never a self-asserted string any more. It is the root credential: issuer, user key, and, at AL3, the per-verifier pseudonym.
- For payments, the open and closed mandates are AP2's own (`mandate.checkout.*`, `mandate.payment.*`). For everything else, AAP defines its own mandate types (below).

## Mapping from v0

| v0 (`types.rs`) | v1 |
|---|---|
| `Delegation` (root, principal-signed JWS) | Open mandate in a KB-SD-JWT+KB signed by the user key |
| `Delegation.principal_id`, `principal_type` | Derived from the root credential; **not repeated in any link** |
| `Delegation.agent_id`, `agent_public_key` | `cnf` of the open mandate (agent identity: optional `aap.agent` claim, informational only) |
| `valid_from` / `valid_until` | `nbf` / `exp` of each link |
| `status_endpoint` | `status` claim: reference into an IETF Token Status List |
| `can_delegate`, `max_delegation_depth` | Constraint `aap.delegation { max_depth }`; **absent means no further delegation** |
| `parent_delegation_id` | Implicit: each link is cryptographically bound to the previous one via `sd_hash` |
| `Scope.actions` | Constraint `aap.actions { allowed: [...] }` |
| `Scope.resources` | Constraint `aap.resources { allowed: [...] }` |
| `Scope.max_amount` | Payments: AP2 `payment.amount_range`. Otherwise: `aap.amount { max, currency }` |
| `Scope.counterparties` | Payments: AP2 `payment.allowed_payees`. Otherwise: `aap.counterparties { allow, deny }` |
| `Scope.data_categories` | Constraint `aap.data_categories { allowed: [...] }` |
| `Scope.time_windows` | Constraint `aap.time_windows { windows: [...] }` |
| `metadata` | `aap.note`, non-authoritative, rendered as "the agent says" (0002) |
| `AgentMessage.request` | Closed mandate content `aap.action.1 { action, resource?, amount?, counterparty?, data_categories? }` |
| `AgentMessage.audience`, `nonce`, `issued_at` | `aud`, `nonce`, `iat` of the final key binding |
| `Receipt` | AP2 Mandate Receipt (`iss`, `result`, `reference`, `error`, `error_description`) plus optional `aap_chain` (hashes of all links) |

Names are written `aap.*` here for readability. The final names depend on the namespace decision in 0001 (e.g. `com.stonewavetech.aap.actions`).

All values that are lists of identifiers (allowed actions, resources, payees) are individually selectively disclosable, like AP2's `allowed_merchants`: a verifier learns that *its* resource is allowed, not which others are.

## Verification semantics

1. Split and verify the chain per Delegate SD-JWT: root against the issuer's key, each link against the previous link's `cnf`, `sd_hash` / `issuer_jwt_hash` binding in both directions, `typ` checked per position (`dc+sd-jwt`, `kb-sd-jwt+kb`, `kb+sd-jwt`).
2. For every link: `nbf <= now <= exp` against the **verifier's** clock, and its status in the status list (fail closed if the list cannot be fetched and no fresh cached copy exists).
3. Chain length against every ancestor's `aap.delegation.max_depth`. A link without `aap.delegation` may not be followed by another open mandate.
4. **Cumulative constraint evaluation:** the closed mandate must satisfy the constraints of **every** link in the chain, not only the leaf. Unknown constraint types fail.
5. Freshness of the final key binding: `iat` within a window (proposed: 5 minutes back, 30 seconds forward), `aud` equal to this verifier, `nonce` either the verifier's own challenge or, for non-interactive APIs, unseen within the freshness window.
6. Issue a Mandate Receipt for every outcome, accept and reject alike.

Point 4 is a deliberate change from v0. v0 checks `narrows(parent, child)` and then evaluates only the leaf scope. If `narrows` has a bug, a child can widen its parent. With cumulative evaluation, widening is impossible no matter what the child claims, because the parent's constraints are still checked. `narrows` remains useful at **issuance** (the Issuer App and agents reject impossible sub-delegations early), but it is no longer part of the security argument. This is AAP's proposed contribution for agent-to-agent delegation (0001, gap G5).

## How the four v0 bugs are resolved

| v0 bug | v1 | Fix in v0 now |
|---|---|---|
| Time windows checked against the agent's own `request.timestamp` | `aap.time_windows` is defined against the verifier's evaluation time; the closed mandate carries no timestamp used for authorization | `scope::matches` takes the verifier's `now`; `request.timestamp` becomes informational |
| Negative amounts pass any ceiling | Amounts are **integer minor units** with ISO 4217 currency; negative values are a schema error | Reject `value < 0` and non-finite values in `matches` and `narrows` |
| Message `issued_at` never checked, nonce store grows forever | Key-binding `iat` window (step 5); nonces expire with the window | Same window in the v0 verifier; `expires_at` on `aap_nonces` plus cleanup |
| Sub-delegation can rewrite `principal_id` | Principal exists only in the root credential | Reject chains whose links differ in `principal_id` / `principal_type`, or whose child outlives its parent |

The v0 fixes come first (phase M0) because `aap-verifier-service` is deployed and used by device pairing.

## Cryptography and format rules

- **ES256 is mandatory to implement.** It is the only algorithm phone secure hardware supports, and AP2 uses it. EdDSA stays allowed for server-held keys (e.g. receipt signing).
- **Low-S is not required.** Secure Enclave signatures are not normalised; S1 measured about 40% high-S signatures on a real iPhone. RFC 7518 does not require low-S, and a verifier that enforces it would reject them.
- **The algorithm is pinned per key**, exactly as in v0 (`jws.rs`): the `alg` header must match the key's own algorithm before any signature check.
- **`typ` is checked per position.** This also fixes a v0 weakness where delegations, messages and receipts all used `typ: JWT` and were distinguished only by their structure.
- **Salts of at least 128 bits** in every disclosure (RFC 9901), decoy digests optional.
- **Amounts:** integer minor units everywhere. AP2's own examples are inconsistent on this (one uses minor units, another decimal major units); AAP raises this upstream and accepts only integers.

## Implementation

**Library choice.** Several Rust crates implement RFC 9901 SD-JWT (e.g. `sd-jwt-payload`, `sd-jwt-rs`, `sdjwt`). None implements Delegate SD-JWT, which is an individual draft. Recommendation: a small, own implementation in a separate crate, in line with v0's hand-rolled JWS. SD-JWT is salted hashes plus JWS, and keeping the trust path small and auditable matters more than saving a few hundred lines. One maintained crate serves as a cross-check in tests.

**Crate layout:**

| Crate | Content |
|---|---|
| `aap-sdjwt` (new) | SD-JWT, key binding, Delegate SD-JWT chains: parsing, signing, verification. Format only, no policy. Typestate: `Unverified<Chain>` → `VerifiedChain` |
| `aap-core` | Constraint types and evaluators, `narrows` for issuance, the verifier, Mandate Receipts. Only accepts `VerifiedChain` |
| `aap-ap2` (new) | AP2 checkout/payment mandate types and constraint evaluators |
| `aap-verifier-service` | v0 and v1 endpoints side by side during migration |
| `aap-wasm-demo`, `aap-demo-cli` | Updated to v1 |
| `aap-admin` | Stays as the AL0 tool (0002) |

**Tests**, in this order of importance:

1. RFC 9901 and Delegate SD-JWT example vectors.
2. The example tokens from the AP2 specification.
3. **Interop with the AP2 reference SDK** (Python) in CI: mandates issued by the AP2 SDK verified by aap-core and vice versa.
4. Property tests for every constraint type: cumulative evaluation never accepts something a single link's constraints reject; `narrows(p, c)` implies "everything `c` accepts, `p` accepts".
5. Negative tests per threat in 0002 and 0003: each documented attack becomes a test that must fail.

## Phases

| Phase | Content | Done when |
|---|---|---|
| **M0** | Fix the four bugs in v0; regression tests; release a new `verifier-v*` | Probe tests from the analysis are inverted and pass; new release deployed |
| **M1** | `aap-sdjwt`: SD-JWT + key binding | RFC 9901 vectors pass; cross-check crate agrees |
| **M2** | Delegate SD-JWT chains | Draft examples pass; chain-binding negative tests |
| **M3** | AAP constraint types, cumulative evaluation, Mandate Receipts, `aap-ap2` | AP2 example tokens verify; interop test with the AP2 SDK green |
| **M4** | v1 endpoints in the verifier-service, Token Status List, migration of existing device-pairing flows | A pairing flow runs on v1 in staging |
| **M5** | Remove v0 types and endpoints | No v0 traffic for an agreed period |

M1–M3 do not depend on the Issuer App (0002). Tests can use software keys at AL0, so the core can be finished while the app is being built.

## Open questions

1. **Namespace** for `vct` and constraint types (see 0001).
2. **Nonce model:** require a verifier-issued challenge everywhere (one extra round trip, strongest), or allow agent-generated nonces for non-interactive APIs?
3. **Status mechanism:** go straight to IETF Token Status List, or keep a simple status endpoint for v1?
4. **v0 sunset:** how long do v0 endpoints stay after M4?
5. **Closed mandate for non-payment actions:** is `aap.action.1` one generic type, or one type per domain (messaging, data access, bookings) as the use-case catalogue grows?
