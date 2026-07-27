# Verification Flow (v1)

A Verifier is anything checking whether an incoming request is backed by real authority: another agent, an API, a piece of software, eventually a human-facing interface or an authority. Same algorithm regardless of who's asking.

## Inputs

- `agentMessage`: the request itself, JWS-signed by the Agent's private key. Payload includes the concrete action (see `scope-matching.md` request shape) plus a `nonce` and `audience` (see below).
- `delegation`: the JWT/JWS Delegation presented alongside the message (see `schemas/delegation.schema.json`).

## Steps

1. **Resolve the Principal's public key.** Via a `Resolver` (interface, not a concrete choice — v1 ships a centralized JSON/SQLite-backed resolver; a DID-based resolver can be swapped in later without touching anything below).
2. **Verify the Delegation's signature** against that public key. Reject if invalid.
3. **Verify the Agent message's signature** against `delegation.agent_public_key`. Reject if invalid.
4. **Check `audience` and `nonce`.** The signed request payload must name this specific Verifier as `audience` and carry a fresh `nonce`. Reject replays (nonce already seen) and reject requests aimed at a different audience presented here (confused-deputy protection — a valid signed request for Verifier A must not be accepted by Verifier B).
5. **Check time validity.** `valid_from <= now <= valid_until`. Reject otherwise.
6. **Check revocation status.** Call `delegation.status_endpoint` (or local cache with a short TTL). Reject if revoked or unreachable-and-policy-says-fail-closed.
7. **If `delegation.parent_delegation_id` is set (sub-delegation):** recursively verify the parent delegation (steps 1-6), and check `narrows(parentScope, delegation.scope)` (see `scope-matching.md`). Reject if the chain doesn't hold or exceeds `max_delegation_depth`.
8. **Check scope.** `matches(delegation.scope, requestedAction)`. Reject otherwise.
9. **Accept.** Optionally emit a `Receipt`/`AuditEvent` (signed record of what was checked and the outcome) for the audit trail.

Steps 4-8 are pure/deterministic — no model in the loop. Step 1 and 6 are the only I/O.

## Interfaces to keep swappable from day one

```ts
interface KeyResolver {
  resolvePrincipalKey(principalId: string): Promise<JWK>;
}

interface StatusChecker {
  isRevoked(delegationId: string, statusEndpoint: string): Promise<boolean>;
}

interface Signer {
  sign(payload: object): Promise<string>; // returns compact JWS
  publicJwk(): JWK;
}
```

`Signer` is what lets Key Custody evolve from "local key file" (v1) to KMS/HSM-backed without changing any caller. `KeyResolver` is what lets the Registry evolve from centralized JSON to DID resolution without changing the Verifier.
