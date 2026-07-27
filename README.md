# Agent Authority Protocol (working title)

A protocol for authenticated, authorized, and liability-attributable actions by AI agents — toward other agents, humans, software systems, and authorities.

An agent is not a legal subject. It always acts in the name of a **Principal** (a natural or legal person), under a cryptographically signed, scope-limited, revocable **Delegation**. Every verifier — another agent, an API, a bank, eventually an authority — checks that delegation deterministically, without trusting the agent's own claims and without an LLM in the trust path.

This is not an attempt to replace A2A, MCP, or OAuth. It's the piece those don't cover: a first-class **Authority + Liability layer** — provable answers to "who acted, under whose authority, within what limits, and who is accountable."

See [`spec/`](spec/) for the data model and [`docs/verification-flow.md`](docs/verification-flow.md) for the verification algorithm.

## Try it

```bash
cargo run -p aap-demo-cli
```

Runs a scripted end-to-end scenario: a Principal issues a Delegation, an in-scope request gets accepted, an over-the-ceiling request gets rejected, a replayed message gets rejected, and a revoked delegation gets rejected — all decided by [`crates/core/src/verifier.rs`](crates/core/src/verifier.rs), never by an LLM.

```bash
cargo test --workspace   # 23 tests: scope matching + full verification flow, incl. sub-delegation chains
```

The core crate (`aap-core`) uses a typestate pattern (`crates/core/src/token.rs`): an `Unverified` delegation or agent message and a `Verified` one are different Rust types. The only way to get a `Verified` token is a successful `verify_signature()` call — a function that grants authority cannot accept an unverified token, at compile time.

## Design decisions for v1

| Topic | v1 choice | Rationale |
|---|---|---|
| Signature format | JWT/JWS (RFC 7515) via `jose` | Don't reinvent crypto; verifiable in any language today |
| Delegation object | Custom JSON Schema, JWT-signed | Full VC/SD-JWT-VC machinery is overkill before the concept is proven |
| Revocation | Status endpoint (`{revoked: bool}`) + `valid_until` | IETF Token Status List is the real long-term answer; not worth building now |
| Scope check | Pure deterministic function, see [`spec/scope-matching.md`](spec/scope-matching.md) | This is the actual trust boundary — must never be "interpreted" |
| Key custody | Local keys in v1, behind a `Signer` interface | Swappable for KMS/HSM later without touching call sites |
| Registry | Centralized (JSON/SQLite), behind a `KeyResolver` interface | Swappable for DID resolution later without touching the verifier |
| Blockchain / DID | Not in v1 | Adds governance and complexity disproportionate to what a proof-of-concept needs |
| Chaining | Sub-delegation only when `can_delegate: true`; child scope must `narrow()` the parent | Prevents privilege escalation through delegation |

## Roadmap

- **Phase 0 — Spec** (current): Delegation schema, Scope language, verification flow, minimal message set. *Done in this pass; refine as Phase 1 surfaces gaps.*
- **Phase 1 — Minimal prototype**: principal/agent keypairs, issue + sign a Delegation, a Verifier that checks signature + time + revocation + scope, a runnable demo (two toy agents, one accepted action, one scope-violating action, one revoked-mid-flow action).
- **Phase 2 — Robustness**: sub-delegation chains, audit receipts, pluggable KMS-backed Signer, real centralized registry service (not just a JSON file).
- **Phase 3 — Opening up**: DID/VC-compatible resolver, mapping to A2A / OpenID AuthZEN / GNAP, public spec + reference implementation, legal/regulatory write-up (EU focus).

## Non-goals (for now)

- Becoming *the* standard — realistic goal is a credible, working reference that others can adopt pieces of, not winning a standards race against Microsoft/Google/OpenID.
- Natural language as an authoritative protocol layer — it may exist as a human-readable explanation, never as the thing a Verifier trusts.
