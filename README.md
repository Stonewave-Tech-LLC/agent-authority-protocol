# Agent Authority Protocol (working title)

A protocol for authenticated, authorized, and liability-attributable actions by AI agents — toward other agents, humans, software systems, and authorities.

An agent is not a legal subject. It always acts in the name of a **Principal** (a natural or legal person), under a cryptographically signed, scope-limited, revocable **Delegation**. Every verifier — another agent, an API, a bank, eventually an authority — checks that delegation deterministically, without trusting the agent's own claims and without an LLM in the trust path.

This is not an attempt to replace A2A, MCP, or OAuth. It's the piece those don't cover: a first-class **Authority + Liability layer** — provable answers to "who acted, under whose authority, within what limits, and who is accountable."

See [`spec/`](spec/) for the data model and [`docs/verification-flow.md`](docs/verification-flow.md) for the verification algorithm.

## Try it

```bash
cargo run -p aap-demo-cli
```

Runs a scripted end-to-end scenario: a Principal issues a Delegation, an in-scope request gets accepted, an over-the-ceiling request gets rejected, a replayed message gets rejected, and a revoked delegation gets rejected — all decided by [`crates/core/src/verifier.rs`](crates/core/src/verifier.rs), never by an LLM. Every one of those decisions, accept or reject, also comes back as a signed [`Receipt`](crates/core/src/receipt.rs) — a durable, independently checkable record of what was decided and why.

```bash
cargo test --workspace   # 25 tests: scope matching, full verification flow, sub-delegation chains, receipts
```

The core crate (`aap-core`) is written in Rust rather than the originally-considered TypeScript specifically because of a compile-time guarantee TS's structural typing can't give: a typestate pattern (`crates/core/src/token.rs`) makes `Unverified` and `Verified` delegations/messages distinct Rust types. The only way to obtain a `Verified` token is a successful `verify_signature()` call — a function that grants authority cannot even compile if it accepts an unverified token.

## Design decisions for v1

| Topic | v1 choice | Rationale |
|---|---|---|
| Language | Rust, not TypeScript | Typestate pattern enforces "unverified data can't be treated as verified" at compile time — the exact bug class that matters most for a trust protocol |
| Signature format | Compact JWS (RFC 7515), hand-rolled over Ed25519 (`ed25519-dalek`) | Don't reinvent crypto, just the thin envelope; full control over the payload shape instead of fighting a claims-bag JWT library |
| Delegation object | Custom JSON Schema, JWT-signed | Full VC/SD-JWT-VC machinery is overkill before the concept is proven |
| Revocation | Status endpoint (`{revoked: bool}`) + `valid_until` | IETF Token Status List is the real long-term answer; not worth building now |
| Scope check | Pure deterministic function, see [`spec/scope-matching.md`](spec/scope-matching.md) | This is the actual trust boundary — must never be "interpreted" |
| Key custody | Local keys in v1, behind a `Signer` interface | Swappable for KMS/HSM later without touching call sites |
| Registry | Centralized (JSON/SQLite), behind a `KeyResolver` interface | Swappable for DID resolution later without touching the verifier |
| Blockchain / DID | Not in v1 | Adds governance and complexity disproportionate to what a proof-of-concept needs |
| Chaining | Sub-delegation only when `can_delegate: true`; child scope must `narrow()` the parent | Prevents privilege escalation through delegation |

## Roadmap

- **Phase 0 — Spec**: Delegation schema, Scope language, verification flow, minimal message set. ✅
- **Phase 1 — Minimal prototype**: principal/agent keypairs, issue + sign a Delegation, a Verifier that checks signature + time + revocation + scope, a runnable demo. ✅
- **Phase 2 — Robustness**: sub-delegation chains ✅, audit receipts ✅, pluggable KMS-backed Signer (still local-key only), real centralized registry service (still in-memory), Handoff/Escalate message types.
- **Phase 3 — Opening up**: DID/VC-compatible resolver, mapping to A2A / OpenID AuthZEN / GNAP, WASM bindings + browser demo, public spec + reference implementation, legal/regulatory write-up (EU focus).

## Non-goals (for now)

- Becoming *the* standard — realistic goal is a credible, working reference that others can adopt pieces of, not winning a standards race against Microsoft/Google/OpenID.
- Natural language as an authoritative protocol layer — it may exist as a human-readable explanation, never as the thing a Verifier trusts.
