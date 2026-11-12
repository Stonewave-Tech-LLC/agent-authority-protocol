# 0001 — Positioning: AAP as a complement to AP2

- **Status:** Draft
- **Date:** 2026-10-18
- **Working position (draft, not decided):** AAP stops being a standalone mandate format and becomes a set of components that plug into the AP2 agent-authorization model, filling the gaps AP2 explicitly leaves open.

## Context

When AAP started, there was no published model for "an agent proves it acts within limits a human signed". That has changed. As of October 2026 the landscape looks like this (sources at the end; everything marked *primary* was read in the specification itself):

| Effort | Who | State | What it covers |
|---|---|---|---|
| **AP2** (Agent Payments Protocol) v0.2 | Google; spec work moving to the FIDO Alliance | v0.2 released 2026-04-28 (*primary*) | User-signed **open mandates** with constraints and an agent key (`cnf`), agent-signed **closed mandates**, verifier-signed **receipts**, dispute evidence. Payments and checkout only. |
| **Delegate SD-JWT** | Individual IETF draft (Google author) | Draft, last change 2026-09 (*primary*) | The chaining format AP2 builds on: a KB-JWT that is itself an SD-JWT, so each holder can delegate further. |
| **UCP** (Universal Commerce Protocol) | Google + retailers | Announced 2026-01 | Discovery, cart, checkout. AP2 is designed to run inside it. |
| **ACP** (Agentic Commerce Protocol) | OpenAI + Stripe | Spec 2026-04-17, beta (*primary*) | Checkout API, delegated payment *vault tokens* with an allowance (one-time, max amount, merchant, expiry), delegated 3DS. **No user-signed artifact**: the platform is trusted. OpenAI moved Instant Checkout away from in-chat checkout in March 2026 and now emphasises discovery. |
| **Visa Trusted Agent Protocol, Mastercard Agent Pay, Web Bot Auth** | Card networks, Cloudflare | Live since 2025 | HTTP Message Signatures that identify the **agent / platform**, with keys in network-run directories. Consumer consent is not represented cryptographically. |

### AP2 already covers most of AAP's v0 data model

| AAP v0 (this repo today) | AP2 v0.2 equivalent |
|---|---|
| `Delegation` signed by the Principal | Open mandate (`mandate.*.open.1`) approved on a Trusted Surface |
| `Delegation.agent_public_key` | `cnf` claim (RFC 7800) in the open mandate |
| `Scope` | `constraints` array, extensible by `type` |
| `AgentMessage` | Closed mandate, signed with the `cnf` key (Key Binding) |
| Sub-delegation chain | Delegate SD-JWT chain (format exists; AP2 declares agent-to-agent delegation out of scope) |
| `Receipt` | Mandate Receipt (verifier-signed JWT with `result` and `reference`) |
| Selective privacy | Selective disclosure (SD-JWT) — AAP has nothing comparable |

Building a competing envelope for the same model would split a young ecosystem and lose against a FIDO-backed spec. The value is elsewhere.

## What AP2 leaves open

These gaps are stated or implied by the AP2 and Delegate SD-JWT texts themselves:

| # | Gap | Evidence |
|---|---|---|
| G1 | **Who proves the Trusted Surface really got the human's consent.** AP2 offers two trust models: trust the *Agent Provider* (it must keep its signing key away from the agent — a MUST with no way for a verifier to check it), or trust the issuer of a *User Credential* such as a payment card credential. A directly trusted, hardware-attested user key is named only as a possible future model. | `agent_authorization.md`, "Mandate Delegation" |
| G2 | **Human identity and uniqueness.** Nothing lets a merchant know it is dealing with one real person, or check an attribute like age, without full identity. | Not addressed |
| G3 | **Revocation of delegated mandates.** Delegate SD-JWT notes that a holder cannot easily distribute revocation information; the mitigation is a short `exp`. | Delegate SD-JWT, "Revocation" |
| G4 | **State across verifiers.** `payment.budget` and `payment.agent_recurrence` require tracking previous presentations, but no party is defined that can see presentations to *different* verifiers. Double-spend prevention relies on the agent not signing overlapping closed mandates. | `payment_mandate.md`, `security_and_privacy_considerations.md` |
| G5 | **Narrowing rules for agent-to-agent delegation.** The chain format exists; what a child may and may not do relative to its parent is undefined. | AP2 spec, "Agent-to-Agent Delegation"; Delegate SD-JWT, "Delegation Policy" |
| G6 | **Domains other than payments.** The authorization model is described as reusable "in the future"; only payment and checkout mandate types exist. | `agent_authorization.md`, introduction |
| G7 | **Dispute evidence retention and retrieval.** Out of scope. | AP2 spec, "Dispute Evidence" |

## Decision

AAP becomes **the trust layer underneath and around AP2**, not a parallel protocol:

```
 Discovery / checkout      UCP, ACP                         (not AAP)
 Agent identity (bot)      Web Bot Auth, Visa TAP           (not AAP, interop only)
 Payment mandates          AP2 checkout + payment mandates  (use as-is)
 ───────────────────────────────────────────────────────────────────────
 AAP adds:
   A1  Trusted Surface profile + Issuer App      → closes G1     (0002)
   A2  Verified Human Credential                 → closes G2     (0003)
   A3  Issuer Service: status, usage ledger,     → closes G3, G4, G7 (0002)
       transparency log, evidence store
   A4  Chain narrowing rules                     → closes G5     (0004)
   A5  Authority mandates for non-payment use    → closes G6     (0004)
```

Concretely:

- **A1** is a profile of AP2's *User Credential* model in which the "User Credential" is an attested hardware key held by a dedicated Issuer App. A verifier no longer has to trust an agent provider's promise; it checks an attestation chain.
- **A2** is an SD-JWT VC that an AP2 verifier can request like any other User Credential (OpenID4VP / DCQL), revealing only what it needs: "verified unique human", "over 18", a per-verifier pseudonym.
- **A3** is optional infrastructure. Verifiers that need revocation or cross-merchant budgets can use it; AP2 flows without it keep working.
- **A4 and A5** use AP2's own extension points (new constraint `type`s, new mandate `vct`s), so an AP2 verifier library can process AAP mandates by adding constraint evaluators instead of a new stack.

### What this repository stops doing

- Its own JWS envelope for delegations and messages → SD-JWT + Delegate SD-JWT.
- Its own `Receipt` format → AP2 Mandate Receipt, plus a few optional AAP claims.
- Its own scope language for **payments** → AP2 payment constraints. AAP constraints remain for everything AP2 does not define (actions, resources, data categories, time windows).

What it keeps: deterministic evaluation, the typestate guarantee in Rust, fail-closed defaults, and the test-first approach. These carry over unchanged.

### Non-goals

- Discovery, carts and checkout APIs (UCP/ACP do this).
- Identifying the agent software itself (Web Bot Auth does this; AAP mandates bind the agent's key, and that is enough).
- Replacing card-network liability rules. AAP produces evidence; who pays in a dispute stays with the payment rails.

## Risks

- **AP2 is v0.2 and moving.** The FIDO handover may change it. Mitigation: track the spec, keep AAP components behind AP2's extension points, run interop tests against the AP2 reference SDK.
- **Delegate SD-JWT is an individual draft**, not a working-group document yet. It may change or be replaced.
- **AP2 is inconsistent on amounts**: the payment mandate example uses integer minor units, while the `payment.amount_range` example uses decimal major units. AAP will use integer minor units everywhere and raise this upstream.
- **Positioning as a complement means depending on someone else's roadmap.** The upside is reach: a merchant that implements AP2 can accept AAP-backed mandates with little extra work.

## Open questions

1. **Upstream engagement.** Contribute A1/A4 to the FIDO AP2 work as proposals, or first ship them as a published AAP profile and propose later?
2. **Naming.** AP2 recommends collision-resistant `vct` and constraint names (reverse DNS or URN). Candidate: `com.stonewavetech.aap.*`. The JSON schemas in `spec/` currently use `agent-authority-protocol.org` as their `$id`. Is that domain registered by us?
3. **Scope of the first release.** Payments only (to prove interop with AP2) or one non-payment domain from the start?

## Sources

Primary (read in the original repositories, 2026-10-18):

- AP2 specification v0.2, agent authorization, mandates, security considerations: [google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2) (`docs/ap2/*.md`, `CHANGELOG.md`, `docs/faq.md` for the FIDO handover)
- Delegate SD-JWT draft: [GarethCOliver/gco-delegate-sd-jwt](https://github.com/GarethCOliver/gco-delegate-sd-jwt)
- ACP specification 2026-04-17, delegate payment and delegate authentication RFCs: [agentic-commerce-protocol/agentic-commerce-protocol](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)
- SD-JWT: [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/)

Secondary:

- [Google: Announcing AP2](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)
- [Stripe: Instant Checkout and ACP](https://stripe.com/newsroom/news/stripe-openai-instant-checkout)
- [Digital Commerce 360: OpenAI shifts checkout plans (2026-03-06)](https://www.digitalcommerce360.com/2026/03/06/openai-shifts-checkout-plans-agentic-commerce-strategy/)
- [InfoQ: Google UCP (2026-01)](https://www.infoq.com/news/2026/01/google-ucp)
- [Cloudflare: Securing agentic commerce with Visa and Mastercard](https://blog.cloudflare.com/secure-agentic-commerce/)
