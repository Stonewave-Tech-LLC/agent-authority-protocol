# Design documents

Numbered design records for decisions that shape the protocol. Each one states its status, the problem, the decision (or the options, while it is still open), and what it deliberately leaves out.

| # | Title | Status |
|---|---|---|
| [0001](0001-positioning-ap2.md) | Positioning: AAP as a complement to AP2 | Draft |
| [0002](0002-trusted-surface-and-issuer.md) | Trusted Surface: proving the human approved | Draft |
| [0003](0003-verified-human-credential.md) | Verified Human Credential | Draft |
| [0004](0004-migration-sd-jwt-vc.md) | Migration to SD-JWT VC and the AP2 mandate model | Draft |
| [0005](0005-use-case-catalogue.md) | Use-case catalogue: risk classes, flows and attack scenarios | Draft |
| [0006](0006-registry-and-issuer-service.md) | Registry and Issuer Service (production design) | Draft |

Status values: **Draft** (under discussion, may change completely), **Accepted** (agreed, implementation may start), **Superseded** (replaced by a later record, linked).

Reading order: 0001 explains *why* the protocol is changing direction; 0002 and 0003 describe the two things AAP adds on top of AP2; 0004 is the concrete plan for the code in this repository; 0005 tests all of it against concrete use cases and attack scenarios and lists the gaps that remain; 0006 specifies the registry and Issuer Service to production standards.

The [November 2026 review](../review-2026-11.md) checks these drafts against the code and the landscape as of 2026-11-12. Its section 7 lists what it supersedes (notably 0001's landscape table) and proposes the next milestones.
