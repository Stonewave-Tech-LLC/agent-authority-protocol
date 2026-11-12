# 0005 — Use-case catalogue: risk classes, flows and attack scenarios

- **Status:** Draft
- **Date:** 2026-10-18
- **Working position (draft, not decided):** Every action an agent can take falls into one of five risk classes (R0–R4). The class is **computed** from the mandate content by a fixed function, never claimed by the agent. It decides the minimum assurance level, whether a standing mandate is allowed at all, how fresh revocation status must be, and how much friction the Issuer App adds. Nineteen use cases are run through this model; each attack scenario has a stable ID (`UCnn-Am`) and becomes a negative test once the design covers it.

## Purpose

0002–0004 describe the building blocks: the Trusted Surface and Issuer App, the Verified Human Credential (VHC), and the SD-JWT / Delegate SD-JWT token shape. Building blocks say nothing about whether the system as a whole is safe for *buying wine*, *paying a new landlord* or *letting one agent hand work to another*. This catalogue does three things:

1. Defines **risk classes** so that verifiers, the Issuer App and agents agree on what a given action requires, with few rules and no per-merchant negotiation.
2. Walks through **universal use cases** — flows, signatures, checks and constraints — to find where the building blocks do not fit together.
3. Lists **attack scenarios** per use case with the expected defence, so the threat model of 0002 turns into a test list for 0004's phase M3 onwards.

The gaps it reveals are collected at the end (CG1–CG18). Most are small: a missing constraint type, a rule that is implied but not written down. A few change 0002–0004 noticeably (CG2, CG3, CG4, CG12).

## Conventions

| Short | Meaning |
|---|---|
| **User** | The human principal, approving on the Issuer App (0002) |
| **U-signs** | Signed by the user's hardware key in the Issuer App, after biometric/PIN and deterministic rendering (0002, "What you see is what you sign") |
| **A-signs** | Signed by an agent's `cnf` key |
| **IS** | Issuer Service: relay, status list, transparency log, usage ledger, evidence store (0002) |
| **V** | Verifier: merchant, bank, data holder, API, another agent |
| **CP** | The AP2 Credential Provider / payment service that executes a payment and checks payment mandates |
| **Issue(…)** | Steps 1–5 of "Issuing a mandate" in 0002 |
| **V1–V6** | Steps 1–6 of "Verification semantics" in 0004 (chain, time and status, depth, cumulative constraints, freshness, receipt) |
| **U-closed** | A per-action mandate whose concrete action is U-signed directly and only forwarded by the agent (proposed in CG2) |

**Mandate types.** AP2 types follow the pattern from 0001: `mandate.checkout.open.1`, `mandate.checkout.closed.1`, `mandate.payment.open.1`, `mandate.payment.closed.1`. For non-payment domains this document uses `aap.authority.open.1` for the open mandate and `aap.action.1` (0004) for the closed one. Both names are placeholders until the namespace decision (0001, open question 2).

**Constraint names.** AP2 constraints are the ones quoted in 0001 and 0004 (`payment.amount_range`, `payment.allowed_payees`, `payment.budget`, `payment.agent_recurrence`, `allowed_merchants`). Names marked † are assumptions about AP2 v0.2 that must be checked against the specification before M3. AAP constraints from 0004 are used as defined there; new ones proposed here are listed in CG6.

**Coverage labels** in the attack tables:

| Label | Meaning |
|---|---|
| **Covered** | Defeated by 0002–0004 as written |
| **Covered\*** | Defeated by a rule this document adds (risk-class rules below); needs to be written into 0002/0004 |
| **Partial** | Bounded or detectable, but not prevented; the remaining risk is named |
| **Gap (CGn)** | Not covered; the gap is described at the end |
| **Residual** | Not solvable by a protocol; accepted and stated openly |
| **Deferred** | Belongs to a part of the design that is out of scope for now |

### Additional attackers

0002 defines T1–T7. The use cases need three more, proposed as additions to 0002's threat model:

| ID | Attacker | Capabilities |
|---|---|---|
| T8 | Malicious verifier / merchant | Receives presentations legitimately; may overcharge, forward presentations elsewhere, request more disclosures than needed, ignore cancellations, issue false receipts |
| T9 | Malicious content source | Web pages, emails, invoices, calendar invites, documents read by the agent. The usual way an honest agent becomes T1 (prompt injection) |
| T10 | Dishonest user | Approves and later denies ("my agent did it"), friendly fraud, claims a mandate was misrendered |

## Design principles

Walking through the use cases converged on eight rules. They are what keeps the system strict without making every use case special.

- **P1 — Constraints protect only where an honest verifier checks them.** A malicious merchant (T8) checks nothing. So every constraint must be enforced by a party with an interest in enforcing it: payment constraints by the CP, data constraints by the data holder, message limits by the sending provider. Each use case below names its enforcing verifier.
- **P2 — Escalate, never split.** An action beyond a standing mandate needs a new mandate, never two smaller actions. Every standing mandate that moves value therefore carries both a per-action ceiling *and* a period budget.
- **P3 — First contact escalates.** A new payee, a new data recipient, a new delivery address is approved per action. Repeat contact with an already approved counterparty can run under a standing mandate.
- **P4 — The class is computed, never claimed.** The Issuer App and the verifier compute it from the content with the same function. An agent cannot lower it.
- **P5 — At R3 and above the human's signature is the declaration.** The agent prepares and transports; it never signs the binding statement itself.
- **P6 — Facts come signed by whoever asserts them.** Item descriptions, payee-name checks, contract terms are shown to the user as statements of the merchant, bank or provider, signed by them, not as agent text.
- **P7 — A shared budget lives in exactly one place.** The CP when there is one payment instrument, otherwise the usage ledger named in the mandate. Never "each verifier counts for itself".
- **P8 — Revocation stops the future; evidence covers the past.** Nothing undoes an executed action. Mandates, receipts and the log make it disputable.

## Risk classes

### The classes

| Class | Name | Typical actions |
|---|---|---|
| **R0** | Informational | Read public or non-sensitive data: product search, price quotes, free/busy |
| **R1** | Low impact, reversible | Small purchases, reading one's own financial data, messages to known contacts, calendar changes, cancellations |
| **R2** | Moderate | Recurring spending, payments to known payees, sign-ups with a commitment, bookings, messages to new recipients, repeat data sharing with an approved recipient |
| **R3** | High or hard to reverse | Payments above the R2 ceiling, any value to a new payee, special-category data (GDPR Art. 9) to a new recipient, legally relevant declarations (claims), changes of standing payment arrangements |
| **R4** | Binding or irreversible, high value | Consumer credit, contracts with long commitment, payments above the R3 ceiling, declarations to authorities |

### Requirements per class

| | R0 | R1 | R2 | R3 | R4 |
|---|---|---|---|---|---|
| Minimum assurance level (0002) | AL1 | AL2 | AL2 | AL3 | AL3 (an eID-backed level later) |
| Mandate kind | Standing | Standing | Standing, bounded (P2) | **Per-action only** (U-closed) | **Per-action only**, with re-confirmation |
| Max lifetime of a standing mandate | 1 year | 90 days | 30 days | — (per-action `exp` ≤ 24 h, single use) | — (as R3) |
| Verified Human Credential | No | Only if the verifier needs an attribute | Only if the verifier needs an attribute | Required | Required, `chip_auth` ≠ `none` |
| Status freshness at the verifier | Cache ≤ 24 h | Cache ≤ 1 h | Cache ≤ 5 min | Online check | Online check |
| Transparency-log inclusion proof | No | No | Required | Required | Required |
| Nonce (0004, open question 2) | Agent nonce allowed | Agent nonce allowed | Verifier challenge when interactive, agent nonce otherwise | Verifier challenge, bound into the U-signed content | As R3 |
| Use reporting to the user (CG3) | No | Daily digest | Per use | Per use | Per use |
| Friction in the Issuer App | None | None | Diff on renewal or extension; warning on first mandate for a counterparty | Full rendering, approve-button delay, no batch approvals; cooling-off for first-time counterparties (CG12) | As R3, plus a second confirmation at least 1 h later or on a second enrolled device |
| Revocation expectation | Effective within 24 h | Within 1 h | Within 5 min | Until execution: immediate (also cancels during cooling-off) | As R3, plus legal withdrawal rights where they exist |

Attribute requirements are **orthogonal** to the class. Buying wine is an R2 action that also needs `age_over_18`; buying tickets limited to one per person is an R2 action that also needs a pseudonym. Requesting an attribute forces an AL3 root (only a VHC carries attributes) but does not turn a standing mandate into a per-action one. 0002's table of assurance levels lists "age-restricted goods" as AL3 typical use, which is correct for the key but should not be read as "per action".

### How a class is assigned

`risk_class(content, context) → R0..R4` is a pure function, specified like `matches` in `spec/scope-matching.md`, implemented once in aap-core and compiled into both the Issuer App and the verifier library (CG1).

1. **Base class from the action.** Each entry in the action vocabulary (CG11) has a base class: reads of non-sensitive data R0, reads of personal or financial data R1, reversible writes R1, declarations R3, contracts and credit R4.
2. **Amount tier.** For value-moving actions, the class follows the amount per action and the period budget, with these defaults:

   | | per action | per month |
   |---|---|---|
   | R1 | ≤ €50 | ≤ €150 |
   | R2 | ≤ €500 | ≤ €1 500 |
   | R3 | ≤ €5 000 | — |
   | R4 | > €5 000 | — |

   For a **commitment** (subscription, instalments, standing order, contract) the amount is the total over the minimum term, or over 12 months if open-ended. A €0 trial that converts to €29.99/month is a €360 commitment, i.e. R2.
3. **Escalators.** Value to a counterparty not yet approved by the user → at least R3 (P3). Special-category data to a recipient not yet approved → at least R3. A term longer than 12 months, or credit → R4.
4. **Standing mandates** take the class of the most dangerous action their constraints permit. A standing mandate that computes to R3 or above is **not signable**; the Issuer App refuses it, like an unknown constraint.
5. **Tightening only.** The user can lower the thresholds for themselves ("everything above €200 is R3"). A verifier can raise the class it requires for its own actions. Nobody can lower the defaults for someone else. A verifier that requires more than the presented mandate kind allows rejects with a receipt `error: insufficient_mandate` and the agent escalates (P2).

The thresholds are proposals for discussion. They sit in the same order of magnitude as PSD2's exemptions from strong customer authentication for low-value remote payments, so R1 stays below where a bank would normally ask for SCA anyway.

## Use cases

| # | Use case | Domain | Class |
|---|---|---|---|
| UC01 | Small one-off basket | Commerce | R1 |
| UC02 | Recurring groceries | Commerce | R2 |
| UC03 | High-value electronics | Commerce | R3 |
| UC04 | Age-restricted goods | Commerce | R2 + age |
| UC05 | Limited quantity, one per person | Commerce | R2 + uniqueness |
| UC06 | Travel booking | Travel | R2 / R3 |
| UC07 | Subscriptions: sign-up and cancellation | Subscriptions | R2 / R1 |
| UC08 | Bank account read | Banking | R1 |
| UC09 | Transfer to a known payee | Banking | R2 |
| UC10 | Transfer to a new payee | Banking | R3 |
| UC11 | Standing orders and recurring bills | Banking | R3 setup / R2 runs |
| UC12 | Insurance claim | Insurance | R3 |
| UC13 | Messages and email on the user's behalf | Communication | R1 / R2 |
| UC14 | Calendar and scheduling between agents | Communication | R0 / R1 |
| UC15 | Sharing health data | Personal data | R3 first / R2 repeat |
| UC16 | Agent-to-agent sub-delegation | Delegation | inherits |
| UC17 | B2B procurement for a legal entity | Procurement | R2 / R3 |
| UC18 | Binding long-term contract | Contracts | R4 |
| UC19 | Interaction with an authority | Government | R4, **deferred** |

---

### UC01 — Small one-off basket

*"Buy these headphones, under €50, today."*

| | |
|---|---|
| Class | R1 · AL2 · standing mandate, single use |
| Actors | User, shopping agent, merchant S (checkout verifier), CP (payment verifier), IS |
| AP2 types | `mandate.checkout.open.1`, `mandate.payment.open.1`, both closed mandates A-signed |
| AAP types | `aap.rate { max_count: 1 }` (CG6a) on the open mandates |
| Required constraints | `allowed_merchants: [S]`; `payment.amount_range {max: 5000, currency: EUR}`; `payment.allowed_payees: [S]`; `exp` ≤ 24 h |
| Enforcing verifier (P1) | CP for amount and payee; S for checkout content |

**Flow**

1. The agent builds the cart at S (total €34.90) and sends a DelegationRequest with the two open mandates. Issue(…): the Issuer App renders "one purchase at S, up to €50.00, until tomorrow 18:00", the user approves, **U-signs** both open mandates (`cnf` = agent key).
2. The agent completes checkout: **A-signs** the closed checkout mandate (cart hash, total 3490 EUR) with `aud` = S and the closed payment mandate with `aud` = CP.
3. S runs V1–V6 on the checkout chain (status cache ≤ 1 h); CP runs V1–V6 on the payment chain and executes the payment.
4. S and CP return Mandate Receipts. The receipt hashes go to the IS use log (CG3) and appear in the user's daily digest.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC01-A1 | Prompt injection on a product page (T9) steers the agent to a look-alike shop S′ that accepts anything (T8) | S′ checks nothing, but the CP refuses: S′ is not in `payment.allowed_payees`. No money moves. Fails if the agent holds raw card data outside AAP | Covered |
| UC01-A2 | S replays the closed payment mandate to charge twice | `nonce` + `iat` window at the CP; `aap.rate {max_count: 1}` counted by the CP | Covered (nonce); count needs CG6a |
| UC01-A3 | S charges €49.00 instead of the agreed €34.90 (still under the ceiling) | The closed mandates are A-signed over the exact total; a different amount breaks the signature | Covered |
| UC01-A4 | The agent reuses the 24 h mandate for a second basket | `aap.rate {max_count: 1}`; today only `exp` limits it | Gap (CG6a) |

---

### UC02 — Recurring groceries

*"Do the weekly shop at A, B or C, up to €80 per order and €320 a month."*

| | |
|---|---|
| Class | R2 · AL2 · standing mandate, 30 days |
| Actors | User, agent, shops A/B/C (checkout verifiers), CP, IS (ledger if more than one instrument) |
| AP2 types | `mandate.checkout.open.1`, `mandate.payment.open.1`; closed mandates A-signed per order |
| AAP types | `aap.product_categories { deny: [alcohol, tobacco] }` (CG6b) |
| Required constraints | `allowed_merchants: [A, B, C]`; `payment.amount_range {max: 8000, currency: EUR}`; `payment.budget {max: 32000, currency: EUR, period: month}`; `payment.agent_recurrence`† (weekly); delivery address in the checkout content†; `exp` 30 days |
| Enforcing verifier | CP for amount, budget and recurrence (it sees every payment with the one instrument); each shop for categories |

**Flow**

1. Issue(…) once. The Issuer App shows the budget, the shops, the excluded categories and the end date. **U-signs**.
2. Weekly: the agent **A-signs** closed checkout and payment mandates; the shop and the CP run V1–V6 (status ≤ 5 min, inclusion proof required at R2).
3. Each use is reported to the user (CG3).
4. On day 30 the agent requests a renewal. The Issuer App shows a diff to the previous mandate *and* the spending over the last period before the user signs again.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC02-A1 | Budget exhaustion across verifiers: €80 orders at A, B and C in the same week, each fine locally | `payment.budget` at the CP, which sees all three payments. If the mandate allows several instruments or CPs, nobody sees the total | Covered for one instrument; otherwise Gap (CG4) |
| UC02-A2 | Stale mandate: the user is on holiday, the agent keeps ordering to the home address | 30-day lifetime; per-use reporting; delivery address in the U-signed content | Partial: depends on AP2 carrying the address† |
| UC02-A3 | Category smuggling: an injected recipe (T9) makes the agent add wine | `aap.product_categories` deny, enforced by the shop on its own line-item classification | Gap (CG6b) |
| UC02-A4 | "Agent tax": a shop quietly raises prices for agent orders, still within budget | Not a protocol violation. Per-use reporting makes it visible | Residual |

---

### UC03 — High-value electronics

*"Buy this laptop for €1 299."*

| | |
|---|---|
| Class | R3 · AL3 · per-action (U-closed) |
| Actors | User, agent, merchant S, CP, IS |
| AP2 types | `mandate.checkout.closed.1`, `mandate.payment.closed.1`, **U-signed** (human present) |
| AAP types | none beyond the class rules |
| Required constraints | The concrete action itself: item identifiers, total, merchant, delivery address, S's challenge nonce, `aud`, `exp` ≤ 24 h |
| Enforcing verifier | S and CP |

**Flow**

1. The agent obtains a checkout offer from S, ideally a merchant-signed cart† (P6), and a challenge nonce.
2. DelegationRequest with the closed content. The Issuer App renders item, condition, price, merchant and delivery address, marks merchant-supplied descriptions as "described by S", delays the approve button, and requires the VHC as root.
3. The user approves; **U-signs** the closed checkout and payment content (CG2). The agent only forwards it.
4. S and CP run V1–V6 with an online status check and a log inclusion proof; the nonce must be S's own.
5. Receipts; per-use report.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC03-A1 | A compromised agent provider (T2) has the agent describe "new" while the structured offer says "refurbished", or a different model | The App renders from structured content only. But the item name and condition are merchant text; unless S signs them, the App cannot vouch for them | Partial: needs verifier-signed context (CG18) |
| UC03-A2 | Splitting below R3: the agent picks "3 × €433 instalments" under an R2 standing mandate (€500 per action) | Classification by total commitment: €1 299 credit commitment is R3 (R4 if it counts as credit) | Gap (CG1, CG9) |
| UC03-A3 | Scam call (T6-like social engineering): "approve the order, it's for your refund", delivery to a new address | New delivery address escalates (P3), shown prominently with a warning; cooling-off for first-time addresses | Partial: coercion is Residual; cooling-off needs CG12 |
| UC03-A4 | The agent holds the approval and uses it a week later, or at another merchant | S's nonce and `aud` are inside the U-signed content; `exp` ≤ 24 h; single use | Covered\* (with CG2) |

---

### UC04 — Age-restricted goods

*"Order the usual wine from W."*

| | |
|---|---|
| Class | R2 + attribute `age_over_18` · AL3 root · standing mandate |
| Actors | User, agent, wine shop W, CP, delivery company (outside AAP) |
| AP2 types | `mandate.checkout.open.1`, `mandate.payment.open.1` |
| AAP types | Root = VHC with `age_over_18` disclosed; `aap.product_categories { allow: [alcohol] }` (CG6b) |
| Required constraints | `allowed_merchants: [W]`; amount and budget as UC02; explicit allow of the restricted category |
| Enforcing verifier | W (age, category), CP (amounts) |

**Flow**

1. Issue(…). The Issuer App shows "includes alcoholic drinks" and "reveals to W: over 18". The disclosure set of the root is fixed at signing; the agent cannot add disclosures later.
2. Orders as in UC02. W verifies the VHC (issuer, `cnf` chain to the open mandate, `age_over_18 = true`, `verified_at`, optionally `chip_auth`).
3. Age at handover is still checked by the courier where the law requires it; AAP does not replace that.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC04-A1 | A minor in the household drives the shared agent account under the adult's standing mandate | AAP proves the adult authorised the purchase, not who consumes it. Delivery check stays | Residual |
| UC04-A2 | W (T7/T8) asks for birth date, country or a pseudonym | The VHC has no birth date; disclosures were fixed at issuance and shown to the user | Covered |
| UC04-A3 | Credential transplant: the agent attaches another adult's VHC to its own mandate | The open mandate must be signed by the VHC's `cnf` key (V1) | Covered |
| UC04-A4 | The groceries mandate (UC02) is used for alcohol at a shop that sells both | Restricted categories must be denied unless explicitly allowed; needs a registry of restricted categories | Gap (CG6b) |

---

### UC05 — Limited quantity, one per person

*"Get me two tickets for the concert on platform T when sales open."*

| | |
|---|---|
| Class | R2 + attribute `pseudonym` · AL3 root · standing mandate |
| Actors | User, agent, ticket platform T, CP |
| AP2 types | `mandate.checkout.open.1`, `mandate.payment.open.1` |
| AAP types | Root = VHC with the per-verifier `pseudonym` for T (0003); `aap.rate` (CG6a) |
| Required constraints | `allowed_merchants: [T]` (exactly one, see UC05-A3); amount range; `exp` after the sale date |
| Enforcing verifier | T, which counts tickets per pseudonym |

**Flow**

1. Issue(…) with the root credential requested for verifier T, so the pseudonym is T's.
2. At sale time T issues challenge nonces; the agent **A-signs** the closed checkout mandate with T's nonce.
3. T checks V1–V6 and its own per-pseudonym limit (four tickets per human).

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC05-A1 | Sybil: one person runs 50 agents with 50 mandates | All roots resolve to the same `person_tag`, hence the same pseudonym at T | Covered (0003) |
| UC05-A2 | A scalper pays real people to enroll and hand over their agents | Expensive, but not preventable | Residual (stated in 0003) |
| UC05-A3 | T and resale platform R correlate customers; easy if one standing mandate names both T and R, because it carries one root with one pseudonym | One chain per verifier for AL3 multi-verifier mandates | Gap (CG5) |
| UC05-A4 | Queue-jumping: the agent pre-signs many closed mandates before sales open | At R2, interactive verifiers issue challenges; T only issues them when sales open | Covered\* |

---

### UC06 — Travel booking

*"Book flight and hotel for Lisbon, 12–15 March, at most €900 in total, refundable only."*

| | |
|---|---|
| Class | R2 as a standing mandate (refundable, ≤ €500 per action); R3 per-action for non-refundable or larger bookings |
| Actors | User, travel agent, airline L and hotel H (checkout verifiers), CP, IS ledger |
| AP2 types | `mandate.checkout.open.1`, `mandate.payment.open.1`; closed mandates A-signed (R2) or U-closed (R3) |
| AAP types | `aap.service_period` (CG6h); `aap.commitment { refundable_only: true }` (CG6c); `aap.data_categories [traveller_name, date_of_birth, passport_number]` with `aap.recipients` per category (CG6e) |
| Required constraints | `allowed_merchants: [L, H]` or a category of merchants; trip budget `payment.budget {max: 90000, currency: EUR}`; dates; refundability; passenger data per recipient |
| Enforcing verifier | CP (budget), L and H (dates, fare terms), the data recipient (categories) |

**Flow**

1. Issue(…). The App renders dates, budget, refundability and which personal data goes to whom ("passport number: airline only").
2. The agent books the flight: **A-signs** the closed checkout with L's fare terms; L checks the service period and refundability; the CP checks the budget.
3. The agent books the hotel at H in the same way. If L and H are paid with different instruments, the budget is reserved at the ledger first (CG4).
4. A non-refundable rate or an amount above €500 per action makes the agent request a U-closed mandate (R3).

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC06-A1 | Drip pricing: €220 fare becomes €310 with seat and bag fees at the last step | The closed mandate covers the final total; the budget bounds it | Covered |
| UC06-A2 | Budget split across verifiers: €480 flight at L plus €480 hotel at H, each under the per-action ceiling, together over €900 | CP if one instrument; otherwise the ledger keyed by the U-signed mandate | Covered for one instrument; otherwise Gap (CG4) |
| UC06-A3 | L labels a non-refundable fare as flexible in its checkout content | `aap.commitment` is evaluated on merchant-declared terms, which must be merchant-signed so that a false declaration is provable | Gap (CG6c, CG18) |
| UC06-A4 | The agent sends the passport number to the hotel, or an injected "visa service" (T9) collects it | Data categories bound to recipients | Gap (CG6e) |

---

### UC07 — Subscriptions: sign-up and cancellation

*"Subscribe me to the cheapest plan of service P; cancel the old one at Q."*

| | |
|---|---|
| Class | Sign-up R2 (classified by total commitment); cancellation R1 |
| Actors | User, agent, providers P and Q, CP |
| AP2 types | `mandate.checkout.open.1` / `mandate.payment.open.1` for the first charge only |
| AAP types | `aap.commitment { max_monthly, max_term, max_notice_period, auto_renew, trial_conversion }` (CG6c); cancellation via `aap.authority.open.1` with `aap.actions [subscription.cancel]` and closed `aap.action.1` |
| Required constraints | Commitment limits; `allowed_merchants`; a monthly cap on *new* commitments across providers |
| Enforcing verifier | P for the commitment terms; CP for the first charge; nobody for later charges (see UC07-A4) |

**Flow**

1. Issue(…) for the sign-up. The App renders "€9.99/month, minimum 1 month, renews monthly, cancel any time" from the structured terms.
2. The agent **A-signs** the closed checkout mandate including P's signed terms; P verifies and starts the subscription; the CP processes the first charge.
3. Later charges are merchant-initiated and never pass through an AAP verifier (CG9).
4. Cancellation at Q: closed `aap.action.1 {action: subscription.cancel, resource: contract id}` with `aud` = Q; Q returns a receipt, which is the user's proof of cancellation.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC07-A1 | Free-trial trap: a €0 checkout converts to a €29.99/month annual plan | Classification by total commitment (€360 → R2), `trial_conversion: require_reapproval` | Gap (CG1, CG6c) |
| UC07-A2 | Q ignores the cancellation and keeps charging (T8) | Signed receipt, or proof of submission in the evidence store if Q issues none; dispute via the payment rails | Partial |
| UC07-A3 | Subscription sprawl: an injected agent signs up for ten €9 tools | Cap on new commitments per month across providers | Gap (CG4, CG6c) |
| UC07-A4 | The user revokes the mandate; P keeps charging the stored card | AAP revocation does not reach merchant-initiated charges | Gap (CG9) |

---

### UC08 — Bank account read

*"Categorise my spending from the last three months."*

| | |
|---|---|
| Class | R1 · AL2 · standing mandate, 90 days |
| Actors | User, finance agent, bank B (verifier), IS |
| AP2 types | none |
| AAP types | `aap.authority.open.1` with `aap.actions [account.read_balance, account.read_transactions]`, `aap.resources [IBAN]`, `aap.data_categories [balance, transactions]`, `aap.rate { max_count: 4, period: day }` (CG6a); closed `aap.action.1` |
| Enforcing verifier | B |

**Flow**

1. Once: the user links the AAP identity to their account at B (CG17), e.g. by approving a pairing in B's own app.
2. Issue(…). The App renders "read balance and transactions of account AT61…, up to 4 times a day, for 90 days".
3. The agent **A-signs** `aap.action.1 {action: account.read_transactions, resource: IBAN}` with `aud` = B; B runs V1–V6 and answers.

Relation to PSD2: account information services already require the bank's own SCA and a registered provider. Whether a bank may accept an AAP mandate as the customer's consent evidence is a regulatory question, not a protocol one.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC08-A1 | An injected agent forwards the statements to an attacker | Nothing in AAP controls data after a read. A messaging mandate with recipient limits (UC13) narrows the channels | Residual |
| UC08-A2 | The agent uses the read mandate to initiate a payment | `aap.actions` does not contain it; unknown action denies | Covered |
| UC08-A3 | The agent provider polls every minute to build a behaviour profile | `aap.rate` | Gap (CG6a) |
| UC08-A4 | The agent asks for a partner's account at the same bank | `aap.resources`; and B must know that the AAP principal *is* this account holder | Partial: needs CG17 |

---

### UC09 — Transfer to a known payee

*"Pay the electricity and the rent when they're due."*

| | |
|---|---|
| Class | R2 · AL2 · standing mandate, 30 days |
| Actors | User, agent, bank B (CP role), payees |
| AP2 types | `mandate.payment.open.1`, closed A-signed |
| AAP types | none |
| Required constraints | `payment.allowed_payees: [IBAN₁, IBAN₂]` (account identifiers, never names); `payment.amount_range {max: 50000, currency: EUR}`; `payment.budget` per month |
| Enforcing verifier | B |

**Flow**

1. Issue(…). The App renders each payee by name *and* IBAN, as previously approved by the user.
2. When an invoice arrives, the agent **A-signs** a closed payment mandate (payee, amount, reference); B runs V1–V6 (status ≤ 5 min) and executes.
3. Receipts and per-use reporting.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC09-A1 | An injected invoice (T9) announces "new bank details" | The new IBAN is not in the U-signed allow-list; it becomes UC10 (R3) | Covered |
| UC09-A2 | The allow-list holds a name only; the attacker opens an account named "Stadtwerke" | Payee constraints must identify accounts, never names; the EU Verification of Payee check adds a second line | Covered\* (rule to be written into the AAP profile of `payment.allowed_payees`) |
| UC09-A3 | Stale mandate: the user moved out, the agent pays the old rent again | 30-day lifetime, renewal with diff, per-use reporting | Covered\* |
| UC09-A4 | The user revokes after noticing a wrong payment; B still has a cached "valid" status | R2 status freshness ≤ 5 min | Covered\* |

---

### UC10 — Transfer to a new payee

*"Pay the €1 800 deposit to my new landlord."*

| | |
|---|---|
| Class | R3 · AL3 · per-action (U-closed) |
| Actors | User, agent, bank B, IS |
| AP2 types | `mandate.payment.closed.1`, U-signed |
| AAP types | `nbf` in the U-signed content as cooling-off (CG12) |
| Required constraints | Exact payee IBAN and name, amount, reference, B's nonce; B's Verification of Payee result, signed by B (CG18) |
| Enforcing verifier | B |

**Flow**

1. The agent submits the draft transfer to B. B performs Verification of Payee and returns the result (match / close match / no match) and a challenge nonce, both signed by B.
2. DelegationRequest. The App verifies B's signature on the VoP result and renders payee, IBAN, "according to B: name matches", amount and reference.
3. The user approves; **U-signs** with `nbf` = now + cooling-off for a first-time payee above a threshold (proposed: 1 h above €1 000). The App, not the IS, sets `nbf`.
4. The agent forwards; B runs V1–V6 with an online status check and inclusion proof, waits until `nbf`, then executes. Revoking before `nbf` cancels.
5. The payee is now "known" and may be added to a UC09 mandate in a later issuance.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC10-A1 | Authorised push-payment scam: a caller talks the user through approving | VoP mismatch shown prominently, cooling-off with a cancel option, warning text for first-time payees | Partial: coercion itself is Residual |
| UC10-A2 | A compromised agent provider (T2) forges "name matches" | The VoP result is signed by B and checked by the App | Gap (CG18) |
| UC10-A3 | A compromised IS (T3) or agent requests the mandate without cooling-off | The App sets `nbf` from the class rules; B enforces `nbf` | Gap (CG12): 0002 places cooling-off in the IS |
| UC10-A4 | The approval is replayed for a second transfer or at another bank | B's nonce and `aud` inside the U-signed content; single use | Covered\* (with CG2) |

---

### UC11 — Standing orders and recurring bills

Two different things that look alike:

- **(a) Bank-executed standing order:** "€950 rent on the 1st of every month." After setup, the bank executes without the agent.
- **(b) Agent-initiated recurring payment:** "Pay the electricity bill each month, up to €150." The agent presents every time.

| | |
|---|---|
| Class | (a) setup and any change: R3 per-action (total commitment and no AAP check on executions). (b) R2 standing mandate |
| Actors | User, agent, bank B, payee |
| AP2 types | (a) `mandate.payment.closed.1` U-signed, describing the standing order; (b) `mandate.payment.open.1` with `payment.agent_recurrence`† |
| AAP types | `aap.actions [standing_order.create]` for (a) if the bank models it as a non-payment action; `aap.commitment` for the end date (CG6c) |
| Required constraints | (a) payee, amount, schedule, end date; (b) payee allow-list, `payment.amount_range {max: 15000}`, monthly recurrence, `exp` 30 days with renewal |
| Enforcing verifier | B |

**Flow**

1. (a) The agent prepares the standing order; the App renders payee, amount, schedule and "until 31 Dec 2027" (or "until cancelled", with a warning); **U-signs**; B creates it. Further executions are B's business.
2. (b) As UC09, with recurrence checked by B.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC11-A1 | Amount creep: the bill rises from €60 to €149 a month, inside the cap | Cap bounds it; per-use reporting; the App can flag deviations from the previous amounts | Partial |
| UC11-A2 | The agent modifies an existing standing order's payee through a "modify" call | Modification with a new payee is R3 per-action; not in `aap.actions` of (b) | Covered |
| UC11-A3 | The standing order outlives the lease; AAP mandate expiry does not stop B's executions | End date rendered and signed; "until cancelled" needs explicit confirmation | Partial (CG9) |

---

### UC12 — Insurance claim

*"File the claim for my stolen bike with insurer I."*

| | |
|---|---|
| Class | R3 (a declaration whose falsehood is fraud) · AL3 · per-action declaration |
| Actors | User, claims agent, insurer I (verifier), sources of documents (shop invoice, police report), IS |
| AP2 types | none (the later payout is I's business) |
| AAP types | U-closed `aap.declaration.1` (CG7): structured claim fields + hashes of attachments; `aap.data_categories`; payout account |
| Required constraints | Policy number, incident date, claimed amount, item list, payout IBAN, attachment hashes, `aud` = I, I's nonce |
| Enforcing verifier | I |

**Flow**

1. The agent collects documents and fills I's claim schema (ideally an I-signed form, CG18).
2. DelegationRequest. The App renders the structured fields, shows every attachment it hashes, labels them "provided by the agent", and highlights the payout account.
3. The user approves; **U-signs** the declaration. The agent forwards it to I.
4. I runs V1–V6 and checks that the payout IBAN is the policyholder's known account; the receipt is the claim acknowledgment.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC12-A1 | The agent inflates the amount or adds items | The user signs the structured amount and list; T10 later cannot deny it | Covered\* (with CG7); not reading remains Residual |
| UC12-A2 | Payout redirection: injected agent sets the payout IBAN to an attacker's account | A payout account not previously used escalates like a new payee (P3); I pays only to known accounts or after its own check | Partial (CG1) |
| UC12-A3 | Document substitution: the user sees photo A, the agent submits photo B | Attachment hashes in the U-signed content; the App renders exactly the bytes it hashes | Gap (CG7) |
| UC12-A4 | I asks for the full medical record for a bike theft (T8) | `aap.data_categories` in the declaration; the App shows what leaves the device | Partial |

---

### UC13 — Messages and email on the user's behalf

*"Answer routine emails from my contacts; never more than 20 messages a day."*

| | |
|---|---|
| Class | R1 to recipients on the user's list; R2 for new recipients; a message that commits the user to something is not classifiable (UC13-A4) |
| Actors | User, agent, sending providers M₁ (email) and M₂ (chat) as verifiers, recipients, IS ledger |
| AP2 types | none |
| AAP types | `aap.authority.open.1` with `aap.actions [message.send, message.reply]`, `aap.recipients { allow, deny }` (CG6e), `aap.rate { max_count: 20, period: day }` across providers (CG6a, CG4); closed `aap.action.1 {action, counterparty: recipient, resource: thread}` |
| Enforcing verifier | The sending provider |

**Flow**

1. Issue(…). The App renders recipients ("your contact list as of today: 143 addresses", or domains), the daily limit, and the providers.
2. Per message: the agent **A-signs** the closed action; the provider runs V1–V6, reserves one unit at the ledger, checks the recipient, sends, and marks the message as agent-sent (CG13).
3. Receipt per message; daily digest.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC13-A1 | An injected email (T9) makes the agent send a phishing link to all contacts | Contacts are allowed; content is not constrained. The rate limit bounds the blast radius; per-use reporting detects it | Partial |
| UC13-A2 | Exfiltration: the agent mails documents to an attacker address | The attacker is not on the recipient list; a new recipient needs R2 issuance | Gap (CG6e) |
| UC13-A3 | Rate exhaustion across providers: 20 per day at M₁ and 20 at M₂ | Ledger keyed by the U-signed mandate | Gap (CG4) |
| UC13-A4 | The agent replies "yes, I accept your offer of €12 000" to a car dealer | Content cannot be classified deterministically. Recipients should see that the message was agent-sent under a mandate that excludes commitments | Gap (CG13) |

---

### UC14 — Calendar and scheduling between agents

*"Find a slot with Maria next week and accept it."*

| | |
|---|---|
| Class | Free/busy read R0 (AL1); proposing and accepting events R1 (AL2) |
| Actors | User A with agent A, user B with agent B, calendar services C_A and C_B (verifiers); agent A also verifies agent B |
| AP2 types | none |
| AAP types | `aap.authority.open.1` with `aap.actions [calendar.read_free_busy, event.propose, event.accept]`, `aap.data_categories [free_busy]`, `aap.time_windows` (working hours), `aap.rate` |
| Enforcing verifier | C_A for A's calendar; agent A for B's claim to speak for user B |

**Flow**

1. Agent B asks agent A for slots and presents its own chain; agent A verifies it like any verifier (V1–V6).
2. Agent A reads free/busy from C_A (**A-signs** the closed read action) and proposes three slots.
3. Agent B creates the event in C_B under B's own mandate; agent A accepts the invitation at C_A (**A-signs** `event.accept`), checked against the time windows.

This is the simplest non-payment flow and a good first candidate for the `aap.authority.open.1` path (0001, open question 3).

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC14-A1 | An injected invite asks agent A to share titles and attendees | C_A returns only `free_busy`; the agent never holds more | Covered |
| UC14-A2 | Agent B claims to schedule for "the CEO of X"; agent A cannot tell, because the VHC carries no name, email or role | Needs a verifiable email, domain or organisational role of the principal | Partial (CG8) |
| UC14-A3 | Calendar flooding: agent A accepts 30 meetings in a day | `aap.rate`, `aap.time_windows` | Partial: needs CG6a |
| UC14-A4 | A paid appointment with a no-show fee is slipped in as a normal meeting | Any amount in a request against a mandate without amounts denies (`spec/scope-matching.md`, rule 3); the fee needs a payment mandate | Covered |

---

### UC15 — Sharing health data

*"Send my lab results from 2025–2026 to Dr. D for the appointment."*

| | |
|---|---|
| Class | First share of special-category data to a recipient: R3 per-action. Repeat shares of the same categories to the same recipient: R2 standing (P3) |
| Actors | User, health agent, data holder H (record portal; verifier), recipient D, IS |
| AP2 types | none |
| AAP types | U-closed `aap.action.1 {action: data.share, resource: record set, data_categories: [lab_results], counterparty: D}`, `aap.purpose [treatment]`, `aap.retention { max_days: 90 }` (CG6d), `aap.recipients [D]` (CG6e) |
| Enforcing verifier | H, which delivers only to the bound recipient |

**Flow**

1. Once: the user's AAP identity is linked to their record at H (CG17).
2. DelegationRequest. The App renders categories, period, recipient, purpose and retention.
3. The user approves; **U-signs** (VHC root). The agent forwards to H.
4. H runs V1–V6 (online status), authenticates D, and sends the data directly to D, not through the agent.
5. For follow-up shares (e.g. monthly glucose readings to the same doctor) the user may issue an R2 standing mandate with recipient D fixed.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC15-A1 | An injected agent names "D-Clinic", an attacker, as recipient | The recipient is part of the U-signed content and rendered with its verified identity; H must authenticate the recipient | Partial: recipient authentication undefined (CG6e) |
| UC15-A2 | The agent requests the full record instead of lab results | `data_categories` with a canonical rendering per category | Covered |
| UC15-A3 | The user withdraws consent; D already has the data | Revocation stops future shares; retention and purpose bind D legally, not technically | Residual (P8) |
| UC15-A4 | The follow-up mandate keeps running after the treatment ended | R2 lifetime 30 days, renewal with diff | Covered\* |

---

### UC16 — Agent-to-agent sub-delegation

*The shopping agent S asks a price-comparison agent P from another provider to find the best offer.*

| | |
|---|---|
| Class | The child link inherits the parent's class as an upper bound; here the child is R0 (read-only quotes) under an R2 parent |
| Actors | User, shopping agent S (holds the user's open mandate), sub-agent P, merchants (verifiers), IS |
| AP2 types | Parent: `mandate.checkout.open.1` / `mandate.payment.open.1`. Child: an A-signed Delegate SD-JWT link (AP2 leaves agent-to-agent delegation out of scope) |
| AAP types | Parent: `aap.delegation { max_depth: 1 }` plus the extensions in CG6f. Child: `aap.actions [catalogue.read, quote.request]`, no `aap.delegation`, `exp` ≤ 1 h |
| Enforcing verifier | Each merchant P talks to, via cumulative evaluation |

**Flow**

1. The user's open mandate to S permits one level of delegation (rendered: "may hand read-only tasks to other agents").
2. S **A-signs** a child link with `cnf` = P's key, read-only actions, `exp` 1 h.
3. P presents chain (root → user link → S link → P's closed request) to merchants; each runs V1–V6, so P's request must satisfy *all* links (0004, point 4).
4. P returns quotes to S. S buys under its own mandate.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC16-A1 | P's link claims a payment ceiling above the parent's | Cumulative evaluation: the parent's constraints are still checked | Covered (0004) |
| UC16-A2 | P re-delegates to a third agent | S's link carries no `aap.delegation`, so no further open mandate may follow | Covered (0004) |
| UC16-A3 | S gives P a purchase sub-mandate of €300 of the €320 budget and keeps spending itself | The budget is counted against the U-signed mandate, not per link | Gap (CG4) |
| UC16-A4 | P misbehaves; S wants to revoke P's link before `exp`. The user never learns that P exists | Agent-signed links have no status entry and are not in the transparency log | Gap (CG15, CG6f): short `exp` is the only mitigation today |

---

### UC17 — B2B procurement for a legal entity

*An employee lets a procurement agent order office supplies for company Y from approved suppliers.*

| | |
|---|---|
| Class | R2 within catalogue limits; R3 per-action above them; orders above €2 000 need two approvers |
| Actors | Company Y (principal, legal person), employee E (approver), finance approver F, procurement agent, supplier marketplaces (verifiers), CP (corporate card or invoice) |
| AP2 types | `mandate.checkout.open.1`, `mandate.payment.open.1` |
| AAP types | Root = organisational role credential "E may commit Y up to €5 000" (CG8) + E's hardware key; `aap.counterparties` (approved suppliers); `aap.product_categories`; `aap.approvals { threshold: 2, above: 200000 }` (CG6g); PO reference in the closed mandate |
| Required constraints | Supplier allow-list, cost-centre budget per month, category limits |
| Enforcing verifier | Supplier (categories, PO); CP or ledger (budget); every verifier for the role credential's status |

**Flow**

1. Y's administrator issues E a role credential bound to E's Attested User Key (needs CG8).
2. Issue(…) by E. The App renders "for company Y, cost centre 4100, suppliers A and B, €1 500/month".
3. Orders: agent **A-signs** closed mandates; suppliers verify V1–V6 including the status of E's role credential.
4. Above €2 000: a U-closed mandate needs signatures from E and F (two keys, two role credentials).

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC17-A1 | E has left Y; E's mandates are still valid | Y revokes E's role credential; every chain rooted in it fails at V2 | Gap (CG8) |
| UC17-A2 | Order splitting: 5 × €1 900 instead of one €9 500 order, across two suppliers | Cost-centre budget at the ledger; P2 | Gap (CG4) |
| UC17-A3 | The agent gets E to approve twice to fake the four-eyes step | `aap.approvals` requires distinct keys bound to distinct role credentials | Gap (CG6g) |
| UC17-A4 | A supplier (T8) delivers cheaper goods than ordered or inflates the invoice | The closed mandate binds the PO lines; three-way matching stays in Y's ERP | Partial |

---

### UC18 — Binding long-term contract

*"Switch me to the 24-month mobile plan from provider K."* The same pattern applies to consumer credit and rental contracts.

| | |
|---|---|
| Class | R4 · AL3, `chip_auth` ≠ `none` · per-action declaration with re-confirmation |
| Actors | User, agent, provider K (verifier), optionally a qualified trust service provider |
| AP2 types | none, or `mandate.payment.closed.1` for a first payment or deposit |
| AAP types | U-closed `aap.declaration.1` (CG7) with the contract document hash and K-signed key terms; `aap.commitment` (CG6c) |
| Required constraints | Total cost over the term, term, notice period, renewal terms, document hash, `aud` = K, K's nonce |
| Enforcing verifier | K |

**Flow**

1. The agent obtains K's offer: the contract document and its key terms in structured form, both signed by K (CG18).
2. DelegationRequest. The App renders the key terms ("€29/month for 24 months, total €696, notice period 3 months, renews monthly afterwards") and lets the user open the full document.
3. First approval. The App asks again at least 1 h later or on a second device; only then **U-signs**.
4. The agent forwards to K; K runs V1–V6 with online status, inclusion proof and VHC freshness, then concludes the contract. Statutory withdrawal rights are unaffected.
5. Where the law requires a qualified electronic signature, the AAP mandate only authorises the agent to prepare and submit; the user signs with a QES. AL3 is not a QES.

**Attacks**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC18-A1 | The structured terms say 24 months, the document says 36 | K signs both; the inconsistency is K's liability. The App cannot interpret legal text | Partial (CG7, CG18) |
| UC18-A2 | Pressure: "sign within 10 minutes or the offer expires" (social engineering) | The re-confirmation delay is mandatory at R4; verifiers must accept it | Partial: coercion is Residual |
| UC18-A3 | A standing mandate "find me a plan under €30/month" is used to conclude the contract | A standing mandate computing to R4 is not signable; the agent must request a declaration | Covered\* |
| UC18-A4 | The user later claims "my agent signed, not me" (T10) | U-signed declaration, VHC root, log entry, receipt | Covered |

---

### UC19 — Interaction with an authority (deferred)

*"File my tax return", "register my change of address", "apply for a parking permit."*

**Status: deferred.** State eID integration (ID Austria, the EUDI Wallet) is out of scope for now (0002, 0003). This entry records what the use case would need, so the gap is not forgotten.

| | |
|---|---|
| Class | R4 |
| Actors | User, agent, authority (verifier), possibly a professional representative (tax advisor) |
| Needs | An eID-backed assurance level above AL3; a legal basis for an authority to accept an agent's submission; a mapping between AAP mandates and existing powers of attorney (e.g. the representation mechanisms of tax portals) |
| AAP types | U-closed `aap.declaration.1` (CG7); a long-lived read mandate for receiving notices (deadlines run for weeks) |

**Sketch of a flow:** the user authenticates with the state eID in the Issuer App, which binds the eID to the hardware key; the agent prepares the filing; the user signs a declaration per filing; the authority verifies the chain and the eID binding; notices come back to the agent under a separate read mandate.

**Attacks (not designed)**

| ID | Scenario | Expected defence | Coverage |
|---|---|---|---|
| UC19-A1 | The agent files with wrong figures | As UC12-A1: the user signs the structured declaration | Deferred |
| UC19-A2 | The authority needs the real identity, which the VHC deliberately does not carry | An eID-backed root | Deferred |
| UC19-A3 | A notice with a deadline reaches the agent but not the user | Read mandates for notices must forward a copy to the user, outside the agent | Deferred |

## Summary matrix

| UC | Class | Min AL | Mandate kind | VHC | AP2 mandate types | Main AAP constraints | Shared state |
|---|---|---|---|---|---|---|---|
| UC01 | R1 | AL2 | Standing, single use | — | checkout + payment (open/closed) | `aap.rate` | — |
| UC02 | R2 | AL2 | Standing | — | checkout + payment, `payment.budget`, `payment.agent_recurrence`† | `aap.product_categories` | CP, else ledger |
| UC03 | R3 | AL3 | Per-action | Required | checkout + payment closed, U-signed | — | — |
| UC04 | R2 + age | AL3 | Standing | `age_over_18` | checkout + payment | `aap.product_categories` | CP |
| UC05 | R2 + uniqueness | AL3 | Standing | `pseudonym` | checkout + payment | `aap.rate` | Verifier, per pseudonym |
| UC06 | R2 / R3 | AL2 / AL3 | Standing / per-action | — / required | checkout + payment | `aap.service_period`, `aap.commitment`, `aap.data_categories`, `aap.recipients` | CP, else ledger |
| UC07 | R2 / R1 | AL2 | Standing | — | checkout + payment (first charge) | `aap.commitment`, `aap.actions` | Ledger (new commitments) |
| UC08 | R1 | AL2 | Standing | — | — | `aap.actions`, `aap.resources`, `aap.data_categories`, `aap.rate` | Verifier |
| UC09 | R2 | AL2 | Standing | — | payment, `payment.allowed_payees`, `payment.budget` | — | CP |
| UC10 | R3 | AL3 | Per-action | Required | payment closed, U-signed | `nbf` cooling-off | — |
| UC11 | R3 / R2 | AL3 / AL2 | Per-action / standing | Required / — | payment closed / open with `payment.agent_recurrence`† | `aap.commitment` | CP |
| UC12 | R3 | AL3 | Per-action declaration | Required | — | `aap.declaration.1`, `aap.data_categories` | — |
| UC13 | R1 / R2 | AL2 | Standing | — | — | `aap.actions`, `aap.recipients`, `aap.rate` | Ledger |
| UC14 | R0 / R1 | AL1 / AL2 | Standing | — | — | `aap.actions`, `aap.data_categories`, `aap.time_windows`, `aap.rate` | — |
| UC15 | R3 / R2 | AL3 | Per-action / standing | Required | — | `aap.data_categories`, `aap.purpose`, `aap.retention`, `aap.recipients` | — |
| UC16 | inherits (R0 child) | as root | Standing, A-signed link | as parent | parent: checkout + payment | `aap.delegation`, `aap.actions` | Ledger keyed by U-signed mandate |
| UC17 | R2 / R3 | AL3 + role | Standing / per-action, 2 approvers | Required + role credential | checkout + payment | `aap.counterparties`, `aap.product_categories`, `aap.approvals` | Ledger |
| UC18 | R4 | AL3 (`chip_auth`) | Per-action declaration + re-confirmation | Required | — (payment if deposit) | `aap.declaration.1`, `aap.commitment` | — |
| UC19 | R4 | eID level (deferred) | Per-action declaration | eID | — | `aap.declaration.1` | Deferred |

**Attack coverage** (74 scenarios): 15 Covered, 9 Covered\*, 3 covered only in the simple case (one payment instrument; nonce without a use count), 17 Partial, 22 Gap, 5 Residual, 3 Deferred. Several Partial entries also depend on a gap; the table rows name it.

The pattern: everything 0004 decided for **chains** (cumulative evaluation, depth, `aud`, nonce, key binding) holds up in every use case. The gaps cluster around **state across verifiers**, **what the user sees** (use reporting, verifier-signed facts, documents) and **missing vocabulary** (constraint types, actions, organisational roles).

## Gaps found

### CG1 — The risk class must be a specified function

0002 lets the IS "apply policy (cooling-off periods for high-risk classes)" and says "risk class decides which kind a verifier accepts", but nothing defines how a class is determined. If the agent's DelegationRequest names the class, a T1 agent simply claims R1. The class must be computed from the content by one deterministic function (above), shipped in aap-core, run by the App and the verifier. Commitments (instalments, trials, subscriptions) are classified by their total.
*Revealed by:* UC03-A2, UC07-A1, UC12-A2.

### CG2 — How a per-action mandate sits in the chain

0002 distinguishes standing (open) and per-action (closed) mandates where the user approves "one concrete action". 0004's token shape only has closed mandates signed by the leaf **agent** key. For R3/R4 the user's signature must cover the concrete action. Proposal: the chain is `root credential ~ closed mandate U-signed` with `aud`, the verifier's nonce and a short `exp` inside the user-signed content; the agent only transports it. The DelegationRequest therefore carries the verifier's nonce. Fallback for strict AP2 compatibility: a U-signed open mandate narrowed to exactly one action plus `aap.rate {max_count: 1}`, closed by the agent — weaker, because the agent still chooses the moment and the audience.
*Revealed by:* UC03, UC10, UC12, UC15, UC18 (all R3/R4 flows).

### CG3 — The user does not see uses, only issuances

SG4 ("misuse is detectable by the user") is met for mandates through the transparency log, but a standing mandate can be misused *within* its constraints, and the receipts go to the agent. Proposal: verifiers send each receipt (or its hash and a minimal summary) to the IS **use log** named in the mandate; the App shows a per-use feed (R2+) or a daily digest (R1). Without it, UC02-A4, UC11-A1 and UC13-A1 are invisible.

### CG4 — Budgets and rates across verifiers need one named counter

0002 makes the usage ledger optional and assumes the CP enforces payment budgets. That holds only with one instrument at one CP. Rules proposed:
- A budget or rate constraint whose permitted counterparties span more than one verifier MUST name its counter (`aap.ledger { endpoint }`, or "CP" for a single instrument). The App refuses to sign otherwise.
- The counter is keyed by the **U-signed** mandate, so sub-delegations share it.
- A verifier reserves before accepting and fails closed if the ledger is unreachable.

*Revealed by:* UC02-A1, UC06-A2, UC07-A3, UC13-A3, UC16-A3, UC17-A2.

### CG5 — Per-verifier pseudonyms vs. multi-verifier mandates

At AL3 the root credential carries one pseudonym, but a standing mandate valid at several verifiers would show the same pseudonym (and the same issuer signature) to all of them, which defeats 0003's pairwise pseudonyms. Proposal: for AL3 mandates naming several verifiers, the App issues **one chain per verifier** (batch issuance, as 0003 already plans for linkability) and links them to one ledger counter (CG4). The user sees and approves one mandate.
*Revealed by:* UC05-A3.

### CG6 — New constraint types

| | Constraint | Purpose | Use cases |
|---|---|---|---|
| a | `aap.rate { max_count, period }` | Single-use mandates, message limits, API polling limits | UC01, UC05, UC08, UC13, UC14 |
| b | `aap.product_categories { allow, deny }` with a registry of restricted categories (alcohol, tobacco, medicines, weapons) that are denied unless explicitly allowed | Restricted goods; procurement | UC02, UC04, UC17 |
| c | `aap.commitment { max_monthly, max_total, max_term, max_notice_period, auto_renew, trial_conversion, refundable_only, max_cancellation_fee }` | Subscriptions, contracts, fare terms; feeds the classification of commitments (CG1) | UC06, UC07, UC11, UC18 |
| d | `aap.purpose { allowed }`, `aap.retention { max_days }` | Data sharing under GDPR | UC15 |
| e | `aap.recipients { allow, deny }`, per data category where needed, with a defined way to authenticate a recipient who is not the verifier | Messages, data shares, passenger data | UC06, UC13, UC15 |
| f | Extensions of `aap.delegation`: `allowed_delegates` (agent identities or attested agent classes), `allowed_actions`, `log: true` | Visible and bounded sub-delegation | UC16 |
| g | `aap.approvals { threshold, above }` | Four-eyes approvals for legal entities | UC17 |
| h | `aap.service_period { from, to }` | Dates of a booked service (distinct from `aap.time_windows`, which constrain *when the agent acts*) | UC06 |

Each needs a canonical rendering (0002, WYSIWYS rule 5), an evaluator, a `narrows` rule and property tests (0004, tests item 4). Before adding (b) and (h), check whether AP2 v0.2 checkout constraints already express line-item categories or service dates†.

### CG7 — Declarations: a closed type for content the user vouches for

0004's open question 5 asks whether `aap.action.1` stays generic. The catalogue's answer: **one generic `aap.action.1` is enough for actions**; domains differ by their action vocabulary (CG11), not by mandate type. One more type is needed for content the user vouches for rather than an action they allow: `aap.declaration.1 { schema, fields, attachments: [{hash, media_type}] }`, always U-signed. It requires the App to display documents (PDF, images) and to render exactly the bytes it hashes, labelled as unstructured content the App does not interpret.
*Revealed by:* UC12-A3, UC18-A1, UC19.

### CG8 — Legal entities and roles

0004 says the principal is the root credential. For a legal person there is no root: a VHC proves a human, not that this human may commit company Y. Needed: an **organisational role credential** (issued by Y's administrator, revocable by Y, bound to the employee's Attested User Key) and a rule that chains for legal entities root in it. Candidates to align with later: the GLEIF vLEI ecosystem and the EU business wallet. The same mechanism would give agents a verifiable email or domain for peer contexts (UC14-A2).
*Revealed by:* UC14-A2, UC17-A1.

### CG9 — Merchant-initiated follow-up charges

Subscriptions, instalments, standing orders and hotel no-show fees are charged later by the merchant or bank, without any agent presentation, so no AAP verifier ever checks them and revoking the mandate does not stop them. AAP cannot enforce these; what it can do: classify the setup by total commitment (CG1), sign the follow-up terms into the setup mandate so they are evidence in a dispute, and let the user's revocation produce a signed cancellation that the agent delivers. Enforcement stays with the payment rails.
*Revealed by:* UC03-A2, UC07-A4, UC11-A3.

### CG10 — Custody of the agent key

0002 protects the user key thoroughly; the agent's `cnf` key is not addressed. A stolen agent key plus a standing mandate lets an attacker act within the constraints until revocation. Proposal: for R2 standing mandates the agent key is held in a KMS/HSM or platform keystore, and the DelegationRequest says so (informational at first, attestable later); short-lived agent keys with refreshed mandates are an alternative. This also bounds T2.
*Revealed by:* the UC01, UC02 and UC09 flows in general; no single scenario, because the impact equals "agent misbehaves within constraints".

### CG11 — An action vocabulary

`aap.actions` and `aap.action.1 { action }` take strings. Interoperability and the classification function both need a registered vocabulary with a base class and a canonical rendering per action (`account.read_transactions`, `message.send`, `event.accept`, `data.share`, `subscription.cancel`, `standing_order.create`, …). Unknown actions are not signable and deny at the verifier.

### CG12 — Cooling-off must be signed, not just policy

0002 places cooling-off in the IS ("can apply policy… cooling-off periods"). A compromised IS (T3) or an agent bypassing the relay (local OpenID4VP path) skips it. Proposal: the App sets `nbf` on per-action mandates from the class rules and the verifier enforces `nbf` (it already checks `nbf <= now`, 0004 V2). Revoking before `nbf` cancels the action. This answers part of 0002's open question 2.
*Revealed by:* UC03-A3, UC10-A3.

### CG13 — Recipients of agent-sent messages

The verifier in UC13 is the sending provider, not the recipient. The recipient cannot tell an agent-sent message from a human one, nor what the mandate allowed. Open: a message header or signature that carries the agent label and a reference to the mandate's non-sensitive summary ("agent-sent; mandate excludes commitments"), so recipients and their own agents can treat the content accordingly.
*Revealed by:* UC13-A4.

### CG14 — Authorities and state eID

Proposed to defer (not decided). UC19 records the needs: an eID-backed assurance level, a legal basis for authorities to accept agent submissions, a mapping to existing powers of attorney, and long-running read mandates for notices.

### CG15 — Revocation of agent-signed links

0004 V2 checks "for every link … its status in the status list", but agents do not run status lists and the IS only allocates entries for U-signed mandates. Options: (a) the IS allocates a status entry for a sub-delegation on the parent agent's request and lets the parent agent revoke it; (b) agent-signed links carry no status and must have a short `exp` (proposed ≤ 1 h) and be refreshed. (b) is simpler and enough for R0–R2 children. In both cases the user should be able to see sub-delegations (CG6f `log: true` writes their hashes to the transparency log).
*Revealed by:* UC16-A4.

### CG16 — Coercion

Coercion stays Residual in UC03, UC10 and UC18. Friction (delays, re-confirmation, cooling-off with cancel) reduces scams that depend on urgency; it does not help against someone standing next to the user. A **duress PIN** — a second PIN that produces a valid-looking signature flagged as coerced, which verifiers treat as a silent decline — is a possible addition. It has its own risks (an attacker who knows the scheme demands the real PIN) and needs separate analysis. Open.

### CG17 — Binding the AAP principal to an existing account

Banks and data holders already know their customer. Before they accept a mandate, they must know that its root (user key, pseudonym) belongs to *this* customer. Nothing in 0002–0004 defines this one-time linking. Proposal: an `aap.action.1 {action: account.link}` presented once, approved inside the verifier's own authenticated session (e.g. the bank app), after which the verifier stores the user's key or pseudonym against the account.
*Revealed by:* UC08-A4, UC15 flow step 1.

### CG18 — Verifier-signed context on the Trusted Surface

WYSIWYS guarantees that the App renders the structured content faithfully, but many facts in that content come from a merchant, a bank or a provider: item descriptions, fare terms, payee-name checks, contract terms. If those arrive as agent-supplied data, a T2 agent can lie through them while the rendering stays "correct". Proposal: a DelegationRequest may carry **context objects signed by the verifier** (merchant-signed cart†, VoP result, insurer form, contract offer); the App verifies them and renders them as "according to X". Unsigned facts are shown with the "the agent says" label of 0002.
*Revealed by:* UC03-A1, UC06-A3, UC10-A2, UC18-A1.

## Open questions answered or raised

**Answered (proposals, to be confirmed in the respective documents):**

- **0002, Q2 (cooling-off and friction thresholds):** the per-class friction rules and amount tiers above; cooling-off as signed `nbf` (CG12).
- **0002, Q4 (multiple devices):** every mandate of R2 and above needs a log inclusion proof, so the user's other devices see it.
- **0004, Q2 (nonce model):** agent-generated nonces for R0–R1 and non-interactive R2 APIs; verifier challenges for interactive R2 and always for R3/R4, bound into the U-signed content.
- **0004, Q5 (generic closed mandate):** generic `aap.action.1` plus one `aap.declaration.1` (CG7); domains differ by action vocabulary (CG11).
- **0001, Q3 (scope of the first release):** UC01 and UC09 prove AP2 interop with payments at R1/R2; UC14 (calendar) is the simplest non-payment case for the `aap.authority.open.1` path.
- **0003, Q4 (documents without chip authentication):** accept with the `chip_auth: none` flag up to R3; reject at R4.

**Raised:**

1. Are the default amount tiers right, and should they be per currency or converted?
2. Should the action vocabulary (CG11) and restricted-goods categories (CG6b) be maintained by AAP or aligned with an existing taxonomy?
3. Is the usage ledger (CG4) operated by the IS, or can a CP act as the ledger for non-payment counters too?
4. Recipient authentication for data shares and messages (CG6e, CG13): which identifier does a recipient prove — a VHC pseudonym, an organisational credential, a domain?
5. Do verifiers in disputes (UC07-A2, UC12, UC17) push for 0003's escrow option B? The catalogue suggests insurers and B2B suppliers will ask for it.
6. Duress PIN (CG16): pursue or drop?

## From scenarios to tests

Every attack ID becomes a test named after it (e.g. `uc09_a1_unlisted_iban_is_rejected`), in the crate where the defence lives: chain and constraint defences in aap-core (0004, tests item 5), App rendering and friction in the Issuer App's own suite, ledger behaviour in the verifier-service. Covered entries are written first. Gap entries are added as pending tests together with the constraint or rule that closes them, so "the gap is closed" means "its test passes". Residual entries get no test; they stay listed here so that nobody claims the protocol prevents them.
