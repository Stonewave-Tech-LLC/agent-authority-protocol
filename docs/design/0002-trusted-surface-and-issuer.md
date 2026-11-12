# 0002 — Trusted Surface: proving the human approved

- **Status:** Draft
- **Date:** 2026-10-18 (updated the same day with the results of spike S1, worked into the sections below)
- **Working position (draft, not decided):** Mandates are signed only by a dedicated **Issuer App** on the user's phone, using a non-exportable hardware key that requires biometric or PIN verification for every signature. An **Issuer Service** relays requests and provides status, logging and attestation, but never holds a user key.

## Problem

A mandate is only worth as much as the guarantee that a human, and not the agent, approved it. Everything the Verifier checks downstream is meaningless if the agent can produce the signature itself.

This repository has exactly that weakness today. `aap-admin` runs on the same machine as the user's coding agents. If `AAP_ADMIN_PASSPHRASE` is set, any agent with shell access can run `echo y | aap-admin pairing sign <id>` and sign a delegation for itself: the confirmation is read from stdin, which the agent controls. Encryption at rest does not help when the attacker is a process running as the user.

AP2 names this role the **Trusted Surface** (a UI that MUST be non-agentic and obtains informed consent) but leaves the proof that a surface is trustworthy to the verifier's trust in an agent provider or credential issuer (see 0001, gap G1). This document defines a Trusted Surface whose trustworthiness a verifier can check.

## Threat model

**Assets:** the user's signing key, the user's intent (what they actually agreed to), the user's identity data (0003).

| ID | Attacker | Capabilities |
|---|---|---|
| T1 | Malicious or prompt-injected agent | Runs code on the user's computer as the user; can read files and environment, drive the terminal and browser, send requests anywhere. Cannot touch the phone's secure hardware. |
| T2 | Compromised agent provider | Controls the agent's backend and everything it sends, including the text it asks the user to approve. |
| T3 | Compromised Issuer Service | Controls relaying, logging and attestation endpoints. |
| T4 | Network attacker | Reads and modifies traffic it can reach. |
| T5 | Thief | Holds the unlocked or locked phone, without the user's biometrics. |
| T6 | Close insider | Household member, possibly enrolled in Face ID / fingerprint on the same phone; can coerce. |
| T7 | Curious verifier | Wants to track the user across services. |
| T8 | Compromised Issuer App | Our own app, modified or exploited. Holds an authenticated context after the user's Face ID. |

**Security goals:**

- **SG1** No mandate exists without the user's approval on the Trusted Surface.
- **SG2** What the user saw is exactly what was signed (WYSIWYS).
- **SG3** The agent can never use or extract the signing key.
- **SG4** Misuse is detectable by the user, even if prevention fails.
- **SG5** Every mandate is revocable by the user, and revocation reaches verifiers.
- **SG6** A verifier can tell *how strongly* SG1–SG3 hold for a given mandate (assurance level) and apply its own policy.

### What can and cannot be proven

"The human alone and truthfully approved" cannot be proven absolutely. Coercion (T6), a second enrolled face, or approving without understanding all remain possible. What the design can prove is a chain:

1. A specific hardware key signed, and that key never leaves the hardware.
2. The hardware only released the key after a fresh biometric or PIN check.
3. The signed bytes are the ones the user was shown.
4. The key belongs to a verified, unique person (0003, optional per assurance level).
5. The issuance was recorded in a log the user monitors.

Each link can be attacked separately; risk classes decide which links are mandatory. This is the same model that qualified electronic signatures and PSD2 strong customer authentication rely on: attribution with a stated assurance, not metaphysical certainty.

## Architecture

```
   Agent (laptop, server, browser)          User's phone
  ┌──────────────────────────┐          ┌──────────────────────────────┐
  │ builds Mandate Content   │          │ Issuer App (Trusted Surface) │
  │ holds agent key (cnf)    │          │  • renders content itself    │
  │ never sees user key      │          │  • hardware key, UV per use  │
  └────────────┬─────────────┘          │  • signs, logs locally       │
               │ 1. DelegationRequest   └──────────────┬───────────────┘
               ▼                                       │ 3. approve + sign
  ┌──────────────────────────────────────────┐         │
  │ Issuer Service                            │ ◄──────┘
  │  • relay + push (2.)                      │
  │  • attested-key credential issuance       │
  │  • status list (revocation)               │
  │  • transparency log                       │
  │  • usage ledger (optional)                │
  │  • NEVER holds or uses user keys          │
  └──────────────────────────────────────────┘
               │ 4. signed mandate back to the agent
               ▼
  Agent presents mandate + closed mandate to a Verifier (AP2 flow, 0004)
```

The Issuer App is a **separate app**, not a module of another product. It has one job, a small code base, and no network-facing features beyond what this document describes. A small app is easier to audit, and auditability is the selling point.

### Key management on the device

| Platform | Signing key | What the platform attests |
|---|---|---|
| iOS / iPadOS | P-256 key in the Secure Enclave, access control `privateKeyUsage` + `biometryCurrentSet` | **Confirmed on hardware (S1):** Apple does not attest individual Secure Enclave keys. **App Attest** attests a genuine instance of our app (team + bundle ID + environment) and its own App Attest key. At enrollment the app hashes the signing key's JWK thumbprint into the App Attest `clientDataHash`. That the key is in the Secure Enclave, non-exportable, and gated by Face ID is guaranteed only by our app's code, not attested. App Attest also cannot pin a build or version. |
| Android | P-256 key in StrongBox (or TEE), `setUserAuthenticationRequired(true)` with a per-use timeout of 0 and `BIOMETRIC_STRONG`/device credential | **Key Attestation** produces a certificate chain to Google's hardware root proving the key is hardware-backed and *which* user-authentication rules are bound to it. **Play Integrity** attests the app. This is stronger than iOS: the key's properties are attested directly. |
| Desktop (later) | Windows Hello (TPM), macOS Secure Enclave with Touch ID | Comparable patterns; not in the first release because the agent typically runs on the same desktop (T1). |

P-256 / ES256 is the only algorithm secure hardware on phones supports. aap-core already implements it (`keys.rs`).

Signatures are bound to the biometric operation itself (Android `BiometricPrompt` with a `CryptoObject`, iOS key usage gated by `LAContext`), not to an earlier unlock. A thief with an unlocked phone (T5) still cannot sign. S1 measured what this means on iOS:

- **"One Face ID per signature" is app behaviour, not hardware behaviour.** The Secure Enclave enforces "a biometric match happened in this `LAContext`". One authenticated context signed 200 payloads after a single Face ID, 5 ms each. A generic "unlock the app with Face ID" check, if its context is reused, silently authorizes later key use.
- **Rules for the Issuer App:** a new `LAContext` for every approval, used for exactly one signature, then `invalidate()`. Never share it with any other biometric check.
- **Device unlock does not count.** A recent Face ID unlock of the phone does not satisfy the key's access control; a fresh scan is shown.
- **There is no silent path.** Without an authenticated context the key refuses to sign.
- **No passcode fallback** with `biometryCurrentSet`: only Face ID unlocks the key. If the Face ID enrolment changes, the key becomes permanently unusable. The app must treat that as "key lost": generate a new key, enroll again, re-issue mandates. It can detect the change in advance through `LAContext.domainState`.
- **Signature encoding:** the Secure Enclave returns DER. JWS needs raw `r||s`, and about 1 in 256 coordinates is shorter than 32 bytes. Conversion must left-pad and be tested against real device output. The Secure Enclave does not normalise S: about 40% of signatures are high-S, so verifiers **must not require low-S** (0004).

### Enrollment

1. The app generates the signing key and obtains platform attestation (above). On iOS: `attestKey` with `clientDataHash = SHA256(server challenge || JWK thumbprint of the signing key)`. This calls Apple's servers (1.3–1.7 s in S1) and may be rate-limited, so it happens **once per key at enrollment**, never per mandate.
2. The Issuer Service verifies the attestation and stores the App Attest public key with the thumbprint it vouched for. The App Attest leaf certificate is valid for only about three days, so the chain is checked at enrollment and never re-checked later.
3. The Issuer Service issues an **Attested User Key credential**: an SD-JWT VC with `cnf` = the user's public key and claims for platform, attestation type (`app_attest` or `key_attestation`), user-verification method and assurance level (AL2-A or AL2-K, below).
4. Enrollment is written to the transparency log. Every other device of the same user is notified.

This credential is what turns AP2's *User Credential* model into something a verifier can check without trusting an agent provider: the verifier trusts the Issuer Service's published enrollment policy and checks the attestation chain.

### Issuing a mandate

1. The agent sends a **DelegationRequest** to the Issuer Service: proposed mandate content (open or closed, see below), the agent's public key, the agent's identity, a request id. The agent signs the request with its own key, so the user can see which agent asked.
2. The Issuer Service pushes the request to the user's devices. It validates the format and can apply policy (rate limits, cooling-off periods for high-risk classes) but cannot change the content: the agent's signature covers it.
3. The Issuer App **renders the content itself** (rules below), shows the requesting agent, the risk class and, for an extension of an existing mandate, the difference to it.
4. The user approves with biometrics or PIN. The app signs the mandate as a Delegate SD-JWT with the user key (format in 0004) and returns it via the Issuer Service. On iOS the app adds an **App Attest assertion over `SHA256(mandate)`**, which ties every mandate to the attested app instance. Its monotonic counter gives ordering and detects a cloned instance (S1: 15–19 ms, no prompt).
5. The mandate's hash is appended to the transparency log; a status-list entry is allocated for revocation.

The same flow also works locally over OpenID4VP with the Digital Credentials API when the agent runs in a browser on the same phone. That is the delegation path AP2 itself describes, so standard AP2 agents can talk to the Issuer App without the relay.

Two kinds of mandates are approved this way:

- **Standing (open) mandate:** constraints approved in advance; the agent later acts alone within them. Example: groceries up to €80 per order at three named shops for one month.
- **Per-action (closed) mandate:** the user approves one concrete action. Example: a bank transfer above a threshold, a contract signature. This is AP2's "human present" mode.

Risk class (from the use-case catalogue, later) decides which kind a verifier accepts.

## What you see is what you sign

The most underestimated attack is not stealing the key but getting the user to sign something other than what they think (T2). Rules:

1. **The app renders every human-readable line from the structured content**, with a deterministic renderer per mandate type and constraint `type`. Example: `payment.amount_range {max: 8000, currency: EUR}` → "up to €80.00 per payment". Text supplied by the agent is never shown as if it were the content.
2. **Unknown constraint types are not signable.** If the renderer cannot express a constraint, the app refuses, mirroring AP2's rule that verifiers treat unknown constraints as failing.
3. **Agent-supplied explanations** (purpose, reasoning) may be shown, visually separated and labelled "the agent says". They are not part of what the renderer vouches for.
4. **Amounts, payees and validity are always shown**, in the user's locale, with the currency spelled out. The signature covers them (the PSD2 "dynamic linking" principle).
5. **The renderer is part of the specification.** Each constraint definition includes its canonical rendering, so two independent Issuer Apps show the same thing and an auditor can check the mapping.
6. **UI hardening:** no overlays (Android `filterTouchesWhenObscured`, no approval while another app draws on top); screenshots of the approval screen are blocked; the approve button is disabled for a short moment after the screen appears (against tap-jacking and reflexive taps).

Where the platform offers a confirmation UI controlled by secure hardware (Android Protected Confirmation on supported devices), the app should use it for per-action mandates. Device support is limited and its current status needs checking before relying on it.

## Assurance levels

| Level | Key | Proof of the human | Typical use |
|---|---|---|---|
| **AL0** | Software key | None | Development, tests, internal automation (today's `aap-admin`) |
| **AL1** | Software key, encrypted at rest | Passphrase | Low-risk reads |
| **AL2-K** (key-attested) | Hardware key whose properties are attested (Android Key Attestation: StrongBox/TEE, user authentication per use) | Biometric or PIN per signature, enforced by the attested key; WYSIWYS renderer | Shopping, bookings, subscriptions |
| **AL2-A** (app-attested) | Hardware key, attested app instance (iOS App Attest) plus an App Attest assertion on every mandate | Biometric per signature and rendering **guaranteed by the attested app's audited code**, not by the platform | Same as AL2-K. Verifiers that want platform-level proof can require AL2-K |
| **AL3** | As AL2 | AL2 + Verified Human Credential (0003) bound to the same key | Payments above thresholds, age-restricted goods, anything needing uniqueness |

The level is a claim in the Attested User Key credential, so it is signed by the Issuer Service and checkable by any verifier. The two AL2 variants exist because S1 confirmed that iOS cannot attest the key's properties. The difference is stated openly instead of claiming more than the platform proves. In production only attestations from the **production** App Attest environment count; development attestations are a policy reject. Binding to a state eID (EUDI Wallet, ID Austria) is deferred. It would become a further level for authorities and contracts.

Passkeys (WebAuthn) are a possible AL2 alternative on platforms where the app is unavailable. Caveats: a WebAuthn assertion is not a plain JWS (it signs `authenticatorData || hash(clientData)`), so it needs its own proof format; synced passkeys are not device-bound and usually carry no attestation.

## Issuer-app policy

Because AL2-A rests on trust in the app's code, that trust has to be pinned and auditable. The Issuer Service publishes a signed **issuer-app policy** that verifiers can reference:

- which team and bundle IDs count as Trusted Surfaces;
- the signing rules: one fresh `LAContext` per approval, invalidated after one signature, no reuse of other biometric checks;
- the deterministic renderer (by version), so anyone can re-render a signed mandate and see what the user saw;
- the minimum app version. App Attest cannot pin a build, so the app writes its version into the signed mandate metadata; that value is self-asserted but covered by the App Attest assertion.

The threat-model boundary has to be explicit. A prompt-injected or compromised **agent** cannot sign: it runs in another process and holds neither the key nor an authenticated context. A compromised **Issuer App** can batch-sign after a single Face ID. That is exactly what AL2-A trusts, and why the app must stay small and audited.

## Issuer Service

Responsibilities:

- **Relay** DelegationRequests and push them to the user's devices.
- **Enrollment and Attested User Key credentials** (above).
- **Revocation:** an IETF Token Status List per issuer; every mandate carries a `status` reference. This answers Delegate SD-JWT's open revocation problem (0001, G3): the user revokes in the app, the service publishes, verifiers check.
- **Transparency log:** an append-only Merkle log (in the style of Certificate Transparency) of **enrollments and mandate hashes**, never contents. The user's devices monitor it and alert on any enrollment or mandate they did not produce. Verifiers *may* require an inclusion proof for AL2+ mandates. Then no mandate can be used without being visible to the user ("no secret mandates").
- **Usage ledger (optional):** for budget and recurrence constraints that span several verifiers (0001, G4). A verifier reserves against the ledger before accepting. For *payments*, the AP2 Credential Provider already sees every payment with an instrument and is the natural place to enforce budgets; the AAP ledger is for non-payment budgets (e.g. "at most 20 messages a day across services").
- **Evidence store (optional):** the user's encrypted copy of mandates and receipts for disputes (0001, G7).

What it must never do: generate, hold, back up or use a user's signing key. If the Issuer Service is fully compromised (T3), the attacker can drop or delay requests, lie about status, and enroll a rogue device for a user. The last one is the critical case: the transparency log makes rogue enrollments visible to the user's existing devices, and AL3 makes them require a fresh passport check (0003).

## Threats and mitigations

| Threat | Mitigation | Remaining risk |
|---|---|---|
| T1 agent signs for itself | Key exists only in phone hardware; signature needs biometrics; no silent signing path (S1) | Agent on the *same* phone: OS sandbox + UV per signature; UI-spoofing hardening |
| T8 compromised Issuer App | Small audited code base; issuer-app policy; App Attest assertion + counter per mandate; transparency log shows every mandate | Can batch-sign after one Face ID (S1). This is the trust AL2-A places in the app |
| T2 misleading content | App-side deterministic rendering; unknown constraints not signable | User approves without reading. Mitigate with risk-based friction and cooling-off |
| T3 compromised service | Never holds keys; log monitored by devices; attestation verifiable by third parties | Denial of service; delayed revocation |
| T4 network | Everything signed end-to-end; TLS | Metadata visible to the network |
| T5 thief | Per-use UV bound to the key operation | Weak device PIN |
| T6 insider / coercion | Only partly addressable: `biometryCurrentSet` invalidates the key when a new biometric is enrolled; cooling-off and limits for high risk; quick revocation | Coercion itself |
| T7 tracking verifier | Selective disclosure; pairwise pseudonyms (0003); batch-issued credentials | Correlation through payment data outside AAP |

## Consequences for this repository

- `aap-admin` becomes an AL0 tool for development and server-to-server automation. Its documentation must say so. Device-pairing flows built on it would move to the Issuer App once that exists.
- Until then, quick hardening of `aap-admin`: remove the `AAP_ADMIN_PASSPHRASE` shortcut from interactive commands, read the confirmation from the terminal device rather than stdin, show the scope rendered locally instead of as server-supplied JSON.

## Open questions

1. ~~Platform order~~ **Working assumption: iOS first** (no Android test device). Spike S1 is done; Android follows for AL2-K.
2. **Cooling-off and friction:** which thresholds trigger a delay or a second confirmation? This depends on the use-case catalogue.
3. **Who operates the Issuer Service and the log**, and do we want a second, independent log operator from the start (the CT model needs more than one)?
4. **Multiple devices:** can a user enroll several phones, and must every mandate be logged so the other devices can see it?
5. **Recovery when all devices are lost:** at AL3 via a new passport check (0003). At AL2 — by account recovery, which is exactly what an attacker would target. Possibly AL2 has no recovery: new enrollment, old mandates revoked.
