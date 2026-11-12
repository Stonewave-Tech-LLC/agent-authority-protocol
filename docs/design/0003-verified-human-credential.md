# 0003 — Verified Human Credential

- **Status:** Draft
- **Date:** 2026-10-18
- **Working position (draft, not decided):** The anchor of a user's identity is the NFC chip in their passport or national ID card, whose data is signed by the issuing state. Verification happens on the phone wherever possible. The Issuer Service keeps only keyed, non-reversible tags. Verifiers receive a selectively disclosable credential ("verified unique human, over 18, pseudonym X") and never the identity itself. Integration with state eID schemes is deliberately out of scope for now.

## Problem

A merchant that accepts agent orders wants to trust one or a few known parties, **never the user's own claims**. In practice it needs:

1. **Non-repudiation**: a mandate demonstrably from the account holder (0002).
2. **Uniqueness**: one human is one customer, so a thousand agent accounts cannot farm promotions or evade bans.
3. **Attributes on demand**: age above a threshold, sometimes country.
4. Usually **not** the name, date of birth or document number.

So the goal is a credential that is practically unforgeable, bound to the user's hardware key, and reveals as little as possible.

## Why combining identity attributes cryptographically is not enough

An earlier idea was to combine identity attributes (name, document number, …) into a hash. Two fundamental problems:

1. **A hash proves nothing about truth.** Anyone can compute `hash(name ‖ document number)` from invented or stolen data. Unforgeability comes from *someone having verified* that the data is genuine and belongs to the person present. Cryptography can bind and protect a verified statement; it cannot create the verification.
2. **Identity data has little entropy.** A document number has a few hundred million possible values; with the name known, the space is searchable in minutes. An unkeyed hash, with or without salt, is reversible by whoever holds the salt. "Not reconstructable" needs a **secret key** in the hash (HMAC or an OPRF), held in an HSM and rate-limited.

## Anchor: the document chip (ICAO 9303)

Passports and the Austrian national ID card carry an NFC chip with the holder's data, digitally signed by the issuing state. Checking it needs no contract with any state system, only the public certificates.

| Check | What it proves | Mechanism |
|---|---|---|
| Chip access | The user physically holds the document | PACE (or legacy BAC) with keys derived from the MRZ or the card access number |
| **Passive Authentication** | The data is unmodified and state-issued | The Document Security Object (SOD) holds hashes of all data groups, signed by a Document Signer certificate that chains to the country's CSCA certificate (from published CSCA master lists / the ICAO PKD) |
| **Active Authentication** or **Chip Authentication** | The chip is genuine, not a clone | Challenge-response with a key that never leaves the chip (DG15 or DG14) |
| Liveness + face match | The person in front of the camera is the holder, not someone with a stolen document | On-device comparison of a live capture with the photo in DG2 |

Data groups used: **DG1** (MRZ data: names, date of birth, nationality, document number, expiry) and **DG2** (face image). Fingerprints and iris data (DG3/DG4) are protected by Extended Access Control and are neither accessible nor wanted.

Both iOS and Android can read these chips over NFC; commercial identity-verification providers work the same way. Forging the result would require forging a state signature.

## Verification flow

The design keeps the photo and biometric data on the device, and sends to the server only what the server must verify.

1. **On the phone (Issuer App):** read the chip (PACE), get DG1, DG2, SOD (and DG14/DG15).
2. **On the phone:** verify that DG2 matches its hash in the SOD; run liveness and face match against DG2. The photo and the live capture are discarded afterwards.
3. **Phone → Issuer Service:** SOD + DG1 + the face-match result, signed with the attested app key (0002). For Active Authentication, the **server chooses the challenge** and the app only relays it to the chip, so the server verifies the chip's signature itself. The app cannot fake a genuine chip.
4. **Issuer Service:** verify the SOD signature chain to the CSCA, verify DG1 against its SOD hash, verify the chip-authentication response, check document expiry.
5. **Issuer Service, inside the HSM:** compute the uniqueness tags (below) from DG1. **DG1 is held in memory only for this step and then discarded.**
6. If no conflicting tag exists, issue the Verified Human Credential bound to the user's Attested User Key (`cnf`), and log the enrollment (0002).

What the server never receives: the photo, the live capture, biometric templates. What it never stores: DG1 or anything derived from it except keyed tags.

## Uniqueness without storing identity

Two keyed tags, computed with a secret key that exists only inside an HSM:

```
person_tag   = HMAC(K_person,   normalized(primary name, secondary names, date of birth, sex))
document_tag = HMAC(K_document, issuing state ‖ document number)
```

- `person_tag` recognises the same person across document renewals (a new passport gets a new number).
- `document_tag` recognises the same document even if name normalisation differs.
- Neither can be reversed without the HSM, and the HSM rate-limits evaluations, so an insider cannot brute-force them either.

Known limitations, to be decided on:

- **Name changes** (e.g. marriage) produce a new `person_tag`. The old document's `document_tag` still links them if the old document is presented once more.
- **Dual nationals with two passports** could enroll twice if names differ between documents. Nationality is deliberately *not* in `person_tag`, so identical names and birth dates still collide correctly.
- **Collisions** of common names with the same birth date are possible. A collision must lead to a manual review path, never to silently treating two people as one.

A stronger variant would have the server never see DG1 at all: the phone proves in zero knowledge that a tag was derived from data the state signed. Existing projects that build zero-knowledge proofs over passport chips (e.g. Self, ZKPassport) should be evaluated for this as a v2 option. They have not been reviewed yet.

## The credential

An SD-JWT VC (format details in 0004). Always visible: `iss`, `vct`, `cnf` (the user's hardware key from 0002), `status`, `iat`, `exp`. Selectively disclosable:

| Claim | Example | Purpose |
|---|---|---|
| `age_over_16`, `age_over_18`, `age_over_21` | `true` | Age checks without birth date |
| `issuing_country` | `AT` | Country-specific rules |
| `chip_auth` | `active` / `chip` / `none` | Lets verifiers discount documents without anti-cloning |
| `verified_at` | timestamp | Freshness policies |
| `pseudonym` | per verifier, see below | Uniqueness *at this verifier* |

Not included at all: name, date of birth, document number, photo. `exp` is the earlier of the document's expiry and one year, after which a new chip scan renews it.

### Pseudonyms per verifier

A merchant needs a stable identifier to recognise the same human, but no two merchants should be able to correlate their customers.

- **v1 (SD-JWT):** `pseudonym = HMAC(K_pseudo, person_tag ‖ verifier_id)`, computed by the Issuer Service when the app requests a credential for a specific verifier. Cost: the Issuer Service learns which verifiers a user presents to. This must be stated openly in the privacy policy.
- **v2 (BBS):** BBS signatures with per-verifier pseudonyms (IRTF CFRG drafts) let the phone derive a verifiable pseudonym itself, without the issuer learning the verifier. The issuer enforces "one credential per `person_tag`", which makes the pseudonym unique per human. This is the target design once libraries and hardware support are mature enough.

### Linkability of presentations

The issuer signature and `cnf` key of an SD-JWT VC are the same in every presentation, which makes presentations correlatable across verifiers even with selective disclosure. Mitigation as in the EU wallet ecosystem: **batch issuance**, i.e. several credentials, each bound to its own hardware key, used once or per verifier. BBS (v2) removes the problem structurally.

## Accountability in case of fraud

Without stored identity, the only recourse is revocation: the credential and the person's uniqueness tag can be blocked, but nobody can name the person. Options:

- **A — no escrow.** Maximum privacy. Fraud leads to blocking, not identification. Disputes are settled with mandates and receipts.
- **B — threshold escrow.** At enrollment, DG1 is encrypted to a key split among independent trustees (e.g. 2 of 3: operator, a law firm, a notary). Decryption happens only on a court order and is itself logged in the transparency log.

Not decided yet. B makes the system more attractive to merchants and payment providers, A makes it simpler and is easier to defend under data protection law.

## Threats

| Threat | Mitigation | Remaining risk |
|---|---|---|
| Stolen document | Liveness + face match against DG2 | Look-alike; mitigated by threshold tuning |
| Forged data | Passive Authentication against CSCA | Compromise of a state's signing keys (handle via a per-country trust list) |
| Cloned chip | Active/Chip Authentication with a server challenge | Older documents without either (flagged as `chip_auth: none`) |
| Injected camera feed / deepfake | Liveness on device, app attestation (0002) | Sophisticated injection on rooted devices; acceptable for AL3 shopping limits, not for high-value use |
| Sybil via many real documents | Uniqueness tags | Buying identities from real people. Cannot be fully prevented; it is also costly for the attacker |
| Insider brute-forcing tags | Keys only in HSM, rate limits, audit log | HSM compromise |
| Tracking by verifiers | Pairwise pseudonyms, selective disclosure, batch issuance | Correlation through delivery addresses and payment data outside AAP |

## Data protection (to be reviewed by a lawyer)

- Face matching for identification is processing of biometric data under GDPR Article 9: it needs explicit consent. Doing it **only on the device, without storing templates**, keeps the risk small.
- A data protection impact assessment will be required before launch.
- Data minimisation is a design property here, not a policy promise: the server cannot leak what it never stores.

## Open questions

1. **Escrow:** option A or B?
2. **Collision handling:** what is the manual review path, and who runs it?
3. **Pseudonym v1:** accept that the Issuer Service learns verifier relationships, or wait for BBS?
4. **Older documents** without Active or Chip Authentication: accept with a flag, or reject?
5. **Liveness and face matching:** build on-device models ourselves or license an SDK that runs fully offline?
