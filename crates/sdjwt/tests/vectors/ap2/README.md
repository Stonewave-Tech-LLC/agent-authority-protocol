# AP2 v0.2 interop test vectors

Test vectors for checking `aap-sdjwt` against the Agent Payments Protocol (AP2)
v0.2 reference SDK (Python). Generated with the SDK itself, using throwaway keys.

- SDK: <https://github.com/google-agentic-commerce/AP2>, commit
  `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (2026-04-29, CHANGELOG 0.2.0)
- Files:
  - `ap2_vectors.json` — the vectors (one fixed snapshot)
  - `gen_vectors.py` — the generator

**Test keys only.** Every key is generated fresh when the script runs. Only
public JWKs are written out (`jwks.keys`); no private key leaves the process.
No real credentials, payment instruments or merchants are involved; all names
and domains are `example.*` placeholders.

## Contents

32 vectors in `ap2_vectors.json`, each with `id`, `type`, `description`,
`token`, `expected_valid` and `sdk_result` (what the reference SDK answered).

| `type` | positive | negative |
| --- | --- | --- |
| `open_checkout_mandate` | valid | wrong issuer key, tampered disclosure |
| `open_payment_mandate` | valid | wrong issuer key, tampered disclosure |
| `closed_checkout_mandate` | HNP chain, HP single | wrong `cnf` key, mismatched `checkout_hash` (HNP and HP), wrong audience, tampered disclosure |
| `closed_payment_mandate` | HNP chain, HP single | wrong `cnf` key, amount above `AmountRange.max`, mismatched `transaction_id`, wrong key (HP), tampered disclosure (HNP and HP) |
| `merchant_checkout_jwt` | valid | tampered payload, wrong key |
| `checkout_receipt` | valid | wrong key, unknown reference, mismatched reference |
| `payment_receipt` | valid | wrong key, mismatched reference, tampered payload |

`flow` is `human_present` (closed mandate signed directly by the user key, a
single root SD-JWT) or `human_not_present` (open mandate signed by the user key
`~~` closed mandate signed by the agent key named in `cnf`).

Extra fields where relevant: `verify_with` (key name in `jwks.keys`),
`expected_aud` / `expected_nonce` (for chains), `checkout_jwt`,
`expected_checkout_hash`, `expected_transaction_id`,
`expected_open_checkout_hash`, `known_references` (receipts).

How to read `expected_valid`: it is the verdict a conforming implementation
should reach for the *whole* check named in the description (signature chain
plus the binding or constraint check where one applies). In a few cases the
reference SDK's single-token verify says `ok: true` where `expected_valid` is
`false`; those are marked `sdk_disagrees_with_expected` (see below).

## Regenerating

Python 3.11+.

```sh
git clone https://github.com/google-agentic-commerce/AP2.git
git -C AP2 checkout e1ea56db72a6385bce3e5c1112b3a56ce60acb43
python -m venv venv && . venv/bin/activate   # or: virtualenv venv
pip install cryptography==46.0.5 jwcrypto==1.5.6 pydantic==2.12.5 sd-jwt==0.10.4
python gen_vectors.py --ap2-repo ./AP2 --out ap2_vectors.json
```

No LLM API keys, no ADK/Gemini sample agents and no payment credentials are
needed; the script only imports from `ap2.sdk`.
Regenerating gives different bytes (fresh keys, randomized ES256 signatures),
so treat the committed JSON as the fixed snapshot and re-commit it as a whole.

## Where the SDK differs from, or is silent about, the spec text

Observed at the pinned commit. Items marked (spec) are contradictions between
documents; (sdk) are SDK behaviors you may trip over when comparing results.

1. **Amount units (spec).** `Amount.amount` and `AmountRange.min/max` are
   integers in ISO 4217 minor units (spec example: `19900`). `Budget.max` is a
   `float` with no unit stated and the spec example is `1000.00`.
   `BudgetEvaluator` converts it with `int(max * 100)`, i.e. it treats it as
   decimal major units with a hard-coded exponent of 2.
2. **Budget rounding and currency exponent (sdk).** `int(19.99 * 100)` is
   `1998`, so a decimal budget can be truncated by one minor unit. The
   factor `100` is also wrong for currencies with other exponents (JPY, KWD).
3. **`vct` strings (spec).** The spec and generated models use
   `mandate.checkout.1`, `mandate.checkout.open.1`, `mandate.payment.1`,
   `mandate.payment.open.1`. Some field descriptions and the SDK README table
   still say `mandate.checkout` / `mandate.payment` (no suffix).
4. **`payment.reference` meaning (spec).** The spec says the constraint holds
   the hash of the open Checkout Mandate (without saying which part of the
   SD-JWT is hashed). `PaymentReferenceEvaluator`'s docstring says the closed
   payment's `transaction_id` must equal it, but the code compares it with a
   caller-supplied `open_checkout_hash`. The vectors use
   `base64url(sha256(root JWT of the open checkout mandate))`, which is our
   reading, not a documented rule.
5. **`checkout_hash` is not checked by the SDK itself (sdk).** The spec says
   the merchant MUST verify it against `checkout_jwt`.
   `CheckoutMandateChain.verify` only compares it with a hash the caller
   passes in, and does nothing if none is passed. A single human-present token
   with a wrong `checkout_hash` verifies fine
   (`closed-checkout-hp-mismatched-checkout-hash`).
6. **Merchant signature on `checkout_jwt` is not verified (sdk).**
   `extract_parsed_checkout_object` base64-decodes and validates the payload
   but never verifies the merchant's signature. Test fixtures use
   `hdr.<payload>.sig` placeholders. The merchant JWT vectors here are really
   signed (ES256).
7. **Tampered disclosures can be silently dropped (sdk).** For a root SD-JWT
   with an altered disclosure, `MandateClient.verify` returned success and the
   claim simply disappeared (e.g. `allowed: []`). For chains, the next hop's
   `sd_hash` catches it. Per the SD-JWT spec a verifier should reject
   disclosures that match no digest; please double-check that reading against
   RFC 9901 before relying on it. The checkout spec text also says an empty
   `allowed` list makes the constraint invalid.
8. **`ReceiptClient.verify_receipt` signature (sdk).** The type hint says
   `ec.EllipticCurvePublicKey`, but it passes the key to `verify_jwt`, which
   needs a `jwcrypto.JWK`; the documented call fails with
   `Unrecognized key type` (recorded in `sdk_result.documented_call_with_pyca_key`).
   With a `JWK` it works. `has_reference_in_store_cb=None` (the default) raises
   `TypeError`.
9. **Receipt `iss` (sdk).** `create_payment_receipt` sets `iss` to `''` when the
   payment mandate has no `pisp`.
10. **Upstream tests.** At this commit two SDK tests fail:
    `kb_sd_jwt_intermediate_tests.py::test_verify_rejects_aud_mismatch` and
    `::test_verify_rejects_nonce_mismatch` (186 pass). `verify_chain` only
    enforces `expected_aud` / `expected_nonce` on the terminal hop.
