//! The example tokens in AP2 v0.2 (docs/ap2/agent_authorization.md).
//!
//! None of AP2's example tokens is complete: every compact token and every
//! signature is truncated, and the doc shows decoded disclosures as JSON,
//! not as their encoded strings. What *is* checkable: re-encoding a
//! disclosure exactly as AP2's Python SDK does (`json.dumps` default
//! separators) must give the digest printed in the matching payload. Three
//! of five do; the other two expose errors in the AP2 doc, pinned below so a
//! fix upstream shows up here.
//!
//! The payloads themselves are run through this crate's verifier by
//! re-signing them with a test key (the published signatures cannot be
//! checked anyway), so disclosure processing runs on AP2's exact JSON.

mod common;

use aap_sdjwt::{ErrorKind, KeyBinding, Position, SdAlg, SigningKey, VerifyOptions};
use common::*;
use serde_json::{json, Value};

/// The decoded "Core SD-JWT Payload" of the Digital Payment Credential.
fn dpc_payload() -> Value {
    json!({
        "iss": "https://digital-credentials.dev",
        "vct": "com.emvco.dpc",
        "iat": 1683000000,
        "exp": 1883000000,
        "_sd_alg": "sha-256",
        "_sd": [
            "0ygSIMbyCz_SAL7CrZeDg_C3AnqJVgf35I1t1ie0RZs",
            "1ipSejAAw_lASOeNsGbj3R_3MZNRtalgU9MYvc73Z5g",
            "3d_ksLaY7NAyu9PQZodRB4XsqF2jquCsl2avOlnWCn8",
            "PBhW42ATJqcs3_odVhHuTGEDhN7idDmZMLLORR-lAec"
        ],
        "cnf": {
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "8jBWriuJBY--u__2jOJfcX4Jj4kEqY4CUX9cf1bQddY",
                "y": "csH2kOGhlemhRRuPUYFKJYZgVqEXQh2JfotRKGRMfLE"
            }
        }
    })
}

/// The disclosures as AP2's SDK encodes them: Python `json.dumps` with its
/// default `", "` separators.
const CARD_LAST_FOUR: &str = r#"["bZNpmTeoL5tYU7gKTVkTUA", "card_last_four", "4444"]"#;
const CARD_NETWORK: &str = r#"["Bu8Gie949nAgBdL6B657Mw", "card_network_code", "ACME"]"#;
const CREDENTIAL_ID: &str =
    r#"["MQ8lrNkAwYlavMT8own4DA", "credential_id", "b3f1c8a2-6d4e-4f9a-9e3d-8a7c2f1b9d34"]"#;
const ACCEPTABLE_ITEM: &str = r#"["vK5dz2nnVpgtoC9dZy9uHw", {"id": "supershoe_limited_edition_gold_sneaker_womens_9_0", "title": "SuperShoe Limited Edition Gold"}]"#;
const MERCHANT: &str = r#"["NAhMECHMBjd978UDQqsAYA", {"id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example"}]"#;

fn digest(disclosure_json: &str) -> String {
    SdAlg::Sha256.digest(&b64(disclosure_json))
}

/// Re-signs `payload` as a root SD-JWT and verifies it with `disclosures`.
fn process_as_root(
    payload: Value,
    disclosures: &[&str],
    now: i64,
) -> Result<Value, aap_sdjwt::Error> {
    let key = SigningKey::generate_p256();
    let jwt = forge(json!({"alg": "ES256", "typ": "dc+sd-jwt"}), payload, &key);
    let mut presentation = format!("{jwt}~");
    for d in disclosures {
        presentation.push_str(&b64(d));
        presentation.push('~');
    }
    let options = VerifyOptions::new(now, "dc+sd-jwt", KeyBinding::NotRequired);
    let chain = verify(&presentation, &key.verifying_key(), &options)?;
    Ok(Value::Object(chain.root().claims().clone()))
}

#[test]
fn dpc_card_disclosures_match_the_credential_digests() {
    let sd: Vec<String> = dpc_payload()["_sd"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().to_owned())
        .collect();
    assert!(sd.contains(&digest(CARD_LAST_FOUR)));
    assert!(sd.contains(&digest(CARD_NETWORK)));

    let claims = process_as_root(dpc_payload(), &[CARD_LAST_FOUR, CARD_NETWORK], NOW).unwrap();
    assert_eq!(claims["card_last_four"], "4444");
    assert_eq!(claims["card_network_code"], "ACME");
    assert!(claims.get("_sd").is_none());
}

#[test]
fn ap2_doc_inconsistency_credential_id_disclosure_has_no_digest() {
    // AP2 shows three disclosures "revealed" from this credential, but the
    // credential_id disclosure hashes to a digest the payload does not
    // contain. An RFC 9901 verifier must reject the presentation.
    let sd = dpc_payload()["_sd"].clone();
    assert!(!sd
        .as_array()
        .unwrap()
        .contains(&json!(digest(CREDENTIAL_ID))));
    let err = process_as_root(
        dpc_payload(),
        &[CARD_LAST_FOUR, CARD_NETWORK, CREDENTIAL_ID],
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::UnreferencedDisclosure);
    assert_eq!(err.position(), Some(Position::Root));
}

/// The decoded open checkout mandate from the Trusted Agent Provider
/// example. Its `cnf` coordinates are truncated in the doc ("7MAQoKtK..."),
/// which only matters for the wrapping disclosure, not the nested ones.
fn open_checkout_mandate() -> Value {
    json!({
        "vct": "mandate.checkout.open.1",
        "iat": 1777326189,
        "exp": 1777329789,
        "constraints": [
            {
                "type": "checkout.line_items",
                "items": [{
                    "id": "line_1",
                    "quantity": 1,
                    "acceptable_items": [
                        {"...": "LqZRRzN7nzxJCVf0kP5OvvWvits5CcATHkoq_xGoz8s"}
                    ]
                }]
            },
            {
                "type": "checkout.allowed_merchants",
                "allowed": [
                    {"...": "UZSGFNQpapJSRQLCeVDfqGzfMCUiJvLL80_kcDai_OI"}
                ]
            }
        ]
    })
}

#[test]
fn allowed_merchant_disclosure_matches_the_open_mandate() {
    assert_eq!(
        digest(MERCHANT),
        "UZSGFNQpapJSRQLCeVDfqGzfMCUiJvLL80_kcDai_OI"
    );
    let claims = process_as_root(open_checkout_mandate(), &[MERCHANT], 1777326199).unwrap();
    assert_eq!(
        claims["constraints"][1]["allowed"],
        json!([{"id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example"}])
    );
    // The acceptable item was not disclosed, so its slot disappears.
    assert_eq!(
        claims["constraints"][0]["items"][0]["acceptable_items"],
        json!([])
    );
}

#[test]
fn ap2_doc_inconsistency_acceptable_item_digest_has_a_typo() {
    // The doc prints ...OvvWvits5... where the disclosure hashes to
    // ...OvvWVits5... (one character's case). The nested disclosure is then
    // unreferenced and the presentation must be rejected.
    let computed = digest(ACCEPTABLE_ITEM);
    assert_eq!(computed, "LqZRRzN7nzxJCVf0kP5OvvWVits5CcATHkoq_xGoz8s");
    let printed =
        open_checkout_mandate()["constraints"][0]["items"][0]["acceptable_items"][0]["..."].clone();
    assert_ne!(printed, json!(computed));
    let err = process_as_root(
        open_checkout_mandate(),
        &[ACCEPTABLE_ITEM, MERCHANT],
        1777326199,
    )
    .unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::UnreferencedDisclosure);
}

#[test]
fn an_ap2_shaped_chain_splits_the_way_the_ap2_sdk_splits_it() {
    // AP2's SDK finds the closed mandate JWT as
    // `token.rsplit("~~", 1)[-1].split("~", 1)[0]` and hashes it for the
    // receipt reference. Our serialization must agree on what that is.
    let parties = Parties::new();
    let presentation = parties.closed();
    let chain = verify(
        &presentation,
        &parties.issuer.verifying_key(),
        &terminal_options(),
    )
    .unwrap();
    let ap2_closed_jwt = presentation
        .rsplit_once("~~")
        .unwrap()
        .1
        .split('~')
        .next()
        .unwrap();
    assert_eq!(
        Some(ap2_closed_jwt),
        chain.leaf().sd_jwt().split('~').next()
    );
    assert_eq!(chain.leaf().claims()["vct"], "mandate.checkout.1");
    assert_eq!(presentation.split("~~").count(), 3);
}
