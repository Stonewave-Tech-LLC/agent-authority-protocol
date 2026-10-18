//! Format-level checks against the AP2 v0.2 interop vectors
//! (`vectors/ap2`, generated with the AP2 Python SDK at e1ea56d).
//!
//! AP2 issues user-signed mandates as a root SD-JWT whose payload is a
//! Delegate Payload ([`RootForm::DelegatePayload`]). This crate checks only
//! the format: signatures, `sd_hash`, disclosures, `typ`, `aud`/`nonce`.
//! Vectors whose defect is semantic (a `checkout_hash`, an amount, a
//! `transaction_id`) are format-valid here and rejected by `aap-authority`,
//! whose own test runs all 32 end to end.

mod common;

use aap_sdjwt::{
    verify_jwt, ErrorKind, KeyBinding, LinkKind, Position, Presentation, RootForm, SdJwtBuilder,
    SdPayload, SigningKey, Unverified, VerifyOptions, VerifyingKey,
};
use common::*;
use serde_json::{json, Value};

const AP2_ROOT_TYP: &str = "example+sd-jwt";

/// Defects only the policy layer can see.
const SEMANTIC: &[&str] = &[
    "closed-checkout-hnp-mismatched-checkout-hash",
    "closed-checkout-hp-mismatched-checkout-hash",
    "closed-payment-hnp-amount-exceeds-constraint",
    "closed-payment-hnp-mismatched-transaction-id",
    "checkout-receipt-unknown-reference",
    "checkout-receipt-mismatched-reference",
    "payment-receipt-mismatched-reference",
];

fn doc() -> Value {
    vector_json("ap2/ap2_vectors.json")
}

fn key(doc: &Value, name: &str) -> VerifyingKey {
    VerifyingKey::from_jwk(&doc["jwks"]["keys"][name]).unwrap()
}

fn check(doc: &Value, v: &Value) -> Result<(), aap_sdjwt::Error> {
    let now = doc["generated_at_unix"].as_i64().unwrap() + 60;
    let token = v["token"].as_str().unwrap();
    let field = |name: &str| v[name].as_str();
    if !v["type"].as_str().unwrap().contains("mandate") {
        return verify_jwt(token, &key(doc, field("verify_with").unwrap()), &["JWT"]).map(|_| ());
    }
    let (issuer, binding) = match field("flow") {
        Some("human_not_present") => (
            key(doc, "user"),
            KeyBinding::TerminalLink {
                audience: field("expected_aud").unwrap().into(),
                nonce: field("expected_nonce").unwrap().into(),
            },
        ),
        _ => (
            key(doc, field("verify_with").unwrap()),
            KeyBinding::NotRequired,
        ),
    };
    let options = VerifyOptions {
        root_form: RootForm::DelegatePayload,
        ..VerifyOptions::new(now, AP2_ROOT_TYP, binding)
    };
    Unverified::<Presentation>::parse(token)?
        .verify(&issuer, &options)
        .map(|_| ())
}

#[test]
fn format_verdicts_match_the_vectors() {
    let doc = doc();
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 32);
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let expected = v["expected_valid"].as_bool().unwrap() || SEMANTIC.contains(&id);
        let result = check(&doc, v);
        assert_eq!(result.is_ok(), expected, "{id}: {result:?}");
    }
}

#[test]
fn tampered_root_disclosures_are_rejected_unlike_the_sdk() {
    // RFC 9901 §7.1: a disclosure no digest references is an error. The AP2
    // SDK dropped it and returned `allowed: []`.
    let doc = doc();
    for v in doc["vectors"].as_array().unwrap() {
        if v["id"].as_str().unwrap().contains("tampered-disclosure") {
            let err = check(&doc, v).unwrap_err();
            assert_eq!(
                err.kind(),
                &ErrorKind::UnreferencedDisclosure,
                "{}",
                v["id"]
            );
            assert_eq!(err.position(), Some(Position::Root));
        }
    }
}

#[test]
fn delegate_form_root_round_trips() {
    let user = SigningKey::generate_p256();
    let agent = SigningKey::generate_p256();
    let payload = SdPayload::new(obj(json!({
        "vct": "mandate.payment.open.1",
        "iat": NOW - 60,
        "exp": NOW + 3600,
        "cnf": agent.verifying_key().to_cnf(),
        "constraints": [{"type": "payment.allowed_payees", "allowed": [{"id": "m1", "name": "M"}]}]
    })))
    .conceal("/constraints/0/allowed/0");
    let root = SdJwtBuilder::delegate_form(AP2_ROOT_TYP, payload)
        .sign(&user)
        .unwrap();
    assert_eq!(
        root.unverified_payload().keys().collect::<Vec<_>>(),
        ["_sd_alg", "delegate_payload"]
    );
    let presentation = Presentation::new(root).serialize();
    let options = VerifyOptions {
        root_form: RootForm::DelegatePayload,
        ..VerifyOptions::new(NOW, AP2_ROOT_TYP, KeyBinding::NotRequired)
    };
    let chain = verify(&presentation, &user.verifying_key(), &options).unwrap();
    let root = chain.root();
    assert_eq!(root.kind(), LinkKind::Root);
    assert_eq!(root.claims()["vct"], "mandate.payment.open.1");
    assert_eq!(root.claims()["constraints"][0]["allowed"][0]["id"], "m1");
    assert_eq!(root.cnf(), Some(&agent.verifying_key()));
    assert!(root.envelope().is_empty());

    // Read as a credential, the same token has no exp at the top level.
    let credential = VerifyOptions::new(NOW, AP2_ROOT_TYP, KeyBinding::NotRequired);
    assert_eq!(
        verify(&presentation, &user.verifying_key(), &credential)
            .unwrap_err()
            .kind(),
        &ErrorKind::MissingExp
    );
}

#[test]
fn delegate_form_root_needs_exactly_one_disclosed_payload() {
    let user = SigningKey::generate_p256();
    let root = SdJwtBuilder::delegate_form(
        AP2_ROOT_TYP,
        SdPayload::new(obj(json!({"vct": "mandate.payment.1", "exp": NOW + 60}))),
    )
    .sign(&user)
    .unwrap();
    // Drop the Delegate Payload disclosure.
    let jwt_only = format!("{}~", root.jwt());
    let options = VerifyOptions {
        root_form: RootForm::DelegatePayload,
        ..VerifyOptions::new(NOW, AP2_ROOT_TYP, KeyBinding::NotRequired)
    };
    assert!(matches!(
        verify(&jwt_only, &user.verifying_key(), &options)
            .unwrap_err()
            .kind(),
        ErrorKind::DelegatePayload(_)
    ));
}
