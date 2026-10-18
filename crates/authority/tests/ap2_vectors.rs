//! The AP2 v0.2 interop vectors (crates/sdjwt/tests/vectors/ap2, generated
//! with the AP2 Python SDK at e1ea56d), run through the full v1 verifier.
//!
//! Every vector must reach its `expected_valid` verdict, *including* the
//! three where the SDK itself disagrees: the two tampered root disclosures
//! (RFC 9901 requires rejecting a disclosure no digest references; the SDK
//! drops it silently) and the human-present checkout whose `checkout_hash`
//! does not match its `checkout_jwt` (the SDK does not compare them).
//!
//! Each case also pins *why* it is rejected, so a vector cannot pass for
//! the wrong reason.

use aap_authority::{
    Cause, ClosedContent, ErrorCode, Failure, Family, NoStatusList, Nonce, OpenMandate, Policy,
    Reason, RootPolicy, TransactionContext, Verifier,
};
use aap_sdjwt::{
    verify_jwt, ErrorKind, KeyBinding, Position, Presentation, RootForm, SdAlg, SigningKey,
    Unverified, VerifyOptions, VerifyingKey,
};
use serde_json::Value;

/// The SDK's placeholder `typ` for user-signed mandates.
const AP2_ROOT_TYP: &str = "example+sd-jwt";

struct Vectors {
    doc: Value,
    now: i64,
}

impl Vectors {
    fn load() -> Self {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sdjwt/tests/vectors/ap2/ap2_vectors.json"
        );
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        // A minute after generation: every mandate is still valid.
        let now = doc["generated_at_unix"].as_i64().unwrap() + 60;
        Vectors { doc, now }
    }

    fn all(&self) -> &[Value] {
        self.doc["vectors"].as_array().unwrap()
    }

    fn get(&self, id: &str) -> &Value {
        self.all()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| panic!("no vector {id}"))
    }

    fn key(&self, name: &str) -> VerifyingKey {
        VerifyingKey::from_jwk(&self.doc["jwks"]["keys"][name]).unwrap()
    }
}

fn s<'a>(v: &'a Value, field: &str) -> Option<&'a str> {
    v[field].as_str()
}

/// Root-only open mandates: the format layer plus mandate parsing.
fn check_open(vs: &Vectors, v: &Value) -> Result<(), String> {
    let options = VerifyOptions {
        root_form: RootForm::DelegatePayload,
        ..VerifyOptions::new(vs.now, AP2_ROOT_TYP, KeyBinding::NotRequired)
    };
    let chain = Unverified::<Presentation>::parse(s(v, "token").unwrap())
        .and_then(|p| p.verify(&vs.key(s(v, "verify_with").unwrap()), &options))
        .map_err(|e| format!("{:?}", e.kind()))?;
    let open = OpenMandate::parse(chain.root().claims(), "k").map_err(|e| e.to_string())?;
    let family = match s(v, "type").unwrap() {
        "open_checkout_mandate" => Family::Checkout,
        _ => Family::Payment,
    };
    assert_eq!(open.family(), family);
    Ok(())
}

fn tx_for(v: &Value, vs: &Vectors) -> TransactionContext {
    let nonce = s(v, "expected_nonce").unwrap_or("unused").to_owned();
    let mut tx = TransactionContext::new(Nonce::Challenge(nonce));
    tx.checkout_jwt = s(v, "checkout_jwt").map(str::to_owned);
    tx.merchant_key = Some(vs.key("merchant"));
    tx.expected_checkout_hash = s(v, "expected_checkout_hash").map(str::to_owned);
    tx.expected_transaction_id = s(v, "expected_transaction_id").map(str::to_owned);
    tx.open_checkout_hash = s(v, "expected_open_checkout_hash").map(str::to_owned);
    tx
}

/// Closed mandates through the verifier. Human-present vectors need the
/// explicit AP2 compatibility switch; see `human_present_needs_opt_in`.
fn check_closed(vs: &Vectors, v: &Value, receipt_key: &SigningKey) -> Result<(), Reason> {
    let human_present = s(v, "flow") == Some("human_present");
    let audience = s(v, "expected_aud").unwrap_or("https://merchant.example");
    let mut policy = Policy::new(
        audience,
        RootPolicy::UserSignedMandate {
            typ: vec![AP2_ROOT_TYP.into()],
        },
    );
    policy.allow_unbound_root_mandate = human_present;
    let issuer = match s(v, "verify_with") {
        Some(k) if human_present => vs.key(k),
        _ => vs.key("user"),
    };
    let verifier = Verifier::new(policy, audience, receipt_key, &NoStatusList);
    let decision = verifier
        .verify(s(v, "token").unwrap(), &issuer, &tx_for(v, vs), vs.now)
        .unwrap();
    // A receipt for every outcome, verifiable with the verifier's key.
    let receipt = verify_jwt(
        decision.receipt_jwt(),
        &receipt_key.verifying_key(),
        &[aap_authority::names::RECEIPT_TYP],
    )
    .unwrap();
    let ok = decision.outcome().is_ok();
    assert_eq!(
        receipt.claims()["result"],
        if ok { "success" } else { "error" }
    );
    decision.into_outcome().map(|a| {
        let expected = match s(v, "type").unwrap() {
            "closed_checkout_mandate" => Family::Checkout,
            _ => Family::Payment,
        };
        assert_eq!(a.closed().family(), expected);
    })
}

/// Merchant checkout JWTs and receipts: plain ES256 JWS.
fn check_jws(vs: &Vectors, v: &Value) -> Result<(), String> {
    let jwt = verify_jwt(
        s(v, "token").unwrap(),
        &vs.key(s(v, "verify_with").unwrap()),
        &["JWT"],
    )
    .map_err(|e| format!("{:?}", e.kind()))?;
    if let Some(known) = v.get("known_references") {
        let reference = &jwt.claims()["reference"];
        if !known.as_array().unwrap().contains(reference) {
            return Err("reference not among the known closed mandates".into());
        }
    }
    Ok(())
}

#[test]
fn every_vector_reaches_its_expected_verdict() {
    let vs = Vectors::load();
    let receipt_key = SigningKey::generate_p256();
    assert_eq!(vs.all().len(), 32);
    let mut report = Vec::new();
    for v in vs.all() {
        let id = s(v, "id").unwrap();
        let verdict = match s(v, "type").unwrap() {
            "open_checkout_mandate" | "open_payment_mandate" => check_open(&vs, v),
            "closed_checkout_mandate" | "closed_payment_mandate" => {
                check_closed(&vs, v, &receipt_key).map_err(|r| r.to_string())
            }
            _ => check_jws(&vs, v),
        };
        assert_eq!(
            verdict.is_ok(),
            v["expected_valid"].as_bool().unwrap(),
            "{id}: {verdict:?}"
        );
        report.push(format!("{id}: {verdict:?}"));
    }
    // `cargo test -- --nocapture` prints why each negative was rejected.
    println!("{}", report.join("\n"));
}

fn reason(vs: &Vectors, id: &str) -> Reason {
    check_closed(vs, vs.get(id), &SigningKey::generate_p256()).unwrap_err()
}

fn credential_error(r: &Reason) -> (ErrorKind, Option<Position>) {
    match r {
        Reason::Credential(e) => (e.kind().clone(), e.position()),
        other => panic!("expected a credential error, got {other}"),
    }
}

#[test]
fn negatives_fail_for_the_right_reason() {
    let vs = Vectors::load();

    let r = reason(&vs, "closed-checkout-hnp-wrong-cnf-key");
    assert_eq!(
        credential_error(&r),
        (ErrorKind::BadSignature, Some(Position::Link(1)))
    );
    assert_eq!(r.code(), ErrorCode::InvalidCredential);

    let r = reason(&vs, "closed-checkout-hnp-wrong-aud");
    assert_eq!(credential_error(&r).0, ErrorKind::AudienceMismatch);

    // A root disclosure was altered: unreferenced at the root, before the
    // next link's sd_hash is even looked at.
    for id in [
        "closed-checkout-hnp-tampered-disclosure",
        "closed-payment-hnp-tampered-disclosure",
    ] {
        assert_eq!(
            credential_error(&reason(&vs, id)),
            (ErrorKind::UnreferencedDisclosure, Some(Position::Root)),
            "{id}"
        );
    }

    for id in [
        "closed-checkout-hnp-mismatched-checkout-hash",
        "closed-checkout-hp-mismatched-checkout-hash",
        "closed-payment-hnp-mismatched-transaction-id",
    ] {
        let r = reason(&vs, id);
        assert!(
            matches!(
                r,
                Reason::Binding {
                    failure: Failure::Violated(_),
                    ..
                }
            ),
            "{id}: {r}"
        );
        assert_eq!(r.code(), ErrorCode::InvalidMandate);
    }

    let r = reason(&vs, "closed-payment-hnp-amount-exceeds-constraint");
    match &r {
        Reason::Chain {
            position: Position::Root,
            cause:
                Cause::Constraint {
                    type_name,
                    failure: Failure::Violated(_),
                },
        } => assert_eq!(*type_name, "payment.amount_range"),
        other => panic!("{other}"),
    }

    let r = reason(&vs, "closed-payment-hp-wrong-key");
    assert_eq!(credential_error(&r).0, ErrorKind::BadSignature);

    let r = reason(&vs, "closed-payment-hp-tampered-disclosure");
    assert_eq!(credential_error(&r).0, ErrorKind::UnreferencedDisclosure);
}

#[test]
fn sdk_disagreements_are_rejected_here() {
    let vs = Vectors::load();
    let disagreeing: Vec<&str> = vs
        .all()
        .iter()
        .filter(|v| v["sdk_disagrees_with_expected"] == true)
        .map(|v| s(v, "id").unwrap())
        .collect();
    assert_eq!(
        disagreeing,
        [
            "open-checkout-tampered-disclosure",
            "open-payment-tampered-disclosure",
            "closed-checkout-hp-mismatched-checkout-hash"
        ]
    );
    for id in &disagreeing[..2] {
        // The SDK returned success with `allowed: []`.
        assert_eq!(
            check_open(&vs, vs.get(id)),
            Err("UnreferencedDisclosure".into())
        );
    }
}

#[test]
fn human_present_needs_opt_in() {
    // AP2 human-present mandates carry no aud, nonce or fresh iat: a
    // captured one replays at any verifier until exp. Rejected unless the
    // verifier opts in.
    let vs = Vectors::load();
    let receipt_key = SigningKey::generate_p256();
    for id in ["closed-checkout-hp-valid", "closed-payment-hp-valid"] {
        let v = vs.get(id);
        let policy = Policy::new(
            "https://merchant.example",
            RootPolicy::UserSignedMandate {
                typ: vec![AP2_ROOT_TYP.into()],
            },
        );
        let verifier = Verifier::new(policy, "v", &receipt_key, &NoStatusList);
        let decision = verifier
            .verify(
                s(v, "token").unwrap(),
                &vs.key("user"),
                &tx_for(v, &vs),
                vs.now,
            )
            .unwrap();
        assert_eq!(decision.outcome().unwrap_err(), &Reason::Unbound, "{id}");
        assert_eq!(
            decision.receipt().error.as_ref().unwrap().0,
            ErrorCode::InvalidCredential
        );
    }
}

#[test]
fn checkout_content_is_trusted_only_when_signed_or_own() {
    // Without the verifier's own checkout_jwt and without the merchant key,
    // the disclosed checkout_jwt is agent-supplied: checkout_hash still
    // binds, but allowed_merchants cannot be evaluated on it.
    let vs = Vectors::load();
    let v = vs.get("closed-checkout-hnp-valid");
    let mut tx = tx_for(v, &vs);
    tx.checkout_jwt = None;
    tx.merchant_key = None;
    let receipt_key = SigningKey::generate_p256();
    let policy = Policy::new(
        "https://merchant.example",
        RootPolicy::UserSignedMandate {
            typ: vec![AP2_ROOT_TYP.into()],
        },
    );
    let verifier = Verifier::new(policy, "v", &receipt_key, &NoStatusList);
    let decision = verifier
        .verify(s(v, "token").unwrap(), &vs.key("user"), &tx, vs.now)
        .unwrap();
    let r = decision.outcome().unwrap_err();
    assert_eq!(r.code(), ErrorCode::UnresolvedConstraint, "{r}");

    // With the merchant's key the signature makes it trustworthy.
    tx.merchant_key = Some(vs.key("merchant"));
    let decision = verifier
        .verify(s(v, "token").unwrap(), &vs.key("user"), &tx, vs.now)
        .unwrap();
    let a = decision.outcome().unwrap();
    assert!(matches!(a.closed().content(), ClosedContent::Checkout(_)));

    // A forged merchant key does not.
    tx.merchant_key = Some(vs.key("wrong_key_not_in_cnf"));
    let decision = verifier
        .verify(s(v, "token").unwrap(), &vs.key("user"), &tx, vs.now)
        .unwrap();
    assert!(matches!(
        decision.outcome().unwrap_err(),
        Reason::Binding {
            failure: Failure::Violated(_),
            ..
        }
    ));
}

#[test]
fn receipt_reference_follows_the_spec_text_not_the_sdk() {
    // AP2: "a hash over the final SD-JWT in the chain ... calculated in the
    // same manner as sd_hash". The SDK hashes the final JWT only, which is
    // what the vectors' receipts reference.
    let vs = Vectors::load();
    let v = vs.get("closed-checkout-hnp-valid");
    let token = s(v, "token").unwrap();
    let last = token.rsplit_once("~~").unwrap().1;
    let sdk_reference = SdAlg::Sha256.digest(last.split('~').next().unwrap());
    assert_eq!(
        vs.get("checkout-receipt-valid")["known_references"][0],
        sdk_reference.as_str()
    );

    let receipt_key = SigningKey::generate_p256();
    let policy = Policy::new(
        "https://merchant.example",
        RootPolicy::UserSignedMandate {
            typ: vec![AP2_ROOT_TYP.into()],
        },
    );
    let verifier = Verifier::new(
        policy,
        "https://merchant.example",
        &receipt_key,
        &NoStatusList,
    );
    let decision = verifier
        .verify(token, &vs.key("user"), &tx_for(v, &vs), vs.now)
        .unwrap();
    assert!(decision.outcome().is_ok());
    assert_eq!(decision.receipt().reference, SdAlg::Sha256.digest(last));
    assert_ne!(decision.receipt().reference, sdk_reference);
    assert_eq!(decision.receipt().aap_chain.len(), 2);
}
