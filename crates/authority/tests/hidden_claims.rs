//! The agent holds every open mandate's disclosures and chooses which ones
//! to present. A constraint it leaves out must not read as "the user set no
//! constraint" (review 2026-11, finding F1). Only leaving out members of an
//! allow-list, which can only narrow a mandate, is accepted.

mod common;

use aap_authority::{Reason, TransactionContext, Verifier};
use aap_sdjwt::{
    typ, BindingClaims, LinkBuilder, Presentation, SdJwtBuilder, SdPayload, SigningKey,
};
use common::*;
use serde_json::{json, Value};

/// Root credential (with `root_conceal` pointers, all left undisclosed),
/// one user-signed open mandate (with `conceal` pointers), and a closed
/// mandate; the agent presents only the open-mandate disclosures at `keep`.
fn build(
    keys: &Keys,
    root_extra: Value,
    root_conceal: &[&str],
    open: Value,
    conceal: &[&str],
    keep: &[&str],
    closed: Value,
) -> String {
    let user = keys.user().verifying_key();
    let mut root_claims = obj(json!({
        "iss": "https://issuer.aap.example", "vct": USER_VCT,
        "iat": NOW - 86_400, "exp": NOW + 86_400 * 365, "cnf": user.to_cnf(),
    }));
    root_claims.extend(obj(root_extra));
    let mut root = SdJwtBuilder::new(typ::SD_JWT_VC, root_claims);
    for c in root_conceal {
        root = root.conceal(c);
    }
    let root = root.sign(&keys.issuer).unwrap();

    let mut claims = obj(open);
    claims.entry("iat").or_insert(json!(NOW - 60));
    claims.entry("exp").or_insert(json!(NOW + 1800));
    claims.insert("cnf".into(), keys.signers[1].verifying_key().to_cnf());
    let mut payload = SdPayload::new(claims);
    for c in conceal {
        payload = payload.conceal(c);
    }
    let b = BindingClaims {
        audience: "https://agent.example".into(),
        nonce: "d0".into(),
        issued_at: NOW - 60,
    };
    let p = Presentation::new(root)
        .select(0, &[])
        .unwrap()
        .delegate(LinkBuilder::new(payload), &b, keys.user())
        .unwrap()
        .select(1, keep)
        .unwrap();
    let b = BindingClaims {
        audience: VERIFIER.into(),
        nonce: CHALLENGE.into(),
        issued_at: NOW,
    };
    p.delegate(
        LinkBuilder::new(SdPayload::new(obj(closed))),
        &b,
        &keys.signers[1],
    )
    .unwrap()
    .serialize()
}

fn outcome(keys: &Keys, pres: &str, tx: &TransactionContext) -> Result<(), Reason> {
    let receipt = SigningKey::generate_p256();
    let status = valid_status();
    let ledger = Ledger::default();
    let v = Verifier::new(policy(), VERIFIER, &receipt, &status).with_ledger(&ledger);
    let d = v
        .verify(pres, &keys.issuer.verifying_key(), tx, NOW)
        .unwrap();
    d.into_outcome().map(|_| ())
}

fn hidden_at(result: Result<(), Reason>) -> String {
    match result {
        Err(Reason::HiddenClaim { pointer, .. }) => pointer,
        other => panic!("expected HiddenClaim, got {other:?}"),
    }
}

fn payment_open() -> Value {
    json!({"vct": "mandate.payment.open.1", "constraints": [
        {"type": "payment.amount_range", "currency": "EUR", "max": 5000},
        {"type": "payment.allowed_payees", "allowed": [{"id": "shop-s", "name": "S"}]},
        {"type": "payment.budget", "max": 5000, "currency": "EUR"}
    ]})
}

const ALL_CONSTRAINTS: &[&str] = &["/constraints/0", "/constraints/1", "/constraints/2"];

#[test]
fn every_constraint_disclosed_still_rejects_the_attack() {
    let keys = Keys::new();
    let pres = build(
        &keys,
        json!({}),
        &[],
        payment_open(),
        ALL_CONSTRAINTS,
        &["/delegate_payload/0/constraints"],
        payment("attacker", 9_999_999, "EUR"),
    );
    assert!(matches!(
        outcome(&keys, &pres, &payment_tx()),
        Err(Reason::Chain { .. })
    ));
}

#[test]
fn hiding_every_payment_constraint_is_rejected() {
    // Before the fix, this 9,999,999 EUR payment to an unknown payee was
    // accepted: with no constraint disclosed, none was evaluated.
    let keys = Keys::new();
    let pres = build(
        &keys,
        json!({}),
        &[],
        payment_open(),
        ALL_CONSTRAINTS,
        &["/delegate_payload/0/vct"],
        payment("attacker", 9_999_999, "EUR"),
    );
    assert_eq!(
        hidden_at(outcome(&keys, &pres, &payment_tx())),
        "/constraints"
    );
}

#[test]
fn hiding_a_deny_entry_is_rejected() {
    let keys = Keys::new();
    let open = authority(json!([
        {"type": "aap.actions", "allowed": ["message.send"]},
        {"type": "aap.counterparties", "deny": ["boss@corp.example", "press@news.example"]}
    ]));
    let closed = action(json!({"action": "message.send", "counterparty": "press@news.example"}));
    let pres = build(
        &keys,
        json!({}),
        &[],
        open,
        &["/constraints/1/deny/0", "/constraints/1/deny/1"],
        &[
            "/delegate_payload/0/constraints/0",
            "/delegate_payload/0/constraints/1/deny/0",
        ],
        closed,
    );
    assert_eq!(
        hidden_at(outcome(&keys, &pres, &challenge())),
        "/constraints/1/deny"
    );
}

#[test]
fn hiding_a_time_window_constraint_is_rejected() {
    let keys = Keys::new();
    let open = authority(json!([
        {"type": "aap.actions", "allowed": ["a"]},
        {"type": "aap.time_windows", "windows": [
            {"days": ["sun"], "start": "00:00", "end": "00:01", "timezone": "UTC"}]}
    ]));
    let pres = build(
        &keys,
        json!({}),
        &[],
        open,
        &["/constraints/1"],
        &["/delegate_payload/0/constraints/0"],
        action(json!({"action": "a"})),
    );
    assert_eq!(
        hidden_at(outcome(&keys, &pres, &challenge())),
        "/constraints"
    );
}

#[test]
fn hiding_a_preset_claim_is_rejected() {
    let keys = Keys::new();
    let open = json!({"vct": "mandate.payment.open.1", "payee": {"id": "shop-s"}, "constraints": [
        {"type": "payment.amount_range", "currency": "EUR", "max": 5000}]});
    let pres = build(
        &keys,
        json!({}),
        &[],
        open,
        &["/payee"],
        &["/delegate_payload/0/constraints"],
        payment("attacker", 100, "EUR"),
    );
    assert_eq!(hidden_at(outcome(&keys, &pres, &payment_tx())), "");
}

#[test]
fn hiding_allow_list_members_only_narrows_and_is_accepted() {
    let keys = Keys::new();
    let open = json!({"vct": "mandate.payment.open.1", "constraints": [
        {"type": "payment.amount_range", "currency": "EUR", "max": 5000},
        {"type": "payment.allowed_payees", "allowed": [
            {"id": "shop-s", "name": "S"}, {"id": "shop-t", "name": "T"}]}
    ]});
    let conceal = &["/constraints/1/allowed/0", "/constraints/1/allowed/1"];
    // Only shop-s is shown to this verifier; shop-t stays private.
    // (Selecting "/delegate_payload/0/constraints" would disclose everything
    // nested in it, both payees included.)
    let keep = &["/delegate_payload/0/constraints/1/allowed/0"];
    let pres = build(
        &keys,
        json!({}),
        &[],
        open.clone(),
        conceal,
        keep,
        payment("shop-s", 100, "EUR"),
    );
    assert_eq!(outcome(&keys, &pres, &payment_tx()), Ok(()));

    // The hidden payee cannot be used through this presentation.
    let pres = build(
        &keys,
        json!({}),
        &[],
        open,
        conceal,
        keep,
        payment("shop-t", 100, "EUR"),
    );
    let rejected = outcome(&keys, &pres, &payment_tx()).expect_err("shop-t is not shown");
    assert!(
        !matches!(rejected, Reason::HiddenClaim { .. }),
        "{rejected:?}"
    );
    assert!(
        rejected.to_string().contains("allowed_payees"),
        "{rejected}"
    );
}

#[test]
fn root_without_visible_status_may_not_hide_top_level_claims() {
    let keys = Keys::new();
    let open = authority(json!([{"type": "aap.actions", "allowed": ["a"]}]));
    let keep = &["/delegate_payload/0/constraints"];
    let closed = action(json!({"action": "a"}));

    // A hidden top-level claim with no visible status: it could be the
    // status entry the holder chose not to show.
    let pres = build(
        &keys,
        json!({"email": "user@example.org"}),
        &["/email"],
        open.clone(),
        &[],
        keep,
        closed.clone(),
    );
    assert_eq!(hidden_at(outcome(&keys, &pres, &challenge())), "");

    // With the status entry visible, personal data may stay hidden.
    let status = json!({"status": {"status_list": {"idx": 7, "uri": "https://issuer.aap.example/status/1"}}});
    let mut extra = obj(status);
    extra.insert("email".into(), json!("user@example.org"));
    let pres = build(
        &keys,
        Value::Object(extra),
        &["/email"],
        open,
        &[],
        keep,
        closed,
    );
    assert_eq!(outcome(&keys, &pres, &challenge()), Ok(()));
}
