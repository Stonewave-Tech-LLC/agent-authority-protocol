//! Regression tests for the November 2026 review: ledger keys that changed
//! with a re-encoded signature, a nonce that could be replayed at the last
//! second of its window, and a past execution date.

mod common;

use aap_authority::{MemoryNonceStore, Nonce, Reason, Usage, Verifier};
use aap_sdjwt::{
    typ, BindingClaims, LinkBuilder, Presentation, SdJwtBuilder, SdPayload, SigningKey, Unverified,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use common::*;
use serde_json::json;

/// The same ES256 signature with `s` replaced by `n - s`: still valid.
fn flip_s(jwt: &str) -> String {
    let parts: Vec<&str> = jwt.split('.').collect();
    let sig = p256::ecdsa::Signature::from_slice(&B64.decode(parts[2]).unwrap()).unwrap();
    let (r, s) = sig.split_scalars();
    let flipped =
        p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s.as_ref()).to_bytes()).unwrap();
    format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        B64.encode(flipped.to_bytes())
    )
}

/// Root credential and a user-signed payment open mandate with a budget.
fn up_to_open(keys: &Keys) -> String {
    let user = keys.user().verifying_key();
    let root = SdJwtBuilder::new(
        typ::SD_JWT_VC,
        obj(json!({
            "iss": "https://issuer.aap.example", "vct": USER_VCT,
            "iat": NOW - 86_400, "exp": NOW + 86_400 * 365, "cnf": user.to_cnf(),
        })),
    )
    .sign(&keys.issuer)
    .unwrap();
    let mut claims = obj(json!({"vct": "mandate.payment.open.1", "constraints": [
        {"type": "payment.amount_range", "currency": "EUR", "max": 32000},
        {"type": "payment.budget", "max": 32000, "currency": "EUR"}]}));
    claims.insert("iat".into(), json!(NOW - 60));
    claims.insert("exp".into(), json!(NOW + 1800));
    claims.insert("cnf".into(), keys.signers[1].verifying_key().to_cnf());
    let b = BindingClaims {
        audience: "https://agent.example".into(),
        nonce: "d0".into(),
        issued_at: NOW - 60,
    };
    Presentation::new(root)
        .delegate(LinkBuilder::new(SdPayload::new(claims)), &b, keys.user())
        .unwrap()
        .serialize()
}

fn close(keys: &Keys, up_to: &str) -> String {
    let p: Presentation = Unverified::<Presentation>::parse(up_to)
        .unwrap()
        .into_inner();
    let b = BindingClaims {
        audience: VERIFIER.into(),
        nonce: CHALLENGE.into(),
        issued_at: NOW,
    };
    p.delegate(
        LinkBuilder::new(SdPayload::new(obj(payment("shop", 30000, "EUR")))),
        &b,
        &keys.signers[1],
    )
    .unwrap()
    .serialize()
}

fn run_with(keys: &Keys, pres: &str, ledger: &Ledger) -> Result<Vec<String>, Reason> {
    let receipt = SigningKey::generate_p256();
    let status = valid_status();
    let v = Verifier::new(policy(), VERIFIER, &receipt, &status).with_ledger(ledger);
    let d = v
        .verify(pres, &keys.issuer.verifying_key(), &payment_tx(), NOW)
        .unwrap();
    d.into_outcome().map(|a| a.ledger_keys().to_vec())
}

#[test]
fn a_high_s_twin_of_the_users_mandate_shares_its_budget() {
    let keys = Keys::new();
    let up_to = up_to_open(&keys);
    // The open mandate is the second JWT in the serialization.
    let mut parts: Vec<String> = up_to.split('~').map(str::to_owned).collect();
    let at = parts
        .iter()
        .enumerate()
        .filter(|(_, s)| s.matches('.').count() == 2)
        .nth(1)
        .unwrap()
        .0;
    parts[at] = flip_s(&parts[at]);
    let twin_up_to = parts.join("~");

    let original = close(&keys, &up_to);
    let twin = close(&keys, &twin_up_to);

    let original_keys = run_with(&keys, &original, &Ledger::default()).unwrap();
    let twin_keys = run_with(&keys, &twin, &Ledger::default()).unwrap();
    assert_eq!(original_keys, twin_keys);

    // Budget used up: the twin must not get a fresh one.
    let mut spent = Ledger::default();
    spent.0.insert(
        original_keys[0].clone(),
        Usage {
            total_minor: 32000,
            uses: 1,
            last_use: Some(NOW - 10),
        },
    );
    assert!(run_with(&keys, &original, &spent).is_err());
    assert!(run_with(&keys, &twin, &spent).is_err());
}

#[test]
fn an_agent_nonce_cannot_be_replayed_at_the_last_second_of_its_window() {
    let keys = Keys::new();
    let open = json!({"vct": "mandate.payment.open.1", "constraints": [
        {"type": "payment.amount_range", "currency": "EUR", "max": 5000}]});
    let mut chain = Chain::new(&keys, vec![open], payment("shop", 100, "EUR"));
    chain.nonce = "agent-nonce-1".into();
    let pres = chain.build();
    let receipt = SigningKey::generate_p256();
    let status = valid_status();
    let store = MemoryNonceStore::default();
    let v = Verifier::new(policy(), VERIFIER, &receipt, &status).with_nonce_store(&store);
    let mut tx = payment_tx();
    tx.nonce = Nonce::AgentGenerated;
    let max_age = policy().max_age;
    let at = |t: i64| {
        v.verify(&pres, &keys.issuer.verifying_key(), &tx, t)
            .unwrap()
            .into_outcome()
            .map(|_| ())
    };

    assert_eq!(at(NOW), Ok(()));
    assert_eq!(at(NOW + max_age - 1), Err(Reason::Replay));
    // Still fresh, so it must still be remembered.
    assert_eq!(at(NOW + max_age), Err(Reason::Replay));
    // One second later the presentation itself is stale.
    assert!(at(NOW + max_age + 1).is_err());
}

#[test]
fn a_past_execution_date_is_rejected() {
    // NOW is 2027-01-15; a date long over must not slip under not_after.
    let keys = Keys::new();
    let open = json!({"vct": "mandate.payment.open.1", "constraints": [
        {"type": "payment.amount_range", "currency": "EUR", "max": 5000},
        {"type": "payment.execution_date", "not_after": "2027-12-31"}]});
    let mut closed = payment("shop", 100, "EUR");
    closed["execution_date"] = json!("2026-12-01");
    let chain = Chain::new(&keys, vec![open.clone()], closed);
    let receipt = SigningKey::generate_p256();
    let status = valid_status();
    let v = Verifier::new(policy(), VERIFIER, &receipt, &status);
    let rejected = run(&v, &keys, &chain.build(), &payment_tx())
        .into_outcome()
        .expect_err("past execution date");
    assert!(rejected.to_string().contains("in the past"), "{rejected}");

    // Today is fine.
    let mut closed = payment("shop", 100, "EUR");
    closed["execution_date"] = json!("2027-01-15");
    let chain = Chain::new(&keys, vec![open], closed);
    assert!(run(&v, &keys, &chain.build(), &payment_tx())
        .into_outcome()
        .is_ok());
}
