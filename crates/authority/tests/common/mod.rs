//! Chains in 0004's target shape, built with aap-sdjwt:
//!
//! ```text
//! user credential (dc+sd-jwt, Issuer Service, cnf = user)
//!   ~ open mandate (signed by user, cnf = agent)        opens[0]
//!   ~ open mandate (signed by agent, cnf = sub-agent)   opens[1], ...
//!   ~ closed mandate (signed by the last delegate, aud/nonce/iat)
//! ```
#![allow(dead_code)]

use std::collections::HashMap;

use aap_authority::{
    Decision, LedgerError, Nonce, Policy, RootPolicy, StatusChecker, StatusError, TokenStatus,
    TransactionContext, Usage, UsageLedger, Verifier,
};
use aap_sdjwt::{
    typ, BindingClaims, LinkBuilder, Presentation, SdJwtBuilder, SdPayload, SigningKey,
};
use serde_json::{json, Map, Value};

pub const NOW: i64 = 1_800_000_000;
pub const VERIFIER: &str = "https://merchant.example";
pub const CHALLENGE: &str = "challenge-0001";
pub const USER_VCT: &str = "urn:aap:user:1";

pub fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(o) => o,
        other => panic!("not an object: {other}"),
    }
}

pub struct Keys {
    pub issuer: SigningKey,
    /// `signers[0]` is the user; `signers[n]` the n-th delegate.
    pub signers: Vec<SigningKey>,
}

impl Keys {
    pub fn new() -> Self {
        Keys {
            issuer: SigningKey::generate_p256(),
            signers: (0..5).map(|_| SigningKey::generate_p256()).collect(),
        }
    }

    pub fn user(&self) -> &SigningKey {
        &self.signers[0]
    }
}

pub struct Chain<'a> {
    pub keys: &'a Keys,
    pub opens: Vec<Value>,
    pub closed: Value,
    pub audience: String,
    pub nonce: String,
    pub iat: i64,
    /// Sign element `i` (0 = first link) with this key instead.
    pub signer_override: Option<(usize, SigningKey)>,
}

impl<'a> Chain<'a> {
    pub fn new(keys: &'a Keys, opens: Vec<Value>, closed: Value) -> Self {
        Chain {
            keys,
            opens,
            closed,
            audience: VERIFIER.into(),
            nonce: CHALLENGE.into(),
            iat: NOW,
            signer_override: None,
        }
    }

    fn signer(&self, i: usize) -> &SigningKey {
        match &self.signer_override {
            Some((at, key)) if *at == i => key,
            _ => &self.keys.signers[i],
        }
    }

    pub fn build(&self) -> String {
        let user = self.keys.user().verifying_key();
        let root = SdJwtBuilder::new(
            typ::SD_JWT_VC,
            obj(json!({
                "iss": "https://issuer.aap.example",
                "vct": USER_VCT,
                "iat": NOW - 86_400,
                "exp": NOW + 86_400 * 365,
                "cnf": user.to_cnf(),
            })),
        )
        .sign(&self.keys.issuer)
        .unwrap();
        let mut p = Presentation::new(root);
        for (i, open) in self.opens.iter().enumerate() {
            let mut claims = obj(open.clone());
            claims.entry("iat").or_insert(json!(NOW - 60));
            claims.entry("exp").or_insert(json!(NOW + 1800));
            claims.insert(
                "cnf".into(),
                self.keys.signers[i + 1].verifying_key().to_cnf(),
            );
            let binding = BindingClaims {
                audience: "https://agent.example".into(),
                nonce: format!("delegation-{i}"),
                issued_at: NOW - 60,
            };
            p = p
                .delegate(
                    LinkBuilder::new(SdPayload::new(claims)),
                    &binding,
                    self.signer(i),
                )
                .unwrap();
        }
        let binding = BindingClaims {
            audience: self.audience.clone(),
            nonce: self.nonce.clone(),
            issued_at: self.iat,
        };
        p.delegate(
            LinkBuilder::new(SdPayload::new(obj(self.closed.clone()))),
            &binding,
            self.signer(self.opens.len()),
        )
        .unwrap()
        .serialize()
    }
}

pub fn policy() -> Policy {
    Policy::new(
        VERIFIER,
        RootPolicy::Credential {
            typ: vec![typ::SD_JWT_VC.into()],
            vct: vec![USER_VCT.into()],
        },
    )
}

pub fn challenge() -> TransactionContext {
    TransactionContext::new(Nonce::Challenge(CHALLENGE.into()))
}

/// Answers every status lookup the same way.
pub struct FixedStatus(pub Result<TokenStatus, StatusError>);

impl StatusChecker for FixedStatus {
    fn check(&self, _: &Value, _: i64) -> Result<TokenStatus, StatusError> {
        self.0.clone()
    }
}

pub fn valid_status() -> FixedStatus {
    FixedStatus(Ok(TokenStatus::Valid))
}

/// Usage per ledger key; unknown keys have no usage.
#[derive(Default)]
pub struct Ledger(pub HashMap<String, Usage>);

impl UsageLedger for Ledger {
    fn usage(&self, key: &str) -> Result<Usage, LedgerError> {
        Ok(self.0.get(key).copied().unwrap_or_default())
    }
}

pub fn run(
    verifier: &Verifier<'_>,
    keys: &Keys,
    presentation: &str,
    tx: &TransactionContext,
) -> Decision {
    verifier
        .verify(presentation, &keys.issuer.verifying_key(), tx, NOW)
        .unwrap()
}

/// An `aap.authority.open.1` with these constraints.
pub fn authority(constraints: Value) -> Value {
    json!({"vct": aap_authority::names::aap::AUTHORITY_OPEN, "constraints": constraints})
}

/// An `aap.action.1`.
pub fn action(fields: Value) -> Value {
    let mut o = obj(fields);
    o.insert("vct".into(), json!(aap_authority::names::aap::ACTION));
    Value::Object(o)
}

/// An AP2 closed payment mandate for `checkout_hash`.
pub fn payment(payee_id: &str, amount: u64, currency: &str) -> Value {
    json!({
        "vct": "mandate.payment.1",
        "transaction_id": "checkout-hash-1",
        "payee": {"id": payee_id, "name": "Payee"},
        "payment_amount": {"amount": amount, "currency": currency},
        "payment_instrument": {"id": "pi-1", "type": "card"}
    })
}

pub fn payment_tx() -> TransactionContext {
    let mut tx = challenge();
    tx.expected_transaction_id = Some("checkout-hash-1".into());
    tx
}
