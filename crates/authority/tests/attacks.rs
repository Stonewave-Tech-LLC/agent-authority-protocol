//! Negative tests named after the attack scenarios of 0005 whose defence
//! lives in the core (chains, constraints, freshness, status). Each must be
//! rejected, at the position and for the reason the design names. Gap
//! entries whose closing constraint is out of M3's scope (`aap.rate`,
//! `aap.recipients`, ...) have no test yet; see the hand-over notes.

mod common;

use aap_authority::{
    narrows, Cause, ErrorCode, Failure, MandateError, MemoryNonceStore, NoStatusList, Nonce,
    OpenMandate, Reason, StatusError, TokenStatus, TransactionContext, Usage, Verifier,
};
use aap_sdjwt::{sign_jwt, ErrorKind, Position, SdAlg, SigningKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use common::*;
use serde_json::{json, Value};

fn reject(keys: &Keys, chain: &Chain<'_>, tx: &TransactionContext) -> Reason {
    let receipt = SigningKey::generate_p256();
    let status = valid_status();
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status);
    run(&verifier, keys, &chain.build(), tx)
        .into_outcome()
        .expect_err("must be rejected")
}

fn accept(keys: &Keys, chain: &Chain<'_>, tx: &TransactionContext) {
    let receipt = SigningKey::generate_p256();
    let status = valid_status();
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status);
    if let Err(r) = run(&verifier, keys, &chain.build(), tx).outcome() {
        panic!("must be accepted: {r}");
    }
}

fn constraint_violation(r: &Reason) -> (Position, &'static str) {
    match r {
        Reason::Chain {
            position,
            cause:
                Cause::Constraint {
                    type_name,
                    failure: Failure::Violated(_),
                },
        } => (*position, type_name),
        other => panic!("expected a constraint violation, got {other}"),
    }
}

fn credential_error(r: &Reason) -> (ErrorKind, Option<Position>) {
    match r {
        Reason::Credential(e) => (e.kind().clone(), e.position()),
        other => panic!("expected a credential error, got {other}"),
    }
}

fn open(v: Value) -> OpenMandate {
    OpenMandate::parse(&common::obj(v), "k").unwrap()
}

// ---- UC16: agent-to-agent sub-delegation ----------------------------------

#[test]
fn uc16_a1_child_ceiling_above_the_parent_is_rejected_by_the_parent() {
    let keys = Keys::new();
    let parent = authority(json!([
        {"type": "aap.actions", "allowed": ["quote.request", "purchase"]},
        {"type": "aap.amount", "max": 30000, "currency": "EUR"},
        {"type": "aap.delegation", "max_depth": 1}
    ]));
    let child = authority(json!([
        {"type": "aap.actions", "allowed": ["purchase"]},
        {"type": "aap.amount", "max": 10000000, "currency": "EUR"}
    ]));
    let buy = |minor: u64| {
        action(json!({"action": "purchase", "amount": {"amount": minor, "currency": "EUR"}}))
    };
    let chain = Chain::new(&keys, vec![parent.clone(), child.clone()], buy(50000));
    let r = reject(&keys, &chain, &challenge());
    assert_eq!(constraint_violation(&r), (Position::Link(1), "aap.amount"));
    assert_eq!(r.code(), ErrorCode::InvalidMandate);

    // Within the parent's ceiling the same chain passes: the child's claim
    // never widened anything, it just was not the binding limit.
    accept(
        &keys,
        &Chain::new(&keys, vec![parent.clone(), child.clone()], buy(25000)),
        &challenge(),
    );

    // Issuance would have refused the child, but the verifier never relied
    // on that.
    assert!(!narrows(&open(parent), &open(child)));
}

#[test]
fn uc16_a2_link_without_delegation_cannot_be_followed_by_another_open_mandate() {
    let keys = Keys::new();
    let parent = authority(json!([
        {"type": "aap.actions", "allowed": ["quote.request"]},
        {"type": "aap.delegation", "max_depth": 1}
    ]));
    let child = authority(json!([{"type": "aap.actions", "allowed": ["quote.request"]}]));
    let closed = action(json!({"action": "quote.request"}));
    accept(
        &keys,
        &Chain::new(&keys, vec![parent, child.clone()], closed.clone()),
        &challenge(),
    );

    // The user allows two levels, but S's link allows none below it.
    let generous = authority(json!([
        {"type": "aap.actions", "allowed": ["quote.request"]},
        {"type": "aap.delegation", "max_depth": 2}
    ]));
    let chain = Chain::new(&keys, vec![generous, child.clone(), child], closed.clone());
    match reject(&keys, &chain, &challenge()) {
        Reason::DelegationDepth {
            position,
            max_depth,
            further,
        } => assert_eq!((position, max_depth, further), (Position::Link(2), 0, 1)),
        other => panic!("{other}"),
    }

    // max_depth 1 allows one further level, not two.
    let deep = authority(json!([
        {"type": "aap.actions", "allowed": ["quote.request"]},
        {"type": "aap.delegation", "max_depth": 1}
    ]));
    let chain = Chain::new(&keys, vec![deep.clone(), deep.clone(), deep], closed);
    assert!(matches!(
        reject(&keys, &chain, &challenge()),
        Reason::DelegationDepth {
            position: Position::Link(1),
            max_depth: 1,
            further: 2
        }
    ));
}

#[test]
fn uc16_a3_budget_is_counted_against_the_user_signed_mandate() {
    // CG4: the counter is keyed by the user-signed mandate, so a purchase
    // sub-mandate cannot spend a budget the parent agent also spends.
    let keys = Keys::new();
    let parent = json!({
        "vct": "mandate.payment.open.1",
        "constraints": [
            {"type": "payment.amount_range", "currency": "EUR", "max": 32000},
            {"type": "payment.budget", "max": 32000, "currency": "EUR"},
            {"type": "payment.agent_recurrence", "frequency": "ON_DEMAND"},
            {"type": "aap.delegation", "max_depth": 1}
        ]
    });
    let child = json!({
        "vct": "mandate.payment.open.1",
        "constraints": [{"type": "payment.amount_range", "currency": "EUR", "max": 30000}]
    });
    let presentation =
        Chain::new(&keys, vec![parent, child], payment("shop", 25000, "EUR")).build();

    let receipt = SigningKey::generate_p256();
    let status = valid_status();
    let fresh = Ledger::default();
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status).with_ledger(&fresh);
    let decision = run(&verifier, &keys, &presentation, &payment_tx());
    let authorized = decision.outcome().unwrap();
    let parent_key = authorized.ledger_keys()[0].clone();

    // The parent agent already spent 10 000 under the same user mandate.
    let mut spent = Ledger::default();
    spent.0.insert(
        parent_key,
        Usage {
            total_minor: 10000,
            uses: 1,
            last_use: Some(NOW - 3600),
        },
    );
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status).with_ledger(&spent);
    let r = run(&verifier, &keys, &presentation, &payment_tx())
        .into_outcome()
        .unwrap_err();
    assert_eq!(
        constraint_violation(&r),
        (Position::Link(1), "payment.budget")
    );

    // No ledger: unresolved, never "pass".
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status);
    let r = run(&verifier, &keys, &presentation, &payment_tx())
        .into_outcome()
        .unwrap_err();
    assert_eq!(r.code(), ErrorCode::UnresolvedConstraint);
}

#[test]
fn uc16_a4_agent_signed_link_without_status_must_be_short_lived() {
    // CG15: agents run no status list, so an unrevocable link is only
    // acceptable with a short exp.
    let keys = Keys::new();
    let parent = authority(json!([
        {"type": "aap.actions", "allowed": ["quote.request"]},
        {"type": "aap.delegation", "max_depth": 1}
    ]));
    let mut parent = common::obj(parent);
    parent.insert(
        "status".into(),
        json!({"status_list": {"idx": 7, "uri": "https://is.example/sl"}}),
    );
    parent.insert("exp".into(), json!(NOW + 86_400 * 30));
    let child = |exp: i64| {
        let mut c = common::obj(authority(
            json!([{"type": "aap.actions", "allowed": ["quote.request"]}]),
        ));
        c.insert("exp".into(), json!(exp));
        Value::Object(c)
    };
    let closed = action(json!({"action": "quote.request"}));
    let parent = Value::Object(parent);
    accept(
        &keys,
        &Chain::new(
            &keys,
            vec![parent.clone(), child(NOW + 3600)],
            closed.clone(),
        ),
        &challenge(),
    );
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![parent, child(NOW + 86_400)], closed),
        &challenge(),
    );
    assert_eq!(
        r,
        Reason::Unrevocable {
            position: Position::Link(2)
        }
    );
}

// ---- UC08, UC11, UC14, UC15: actions and data categories ------------------

#[test]
fn uc08_a2_read_mandate_cannot_initiate_a_payment() {
    let keys = Keys::new();
    let read = authority(json!([
        {"type": "aap.actions", "allowed": ["account.read_balance", "account.read_transactions"]},
        {"type": "aap.resources", "allowed": ["AT611904300234573201"]},
        {"type": "aap.data_categories", "allowed": ["balance", "transactions"]}
    ]));
    let pay = action(json!({"action": "payment.initiate", "resource": "AT611904300234573201"}));
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![read.clone()], pay),
        &challenge(),
    );
    assert_eq!(constraint_violation(&r), (Position::Link(1), "aap.actions"));

    // UC08-A4 (partial): the partner's account is not in aap.resources.
    let other =
        action(json!({"action": "account.read_balance", "resource": "AT483200000012345864"}));
    let r = reject(&keys, &Chain::new(&keys, vec![read], other), &challenge());
    assert_eq!(
        constraint_violation(&r),
        (Position::Link(1), "aap.resources")
    );
}

#[test]
fn uc11_a2_modifying_a_standing_order_is_not_in_the_mandate() {
    let keys = Keys::new();
    let runs = authority(json!([{"type": "aap.actions", "allowed": ["standing_order.execute"]}]));
    let modify = action(
        json!({"action": "standing_order.modify", "counterparty": "DE89370400440532013000"}),
    );
    let r = reject(&keys, &Chain::new(&keys, vec![runs], modify), &challenge());
    assert_eq!(constraint_violation(&r).1, "aap.actions");
}

#[test]
fn uc14_a1_calendar_mandate_returns_only_free_busy() {
    let keys = Keys::new();
    let cal = authority(json!([
        {"type": "aap.actions", "allowed": ["calendar.read"]},
        {"type": "aap.data_categories", "allowed": ["free_busy"]}
    ]));
    let titles = action(
        json!({"action": "calendar.read", "data_categories": ["free_busy", "titles", "attendees"]}),
    );
    let r = reject(&keys, &Chain::new(&keys, vec![cal], titles), &challenge());
    assert_eq!(constraint_violation(&r).1, "aap.data_categories");
}

#[test]
fn uc14_a4_amount_against_a_mandate_without_amounts_is_rejected() {
    let keys = Keys::new();
    let cal = authority(json!([{"type": "aap.actions", "allowed": ["event.accept"]}]));
    let fee =
        action(json!({"action": "event.accept", "amount": {"amount": 5000, "currency": "EUR"}}));
    let r = reject(&keys, &Chain::new(&keys, vec![cal], fee), &challenge());
    assert_eq!(
        r,
        Reason::Chain {
            position: Position::Link(1),
            cause: Cause::AmountWithoutCeiling
        }
    );
}

#[test]
fn uc15_a2_full_record_instead_of_lab_results() {
    let keys = Keys::new();
    let share = authority(json!([
        {"type": "aap.actions", "allowed": ["data.share"]},
        {"type": "aap.data_categories", "allowed": ["lab_results"]}
    ]));
    let full = action(json!({"action": "data.share", "data_categories": ["full_record"]}));
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![share.clone()], full),
        &challenge(),
    );
    assert_eq!(constraint_violation(&r).1, "aap.data_categories");
    let lab = action(json!({"action": "data.share", "data_categories": ["lab_results"]}));
    accept(&keys, &Chain::new(&keys, vec![share], lab), &challenge());
}

// ---- UC01, UC06, UC09: payments --------------------------------------------

fn open_payment(payees: Value, max: u64) -> Value {
    json!({
        "vct": "mandate.payment.open.1",
        "constraints": [
            {"type": "payment.amount_range", "currency": "EUR", "max": max},
            {"type": "payment.allowed_payees", "allowed": payees}
        ]
    })
}

#[test]
fn uc09_a1_unlisted_iban_is_rejected() {
    let keys = Keys::new();
    let mandate = open_payment(
        json!([{"id": "AT611904300234573201", "name": "Stadtwerke"},
               {"id": "AT026000000001349870", "name": "Landlord"}]),
        50000,
    );
    accept(
        &keys,
        &Chain::new(
            &keys,
            vec![mandate.clone()],
            payment("AT611904300234573201", 8900, "EUR"),
        ),
        &payment_tx(),
    );
    // The "new bank details" from an injected invoice, same display name.
    let r = reject(
        &keys,
        &Chain::new(
            &keys,
            vec![mandate],
            payment("DE89370400440532013000", 8900, "EUR"),
        ),
        &payment_tx(),
    );
    assert_eq!(
        constraint_violation(&r),
        (Position::Link(1), "payment.allowed_payees")
    );
}

#[test]
fn uc09_a2_payees_are_identified_by_account_never_by_name() {
    let keys = Keys::new();
    let names_only = open_payment(json!([{"name": "Stadtwerke"}]), 50000);
    let r = reject(
        &keys,
        &Chain::new(
            &keys,
            vec![names_only],
            payment("DE89370400440532013000", 8900, "EUR"),
        ),
        &payment_tx(),
    );
    assert!(
        matches!(
            r,
            Reason::Mandate {
                position: Position::Link(1),
                error: MandateError::Constraint { index: 1, .. }
            }
        ),
        "{r}"
    );
    assert_eq!(r.code(), ErrorCode::InvalidMandate);
}

#[test]
fn uc01_a1_lookalike_shop_is_not_an_allowed_merchant() {
    let keys = Keys::new();
    let merchant_key = SigningKey::generate_p256();
    let checkout = sign_jwt(
        "JWT",
        &Default::default(),
        &common::obj(json!({
            "id": "chk-1",
            "merchant": {"id": "shop-s-prime", "name": "Shop S"},
            "line_items": [{"id": "li-1", "item": {"id": "sku-1", "title": "Widget", "price": 3490}, "quantity": 1}],
            "currency": "EUR"
        })),
        &merchant_key,
    )
    .unwrap();
    let open = json!({
        "vct": "mandate.checkout.open.1",
        "constraints": [{"type": "checkout.allowed_merchants", "allowed": [{"id": "shop-s", "name": "Shop S"}]}]
    });
    let closed = json!({
        "vct": "mandate.checkout.1",
        "checkout_jwt": checkout,
        "checkout_hash": SdAlg::Sha256.digest(&checkout)
    });
    let mut tx = challenge();
    tx.checkout_jwt = Some(checkout.clone());
    let r = reject(&keys, &Chain::new(&keys, vec![open], closed), &tx);
    assert_eq!(
        constraint_violation(&r),
        (Position::Link(1), "checkout.allowed_merchants")
    );
}

#[test]
fn uc01_a2_replayed_closed_mandate_is_rejected() {
    let keys = Keys::new();
    let mandate = open_payment(json!([{"id": "shop-s", "name": "S"}]), 15000);
    let presentation =
        Chain::new(&keys, vec![mandate.clone()], payment("shop-s", 3490, "EUR")).build();
    let receipt = SigningKey::generate_p256();
    let status = valid_status();

    // Verifier challenge: the second checkout has a new challenge.
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status);
    assert!(run(&verifier, &keys, &presentation, &payment_tx())
        .outcome()
        .is_ok());
    let mut next = payment_tx();
    next.nonce = Nonce::Challenge("challenge-0002".into());
    let r = run(&verifier, &keys, &presentation, &next)
        .into_outcome()
        .unwrap_err();
    assert_eq!(credential_error(&r).0, ErrorKind::NonceMismatch);

    // Agent-chosen nonce: accepted once within the freshness window.
    let store = MemoryNonceStore::default();
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status).with_nonce_store(&store);
    let mut agent = payment_tx();
    agent.nonce = Nonce::AgentGenerated;
    assert!(run(&verifier, &keys, &presentation, &agent)
        .outcome()
        .is_ok());
    let r = run(&verifier, &keys, &presentation, &agent)
        .into_outcome()
        .unwrap_err();
    assert_eq!(r, Reason::Replay);

    // ... and never without a store to remember it in.
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &status);
    let r = run(&verifier, &keys, &presentation, &agent)
        .into_outcome()
        .unwrap_err();
    assert!(matches!(r, Reason::NonceStore(_)));
}

#[test]
fn uc01_a3_changed_amount_breaks_the_signature() {
    let keys = Keys::new();
    let mandate = open_payment(json!([{"id": "shop-s", "name": "S"}]), 15000);
    let presentation = Chain::new(&keys, vec![mandate], payment("shop-s", 3490, "EUR")).build();
    // Re-encode the closed mandate's Delegate Payload with 4900 instead.
    let (head, last) = presentation.rsplit_once("~~").unwrap();
    let mut parts: Vec<String> = last.split('~').map(str::to_owned).collect();
    let mut disclosure: Value = serde_json::from_slice(&B64.decode(&parts[1]).unwrap()).unwrap();
    disclosure[1]["payment_amount"]["amount"] = json!(4900);
    parts[1] = B64.encode(disclosure.to_string());
    let forged = format!("{head}~~{}", parts.join("~"));

    let receipt = SigningKey::generate_p256();
    let verifier = Verifier::new(policy(), VERIFIER, &receipt, &NoStatusList);
    let r = run(&verifier, &keys, &forged, &payment_tx())
        .into_outcome()
        .unwrap_err();
    assert_eq!(
        credential_error(&r),
        (ErrorKind::UnreferencedDisclosure, Some(Position::Link(2)))
    );
}

#[test]
fn uc06_a1_drip_pricing_above_the_range_is_rejected() {
    let keys = Keys::new();
    let mandate = open_payment(json!([{"id": "airline", "name": "L"}]), 22000);
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![mandate], payment("airline", 31000, "EUR")),
        &payment_tx(),
    );
    assert_eq!(constraint_violation(&r).1, "payment.amount_range");
}

// ---- UC03, UC04, UC09, UC10: credential, status, freshness -----------------

#[test]
fn uc04_a3_credential_transplant_is_rejected() {
    // The open mandate is signed by another person's key, attached to this
    // user's credential.
    let keys = Keys::new();
    let mandate = open_payment(json!([{"id": "wine-shop", "name": "W"}]), 15000);
    let mut chain = Chain::new(&keys, vec![mandate], payment("wine-shop", 4500, "EUR"));
    chain.signer_override = Some((0, SigningKey::generate_p256()));
    let r = reject(&keys, &chain, &payment_tx());
    assert_eq!(
        credential_error(&r),
        (ErrorKind::BadSignature, Some(Position::Link(1)))
    );
}

#[test]
fn uc03_a4_uc10_a4_user_signed_closed_mandate_is_bound_to_one_verifier_and_moment() {
    // CG2: the user signs the concrete action directly, with the verifier's
    // nonce and aud inside; no open mandate at all.
    let keys = Keys::new();
    let closed = payment("tv-shop", 189900, "EUR");
    accept(
        &keys,
        &Chain::new(&keys, vec![], closed.clone()),
        &payment_tx(),
    );

    let mut elsewhere = Chain::new(&keys, vec![], closed.clone());
    elsewhere.audience = "https://other-shop.example".into();
    let r = reject(&keys, &elsewhere, &payment_tx());
    assert_eq!(credential_error(&r).0, ErrorKind::AudienceMismatch);

    let mut later = Chain::new(&keys, vec![], closed);
    later.iat = NOW - 7 * 86_400;
    let r = reject(&keys, &later, &payment_tx());
    assert_eq!(credential_error(&r).0, ErrorKind::IatOutOfWindow);
}

#[test]
fn uc09_a4_revoked_or_unknown_status_is_rejected() {
    let keys = Keys::new();
    let mut mandate = common::obj(open_payment(
        json!([{"id": "landlord", "name": "L"}]),
        90000,
    ));
    mandate.insert(
        "status".into(),
        json!({"status_list": {"idx": 3, "uri": "https://is.example/sl"}}),
    );
    mandate.insert("exp".into(), json!(NOW + 30 * 86_400));
    let presentation = Chain::new(
        &keys,
        vec![Value::Object(mandate)],
        payment("landlord", 85000, "EUR"),
    )
    .build();
    let receipt = SigningKey::generate_p256();
    let outcome = |status: &FixedStatus| {
        let verifier = Verifier::new(policy(), VERIFIER, &receipt, status);
        run(&verifier, &keys, &presentation, &payment_tx()).into_outcome()
    };
    assert!(outcome(&valid_status()).is_ok());
    assert_eq!(
        outcome(&FixedStatus(Ok(TokenStatus::Invalid))).unwrap_err(),
        Reason::Revoked {
            position: Position::Link(1),
            status: TokenStatus::Invalid
        }
    );
    assert!(matches!(
        outcome(&FixedStatus(Ok(TokenStatus::Suspended))).unwrap_err(),
        Reason::Revoked {
            status: TokenStatus::Suspended,
            ..
        }
    ));
    // The list cannot be fetched and no fresh copy is cached: fail closed.
    let r = outcome(&FixedStatus(Err(StatusError("timeout".into())))).unwrap_err();
    assert!(matches!(
        r,
        Reason::StatusUnavailable {
            position: Position::Link(1),
            ..
        }
    ));
    assert_eq!(r.code(), ErrorCode::InvalidCredential);
}

// ---- Fail-closed rules that are not one scenario -------------------------

#[test]
fn unknown_or_misplaced_constraints_are_unresolved() {
    let keys = Keys::new();
    let closed = action(json!({"action": "message.send"}));
    for constraints in [
        json!([{"type": "aap.actions", "allowed": ["message.send"]}, {"type": "aap.rate", "max_count": 4, "period": "day"}]),
        json!([{"type": "aap.actions", "allowed": ["message.send"]}, {"type": "payment.amount_range", "currency": "EUR", "max": 1}]),
    ] {
        let r = reject(
            &keys,
            &Chain::new(&keys, vec![authority(constraints)], closed.clone()),
            &challenge(),
        );
        assert_eq!(r.code(), ErrorCode::UnresolvedConstraint, "{r}");
    }
}

#[test]
fn a_chain_stays_in_one_mandate_family() {
    let keys = Keys::new();
    let checkout = json!({
        "vct": "mandate.checkout.open.1",
        "constraints": [{"type": "checkout.allowed_merchants", "allowed": [{"id": "m", "name": "M"}]}]
    });
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![checkout], payment("m", 100, "EUR")),
        &payment_tx(),
    );
    assert!(
        matches!(
            r,
            Reason::Chain {
                cause: Cause::FamilyMismatch { .. },
                ..
            }
        ),
        "{r}"
    );
}

#[test]
fn pre_set_claims_must_reach_the_closed_mandate_unchanged() {
    let keys = Keys::new();
    let mut mandate = common::obj(open_payment(json!([{"id": "shop", "name": "S"}]), 50000));
    mandate.insert(
        "payment_amount".into(),
        json!({"amount": 1999, "currency": "EUR"}),
    );
    let mandate = Value::Object(mandate);
    accept(
        &keys,
        &Chain::new(&keys, vec![mandate.clone()], payment("shop", 1999, "EUR")),
        &payment_tx(),
    );
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![mandate], payment("shop", 2999, "EUR")),
        &payment_tx(),
    );
    assert_eq!(
        r,
        Reason::Chain {
            position: Position::Link(1),
            cause: Cause::Preset {
                claim: "payment_amount".into()
            }
        }
    );
}

#[test]
fn time_windows_use_the_verifier_clock_not_the_agent_claim() {
    // v0 bug 1. NOW (1 800 000 000) is Friday 2027-01-15 08:00 UTC.
    let keys = Keys::new();
    let window = |start: &str, end: &str| {
        authority(json!([
            {"type": "aap.actions", "allowed": ["message.send"]},
            {"type": "aap.time_windows", "windows": [{"days": ["fri"], "start": start, "end": end, "timezone": "UTC"}]}
        ]))
    };
    let closed = action(json!({"action": "message.send"}));
    accept(
        &keys,
        &Chain::new(&keys, vec![window("07:30", "08:30")], closed.clone()),
        &challenge(),
    );
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![window("09:00", "17:00")], closed),
        &challenge(),
    );
    assert_eq!(constraint_violation(&r).1, "aap.time_windows");
    // An agent-written timestamp is not even a known member of the action.
    let stamped = action(json!({"action": "message.send", "timestamp": "2027-01-15T10:00:00Z"}));
    let r = reject(
        &keys,
        &Chain::new(&keys, vec![window("09:00", "17:00")], stamped),
        &challenge(),
    );
    assert!(
        matches!(
            r,
            Reason::Mandate {
                error: MandateError::Schema(_),
                ..
            }
        ),
        "{r}"
    );
}

#[test]
fn negative_and_fractional_amounts_are_schema_errors() {
    // v0 bug 2.
    let keys = Keys::new();
    let m = authority(json!([
        {"type": "aap.actions", "allowed": ["refund"]},
        {"type": "aap.amount", "max": 1000, "currency": "EUR"}
    ]));
    for amount in [json!(-500), json!(10.5)] {
        let closed =
            action(json!({"action": "refund", "amount": {"amount": amount, "currency": "EUR"}}));
        let r = reject(
            &keys,
            &Chain::new(&keys, vec![m.clone()], closed),
            &challenge(),
        );
        assert!(
            matches!(
                r,
                Reason::Mandate {
                    error: MandateError::Schema(_),
                    ..
                }
            ),
            "{r}"
        );
    }
}

#[test]
fn every_outcome_gets_a_signed_receipt() {
    let keys = Keys::new();
    let receipt_key = SigningKey::generate_p256();
    let verifier = Verifier::new(policy(), VERIFIER, &receipt_key, &NoStatusList);
    let garbage = "not a presentation";
    let decision = verifier
        .verify(garbage, &keys.issuer.verifying_key(), &challenge(), NOW)
        .unwrap();
    let claims = aap_sdjwt::verify_jwt(
        decision.receipt_jwt(),
        &receipt_key.verifying_key(),
        &[aap_authority::names::RECEIPT_TYP],
    )
    .unwrap()
    .claims()
    .clone();
    assert_eq!(claims["iss"], VERIFIER);
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["result"], "error");
    assert_eq!(claims["error"], "invalid_credential");
    assert_eq!(claims["reference"], SdAlg::Sha256.digest(garbage));

    let mandate = authority(json!([{"type": "aap.actions", "allowed": ["quote.request"]}]));
    let presentation = Chain::new(
        &keys,
        vec![mandate],
        action(json!({"action": "quote.request"})),
    )
    .build();
    let decision = run(&verifier, &keys, &presentation, &challenge());
    let a = decision.outcome().unwrap();
    let receipt = decision.receipt();
    assert_eq!(receipt.result(), "success");
    assert!(receipt.error.is_none());
    let leaf = a.chain().leaf();
    assert_eq!(receipt.reference, leaf.sd_alg().digest(leaf.sd_jwt()));
    assert_eq!(receipt.aap_chain.len(), 3, "credential, open, closed");
    assert!(
        matches!(a.principal(), aap_authority::Principal::Credential { user_key: Some(k), .. } if *k == keys.user().verifying_key())
    );
}

#[test]
fn root_credential_type_is_the_verifier_s_choice() {
    let keys = Keys::new();
    let receipt = SigningKey::generate_p256();
    let mut policy = policy();
    policy.root = aap_authority::RootPolicy::Credential {
        typ: vec![aap_sdjwt::typ::SD_JWT_VC.into()],
        vct: vec!["urn:aap:vhc:1".into()],
    };
    let verifier = Verifier::new(policy, VERIFIER, &receipt, &NoStatusList);
    let mandate = authority(json!([{"type": "aap.actions", "allowed": ["quote.request"]}]));
    let presentation = Chain::new(
        &keys,
        vec![mandate],
        action(json!({"action": "quote.request"})),
    )
    .build();
    let r = run(&verifier, &keys, &presentation, &challenge())
        .into_outcome()
        .unwrap_err();
    assert_eq!(r, Reason::RootNotAccepted);
}
