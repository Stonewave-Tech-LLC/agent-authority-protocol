use chrono::{Duration, Utc};

use aap_core::{
    delegation, message, ActionRequest, DelegationParams, InMemoryNonceStore, InMemoryRegistry,
    InMemoryStatus, LocalSigner, PrincipalType, Scope, Signer, VerificationFailure, Verifier,
};

struct Fixture {
    principal_signer: LocalSigner,
    agent_signer: LocalSigner,
    registry: InMemoryRegistry,
    status: InMemoryStatus,
    nonces: InMemoryNonceStore,
}

fn setup() -> Fixture {
    let principal_signer = LocalSigner::generate();
    let agent_signer = LocalSigner::generate();
    let registry = InMemoryRegistry::new();
    registry.register("principal:neo", principal_signer.public_jwk());
    Fixture {
        principal_signer,
        agent_signer,
        registry,
        status: InMemoryStatus::new(),
        nonces: InMemoryNonceStore::new(),
    }
}

fn issue_basic_delegation(f: &Fixture, scope: Scope) -> delegation::IssuedDelegation {
    delegation::issue(
        &f.principal_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1".into(),
            agent_public_key: f.agent_signer.public_jwk(),
            scope,
            valid_for: Duration::hours(1),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .expect("issuance should succeed")
}

fn payment_scope(max_eur: f64) -> Scope {
    Scope {
        actions: vec!["create_payment".into()],
        max_amount: Some(aap_core::Amount {
            value: max_eur,
            currency: "EUR".into(),
        }),
        ..Default::default()
    }
}

fn payment_request(amount_eur: f64) -> ActionRequest {
    ActionRequest {
        action: "create_payment".into(),
        amount: Some(aap_core::Amount {
            value: amount_eur,
            currency: "EUR".into(),
        }),
        timestamp: Utc::now(),
        ..Default::default()
    }
}

#[test]
fn accepts_a_valid_in_scope_request() {
    let f = setup();
    let del = issue_basic_delegation(&f, payment_scope(500.0));
    let msg = message::issue(
        &f.agent_signer,
        "agent:wave-1",
        "bank-api",
        payment_request(100.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&del.jws], &msg.jws);

    assert!(result.is_ok(), "expected accept, got {:?}", result.err());
}

#[test]
fn rejects_action_outside_scope() {
    let f = setup();
    let del = issue_basic_delegation(&f, payment_scope(500.0));
    // 1000 EUR exceeds the 500 EUR ceiling.
    let msg = message::issue(
        &f.agent_signer,
        "agent:wave-1",
        "bank-api",
        payment_request(1000.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&del.jws], &msg.jws);

    assert!(matches!(result, Err(VerificationFailure::ScopeDenied)));
}

#[test]
fn rejects_revoked_delegation() {
    let f = setup();
    let del = issue_basic_delegation(&f, payment_scope(500.0));
    f.status.revoke(del.payload.delegation_id);
    let msg = message::issue(
        &f.agent_signer,
        "agent:wave-1",
        "bank-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&del.jws], &msg.jws);

    assert!(matches!(result, Err(VerificationFailure::Revoked)));
}

#[test]
fn rejects_message_signed_for_a_different_verifier() {
    let f = setup();
    let del = issue_basic_delegation(&f, payment_scope(500.0));
    // Signed for "other-api", but presented to "bank-api" — confused-deputy replay.
    let msg = message::issue(
        &f.agent_signer,
        "agent:wave-1",
        "other-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&del.jws], &msg.jws);

    assert!(matches!(result, Err(VerificationFailure::AudienceMismatch)));
}

#[test]
fn rejects_replayed_nonce() {
    let f = setup();
    let del = issue_basic_delegation(&f, payment_scope(500.0));
    let msg = message::issue(
        &f.agent_signer,
        "agent:wave-1",
        "bank-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let first = verifier.verify(&[&del.jws], &msg.jws);
    assert!(first.is_ok());

    // Same exact signed message presented again.
    let second = verifier.verify(&[&del.jws], &msg.jws);
    assert!(matches!(second, Err(VerificationFailure::NonceReplayed)));
}

#[test]
fn rejects_delegation_signed_by_the_wrong_key() {
    let f = setup();
    let impostor = LocalSigner::generate();
    // Signed by someone who is NOT "principal:neo" in the registry.
    let del = delegation::issue(
        &impostor,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1".into(),
            agent_public_key: f.agent_signer.public_jwk(),
            scope: payment_scope(500.0),
            valid_for: Duration::hours(1),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .unwrap();
    let msg = message::issue(
        &f.agent_signer,
        "agent:wave-1",
        "bank-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&del.jws], &msg.jws);

    assert!(matches!(
        result,
        Err(VerificationFailure::InvalidDelegationSignature)
    ));
}

#[test]
fn rejects_expired_delegation() {
    let f = setup();
    let mut del = issue_basic_delegation(&f, payment_scope(500.0));
    // Tamper is not possible post-signature (that's the point) — instead
    // issue with a window that's already in the past by re-signing directly.
    del.payload.valid_until = Utc::now() - Duration::minutes(1);
    let del = delegation::issue(
        &f.principal_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1".into(),
            agent_public_key: f.agent_signer.public_jwk(),
            scope: payment_scope(500.0),
            valid_for: Duration::seconds(-1),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .unwrap();
    let msg = message::issue(
        &f.agent_signer,
        "agent:wave-1",
        "bank-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&del.jws], &msg.jws);

    assert!(matches!(result, Err(VerificationFailure::Expired)));
}

#[test]
fn sub_delegation_chain_is_accepted_when_scope_narrows() {
    let f = setup();
    let sub_agent_signer = LocalSigner::generate();

    let root = delegation::issue(
        &f.principal_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1".into(),
            agent_public_key: f.agent_signer.public_jwk(),
            scope: payment_scope(500.0),
            valid_for: Duration::hours(1),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: true,
            max_delegation_depth: Some(2),
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .unwrap();

    // agent:wave-1 sub-delegates a *narrower* scope to agent:wave-1-sub, signing with its OWN key.
    let sub = delegation::issue(
        &f.agent_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1-sub".into(),
            agent_public_key: sub_agent_signer.public_jwk(),
            scope: payment_scope(100.0), // narrower than the 500 ceiling above
            valid_for: Duration::minutes(30),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: Some(root.payload.delegation_id),
            metadata: None,
        },
    )
    .unwrap();

    let msg = message::issue(
        &sub_agent_signer,
        "agent:wave-1-sub",
        "bank-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    // Leaf-first: the sub-delegation, then its parent.
    let result = verifier.verify(&[&sub.jws, &root.jws], &msg.jws);

    assert!(result.is_ok(), "expected accept, got {:?}", result.err());
}

#[test]
fn sub_delegation_chain_rejects_scope_widening() {
    let f = setup();
    let sub_agent_signer = LocalSigner::generate();

    let root = delegation::issue(
        &f.principal_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1".into(),
            agent_public_key: f.agent_signer.public_jwk(),
            scope: payment_scope(100.0),
            valid_for: Duration::hours(1),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: true,
            max_delegation_depth: Some(2),
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .unwrap();

    // Attempted privilege escalation: sub-delegation raises the ceiling above the parent's.
    let sub = delegation::issue(
        &f.agent_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1-sub".into(),
            agent_public_key: sub_agent_signer.public_jwk(),
            scope: payment_scope(1000.0),
            valid_for: Duration::minutes(30),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: Some(root.payload.delegation_id),
            metadata: None,
        },
    )
    .unwrap();

    let msg = message::issue(
        &sub_agent_signer,
        "agent:wave-1-sub",
        "bank-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&sub.jws, &root.jws], &msg.jws);

    assert!(matches!(result, Err(VerificationFailure::ScopeNotNarrowed)));
}

#[test]
fn rejects_sub_delegation_when_parent_forbids_delegation() {
    let f = setup();
    let sub_agent_signer = LocalSigner::generate();

    let root = issue_basic_delegation(&f, payment_scope(500.0)); // can_delegate: false by default

    let sub = delegation::issue(
        &f.agent_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1-sub".into(),
            agent_public_key: sub_agent_signer.public_jwk(),
            scope: payment_scope(100.0),
            valid_for: Duration::minutes(30),
            status_endpoint: "https://example.org/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: Some(root.payload.delegation_id),
            metadata: None,
        },
    )
    .unwrap();

    let msg = message::issue(
        &sub_agent_signer,
        "agent:wave-1-sub",
        "bank-api",
        payment_request(50.0),
    )
    .unwrap();

    let verifier = Verifier::new("bank-api", &f.registry, &f.status, &f.nonces);
    let result = verifier.verify(&[&sub.jws, &root.jws], &msg.jws);

    assert!(matches!(result, Err(VerificationFailure::ChainBroken(_))));
}
