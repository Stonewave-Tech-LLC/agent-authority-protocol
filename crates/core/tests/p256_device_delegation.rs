//! End-to-end proof that the full Delegation -> AgentMessage -> Verifier ->
//! Receipt flow works when the delegated party is a P-256 key — i.e. the
//! exact shape a real device's Secure Enclave key would take, not just the
//! server-held Ed25519 keys exercised by verifier_flow.rs. Deliberately its
//! own file/fixture rather than parametrizing verifier_flow.rs's tests, so
//! this reads as a standalone proof that P-256 support is real end-to-end,
//! not just at the jws.rs layer.

use chrono::{Duration, Utc};

use aap_core::{
    delegation, message, ActionRequest, DelegationParams, InMemoryNonceStore, InMemoryRegistry,
    InMemoryStatus, LocalSigner, PrincipalType, Scope, Signer, Verifier,
};

#[test]
fn a_p256_device_key_can_be_delegated_and_verified_like_any_other_agent() {
    // principal_signer stands in for Neo's principal key (still Ed25519 in
    // this test — the principal key issuing the Delegation is unrelated to
    // what curve the delegated agent/device key uses).
    let principal_signer = LocalSigner::generate();
    // device_signer stands in for a Secure Enclave-backed approval key on
    // Neo's Mac/iPhone — this is the whole point: Secure Enclave can only
    // ever produce P-256, so this MUST work for the device-delegation
    // design in the architecture proposal to be viable at all.
    let device_signer = LocalSigner::generate_p256();
    let receipt_signer = LocalSigner::generate();

    let registry = InMemoryRegistry::new();
    registry.register("principal:neo", principal_signer.public_jwk());
    let status = InMemoryStatus::new();
    let nonces = InMemoryNonceStore::new();

    let scope = Scope {
        actions: vec!["approve_pending_action".to_string()],
        ..Default::default()
    };

    let issued = delegation::issue(
        &principal_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "neo-device-mac".into(),
            agent_public_key: device_signer.public_jwk(),
            scope,
            valid_for: Duration::hours(24 * 365),
            status_endpoint:
                "https://systems.stonewavetech.com/api/aap/devices/neo-device-mac/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .expect("issuing a delegation to a P-256 device key must succeed");

    assert_eq!(issued.payload.agent_public_key.kty, "EC");
    assert_eq!(issued.payload.agent_public_key.crv, "P-256");

    let issued_message = message::issue(
        &device_signer,
        "neo-device-mac",
        "aap-verifier",
        ActionRequest {
            action: "approve_pending_action".into(),
            resource: Some("pending_action:11111111-1111-1111-1111-111111111111".into()),
            timestamp: Utc::now(),
            ..Default::default()
        },
    )
    .expect("signing an AgentMessage with a P-256 key must succeed");

    let verifier = Verifier::new(
        "verifier:aap-verifier",
        "aap-verifier",
        &registry,
        &status,
        &nonces,
        &receipt_signer,
    );

    let outcome = verifier.verify(&[&issued.jws], &issued_message.jws);

    let verified = outcome
        .decision
        .expect("a validly signed P-256 approval must verify");
    assert_eq!(verified.agent_message.agent_id, "neo-device-mac");
    assert_eq!(
        verified.agent_message.request.action,
        "approve_pending_action"
    );

    // A stolen/replayed copy of the exact same signed approval must never
    // verify twice — this is the actual security property a Touch ID
    // approval leans on (one biometric prompt -> one usable signature).
    let replay_outcome = verifier.verify(&[&issued.jws], &issued_message.jws);
    assert!(
        replay_outcome.decision.is_err(),
        "replaying the same signed ChallengeResponse/approval must be rejected"
    );
}
