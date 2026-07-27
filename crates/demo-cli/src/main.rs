use chrono::{Duration, Utc};

use aap_core::{
    delegation, message, ActionRequest, Amount, DelegationParams, InMemoryNonceStore,
    InMemoryRegistry, InMemoryStatus, LocalSigner, PrincipalType, Scope, Signer,
    VerificationFailure, Verifier,
};

fn line() {
    println!("{}", "-".repeat(72));
}

fn main() {
    println!("Agent Authority Protocol — reference demo\n");

    // --- Setup: a Principal (Neo) and an Agent (Wave) with their own keypairs.
    let principal_signer = LocalSigner::generate();
    let agent_signer = LocalSigner::generate();

    let registry = InMemoryRegistry::new();
    registry.register("principal:neo", principal_signer.public_jwk());

    let status = InMemoryStatus::new();
    let nonces = InMemoryNonceStore::new();
    let verifier = Verifier::new("bank-api", &registry, &status, &nonces);

    // --- Principal issues a Delegation: Wave may create payments up to 200 EUR.
    println!("1) Principal 'neo' issues a Delegation to Agent 'wave-1':");
    println!("   scope = create_payment, max 200 EUR\n");

    let del = delegation::issue(
        &principal_signer,
        DelegationParams {
            principal_id: "principal:neo".into(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "agent:wave-1".into(),
            agent_public_key: agent_signer.public_jwk(),
            scope: Scope {
                actions: vec!["create_payment".into()],
                max_amount: Some(Amount {
                    value: 200.0,
                    currency: "EUR".into(),
                }),
                ..Default::default()
            },
            valid_for: Duration::hours(1),
            status_endpoint: "https://registry.example.org/status".into(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .expect("issuance should succeed");

    println!("   delegation_id = {}", del.payload.delegation_id);
    line();

    // --- Scenario A: in-scope request. Should be accepted.
    println!("2) Agent 'wave-1' requests: create_payment, 150 EUR -> 'bank-api'");
    let req_a = ActionRequest {
        action: "create_payment".into(),
        amount: Some(Amount {
            value: 150.0,
            currency: "EUR".into(),
        }),
        timestamp: Utc::now(),
        ..Default::default()
    };
    let msg_a = message::issue(&agent_signer, "agent:wave-1", "bank-api", req_a).unwrap();
    report(verifier.verify(&[&del.jws], &msg_a.jws));
    line();

    // --- Scenario B: scope violation (amount over the ceiling). Should be rejected.
    println!("3) Agent 'wave-1' requests: create_payment, 5000 EUR -> 'bank-api'");
    println!("   (exceeds the 200 EUR ceiling in the delegation)");
    let req_b = ActionRequest {
        action: "create_payment".into(),
        amount: Some(Amount {
            value: 5000.0,
            currency: "EUR".into(),
        }),
        timestamp: Utc::now(),
        ..Default::default()
    };
    let msg_b = message::issue(&agent_signer, "agent:wave-1", "bank-api", req_b).unwrap();
    report(verifier.verify(&[&del.jws], &msg_b.jws));
    line();

    // --- Scenario C: replay of message A. Should be rejected.
    println!("4) Someone replays the exact same signed message from step 2 again");
    report(verifier.verify(&[&del.jws], &msg_a.jws));
    line();

    // --- Scenario D: Principal revokes the delegation. A fresh, otherwise-valid request now fails.
    println!(
        "5) Principal 'neo' revokes delegation {}",
        del.payload.delegation_id
    );
    status.revoke(del.payload.delegation_id);
    println!("   Agent 'wave-1' requests: create_payment, 50 EUR -> 'bank-api' (fresh nonce)");
    let req_d = ActionRequest {
        action: "create_payment".into(),
        amount: Some(Amount {
            value: 50.0,
            currency: "EUR".into(),
        }),
        timestamp: Utc::now(),
        ..Default::default()
    };
    let msg_d = message::issue(&agent_signer, "agent:wave-1", "bank-api", req_d).unwrap();
    report(verifier.verify(&[&del.jws], &msg_d.jws));
    line();

    println!("Done. Every accept/reject above was decided by pure signature + time +");
    println!("revocation + scope checks in aap-core::verifier — no LLM in the trust path.");
}

fn report(result: Result<aap_core::VerifiedAction, VerificationFailure>) {
    match result {
        Ok(action) => {
            println!(
                "   -> ACCEPTED: agent '{}' authorized to '{}' (chain depth {})",
                action.agent_message.agent_id,
                action.agent_message.request.action,
                action.delegation_chain.len()
            );
        }
        Err(reason) => {
            println!("   -> REJECTED: {reason}");
        }
    }
}
