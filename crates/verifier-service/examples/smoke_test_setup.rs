//! Throwaway smoke-test fixture generator, NOT part of the shipped service.
//! Registers a disposable test principal in aap_principals, issues a
//! Delegation to a P-256 "device" key, signs an AgentMessage against it,
//! and prints everything /verify needs as JSON on stdout so it can be piped
//! straight into `curl`. Run `cargo run --example smoke_test_cleanup` after
//! to remove the test principal row again.

use aap_core::{
    delegation, message, ActionRequest, DelegationParams, LocalSigner, PrincipalType, Scope, Signer,
};
use chrono::{Duration, Utc};
use tokio_postgres::NoTls;

const TEST_PRINCIPAL_ID: &str = "principal:smoke-test-throwaway";

#[tokio::main]
async fn main() {
    let database_url =
        std::env::var("AAP_VERIFIER_DATABASE_URL").expect("set AAP_VERIFIER_DATABASE_URL");
    let (client, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });

    let principal_signer = LocalSigner::generate();
    let device_signer = LocalSigner::generate_p256();

    let principal_jwk = serde_json::to_value(principal_signer.public_jwk()).unwrap();
    client
        .execute(
            "insert into aap_principals (principal_id, principal_type, public_key, display_name) \
             values ($1, 'natural_person', $2, 'Smoke Test Throwaway') \
             on conflict (principal_id) do update set public_key = excluded.public_key",
            &[&TEST_PRINCIPAL_ID, &principal_jwk],
        )
        .await
        .expect("insert principal");

    let scope = Scope {
        actions: vec!["approve_pending_action".to_string()],
        ..Default::default()
    };

    let issued = delegation::issue(
        &principal_signer,
        DelegationParams {
            principal_id: TEST_PRINCIPAL_ID.to_string(),
            principal_type: PrincipalType::NaturalPerson,
            agent_id: "smoke-test-device".to_string(),
            agent_public_key: device_signer.public_jwk(),
            scope,
            valid_for: Duration::hours(1),
            status_endpoint: "https://example.invalid/status".to_string(),
            can_delegate: false,
            max_delegation_depth: None,
            parent_delegation_id: None,
            metadata: None,
        },
    )
    .expect("issue delegation");

    // The verifier looks up revocation status in aap_delegations, not by
    // trusting the JWS alone — an issued-but-never-registered delegation
    // must fail closed (see PgStatusChecker/status_for_chain: "unknown"
    // is treated as revoked). A real device-pairing flow would insert this
    // row as part of accepting the pairing request; this smoke test does
    // the same thing by hand.
    let scope_json = serde_json::to_value(&issued.payload.scope).unwrap();
    let agent_public_key_json = serde_json::to_value(&issued.payload.agent_public_key).unwrap();
    client
        .execute(
            "insert into aap_delegations \
                (delegation_id, subject_type, subject_id, principal_id, scope, valid_from, \
                 valid_until, can_delegate, delegation_jws, agent_public_key, status_endpoint) \
             values ($1, 'device', $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &issued.payload.delegation_id,
                &issued.payload.agent_id,
                &TEST_PRINCIPAL_ID,
                &scope_json,
                &issued.payload.valid_from,
                &issued.payload.valid_until,
                &issued.payload.can_delegate,
                &issued.jws,
                &agent_public_key_json,
                &issued.payload.status_endpoint,
            ],
        )
        .await
        .expect("insert delegation row");

    let issued_message = message::issue(
        &device_signer,
        "smoke-test-device",
        "aap-verifier",
        ActionRequest {
            action: "approve_pending_action".to_string(),
            resource: Some("smoke-test-resource".to_string()),
            timestamp: Utc::now(),
            ..Default::default()
        },
    )
    .expect("issue message");

    let body = serde_json::json!({
        "delegation_chain_jws": [issued.jws],
        "agent_message_jws": issued_message.jws,
    });

    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    eprintln!("test principal_id: {TEST_PRINCIPAL_ID}");
}
