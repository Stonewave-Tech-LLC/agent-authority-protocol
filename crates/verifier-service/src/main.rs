//! Thin HTTP wrapper around aap-core's `Verifier`. Deliberately does as
//! little as possible itself: authentication of the *caller* (shared
//! secret, matching the existing internal-service pattern already used
//! elsewhere in this stack — x-render-secret, x-scout-secret, etc.), async
//! Postgres prefetch (see db.rs for why this is async and the actual
//! verification is not), then hands off to aap-core for every actual trust
//! decision, then persists whatever aap-core decided (a signed Receipt,
//! always, accept or reject) and returns it. No policy logic lives here.

mod db;

use std::sync::Arc;

use aap_core::token::{AgentMessageToken, DelegationToken};
use aap_core::{LocalSigner, Verifier};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

struct AppState {
    pool: Pool,
    receipt_signer: LocalSigner,
    verifier_id: String,
    audience: String,
    shared_secret: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    /// Leaf-first, as required by aap-core's Verifier::verify.
    delegation_chain_jws: Vec<String>,
    agent_message_jws: String,
    /// Exactly one of these should be set by the caller — which row this
    /// verification is *about*, purely for the receipt's foreign key. Never
    /// used in the verification decision itself.
    pending_action_id: Option<Uuid>,
    challenge_id: Option<Uuid>,
}

#[derive(Serialize)]
struct VerifyResponse {
    accepted: bool,
    reason: Option<String>,
    receipt_id: Uuid,
    receipt_jws: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let database_url =
        std::env::var("AAP_VERIFIER_DATABASE_URL").expect("AAP_VERIFIER_DATABASE_URL must be set");
    let shared_secret = std::env::var("AAP_VERIFIER_SHARED_SECRET").expect(
        "AAP_VERIFIER_SHARED_SECRET must be set — this service must never accept unauthenticated callers",
    );
    let verifier_id =
        std::env::var("AAP_VERIFIER_ID").unwrap_or_else(|_| "verifier:aap-verifier".to_string());
    let audience =
        std::env::var("AAP_VERIFIER_AUDIENCE").unwrap_or_else(|_| "aap-verifier".to_string());
    let port: u16 = std::env::var("AAP_VERIFIER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8500);

    // TODO(phase 1 follow-up): load a persisted Ed25519 seed from
    // AAP_VERIFIER_RECEIPT_SIGNING_KEY instead of always generating fresh.
    // Left as a loud startup warning rather than silently accepted, so it
    // can't be mistaken for "already handled". Every receipt issued by THIS
    // process instance is internally consistent (same key for the whole
    // run — cloned once into every request handler below), but a restart
    // today invalidates the ability to verify old receipts against a
    // stable verifier public key.
    if std::env::var("AAP_VERIFIER_RECEIPT_SIGNING_KEY").is_err() {
        tracing::warn!(
            "AAP_VERIFIER_RECEIPT_SIGNING_KEY not set — generating an ephemeral receipt \
             signing key for this process run. Fine for local dev, NOT fine for production: \
             receipts won't be checkable against a stable key across restarts."
        );
    }
    let receipt_signer = LocalSigner::generate();

    let pool = db::build_pool(&database_url);

    let state = Arc::new(AppState {
        pool,
        receipt_signer,
        verifier_id,
        audience,
        shared_secret,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/verify", post(verify))
        .route(
            "/verify-delegation-signature",
            post(verify_delegation_signature),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("failed to bind 127.0.0.1:{port}: {e}"));
    tracing::info!("aap-verifier-service listening on 127.0.0.1:{port}");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> &'static str {
    "ok"
}

fn authorized(headers: &HeaderMap, expected_secret: &str) -> bool {
    headers
        .get("x-verifier-secret")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == expected_secret)
}

async fn verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    if !authorized(&headers, &state.shared_secret) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid or missing x-verifier-secret".into(),
        ));
    }
    if req.delegation_chain_jws.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "delegation_chain_jws must not be empty".into(),
        ));
    }

    // Peek at the UNVERIFIED payloads purely to know what to prefetch from
    // Postgres. Never used for any trust decision — that happens only
    // inside verifier.verify() below, against the cryptographically
    // verified payloads. Malformed JWS here just means the prefetch finds
    // nothing useful, and verify() itself reports the real parse/signature
    // failure as the rejection reason.
    let unverified_chain: Vec<_> = req
        .delegation_chain_jws
        .iter()
        .filter_map(|jws| DelegationToken::from_jws(jws).ok())
        .collect();
    let delegation_ids: Vec<Uuid> = unverified_chain
        .iter()
        .map(|t| t.payload.delegation_id)
        .collect();
    let root_principal_id = unverified_chain
        .last()
        .map(|t| t.payload.principal_id.clone());

    let registry = match &root_principal_id {
        Some(pid) => db::registry_with_principal_key(&state.pool, pid)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?,
        None => aap_core::InMemoryRegistry::new(),
    };
    let status = db::status_for_chain(&state.pool, &delegation_ids)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let nonces = if let Ok(unverified_msg) = AgentMessageToken::from_jws(&req.agent_message_jws) {
        db::precheck_nonce(
            &state.pool,
            &unverified_msg.payload.agent_id,
            &unverified_msg.payload.nonce,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    } else {
        // Malformed message JWS: verify() will reject it on parse anyway;
        // hand it a nonce store that can't accidentally claim "fresh".
        db::PrecomputedNonceStore::rejects_everything()
    };

    let verifier = Verifier::new(
        state.verifier_id.clone(),
        state.audience.clone(),
        &registry,
        &status,
        &nonces,
        &state.receipt_signer,
    );
    let chain_refs: Vec<&str> = req
        .delegation_chain_jws
        .iter()
        .map(String::as_str)
        .collect();
    let outcome = verifier.verify(&chain_refs, &req.agent_message_jws);

    let accepted = outcome.decision.is_ok();
    let reason = outcome.decision.as_ref().err().map(|e| e.to_string());
    let receipt = outcome.receipt;

    db::persist_receipt(
        &state.pool,
        &receipt.payload,
        &receipt.jws,
        req.pending_action_id,
        req.challenge_id,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(VerifyResponse {
        accepted,
        reason,
        receipt_id: receipt.payload.receipt_id,
        receipt_jws: receipt.jws,
    }))
}

#[derive(Deserialize)]
struct VerifyDelegationSignatureRequest {
    delegation_jws: String,
}

#[derive(Serialize)]
struct VerifyDelegationSignatureResponse {
    valid: bool,
    reason: Option<String>,
    delegation: Option<aap_core::Delegation>,
}

/// Used by the device-pairing finalize step (stonewave-systems): confirms a
/// freshly-issued Delegation was genuinely signed by the claimed principal's
/// own key, right now, within its stated validity window. Deliberately
/// narrower than `/verify`: no AgentMessage, no scope/nonce/audience check —
/// there is no request being authorized yet, only "is this Delegation
/// itself real". stonewave-systems is the one that decides whether to
/// persist it into aap_delegations after this comes back valid.
async fn verify_delegation_signature(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VerifyDelegationSignatureRequest>,
) -> Result<Json<VerifyDelegationSignatureResponse>, (StatusCode, String)> {
    if !authorized(&headers, &state.shared_secret) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid or missing x-verifier-secret".into(),
        ));
    }

    let Ok(unverified) = DelegationToken::from_jws(&req.delegation_jws) else {
        return Ok(Json(VerifyDelegationSignatureResponse {
            valid: false,
            reason: Some("malformed delegation JWS".into()),
            delegation: None,
        }));
    };
    let principal_id = unverified.payload.principal_id.clone();

    let registry = db::registry_with_principal_key(&state.pool, &principal_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let verified = match aap_core::KeyResolver::resolve_principal_key(&registry, &principal_id)
        .ok()
        .and_then(|key| unverified.verify_signature(&key).ok())
    {
        Some(v) => v,
        None => {
            return Ok(Json(VerifyDelegationSignatureResponse {
                valid: false,
                reason: Some("signature invalid or unknown principal_id".into()),
                delegation: None,
            }))
        }
    };

    let now = chrono::Utc::now();
    if now < verified.payload.valid_from || now > verified.payload.valid_until {
        return Ok(Json(VerifyDelegationSignatureResponse {
            valid: false,
            reason: Some("delegation is outside its valid_from/valid_until window".into()),
            delegation: None,
        }));
    }

    Ok(Json(VerifyDelegationSignatureResponse {
        valid: true,
        reason: None,
        delegation: Some(verified.payload),
    }))
}
