//! Async I/O against Postgres, kept entirely separate from the actual trust
//! decision. aap-core's KeyResolver/StatusChecker/NonceStore traits are
//! deliberately synchronous (keeps the core crate dependency-light and
//! usable from a WASM demo) — this service resolves that by doing all
//! Postgres access asynchronously *before* calling `Verifier::verify()`,
//! then handing aap-core small, already-populated in-memory adapters
//! (`InMemoryRegistry`/`InMemoryStatus`, both shipped by aap-core itself)
//! plus one precomputed nonce-freshness bool. The verify() call itself is
//! then a pure, fast, synchronous computation with zero I/O inside it —
//! never a blocking DB client fighting the async runtime for control of a
//! thread (an earlier version of this file tried spawn_blocking + a
//! blocking postgres client and crashed with "cannot start a runtime from
//! within a runtime": the blocking `postgres` crate builds its own runtime
//! internally and refuses to do so from a thread tokio already manages).

use aap_core::nonce::NonceStore;
use aap_core::{InMemoryRegistry, InMemoryStatus, PublicKeyJwk};
use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;
use uuid::Uuid;

pub fn build_pool(database_url: &str) -> Pool {
    let mut cfg = Config::new();
    cfg.url = Some(database_url.to_string());
    cfg.pool = Some(deadpool_postgres::PoolConfig::new(8));
    cfg.create_pool(Some(Runtime::Tokio1), NoTls)
        .expect("failed to build Postgres connection pool")
}

/// Looks up a principal's public key and, if found, registers it into a
/// fresh `InMemoryRegistry` under that same principal_id — the exact shape
/// `Verifier::verify()` expects from `KeyResolver`. Not found -> an empty
/// registry, which makes aap-core's own `resolve_principal_key` fail
/// naturally with "unknown principal_id" (no special-casing here).
pub async fn registry_with_principal_key(
    pool: &Pool,
    principal_id: &str,
) -> Result<InMemoryRegistry, String> {
    let registry = InMemoryRegistry::new();
    let client = pool
        .get()
        .await
        .map_err(|e| format!("db pool error: {e}"))?;
    let row = client
        .query_opt(
            "select public_key from aap_principals where principal_id = $1",
            &[&principal_id],
        )
        .await
        .map_err(|e| format!("db query error: {e}"))?;
    if let Some(row) = row {
        let jwk_value: serde_json::Value = row.get(0);
        let jwk: PublicKeyJwk =
            serde_json::from_value(jwk_value).map_err(|e| format!("malformed stored JWK: {e}"))?;
        registry.register(principal_id, jwk);
    }
    Ok(registry)
}

/// Looks up revocation status for every delegation_id in the presented
/// chain and returns an `InMemoryStatus` with the revoked ones marked.
/// Fails closed: a delegation_id this service has never heard of is
/// treated as revoked (`.revoke()`d) — "unknown" must never silently pass
/// as "valid".
pub async fn status_for_chain(
    pool: &Pool,
    delegation_ids: &[Uuid],
) -> Result<InMemoryStatus, String> {
    let status = InMemoryStatus::new();
    let client = pool
        .get()
        .await
        .map_err(|e| format!("db pool error: {e}"))?;
    for id in delegation_ids {
        let row = client
            .query_opt(
                "select revoked_at from aap_delegations where delegation_id = $1",
                &[id],
            )
            .await
            .map_err(|e| format!("db query error: {e}"))?;
        let revoked = match row {
            Some(r) => {
                let revoked_at: Option<chrono::DateTime<chrono::Utc>> = r.get(0);
                revoked_at.is_some()
            }
            None => true, // never issued / unknown -> fail closed
        };
        if revoked {
            status.revoke(*id);
        }
    }
    Ok(status)
}

/// Atomically checks-and-records (agent_id, nonce) against aap_nonces
/// *before* verify() runs, then hands verify() a `PrecomputedNonceStore`
/// that just replays this one precomputed answer for that exact pair.
/// Extracting agent_id/nonce from the *unverified* AgentMessage payload is
/// safe here: signature verification never changes field values, it only
/// proves who actually wrote them — by the time verify() re-checks the
/// same (agent_id, nonce) pair post-signature-check, it's asking about the
/// literal same bytes this function already recorded.
pub async fn precheck_nonce(
    pool: &Pool,
    agent_id: &str,
    nonce: &str,
) -> Result<PrecomputedNonceStore, String> {
    let client = pool
        .get()
        .await
        .map_err(|e| format!("db pool error: {e}"))?;
    let rows_affected = client
        .execute(
            "insert into aap_nonces (agent_id, nonce) values ($1, $2) on conflict do nothing",
            &[&agent_id, &nonce],
        )
        .await
        .map_err(|e| format!("db query error: {e}"))?;
    // 0 rows affected => the pair already existed => this is a replay.
    Ok(PrecomputedNonceStore {
        agent_id: agent_id.to_string(),
        nonce: nonce.to_string(),
        already_seen: rows_affected == 0,
    })
}

pub struct PrecomputedNonceStore {
    agent_id: String,
    nonce: String,
    already_seen: bool,
}

impl PrecomputedNonceStore {
    /// Used when the AgentMessage JWS couldn't even be parsed — there is no
    /// (agent_id, nonce) to precheck, and verify() is about to reject the
    /// message on parse/signature grounds anyway. Never reports "fresh".
    pub fn rejects_everything() -> Self {
        Self {
            agent_id: String::new(),
            nonce: String::new(),
            already_seen: true,
        }
    }
}

impl NonceStore for PrecomputedNonceStore {
    fn seen_and_record(&self, agent_id: &str, nonce: &str) -> bool {
        // Fail closed on any mismatch against what was precomputed — this
        // should be unreachable in normal operation (aap-core only ever
        // calls this once, with the leaf AgentMessage's own agent_id/nonce,
        // which is exactly what precheck_nonce() was called with), but a
        // mismatch must never be silently treated as "fresh".
        if agent_id != self.agent_id || nonce != self.nonce {
            return true;
        }
        self.already_seen
    }
}

pub async fn persist_receipt(
    pool: &Pool,
    receipt: &aap_core::Receipt,
    receipt_jws: &str,
    pending_action_id: Option<Uuid>,
    challenge_id: Option<Uuid>,
) -> Result<(), String> {
    let client = pool
        .get()
        .await
        .map_err(|e| format!("db pool error: {e}"))?;
    let (outcome, reject_reason): (&str, Option<String>) = match &receipt.outcome {
        aap_core::ReceiptOutcome::Accepted => ("accepted", None),
        aap_core::ReceiptOutcome::Rejected { reason } => ("rejected", Some(reason.clone())),
    };
    client
        .execute(
            "insert into aap_receipts \
                (receipt_id, verifier_id, agent_id, delegation_ids, request_digest, outcome, \
                 reject_reason, receipt_jws, pending_action_id, challenge_id, decided_at) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &[
                &receipt.receipt_id,
                &receipt.verifier_id,
                &receipt.agent_id,
                &receipt.delegation_ids,
                &receipt.request_digest,
                &outcome,
                &reject_reason,
                &receipt_jws,
                &pending_action_id,
                &challenge_id,
                &receipt.decided_at,
            ],
        )
        .await
        .map_err(|e| format!("failed to persist receipt: {e}"))?;
    Ok(())
}
