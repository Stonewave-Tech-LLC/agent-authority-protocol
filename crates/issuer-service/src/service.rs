//! The three operations of the Issuer Service, independent of HTTP framing.
//! Every function fails closed: an error means nothing was recorded except
//! (where noted) an audit event describing the rejection.

use aap_core::jws;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use base64::Engine as _;
use deadpool_postgres::Pool;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_postgres::{error::SqlState, GenericClient};
use uuid::Uuid;

use crate::appattest::{self, AppAttestError, Environment, Policy};
use crate::config::Config;
use crate::error::ApiError;
use crate::jwk::{self, JwkIn, ValidJwk};

const MAX_KEY_ID_B64: usize = 44;
const MAX_ATTESTATION_B64: usize = 32 * 1024;
const MAX_POP_JWS: usize = 1024;
const MAX_ASSERTION_B64: usize = 4 * 1024;

// ---------------------------------------------------------------- challenge

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn create_challenge(pool: &Pool, cfg: &Config) -> Result<ChallengeResponse, ApiError> {
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    let challenge_id = Uuid::new_v4();
    let client = pool.get().await?;
    let row = client
        .query_one(
            "insert into enrollment_challenges (challenge_id, challenge, expires_at)
             values ($1, $2, now() + make_interval(secs => $3))
             returning expires_at",
            &[
                &challenge_id,
                &&challenge[..],
                &cfg.challenge_ttl.as_secs_f64(),
            ],
        )
        .await?;
    Ok(ChallengeResponse {
        challenge_id,
        challenge: B64.encode(challenge),
        expires_at: row.get(0),
    })
}

/// Housekeeping: drop challenges that expired more than an hour ago.
pub async fn purge_expired_challenges(pool: &Pool) -> Result<u64, ApiError> {
    let client = pool.get().await?;
    Ok(client
        .execute(
            "delete from enrollment_challenges where expires_at < now() - interval '1 hour'",
            &[],
        )
        .await?)
}

// --------------------------------------------------------------- enrollment

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    challenge_id: Uuid,
    /// App Attest key id, standard base64 exactly as iOS reports it.
    key_id: String,
    /// Attestation object (CBOR), base64url.
    attestation: String,
    principal_jwk: JwkIn,
    /// Compact ES256 JWS signed by the principal key.
    pop_jws: String,
}

/// Domain separation for the proof of possession: the principal key also
/// signs mandates, so the PoP must name what it is and can never be mistaken
/// for (or replayed as) anything else.
pub const POP_PURPOSE: &str = "aap-enrollment-pop/v1";

/// The proof-of-possession payload the principal key signs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PopPayload {
    purpose: String,
    challenge: String,
    key_id: String,
    jwk_thumbprint: String,
}

pub struct ParsedEnroll {
    pub challenge_id: Uuid,
    pub key_id_b64: String,
    pub key_id: Vec<u8>,
    pub attestation: Vec<u8>,
    pub jwk: ValidJwk,
    pub pop_jws: String,
}

fn decode_exact(s: &str, max_len: usize, reason: &'static str) -> Result<Vec<u8>, ApiError> {
    if s.len() > max_len {
        return Err(ApiError::BadRequest(reason));
    }
    B64.decode(s).map_err(|_| ApiError::BadRequest(reason))
}

/// Strict parse and validation of an enrollment body. No I/O.
pub fn parse_enroll_request(body: &[u8]) -> Result<ParsedEnroll, ApiError> {
    let req: EnrollRequest =
        serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("malformed_json"))?;
    if req.key_id.len() > MAX_KEY_ID_B64 {
        return Err(ApiError::BadRequest("key_id"));
    }
    let key_id = STANDARD
        .decode(&req.key_id)
        .map_err(|_| ApiError::BadRequest("key_id"))?;
    if key_id.len() != 32 || STANDARD.encode(&key_id) != req.key_id {
        return Err(ApiError::BadRequest("key_id"));
    }
    let attestation = decode_exact(&req.attestation, MAX_ATTESTATION_B64, "attestation")?;
    if attestation.is_empty() {
        return Err(ApiError::BadRequest("attestation"));
    }
    if req.pop_jws.is_empty() || req.pop_jws.len() > MAX_POP_JWS {
        return Err(ApiError::BadRequest("pop_jws"));
    }
    let jwk = jwk::validate(&req.principal_jwk).map_err(ApiError::BadRequest)?;
    Ok(ParsedEnroll {
        challenge_id: req.challenge_id,
        key_id_b64: req.key_id,
        key_id,
        attestation,
        jwk,
        pop_jws: req.pop_jws,
    })
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub attestation_type: &'static str,
    pub environment: &'static str,
}

fn attest_reject(e: AppAttestError) -> ApiError {
    ApiError::Rejected {
        error: "attestation_rejected",
        reason: e.code(),
    }
}

pub async fn enroll(
    pool: &Pool,
    cfg: &Config,
    root_pem: &[u8],
    body: &[u8],
) -> Result<EnrollResponse, ApiError> {
    let req = parse_enroll_request(body)?;
    let mut client = pool.get().await?;

    // Consume first, atomically and unconditionally: a challenge is good for
    // exactly one attempt, successful or not.
    let row = client
        .query_opt(
            "update enrollment_challenges set consumed_at = now()
             where challenge_id = $1 and consumed_at is null and expires_at > now()
             returning challenge",
            &[&req.challenge_id],
        )
        .await?;
    let Some(row) = row else {
        audit_reject(
            raw(&client),
            "enrollment_rejected",
            None,
            "invalid_challenge",
        )
        .await;
        return Err(ApiError::InvalidChallenge);
    };
    let challenge: Vec<u8> = row.get(0);

    match verify_enrollment_at(
        cfg,
        root_pem,
        &req,
        &challenge,
        chrono::Utc::now().timestamp(),
    ) {
        Ok(attested) => {
            let user_id = Uuid::new_v4();
            let device_id = Uuid::new_v4();
            insert_device(&mut client, user_id, device_id, &req, &attested).await?;
            tracing::info!(%user_id, %device_id, env = attested.environment.as_str(), "device enrolled");
            Ok(EnrollResponse {
                user_id,
                device_id,
                attestation_type: "app_attest",
                environment: attested.environment.as_str(),
            })
        }
        Err(e) => {
            audit_reject(
                raw(&client),
                "enrollment_rejected",
                None,
                e.reason().unwrap_or(e.code()),
            )
            .await;
            Err(e)
        }
    }
}

/// Everything that can be decided without touching the database.
/// `root_pem` is the attestation trust anchor: the pinned Apple root in
/// production (see `AppState::new`), a synthetic one only in tests.
pub fn verify_enrollment_at(
    cfg: &Config,
    root_pem: &[u8],
    req: &ParsedEnroll,
    challenge: &[u8],
    now_unix: i64,
) -> Result<appattest::AttestedKey, ApiError> {
    let pop_err = |reason| ApiError::Rejected {
        error: "pop_rejected",
        reason,
    };
    // Proof of possession first: cheap, and it fails before any x509 work.
    let pop: PopPayload = jws::verify(&req.pop_jws, &req.jwk.key).map_err(|e| match e {
        jws::JwsError::AlgorithmMismatch | jws::JwsError::UnsupportedHeader(_) => pop_err("alg"),
        jws::JwsError::BadSignature => pop_err("signature"),
        _ => pop_err("malformed"),
    })?;
    if pop.purpose != POP_PURPOSE {
        return Err(pop_err("purpose_mismatch"));
    }
    let thumb_b64 = B64.encode(req.jwk.thumbprint);
    if pop.jwk_thumbprint != thumb_b64 {
        return Err(pop_err("thumbprint_mismatch"));
    }
    if pop.challenge != B64.encode(challenge) {
        return Err(pop_err("challenge_mismatch"));
    }
    if pop.key_id != req.key_id_b64 {
        return Err(pop_err("key_id_mismatch"));
    }

    // clientDataHash = SHA256(challenge || RFC 7638 thumbprint)
    let client_data_hash = Sha256::new()
        .chain_update(challenge)
        .chain_update(req.jwk.thumbprint)
        .finalize();
    let policy = Policy {
        app_ids: &cfg.app_ids,
        allow_development: cfg.allow_development,
    };
    appattest::verify_attestation_with_root(
        root_pem,
        &req.attestation,
        &req.key_id,
        &client_data_hash,
        &policy,
        now_unix,
    )
    .map_err(attest_reject)
}

async fn insert_device(
    client: &mut deadpool_postgres::Object,
    user_id: Uuid,
    device_id: Uuid,
    req: &ParsedEnroll,
    attested: &appattest::AttestedKey,
) -> Result<(), ApiError> {
    let jwk_json = serde_json::to_value(&req.jwk.jwk).map_err(|_| ApiError::Internal)?;
    let thumb = req.jwk.thumbprint.to_vec();
    let tx = client.transaction().await?;
    tx.execute("insert into users (user_id) values ($1)", &[&user_id])
        .await?;
    let inserted = tx
        .execute(
            "insert into devices
                 (device_id, user_id, principal_jwk, jwk_thumbprint, attestation_type,
                  app_attest_key_id, app_attest_public_key, app_id, environment)
             values ($1, $2, $3, $4, 'app_attest', $5, $6, $7, $8)",
            &[
                &device_id,
                &user_id,
                &jwk_json,
                &thumb,
                &req.key_id_b64,
                &attested.public_key,
                &attested.app_id,
                &attested.environment.as_str(),
            ],
        )
        .await;
    match inserted {
        Ok(_) => {}
        Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            drop(tx);
            audit_reject(raw(client), "enrollment_rejected", None, "already_enrolled").await;
            return Err(ApiError::AlreadyEnrolled);
        }
        Err(e) => return Err(e.into()),
    }
    audit(
        &*tx,
        "device_enrolled",
        Some(user_id),
        Some(device_id),
        json!({
            "attestation_type": "app_attest",
            "environment": attested.environment.as_str(),
            "app_id": attested.app_id,
            "jwk_thumbprint": B64.encode(&thumb),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

// --------------------------------------------------------------- assertions

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionRequest {
    device_id: Uuid,
    /// SHA-256 of the mandate bytes, base64url. This is the `clientDataHash`
    /// the app passed to `generateAssertion`.
    payload_digest: String,
    /// Assertion object (CBOR), base64url.
    assertion: String,
}

pub struct ParsedAssertion {
    pub device_id: Uuid,
    pub payload_digest: [u8; 32],
    pub assertion: Vec<u8>,
}

/// Strict parse and validation of an assertion body. No I/O.
pub fn parse_assertion_request(body: &[u8]) -> Result<ParsedAssertion, ApiError> {
    let req: AssertionRequest =
        serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("malformed_json"))?;
    let digest = decode_exact(&req.payload_digest, 43, "payload_digest")?;
    let payload_digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| ApiError::BadRequest("payload_digest"))?;
    let assertion = decode_exact(&req.assertion, MAX_ASSERTION_B64, "assertion")?;
    if assertion.is_empty() {
        return Err(ApiError::BadRequest("assertion"));
    }
    Ok(ParsedAssertion {
        device_id: req.device_id,
        payload_digest,
        assertion,
    })
}

#[derive(Serialize)]
pub struct AssertionResponse {
    pub verified: bool,
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub counter: u32,
    pub attestation_type: &'static str,
    pub environment: String,
}

pub async fn verify_assertion(
    pool: &Pool,
    cfg: &Config,
    body: &[u8],
) -> Result<AssertionResponse, ApiError> {
    let req = parse_assertion_request(body)?;
    let mut client = pool.get().await?;
    let row = client
        .query_opt(
            "select user_id, app_attest_public_key, app_id, environment, status
             from devices where device_id = $1",
            &[&req.device_id],
        )
        .await?;
    let Some(row) = row else {
        return Err(ApiError::UnknownDevice);
    };
    let user_id: Uuid = row.get(0);
    let public_key: Vec<u8> = row.get(1);
    let app_id: String = row.get(2);
    let environment: String = row.get(3);
    let status: String = row.get(4);
    if status != "active" {
        return Err(ApiError::DeviceNotActive);
    }

    let reject = |reason: &'static str| ApiError::Rejected {
        error: "assertion_rejected",
        reason,
    };
    // The deployment policy applies at use time too, not only at enrollment.
    if !cfg.app_ids.contains(&app_id) {
        return Err(reject("app_id_not_allowed"));
    }
    if environment == Environment::Development.as_str() && !cfg.allow_development {
        return Err(reject("development_not_accepted"));
    }

    let new_counter = match appattest::verify_assertion(
        &req.assertion,
        &req.payload_digest,
        &app_id,
        &public_key,
    ) {
        Ok(c) => c,
        Err(e) => {
            audit_reject(
                raw(&client),
                "assertion_rejected",
                Some(req.device_id),
                e.code(),
            )
            .await;
            return Err(reject(e.code()));
        }
    };

    // The only place the counter moves: one conditional UPDATE, so concurrent
    // requests cannot both win.
    let tx = client.transaction().await?;
    let advanced = tx
        .execute(
            "update devices set counter = $2, last_payload_digest = $3, last_assertion_at = now()
             where device_id = $1 and status = 'active' and counter < $2",
            &[
                &req.device_id,
                &(new_counter as i64),
                &&req.payload_digest[..],
            ],
        )
        .await?;
    if advanced == 1 {
        audit(
            &*tx,
            "assertion_verified",
            Some(user_id),
            Some(req.device_id),
            json!({
                "payload_digest": B64.encode(req.payload_digest),
                "counter": new_counter,
            }),
        )
        .await?;
        tx.commit().await?;
        return Ok(AssertionResponse {
            verified: true,
            device_id: req.device_id,
            user_id,
            counter: new_counter,
            attestation_type: "app_attest",
            environment,
        });
    }

    // A validly signed assertion whose counter did not advance. Only a second,
    // *different* assertion with the counter already accepted proves misuse of
    // the key: that flags the device. A verbatim replay or a stale assertion
    // is merely rejected, otherwise anyone who has seen one assertion (a
    // merchant, a log reader) could lock the user out by replaying it.
    let flagged = tx
        .execute(
            "update devices
             set status = 'flagged', flagged_at = now(), flagged_reason = 'counter_conflict'
             where device_id = $1 and status = 'active' and counter = $2
               and last_payload_digest is distinct from $3",
            &[
                &req.device_id,
                &(new_counter as i64),
                &&req.payload_digest[..],
            ],
        )
        .await?;
    let (event, result) = if flagged == 1 {
        ("device_flagged", Err(ApiError::CounterConflict))
    } else {
        let still_active = tx
            .query_opt(
                "select 1 from devices where device_id = $1 and status = 'active'",
                &[&req.device_id],
            )
            .await?
            .is_some();
        if still_active {
            ("assertion_replay_rejected", Err(ApiError::AssertionReplay))
        } else {
            ("assertion_rejected", Err(ApiError::DeviceNotActive))
        }
    };
    audit(
        &*tx,
        event,
        Some(user_id),
        Some(req.device_id),
        json!({
            "reason": if flagged == 1 { "counter_conflict" } else { "counter_not_advanced" },
            "presented_counter": new_counter,
        }),
    )
    .await?;
    tx.commit().await?;
    tracing::warn!(device_id = %req.device_id, presented_counter = new_counter, flagged = flagged == 1, "assertion counter did not advance");
    result
}

// -------------------------------------------------------------------- audit

fn raw(c: &deadpool_postgres::Object) -> &tokio_postgres::Client {
    c
}

/// Appends an audit event. `detail` must never contain request bodies, keys
/// or other secrets; callers pass identifiers and reason codes only.
pub async fn audit<C: GenericClient>(
    client: &C,
    event_type: &str,
    user_id: Option<Uuid>,
    device_id: Option<Uuid>,
    detail: serde_json::Value,
) -> Result<(), ApiError> {
    client
        .execute(
            "insert into audit_events (event_type, user_id, device_id, detail)
             values ($1, $2, $3, $4)",
            &[&event_type, &user_id, &device_id, &detail],
        )
        .await?;
    Ok(())
}

/// Best-effort audit of a rejection: a failure to write it is logged but
/// never turns a rejection into something else.
async fn audit_reject<C: GenericClient>(
    client: &C,
    event_type: &str,
    device_id: Option<Uuid>,
    reason: &str,
) {
    if audit(
        client,
        event_type,
        None,
        device_id,
        json!({ "reason": reason }),
    )
    .await
    .is_err()
    {
        tracing::error!(event_type, "failed to write audit event");
    }
    tracing::warn!(event_type, reason, "request rejected");
}

pub async fn ping(pool: &Pool) -> bool {
    match pool.get().await {
        Ok(c) => c.simple_query("select 1").await.is_ok(),
        Err(_) => false,
    }
}
