//! End-to-end behavior against a real (throwaway) Postgres, driven through
//! the actual axum router. Skips when `ISSUER_TEST_DATABASE_URL` is unset.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use aap_issuer_service::config::Config;
use aap_issuer_service::http::{router, AppState};
use aap_issuer_service::migrate;
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use common::db::TestDb;
use common::*;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

struct Api {
    router: Router,
}

impl Api {
    fn new(db: &TestDb, pki: &Pki, tweak: &[(&str, &str)]) -> Api {
        let mut env: HashMap<String, String> = HashMap::from([
            ("ISSUER_ENV".into(), "staging".into()),
            ("ISSUER_DATABASE_URL".into(), "postgres://unused".into()),
            ("ISSUER_APP_IDS".into(), APP_ID.into()),
        ]);
        for (k, v) in tweak {
            env.insert(k.to_string(), v.to_string());
        }
        let cfg = Config::from_lookup(|k| env.get(k).cloned()).unwrap();
        let state = Arc::new(AppState::with_trust_anchor(
            db.app_pool.clone(),
            cfg,
            pki.root_pem(),
        ));
        Api {
            router: router(state),
        }
    }

    async fn call(&self, method: &str, path: &str, body: Vec<u8>, ip: &str) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let addr: SocketAddr = format!("{ip}:1234").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    async fn post(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            "POST",
            path,
            serde_json::to_vec(body).unwrap(),
            "192.0.2.10",
        )
        .await
    }

    async fn challenge(&self) -> (String, Vec<u8>) {
        let (s, v) = self.post("/v1/enrollment/challenge", &json!({})).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        (
            v["challenge_id"].as_str().unwrap().to_string(),
            B64.decode(v["challenge"].as_str().unwrap()).unwrap(),
        )
    }

    /// Enrolls a fresh device; returns (device_id, user_id, app key).
    async fn enroll(&self, pki: &Pki, opts: Opts) -> (String, String, AppAttestDevice) {
        let app = AppAttestDevice::new();
        let principal = Principal::new();
        let (id, ch) = self.challenge().await;
        let mut e = Enrollment::new(pki, &app, &principal, ch);
        e.opts = opts;
        let (s, v) = self.post("/v1/enrollment", &e.body(&id)).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        (
            v["device_id"].as_str().unwrap().to_string(),
            v["user_id"].as_str().unwrap().to_string(),
            app,
        )
    }

    async fn assert_req(
        &self,
        device_id: &str,
        digest: &[u8; 32],
        assertion: &[u8],
    ) -> (StatusCode, Value) {
        self.post(
            "/v1/assertions/verify",
            &json!({
                "device_id": device_id,
                "payload_digest": B64.encode(digest),
                "assertion": B64.encode(assertion),
            }),
        )
        .await
    }
}

macro_rules! db_test {
    ($db:ident, $body:block) => {{
        #[allow(unused_mut)]
        let Some(mut $db) = TestDb::new(true).await else { return };
        $body
        $db.teardown().await;
    }};
}

#[tokio::test]
async fn migrations_are_idempotent_and_tamper_evident() {
    db_test!(db, {
        assert!(migrate::run(&mut db.owner, &db.role)
            .await
            .unwrap()
            .is_empty());
        let app = db.app_pool.get().await.unwrap();
        migrate::verify_schema(&app).await.unwrap();
        db.owner
            .batch_execute("update schema_migrations set checksum = '\\x00'")
            .await
            .unwrap();
        assert!(matches!(
            migrate::run(&mut db.owner, &db.role).await,
            Err(migrate::MigrateError::ChecksumMismatch(1))
        ));
        assert!(matches!(
            migrate::verify_schema(&app).await,
            Err(migrate::MigrateError::ChecksumMismatch(1))
        ));
    });
}

#[tokio::test]
async fn server_refuses_an_unmigrated_schema() {
    let Some(db) = TestDb::new(false).await else {
        return;
    };
    let app = db.app_pool.get().await;
    // Without the migrate step even the bookkeeping table is missing.
    let err = match app {
        Ok(c) => migrate::verify_schema(&c).await.err(),
        Err(_) => return,
    };
    assert!(err.is_some());
    db.teardown().await;
}

#[tokio::test]
async fn app_role_cannot_rewrite_history_or_escalate() {
    db_test!(db, {
        let app = db.app_pool.get().await.unwrap();
        let denied = |r: Result<u64, tokio_postgres::Error>| {
            let e = r.expect_err("must be denied");
            assert_eq!(e.code().map(|c| c.code()), Some("42501"), "{e}");
        };
        app.execute("insert into audit_events (event_type) values ('t')", &[])
            .await
            .unwrap();
        denied(
            app.execute("update audit_events set event_type = 'x'", &[])
                .await,
        );
        denied(app.execute("delete from audit_events", &[]).await);
        denied(app.execute("truncate audit_events", &[]).await);
        denied(app.execute("update devices set app_id = 'x'", &[]).await);
        denied(
            app.execute("update devices set principal_jwk = '{}'", &[])
                .await,
        );
        denied(app.execute("delete from devices", &[]).await);
        denied(app.execute("delete from users", &[]).await);
        denied(app.execute("create table sneaky (i int)", &[]).await);

        // Second line of defense: the owner is stopped by the trigger.
        for stmt in [
            "update audit_events set event_type = 'x'",
            "delete from audit_events",
            "truncate audit_events",
        ] {
            let e = db
                .owner
                .batch_execute(stmt)
                .await
                .expect_err("trigger must block");
            let msg = e
                .as_db_error()
                .map(|d| d.message().to_string())
                .unwrap_or_default();
            assert!(msg.contains("append-only"), "{stmt}: {e:?}");
        }
        let n: i64 = db
            .owner
            .query_one("select count(*) from audit_events", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 1);
    });
}

#[tokio::test]
async fn enrollment_creates_user_and_device_and_audits_it() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let app = AppAttestDevice::new();
        let principal = Principal::new();
        let (id, ch) = api.challenge().await;
        let (s, v) = api
            .post(
                "/v1/enrollment",
                &Enrollment::new(&pki, &app, &principal, ch).body(&id),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        assert_eq!(v["attestation_type"], "app_attest");
        assert_eq!(v["environment"], "production");

        let device_id: uuid::Uuid = v["device_id"].as_str().unwrap().parse().unwrap();
        let row = db.owner.query_one(
            "select user_id, jwk_thumbprint, attestation_type, app_attest_key_id, app_attest_public_key,
                    app_id, environment, counter, status, principal_jwk
             from devices where device_id = $1", &[&device_id]).await.unwrap();
        let thumb: Vec<u8> = row.get(1);
        assert_eq!(thumb, principal.thumbprint());
        assert_eq!(row.get::<_, String>(2), "app_attest");
        assert_eq!(row.get::<_, String>(3), app.key_id_b64());
        assert_eq!(
            row.get::<_, Vec<u8>>(4),
            app.sk.verifying_key().to_encoded_point(false).as_bytes()
        );
        assert_eq!(row.get::<_, String>(5), APP_ID);
        assert_eq!(row.get::<_, String>(6), "production");
        assert_eq!(row.get::<_, i64>(7), 0);
        assert_eq!(row.get::<_, String>(8), "active");
        assert_eq!(row.get::<_, Value>(9), principal.jwk());
        let users: i64 = db
            .owner
            .query_one("select count(*) from users", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(users, 1);
        let ev = db
            .owner
            .query_one(
                "select detail from audit_events where event_type = 'device_enrolled'",
                &[],
            )
            .await
            .unwrap();
        let detail: Value = ev.get(0);
        assert_eq!(detail["attestation_type"], "app_attest");
        assert!(detail.to_string().find("pop_jws").is_none());
    });
}

#[tokio::test]
async fn challenges_are_single_use_and_expire() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (app, principal) = (AppAttestDevice::new(), Principal::new());

        // Reuse.
        let (id, ch) = api.challenge().await;
        let body = Enrollment::new(&pki, &app, &principal, ch).body(&id);
        assert_eq!(
            api.post("/v1/enrollment", &body).await.0,
            StatusCode::CREATED
        );
        let (s, v) = api.post("/v1/enrollment", &body).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_challenge"))
        );

        // Expiry.
        let (id, ch) = api.challenge().await;
        db.owner.execute(
            "update enrollment_challenges set expires_at = now() - interval '1 second' where challenge_id = $1",
            &[&id.parse::<uuid::Uuid>().unwrap()]).await.unwrap();
        let (app2, principal2) = (AppAttestDevice::new(), Principal::new());
        let (s, v) = api
            .post(
                "/v1/enrollment",
                &Enrollment::new(&pki, &app2, &principal2, ch).body(&id),
            )
            .await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_challenge"))
        );

        // Unknown id.
        let (s, v) = api
            .post(
                "/v1/enrollment",
                &Enrollment::new(&pki, &app2, &principal2, vec![0; 32])
                    .body(&uuid::Uuid::new_v4().to_string()),
            )
            .await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_challenge"))
        );

        // A failed attempt burns the challenge: the correct body is refused afterwards.
        let (id, ch) = api.challenge().await;
        let mut bad = Enrollment::new(&pki, &app2, &principal2, ch.clone());
        bad.opts.bad_nonce = true;
        assert_eq!(
            api.post("/v1/enrollment", &bad.body(&id)).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let good = Enrollment::new(&pki, &app2, &principal2, ch).body(&id);
        let (s, v) = api.post("/v1/enrollment", &good).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_challenge"))
        );
    });
}

#[tokio::test]
async fn expired_challenge_cannot_be_consumed_concurrently_twice() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (id, ch) = api.challenge().await;
        let (a1, p1, a2, p2) = (
            AppAttestDevice::new(),
            Principal::new(),
            AppAttestDevice::new(),
            Principal::new(),
        );
        let b1 = Enrollment::new(&pki, &a1, &p1, ch.clone()).body(&id);
        let b2 = Enrollment::new(&pki, &a2, &p2, ch).body(&id);
        let (r1, r2) = tokio::join!(
            api.post("/v1/enrollment", &b1),
            api.post("/v1/enrollment", &b2)
        );
        let mut codes = [r1.0.as_u16(), r2.0.as_u16()];
        codes.sort();
        assert_eq!(
            codes,
            [201, 400],
            "exactly one enrollment may win the challenge"
        );
    });
}

#[tokio::test]
async fn every_enrollment_rejection_path_is_closed() {
    db_test!(db, {
        let pki = Pki::new();
        // staging, development aaguid NOT accepted. Each case is one challenge
        // plus one enrollment from the same test IP, so lift the per-minute
        // limits above the number of cases (rate limiting has its own test).
        let api = Api::new(
            &db,
            &pki,
            &[
                ("ISSUER_RATE_CHALLENGE_PER_MIN", "1000"),
                ("ISSUER_RATE_ENROLLMENT_PER_MIN", "1000"),
            ],
        );
        let other_principal = Principal::new();

        type Tweak = Box<dyn for<'a> Fn(&mut Enrollment<'a>, &'a Principal)>;
        let cases: Vec<(&str, &str, &str, Tweak)> = vec![
            (
                "wrong rpIdHash",
                "attestation_rejected",
                "rp_id_not_allowed",
                Box::new(|e, _| e.opts.app_id = OTHER_APP_ID.into()),
            ),
            (
                "wrong nonce",
                "attestation_rejected",
                "nonce_mismatch",
                Box::new(|e, _| e.opts.bad_nonce = true),
            ),
            (
                "attestation bound to another thumbprint",
                "attestation_rejected",
                "nonce_mismatch",
                Box::new(|e, o| e.cdh_thumbprint = Some(o.thumbprint())),
            ),
            (
                "development aaguid with development not accepted",
                "attestation_rejected",
                "development_not_accepted",
                Box::new(|e, _| e.opts = dev_opts()),
            ),
            (
                "attestation counter not zero",
                "attestation_rejected",
                "counter_not_zero",
                Box::new(|e, _| e.opts.counter = 5),
            ),
            (
                "credentialId != keyId",
                "attestation_rejected",
                "credential_id_mismatch",
                Box::new(|e, _| e.opts.credential_id = Some(vec![1; 32])),
            ),
            (
                "PoP signed by a different key",
                "pop_rejected",
                "signature",
                Box::new(|e, o| e.pop_signer = Some(o)),
            ),
            (
                "PoP thumbprint mismatch",
                "pop_rejected",
                "thumbprint_mismatch",
                Box::new(|e, o| e.pop_thumbprint = Some(B64.encode(o.thumbprint()))),
            ),
            (
                "PoP challenge mismatch",
                "pop_rejected",
                "challenge_mismatch",
                Box::new(|e, _| e.pop_challenge = Some(B64.encode([1u8; 32]))),
            ),
            (
                "PoP key id mismatch",
                "pop_rejected",
                "key_id_mismatch",
                Box::new(|e, _| e.pop_key_id = Some(AppAttestDevice::new().key_id_b64())),
            ),
            (
                "PoP with a different purpose (e.g. a mandate signature)",
                "pop_rejected",
                "purpose_mismatch",
                Box::new(|e, _| e.pop_purpose = Some("aap-mandate".into())),
            ),
        ];
        for (name, error, reason, tweak) in &cases {
            let (app, principal) = (AppAttestDevice::new(), Principal::new());
            let (id, ch) = api.challenge().await;
            let mut e = Enrollment::new(&pki, &app, &principal, ch);
            tweak(&mut e, &other_principal);
            let (s, v) = api.post("/v1/enrollment", &e.body(&id)).await;
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {v}");
            assert_eq!(
                (v["error"].as_str(), v["reason"].as_str()),
                (Some(*error), Some(*reason)),
                "{name}"
            );
        }
        // Nothing was created by any rejected attempt.
        for t in ["users", "devices"] {
            let n: i64 = db
                .owner
                .query_one(&format!("select count(*) from {t}"), &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(n, 0, "{t}");
        }
        let n: i64 = db
            .owner
            .query_one(
                "select count(*) from audit_events where event_type = 'enrollment_rejected'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n as usize, cases.len());
    });
}

#[tokio::test]
async fn a_second_enrollment_of_the_same_keys_is_a_conflict_and_leaves_no_user() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (app, principal) = (AppAttestDevice::new(), Principal::new());
        for expect in [StatusCode::CREATED, StatusCode::CONFLICT] {
            let (id, ch) = api.challenge().await;
            let (s, v) = api
                .post(
                    "/v1/enrollment",
                    &Enrollment::new(&pki, &app, &principal, ch).body(&id),
                )
                .await;
            assert_eq!(s, expect, "{v}");
        }
        let n: i64 = db
            .owner
            .query_one("select count(*) from users", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 1, "the failed insert must roll the new user back");
    });
}

#[tokio::test]
async fn development_devices_enroll_only_where_policy_allows() {
    db_test!(db, {
        let pki = Pki::new();
        let staging = Api::new(&db, &pki, &[("ISSUER_ALLOW_DEVELOPMENT_AAGUID", "true")]);
        let (device, _, app) = staging.enroll(&pki, dev_opts()).await;
        let row = db
            .owner
            .query_one("select environment from devices", &[])
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "development");

        // The same database seen by a stricter deployment: the policy applies
        // at use time as well, not only at enrollment.
        let strict = Api::new(&db, &pki, &[]);
        let d = mandate_digest(b"m");
        let (s, v) = strict
            .assert_req(&device, &d, &assertion(&app, 1, &d))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(v["reason"], "development_not_accepted");
        // Still works where development is accepted.
        assert_eq!(
            staging
                .assert_req(&device, &d, &assertion(&app, 1, &d))
                .await
                .0,
            StatusCode::OK
        );
    });
}

#[tokio::test]
async fn assertions_bind_mandates_and_counters_only_move_forward() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (device, user, app) = api.enroll(&pki, Opts::default()).await;
        let did: uuid::Uuid = device.parse().unwrap();
        let counter = || async {
            db.owner
                .query_one("select counter from devices where device_id = $1", &[&did])
                .await
                .unwrap()
                .get::<_, i64>(0)
        };

        let d1 = mandate_digest(b"mandate one");
        let (s, v) = api.assert_req(&device, &d1, &assertion(&app, 1, &d1)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(
            (
                v["counter"].as_u64(),
                v["user_id"].as_str(),
                v["attestation_type"].as_str()
            ),
            (Some(1), Some(user.as_str()), Some("app_attest"))
        );
        assert_eq!(counter().await, 1);

        // A high-S signature must not matter.
        let d2 = mandate_digest(b"mandate two");
        let hs = assertion_with(&app, APP_ID, 2, &d2, true);
        assert_eq!(api.assert_req(&device, &d2, &hs).await.0, StatusCode::OK);
        assert_eq!(counter().await, 2);

        // The mandate digest is part of what was signed.
        let (s, v) = api.assert_req(&device, &d1, &assertion(&app, 3, &d2)).await;
        assert_eq!(
            (s, v["reason"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some("bad_signature"))
        );
        assert_eq!(counter().await, 2);

        // Unknown device.
        let (s, _) = api
            .assert_req(
                &uuid::Uuid::new_v4().to_string(),
                &d1,
                &assertion(&app, 3, &d1),
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // Replay of the old counter-1 assertion (e.g. by a merchant who saw it):
        // rejected, but the device must stay usable.
        let (s, v) = api.assert_req(&device, &d1, &assertion(&app, 1, &d1)).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::CONFLICT, Some("assertion_replay"))
        );
        let status_of = || async {
            db.owner
                .query_one("select status from devices where device_id = $1", &[&did])
                .await
                .unwrap()
                .get::<_, String>(0)
        };
        assert_eq!(
            status_of().await,
            "active",
            "a replay must not lock the user out"
        );
        assert_eq!(
            counter().await,
            2,
            "a rejected assertion never moves the counter"
        );

        // The device keeps working after the replay.
        let d3 = mandate_digest(b"mandate three");
        let (s, v) = api
            .assert_req(&device, &d3, &assertion(&app, 10, &d3))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");

        // A second, different assertion with the accepted counter 10 is
        // impossible for an honest key: flagged.
        let d4 = mandate_digest(b"mandate four");
        let (s, v) = api
            .assert_req(&device, &d4, &assertion(&app, 10, &d4))
            .await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::CONFLICT, Some("counter_conflict"))
        );
        let st = db
            .owner
            .query_one(
                "select status, flagged_reason from devices where device_id = $1",
                &[&did],
            )
            .await
            .unwrap();
        assert_eq!(
            (st.get::<_, String>(0), st.get::<_, String>(1)),
            ("flagged".into(), "counter_conflict".into())
        );
        let n: i64 = db
            .owner
            .query_one(
                "select count(*) from audit_events where event_type = 'device_flagged'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 1);

        // A flagged device is refused, even with a perfectly good assertion.
        let d5 = mandate_digest(b"mandate five");
        let (s, v) = api
            .assert_req(&device, &d5, &assertion(&app, 11, &d5))
            .await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("device_not_active"))
        );

        // Each verified assertion left an audit record with the digest, nothing secret.
        let n: i64 = db
            .owner
            .query_one(
                "select count(*) from audit_events where event_type = 'assertion_verified'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 3);
    });
}

#[tokio::test]
async fn a_verbatim_replay_of_the_last_assertion_does_not_flag() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (device, _, app) = api.enroll(&pki, Opts::default()).await;
        let d = mandate_digest(b"m");
        let a = assertion(&app, 4, &d);
        assert_eq!(api.assert_req(&device, &d, &a).await.0, StatusCode::OK);
        let (s, v) = api.assert_req(&device, &d, &a).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::CONFLICT, Some("assertion_replay"))
        );
        let d2 = mandate_digest(b"next");
        assert_eq!(
            api.assert_req(&device, &d2, &assertion(&app, 5, &d2))
                .await
                .0,
            StatusCode::OK,
            "device still active after a verbatim replay"
        );
    });
}

#[tokio::test]
async fn an_equal_counter_with_a_different_payload_flags_the_device() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (device, _, app) = api.enroll(&pki, Opts::default()).await;
        let d = mandate_digest(b"m");
        assert_eq!(
            api.assert_req(&device, &d, &assertion(&app, 4, &d)).await.0,
            StatusCode::OK
        );
        let d2 = mandate_digest(b"another mandate");
        let (s, v) = api.assert_req(&device, &d2, &assertion(&app, 4, &d2)).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::CONFLICT, Some("counter_conflict"))
        );
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_assertions_with_the_same_counter_cannot_both_win() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (device, _, app) = api.enroll(&pki, Opts::default()).await;
        let (da, dbb) = (mandate_digest(b"a"), mandate_digest(b"b"));
        let (aa, ab) = (assertion(&app, 1, &da), assertion(&app, 1, &dbb));
        let (r1, r2) = tokio::join!(
            api.assert_req(&device, &da, &aa),
            api.assert_req(&device, &dbb, &ab)
        );
        let mut codes = [r1.0.as_u16(), r2.0.as_u16()];
        codes.sort();
        assert!(codes == [200, 409] || codes == [200, 403], "{codes:?}");
        let n: i64 = db
            .owner
            .query_one(
                "select count(*) from audit_events where event_type = 'assertion_verified'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 1);
    });
}

#[tokio::test]
async fn rate_limits_apply_per_client_ip() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[("ISSUER_RATE_CHALLENGE_PER_MIN", "2")]);
        let hit = |ip: &'static str| api.call("POST", "/v1/enrollment/challenge", vec![], ip);
        assert_eq!(hit("198.51.100.1").await.0, StatusCode::CREATED);
        assert_eq!(hit("198.51.100.1").await.0, StatusCode::CREATED);
        let (s, v) = hit("198.51.100.1").await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
        );
        assert_eq!(
            hit("198.51.100.2").await.0,
            StatusCode::CREATED,
            "other clients unaffected"
        );

        let api = Api::new(&db, &pki, &[("ISSUER_RATE_ENROLLMENT_PER_MIN", "1")]);
        let junk = |ip: &'static str| api.call("POST", "/v1/enrollment", b"{}".to_vec(), ip);
        assert_eq!(junk("198.51.100.3").await.0, StatusCode::BAD_REQUEST);
        assert_eq!(junk("198.51.100.3").await.0, StatusCode::TOO_MANY_REQUESTS);
    });
}

#[tokio::test]
async fn proxy_header_is_only_trusted_when_configured() {
    db_test!(db, {
        let pki = Pki::new();
        let mk = |tweak: &[(&str, &str)]| Api::new(&db, &pki, tweak);
        let send = |api: &Api, xff: &'static str| {
            let mut req = Request::builder()
                .method("POST")
                .uri("/v1/enrollment/challenge")
                .header("x-forwarded-for", xff)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo("127.0.0.1:9".parse::<SocketAddr>().unwrap()));
            api.router.clone().oneshot(req)
        };
        // Not configured: the header is ignored, everything is one peer.
        let api = mk(&[("ISSUER_RATE_CHALLENGE_PER_MIN", "1")]);
        assert_eq!(
            send(&api, "203.0.113.1").await.unwrap().status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(&api, "203.0.113.2").await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // Configured: the rightmost entry (written by our proxy) is the client.
        let api = mk(&[
            ("ISSUER_RATE_CHALLENGE_PER_MIN", "1"),
            ("ISSUER_CLIENT_IP_HEADER", "X-Forwarded-For"),
        ]);
        assert_eq!(
            send(&api, "198.51.100.77, 203.0.113.1")
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(&api, "198.51.100.77, 203.0.113.2")
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(&api, "1.2.3.4, 203.0.113.2").await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    });
}

#[tokio::test]
async fn bodies_are_size_limited_and_parsed_strictly() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let big = vec![b'a'; 64 * 1024];
        assert_eq!(
            api.call("POST", "/v1/enrollment", big.clone(), "192.0.2.20")
                .await
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            api.call(
                "POST",
                "/v1/enrollment/challenge",
                vec![b'a'; 2048],
                "192.0.2.20"
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            api.call("POST", "/v1/assertions/verify", big, "192.0.2.20")
                .await
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let (app, principal) = (AppAttestDevice::new(), Principal::new());
        let (id, ch) = api.challenge().await;
        let good = Enrollment::new(&pki, &app, &principal, ch).body(&id);
        let api_ref = &api;
        let bad_request = |v: Value| async move { api_ref.post("/v1/enrollment", &v).await };
        // Unknown member.
        let mut v = good.clone();
        v["extra"] = json!(1);
        let (s, r) = bad_request(v).await;
        assert_eq!(
            (s, r["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_request"))
        );
        // Unknown JWK member (e.g. a private "d" smuggled in).
        let mut v = good.clone();
        v["principal_jwk"]["d"] = json!("AAAA");
        assert_eq!(bad_request(v).await.0, StatusCode::BAD_REQUEST);
        // Non-P-256 key, non-canonical coordinate, off-curve point, bad key id.
        let mut v = good.clone();
        v["principal_jwk"]["crv"] = json!("P-384");
        assert_eq!(bad_request(v).await.1["reason"], "jwk_not_p256");
        let mut v = good.clone();
        let x = v["principal_jwk"]["x"].as_str().unwrap().to_string();
        v["principal_jwk"]["x"] = json!(format!("{x}="));
        assert_eq!(bad_request(v).await.1["reason"], "jwk_bad_coordinates");
        let mut v = good.clone();
        v["principal_jwk"]["y"] = json!(B64.encode([7u8; 32]));
        assert_eq!(bad_request(v).await.1["reason"], "jwk_not_on_curve");
        let mut v = good.clone();
        v["key_id"] = json!("not base64!");
        assert_eq!(bad_request(v).await.1["reason"], "key_id");
        let mut v = good.clone();
        v["challenge_id"] = json!("not-a-uuid");
        assert_eq!(bad_request(v).await.0, StatusCode::BAD_REQUEST);
        // None of the above touched the challenge: the good body still works.
        assert_eq!(
            api.post("/v1/enrollment", &good).await.0,
            StatusCode::CREATED
        );

        // Assertion request strictness.
        let (s, r) = api.post("/v1/assertions/verify", &json!({"device_id": uuid::Uuid::new_v4(), "payload_digest": "short", "assertion": "AAAA"})).await;
        assert_eq!(
            (s, r["reason"].as_str()),
            (StatusCode::BAD_REQUEST, Some("payload_digest"))
        );
    });
}

#[tokio::test]
async fn health_reports_database_reachability_and_environment() {
    db_test!(db, {
        let pki = Pki::new();
        let api = Api::new(&db, &pki, &[]);
        let (s, v) = api.call("GET", "/health", vec![], "192.0.2.30").await;
        assert_eq!(
            (s, v["status"].as_str(), v["env"].as_str()),
            (StatusCode::OK, Some("ok"), Some("staging"))
        );
    });
}
