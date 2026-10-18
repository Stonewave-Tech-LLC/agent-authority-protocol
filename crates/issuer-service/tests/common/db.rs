//! Throwaway-database harness. Point `ISSUER_TEST_DATABASE_URL` at a
//! superuser-capable Postgres (CI uses a service container, locally a
//! scratch cluster). Each test creates its own database and its own
//! least-privilege app role, runs the real migrations, and drops both.
//! Without the variable the DB tests skip, unless `ISSUER_TEST_REQUIRE_DB=1`.
#![allow(dead_code)]

use std::str::FromStr;

use aap_issuer_service::migrate;
use deadpool_postgres::{Config as PoolConfig, Pool, Runtime};
use tokio_postgres::{config::Host, Client, NoTls};
use uuid::Uuid;

pub struct TestDb {
    admin: Client,
    pub owner: Client,
    pub app_pool: Pool,
    pub db_name: String,
    pub role: String,
}

async fn connect(cfg: &tokio_postgres::Config) -> Client {
    let (client, conn) = cfg.connect(NoTls).await.expect("connect to test database");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

impl TestDb {
    /// `None` means "skip this test".
    pub async fn new(run_migrations: bool) -> Option<TestDb> {
        let url = match std::env::var("ISSUER_TEST_DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                if std::env::var("ISSUER_TEST_REQUIRE_DB").as_deref() == Ok("1") {
                    panic!("ISSUER_TEST_DATABASE_URL is required but not set");
                }
                eprintln!("skipping: ISSUER_TEST_DATABASE_URL not set");
                return None;
            }
        };
        let base = tokio_postgres::Config::from_str(&url).expect("ISSUER_TEST_DATABASE_URL");
        let admin = connect(&base).await;
        let tag = Uuid::new_v4().simple().to_string();
        let db_name = format!("issuer_test_{}", &tag[..12]);
        let role = format!("issuer_app_{}", &tag[..12]);
        admin
            .batch_execute(&format!("create database {db_name}"))
            .await
            .unwrap();
        admin
            .batch_execute(&format!("create role {role} login password 'test-pw'"))
            .await
            .unwrap();

        let mut owner_cfg = base.clone();
        owner_cfg.dbname(&db_name);
        let mut owner = connect(&owner_cfg).await;
        if run_migrations {
            migrate::run(&mut owner, &role).await.expect("migrations");
        } else {
            // Give the app role what a real provisioning step would.
            owner
                .batch_execute(&format!("grant usage on schema public to {role}"))
                .await
                .unwrap();
        }

        let host = match &base.get_hosts()[0] {
            Host::Tcp(h) => h.clone(),
            #[allow(unreachable_patterns)]
            _ => "127.0.0.1".to_string(),
        };
        let mut pc = PoolConfig::new();
        pc.host = Some(host);
        pc.port = base.get_ports().first().copied();
        pc.user = Some(role.clone());
        pc.password = Some("test-pw".into());
        pc.dbname = Some(db_name.clone());
        pc.pool = Some(deadpool_postgres::PoolConfig::new(8));
        let app_pool = pc.create_pool(Some(Runtime::Tokio1), NoTls).unwrap();

        Some(TestDb {
            admin,
            owner,
            app_pool,
            db_name,
            role,
        })
    }

    pub async fn teardown(self) {
        self.app_pool.close();
        drop(self.owner);
        let _ = self
            .admin
            .batch_execute(&format!(
                "drop database if exists {} with (force)",
                self.db_name
            ))
            .await;
        let _ = self
            .admin
            .batch_execute(&format!("drop role if exists {}", self.role))
            .await;
    }
}
