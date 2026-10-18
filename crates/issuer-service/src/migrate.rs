//! Versioned SQL migrations, applied only by the explicit `migrate`
//! subcommand and never implicitly on server start. The server instead
//! verifies at startup that exactly the expected migrations are applied.
//!
//! Safety properties: a session advisory lock serialises concurrent runs,
//! each migration runs in its own transaction together with its bookkeeping
//! row, and the SHA-256 of every applied file is recorded and re-checked, so
//! editing an already-applied migration is detected instead of silently
//! diverging.

use sha2::{Digest, Sha256};
use tokio_postgres::Client;

use crate::config::valid_role_name;

pub struct Migration {
    pub version: i32,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "init",
    sql: include_str!("../migrations/0001_init.sql"),
}];

const ADVISORY_LOCK_KEY: i64 = 0x4141_5049_5353_5545; // "AAPISSUE"

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("invalid app role name")]
    BadRole,
    #[error("database error: {0}")]
    Db(#[from] tokio_postgres::Error),
    #[error("migration {0} was modified after it was applied")]
    ChecksumMismatch(i32),
    #[error("database has migration {0} which this binary does not know (downgrade?)")]
    UnknownApplied(i32),
    #[error("migrations pending: database is at {have}, binary expects {want}")]
    Pending { have: i32, want: i32 },
}

pub fn checksum(m: &Migration) -> Vec<u8> {
    Sha256::digest(m.sql.as_bytes()).to_vec()
}

fn render(sql: &str, app_role: &str) -> String {
    sql.replace("{{app_role}}", &format!("\"{app_role}\""))
}

/// Applies every pending migration. Returns the versions applied.
pub async fn run(client: &mut Client, app_role: &str) -> Result<Vec<i32>, MigrateError> {
    if !valid_role_name(app_role) {
        return Err(MigrateError::BadRole);
    }
    client
        .execute("select pg_advisory_lock($1)", &[&ADVISORY_LOCK_KEY])
        .await?;
    let result = run_locked(client, app_role).await;
    // The lock is session-scoped; release it explicitly even on error.
    let _ = client
        .execute("select pg_advisory_unlock($1)", &[&ADVISORY_LOCK_KEY])
        .await;
    result
}

async fn run_locked(client: &mut Client, app_role: &str) -> Result<Vec<i32>, MigrateError> {
    client
        .batch_execute(
            "create table if not exists schema_migrations (
                 version    integer primary key,
                 name       text not null,
                 checksum   bytea not null,
                 applied_at timestamptz not null default now()
             )",
        )
        .await?;
    // The service reads this table at startup to refuse to run on a stale schema.
    client
        .batch_execute(&format!(
            "grant select on schema_migrations to \"{app_role}\""
        ))
        .await?;

    let applied = client
        .query(
            "select version, checksum from schema_migrations order by version",
            &[],
        )
        .await?;
    for row in &applied {
        let version: i32 = row.get(0);
        let sum: Vec<u8> = row.get(1);
        match MIGRATIONS.iter().find(|m| m.version == version) {
            None => return Err(MigrateError::UnknownApplied(version)),
            Some(m) if checksum(m) != sum => return Err(MigrateError::ChecksumMismatch(version)),
            Some(_) => {}
        }
    }
    let applied_versions: Vec<i32> = applied.iter().map(|r| r.get(0)).collect();

    let mut done = Vec::new();
    for m in MIGRATIONS {
        if applied_versions.contains(&m.version) {
            continue;
        }
        let tx = client.transaction().await?;
        tx.batch_execute(&render(m.sql, app_role)).await?;
        tx.execute(
            "insert into schema_migrations (version, name, checksum) values ($1, $2, $3)",
            &[&m.version, &m.name, &checksum(m)],
        )
        .await?;
        tx.commit().await?;
        done.push(m.version);
    }
    Ok(done)
}

/// Startup guard for the server: the schema must be exactly at this binary's
/// version, with matching checksums.
pub async fn verify_schema(client: &Client) -> Result<(), MigrateError> {
    let rows = client
        .query(
            "select version, checksum from schema_migrations order by version",
            &[],
        )
        .await?;
    let want = MIGRATIONS.last().map_or(0, |m| m.version);
    let mut have = 0;
    for row in &rows {
        let version: i32 = row.get(0);
        let sum: Vec<u8> = row.get(1);
        match MIGRATIONS.iter().find(|m| m.version == version) {
            None => return Err(MigrateError::UnknownApplied(version)),
            Some(m) if checksum(m) != sum => return Err(MigrateError::ChecksumMismatch(version)),
            Some(_) => have = have.max(version),
        }
    }
    if have != want || rows.len() != MIGRATIONS.len() {
        return Err(MigrateError::Pending { have, want });
    }
    Ok(())
}
