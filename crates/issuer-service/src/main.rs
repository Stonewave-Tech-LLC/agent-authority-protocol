//! `aap-issuer-service serve` runs the HTTP service.
//! `aap-issuer-service migrate` applies pending SQL migrations (explicitly,
//! as the migration role) and exits. The server never migrates implicitly.

use std::sync::Arc;
use std::time::Duration;

use aap_issuer_service::config::{Config, MigrateConfig};
use aap_issuer_service::{http, migrate, service};
use deadpool_postgres::{Config as PoolConfig, Pool, Runtime};
use tokio_postgres::NoTls;

fn init_logging() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}

fn build_pool(database_url: &str) -> Pool {
    let mut cfg = PoolConfig::new();
    cfg.url = Some(database_url.to_string());
    cfg.pool = Some(deadpool_postgres::PoolConfig::new(8));
    cfg.options = Some("-c statement_timeout=10000".to_string());
    cfg.create_pool(Some(Runtime::Tokio1), NoTls)
        .expect("failed to build Postgres connection pool")
}

#[tokio::main]
async fn main() {
    init_logging();
    let code = match std::env::args().nth(1).as_deref() {
        Some("serve") => serve().await,
        Some("migrate") => run_migrate().await,
        _ => {
            eprintln!("usage: aap-issuer-service <serve|migrate>");
            2
        }
    };
    std::process::exit(code);
}

async fn run_migrate() -> i32 {
    let cfg = match MigrateConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "invalid migration configuration");
            return 1;
        }
    };
    let (mut client, connection) = match tokio_postgres::connect(&cfg.database_url, NoTls).await {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(error = %e, "cannot connect to database");
            return 1;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!(error = %e, "database connection error");
        }
    });
    match migrate::run(&mut client, &cfg.app_role).await {
        Ok(applied) if applied.is_empty() => {
            tracing::info!("schema already up to date");
            0
        }
        Ok(applied) => {
            tracing::info!(?applied, "migrations applied");
            0
        }
        Err(e) => {
            tracing::error!(error = %e, "migration failed");
            1
        }
    }
}

async fn serve() -> i32 {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "invalid configuration, refusing to start");
            return 1;
        }
    };
    let pool = build_pool(&config.database_url);
    // Refuse to run against a schema this binary does not match.
    match pool.get().await {
        Ok(client) => {
            if let Err(e) = migrate::verify_schema(&client).await {
                tracing::error!(error = %e, "schema check failed, refusing to start (run `migrate`?)");
                return 1;
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "cannot reach database, refusing to start");
            return 1;
        }
    }

    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, bind = %config.bind, "cannot bind");
            return 1;
        }
    };
    tracing::info!(
        bind = %config.bind,
        env = config.env.as_str(),
        allow_development = config.allow_development,
        app_ids = config.app_ids.len(),
        "aap-issuer-service listening"
    );

    let purge_pool = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            if let Err(e) = service::purge_expired_challenges(&purge_pool).await {
                tracing::warn!(error = ?e, "challenge purge failed");
            }
        }
    });

    let state = Arc::new(http::AppState::new(pool, config));
    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        // SIGTERM is how PM2/systemd stop the service; on non-Unix development
        // machines Ctrl-C is the only shutdown signal (keeps the workspace
        // building on Windows).
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
    };
    match http::serve(listener, state, shutdown).await {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, "server error");
            1
        }
    }
}
