//! HTTP surface: routing, request-size and time limits, per-IP rate limiting,
//! and strict body handling. All decisions live in `service`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use deadpool_postgres::Pool;
use serde::Serialize;
use tower_http::{set_header::SetResponseHeaderLayer, timeout::TimeoutLayer};

use crate::config::Config;
use crate::error::ApiError;
use crate::ratelimit::RateLimiter;
use crate::service;

pub struct AppState {
    pub pool: Pool,
    pub config: Config,
    /// Attestation trust anchor (PEM). Always Apple's pinned root outside tests.
    root_pem: Vec<u8>,
    challenge_limiter: RateLimiter,
    enrollment_limiter: RateLimiter,
    assertion_limiter: RateLimiter,
}

impl AppState {
    pub fn new(pool: Pool, config: Config) -> Self {
        Self::with_trust_anchor(pool, config, crate::appattest::APPLE_APP_ATTEST_ROOT_PEM)
    }

    /// Tests only: lets a synthetic CA stand in for Apple's. Nothing in the
    /// binary, its configuration or its environment can reach this.
    #[doc(hidden)]
    pub fn with_trust_anchor(pool: Pool, config: Config, root_pem: &[u8]) -> Self {
        AppState {
            root_pem: root_pem.to_vec(),
            challenge_limiter: RateLimiter::new(config.rate_limits.challenge_per_min),
            enrollment_limiter: RateLimiter::new(config.rate_limits.enrollment_per_min),
            assertion_limiter: RateLimiter::new(config.rate_limits.assertion_per_min),
            pool,
            config,
        }
    }
}

const CHALLENGE_BODY_LIMIT: usize = 1024;
const ENROLLMENT_BODY_LIMIT: usize = 48 * 1024;
const ASSERTION_BODY_LIMIT: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub fn router(state: Arc<AppState>) -> Router {
    let challenge = Router::new()
        .route(
            "/v1/enrollment/challenge",
            post(challenge).layer(DefaultBodyLimit::max(CHALLENGE_BODY_LIMIT)),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            limit_challenge,
        ));
    let enrollment = Router::new()
        .route(
            "/v1/enrollment",
            post(enrollment).layer(DefaultBodyLimit::max(ENROLLMENT_BODY_LIMIT)),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            limit_enrollment,
        ));
    let assertions = Router::new()
        .route(
            "/v1/assertions/verify",
            post(assertion).layer(DefaultBodyLimit::max(ASSERTION_BODY_LIMIT)),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            limit_assertion,
        ));

    Router::new()
        .route("/health", get(health))
        .merge(challenge)
        .merge(enrollment)
        .merge(assertions)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

/// Serves the router; `ConnectInfo` is what the rate limiter keys on.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Reads the whole body (already size-limited by `DefaultBodyLimit`). Content
/// is parsed strictly by `service`; this only maps framing errors.
struct RawBody(Bytes);

impl<S: Send + Sync> FromRequest<S> for RawBody {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        Bytes::from_request(req, state)
            .await
            .map(RawBody)
            .map_err(|_| ApiError::PayloadTooLarge)
    }
}

fn client_ip(state: &AppState, req: &Request) -> IpAddr {
    if let Some(name) = &state.config.client_ip_header {
        // Behind a trusted proxy that appends the real client address: the
        // rightmost entry is the one our proxy wrote.
        if let Some(ip) = req
            .headers()
            .get(name.as_str())
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

async fn limited(limiter: &RateLimiter, state: &AppState, req: Request, next: Next) -> Response {
    if !limiter.check(client_ip(state, &req)) {
        return ApiError::RateLimited.into_response();
    }
    next.run(req).await
}

async fn limit_challenge(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    limited(&s.challenge_limiter, &s, req, next).await
}
async fn limit_enrollment(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    limited(&s.enrollment_limiter, &s, req, next).await
}
async fn limit_assertion(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    limited(&s.assertion_limiter, &s, req, next).await
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    env: &'static str,
}

async fn health(State(s): State<Arc<AppState>>) -> Response {
    if service::ping(&s.pool).await {
        Json(Health {
            status: "ok",
            env: s.config.env.as_str(),
        })
        .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "unavailable" })),
        )
            .into_response()
    }
}

async fn challenge(
    State(s): State<Arc<AppState>>,
    // The body is ignored, but reading it is what enforces the size limit.
    RawBody(_): RawBody,
) -> Result<Response, ApiError> {
    let r = service::create_challenge(&s.pool, &s.config).await?;
    Ok((StatusCode::CREATED, Json(r)).into_response())
}

async fn enrollment(
    State(s): State<Arc<AppState>>,
    RawBody(body): RawBody,
) -> Result<Response, ApiError> {
    let r = service::enroll(&s.pool, &s.config, &s.root_pem, &body).await?;
    Ok((StatusCode::CREATED, Json(r)).into_response())
}

async fn assertion(
    State(s): State<Arc<AppState>>,
    RawBody(body): RawBody,
) -> Result<Response, ApiError> {
    let r = service::verify_assertion(&s.pool, &s.config, &body).await?;
    Ok(Json(r).into_response())
}
