//! API errors. Every response is `{"error": <stable code>}` plus an optional
//! content-free `reason` code; no input is ever echoed back.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(&'static str),
    PayloadTooLarge,
    InvalidChallenge,
    /// Verification failed: `error` is the class, `reason` the specific check.
    Rejected {
        error: &'static str,
        reason: &'static str,
    },
    UnknownDevice,
    DeviceNotActive,
    AlreadyEnrolled,
    /// A validly signed assertion that is not newer than the last accepted one:
    /// a verbatim replay or a stale, reordered submission. Rejected, but it
    /// does not flag the device: anyone who has seen an assertion could
    /// otherwise lock the user out by replaying it.
    AssertionReplay,
    /// A second, different assertion carrying the counter that was already
    /// accepted. An honest App Attest key never produces this: the device is
    /// flagged.
    CounterConflict,
    RateLimited,
    Internal,
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) | ApiError::InvalidChallenge => StatusCode::BAD_REQUEST,
            ApiError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::Rejected { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::UnknownDevice => StatusCode::NOT_FOUND,
            ApiError::DeviceNotActive => StatusCode::FORBIDDEN,
            ApiError::AlreadyEnrolled | ApiError::AssertionReplay | ApiError::CounterConflict => {
                StatusCode::CONFLICT
            }
            ApiError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::PayloadTooLarge => "payload_too_large",
            ApiError::InvalidChallenge => "invalid_challenge",
            ApiError::Rejected { error, .. } => error,
            ApiError::UnknownDevice => "unknown_device",
            ApiError::DeviceNotActive => "device_not_active",
            ApiError::AlreadyEnrolled => "already_enrolled",
            ApiError::AssertionReplay => "assertion_replay",
            ApiError::CounterConflict => "counter_conflict",
            ApiError::RateLimited => "rate_limited",
            ApiError::Internal => "internal",
        }
    }

    pub fn reason(&self) -> Option<&'static str> {
        match self {
            ApiError::BadRequest(r) => Some(r),
            ApiError::Rejected { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = match self.reason() {
            Some(reason) => json!({ "error": self.code(), "reason": reason }),
            None => json!({ "error": self.code() }),
        };
        (self.status(), Json(body)).into_response()
    }
}

/// Database failures are logged with their (content-free) error text and
/// reported to the caller as an opaque 500: fail closed.
impl From<tokio_postgres::Error> for ApiError {
    fn from(e: tokio_postgres::Error) -> Self {
        tracing::error!(error = %e, "database error");
        ApiError::Internal
    }
}

impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        tracing::error!(error = %e, "database pool error");
        ApiError::Internal
    }
}
