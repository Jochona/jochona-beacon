//! One error type for every `/jochona/beacon/v1/*` handler. Every variant
//! carries a short machine-readable token (matching the ones the wire
//! contract already fixes, e.g. `"no_open_pairing_window"`,
//! `"confirmation_mismatch"`) so the JSON body is `{"error": "<token>"}`
//! and never leaks internal detail to the network.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::api::dto::ErrorBody;

pub enum ApiError {
    BadRequest(String),
    Forbidden(&'static str),
    NotFound(&'static str),
    Conflict(&'static str),
    Gone(&'static str),
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Forbidden(token) => (StatusCode::FORBIDDEN, token.to_string()),
            ApiError::NotFound(token) => (StatusCode::NOT_FOUND, token.to_string()),
            ApiError::Conflict(token) => (StatusCode::CONFLICT, token.to_string()),
            ApiError::Gone(token) => (StatusCode::GONE, token.to_string()),
            ApiError::Internal(err) => {
                tracing::error!(error = %err, "internal API error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error".to_string(),
                )
            }
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err)
    }
}
