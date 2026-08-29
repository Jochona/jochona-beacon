//! The loopback-only administration interface — a server-rendered web UI
//! for the human operator running this Beacon. Deliberately plain HTTP,
//! no mTLS: it is bound to `127.0.0.1` only (`Config::admin_bind`), so its
//! trust boundary is "can reach this port on the local machine", the same
//! boundary that already protects the master key and SQLite database on
//! disk. This is where pairing windows are opened (Beacon-initiated, per
//! the wire contract — the Client only ever *joins* an already-open
//! window), Hosts are discovered/enrolled/revoked, Clients are revoked,
//! and the identity hard-block lives.

mod handlers;
mod pages;

use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::app::AppState;

fn allowed_admin_authority(authority: &str, port: u16) -> bool {
    authority == format!("127.0.0.1:{port}")
        || authority == format!("localhost:{port}")
        || authority == format!("[::1]:{port}")
}

fn allowed_admin_origin(origin: &str, port: u16) -> bool {
    origin == format!("http://127.0.0.1:{port}")
        || origin == format!("http://localhost:{port}")
        || origin == format!("http://[::1]:{port}")
}

async fn require_local_admin_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let port = state.config.admin_bind.port();
    let authority = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    if !allowed_admin_authority(authority, port) {
        return Err(StatusCode::FORBIDDEN);
    }

    if request
        .headers()
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("cross-site"))
    {
        return Err(StatusCode::FORBIDDEN);
    }

    if request.method() != Method::GET && request.method() != Method::HEAD {
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;
        if !allowed_admin_origin(origin, port) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(next.run(request).await)
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::dashboard))
        .route("/pairing", get(handlers::pairing_page))
        .route("/pairing/open", post(handlers::open_pairing))
        .route("/pairing/close", post(handlers::close_pairing))
        .route(
            "/clients/:fingerprint/revoke",
            post(handlers::revoke_client),
        )
        .route("/hosts/discover", get(handlers::discover_hosts))
        .route("/hosts/enroll", post(handlers::enroll_host))
        .route("/hosts/:id/revoke", post(handlers::revoke_host))
        .route("/identity/regenerate", post(handlers::regenerate_identity))
        .route("/history", get(handlers::history))
        .route("/history/clear", post(handlers::clear_history))
        .route_layer(from_fn_with_state(
            state.clone(),
            require_local_admin_origin,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_authority_accepts_only_explicit_loopback_names() {
        assert!(allowed_admin_authority("127.0.0.1:47101", 47101));
        assert!(allowed_admin_authority("localhost:47101", 47101));
        assert!(allowed_admin_authority("[::1]:47101", 47101));
        assert!(!allowed_admin_authority("beacon.local:47101", 47101));
        assert!(!allowed_admin_authority("127.0.0.1:80", 47101));
    }

    #[test]
    fn admin_origin_accepts_only_same_loopback_origin() {
        assert!(allowed_admin_origin("http://127.0.0.1:47101", 47101));
        assert!(allowed_admin_origin("http://localhost:47101", 47101));
        assert!(!allowed_admin_origin("https://attacker.example", 47101));
    }
}
