//! The mTLS-authenticated `/jochona/beacon/v1/*` surface — the exact wire
//! contract locked with the Client team in
//! `local://beacon-client-wire-contract.md`. Served over Beacon's own
//! HTTPS listener (`crate::api::serve`), distinct from the loopback-only
//! plain-HTTP admin interface (`crate::admin`).

pub mod dto;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod serve;
pub mod wake_scheduler;

use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;

use crate::app::AppState;

/// Base path fixed by the wire contract.
pub const BASE_PATH: &str = "/jochona/beacon/v1";

pub fn build_router(state: AppState) -> Router {
    // Reachable during the 60s pairing window without prior authorization.
    let pairing_routes = Router::new()
        .route("/pairing", get(routes::pairing::get_pairing))
        .route(
            "/pairing/:pairing_id/spake2/start",
            post(routes::pairing::spake2_start),
        )
        .route(
            "/pairing/:pairing_id/spake2/confirm",
            post(routes::pairing::spake2_confirm),
        );

    // mTLS required, authorized clients only.
    let authorized_routes = Router::new()
        .route("/hosts", get(routes::hosts::list_hosts))
        .route("/hosts/:id/wake", post(routes::wake::wake_host))
        .route("/wake/:wake_id", get(routes::wake::get_wake))
        .route("/events", get(routes::events::stream_events))
        .route_layer(from_fn_with_state(
            state.clone(),
            middleware::require_authorized_client,
        ));

    Router::new()
        .nest(BASE_PATH, pairing_routes.merge(authorized_routes))
        .with_state(state)
}
