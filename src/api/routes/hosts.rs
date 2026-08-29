//! `GET /hosts` — mTLS required, authorized clients only (enforced by
//! `crate::api::middleware::require_authorized_client` on the route
//! group, not here).

use axum::extract::State;
use axum::Json;

use crate::api::dto::HostDto;
use crate::api::error::ApiError;
use crate::app::AppState;
use crate::storage::repo::hosts as hosts_repo;

pub async fn list_hosts(State(state): State<AppState>) -> Result<Json<Vec<HostDto>>, ApiError> {
    let hosts = hosts_repo::list(&state.db, &state.master_key).await?;
    Ok(Json(hosts.into_iter().map(HostDto::from).collect()))
}
