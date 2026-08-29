//! `POST /hosts/:id/wake` and `GET /wake/:wake_id` — mTLS required,
//! authorized clients only. Exactly one accepted request ever schedules a
//! burst: replays of the same `(authorized_client_fingerprint, host_id,
//! Idempotency-Key)` tuple return the original recorded 202 body and
//! never touch `crate::api::wake_scheduler` again.

use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::api::dto::{WakeAccepted, WakeStatus};
use crate::api::error::ApiError;
use crate::api::middleware::AuthorizedClientFingerprint;
use crate::api::wake_scheduler;
use crate::app::AppState;
use crate::domain::{BeaconEvent, WakeEvent};
use crate::storage::repo::time_fmt;
use crate::storage::repo::{hosts as hosts_repo, wake_events as wake_events_repo};

fn accepted_response(accepted: &WakeEvent) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(WakeAccepted {
            wake_id: accepted.id,
            host_id: accepted.host_id,
            status: "accepted",
            idempotency_key: accepted.idempotency_key.clone(),
        }),
    )
        .into_response()
}

pub async fn wake_host(
    State(state): State<AppState>,
    Extension(AuthorizedClientFingerprint(fingerprint)): Extension<AuthorizedClientFingerprint>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ApiError::BadRequest("missing Idempotency-Key header".to_string()))?;

    let Some(host) = hosts_repo::get(&state.db, &state.master_key, host_id).await? else {
        return Err(ApiError::NotFound("unknown_host"));
    };
    if host.revoked_at.is_some() {
        return Err(ApiError::NotFound("unknown_host"));
    }

    if let Some(existing) =
        wake_events_repo::find_by_idempotency(&state.db, &fingerprint, host_id, &idempotency_key)
            .await?
    {
        return Ok(accepted_response(&existing));
    }

    let wake_id = Uuid::new_v4();
    let accepted_at = OffsetDateTime::now_utc();
    let event = WakeEvent {
        id: wake_id,
        host_id,
        requested_by_fingerprint: fingerprint.clone(),
        idempotency_key: idempotency_key.clone(),
        accepted_at,
        sent_at: Vec::new(),
        failed_at: None,
        error: None,
    };

    if let Err(err) = wake_events_repo::insert_accepted(&state.db, &event).await {
        // A concurrent request with the identical idempotency tuple may
        // have won the race between our lookup above and this insert; the
        // unique index makes that a constraint failure here rather than a
        // silent double-accept. Re-check for it before treating this as a
        // genuine error.
        if let Some(existing) = wake_events_repo::find_by_idempotency(
            &state.db,
            &fingerprint,
            host_id,
            &idempotency_key,
        )
        .await?
        {
            return Ok(accepted_response(&existing));
        }
        return Err(ApiError::from(err));
    }

    state
        .emit_event(BeaconEvent::WakeAccepted { wake_id, host_id })
        .await?;

    let scheduler_state = state.clone();
    tokio::spawn(async move {
        wake_scheduler::run_burst(scheduler_state, wake_id, host).await;
    });

    Ok(accepted_response(&event))
}

pub async fn get_wake(
    State(state): State<AppState>,
    Path(wake_id): Path<Uuid>,
) -> Result<Json<WakeStatus>, ApiError> {
    let Some(w) = wake_events_repo::get(&state.db, wake_id).await? else {
        return Err(ApiError::NotFound("unknown_wake_id"));
    };
    Ok(Json(WakeStatus {
        wake_id: w.id,
        host_id: w.host_id,
        accepted_at: time_fmt::format(w.accepted_at),
        sent_at: w.sent_at.into_iter().map(time_fmt::format).collect(),
        failed_at: w.failed_at.map(time_fmt::format),
        error: w.error,
    }))
}
