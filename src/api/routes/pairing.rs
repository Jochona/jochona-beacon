//! `GET /pairing`, `POST /pairing/:id/spake2/start`, `POST
//! /pairing/:id/spake2/confirm` — reachable during the 60s pairing window
//! without prior authorization (see `docs/protocols/client-v1.md`
//! §3). Every crypto step is delegated to `crate::crypto::spake2_pairing`;
//! this module only wires HTTP <-> that module <-> `crate::storage::repo`.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::api::dto::{
    sha256_prefixed, PairingInfo, Spake2ConfirmFailure, Spake2ConfirmRequest, Spake2ConfirmSuccess,
    Spake2StartRequest, Spake2StartResponse,
};
use crate::api::error::ApiError;
use crate::api::middleware::PeerIdentity;
use crate::app::AppState;
use crate::crypto::spake2_pairing;
use crate::domain::{BeaconEvent, PairingPhase};
use crate::storage::repo::time_fmt;
use crate::storage::repo::{clients as clients_repo, pairings as pairings_repo};

const CIPHERSUITE: &str = "SPAKE2-P256-SHA256-HKDF-HMAC";

fn client_identity(fingerprint: &str) -> String {
    format!("jochona-client:{fingerprint}")
}

fn beacon_identity(beacon_id: Uuid, fingerprint: &str) -> String {
    format!("jochona-beacon:{beacon_id}:{fingerprint}")
}

async fn abort_pairing(state: &AppState, pairing_id: Uuid, reason: &str) {
    let _ = pairings_repo::close(&state.db, pairing_id).await;
    let _ = state
        .emit_event(BeaconEvent::PairingClosed {
            pairing_id,
            reason: reason.to_string(),
        })
        .await;
}

fn confirmation_mismatch() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(Spake2ConfirmFailure {
            status: "failed",
            reason: "confirmation_mismatch",
        }),
    )
        .into_response()
}

pub async fn get_pairing(State(state): State<AppState>) -> Result<Json<PairingInfo>, ApiError> {
    let session = pairings_repo::current_open(&state.db).await?;
    let Some(session) = session else {
        return Err(ApiError::NotFound("no_open_pairing_window"));
    };

    let identity = state.identity.read().await;
    let beacon_id = identity.beacon_id;
    let fingerprint = identity.fingerprint()?;
    drop(identity);

    Ok(Json(PairingInfo {
        beacon_id,
        beacon_fingerprint: sha256_prefixed(&fingerprint),
        pairing_id: session.id,
        expires_at: time_fmt::format(session.expires_at),
        ciphersuite: CIPHERSUITE,
    }))
}

pub async fn spake2_start(
    State(state): State<AppState>,
    Extension(peer): Extension<PeerIdentity>,
    Path(pairing_id): Path<Uuid>,
    Json(req): Json<Spake2StartRequest>,
) -> Result<Json<Spake2StartResponse>, ApiError> {
    let peer_fingerprint = peer.fingerprint.ok_or_else(|| {
        ApiError::BadRequest("no client certificate presented on this connection".to_string())
    })?;

    let Some(session) = pairings_repo::get(&state.db, pairing_id).await? else {
        return Err(ApiError::NotFound("unknown_pairing_id"));
    };
    let now = OffsetDateTime::now_utc();
    if session.is_expired(now) {
        pairings_repo::close(&state.db, pairing_id).await?;
        return Err(ApiError::NotFound("unknown_pairing_id"));
    }
    if session.phase != PairingPhase::Open {
        return Err(ApiError::Conflict("pairing_already_started"));
    }

    let pa_bytes = B64
        .decode(req.client_share.as_bytes())
        .map_err(|_| ApiError::BadRequest("client_share is not valid base64".to_string()))?;

    let identity = state.identity.read().await;
    let beacon_id = identity.beacon_id;
    let beacon_fp = identity.fingerprint()?;
    drop(identity);

    let a_identity = client_identity(&peer_fingerprint);
    let b_identity = beacon_identity(beacon_id, &beacon_fp);

    let round1 = spake2_pairing::beacon_round1(
        &a_identity,
        &b_identity,
        &session.salt,
        &session.short_code,
        pairing_id,
        &pa_bytes,
    )
    .map_err(|err| ApiError::BadRequest(format!("invalid client_share: {err}")))?;

    if !pairings_repo::record_started(
        &state.db,
        pairing_id,
        &a_identity,
        &pa_bytes,
        &round1.y_scalar,
        &round1.pb,
    )
    .await?
    {
        let current = pairings_repo::get(&state.db, pairing_id).await?;
        if current.is_none()
            || current.is_some_and(|value| value.is_expired(OffsetDateTime::now_utc()))
        {
            return Err(ApiError::NotFound("unknown_pairing_id"));
        }
        return Err(ApiError::Conflict("pairing_already_started"));
    }

    Ok(Json(Spake2StartResponse {
        beacon_share: B64.encode(round1.pb),
        beacon_confirm: B64.encode(round1.cb),
    }))
}

pub async fn spake2_confirm(
    State(state): State<AppState>,
    Extension(peer): Extension<PeerIdentity>,
    Path(pairing_id): Path<Uuid>,
    Json(req): Json<Spake2ConfirmRequest>,
) -> Result<Response, ApiError> {
    let (peer_fingerprint, peer_cert_der) = match (peer.fingerprint, peer.cert_der) {
        (Some(fp), Some(cert)) => (fp, cert),
        _ => {
            return Err(ApiError::BadRequest(
                "no client certificate presented on this connection".to_string(),
            ))
        }
    };

    // Atomically claims the session before any verification runs: two
    // concurrent `/confirm` requests for the same `pairing_id` must never
    // both reach `beacon_verify_confirm` below, or the one-shot guarantee
    // (exactly one evaluated guess per window) would be defeated by
    // sending several guesses at once instead of serially.
    let Some(session) = pairings_repo::claim_for_confirmation(&state.db, pairing_id).await? else {
        return Err(ApiError::Gone("pairing_window_expired"));
    };

    let identity = state.identity.read().await;
    let beacon_id = identity.beacon_id;
    let beacon_fp = identity.fingerprint()?;
    drop(identity);
    let b_identity = beacon_identity(beacon_id, &beacon_fp);

    // The transcript is bound to whatever identity was recorded at
    // `/start` — recomputing from *this* connection's cert would be
    // equivalent in the normal case (same client cert file) but the
    // persisted value is the one every other transcript field was already
    // computed against, so it is authoritative here.
    let session_a_identity = session.client_identity_a.clone().unwrap_or_default();

    if session_a_identity != client_identity(&peer_fingerprint) {
        abort_pairing(&state, pairing_id, "confirmation_mismatch").await;
        return Ok(confirmation_mismatch());
    }

    let ca_bytes = match B64.decode(req.client_confirm.as_bytes()) {
        Ok(b) => b,
        Err(_) => {
            abort_pairing(&state, pairing_id, "confirmation_mismatch").await;
            return Ok(confirmation_mismatch());
        }
    };

    let (Some(pa), Some(pb), Some(y)) = (
        &session.client_share_pa,
        &session.beacon_share_pb,
        &session.beacon_scalar_y,
    ) else {
        abort_pairing(&state, pairing_id, "confirmation_mismatch").await;
        return Ok(confirmation_mismatch());
    };

    let verified = spake2_pairing::beacon_verify_confirm(
        &session_a_identity,
        &b_identity,
        &session.salt,
        &session.short_code,
        pairing_id,
        pa,
        pb,
        y,
        &ca_bytes,
    )
    .unwrap_or(false);

    if !verified {
        abort_pairing(&state, pairing_id, "confirmation_mismatch").await;
        return Ok(confirmation_mismatch());
    }

    let beacon_id_str = beacon_id.to_string();
    clients_repo::authorize(
        &state.db,
        &peer_fingerprint,
        &peer_cert_der,
        None,
        &beacon_id_str,
    )
    .await?;
    pairings_repo::close(&state.db, pairing_id).await?;

    let authorized_at = OffsetDateTime::now_utc();
    state
        .emit_event(BeaconEvent::ClientAuthorized {
            fingerprint: peer_fingerprint.clone(),
        })
        .await?;
    state
        .emit_event(BeaconEvent::PairingClosed {
            pairing_id,
            reason: "confirmed".to_string(),
        })
        .await?;

    Ok(Json(Spake2ConfirmSuccess {
        status: "authorized",
        beacon_id,
        authorized_client_fingerprint: sha256_prefixed(&peer_fingerprint),
        authorized_at: time_fmt::format(authorized_at),
    })
    .into_response())
}
