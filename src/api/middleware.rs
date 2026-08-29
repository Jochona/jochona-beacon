//! Per-route mTLS authorization. The TLS accept loop
//! (`crate::api::serve`) extracts the connecting client certificate's
//! fingerprint once per connection and threads it through as
//! `Extension<PeerIdentity>`; this middleware is what turns that into an
//! actual accept/reject decision for the "authorized clients only" route
//! group (`GET /hosts`, `POST /hosts/:id/wake`, `GET /wake/:wake_id`,
//! `GET /events`) — pairing routes deliberately never use it.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;

use crate::api::error::ApiError;
use crate::app::AppState;
use crate::storage::repo::clients as clients_repo;

/// The connecting client certificate's fingerprint/DER for *this*
/// connection, extracted immediately after the TLS handshake. `None` only
/// if the handshake somehow completed without a peer certificate, which
/// `crate::tls::inbound`'s `client_auth_mandatory() == true` should make
/// impossible in practice — kept as a safe fallback rather than a panic.
#[derive(Clone, Default)]
pub struct PeerIdentity {
    pub fingerprint: Option<String>,
    pub cert_der: Option<Vec<u8>>,
}

/// Inserted by `require_authorized_client` once a peer fingerprint has
/// been confirmed active, so downstream handlers never need to re-run the
/// authorization lookup themselves.
#[derive(Clone)]
pub struct AuthorizedClientFingerprint(pub String);

const UNAUTHORIZED: ApiError = ApiError::Forbidden("unauthorized");

pub async fn require_authorized_client(
    State(state): State<AppState>,
    Extension(peer): Extension<PeerIdentity>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let fingerprint = peer.fingerprint.ok_or(UNAUTHORIZED)?;

    let beacon_id = state.beacon_id().await.to_string();
    let client = clients_repo::find_by_fingerprint(&state.db, &fingerprint).await?;
    let Some(client) = client else {
        return Err(UNAUTHORIZED);
    };
    if !client.is_active(&beacon_id) {
        return Err(UNAUTHORIZED);
    }

    req.extensions_mut()
        .insert(AuthorizedClientFingerprint(fingerprint));
    Ok(next.run(req).await)
}
