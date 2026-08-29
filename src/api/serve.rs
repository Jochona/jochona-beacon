//! Manual TLS-terminating accept loop. `axum::serve` has no TLS story, so
//! this hand-rolls the same shape as axum's own low-level rustls example,
//! adding the one thing that isn't optional for Beacon: the per-connection
//! client certificate fingerprint is extracted right after the handshake
//! and threaded into every request on that connection as
//! `Extension<PeerIdentity>` — this is what makes per-route mTLS
//! authorization (`crate::api::middleware::require_authorized_client`)
//! possible without re-deriving it per request.
//!
//! The acceptor is held behind a lock so `AppState::regenerate_identity`
//! (the identity hard-block) can hot-swap Beacon's TLS certificate without
//! restarting the listener or dropping in-flight connections.

use std::sync::Arc;

use axum::extract::Extension;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

use crate::api::middleware::PeerIdentity;
use crate::tls;

pub type SharedAcceptor = Arc<RwLock<TlsAcceptor>>;

pub async fn run(app: Router, listener: TcpListener, acceptor: SharedAcceptor) {
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(error = %err, "accepting TCP connection failed");
                continue;
            }
        };

        let current_acceptor = acceptor.read().await.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match current_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(err) => {
                    tracing::debug!(error = %err, %remote_addr, "TLS handshake failed");
                    return;
                }
            };

            let (_, session) = tls_stream.get_ref();
            let peer = tls::inbound::peer_fingerprint(session.peer_certificates());
            let peer_identity = PeerIdentity {
                fingerprint: peer.as_ref().map(|(fp, _)| fp.clone()),
                cert_der: peer.map(|(_, cert)| cert),
            };

            let app = app.layer(Extension(peer_identity));
            let io = TokioIo::new(tls_stream);

            let service = TowerToHyperService::new(app);
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!(error = %err, %remote_addr, "connection closed with error");
            }
        });
    }
}
