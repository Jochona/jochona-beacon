//! Application bootstrap: wires storage, crypto identities, the mTLS API
//! listener, the loopback admin listener, and every background task
//! (observer poll loop, pairing-window sweep, retention pruning, mDNS
//! advertisement) into one running daemon.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::api;
use crate::crypto::gamestream_pairing::GameStreamIdentity;
use crate::crypto::master_key::MasterKey;
use crate::domain::{BeaconEvent, BeaconIdentity};
use crate::observer;
use crate::storage::repo::{
    events as events_repo, gamestream_identity as gamestream_identity_repo,
    identity as identity_repo, observations as observations_repo, pairings as pairings_repo,
};
use crate::storage::Db;
use crate::tls;
use crate::transport::mdns_beacon::BeaconAdvertiser;

#[derive(Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    /// Beacon's own mTLS HTTPS API listener — LAN-reachable.
    pub bind: SocketAddr,
    /// The loopback-only administration interface.
    pub admin_bind: SocketAddr,
    /// Advertised in mDNS as `<hostname>.local.`; also shown on the admin
    /// pairing page as a manual-entry fallback.
    pub hostname: String,
    pub observer_poll_interval: Duration,
    pub pairing_sweep_interval: Duration,
    pub retention_sweep_interval: Duration,
    pub event_retention: time::Duration,
    pub observation_retention: time::Duration,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub master_key: MasterKey,
    pub identity: Arc<RwLock<BeaconIdentity>>,
    pub gamestream_identity: Arc<GameStreamIdentity>,
    pub tls_acceptor: api::serve::SharedAcceptor,
    pub advertiser: Arc<RwLock<Option<BeaconAdvertiser>>>,
    pub event_tx: broadcast::Sender<serde_json::Value>,
    pub config: Arc<Config>,
}

impl AppState {
    /// Appends one structured event to the durable audit log and fans it
    /// out to every live SSE subscriber, atomically from the caller's
    /// point of view (both use the same timestamp). Every event emission
    /// site in the API and background tasks goes through this — never
    /// `events::append` directly — so the two never drift apart.
    pub async fn emit_event(&self, event: BeaconEvent) -> Result<i64> {
        let at = time::OffsetDateTime::now_utc();
        let rowid = events_repo::append(&self.db, &event, at).await?;
        let _ = self.event_tx.send(event.to_envelope_json(at));
        Ok(rowid)
    }

    pub async fn beacon_id(&self) -> Uuid {
        self.identity.read().await.beacon_id
    }

    pub async fn beacon_fingerprint(&self) -> Result<String> {
        self.identity.read().await.fingerprint()
    }

    /// Regenerates Beacon's mTLS identity — the identity hard-block.
    /// Every previously authorized client immediately stops being able to
    /// authenticate (`AuthorizedClient::is_active` checks
    /// `authorized_since_beacon_identity` against the *new* beacon id on
    /// its very next request), and the live TLS acceptor is hot-swapped
    /// so the new certificate takes effect without restarting the
    /// listener or dropping unrelated in-flight connections.
    pub async fn regenerate_identity(&self) -> Result<BeaconIdentity> {
        let new_identity = identity_repo::regenerate(&self.db, self.master_key.clone()).await?;
        let fingerprint = new_identity.fingerprint()?;
        let new_advertiser = BeaconAdvertiser::start(
            new_identity.beacon_id,
            &fingerprint,
            &self.config.hostname,
            self.config.bind.port(),
        )
        .context("restarting mDNS advertisement for new Beacon identity")?;
        let server_config = tls::inbound::server_config(&new_identity)?;
        let new_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        *self.tls_acceptor.write().await = new_acceptor;
        *self.identity.write().await = new_identity.clone();
        *self.advertiser.write().await = Some(new_advertiser);
        Ok(new_identity)
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("installing SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("waiting for SIGINT")?;
            }
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("waiting for shutdown signal")?;

    Ok(())
}

pub async fn run(config: Config) -> Result<()> {
    if !config.admin_bind.ip().is_loopback() {
        anyhow::bail!(
            "admin listener {} is not loopback; use 127.0.0.1 or ::1",
            config.admin_bind
        );
    }
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("creating data directory {}", config.data_dir.display()))?;

    let db = Db::open(&config.data_dir.join("beacon.db"))?;
    let master_key = MasterKey::load(&config.data_dir)?;

    let identity = identity_repo::load_or_create(&db, master_key.clone()).await?;
    let gamestream_identity =
        gamestream_identity_repo::load_or_create(&db, master_key.clone()).await?;

    let server_config = tls::inbound::server_config(&identity)?;
    let tls_acceptor: api::serve::SharedAcceptor = Arc::new(RwLock::new(
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
    ));

    let (event_tx, _rx) = broadcast::channel(1024);
    let fingerprint = identity.fingerprint()?;
    let advertiser = BeaconAdvertiser::start(
        identity.beacon_id,
        &fingerprint,
        &config.hostname,
        config.bind.port(),
    )
    .context("starting mDNS advertisement")?;

    let state = AppState {
        db,
        master_key,
        identity: Arc::new(RwLock::new(identity.clone())),
        gamestream_identity: Arc::new(gamestream_identity),
        tls_acceptor: tls_acceptor.clone(),
        advertiser: Arc::new(RwLock::new(Some(advertiser))),
        event_tx,
        config: Arc::new(config.clone()),
    };

    let fingerprint = identity.fingerprint()?;

    let api_router = api::build_router(state.clone());
    let api_listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding HTTPS listener on {}", config.bind))?;

    let admin_router = crate::admin::build_router(state.clone());
    let admin_listener = TcpListener::bind(config.admin_bind)
        .await
        .with_context(|| format!("binding admin listener on {}", config.admin_bind))?;

    tracing::info!(
        bind = %config.bind,
        admin_bind = %config.admin_bind,
        beacon_id = %identity.beacon_id,
        fingerprint = %fingerprint,
        "jochona-beacon started"
    );

    let mut api_task = tokio::spawn(api::serve::run(api_router, api_listener, tls_acceptor));
    let pairing_sweep_task = tokio::spawn(pairing_sweep_loop(state.clone()));
    let retention_task = tokio::spawn(retention_loop(state.clone()));
    let observer_task = tokio::spawn(observer::gamestream::run_poll_loop(state.clone()));
    let mut admin_task =
        tokio::spawn(async move { axum::serve(admin_listener, admin_router).await });
    tokio::select! {
        result = shutdown_signal() => {
            result?;
            tracing::info!("received shutdown signal");
        }
        res = &mut api_task => {
            if let Err(err) = res {
                tracing::error!(error = %err, "HTTPS listener task panicked");
            }
        }
        res = &mut admin_task => {
            match res {
                Ok(Err(err)) => tracing::error!(error = %err, "admin listener exited with error"),
                Err(err) => tracing::error!(error = %err, "admin listener task panicked"),
                Ok(Ok(())) => {}
            }
        }
    }

    api_task.abort();
    admin_task.abort();

    pairing_sweep_task.abort();
    retention_task.abort();
    observer_task.abort();
    state.advertiser.write().await.take();
    Ok(())
}

async fn pairing_sweep_loop(state: AppState) {
    let mut interval = tokio::time::interval(state.config.pairing_sweep_interval);
    loop {
        interval.tick().await;
        if let Err(err) = pairings_repo::sweep_expired(&state.db).await {
            tracing::warn!(error = %err, "pairing window sweep failed");
        }
    }
}

async fn retention_loop(state: AppState) {
    let mut interval = tokio::time::interval(state.config.retention_sweep_interval);
    loop {
        interval.tick().await;
        let now = time::OffsetDateTime::now_utc();
        if let Err(err) =
            events_repo::prune_older_than(&state.db, now - state.config.event_retention).await
        {
            tracing::warn!(error = %err, "event retention prune failed");
        }
        if let Err(err) =
            observations_repo::prune_older_than(&state.db, now - state.config.observation_retention)
                .await
        {
            tracing::warn!(error = %err, "observation retention prune failed");
        }
    }
}
