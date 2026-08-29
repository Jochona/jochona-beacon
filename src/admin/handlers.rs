use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::extract::{Form, Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::admin::pages;
use crate::app::AppState;
use crate::crypto::gamestream_pairing;
use crate::domain::{BeaconEvent, Host, HostState};
use crate::observer::{self, gamestream as observer_gamestream};
use crate::storage::repo::{
    clients as clients_repo, events as events_repo, hosts as hosts_repo, pairings as pairings_repo,
    time_fmt, wake_events as wake_events_repo,
};
use crate::transport::{mdns_host_discovery, route};

/// Renders as a plain error page — the admin interface is a
/// local/loopback-only trust boundary, so surfacing the underlying reason
/// (e.g. "wrong PIN", "not on the physical LAN") is a feature, not an
/// information-disclosure risk.
pub struct AdminError(anyhow::Error);

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        pages::layout(
            "Error",
            &format!(
                r#"<p class="card">{}</p><p><a href="/">Back to dashboard</a></p>"#,
                pages::escape(&self.0.to_string())
            ),
        )
        .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AdminError {
    fn from(err: E) -> Self {
        AdminError(err.into())
    }
}

/// Beacon's own primary physical-LAN IPv4 address, shown on the dashboard
/// and embedded in the pairing QR payload. `None` if no physical interface
/// currently carries an address (e.g. cable unplugged).
fn primary_lan_ipv4() -> Option<Ipv4Addr> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find_map(|iface| {
            if iface.is_loopback() || !route::is_physical_interface(&iface.name) {
                return None;
            }
            match iface.addr {
                if_addrs::IfAddr::V4(v4) => Some(v4.ip),
                _ => None,
            }
        })
}

fn interface_broadcast(interface_name: &str) -> Result<Ipv4Addr> {
    for iface in if_addrs::get_if_addrs().context("enumerating network interfaces")? {
        if iface.name != interface_name {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = iface.addr {
            if let Some(b) = v4.broadcast {
                return Ok(b);
            }
            let ip = u32::from(v4.ip);
            let mask = u32::from(v4.netmask);
            return Ok(Ipv4Addr::from(ip | !mask));
        }
    }
    bail!("could not determine the broadcast address for interface {interface_name}");
}

pub async fn dashboard(State(state): State<AppState>) -> Result<Html<String>, AdminError> {
    let identity = state.identity.read().await;
    let beacon_id = identity.beacon_id;
    let fingerprint = identity.fingerprint()?;
    drop(identity);

    let pairing_open = pairings_repo::current_open(&state.db).await?.is_some();
    let clients = clients_repo::list(&state.db).await?;
    let hosts = hosts_repo::list(&state.db, &state.master_key).await?;
    let lan = primary_lan_ipv4().map(|ip| ip.to_string());

    let body = pages::dashboard(
        beacon_id,
        &fingerprint,
        lan,
        state.config.bind.port(),
        pairing_open,
        &clients,
        &hosts,
    );
    Ok(pages::layout("Beacon", &body))
}

pub async fn open_pairing(State(state): State<AppState>) -> Result<Redirect, AdminError> {
    let beacon_id = state.beacon_id().await;
    let (session, _short_code) = pairings_repo::open_window(&state.db, beacon_id).await?;
    state
        .emit_event(BeaconEvent::PairingOpened {
            pairing_id: session.id,
            expires_at: time_fmt::format(session.expires_at),
        })
        .await?;
    Ok(Redirect::to("/pairing"))
}

pub async fn pairing_page(State(state): State<AppState>) -> Result<Html<String>, AdminError> {
    let Some(session) = pairings_repo::current_open(&state.db).await? else {
        return Ok(pages::layout("Pairing", &pages::pairing_closed()));
    };

    let identity = state.identity.read().await;
    let fingerprint = identity.fingerprint()?;
    drop(identity);

    let host = primary_lan_ipv4()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| state.config.hostname.clone());
    let port = state.config.bind.port();
    let connect_payload = serde_json::json!({
        "v": 1,
        "beacon_host": host,
        "beacon_port": port,
        "pairing_id": session.id,
        "beacon_fingerprint": format!("sha256:{fingerprint}"),
    })
    .to_string();
    let qr_svg = render_qr_svg(&connect_payload)?;

    let body = pages::pairing_open(
        &qr_svg,
        &session.short_code,
        &time_fmt::format(session.expires_at),
        &connect_payload,
    );
    Ok(pages::layout("Pairing", &body))
}

fn render_qr_svg(data: &str) -> Result<String> {
    let code = qrcode::QrCode::new(data.as_bytes())
        .map_err(|e| anyhow::anyhow!("building pairing QR code: {e:?}"))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .dark_color(qrcode::render::svg::Color("#111111"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

pub async fn close_pairing(State(state): State<AppState>) -> Result<Redirect, AdminError> {
    if let Some(session) = pairings_repo::current_open(&state.db).await? {
        pairings_repo::close(&state.db, session.id).await?;
        state
            .emit_event(BeaconEvent::PairingClosed {
                pairing_id: session.id,
                reason: "cancelled_by_admin".to_string(),
            })
            .await?;
    }
    Ok(Redirect::to("/"))
}

pub async fn revoke_client(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> Result<Redirect, AdminError> {
    if clients_repo::revoke(&state.db, &fingerprint).await? {
        state
            .emit_event(BeaconEvent::ClientRevoked { fingerprint })
            .await?;
    }
    Ok(Redirect::to("/"))
}

pub async fn discover_hosts(State(_state): State<AppState>) -> Result<Html<String>, AdminError> {
    let candidates = mdns_host_discovery::discover(Duration::from_secs(3)).await?;
    let candidates_html = if candidates.is_empty() {
        r#"<p class="muted">No GameStream servers found broadcasting on the LAN right now. You can still enroll one manually below.</p>"#.to_string()
    } else {
        let rows = candidates
            .iter()
            .map(|c| {
                format!(
                    "<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                    pages::escape(&c.instance_name),
                    c.address,
                    c.port
                )
            })
            .collect::<String>();
        format!("<table><tr><th>Name</th><th>Address</th><th>Port</th></tr>{rows}</table>")
    };
    Ok(pages::layout(
        "Enroll a Host",
        &pages::discover_hosts(&candidates_html),
    ))
}

#[derive(Deserialize)]
pub struct EnrollForm {
    pub name: String,
    pub ip: String,
    pub http_port: u16,
    pub https_port: u16,
    pub pin: String,
    #[serde(default)]
    pub secure_on_hex: String,
}

/// Parses the admin form's optional 12-hex-char SecureOn password. An
/// empty field (the common case — most NICs don't require one) means
/// `None`; anything else must be exactly 6 bytes of hex or enrollment
/// fails loudly rather than silently dropping a password the operator
/// typed.
fn parse_secure_on(hex_str: &str) -> Result<Option<[u8; 6]>> {
    let trimmed = hex_str.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(trimmed)
        .map_err(|_| anyhow::anyhow!("SecureOn password must be 12 hex characters"))?;
    if bytes.len() != 6 {
        bail!(
            "SecureOn password must decode to exactly 6 bytes, got {}",
            bytes.len()
        );
    }
    let mut arr = [0u8; 6];
    arr.copy_from_slice(&bytes);
    Ok(Some(arr))
}

pub async fn enroll_host(
    State(state): State<AppState>,
    Form(form): Form<EnrollForm>,
) -> Result<Redirect, AdminError> {
    let ip: Ipv4Addr = form
        .ip
        .parse()
        .map_err(|_| anyhow::anyhow!("{:?} is not a valid IPv4 address", form.ip))?;

    let (mac, learned_interface) = route::learn_mac_via_physical_route(ip)?.ok_or_else(|| {
        anyhow::anyhow!("{ip} is not reachable via a trusted physical LAN route from this Beacon")
    })?;
    let broadcast_address = interface_broadcast(&learned_interface)?;

    let beacon_unique_id = state.beacon_id().await.to_string();
    let pairing_result = gamestream_pairing::pair_with_host(
        &state.gamestream_identity,
        &ip.to_string(),
        form.http_port,
        &form.pin,
        &beacon_unique_id,
    )
    .await
    .context("GameStream pairing with the Host failed")?;

    let expected_spki = observer_gamestream::expected_spki_sha256(&pairing_result.host_cert_der)?;
    let serverinfo_xml = observer_gamestream::fetch_serverinfo(
        ip,
        form.https_port,
        expected_spki,
        &beacon_unique_id,
    )
    .await
    .context("Host paired successfully but the pinned /serverinfo probe failed")?;
    let gamestream_uuid = observer_gamestream::extract_uniqueid(&serverinfo_xml)?;
    let classification = observer::permission::classify(&serverinfo_xml)?;

    let host = Host {
        id: Uuid::new_v4(),
        gamestream_uuid,
        name: form.name,
        host_family: classification.host_family,
        observer_permission: classification.observer_permission,
        cert_der: pairing_result.host_cert_der,
        mac_address: mac,
        learned_interface,
        http_port: form.http_port,
        https_port: form.https_port,
        broadcast_address,
        secure_on: parse_secure_on(&form.secure_on_hex)?,
        last_state: HostState::Unknown,
        last_observed_at: None,
        enrolled_at: OffsetDateTime::now_utc(),
        revoked_at: None,
    };

    let persisted_host_id =
        hosts_repo::upsert_by_gamestream_uuid(&state.db, &state.master_key, &host).await?;
    state
        .emit_event(BeaconEvent::HostEnrolled {
            host_id: persisted_host_id,
            name: host.name.clone(),
            host_family: host.host_family.as_str().to_string(),
            observer_permission: match host.observer_permission {
                crate::domain::ObserverPermission::ObserverOnly => "observer_only".to_string(),
                crate::domain::ObserverPermission::BroadPermissionWarning => {
                    "broad_permission_warning".to_string()
                }
            },
        })
        .await?;

    Ok(Redirect::to("/"))
}

pub async fn revoke_host(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Redirect, AdminError> {
    if hosts_repo::revoke(&state.db, id).await? {
        state
            .emit_event(BeaconEvent::HostRevoked { host_id: id })
            .await?;
    }
    Ok(Redirect::to("/"))
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    pub confirm: String,
}

pub async fn regenerate_identity(
    State(state): State<AppState>,
    Form(form): Form<ConfirmForm>,
) -> Result<Redirect, AdminError> {
    if form.confirm != "yes" {
        return Err(anyhow::anyhow!("identity regeneration was not confirmed").into());
    }
    let new_identity = state.regenerate_identity().await?;
    state
        .emit_event(BeaconEvent::IdentityRegenerated {
            beacon_id: new_identity.beacon_id,
        })
        .await?;
    Ok(Redirect::to("/"))
}

pub async fn history(State(state): State<AppState>) -> Result<Html<String>, AdminError> {
    let events = events_repo::list_since(&state.db, 0, 200).await?;
    let events_html = if events.is_empty() {
        r#"<p class="muted">No events recorded yet.</p>"#.to_string()
    } else {
        let rows = events
            .iter()
            .rev()
            .take(100)
            .map(|(_, payload)| {
                format!(
                    "<tr><td class=\"mono\">{}</td></tr>",
                    pages::escape(&payload.to_string())
                )
            })
            .collect::<String>();
        format!("<table>{rows}</table>")
    };

    let wakes = wake_events_repo::list_recent(&state.db, 50).await?;
    let wakes_html = if wakes.is_empty() {
        r#"<p class="muted">No wake attempts recorded yet.</p>"#.to_string()
    } else {
        let rows = wakes
            .iter()
            .map(|w| {
                let sent = w.sent_at.len();
                let status = if w.failed_at.is_some() {
                    format!("failed: {}", w.error.as_deref().unwrap_or("unknown"))
                } else {
                    format!("{sent}/3 bursts sent")
                };
                format!(
                    "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"muted\">{}</td><td>{}</td></tr>",
                    w.id,
                    w.host_id,
                    time_fmt::format(w.accepted_at),
                    pages::escape(&status),
                )
            })
            .collect::<String>();
        format!("<table><tr><th>Wake ID</th><th>Host</th><th>Accepted</th><th>Status</th></tr>{rows}</table>")
    };

    Ok(pages::layout(
        "History",
        &pages::history(&events_html, &wakes_html),
    ))
}

pub async fn clear_history(State(state): State<AppState>) -> Result<Redirect, AdminError> {
    events_repo::clear_all(&state.db).await?;
    Ok(Redirect::to("/history"))
}
