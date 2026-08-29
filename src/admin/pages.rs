//! Server-rendered HTML for the loopback administration interface. Plain
//! `format!`-built markup with inline CSS — no template engine or
//! frontend build step, matching the rest of this daemon's dependency
//! posture (nothing in `Cargo.toml` pulls in one).

use axum::response::Html;

use crate::domain::{AuthorizedClient, Host, HostState};

const STYLE: &str = r#"
:root { color-scheme: light dark; }
body { font-family: -apple-system, system-ui, sans-serif; max-width: 880px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
h1 { font-size: 1.4rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #8884; padding-bottom: .25rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid #8883; font-size: .92rem; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; word-break: break-all; }
form.inline { display: inline; }
button, input[type=submit] { cursor: pointer; padding: .3rem .7rem; border-radius: 6px; border: 1px solid #8888; background: #eee1; }
button.danger, input.danger { border-color: #c33; color: #c33; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .78rem; }
.badge.online { background: #2a72; color: #0a0; }
.badge.offline { background: #a222; color: #a00; }
.badge.unknown { background: #8882; }
.badge.warn { background: #fa02; color: #a60; }
.card { border: 1px solid #8884; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
.muted { opacity: .7; font-size: .88rem; }
label { display: block; margin: .5rem 0 .2rem; font-size: .9rem; }
input[type=text], input[type=number] { width: 100%; padding: .35rem; box-sizing: border-box; }
nav a { margin-right: 1rem; }
"#;

pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn layout(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Jochona Beacon</title><style>{STYLE}</style></head><body>
<nav><a href="/">Dashboard</a><a href="/pairing">Pairing</a><a href="/hosts/discover">Enroll a Host</a><a href="/history">History</a></nav>
<h1>{title}</h1>
{body}
</body></html>"#,
        title = escape(title),
    ))
}

fn host_state_badge(state: HostState) -> &'static str {
    match state {
        HostState::Online => r#"<span class="badge online">online</span>"#,
        HostState::Offline => r#"<span class="badge offline">offline</span>"#,
        HostState::Unknown => r#"<span class="badge unknown">unknown</span>"#,
    }
}

pub fn dashboard(
    beacon_id: uuid::Uuid,
    fingerprint: &str,
    lan_address: Option<String>,
    port: u16,
    pairing_window_open: bool,
    clients: &[AuthorizedClient],
    hosts: &[Host],
) -> String {
    let clients_rows = clients
        .iter()
        .filter(|c| c.revoked_at.is_none())
        .map(|c| {
            format!(
                r#"<tr><td class="mono">{fp}</td><td>{label}</td><td class="muted">{authorized_at}</td>
<td><form class="inline" method="post" action="/clients/{fp}/revoke" onsubmit="return confirm('Revoke this Client? It will immediately lose access.')"><button class="danger" type="submit">Revoke</button></form></td></tr>"#,
                fp = escape(&c.spki_fingerprint),
                label = escape(c.label.as_deref().unwrap_or("(unlabeled)")),
                authorized_at = escape(&crate::storage::repo::time_fmt::format(c.authorized_at)),
            )
        })
        .collect::<String>();
    let clients_table = if clients_rows.is_empty() {
        r#"<p class="muted">No Clients are authorized yet. Open a pairing window to authorize one.</p>"#.to_string()
    } else {
        format!("<table><tr><th>Fingerprint</th><th>Label</th><th>Authorized</th><th></th></tr>{clients_rows}</table>")
    };

    let hosts_rows = hosts
        .iter()
        .map(|h| {
            format!(
                r#"<tr><td>{name}</td><td>{family}</td><td>{state}</td><td>{permission}</td><td class="muted">{last_observed}</td>
<td><form class="inline" method="post" action="/hosts/{id}/revoke" onsubmit="return confirm('Remove this Host from the registry?')"><button class="danger" type="submit">Remove</button></form></td></tr>"#,
                name = escape(&h.name),
                family = escape(h.host_family.as_str()),
                state = host_state_badge(h.last_state),
                permission = if matches!(h.observer_permission, crate::domain::ObserverPermission::BroadPermissionWarning) {
                    r#"<span class="badge warn">broad permission</span>"#.to_string()
                } else {
                    "observer-only".to_string()
                },
                last_observed = h.last_observed_at.map(crate::storage::repo::time_fmt::format).unwrap_or_else(|| "never".to_string()),
                id = h.id,
            )
        })
        .collect::<String>();
    let hosts_table = if hosts_rows.is_empty() {
        r#"<p class="muted">No Hosts enrolled yet.</p>"#.to_string()
    } else {
        format!("<table><tr><th>Name</th><th>Family</th><th>State</th><th>Permission</th><th>Last observed</th><th></th></tr>{hosts_rows}</table>")
    };

    let pairing_cta = if pairing_window_open {
        r#"<p><a href="/pairing">A pairing window is currently open — view QR / short code</a></p>"#
            .to_string()
    } else {
        r#"<form method="post" action="/pairing/open"><button type="submit">Start pairing a new Client</button></form>"#.to_string()
    };

    format!(
        r#"
<div class="card">
<p><strong>Beacon ID:</strong> <span class="mono">{beacon_id}</span></p>
<p><strong>Fingerprint:</strong> <span class="mono">sha256:{fingerprint}</span></p>
<p><strong>Address:</strong> <span class="mono">{lan}:{port}</span></p>
{pairing_cta}
</div>

<h2>Authorized Clients</h2>
{clients_table}

<h2>Enrolled Hosts</h2>
{hosts_table}
<p><a href="/hosts/discover">+ Enroll a Host</a></p>

<h2>Danger zone</h2>
<details><summary>Regenerate Beacon identity</summary>
<p class="muted">Every currently-authorized Client will immediately lose access and must re-pair. This cannot be undone.</p>
<form method="post" action="/identity/regenerate" onsubmit="return confirm('This hard-blocks every authorized Client. Continue?')">
<input type="hidden" name="confirm" value="yes">
<button class="danger" type="submit">Regenerate identity</button>
</form>
</details>
"#,
        beacon_id = beacon_id,
        fingerprint = escape(fingerprint),
        lan = lan_address
            .as_deref()
            .unwrap_or("(no physical LAN address detected)"),
        port = port,
        pairing_cta = pairing_cta,
        clients_table = clients_table,
        hosts_table = hosts_table,
    )
}

pub fn pairing_closed() -> String {
    r#"<p>No pairing window is currently open.</p><form method="post" action="/pairing/open"><button type="submit">Start pairing</button></form>"#.to_string()
}

pub fn pairing_open(qr_svg: &str, short_code: &str, expires_at: &str, connect_uri: &str) -> String {
    format!(
        r#"
<div class="card">
<p>Scan with the Jochona Client, or enter manually. This window closes at <span class="mono">{expires_at}</span> or after one failed attempt.</p>
<div style="max-width:260px">{qr_svg}</div>
<p><strong>Short code:</strong> <span class="mono" style="font-size:1.4rem;letter-spacing:.15em">{short_code}</span></p>
<p class="muted">Connection info: <span class="mono">{connect_uri}</span></p>
<form method="post" action="/pairing/close"><button type="submit">Cancel pairing</button></form>
</div>
"#,
        qr_svg = qr_svg,
        short_code = escape(short_code),
        expires_at = escape(expires_at),
        connect_uri = escape(connect_uri),
    )
}

pub fn discover_hosts(candidates_html: &str) -> String {
    format!(
        r#"
<h2>Discovered on the LAN</h2>
{candidates_html}

<h2>Enroll manually</h2>
<form method="post" action="/hosts/enroll">
<label>Name<input type="text" name="name" required></label>
<label>IP address<input type="text" name="ip" required></label>
<label>HTTP port (plain-HTTP GameStream pairing)<input type="number" name="http_port" value="47989" required></label>
<label>HTTPS port (pinned /serverinfo)<input type="number" name="https_port" value="47984" required></label>
<label>PIN shown on the Host's own pairing prompt<input type="text" name="pin" required></label>
<label>SecureOn password (optional, 12 hex chars — only if the Host NIC requires one)<input type="text" name="secure_on_hex" pattern="[0-9a-fA-F]{{12}}" placeholder="AABBCCDDEEFF"></label>
<p><button type="submit">Pair &amp; enroll</button></p>
</form>
"#,
        candidates_html = candidates_html,
    )
}

pub fn history(events_html: &str, wakes_html: &str) -> String {
    format!(
        r#"
<h2>Recent events</h2>
{events_html}

<h2>Recent wakes</h2>
{wakes_html}

<form method="post" action="/history/clear" onsubmit="return confirm('Delete all retained event and observation history?')">
<button class="danger" type="submit">Clear history</button>
</form>
"#
    )
}
