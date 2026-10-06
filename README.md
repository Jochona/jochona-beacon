# Jochona Beacon

A hardened, Linux-only LAN daemon that:

- pairs with the Jochona Client over a locked mTLS + SPAKE2 wire contract
  (see `SPAKE2-P256-SHA256-HKDF-HMAC` in [`src/crypto/spake2_pairing.rs`](src/crypto/spake2_pairing.rs)
  and the HTTP surface in [`src/api/routes/`](src/api/routes/)), and
- wakes registered Jochona/Sunshine/Apollo GameStream Hosts over
  Wake-on-LAN, observing their online/offline state via a pinned,
  authenticated `/serverinfo` poll — never by launching, stopping, or
  otherwise controlling them.

Beacon is optional: a paired Host and Client stream directly over the
LAN without it. Add Beacon only when something between them (a mesh
VPN overlay, a different subnet) can't carry the Wake-on-LAN broadcast
or you want LAN presence reporting independent of the stream itself.

The byte-for-byte Client contract is locked in
[`docs/protocols/client-v1.md`](docs/protocols/client-v1.md).

## Architecture

```
                         LAN (mTLS, cert-pinned, no CA)
Jochona Client  ───────────────────────────────────────►  Beacon HTTPS API
                                                            /jochona/beacon/v1/*
                                                            (src/api)
                                                                 │
                                                                 │ owns
                                                                 ▼
                                                          SQLite (src/storage)
                                                          — identity, clients,
                                                            hosts, wake_events,
                                                            pairing_sessions,
                                                            beacon_events

Local operator ──── loopback only, plain HTTP ────────►  Admin UI
                     127.0.0.1:<admin-port>                (src/admin)

Beacon ──── pinned HTTPS GET /serverinfo (observer) ───►  Host
       ──── Wake-on-LAN magic packets (UDP broadcast) ──►  Host
       ──── GameStream pairing handshake (enrollment) ──►  Host
```

- **`src/api`** — the Client-facing wire contract: pairing, `GET /hosts`,
  `POST /hosts/:id/wake`, `GET /wake/:id`, `GET /events` (SSE). Served
  over Beacon's own mTLS listener via a hand-rolled TLS accept loop
  (`src/api/serve.rs`) that extracts the connecting client certificate's
  fingerprint per-connection.
- **`src/admin`** — the loopback-only operator UI: open a pairing window
  (QR + short code), review/revoke authorized Clients, discover/enroll/
  revoke Hosts, view event and wake history, and the identity hard-block.
- **`src/crypto`** — Beacon's stable mTLS identity, the master key
  protecting secrets at rest, the SPAKE2 pairing ciphersuite, and the
  GameStream (Moonlight/Sunshine-compatible) pairing handshake used to
  enroll Hosts.
- **`src/storage`** — SQLite persistence (`rusqlite`, bundled SQLite,
  forward-only migrations in `migrations/`), AEAD sealing for
  encrypted-at-rest secrets.
- **`src/observer`** — the periodic pinned `/serverinfo` poll that is the
  *only* source of Host online/offline state, and Host family/permission
  classification.
- **`src/transport`** — Wake-on-LAN packets, physical-route-only MAC
  learning (`/proc/net/route` + `/proc/net/arp`), and the two mDNS roles
  (advertising `_jochona-beacon._tcp`, browsing for `_nvstream._tcp`).
- **`src/tls`** — inbound mTLS (accept any cert at the handshake,
  authorize per-route) and outbound certificate pinning (no CA) for
  Host connections.

## Building

```sh
cargo build --release
```

Requires Rust 1.88+. No system dependencies: SQLite is vendored
(`rusqlite`'s `bundled` feature) and TLS is pure-Rust (`rustls`/`ring`).

Every push and pull request runs `cargo fmt --check`, `cargo clippy
--all-targets --all-features -- -D warnings`, `cargo test --locked`, and
`cargo build --release --locked` (see `.github/workflows/ci.yml`).
Tagged `v*` pushes build release binaries for Linux (x86_64, aarch64),
Windows, and macOS, publish a `ghcr.io/jochona/jochona-beacon` image,
and attach everything to a GitHub Release
(`.github/workflows/release.yml`).

## Running

### systemd (recommended for bare-metal)

```sh
install -D -m 0644 packaging/systemd/jochona-beacon.service /etc/systemd/system/
install -d -m 0700 /etc/jochona-beacon
head -c 32 /dev/urandom > /etc/jochona-beacon/master-key
chmod 0600 /etc/jochona-beacon/master-key
systemctl daemon-reload
systemctl enable --now jochona-beacon
```

See the unit file's own header comment for the full master-key delivery
contract and the sandboxing/capability set it runs under.

### Container

```sh
docker build -t jochona-beacon .
docker run -d --network host --cap-add NET_BROADCAST --cap-add NET_RAW \
  -v jochona-beacon-data:/var/lib/jochona-beacon jochona-beacon
```

Host networking is required: Beacon needs to see the real LAN interfaces
for mDNS, Wake-on-LAN broadcast, and ARP-based MAC learning. See the
Dockerfile's own comments.

### Development

```sh
cargo run -- --data-dir ./data --bind 0.0.0.0:47100 --admin-bind 127.0.0.1:47101
```

Then open `http://127.0.0.1:47101/` for the admin UI.

## Configuration

Every flag has a matching `JOCHONA_BEACON_*` environment variable; run
`jochona-beacon --help` for the full, current list. The two addresses
that matter most:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--bind` | `0.0.0.0:47100` | LAN-reachable mTLS API (the wire contract) |
| `--admin-bind` | `127.0.0.1:47101` | Loopback-only admin UI — never expose this beyond localhost |

## Pairing a Client

1. Open `http://127.0.0.1:47101/pairing` (or click "Start pairing" on the
   dashboard) — this opens Beacon's one 60-second pairing window.
2. Scan the QR code with the Client, or enter the beacon address/
   fingerprint manually and type in the 8-digit short code shown.
3. The window closes automatically after one confirmation attempt,
   success or failure — a leaked/guessed short code never gets a second
   try.

## Enrolling a Host

`/hosts/discover` in the admin UI browses `_nvstream._tcp` for candidates
and lets you pair manually with a Host's own pairing PIN. Enrollment:

1. learns the Host's MAC only via a trusted physical-LAN ARP/route entry
   (never accepted as free-form input — see `src/transport/route.rs`);
2. runs the standard GameStream/Moonlight pairing handshake, requesting
   observer-only permission (`jochona_permission=observer_only` on the
   `getservercert` phase — a Jochona Host honors it, a stock
   Sunshine/Apollo Host simply ignores the unrecognized parameter) and
   pinning the Host's certificate for every future `/serverinfo` poll;
3. classifies the Host's family and the permission it actually granted,
   from the live `/serverinfo` response — never from having merely sent
   the request (Jochona Hosts that honor it report observer-only there;
   Sunshine/Apollo Hosts are always flagged with a broad-permission
   warning, since neither has a narrower grant to offer).

Beacon never stores the enrollment PIN or any other Host operator
credential — it exists only transiently, in memory, for the duration of
the pairing handshake.

## Data & secrets

All state lives under `--data-dir` (default `/var/lib/jochona-beacon`):
one SQLite database (`beacon.db`, mode 0600) and — only if no systemd
credential is configured — a fallback master key file (`master.key`,
mode 0600, rejected if permissions ever loosen). Every private key and
SecureOn password in the database is additionally sealed with
ChaCha20-Poly1305 under that master key before it ever touches disk; see
[`SECURITY.md`](SECURITY.md) for the full model.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option. Third-party notices: [`NOTICE`](NOTICE).
