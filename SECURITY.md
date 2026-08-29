# Security model

Jochona Beacon is designed to run unattended on a home/small-office LAN
with no central CA and no cloud dependency. Trust is established entirely
by physical/local access and TOFU (trust-on-first-use) certificate
pinning, confirmed by a password-authenticated key exchange. This
document describes that model, its boundaries, and how to report a
vulnerability.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Contact the
maintainers privately (see the repository's contact information) with a
description and, if possible, reproduction steps. We aim to acknowledge
within a few business days.

## Trust boundaries

Beacon exposes exactly two listeners, with two different trust models:

1. **`--bind` (default `0.0.0.0:47100`) — mTLS, LAN-reachable.** This is
   the wire contract surface the Jochona Client talks to. No CA is
   trusted in either direction (§ "No CA" below); a pairing window must
   be explicitly opened by the local operator before any new Client can
   authorize itself, and after that, every route except the pairing
   handshake requires a cert already recorded in `authorized_clients`.
2. **`--admin-bind` (default `127.0.0.1:47101`) — plain HTTP, loopback
   only.** Startup rejects a non-loopback address. The router also checks
   the loopback `Host`, same-origin mutations, and browser fetch metadata
   to block DNS-rebinding and cross-site form requests. It has no separate
   user authentication, so local processes can administer Beacon.
   **Never** reverse-proxy or port-forward this listener.

## No CA — pure certificate pinning

Beacon's mTLS listener requests a client certificate on every connection
but accepts any well-formed certificate at the TLS handshake layer
(`src/tls/inbound.rs`); authorization is decided per-route afterward by
checking the connection's certificate fingerprint
(`SHA-256(SubjectPublicKeyInfo DER)`) against `authorized_clients`. This
is what makes the pairing endpoints reachable pre-authorization at all.

Both implementations hash the complete DER-encoded
`SubjectPublicKeyInfo` sequence. OpenSSL clients must encode
`X509_get_X509_PUBKEY(cert)` with `i2d_X509_PUBKEY` before SHA-256;
`X509_pubkey_digest` hashes only the key bits and is not equivalent.

Symmetrically, Beacon's own identity is a single self-signed P-256
certificate persisted for the daemon's lifetime (`src/crypto/identity.rs`).
The Client pins Beacon's fingerprint the first time SPAKE2 confirmation
succeeds on a live connection (never from an out-of-band hint like the QR
code or mDNS TXT record, which are only TOFU *hints* used to find
`host:port` — the pin is always the certificate actually observed at the
moment the password-authenticated exchange succeeds) and refuses any
future connection presenting a different one ("Beacon identity changed —
re-pair required").

## The identity hard-block

If Beacon's own mTLS identity is ever regenerated (`POST
/identity/regenerate` in the admin UI — a deliberate, confirmed, audited
action, never automatic), every previously authorized Client becomes
unauthorized on its very next request: `authorized_clients.
authorized_since_beacon_identity` is checked against the *current*
identity id on every request (`AuthorizedClient::is_active`), so there is
no separate revocation pass to forget to run. The live TLS listener is
hot-swapped to the new certificate at the same moment
(`AppState::regenerate_identity`), so there is no window where the old
and new identities are simultaneously valid.

## Pairing: SPAKE2, not a bearer secret

The 8-digit short code shown by the admin UI is never transmitted or
compared directly — it is folded into a `scrypt`-stretched password
scalar and consumed by a full `SPAKE2-P256-SHA256-HKDF-HMAC` exchange
(RFC 9382 §6, Table 1; see `src/crypto/spake2_pairing.rs` for the exact
transcript and a reproducible test vector shared with the Client team).
A pairing window is one-shot: any failed confirmation attempt — wrong
code, tampered transcript, replayed/relayed connection — immediately
closes the entire window rather than allowing further guesses.

## Host enrollment: observer-only by construction, never broad control

Beacon enrolls a Host via the standard GameStream/Moonlight pairing
handshake (`src/crypto/gamestream_pairing.rs`), pinning the Host's
certificate for every future request. After enrollment, Beacon only ever:

- performs a periodic, pinned, authenticated `GET /serverinfo` poll
  (`src/observer/gamestream.rs`) — the sole source of Host online/offline
  state; and
- sends Wake-on-LAN magic packets (`src/transport/wake.rs`) — the sole
  mechanism for waking a Host.

There is no other Host-facing RPC anywhere in this codebase: Beacon can
never launch, stop, pause, or send input to a Host, regardless of what
permission a non-Jochona Host (stock Sunshine/Apollo) might have granted
during pairing. Any Host that isn't a Jochona Host is always flagged
`broad_permission_warning` at enrollment and persisted as such
(`src/observer/permission.rs`), since it has no narrower grant to offer —
this is surfaced to the operator, never silently accepted as
observer-only.

## Physical-route-only MAC learning

A Host's MAC address is only ever trusted if learned from a live ARP
entry whose *route* to that IP egresses a physical network interface —
never a bridge, veth pair, container/VM/VPN tunnel, or loopback
(`src/transport/route.rs`). This is what makes Wake-on-LAN targeting
safe: Beacon will never learn (and therefore never wake-target) a MAC
that is only reachable through a virtual hop, where "same physical LAN"
trust doesn't actually hold. The same re-resolution runs on every
`/serverinfo` poll and wake, rather than trusting a cached/stale IP —
DHCP leases move; the MAC does not.

## Secrets at rest

Every private key and Host SecureOn password is sealed with
ChaCha20-Poly1305 (`src/storage/secret_box.rs`) under a 256-bit master
key before it is written to SQLite, with AAD binding each ciphertext to
the specific row/column it belongs to (so ciphertext can never be
silently moved between rows and successfully decrypt). The master key
itself is never stored in the database:

1. **Preferred:** a systemd credential (`LoadCredential=master-key:...`,
   see `packaging/systemd/jochona-beacon.service`) — the source file is
   root-owned/mode 0600 on disk, and systemd re-exposes it to the
   unprivileged service user only via a private tmpfs at process start.
2. **Fallback:** a self-generated, mode-0600 file inside the data
   directory, used for non-systemd installs (tarball, container,
   development). Beacon fails closed — refuses to start — rather than
   trust a fallback key file whose permissions have been loosened by
   anyone else.

Beacon never stores a Host operator's enrollment PIN, or any other Host
operator credential, in any form, at any point — it exists only
transiently in memory for the duration of the pairing handshake.

## Sandboxing

The packaged systemd unit runs Beacon as an unprivileged user with a
minimal capability set (`CAP_NET_BROADCAST`, `CAP_NET_RAW` — required for
WoL broadcast and raw ARP/route introspection respectively) and a broad
set of `systemd`-level sandboxing directives (`ProtectSystem=strict`,
`PrivateDevices=true`, `MemoryDenyWriteExecute=true`, syscall filtering,
namespace/personality restrictions); see the unit file for the complete,
current list.
