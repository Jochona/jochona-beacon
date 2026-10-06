# Changelog

## 1.0.0

Initial release. Jochona Beacon is an optional, Linux-only LAN daemon
that pairs with the Jochona Client and wakes registered GameStream
Hosts; a paired Host and Client already stream directly without it.

- **Client pairing** over a locked mTLS wire contract with no CA: a
  loopback-only admin UI (`127.0.0.1:47101/pairing`) opens a one-shot,
  60-second QR/short-code pairing window, confirmed by a
  `SPAKE2-P256-SHA256-HKDF-HMAC` password-authenticated key exchange
  (RFC 9382) rather than a bearer secret.
- **Host enrollment** via the standard GameStream/Moonlight pairing
  handshake, requesting observer-only permission
  (`jochona_permission=observer_only`) and pinning the Host's
  certificate for every future `/serverinfo` poll; Beacon can never
  launch, stop, or control a Host — only observe state and wake it.
- **Wake-on-LAN** with physical-route-only MAC learning: a Host's MAC
  is trusted only from a live ARP entry whose route egresses a real
  physical interface, re-resolved on every poll and wake rather than
  cached.
- **SQLite-backed state** (bundled `rusqlite`, forward-only migrations)
  with every private key and Host SecureOn password sealed via
  ChaCha20-Poly1305 under a master key before it touches disk, sourced
  from a systemd credential or a fallback mode-0600 file.
- **Packaging**: a systemd unit with capability/sandboxing restrictions
  for bare-metal installs, and a Debian-slim Docker image run with host
  networking.
- **Release pipeline**: tagged `v*` pushes build binaries for Linux
  (x86_64, aarch64 via `cross`), Windows (x86_64), and macOS (aarch64);
  publish a `ghcr.io/jochona/jochona-beacon` Docker image; and attach
  every archive plus a `SHA256SUMS` checksum file to an auto-generated
  GitHub Release. Binaries are unsigned.
