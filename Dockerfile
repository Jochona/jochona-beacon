# Jochona Beacon container image.
#
# Beacon is a LAN-facing daemon: it needs to see the host's real network
# interfaces (mDNS advertisement/discovery, Wake-on-LAN broadcast,
# physical-route ARP introspection for MAC learning — see
# src/transport/route.rs) and its own `/proc/net/route` + `/proc/net/arp`.
# Run it with the host network namespace, not a bridged/NAT'd one:
#
#   docker run -d --name jochona-beacon \
#     --network host \
#     --cap-add NET_BROADCAST --cap-add NET_RAW \
#     -v jochona-beacon-data:/var/lib/jochona-beacon \
#     -e JOCHONA_BEACON_LOG_FORMAT=json \
#     ghcr.io/jochona/jochona-beacon:latest
#
# The master key falls back to a self-generated 0600 file inside the data
# volume when no systemd credential is present (there is no systemd
# inside the container) — see src/crypto/master_key.rs. Mount the data
# volume persistently so identity/authorization/enrollment state survives
# container recreation.

FROM rust:1.88-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked --bin jochona-beacon

FROM debian:bookworm-slim
RUN useradd --system --home-dir /var/lib/jochona-beacon --create-home --shell /usr/sbin/nologin jochona-beacon
COPY --from=builder /build/target/release/jochona-beacon /usr/local/bin/jochona-beacon
USER jochona-beacon
ENV JOCHONA_BEACON_DATA_DIR=/var/lib/jochona-beacon
VOLUME ["/var/lib/jochona-beacon"]
EXPOSE 47100/tcp
EXPOSE 47101/tcp
ENTRYPOINT ["/usr/local/bin/jochona-beacon"]
