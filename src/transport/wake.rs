//! Wake-on-LAN magic packet construction and the 0s/1s/3s burst schedule.
//! Every fact the packet needs (MAC, broadcast address, port, optional
//! SecureOn) is resolved server-side from the enrolled `Host` row — callers
//! never supply any of it (contract: "accepts no client-supplied
//! MAC/broadcast").

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Standard Wake-on-LAN magic packet: 6×`0xFF` then the target MAC
/// repeated 16 times, optionally followed by a 6-byte SecureOn password.
pub fn build_magic_packet(mac: &[u8; 6], secure_on: Option<&[u8; 6]>) -> Vec<u8> {
    let mut packet = Vec::with_capacity(6 + 16 * 6 + 6);
    packet.extend_from_slice(&[0xFFu8; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(mac);
    }
    if let Some(pw) = secure_on {
        packet.extend_from_slice(pw);
    }
    packet
}

/// Sends one magic packet to `broadcast_address:port`. A fresh broadcast-
/// enabled UDP socket is used per burst rather than kept open — wake
/// traffic is rare enough (seconds apart, at most a few times a day per
/// host) that the setup cost is irrelevant and it keeps the socket's
/// lifetime obviously scoped to a single send.
pub async fn send_burst(broadcast_address: Ipv4Addr, port: u16, packet: &[u8]) -> Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating WoL UDP socket")?;
    socket
        .set_broadcast(true)
        .context("enabling SO_BROADCAST")?;
    socket
        .set_nonblocking(true)
        .context("setting non-blocking mode")?;
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().expect("static bind address is valid");
    socket
        .bind(&bind_addr.into())
        .context("binding WoL UDP socket")?;
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket =
        UdpSocket::from_std(std_socket).context("adopting WoL UDP socket into tokio")?;

    let target = SocketAddr::new(broadcast_address.into(), port);
    tokio_socket
        .send_to(packet, target)
        .await
        .with_context(|| format!("sending WoL burst to {target}"))?;
    Ok(())
}

/// The wake burst schedule the contract fixes: absolute offsets of 0s, 1s,
/// and 3s from acceptance. The scheduler must not sleep these values
/// cumulatively.
pub const BURST_DELAYS_SECONDS: [u64; 3] = [0, 1, 3];

/// The UDP port Beacon targets for every magic packet — the traditional
/// Wake-on-LAN discard port. Not a per-Host setting: like MAC/broadcast/
/// SecureOn, "port" is one of the packet facts the contract requires
/// Beacon to resolve entirely server-side.
pub const WOL_PORT: u16 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_packet_has_correct_shape_without_secure_on() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = build_magic_packet(&mac, None);
        assert_eq!(packet.len(), 6 + 16 * 6);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        for chunk in packet[6..].chunks(6) {
            assert_eq!(chunk, &mac);
        }
    }

    #[test]
    fn magic_packet_appends_secure_on_password() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let secure_on = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let packet = build_magic_packet(&mac, Some(&secure_on));
        assert_eq!(packet.len(), 6 + 16 * 6 + 6);
        assert_eq!(&packet[packet.len() - 6..], &secure_on);
    }

    #[test]
    fn burst_schedule_uses_absolute_contract_offsets() {
        assert_eq!(BURST_DELAYS_SECONDS, [0, 1, 3]);
    }

    #[tokio::test]
    async fn burst_send_succeeds_against_loopback_broadcast_style_target() {
        // Loopback doesn't accept real broadcast, but sending to 127.0.0.1
        // on an ephemeral high port exercises the exact same code path
        // (socket creation, SO_BROADCAST, send_to) without needing a real
        // LAN segment, and must not error.
        let packet = build_magic_packet(&[1, 2, 3, 4, 5, 6], None);
        let result = send_burst(Ipv4Addr::new(127, 0, 0, 1), 39_000, &packet).await;
        assert!(
            result.is_ok(),
            "sending a UDP datagram to loopback must succeed: {result:?}"
        );
    }
}
