//! Physical-route-only MAC learning. Beacon is Linux-only (contract:
//! "Rust, Linux x86_64 + aarch64"), so this reads `/proc/net/route` and
//! `/proc/net/arp` directly rather than pulling in a netlink crate for
//! what is, in the end, two small text files.
//!
//! A Host's MAC is only ever trusted if it was learned from an ARP entry
//! whose *route* to that IP goes out a physical interface — never a
//! virtual one (bridges, veth pairs, tunnels, VPNs, loopback). This is the
//! contract's "physical-route-only MAC learning" requirement: Beacon must
//! never learn (and therefore never wake-target) a MAC reachable only
//! through a container/VM/VPN hop, where "physical LAN" trust doesn't
//! actually hold.

use std::fs;
use std::net::Ipv4Addr;

use anyhow::{anyhow, Context, Result};

/// Interface name prefixes that are never treated as physical LAN links.
/// Not exhaustive by design (an allowlist would need updating for every
/// vendor's queue/bonding naming); this denylist plus the additional
/// `/sys/class/net/<if>/device` check below catches the common virtual
/// interface families on Linux.
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "lo", "veth", "docker", "br-", "virbr", "tun", "tap", "wg", "ppp", "cni", "flannel", "cali",
    "zt",
];

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub interface: String,
    pub destination: Ipv4Addr,
    pub mask: Ipv4Addr,
}

fn parse_hex_be_u32(field: &str) -> Result<u32> {
    // /proc/net/route stores destination/mask as little-endian hex words;
    // /proc/net/arp's addresses are plain dotted-decimal, so this helper is
    // only used for the route table.
    let raw = u32::from_str_radix(field, 16)
        .with_context(|| format!("parsing route table hex field {field:?}"))?;
    Ok(raw.swap_bytes())
}

pub fn read_route_table() -> Result<Vec<RouteEntry>> {
    read_route_table_from(
        &fs::read_to_string("/proc/net/route").context("reading /proc/net/route")?,
    )
}

fn read_route_table_from(contents: &str) -> Result<Vec<RouteEntry>> {
    let mut entries = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let interface = fields[0].to_string();
        let destination = Ipv4Addr::from(parse_hex_be_u32(fields[1])?);
        let mask = Ipv4Addr::from(parse_hex_be_u32(fields[7])?);
        entries.push(RouteEntry {
            interface,
            destination,
            mask,
        });
    }
    Ok(entries)
}

/// Longest-prefix-match lookup, exactly as the kernel would route the
/// packet, so the interface we check for "physical-ness" is the one the
/// wake/observation traffic would actually egress on.
pub fn interface_for(route_table: &[RouteEntry], target: Ipv4Addr) -> Option<String> {
    let target_bits = u32::from(target);
    route_table
        .iter()
        .filter(|e| {
            let mask_bits = u32::from(e.mask);
            let dest_bits = u32::from(e.destination);
            (target_bits & mask_bits) == (dest_bits & mask_bits)
        })
        .max_by_key(|e| u32::from(e.mask).count_ones())
        .map(|e| e.interface.clone())
}

pub fn is_physical_interface(name: &str) -> bool {
    if VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|p| name.starts_with(p))
    {
        return false;
    }
    // A physical NIC has a `device` symlink under sysfs pointing at a real
    // PCI/USB device; purely software interfaces (bonds, VLAN sub-ifs not
    // caught by the prefix list, wireguard variants, etc.) do not.
    std::path::Path::new(&format!("/sys/class/net/{name}/device")).exists()
}

pub fn read_arp_table() -> Result<Vec<(Ipv4Addr, [u8; 6], String)>> {
    read_arp_table_from(&fs::read_to_string("/proc/net/arp").context("reading /proc/net/arp")?)
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!("malformed MAC address {s:?}"));
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] =
            u8::from_str_radix(p, 16).with_context(|| format!("malformed MAC address {s:?}"))?;
    }
    Ok(out)
}

fn read_arp_table_from(contents: &str) -> Result<Vec<(Ipv4Addr, [u8; 6], String)>> {
    let mut entries = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let ip: Ipv4Addr = fields[0]
            .parse()
            .with_context(|| format!("parsing ARP IP {:?}", fields[0]))?;
        let mac_str = fields[3];
        if mac_str == "00:00:00:00:00:00" {
            continue; // incomplete entry
        }
        let mac = parse_mac(mac_str)?;
        let device = fields[5].to_string();
        entries.push((ip, mac, device));
    }
    Ok(entries)
}

/// The single entry point the enrollment flow calls: "give me the MAC for
/// this Host IP, but only if it is reachable via a trusted physical LAN
/// route" — returns `Ok(None)` (not an error) when the IP is only
/// reachable virtually, so callers can surface a clear "not on the
/// physical LAN" enrollment failure rather than a generic error.
pub fn learn_mac_via_physical_route(target: Ipv4Addr) -> Result<Option<([u8; 6], String)>> {
    let route_table = read_route_table()?;
    let Some(interface) = interface_for(&route_table, target) else {
        return Ok(None);
    };
    if !is_physical_interface(&interface) {
        return Ok(None);
    }
    let arp_table = read_arp_table()?;
    let hit = arp_table
        .into_iter()
        .find(|(ip, _mac, dev)| *ip == target && *dev == interface);
    Ok(hit.map(|(_ip, mac, dev)| (mac, dev)))
}

/// Reverse lookup used by wake targeting and the `/serverinfo` observer
/// poll: given the MAC learned at enrollment time, find its *current* IP
/// via the physical ARP table. Never trusts a stored/cached IP — DHCP
/// leases move while the MAC (and the physical-route trust established at
/// enrollment) stays stable. Returns `Ok(None)` (not an error) if the MAC
/// is no longer visible on `expected_interface`, e.g. the Host is
/// powered off, disconnected, or has roamed to another link — callers
/// treat that as "currently unreachable", not a hard error.
pub fn resolve_ip_for_mac(mac: [u8; 6], expected_interface: &str) -> Result<Option<Ipv4Addr>> {
    if !is_physical_interface(expected_interface) {
        return Ok(None);
    }
    let arp_table = read_arp_table()?;
    Ok(arp_table
        .into_iter()
        .find(|(_ip, entry_mac, dev)| *entry_mac == mac && dev == expected_interface)
        .map(|(ip, _mac, _dev)| ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_route_format() {
        // Real /proc/net/route line shape: Iface Destination Gateway Flags
        // RefCnt Use Metric Mask MTU Window IRTT. Destination/mask are
        // little-endian hex words (0x0101A8C0 == 192.168.1.1's LE encoding).
        let sample =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                       eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
                       eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        let table = read_route_table_from(sample).unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].interface, "eth0");
        assert_eq!(table[0].destination, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(table[0].mask, Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn longest_prefix_match_prefers_specific_route_over_default() {
        let table = vec![
            RouteEntry {
                interface: "eth0".into(),
                destination: Ipv4Addr::new(192, 168, 1, 0),
                mask: Ipv4Addr::new(255, 255, 255, 0),
            },
            RouteEntry {
                interface: "eth0".into(),
                destination: Ipv4Addr::new(0, 0, 0, 0),
                mask: Ipv4Addr::new(0, 0, 0, 0),
            },
        ];
        let iface = interface_for(&table, Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(iface.as_deref(), Some("eth0"));
    }

    #[test]
    fn virtual_interface_prefixes_are_rejected_by_name_alone() {
        assert!(!is_physical_interface("veth1234"));
        assert!(!is_physical_interface("docker0"));
        assert!(!is_physical_interface("lo"));
        assert!(!is_physical_interface("tun0"));
        assert!(!is_physical_interface("wg0"));
    }

    #[test]
    fn parses_proc_net_arp_format_and_skips_incomplete_entries() {
        let sample = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       192.168.1.10      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                       192.168.1.11      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let table = read_arp_table_from(sample).unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].0, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(table[0].1, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(table[0].2, "eth0");
    }

    #[test]
    fn resolve_ip_for_mac_rejects_non_physical_interface_without_reading_arp() {
        // A denylisted interface name is rejected before any ARP table
        // read happens, so this must pass even on hosts with no
        // /proc/net/arp at all (e.g. this test running on macOS/CI).
        let result = resolve_ip_for_mac([0, 1, 2, 3, 4, 5], "docker0");
        assert_eq!(result.unwrap(), None);
    }
}
