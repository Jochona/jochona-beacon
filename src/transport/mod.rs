//! Everything that puts bytes on the physical LAN: Wake-on-LAN magic
//! packets, physical-route MAC learning, and the two mDNS roles (Beacon
//! advertises itself; Beacon also browses for Hosts).

pub mod mdns_beacon;
pub mod mdns_host_discovery;
pub mod route;
pub mod wake;
