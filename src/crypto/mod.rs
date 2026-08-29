//! Cryptography: Beacon's own TLS identity, the master key protecting
//! encrypted-at-rest secrets, the Beacon↔Client SPAKE2 pairing protocol,
//! and the GameStream (Moonlight/Sunshine-compatible) observer-pairing
//! handshake used to enroll Hosts.

pub mod gamestream_pairing;
pub mod identity;
pub mod master_key;
pub mod spake2_pairing;
