//! TLS for both directions Beacon talks: inbound (its own HTTPS API, mTLS
//! against authorized Client certificates) and outbound (pinned HTTPS GETs
//! against enrolled Hosts' `/serverinfo`).

pub mod inbound;
pub mod pinned_client;

pub use pinned_client::PinnedCertVerifier;
