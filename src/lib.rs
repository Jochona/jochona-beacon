//! Jochona Beacon: a hardened Linux LAN daemon that pairs with the
//! Jochona Client over a locked mTLS + SPAKE2 wire contract
//! (`local://beacon-client-wire-contract.md`) and wakes registered
//! Jochona/Sunshine/Apollo Hosts over Wake-on-LAN.

pub mod admin;
pub mod api;
pub mod app;
pub mod crypto;
pub mod domain;
pub mod net;
pub mod observer;
pub mod storage;
pub mod tls;
pub mod transport;
