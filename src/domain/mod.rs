//! Plain domain types shared across storage, crypto, transport, and the API.
//!
//! This module intentionally has no I/O: it is the vocabulary the rest of
//! the daemon is built from. Persistence lives in `crate::storage`, wire
//! shapes live in `crate::api::dto`.

mod client;
mod event;
mod host;
mod identity;
mod observation;
mod pairing;
mod wake;

pub use client::AuthorizedClient;
pub use event::{host_state_event, BeaconEvent};
pub use host::{Host, HostFamily, HostState, ObserverPermission};
pub use identity::BeaconIdentity;
pub use observation::{HostObservation, ObservationSource};
pub use pairing::{PairingPhase, PairingSession};
pub use wake::WakeEvent;
