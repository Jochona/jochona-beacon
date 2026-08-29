//! GameStream observation: the periodic authenticated `/serverinfo` poll
//! that independently tracks Host online/offline state (never derived from
//! wake send/accept results — see `crate::domain::HostObservation`), plus
//! the permission-family classification used at enrollment time.

pub mod gamestream;
pub mod permission;
