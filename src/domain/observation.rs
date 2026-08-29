use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationSource {
    /// Periodic authenticated `/serverinfo` poll against the Host's pinned
    /// certificate — the only source that may claim "online".
    ServerinfoPoll,
    /// The one observation recorded at enrollment time.
    Enrollment,
}

impl ObservationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ObservationSource::ServerinfoPoll => "serverinfo_poll",
            ObservationSource::Enrollment => "enrollment",
        }
    }
}

/// One independent online/offline data point for a Host. Deliberately
/// separate from `WakeEvent`: a sent magic packet is not evidence of
/// readiness, only a later successful `/serverinfo` probe is.
#[derive(Clone)]
pub struct HostObservation {
    pub host_id: Uuid,
    pub observed_at: OffsetDateTime,
    pub online: bool,
    pub source: ObservationSource,
}
