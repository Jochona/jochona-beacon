use time::OffsetDateTime;
use uuid::Uuid;

/// Result bookkeeping for one wake request. `sent_at` accumulates one
/// timestamp per magic-packet burst (0s/1s/3s); `failed_at` is set only if
/// sending itself failed (e.g. socket error) — it is never inferred from
/// the Host's later online/offline observation, which is tracked
/// completely separately in `HostObservation`.
#[derive(Clone)]
pub struct WakeEvent {
    pub id: Uuid,
    pub host_id: Uuid,
    pub requested_by_fingerprint: String,
    pub idempotency_key: String,
    pub accepted_at: OffsetDateTime,
    pub sent_at: Vec<OffsetDateTime>,
    pub failed_at: Option<OffsetDateTime>,
    pub error: Option<String>,
}
