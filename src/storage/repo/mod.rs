pub mod clients;
pub mod events;
pub mod gamestream_identity;
pub mod hosts;
pub mod identity;
pub mod observations;
pub mod pairings;
pub mod wake_events;

/// Shared RFC3339 helpers so every repo formats/parses timestamps the same
/// way (SQLite has no native datetime type; we store TEXT).
pub(crate) mod time_fmt {
    use anyhow::{Context, Result};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn format(t: OffsetDateTime) -> String {
        t.format(&Rfc3339)
            .expect("OffsetDateTime always formats as RFC3339")
    }

    pub fn parse(s: &str) -> Result<OffsetDateTime> {
        OffsetDateTime::parse(s, &Rfc3339)
            .with_context(|| format!("parsing stored RFC3339 timestamp {s:?}"))
    }
}
