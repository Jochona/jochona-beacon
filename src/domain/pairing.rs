use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingPhase {
    /// Window opened, waiting for `/spake2/start`.
    Open,
    /// `pB`/`cB` issued, waiting for `/spake2/confirm`.
    Started,
    /// Confirmation verified; the client cert on that connection is now
    /// authorized. Terminal — the row is deleted right after.
    Confirmed,
    /// Any failure (bad point, mismatched confirm, expiry). Terminal, and
    /// per the one-shot design the whole window closes with it.
    Failed,
}

impl PairingPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            PairingPhase::Open => "open",
            PairingPhase::Started => "started",
            PairingPhase::Confirmed => "confirmed",
            PairingPhase::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(PairingPhase::Open),
            "started" => Some(PairingPhase::Started),
            "confirmed" => Some(PairingPhase::Confirmed),
            "failed" => Some(PairingPhase::Failed),
            _ => None,
        }
    }
}

pub struct PairingSession {
    pub id: Uuid,
    pub short_code: String,
    pub salt: Vec<u8>,
    pub phase: PairingPhase,
    pub beacon_scalar_y: Option<Vec<u8>>,
    pub client_share_pa: Option<Vec<u8>>,
    pub beacon_share_pb: Option<Vec<u8>>,
    pub client_identity_a: Option<String>,
    pub attempts: u32,
    pub opened_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl PairingSession {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }
}
