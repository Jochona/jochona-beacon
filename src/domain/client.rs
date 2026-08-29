use time::OffsetDateTime;

/// A Jochona Client X.509 certificate authorized for mTLS after a
/// successful SPAKE2 pairing.
#[derive(Clone, Debug)]
pub struct AuthorizedClient {
    pub id: i64,
    /// Lowercase hex `sha256(SubjectPublicKeyInfo DER)`.
    pub spki_fingerprint: String,
    pub cert_der: Vec<u8>,
    pub label: Option<String>,
    /// Beacon identity id this authorization was granted under. If Beacon's
    /// identity is later regenerated, authorizations bound to an older
    /// identity are treated as revoked (identity-change hard-block).
    pub authorized_since_beacon_identity: String,
    pub authorized_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl AuthorizedClient {
    pub fn is_active(&self, current_beacon_id: &str) -> bool {
        self.revoked_at.is_none() && self.authorized_since_beacon_identity == current_beacon_id
    }
}
