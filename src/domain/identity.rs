use time::OffsetDateTime;
use uuid::Uuid;

/// Beacon's own stable TLS identity: one self-signed P-256 leaf certificate
/// plus its private key. Regenerating this identity is the "hard block"
/// event — every previously authorized client becomes unauthorized (see
/// `crate::storage::repo::clients`) until the owner re-pairs.
#[derive(Clone)]
pub struct BeaconIdentity {
    pub beacon_id: Uuid,
    pub cert_der: Vec<u8>,
    /// Decrypted PKCS#8 DER private key. Only ever held in memory; the
    /// on-disk row stores this encrypted (see `crate::crypto::secret_box`).
    pub key_pkcs8_der: Vec<u8>,
    pub created_at: OffsetDateTime,
}

impl BeaconIdentity {
    /// `sha256(SubjectPublicKeyInfo DER)`, lowercase hex — the value both
    /// Beacon and Client refer to as the "Beacon fingerprint".
    pub fn fingerprint(&self) -> anyhow::Result<String> {
        crate::crypto::identity::spki_fingerprint_hex(&self.cert_der)
    }
}
