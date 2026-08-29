//! Beacon's stable TLS identity: a self-signed P-256 (secp256r1) leaf
//! certificate. Pure crypto here — persistence, encryption-at-rest, and the
//! "regenerating this hard-blocks every authorized client" policy live in
//! `crate::storage::repo::identity`.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::prelude::FromDer;

pub struct GeneratedIdentity {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
}

/// Generates a fresh self-signed P-256 leaf certificate for `beacon_id`,
/// valid for a long, effectively-unbounded window: the certificate's own
/// expiry is not the trust boundary here, the SPKI pin is.
pub fn generate_self_signed(beacon_id: Uuid) -> Result<GeneratedIdentity> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("generating beacon identity keypair")?;

    let mut params =
        CertificateParams::new(Vec::<String>::new()).context("building certificate params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("jochona-beacon:{beacon_id}"));
    dn.push(DnType::OrganizationName, "Jochona Beacon");
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2999, 1, 1);
    params.is_ca = rcgen::IsCa::NoCa;

    let cert = params
        .self_signed(&key_pair)
        .context("self-signing beacon identity certificate")?;

    Ok(GeneratedIdentity {
        cert_der: cert.der().to_vec(),
        key_pkcs8_der: key_pair.serialize_der(),
    })
}

/// `sha256(SubjectPublicKeyInfo DER)`, lowercase hex. OpenSSL clients must DER-
/// encode the complete `X509_PUBKEY` with `i2d_X509_PUBKEY`; hashing only the
/// public-key bits produces a different value.
pub fn spki_fingerprint_hex(cert_der: &[u8]) -> Result<String> {
    let spki = subject_public_key_info_der(cert_der)?;
    let digest = Sha256::digest(spki);
    Ok(hex::encode(digest))
}

pub fn subject_public_key_info_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .context("parsing certificate to extract SubjectPublicKeyInfo")?;
    Ok(cert.public_key().raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_parseable_self_signed_certificate_with_stable_fingerprint() {
        let id = Uuid::new_v4();
        let generated = generate_self_signed(id).unwrap();
        let fp1 = spki_fingerprint_hex(&generated.cert_der).unwrap();
        let fp2 = spki_fingerprint_hex(&generated.cert_der).unwrap();
        assert_eq!(
            fp1, fp2,
            "fingerprint must be deterministic for a fixed cert"
        );
        assert_eq!(fp1.len(), 64, "sha256 hex must be 64 chars");
    }

    #[test]
    fn distinct_identities_produce_distinct_fingerprints() {
        let a = generate_self_signed(Uuid::new_v4()).unwrap();
        let b = generate_self_signed(Uuid::new_v4()).unwrap();
        assert_ne!(
            spki_fingerprint_hex(&a.cert_der).unwrap(),
            spki_fingerprint_hex(&b.cert_der).unwrap()
        );
    }
}
