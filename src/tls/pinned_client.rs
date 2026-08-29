//! Outgoing TLS verification for Beacon's own connections to enrolled
//! Hosts: no CA chain, pure certificate pinning by
//! `SHA-256(SubjectPublicKeyInfo DER)` — the pin recorded at GameStream
//! observer-pairing time (`crate::crypto::gamestream_pairing`). Signature
//! cryptography is still fully verified; only chain-of-trust is replaced.

use std::fmt::Debug;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct PinnedCertVerifier {
    pub expected_spki_sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedCertVerifier {
    pub fn new(expected_spki_sha256: [u8; 32]) -> Self {
        Self {
            expected_spki_sha256,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let spki = crate::crypto::identity::subject_public_key_info_der(end_entity.as_ref())
            .map_err(|e| TlsError::General(format!("parsing presented certificate: {e}")))?;
        let digest: [u8; 32] = Sha256::digest(&spki).into();
        if digest == self.expected_spki_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "Host certificate pin mismatch: the pinned certificate from enrollment no longer matches \
                 what the Host is presenting. Re-enroll the Host if this change was intentional."
                    .to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
