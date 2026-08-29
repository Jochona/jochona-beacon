//! Beacon's own HTTPS listener: always requests a client certificate, but
//! accepts *any* well-formed one at the handshake layer — pairing
//! (`/pairing/*`) must be reachable before a certificate is authorized.
//! Per-route authorization happens afterward, in `crate::api::middleware`,
//! keyed on the fingerprint this module extracts from the live connection.

use std::fmt::Debug;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::FromDer;

use crate::domain::BeaconIdentity;

/// Accepts any syntactically valid X.509 client certificate — Beacon has no
/// CA to check clients against; trust is established out-of-band by SPAKE2
/// pairing (crypto::spake2_pairing) and enforced per-route afterward by
/// checking the extracted fingerprint against `authorized_clients`.
#[derive(Debug)]
struct AnyClientCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for AnyClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // Every route Beacon exposes needs *a* fingerprint to reason about
        // (pairing routes derive their SPAKE2 identity from it; every other
        // route requires it to already be authorized) — so a bare TLS
        // handshake with no client cert at all is never useful and is
        // rejected right here instead of failing confusingly later.
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref()).map_err(|e| {
            TlsError::General(format!("client presented a malformed certificate: {e}"))
        })?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
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
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
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

/// Builds Beacon's HTTPS server TLS config: its own identity cert/key,
/// client-cert-requested-but-any-accepted.
pub fn server_config(identity: &BeaconIdentity) -> anyhow::Result<ServerConfig> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivateKeyDer::try_from(identity.key_pkcs8_der.clone())
        .map_err(|e| anyhow::anyhow!("beacon identity private key is not valid PKCS#8: {e}"))?;

    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(AnyClientCertVerifier {
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    });
    // Silence an otherwise-unused-import warning if WebPkiClientVerifier is
    // ever swapped back in for a stricter deployment mode.
    let _ = WebPkiClientVerifier::builder;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|e| anyhow::anyhow!("building beacon TLS server config: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// `sha256(SubjectPublicKeyInfo DER)` of the leaf certificate presented on
/// a live connection — the value every mTLS-authorization decision hinges
/// on. Returns `None` if the handshake somehow completed without a peer
/// certificate (impossible given `client_auth_mandatory() == true`, kept as
/// a safe fallback rather than a panic).
pub fn peer_fingerprint(
    peer_certs: Option<&[CertificateDer<'static>]>,
) -> Option<(String, Vec<u8>)> {
    let leaf = peer_certs?.first()?;
    let spki = crate::crypto::identity::subject_public_key_info_der(leaf.as_ref()).ok()?;
    Some((hex::encode(Sha256::digest(&spki)), leaf.as_ref().to_vec()))
}
