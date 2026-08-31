//! Client-side implementation of the NVIDIA GameStream / Moonlight pairing
//! handshake, as implemented identically by Sunshine (`src/nvhttp.cpp`,
//! `src/crypto.cpp`) and therefore by Jochona Host and by stock
//! Sunshine/Apollo installations alike. Beacon plays the "Moonlight client"
//! role here, using a dedicated, persistent RSA identity distinct from its
//! own P-256 mTLS identity (`crate::crypto::identity`) — this one exists
//! purely to be pinned by Hosts.
//!
//! Algorithm verified against Sunshine's actual server-side implementation
//! (read from `LizardByte/Sunshine` `src/nvhttp.cpp` + `src/crypto.cpp`,
//! commit tracked in `docs/` — see the four `nvhttp::PAIR_PHASE` handlers:
//! `getservercert`, `clientchallenge`, `serverchallengeresp`,
//! `clientpairingsecret`):
//!
//! ```text
//! 1. getservercert:      client -> salt(16), clientcert(PEM)
//!                        server -> plaincert(PEM), key = SHA256(salt||pin)[..16]
//! 2. clientchallenge:    client -> AES128-ECB(key, challenge(16))
//!                        server -> AES128-ECB(key, SHA256(challenge||sign(serverCert)||serverSecret(16)) || serverChallenge(16))
//! 3. serverchallengeresp:client -> AES128-ECB(key, SHA256(serverChallenge||sign(clientCert)||clientSecret(16)))
//!                        server -> serverSecret(16) || RSA-SHA256-sign(serverSecret)
//! 4. clientpairingsecret:client -> clientSecret(16) || RSA-SHA256-sign(clientSecret)
//!                        server -> paired = 1/0
//! ```

use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};
use ecb::cipher::block_padding::NoPadding;
use ecb::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};
use rand::RngCore;
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rustls_pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::FromDer;

use crate::net::http_client;

type Aes128EcbEnc = ecb::Encryptor<Aes128>;
type Aes128EcbDec = ecb::Decryptor<Aes128>;

pub struct GameStreamIdentity {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pkcs8_der: Vec<u8>,
}

/// Generates Beacon's persistent RSA-2048 pairing identity. Must be
/// generated once and reused for every Host pairing — Hosts pin this
/// certificate, so regenerating it silently would strand every prior
/// pairing (mirroring the P-256 identity's own hard-block philosophy, just
/// enforced by the Host side instead of Beacon's).
pub fn generate_identity() -> Result<GameStreamIdentity> {
    let mut rng = rand::rngs::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).context("generating RSA-2048 GameStream pairing key")?;
    let key_pkcs8_der = private_key
        .to_pkcs8_der()
        .context("encoding GameStream pairing key as PKCS#8")?
        .as_bytes()
        .to_vec();

    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key_pkcs8_der.as_slice()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .context("loading RSA key into rcgen")?;

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .context("building GameStream identity cert params")?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "jochona-beacon-observer");
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2999, 1, 1);
    params.is_ca = rcgen::IsCa::NoCa;

    let cert = params
        .self_signed(&key_pair)
        .context("self-signing GameStream identity certificate")?;

    Ok(GameStreamIdentity {
        cert_der: cert.der().to_vec(),
        cert_pem: cert.pem(),
        key_pkcs8_der,
    })
}

fn signing_key_from_pkcs8_der(der: &[u8]) -> Result<SigningKey<Sha256>> {
    let private_key =
        RsaPrivateKey::from_pkcs8_der(der).context("parsing GameStream pairing private key")?;
    Ok(SigningKey::<Sha256>::new(private_key))
}

/// The ASN.1 `signatureValue` bytes of a self-signed certificate — used as
/// an identity-binding value exactly as Sunshine's `crypto::signature()`
/// does, not verified as a real signature here.
fn cert_signature_bytes(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .context("parsing certificate for signature extraction")?;
    Ok(cert.signature_value.data.to_vec())
}

fn cert_rsa_public_key(cert_der: &[u8]) -> Result<RsaPublicKey> {
    let spki = crate::crypto::identity::subject_public_key_info_der(cert_der)?;
    RsaPublicKey::from_public_key_der(&spki)
        .context("certificate does not carry a valid RSA public key")
}

fn derive_key(salt: &[u8; 16], pin: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(pin.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

fn aes_ecb_encrypt(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    Aes128EcbEnc::new(key.into()).encrypt_padded_vec_mut::<NoPadding>(plaintext)
}

fn aes_ecb_decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    Aes128EcbDec::new(key.into())
        .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .map_err(|e| anyhow!("AES-ECB decryption failed (wrong PIN?): {e}"))
}

fn xml_text(body: &[u8], tag: &str) -> Result<String> {
    let text = std::str::from_utf8(body).context("GameStream response is not valid UTF-8")?;
    let doc = roxmltree::Document::parse(text).context("GameStream response is not valid XML")?;
    let node = doc
        .descendants()
        .find(|n| n.has_tag_name(tag))
        .ok_or_else(|| anyhow!("GameStream response missing <{tag}>"))?;
    Ok(node.text().unwrap_or_default().to_string())
}

fn xml_status_ok(body: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(body).context("GameStream response is not valid UTF-8")?;
    let doc = roxmltree::Document::parse(text).context("GameStream response is not valid XML")?;
    let root = doc.root_element();
    let paired = root
        .descendants()
        .find(|n| n.has_tag_name("paired"))
        .and_then(|n| n.text());
    if paired != Some("1") {
        bail!("Host rejected pairing at this phase (paired != 1)");
    }
    Ok(())
}

pub struct HostPairingResult {
    /// The Host's GameStream server certificate, pinned for every future
    /// `/serverinfo` observation poll.
    pub host_cert_der: Vec<u8>,
}

/// Builds the Phase 1 (`getservercert`) request URI, including the
/// `jochona_permission=observer_only` request described on `pair_with_host`.
/// Pulled out of that function so the exact query string Beacon sends is
/// directly assertable in a test without a live/mock GameStream server.
fn getservercert_query(
    beacon_unique_id: &str,
    client_uuid: uuid::Uuid,
    salt: &[u8; 16],
    client_cert_pem: &[u8],
) -> String {
    format!(
        "/pair?uniqueid={}&uuid={}&phrase=getservercert&salt={}&clientcert={}&jochona_permission=observer_only",
        beacon_unique_id,
        client_uuid,
        hex::encode(salt),
        hex::encode(client_cert_pem)
    )
}

/// Runs the full four-phase pairing handshake against a Host discovered on
/// `_nvstream._tcp` (plain-HTTP port, typically 47989). `pin` is the short
/// numeric code the operator enters into the Host's own pairing prompt (a
/// *different* code than the Beacon↔Client SPAKE2 short code — this one is
/// dictated entirely by the upstream GameStream protocol, which Beacon does
/// not control, since the Host may be stock Sunshine/Apollo).
pub async fn pair_with_host(
    identity: &GameStreamIdentity,
    host_ip: &str,
    http_port: u16,
    pin: &str,
    beacon_unique_id: &str,
) -> Result<HostPairingResult> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_key(&salt, pin);

    // Phase 1: getservercert. `jochona_permission=observer_only` asks a
    // Jochona Host to restrict this pairing to observer-only access —
    // Beacon never wants anything broader, that is its entire design
    // (see SECURITY.md "Host enrollment"). Stock Sunshine/Apollo hosts
    // ignore unrecognized query parameters, so this is a no-op there;
    // Beacon's `broad_permission_warning` fallback in
    // `crate::observer::permission` still applies to them. This is only
    // ever a *request* — Beacon classifies a Host as observer-only solely
    // from the `<jochona_permission>` tag actually observed in that
    // Host's own `/serverinfo` response, never from having sent this.
    let query = getservercert_query(
        beacon_unique_id,
        uuid::Uuid::new_v4(),
        &salt,
        identity.cert_pem.as_bytes(),
    );
    let resp = http_client::get_http(host_ip, http_port, &query)
        .await
        .context("GameStream pairing phase 1 (getservercert)")?;
    if resp.status != 200 {
        bail!("Host returned HTTP {} for getservercert", resp.status);
    }
    xml_status_ok(&resp.body)?;
    let plaincert_hex = xml_text(&resp.body, "plaincert")?;
    let server_cert_pem =
        String::from_utf8(hex::decode(&plaincert_hex).context("decoding plaincert hex")?)
            .context("plaincert is not valid UTF-8 PEM")?;
    let server_cert_der = pem_to_der(&server_cert_pem)?;
    let server_sign = cert_signature_bytes(&server_cert_der)?;

    // Phase 2: clientchallenge
    let mut challenge = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    let encrypted_challenge = aes_ecb_encrypt(&key, &challenge);
    let query = format!(
        "/pair?uniqueid={}&devicename=beacon&updateState=1&clientchallenge={}",
        beacon_unique_id,
        hex::encode(encrypted_challenge)
    );
    let resp = http_client::get_http(host_ip, http_port, &query)
        .await
        .context("GameStream pairing phase 2 (clientchallenge)")?;
    xml_status_ok(&resp.body)?;
    let challengeresponse_hex = xml_text(&resp.body, "challengeresponse")?;
    let challengeresponse =
        hex::decode(&challengeresponse_hex).context("decoding challengeresponse hex")?;
    let decrypted = aes_ecb_decrypt(&key, &challengeresponse)?;
    if decrypted.len() != 48 {
        bail!(
            "challengeresponse must decrypt to 48 bytes, got {}",
            decrypted.len()
        );
    }
    let server_hash = &decrypted[..32];
    let server_challenge: [u8; 16] = decrypted[32..48]
        .try_into()
        .expect("slice is exactly 16 bytes");

    // Sanity-check the server's identity binding: SHA256(ourChallenge || sign(serverCert) || serverSecret)
    // is only fully verifiable once serverSecret arrives in phase 3, so we
    // defer that check to right after phase 3 completes (see below).

    // Phase 3: serverchallengeresp
    let mut client_secret = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut client_secret);
    let client_sign = cert_signature_bytes(&identity.cert_der)?;
    let mut hash_input = Vec::with_capacity(16 + client_sign.len() + 16);
    hash_input.extend_from_slice(&server_challenge);
    hash_input.extend_from_slice(&client_sign);
    hash_input.extend_from_slice(&client_secret);
    let client_hash = Sha256::digest(&hash_input);
    let encrypted_client_hash = aes_ecb_encrypt(&key, &client_hash);
    let query = format!(
        "/pair?uniqueid={}&devicename=beacon&updateState=1&serverchallengeresp={}",
        beacon_unique_id,
        hex::encode(encrypted_client_hash)
    );
    let resp = http_client::get_http(host_ip, http_port, &query)
        .await
        .context("GameStream pairing phase 3 (serverchallengeresp)")?;
    xml_status_ok(&resp.body)?;
    let pairingsecret_hex = xml_text(&resp.body, "pairingsecret")?;
    let pairingsecret = hex::decode(&pairingsecret_hex).context("decoding pairingsecret hex")?;
    if pairingsecret.len() <= 16 {
        bail!("pairingsecret too short");
    }
    let server_secret = &pairingsecret[..16];
    let server_secret_signature = &pairingsecret[16..];

    // Now verify the server actually holds the private key matching the
    // certificate we pinned in phase 1 (defeats a MITM without the real key).
    let server_pubkey = cert_rsa_public_key(&server_cert_der)?;
    let verifying_key = VerifyingKey::<Sha256>::new(server_pubkey);
    let server_sig =
        RsaSignature::try_from(server_secret_signature).context("malformed server signature")?;
    verifying_key
        .verify(server_secret, &server_sig)
        .map_err(|_| anyhow!("Host's proof-of-possession signature over serverSecret did not verify — possible MITM"))?;

    // And that the earlier challenge-response hash matches now that we know serverSecret.
    let mut expected_hash_input = Vec::with_capacity(16 + server_sign.len() + 16);
    expected_hash_input.extend_from_slice(&challenge);
    expected_hash_input.extend_from_slice(&server_sign);
    expected_hash_input.extend_from_slice(server_secret);
    let expected_hash = Sha256::digest(&expected_hash_input);
    if expected_hash.as_slice() != server_hash {
        bail!("Host's challenge-response hash did not match — wrong PIN or possible MITM");
    }

    // Phase 4: clientpairingsecret
    let signing_key = signing_key_from_pkcs8_der(&identity.key_pkcs8_der)?;
    let client_secret_signature = signing_key.sign(&client_secret);
    let mut client_pairing_secret =
        Vec::with_capacity(16 + client_secret_signature.to_bytes().len());
    client_pairing_secret.extend_from_slice(&client_secret);
    client_pairing_secret.extend_from_slice(&client_secret_signature.to_bytes());
    let query = format!(
        "/pair?uniqueid={}&devicename=beacon&updateState=1&clientpairingsecret={}",
        beacon_unique_id,
        hex::encode(client_pairing_secret)
    );
    let resp = http_client::get_http(host_ip, http_port, &query)
        .await
        .context("GameStream pairing phase 4 (clientpairingsecret)")?;
    xml_status_ok(&resp.body).context("Host rejected the final pairing proof")?;

    Ok(HostPairingResult {
        host_cert_der: server_cert_der,
    })
}

fn pem_to_der(pem_str: &str) -> Result<Vec<u8>> {
    let parsed =
        pem::parse(pem_str).map_err(|e| anyhow!("decoding server certificate PEM: {e}"))?;
    if parsed.tag() != "CERTIFICATE" {
        bail!("expected a CERTIFICATE PEM block, got {}", parsed.tag());
    }
    Ok(parsed.contents().to_vec())
}

#[cfg(test)]
mod pairing_query_tests {
    use super::*;

    #[test]
    fn getservercert_query_requests_observer_only_permission() {
        let salt = [7u8; 16];
        let query = getservercert_query(
            "beacon-unique-id",
            uuid::Uuid::nil(),
            &salt,
            b"-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
        );
        assert!(
            query.contains("&jochona_permission=observer_only"),
            "query must request observer-only permission: {query}"
        );
        assert!(query.starts_with(
            "/pair?uniqueid=beacon-unique-id&uuid=00000000-0000-0000-0000-000000000000&phrase=getservercert&salt="
        ));
    }
}
