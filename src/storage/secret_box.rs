//! AEAD sealing for the encrypted-at-rest columns (`beacon_identity.key_*`,
//! `hosts.secure_on_*`). ChaCha20-Poly1305 keyed by the master key
//! (`crate::crypto::master_key`); nonces are random and stored alongside
//! the ciphertext, AAD binds each secret to the row/column it belongs to so
//! ciphertext cannot be silently moved between rows.

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::RngCore;

use crate::crypto::master_key::MasterKey;

pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub fn seal(master_key: &MasterKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&master_key.0));
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("secret_box: encryption failure"))?;
    Ok(Sealed {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
    })
}

pub fn open(
    master_key: &MasterKey,
    aad: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(anyhow!(
            "secret_box: nonce must be 12 bytes, got {}",
            nonce.len()
        ));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&master_key.0));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("secret_box: decryption/authentication failure (wrong master key, tampered ciphertext, or mismatched AAD)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> MasterKey {
        MasterKey([9u8; 32])
    }

    #[test]
    fn round_trips_with_matching_aad() {
        let key = test_key();
        let sealed = seal(&key, b"hosts.secure_on:abc", b"topsecret").unwrap();
        let opened = open(
            &key,
            b"hosts.secure_on:abc",
            &sealed.ciphertext,
            &sealed.nonce,
        )
        .unwrap();
        assert_eq!(opened, b"topsecret");
    }

    #[test]
    fn rejects_mismatched_aad() {
        let key = test_key();
        let sealed = seal(&key, b"hosts.secure_on:abc", b"topsecret").unwrap();
        let opened = open(
            &key,
            b"hosts.secure_on:xyz",
            &sealed.ciphertext,
            &sealed.nonce,
        );
        assert!(
            opened.is_err(),
            "wrong AAD (moved ciphertext) must fail to decrypt"
        );
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = test_key();
        let mut sealed = seal(&key, b"aad", b"topsecret").unwrap();
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0xFF;
        let opened = open(&key, b"aad", &sealed.ciphertext, &sealed.nonce);
        assert!(opened.is_err());
    }
}
