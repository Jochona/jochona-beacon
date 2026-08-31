//! `SPAKE2-P256-SHA256-HKDF-HMAC` (RFC 9382 §6, Table 1), locked with the
//! Client team in `docs/protocols/client-v1.md`. Implemented
//! directly against P-256 point arithmetic (not the `spake2` crate, which
//! only ships an edwards25519 ciphersuite) so both this daemon and the
//! Client's OpenSSL-3-based implementation compute byte-identical values —
//! P-256's `EC_POINT`/`EVP_KDF` primitives are all public OpenSSL 3 API.
//!
//! Beacon always plays role **B** (uses point `N`); the Client plays role
//! **A** (uses `M`). Roles are fixed, never symmetric.
//!
//! The two-message RFC flow is spread across two HTTP round trips
//! (`/spake2/start`, `/spake2/confirm`). Between them Beacon must persist
//! only public values plus its own ephemeral scalar `y` — `Ka`/`Kc{A,B}`
//! are recomputed fresh at confirm time and never touch disk (see
//! `crate::storage::repo::pairings`).

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, Group, PrimeField};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

const M_COMPRESSED_HEX: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N_COMPRESSED_HEX: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

const SCRYPT_LOG_N: u8 = 15; // N = 32768
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DK_LEN: usize = 40; // NIST SP 800-56Ar3: order bit-length (256) + 64 bits, rounded to bytes

/// SEC1 uncompressed point encoding, 65 bytes for P-256: `0x04 || X || Y`.
pub type EncodedPointBytes = [u8; 65];
pub type Tag32 = [u8; 32];
pub type ScalarBytes = [u8; 32];

fn fixed_point(hex_compressed: &str) -> AffinePoint {
    let bytes = hex::decode(hex_compressed).expect("static M/N constant is valid hex");
    let encoded =
        EncodedPoint::from_bytes(&bytes).expect("static M/N constant is a valid SEC1 point");
    Option::from(AffinePoint::from_encoded_point(&encoded))
        .expect("static M/N constant is on-curve")
}

fn point_m() -> ProjectivePoint {
    ProjectivePoint::from(fixed_point(M_COMPRESSED_HEX))
}

fn point_n() -> ProjectivePoint {
    ProjectivePoint::from(fixed_point(N_COMPRESSED_HEX))
}

/// `salt = "jochona-beacon-pairing-v1" || 0x00 || beacon_id(16) || 0x00 || pairing_id(16)`.
pub fn compute_salt(beacon_id: Uuid, pairing_id: Uuid) -> Vec<u8> {
    let mut salt = Vec::with_capacity(26 + 1 + 16 + 1 + 16);
    salt.extend_from_slice(b"jochona-beacon-pairing-v1");
    salt.push(0);
    salt.extend_from_slice(beacon_id.as_bytes());
    salt.push(0);
    salt.extend_from_slice(pairing_id.as_bytes());
    salt
}

/// `w = OS2IP(scrypt(short_code, salt, N=32768, r=8, p=1, dkLen=40)) mod n`.
pub fn derive_w(short_code: &str, salt: &[u8]) -> Result<Scalar> {
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DK_LEN)
        .map_err(|e| anyhow!("invalid scrypt params: {e}"))?;
    let mut dk = [0u8; SCRYPT_DK_LEN];
    scrypt::scrypt(short_code.as_bytes(), salt, &params, &mut dk)
        .map_err(|e| anyhow!("scrypt derivation failed: {e}"))?;

    let n = p256_order();
    let reduced = BigUint::from_bytes_be(&dk) % &n;
    dk.zeroize();
    let mut w_bytes = [0u8; 32];
    let reduced_be = reduced.to_bytes_be();
    w_bytes[32 - reduced_be.len()..].copy_from_slice(&reduced_be);

    let scalar = Option::<Scalar>::from(Scalar::from_repr(w_bytes.into()))
        .ok_or_else(|| anyhow!("reduced scrypt output did not form a valid P-256 scalar"))?;
    Ok(scalar)
}

fn p256_order() -> BigUint {
    // NIST P-256 group order n.
    BigUint::parse_bytes(
        b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    .expect("static P-256 order literal is valid hex")
}

/// `w`, padded to 32 bytes big-endian (RFC 9382 §3.3: "padded to the length
/// of p"), for use inside the transcript.
pub fn w_encoded(w: &Scalar) -> ScalarBytes {
    w.to_bytes().into()
}

pub fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        bail!("public share must be a 65-byte SEC1 uncompressed point");
    }
    let encoded =
        EncodedPoint::from_bytes(bytes).map_err(|_| anyhow!("malformed SEC1 point encoding"))?;
    let affine: AffinePoint = Option::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| anyhow!("point is not on the P-256 curve"))?;
    let point = ProjectivePoint::from(affine);
    if bool::from(point.is_identity()) {
        bail!("point must not be the identity element (RFC 9382 §7)");
    }
    Ok(point)
}

fn encode_point(point: &ProjectivePoint) -> EncodedPointBytes {
    let encoded = point.to_affine().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(encoded.as_bytes());
    out
}

pub fn decode_scalar(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != 32 {
        bail!("scalar must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_repr(arr.into()))
        .ok_or_else(|| anyhow!("bytes do not form a valid P-256 scalar"))
}

/// `len(S)` as an 8-byte **little-endian** integer, per RFC 9382 §3.2.
fn le8(len: usize) -> [u8; 8] {
    (len as u64).to_le_bytes()
}

fn transcript(
    a_id: &[u8],
    b_id: &[u8],
    pa: &[u8],
    pb: &[u8],
    k: &[u8],
    w_enc: &ScalarBytes,
) -> Vec<u8> {
    let mut tt = Vec::with_capacity(
        8 * 6 + a_id.len() + b_id.len() + pa.len() + pb.len() + k.len() + w_enc.len(),
    );
    for (len_of, field) in [
        (a_id.len(), a_id),
        (b_id.len(), b_id),
        (pa.len(), pa),
        (pb.len(), pb),
        (k.len(), k),
        (w_enc.len(), w_enc.as_slice()),
    ] {
        tt.extend_from_slice(&le8(len_of));
        tt.extend_from_slice(field);
    }
    tt
}

struct KeySchedule {
    kc_a: [u8; 16],
    kc_b: [u8; 16],
}

fn key_schedule(tt: &[u8], aad: &[u8]) -> KeySchedule {
    let hash = Sha256::digest(tt);
    // Ke = hash[..16] is the RFC's protocol output; Beacon does not carry a
    // post-pairing session key (trust lives in the mTLS cert pin), so only
    // Ka is used further here.
    let mut ka = [0u8; 16];
    ka.copy_from_slice(&hash[16..]);

    let hk = hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ka);
    let mut info = Vec::with_capacity(16 + aad.len());
    info.extend_from_slice(b"ConfirmationKeys");
    info.extend_from_slice(aad);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes never fails");

    let mut kc_a = [0u8; 16];
    let mut kc_b = [0u8; 16];
    kc_a.copy_from_slice(&okm[..16]);
    kc_b.copy_from_slice(&okm[16..]);
    ka.zeroize();
    KeySchedule { kc_a, kc_b }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Tag32 {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Output of Beacon's round 1 (`POST /pairing/{id}/spake2/start`).
pub struct BeaconRound1 {
    pub pb: EncodedPointBytes,
    pub cb: Tag32,
    /// Persist alongside the session row; needed to recompute `K`
    /// deterministically at confirm time without storing `K`, `Ka`, or any
    /// `Kc*` value.
    pub y_scalar: ScalarBytes,
}

/// Beacon's (role B) round 1: consume the Client's `pA`, derive `w`, and
/// produce `pB`/`cB`.
pub fn beacon_round1(
    a_identity: &str,
    b_identity: &str,
    salt: &[u8],
    short_code: &str,
    pairing_id: Uuid,
    pa_bytes: &[u8],
) -> Result<BeaconRound1> {
    let pa = decode_point(pa_bytes)?;
    let w = derive_w(short_code, salt)?;
    let w_enc = w_encoded(&w);

    let y = Scalar::random(OsRng);
    let y_g = ProjectivePoint::generator() * y;
    let w_n = point_n() * w;
    let pb_point = w_n + y_g;
    let pb = encode_point(&pb_point);

    let w_m = point_m() * w;
    let k_point = (pa - w_m) * y;
    if bool::from(k_point.is_identity()) {
        bail!("derived shared point K is the identity element; aborting (likely wrong password)");
    }
    let k = encode_point(&k_point);

    let tt = transcript(
        a_identity.as_bytes(),
        b_identity.as_bytes(),
        pa_bytes,
        &pb,
        &k,
        &w_enc,
    );
    let schedule = key_schedule(&tt, pairing_id.as_bytes());
    let cb = hmac_sha256(&schedule.kc_b, &tt);

    Ok(BeaconRound1 {
        pb,
        cb,
        y_scalar: y.to_bytes().into(),
    })
}

/// Beacon's (role B) round 2: recompute `K`/`TT`/`KcA` from the persisted
/// `y` and the public values exchanged in round 1, then check the Client's
/// confirmation `cA` in constant time.
#[allow(clippy::too_many_arguments)]
pub fn beacon_verify_confirm(
    a_identity: &str,
    b_identity: &str,
    salt: &[u8],
    short_code: &str,
    pairing_id: Uuid,
    pa_bytes: &[u8],
    pb_bytes: &[u8],
    y_scalar_bytes: &[u8],
    ca_bytes: &[u8],
) -> Result<bool> {
    if ca_bytes.len() != 32 {
        bail!("client confirmation must be 32 bytes");
    }
    let pa = decode_point(pa_bytes)?;
    let y = decode_scalar(y_scalar_bytes)?;
    let w = derive_w(short_code, salt)?;
    let w_enc = w_encoded(&w);
    let w_m = point_m() * w;
    let k_point = (pa - w_m) * y;
    if bool::from(k_point.is_identity()) {
        return Ok(false);
    }
    let k = encode_point(&k_point);

    let tt = transcript(
        a_identity.as_bytes(),
        b_identity.as_bytes(),
        pa_bytes,
        pb_bytes,
        &k,
        &w_enc,
    );
    let schedule = key_schedule(&tt, pairing_id.as_bytes());
    let expected = hmac_sha256(&schedule.kc_a, &tt);
    Ok(expected.ct_eq(ca_bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the Client's role-A computation so the whole exchange can be
    /// validated without a live Client.
    fn client_round1(
        a_identity: &str,
        salt: &[u8],
        short_code: &str,
        x: Scalar,
    ) -> (EncodedPointBytes, Scalar) {
        let _ = a_identity;
        let w = derive_w(short_code, salt).unwrap();
        let x_g = ProjectivePoint::generator() * x;
        let w_m = point_m() * w;
        let pa_point = w_m + x_g;
        (encode_point(&pa_point), w)
    }

    fn client_confirm(
        a_identity: &str,
        b_identity: &str,
        pa: &[u8; 65],
        pb: &[u8],
        x: Scalar,
        w: Scalar,
        pairing_id: Uuid,
    ) -> Tag32 {
        let pb_point = decode_point(pb).unwrap();
        let w_n = point_n() * w;
        let k_point = (pb_point - w_n) * x;
        let k = encode_point(&k_point);
        let w_enc = w_encoded(&w);
        let tt = transcript(
            a_identity.as_bytes(),
            b_identity.as_bytes(),
            pa,
            pb,
            &k,
            &w_enc,
        );
        let schedule = key_schedule(&tt, pairing_id.as_bytes());
        hmac_sha256(&schedule.kc_a, &tt)
    }

    #[test]
    fn full_exchange_round_trips_and_both_sides_confirm() {
        let beacon_id = Uuid::new_v4();
        let pairing_id = Uuid::new_v4();
        let short_code = "48213077";
        let salt = compute_salt(beacon_id, pairing_id);
        let a_identity = "jochona-client:testfingerprint";
        let b_identity = format!("jochona-beacon:{beacon_id}:testfingerprint");

        let x = Scalar::random(OsRng);
        let (pa, w_client) = client_round1(a_identity, &salt, short_code, x);

        let round1 =
            beacon_round1(a_identity, &b_identity, &salt, short_code, pairing_id, &pa).unwrap();
        let ca = client_confirm(
            a_identity,
            &b_identity,
            &pa,
            &round1.pb,
            x,
            w_client,
            pairing_id,
        );

        let ok = beacon_verify_confirm(
            a_identity,
            &b_identity,
            &salt,
            short_code,
            pairing_id,
            &pa,
            &round1.pb,
            &round1.y_scalar,
            &ca,
        )
        .unwrap();
        assert!(ok, "valid client confirmation must verify");

        let mut bad_ca = ca;
        bad_ca[0] ^= 1;
        let bad = beacon_verify_confirm(
            a_identity,
            &b_identity,
            &salt,
            short_code,
            pairing_id,
            &pa,
            &round1.pb,
            &round1.y_scalar,
            &bad_ca,
        )
        .unwrap();
        assert!(!bad, "tampered confirmation must not verify");
    }

    #[test]
    fn mismatched_short_code_never_verifies() {
        let beacon_id = Uuid::new_v4();
        let pairing_id = Uuid::new_v4();
        let salt = compute_salt(beacon_id, pairing_id);
        let a_identity = "jochona-client:testfingerprint";
        let b_identity = format!("jochona-beacon:{beacon_id}:testfingerprint");

        let x = Scalar::random(OsRng);
        let (pa, w_client) = client_round1(a_identity, &salt, "11111111", x);

        // Beacon's session was opened with a different code.
        let round1 = beacon_round1(a_identity, &b_identity, &salt, "99999999", pairing_id, &pa);
        if let Ok(round1) = round1 {
            let ca = client_confirm(
                a_identity,
                &b_identity,
                &pa,
                &round1.pb,
                x,
                w_client,
                pairing_id,
            );
            let ok = beacon_verify_confirm(
                a_identity,
                &b_identity,
                &salt,
                "99999999",
                pairing_id,
                &pa,
                &round1.pb,
                &round1.y_scalar,
                &ca,
            )
            .unwrap();
            assert!(
                !ok,
                "mismatched short codes must never produce a valid confirmation"
            );
        }
    }

    /// Cross-checks the module against the byte-exact test vector published
    /// in `docs/protocols/client-v1.md`, computed independently
    /// with pure-Python P-256 arithmetic. Uses fixed (non-random) `x`/`y`
    /// scalars, which only `beacon_round1`'s *internals* would normally
    /// randomize — so this test recomputes round 1 manually rather than
    /// calling `beacon_round1` (which always samples a fresh `y`).
    #[test]
    fn matches_published_interop_test_vector() {
        let beacon_id = Uuid::parse_str("0f9e1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b").unwrap();
        let pairing_id = Uuid::parse_str("7d6c5b4a-3928-4170-9e1d-2c3b4a5f6e7d").unwrap();
        let short_code = "12345678";
        let client_spki = "aa11bb22cc33dd44ee55ff660011223344556677889900aabbccddeeff001122";
        let beacon_spki = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff11";
        let a_identity = format!("jochona-client:{client_spki}");
        let b_identity = format!("jochona-beacon:{beacon_id}:{beacon_spki}");

        let salt = compute_salt(beacon_id, pairing_id);
        assert_eq!(
            hex::encode(&salt),
            "6a6f63686f6e612d626561636f6e2d70616972696e672d7631000f9e1a2b3c4d4e5f8a9b0c1d2e3f4a5b007d6c5b4a392841709e1d2c3b4a5f6e7d"
        );

        let w = derive_w(short_code, &salt).unwrap();
        assert_eq!(
            hex::encode(w_encoded(&w)),
            "6f18c7f9d15dcfb1545265b92235c29dc971049d043ce76c8b100821e77e42ef"
        );

        let x = decode_scalar(
            &hex::decode("3f4e2a1b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071")
                .unwrap()[..32],
        )
        .unwrap();
        let y = decode_scalar(
            &hex::decode("1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809")
                .unwrap()[..32],
        )
        .unwrap();

        let x_g = ProjectivePoint::generator() * x;
        let w_m = point_m() * w;
        let pa_point = w_m + x_g;
        let pa = encode_point(&pa_point);
        assert_eq!(
            base64_of(&pa),
            "BOc2/2XFEtpLIE5dyhXACT5AlMH60h0UpfRHWh7JFhs/5dqCHGwwLQRADdOpKsi3Gvfz46mvwkvQ2yQEUZuumzg="
        );

        let y_g = ProjectivePoint::generator() * y;
        let w_n = point_n() * w;
        let pb_point = w_n + y_g;
        let pb = encode_point(&pb_point);
        assert_eq!(
            base64_of(&pb),
            "BJaiznnzPyov715ehyGpGKRkhQcpK1rnJYVGOSTCiP3QJlsm8aC1eBwg1ApTCF7F963YZOmvw/TI+elyzWxhfaQ="
        );

        let k_point = (pa_point - w_m) * y;
        let k = encode_point(&k_point);
        assert_eq!(
            base64_of(&k),
            "BCW9h1yqRmpoJo1FQnb38nhYZJC2FCqroIZeGOgWkU1nN/+EUHXASw85VOsayoq+ARFjgjGF9W0Xened3vdkeSg="
        );

        let w_enc = w_encoded(&w);
        let tt = transcript(
            a_identity.as_bytes(),
            b_identity.as_bytes(),
            &pa,
            &pb,
            &k,
            &w_enc,
        );
        assert_eq!(tt.len(), 470);

        let schedule = key_schedule(&tt, pairing_id.as_bytes());
        let ca = hmac_sha256(&schedule.kc_a, &tt);
        let cb = hmac_sha256(&schedule.kc_b, &tt);
        assert_eq!(
            base64_of(&ca),
            "W8X+XoTxl8pa/zzlH8f/mAs2mNkrCOVN40W9iH6QC0Q="
        );
        assert_eq!(
            base64_of(&cb),
            "8otjQyWycp3XAmvNjy0uCfoHuHXJ82PNJJX6v9wDEkA="
        );
    }

    fn base64_of(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}
