# Jochona Beacon ⇄ Client Wire Contract v1 (locked)

Authoritative for `Jochona/jochona-beacon` and the Client's Beacon integration. Wake endpoint path/verb is unchanged from the original contract (`POST /jochona/beacon/v1/hosts/:id/wake`).

## 1. TLS bootstrap & pinning (no CA — pure cert pinning, OpenSSL-3-native)

- Beacon holds one stable identity: ECDSA **P-256** keypair + self-signed X.509 leaf cert (SHA-256 signature), persisted for the daemon's lifetime. "Beacon fingerprint" = `SHA-256(SubjectPublicKeyInfo DER)`, lowercase hex, 32 bytes.
  - OpenSSL 3 side: obtain `X509_get_X509_PUBKEY(cert)`, DER-encode it with `i2d_X509_PUBKEY`, then hash those bytes with SHA-256. `X509_pubkey_digest` hashes only the key bits and is not equivalent.
- Beacon's HTTPS listener (mTLS-capable) always requests a client cert but accepts **any** well-formed cert at the TLS layer (self-signed is fine); authorization is decided at the HTTP layer per route, never at the handshake. This is what makes the pairing endpoints reachable pre-authorization.
- The default API port is `47100`. A Client must use `47100` when a manual Beacon URL omits its port.
- Discovery of `host:port` + fingerprint, in priority order: (a) QR payload from an open pairing window, (b) manual admin-page entry, (c) mDNS `_jochona-beacon._tcp.local.` TXT records (`id=<beacon_id>`, `fp=<sha256 hex>`, `v=1`). Any of these is only a **TOFU hint** — the value that gets durably pinned by the Client is the fingerprint of the cert actually observed on the TLS connection where SPAKE2 confirmation (§2) succeeds, never the out-of-band hint blindly.
- Every subsequent connection: Client's verify callback DER-encodes the presented leaf's complete `X509_PUBKEY`, hashes it with SHA-256, and compares it to the persisted pin. Reject the handshake on any mismatch. **Never** fall back to unpinned/any-cert mode.
- Identity-change hard-block: if the pin ever mismatches, Client must surface "Beacon identity changed — re-pair required" and refuse to connect; it must not auto-trust a new fingerprint. Symmetrically, Beacon invalidates every authorized client whose `authorized_since_beacon_identity_id` doesn't match Beacon's current identity row.

## 2. Pairing ciphersuite: `SPAKE2-P256-SHA256-HKDF-HMAC` (RFC 9382 §6, Table 1)

Chosen specifically because P-256 point ops, SHA-256, HKDF and HMAC are all native OpenSSL 3 public API (`EC_POINT_*` on `NID_X9_62_prime256v1`, `EVP_PKEY_derive` not needed — raw `EC_POINT_mul`/`EC_POINT_add` suffice, `EVP_KDF` "HKDF", `HMAC()`). No Rust-only or opaque format.

- Group: NIST P-256. Roles are **fixed**, not symmetric: **Client = A** (uses `M`), **Beacon = B** (uses `N`).
- `M`/`N` = the exact RFC 9382 §6 P-256 points (SEC1 compressed):
  - `M = 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f`
  - `N = 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49`
- Public values `pA`/`pB` (and `K`) are encoded **SEC1 uncompressed**: `0x04 || X(32B) || Y(32B)` = 65 bytes, then base64-std (padded) in JSON.
- **w (password scalar)**, never the raw short code / never a raw PSK:
  ```
  salt   = "jochona-beacon-pairing-v1" || 0x00 || beacon_id(16 raw UUID bytes) || 0x00 || pairing_id(16 raw UUID bytes)
  dk(40) = scrypt(password = short_code_ascii_bytes, salt = salt, N=32768, r=8, p=1, dkLen=40)   ; OpenSSL 3: EVP_KDF "SCRYPT"
  w      = OS2IP(dk) mod n                       ; n = P-256 order
  w_enc  = w as 32-byte big-endian (= len of p)   ; used inside TT, never sent on the wire
  ```
  40-byte scrypt output follows NIST SP 800-56Ar3 (order bit-length + 64 bits, rounded to bytes) to remove mod-bias.
- **Identities** (transcript-bind the exact TLS channel, defeats relay/MITM even if the code leaks). Reuses the *exact same* SPKI fingerprint function as §1 pinning (`SHA-256(SubjectPublicKeyInfo DER)` — OpenSSL: `X509_get_X509_PUBKEY` + `i2d_X509_PUBKEY` + SHA-256), so there is only one fingerprint routine to implement per side, not two:
  ```
  A = "jochona-client:" || lowercase-hex(SHA-256(SubjectPublicKeyInfo DER of client leaf cert))
  B = "jochona-beacon:" || beacon_id (UUID string) || ":" || lowercase-hex(SHA-256(SubjectPublicKeyInfo DER of beacon leaf cert))
  ```
  Both sides derive these from the certs actually seen on the live mTLS connection — never from client-supplied strings.
- **Transcript** (byte-for-byte RFC 9382 §3.3 — note `len()` is **8-byte little-endian**, not big-endian):
  ```
  TT = len(A)||A || len(B)||B || len(pA)||pA || len(pB)||pB || len(K)||K || len(w_enc)||w_enc
  ```
- **Key schedule** (RFC 9382 §4):
  ```
  Ke || Ka       = SHA-256(TT)                                     ; 16B || 16B
  AAD            = pairing_id (16 raw UUID bytes)
  KcA || KcB     = HKDF-SHA256(salt = 32 zero bytes, ikm = Ka, info = "ConfirmationKeys" || AAD, L = 32)   ; 16B || 16B
  cA             = HMAC-SHA256(KcA, TT)                             ; 32B, full tag, no truncation
  cB             = HMAC-SHA256(KcB, TT)                             ; 32B
  ```
  `Ke` is computed for spec-completeness but **not used further** — post-pairing trust is carried entirely by the mTLS cert pin (§1), so there is no additional session-key handshake to implement.
- Both endpoints MUST validate received points are on-curve and not the identity element before use (RFC 9382 §7).

### Verified test vector (independently computed, both sides must reproduce)

```
beacon_id   = 0f9e1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b
pairing_id  = 7d6c5b4a-3928-4170-9e1d-2c3b4a5f6e7d
short_code  = "12345678"
client_spki_sha256 = aa11bb22cc33dd44ee55ff660011223344556677889900aabbccddeeff001122   (32 bytes / 64 hex chars — SHA-256 of client leaf cert's SubjectPublicKeyInfo DER)
beacon_spki_sha256 = 112233445566778899aabbccddeeff00112233445566778899aabbccddeeff11   (32 bytes / 64 hex chars — SHA-256 of beacon leaf cert's SubjectPublicKeyInfo DER)

A = "jochona-client:aa11bb22cc33dd44ee55ff660011223344556677889900aabbccddeeff001122"   (79 bytes)
B = "jochona-beacon:0f9e1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b:112233445566778899aabbccddeeff00112233445566778899aabbccddeeff11"   (116 bytes)

salt (hex, 59 bytes) = 6a6f63686f6e612d626561636f6e2d70616972696e672d7631000f9e1a2b3c4d4e5f8a9b0c1d2e3f4a5b007d6c5b4a392841709e1d2c3b4a5f6e7d
w_bytes(40, hex) = bda9391c2398efc34b7fd837b29ff890229c924eaf3f419905075b8ed0974bf3a54e72a30f926c7e
w (mod n, hex, 32 bytes) = 6f18c7f9d15dcfb1545265b92235c29dc971049d043ce76c8b100821e77e42ef

x (Client ephemeral scalar, TEST ONLY — must be random in production) =
  3f4e2a1b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071
y (Beacon ephemeral scalar, TEST ONLY) =
  1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809

pA (base64, 65B uncompressed) = BOc2/2XFEtpLIE5dyhXACT5AlMH60h0UpfRHWh7JFhs/5dqCHGwwLQRADdOpKsi3Gvfz46mvwkvQ2yQEUZuumzg=
pB (base64, 65B uncompressed) = BJaiznnzPyov715ehyGpGKRkhQcpK1rnJYVGOSTCiP3QJlsm8aC1eBwg1ApTCF7F963YZOmvw/TI+elyzWxhfaQ=
K  (base64, 65B uncompressed) = BCW9h1yqRmpoJo1FQnb38nhYZJC2FCqroIZeGOgWkU1nN/+EUHXASw85VOsayoq+ARFjgjGF9W0Xened3vdkeSg=
(pA/pB/K are unchanged from the prior draft — they depend only on x, y, w, never on the identity strings.)

TT length = 470 bytes   (= 48 header bytes + 79 + 116 + 65 + 65 + 65 + 32)
Ke  (hex, 16 bytes) = 0efe0bcaa27d29cb7a0b5acf5d31e92e
Ka  (hex, 16 bytes) = da19e806d4c80b3413a25c216872b723
KcA (hex, 16 bytes) = 18c6873cf94381adb01674ae9dcdc482
KcB (hex, 16 bytes) = 6ed1e9c013e0391738b9c7f0cdbefe47

cA (base64, 32 bytes) = W8X+XoTxl8pa/zzlH8f/mAs2mNkrCOVN40W9iH6QC0Q=
cB (base64, 32 bytes) = 8otjQyWycp3XAmvNjy0uCfoHuHXJ82PNJJX6v9wDEkA=
```
Independently recomputed with pure P-256 affine arithmetic against the RFC 9382 M/N constants; `K` cross-checked both directions (`x·(pB−wN) == y·(pA−wM)`) before deriving the rest. Every hex/base64 value's decoded byte length was asserted programmatically (not eyeballed) before publishing — the prior draft's two example fingerprints were 31 bytes instead of 32 and have been corrected; **only `TT`/`Ke`/`Ka`/`KcA`/`KcB`/`cA`/`cB` changed as a result — `pA`/`pB`/`K` are identical to the previous draft.** Use this vector as a unit test fixture on both sides.

## 3. HTTP surface (base path `/jochona/beacon/v1`, JSON, all timestamps RFC 3339 UTC)

### Pairing (reachable during the 60s window without prior authorization)

`GET /pairing` →
```json
{"beacon_id":"<uuid>","beacon_fingerprint":"sha256:<hex>","pairing_id":"<uuid>","expires_at":"...","ciphersuite":"SPAKE2-P256-SHA256-HKDF-HMAC"}
```
404 `{"error":"no_open_pairing_window"}` if none open.

`POST /pairing/{pairing_id}/spake2/start`
```json
{"client_share": "<base64 pA>"}
```
→ 200
```json
{"beacon_share": "<base64 pB>", "beacon_confirm": "<base64 cB>"}
```
Client identity `A` is derived server-side from the verified mTLS peer cert on *this* connection — never sent by the client. Errors: 404 unknown/expired `pairing_id`, 409 wrong phase / already consumed, 400 point not on curve or identity element.

`POST /pairing/{pairing_id}/spake2/confirm`
```json
{"client_confirm": "<base64 cA>"}
```
→ 200
```json
{"status":"authorized","beacon_id":"<uuid>","authorized_client_fingerprint":"sha256:<hex>","authorized_at":"..."}
```
→ 401 `{"status":"failed","reason":"confirmation_mismatch"}` — **one-shot**: any failure immediately invalidates the whole pairing window (no brute-force retries against the short code). → 410 if the 60s window lapsed between calls.

### Hosts & wake (mTLS required, authorized clients only)

`GET /hosts` →
```json
[{"id":"<uuid>","name":"...","host_family":"jochona|sunshine|apollo","observer_permission":"observer_only|broad_permission_warning","state":"online|offline|unknown","last_observed_at":"...|null","enrolled_at":"..."}]
```

`POST /hosts/{id}/wake` — **unchanged from the original contract**: mTLS + required `Idempotency-Key` header, empty body (`{}`), server resolves every packet fact (MAC, broadcast, port, SecureOn) itself.
→ 202
```json
{"wake_id":"<uuid>","host_id":"<uuid>","status":"accepted","idempotency_key":"<key>"}
```
Same `(authorized_client_fingerprint, host_id, Idempotency-Key)` replay returns the identical recorded 202 body, no new packets sent. 400 missing key, 403 unauthorized, 404 unknown host.

`GET /wake/{wake_id}` →
```json
{"wake_id":"...","host_id":"...","accepted_at":"...","sent_at":["...","...","..."] ,"failed_at":null,"error":null}
```
`sent_at` accumulates one timestamp per burst (0/1/3s); `failed_at`/`error` are populated independently — **never** conflated with host online/offline observation.

`GET /events` — authenticated SSE, `data:` = one JSON object per line:
```json
{"type":"wake.accepted|wake.sent|wake.failed|host.observed_online|host.observed_offline|pairing.opened|pairing.closed|host.enrolled|host.revoked","at":"...", "...type-specific fields..."}
```
`host.observed_online/offline` come only from the independently-pinned `/serverinfo` observer loop, never from wake send/accept results.

## 4. Client-side implementation notes
- Client's existing X.509 client cert (from CredentialStore) is presented as the mTLS client cert on every Beacon connection, pairing included.
- All EC/HKDF/HMAC/scrypt primitives above are directly available via OpenSSL 3's public `EC_POINT`, `EVP_KDF` ("HKDF", "SCRYPT"), and `HMAC` APIs — no custom bignum code required beyond wiring calls together.
- Beacon implements this contract in `src/crypto/spake2_pairing.rs` and `src/api/routes/pairing.rs`.
