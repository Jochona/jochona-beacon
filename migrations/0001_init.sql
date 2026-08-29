-- Jochona Beacon initial schema.
-- Applied by src/storage/migrations.rs inside a single transaction.
-- SQLite pragmas (foreign_keys, journal_mode=WAL) are set by the connection
-- opener in src/storage/mod.rs, not here.

-- Singleton row describing this Beacon's stable identity. Enforced to a
-- single row via the CHECK(id = 1) primary key trick.
CREATE TABLE beacon_identity (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    beacon_id           TEXT NOT NULL,              -- UUID, stable for the daemon's lifetime
    cert_der            BLOB NOT NULL,               -- self-signed P-256 leaf certificate (DER)
    key_ciphertext       BLOB NOT NULL,               -- private key, encrypted (see secret_box)
    key_nonce           BLOB NOT NULL,
    created_at          TEXT NOT NULL,               -- RFC3339
    superseded_at        TEXT                          -- set when identity is regenerated (hard-block marker)
);

-- Singleton row describing Beacon's persistent RSA-2048 identity used only
-- for the GameStream observer-pairing handshake against Hosts (see
-- crypto::gamestream_pairing). Distinct from beacon_identity: Hosts pin
-- this certificate server-side, so it must never be regenerated silently.
CREATE TABLE gamestream_identity (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    cert_der            BLOB NOT NULL,
    cert_pem            TEXT NOT NULL,
    key_ciphertext       BLOB NOT NULL,
    key_nonce           BLOB NOT NULL,
    created_at          TEXT NOT NULL
);

-- Every client certificate ever authorized (or revoked) for mTLS.
CREATE TABLE authorized_clients (
    id                              INTEGER PRIMARY KEY AUTOINCREMENT,
    spki_fingerprint                TEXT NOT NULL UNIQUE,  -- lowercase hex sha256(SubjectPublicKeyInfo DER)
    cert_der                        BLOB NOT NULL,
    label                           TEXT,
    authorized_since_beacon_identity TEXT NOT NULL,        -- beacon_id this authorization is bound to
    authorized_at                   TEXT NOT NULL,
    revoked_at                      TEXT
);

CREATE INDEX idx_authorized_clients_fingerprint ON authorized_clients (spki_fingerprint);

-- Ephemeral pairing sessions (60s window). Rows are deleted on completion,
-- failure, or expiry sweep; never long-lived.
CREATE TABLE pairing_sessions (
    id                  TEXT PRIMARY KEY,           -- pairing_id (UUID)
    short_code          TEXT NOT NULL,               -- 8-digit decimal, cleared once consumed
    salt                BLOB NOT NULL,               -- scrypt salt bound to (beacon_id, pairing_id)
    phase               TEXT NOT NULL,               -- 'open' | 'started' | 'confirmed' | 'failed'
    beacon_scalar_y     BLOB,                        -- ephemeral SPAKE2 scalar y, cleared after /confirm
    client_share_pa     BLOB,                        -- pA as received at /start, needed to recompute K at /confirm
    beacon_share_pb      BLOB,                        -- pB, echoed back for idempotent re-fetch
    client_identity_a   TEXT,                        -- "jochona-client:<fingerprint>" bound at /start
    attempts            INTEGER NOT NULL DEFAULT 0,
    opened_at           TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);

-- Registered Hosts (Jochona / Sunshine / Apollo GameStream servers).
CREATE TABLE hosts (
    id                      TEXT PRIMARY KEY,          -- UUID assigned by Beacon at enrollment
    gamestream_uuid         TEXT NOT NULL UNIQUE,       -- Host's own GameStream uniqueid
    name                    TEXT NOT NULL,
    host_family             TEXT NOT NULL,              -- 'jochona' | 'sunshine' | 'apollo'
    observer_permission     TEXT NOT NULL,              -- 'observer_only' | 'broad_permission_warning'
    cert_der                BLOB NOT NULL,               -- pinned GameStream server certificate
    mac_address              TEXT NOT NULL,               -- learned only via a trusted physical-LAN route
    learned_interface       TEXT NOT NULL,
    http_port               INTEGER NOT NULL,
    https_port              INTEGER NOT NULL,
    broadcast_address       TEXT NOT NULL,
    secure_on_ciphertext     BLOB,                        -- encrypted 6-byte SecureOn password, nullable
    secure_on_nonce         BLOB,
    last_state               TEXT NOT NULL DEFAULT 'unknown', -- 'online' | 'offline' | 'unknown'
    last_observed_at         TEXT,
    enrolled_at              TEXT NOT NULL,
    revoked_at               TEXT
);

CREATE INDEX idx_hosts_gamestream_uuid ON hosts (gamestream_uuid);

-- Wake attempts, keyed by idempotency for safe client retries.
CREATE TABLE wake_events (
    id                          TEXT PRIMARY KEY,      -- wake_id (UUID)
    host_id                     TEXT NOT NULL REFERENCES hosts(id),
    requested_by_fingerprint     TEXT NOT NULL,
    idempotency_key              TEXT NOT NULL,
    accepted_at                  TEXT NOT NULL,
    sent_at_json                 TEXT NOT NULL DEFAULT '[]',  -- JSON array of RFC3339 burst timestamps
    failed_at                    TEXT,
    error                       TEXT
);

CREATE UNIQUE INDEX idx_wake_events_idempotency
    ON wake_events (requested_by_fingerprint, host_id, idempotency_key);

-- Independent GameStream-observation history (never conflated with wake_events).
CREATE TABLE host_observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         TEXT NOT NULL REFERENCES hosts(id),
    observed_at     TEXT NOT NULL,
    online          INTEGER NOT NULL,  -- 0/1
    source          TEXT NOT NULL      -- 'serverinfo_poll' | 'enrollment'
);

CREATE INDEX idx_host_observations_host_time ON host_observations (host_id, observed_at);

-- Structured audit/event log, source of truth for the SSE feed and for
-- retention pruning (30-day default, configurable).
CREATE TABLE beacon_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_beacon_events_created_at ON beacon_events (created_at);
