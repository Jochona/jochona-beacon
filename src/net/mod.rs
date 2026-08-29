//! Minimal outbound HTTP client used only for the two GameStream endpoints
//! Beacon ever calls as a client: the plain-HTTP pairing handshake
//! (`crate::crypto::gamestream_pairing`) and the pinned-HTTPS
//! `/serverinfo` observation poll (`crate::observer::gamestream`). A full
//! HTTP client crate would pull in far more machinery than either single-
//! request-response, `Connection: close` exchange needs.

pub mod http_client;
