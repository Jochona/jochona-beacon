use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::tls::PinnedCertVerifier;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

fn build_request(host: &str, path_and_query: &str) -> Vec<u8> {
    format!("GET {path_and_query} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: jochona-beacon\r\nAccept: */*\r\nConnection: close\r\n\r\n").into_bytes()
}

/// Parses a minimal HTTP/1.1 response: status line + headers (only
/// `Content-Length` is honored) + body. GameStream endpoints are simple
/// enough that chunked transfer-encoding is not something we need to
/// support; if a server ever sends it, `bail!` here rather than
/// mis-parsing.
fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let header_end = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response: no header terminator"))?;
    let header_text = std::str::from_utf8(&raw[..header_end])
        .context("HTTP response headers are not valid UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow!("empty HTTP response"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("malformed HTTP status line: {status_line:?}"))?
        .parse()
        .with_context(|| format!("malformed HTTP status code in {status_line:?}"))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse().ok();
            } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }

    let body_start = header_end + 4;
    if chunked {
        bail!(
            "chunked transfer-encoding is not supported by Beacon's minimal GameStream HTTP client"
        );
    }
    let body = match content_length {
        Some(len) if body_start + len <= raw.len() => raw[body_start..body_start + len].to_vec(),
        _ => raw[body_start..].to_vec(),
    };
    Ok(HttpResponse { status, body })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn read_to_close(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    timeout(REQUEST_TIMEOUT, stream.read_to_end(&mut buf))
        .await
        .context("timed out reading HTTP response")??;
    Ok(buf)
}

/// Plain-HTTP GET — used only for the unencrypted GameStream pairing
/// handshake (`crate::crypto::gamestream_pairing`), which is unencrypted by
/// the upstream protocol's own design (the AES key derived from the PIN is
/// what protects it, not TLS).
pub async fn get_http(host: &str, port: u16, path_and_query: &str) -> Result<HttpResponse> {
    let addr = format!("{host}:{port}");
    let mut stream = timeout(REQUEST_TIMEOUT, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("connecting to {addr}"))??;
    stream.set_nodelay(true).ok();
    let request = build_request(host, path_and_query);
    timeout(REQUEST_TIMEOUT, stream.write_all(&request))
        .await
        .context("writing HTTP request")??;
    let raw = read_to_close(&mut stream).await?;
    parse_response(&raw)
}

/// Pinned-HTTPS GET — used for the authenticated `/serverinfo` observation
/// poll. No CA chain is trusted; the connection is refused unless the
/// presented leaf certificate's SPKI matches `expected_spki_sha256`
/// exactly (see `crate::tls::PinnedCertVerifier`).
pub async fn get_https_pinned(
    host: &str,
    port: u16,
    path_and_query: &str,
    expected_spki_sha256: [u8; 32],
) -> Result<HttpResponse> {
    let addr = format!("{host}:{port}");
    let tcp = timeout(REQUEST_TIMEOUT, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("connecting to {addr}"))??;
    tcp.set_nodelay(true).ok();

    let verifier = Arc::new(PinnedCertVerifier::new(expected_spki_sha256));
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    // The pin — not the hostname — is what we trust; any syntactically
    // valid SNI/DNS name works since `PinnedCertVerifier` ignores it.
    let server_name = ServerName::try_from("jochona-host.invalid".to_string())
        .expect("static hostname is a valid DNS name");
    let mut tls_stream = timeout(REQUEST_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .with_context(|| format!("TLS handshake with {addr}"))??;

    let request = build_request(host, path_and_query);
    timeout(REQUEST_TIMEOUT, tls_stream.write_all(&request))
        .await
        .context("writing HTTPS request")??;
    let raw = read_to_close(&mut tls_stream).await?;
    parse_response(&raw)
}
