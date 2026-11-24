//! A fake firewall over TLS, with a throwaway self-signed certificate.

// Each test file uses a part of it only.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use omnisync_core::network::inventory::{Kind, Secret, Source, Wanted};
use omnisync_fortios::api::FortiosClient;
use rustls::SupportedProtocolVersion;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub const PASSWORD: &str = "pw-forti";

/// (method, path as received, form fields of a POST, had the session cookie)
pub type Seen = (String, String, Vec<(String, String)>, bool);

/// A certificate made for one test, and the key it was signed with (PKCS#8).
pub struct Identity {
    pub certificate: CertificateDer<'static>,
    pub key: Vec<u8>,
}

pub fn identity() -> Identity {
    let generated =
        rcgen::generate_simple_self_signed(vec!["FortiGate".to_owned()]).expect("a self-signed certificate");
    Identity { certificate: generated.cert.der().clone(), key: generated.signing_key.serialize_der() }
}

/// The SHA-256 of a certificate, as the inventory stores it.
pub fn fingerprint_of(certificate: &CertificateDer<'_>) -> String {
    Sha256::digest(certificate.as_ref()).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Presents one certificate whatever the client asks, without checking that the key is its own.
#[derive(Debug)]
struct Always(Arc<CertifiedKey>);

impl ResolvesServerCert for Always {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// What the fake firewall received; it stops listening when dropped.
pub struct Firewall {
    pub port: u16,
    pub fingerprint: String,
    requests: Arc<Mutex<Vec<Seen>>>,
    server: JoinHandle<()>,
}

impl Drop for Firewall {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Firewall {
    /// A firewall with a certificate of its own.
    pub async fn start() -> Self {
        let Identity { certificate, key } = identity();
        Firewall::presenting(certificate, key).await
    }

    /// A firewall that presents `certificate` and signs its handshakes with `key`.
    pub async fn presenting(certificate: CertificateDer<'static>, key: Vec<u8>) -> Self {
        Firewall::speaking(rustls::DEFAULT_VERSIONS, certificate, key).await
    }

    /// The same, speaking these versions of TLS only.
    pub async fn speaking(
        versions: &[&'static SupportedProtocolVersion],
        certificate: CertificateDer<'static>,
        key: Vec<u8>,
    ) -> Self {
        let provider = default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
            .expect("a PKCS#8 key");
        let fingerprint = fingerprint_of(&certificate);
        let presented = Arc::new(CertifiedKey::new(vec![certificate], signing_key));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .expect("versions the provider supports")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Always(presented)));
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
        let port = listener.local_addr().expect("the address of the listener").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let server = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, recorded) = (acceptor.clone(), recorded.clone());
                tokio::spawn(async move {
                    // A handshake the client gives up is not a request.
                    if let Ok(stream) = acceptor.accept(stream).await {
                        serve(stream, recorded).await;
                    }
                });
            }
        });
        Firewall { port, fingerprint, requests, server }
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.requests.lock().expect("the requests").clone()
    }

    /// The paths of the requests received with this method.
    pub fn seen(&self, verb: &str) -> Vec<String> {
        self.requests().into_iter().filter(|(method, ..)| method == verb).map(|(_, target, ..)| target).collect()
    }

    /// The inventory entry of this firewall, expecting the certificate of `fingerprint`.
    pub fn source(&self, fingerprint: &str) -> Source {
        source(self.port, fingerprint)
    }

    pub fn client(&self, fingerprint: &str) -> FortiosClient {
        FortiosClient::for_source(&self.source(fingerprint), Duration::from_secs(5)).expect("a complete source")
    }
}

/// The inventory entry of a firewall listening on a local port.
pub fn source(port: u16, fingerprint: &str) -> Source {
    Source {
        username: "readonly".to_owned(),
        password: Some(Wanted::Held(Secret::new(PASSWORD))),
        tls_fingerprint: Some(fingerprint.to_owned()),
        port: Some(port),
        ..Source::new("fw01.dc1", Kind::Firewall, "fortios", "127.0.0.1")
    }
}

/// A server that does not speak TLS at all: it answers anything in plain HTTP.
pub async fn plain_server() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let port = listener.local_addr().expect("the address of the listener").port();
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut received = [0u8; 4096];
            if stream.read(&mut received).await.is_ok() {
                // The client may already be gone.
                let _ = stream.write_all(b"HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
            }
        }
    });
    (port, server)
}

fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Reads from the connection until `buffer` holds `wanted` bytes; false when it closes first.
async fn fill<S: AsyncRead + Unpin>(stream: &mut S, buffer: &mut Vec<u8>, wanted: usize) -> bool {
    let mut chunk = [0u8; 4096];
    while buffer.len() < wanted {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return false,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
    true
}

/// Answers the HTTP/1.1 requests of one connection as a firewall would: any
/// login opens the session `session=open`, a read without it is refused.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, requests: Arc<Mutex<Vec<Seen>>>) {
    let mut buffer = Vec::new();
    loop {
        let head_end = loop {
            if let Some(at) = position(&buffer, b"\r\n\r\n") {
                break at + 4;
            }
            let wanted = buffer.len() + 1;
            if !fill(&mut stream, &mut buffer, wanted).await {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap_or_default().split(' ');
        let method = request_line.next().unwrap_or_default().to_owned();
        let target = request_line.next().unwrap_or_default().to_owned();
        let (mut length, mut cookie) = (0usize, false);
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    "content-length" => length = value.trim().parse().expect("a body length"),
                    "cookie" => cookie = value.trim() == "session=open",
                    _ => {}
                }
            }
        }
        if !fill(&mut stream, &mut buffer, head_end + length).await {
            return;
        }
        let form = fields(&buffer[head_end..head_end + length]);
        buffer.drain(..head_end + length);
        let login = method == "POST" && target == "/api/v2/authentication";
        requests.lock().expect("the requests").push((method.clone(), target, form, cookie));
        let (status, body) = if method == "GET" && !cookie {
            ("401 Unauthorized", "unauthorized")
        } else if login {
            // What FortiOS 7.4.11 answered a login it took.
            ("200 OK", r#"{"status_code":5,"status_message":"LOGIN_SUCCESS"}"#)
        } else {
            ("200 OK", r#"{"results": []}"#)
        };
        let session = if login { "Set-Cookie: session=open; Path=/\r\n" } else { "" };
        let answer = format!("HTTP/1.1 {status}\r\n{session}Content-Length: {}\r\n\r\n{body}", body.len());
        if stream.write_all(answer.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// The text fields of a JSON object body, in the order of their names.
fn fields(body: &[u8]) -> Vec<(String, String)> {
    let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) else {
        return Vec::new();
    };
    object.into_iter().filter_map(|(name, value)| Some((name, value.as_str()?.to_owned()))).collect()
}
