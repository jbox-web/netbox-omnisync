//! The Redfish client against a local HTTPS server with a self-signed
//! certificate, as a BMC presents the one it was shipped with.

use std::sync::{Arc, Mutex};

use omnisync_redfish::{Call, Credentials, RedfishClient};
use omnisync_tls::Fingerprint;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A BMC answering `{}` to any request over TLS, with a throwaway certificate;
/// its port, the SHA-256 of its certificate, and how many requests reached it.
async fn bmc() -> (u16, String, Arc<Mutex<usize>>) {
    let generated = rcgen::generate_simple_self_signed(vec!["idrac".to_owned()]).expect("a certificate");
    let certificate: CertificateDer<'static> = generated.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()));
    let fingerprint: String = Sha256::digest(certificate.as_ref()).iter().map(|byte| format!("{byte:02x}")).collect();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the default versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("a certificate and its key");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let port = listener.local_addr().expect("an address").port();
    let requests = Arc::new(Mutex::new(0));
    let counted = Arc::clone(&requests);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, counted) = (acceptor.clone(), Arc::clone(&counted));
            tokio::spawn(async move {
                // A handshake the client refuses is not a request.
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = vec![0; 4096];
                if stream.read(&mut buffer).await.unwrap_or(0) > 0 {
                    *counted.lock().unwrap() += 1;
                    let answer = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
                    let _ = stream.write_all(answer.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    (port, fingerprint, requests)
}

fn client(port: u16, fingerprint: &str) -> RedfishClient {
    RedfishClient::builder(&format!("https://127.0.0.1:{port}"), Credentials::new("sync", "pw"))
        .tls_fingerprint(Fingerprint::parse(fingerprint).expect("a fingerprint"))
        .build()
        .expect("a client")
}

#[tokio::test]
async fn the_pinned_certificate_of_a_bmc_is_taken_without_any_authority() {
    let (port, fingerprint, requests) = bmc().await;
    let answer = client(port, &fingerprint).get(&Call::ServiceRoot).await.expect("the pinned one");
    assert_eq!(answer, serde_json::json!({}));
    assert_eq!(*requests.lock().unwrap(), 1);
}

#[tokio::test]
async fn another_certificate_is_refused_before_the_account_leaves() {
    let (port, _, requests) = bmc().await;
    let error = client(port, &"00".repeat(32)).get(&Call::ServiceRoot).await.unwrap_err();
    assert_eq!(error.to_string(), "GET /redfish/v1/: the certificate presented is not the one of tls_fingerprints");
    assert_eq!(*requests.lock().unwrap(), 0);
}
