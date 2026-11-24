//! The FortiOS API client against a local HTTPS server with a self-signed certificate.

mod common;

use std::time::Duration;

use common::{Firewall, Identity, PASSWORD, fingerprint_of, identity, plain_server, source};
use omnisync_fortios::api::{FortiosClient, STATUS};
use rustls::version::{TLS12, TLS13};

#[tokio::test]
async fn logs_in_reads_and_logs_out_with_the_pinned_certificate() {
    let firewall = Firewall::start().await;
    let client = firewall.client(&firewall.fingerprint);
    client.login().await.expect("the pinned certificate is presented");
    let body = client.run(STATUS).await.expect("the read is answered");
    client.logout().await;
    assert_eq!(body, r#"{"results": []}"#);
    let form = vec![
        ("password".to_owned(), PASSWORD.to_owned()),
        ("secretkey".to_owned(), PASSWORD.to_owned()),
        ("username".to_owned(), "readonly".to_owned()),
    ];
    assert_eq!(
        firewall.requests(),
        [
            ("POST".to_owned(), "/api/v2/authentication".to_owned(), form, false),
            ("GET".to_owned(), "/api/v2/monitor/system/status".to_owned(), vec![], true),
            ("POST".to_owned(), "/logout".to_owned(), vec![], true),
        ]
    );
}

#[tokio::test]
async fn fingerprint_as_openssl_prints_it_pins_the_same_certificate() {
    let firewall = Firewall::start().await;
    let pairs: Vec<String> =
        firewall.fingerprint.as_bytes().chunks(2).map(|pair| String::from_utf8_lossy(pair).to_uppercase()).collect();
    let client = firewall.client(&pairs.join(":"));
    client.login().await.expect("the pinned certificate is presented");
    assert_eq!(firewall.seen("POST"), ["/api/v2/authentication"]);
}

#[tokio::test]
async fn another_certificate_is_refused_before_the_credentials_leave() {
    let firewall = Firewall::start().await;
    let error = firewall.client(&"00".repeat(32)).login().await.expect_err("another certificate");
    assert_eq!(
        error.0,
        format!("API of 127.0.0.1:{}: the certificate presented is not the one of tls_fingerprint", firewall.port)
    );
    assert_eq!(firewall.requests(), []);
}

#[tokio::test]
async fn certificate_of_another_firewall_is_refused_on_a_read_too() {
    // No login: every connection is checked, not the first one only.
    let firewall = Firewall::start().await;
    let other = fingerprint_of(&identity().certificate);
    let error = firewall.client(&other).run(STATUS).await.expect_err("another certificate");
    assert_eq!(error.0, format!("API of 127.0.0.1:{}: monitor/system/status: SSLError", firewall.port));
    assert_eq!(firewall.requests(), []);
}

#[tokio::test]
async fn pinned_certificate_presented_without_its_key_is_refused() {
    // A certificate is public, anyone can present it: the pin does not replace
    // the proof that the server holds its key.
    let (genuine, forger) = (identity(), identity());
    let firewall = Firewall::presenting(genuine.certificate.clone(), forger.key).await;
    let error = firewall.client(&fingerprint_of(&genuine.certificate)).login().await.expect_err("a forged handshake");
    assert_eq!(error.0, format!("API of 127.0.0.1:{}: login failed: SSLError", firewall.port));
    assert_eq!(firewall.requests(), []);
}

#[tokio::test]
async fn each_version_of_tls_reads_through_the_pinned_certificate() {
    for version in [&TLS12, &TLS13] {
        let Identity { certificate, key } = identity();
        let firewall = Firewall::speaking(&[version], certificate, key).await;
        let mut client = firewall.client(&firewall.fingerprint);
        let body = client.session(async |client| client.run(STATUS).await).await;
        assert_eq!(body.expect("the read is answered"), r#"{"results": []}"#, "{version:?}");
        assert_eq!(firewall.seen("GET"), ["/api/v2/monitor/system/status"]);
    }
}

#[tokio::test]
async fn each_version_of_tls_refuses_a_certificate_presented_without_its_key() {
    for version in [&TLS12, &TLS13] {
        let (genuine, forger) = (identity(), identity());
        let firewall = Firewall::speaking(&[version], genuine.certificate.clone(), forger.key).await;
        let client = firewall.client(&fingerprint_of(&genuine.certificate));
        let error = client.login().await.expect_err("a forged handshake");
        assert_eq!(error.0, format!("API of 127.0.0.1:{}: login failed: SSLError", firewall.port), "{version:?}");
        assert_eq!(firewall.requests(), []);
    }
}

#[tokio::test]
async fn tls_failure_that_is_not_the_fingerprint_is_not_blamed_on_it() {
    // A server that does not speak TLS at all.
    let (port, server) = plain_server().await;
    let client =
        FortiosClient::for_source(&source(port, &"ab".repeat(32)), Duration::from_secs(5)).expect("a complete source");
    let error = client.login().await.expect_err("no TLS");
    server.abort();
    assert!(!error.0.contains("tls_fingerprint"), "{error}");
    assert_eq!(error.0, format!("API of 127.0.0.1:{port}: login failed: SSLError"));
}
