//! A BMC served from the recorded answers of a real one, shared by the test
//! files of this crate and by the end-to-end tests of the command line.

// Each test file uses its own part of these helpers.
#![allow(dead_code)]

use std::collections::BTreeMap;

use omnisync_redfish::{Bmc, Credentials, RedfishClient, collect};
use serde_json::Value;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Request path → HTTP status and body.
pub type Answers = BTreeMap<String, (u16, Value)>;

/// The account the fake BMC knows.
pub const USER: &str = "0perator-never-shown";
pub const PASSWORD: &str = "s3ntinel pass&word/+";
/// `USER:PASSWORD` in base64, computed apart
/// (`printf '%s' '0perator-never-shown:s3ntinel pass&word/+' | base64`).
pub const BASIC: &str = "Basic MHBlcmF0b3ItbmV2ZXItc2hvd246czNudGluZWwgcGFzcyZ3b3JkLys=";

/// The root of the service, the one resource a BMC gives to anybody.
const ROOT: &str = "/redfish/v1/";

/// The recorded answers of one BMC: `tests/fixtures/<family>/api.json`.
pub fn fixture(family: &str) -> Answers {
    // From the directory of this crate, whichever crate includes the file.
    let file = format!("{}/../redfish/tests/fixtures/{family}/api.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&file).unwrap_or_else(|error| panic!("{file}: {error}"));
    let answers: BTreeMap<String, Value> = serde_json::from_str(&text).unwrap();
    answers
        .into_iter()
        .map(|(path, answer)| {
            let status = u16::try_from(answer["status"].as_u64().unwrap()).unwrap();
            (path, (status, answer["body"].clone()))
        })
        .collect()
}

/// A BMC answering `answers` to whoever carries the account, and `401` to the
/// others; a path that was not recorded is `404`. Only `GET` is answered.
pub async fn serve(answers: Answers) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(move |request: &Request| {
            let path = request.url.path();
            let account = request.headers.get("authorization").and_then(|sent| sent.to_str().ok());
            if path != ROOT && account != Some(BASIC) {
                return ResponseTemplate::new(401);
            }
            match answers.get(path) {
                // A body recorded empty (the 308 of an iLO 4) is served empty.
                Some((status, Value::String(body))) => ResponseTemplate::new(*status).set_body_string(body.as_str()),
                Some((status, body)) => ResponseTemplate::new(*status).set_body_json(body),
                None => ResponseTemplate::new(404),
            }
        })
        .mount(&server)
        .await;
    server
}

/// The BMC of the fixture `family`.
pub async fn bmc(family: &str) -> MockServer {
    serve(fixture(family)).await
}

pub fn client(server: &MockServer) -> RedfishClient {
    RedfishClient::new(&server.uri(), Credentials::new(USER, PASSWORD)).unwrap()
}

/// The fixture `family`, collected.
pub async fn collected(family: &str) -> Bmc {
    let server = bmc(family).await;
    collect(&client(&server)).await.unwrap()
}

/// The path of every request the server received, which must all be `GET`.
pub async fn gets(server: &MockServer) -> Vec<String> {
    let requests = server.received_requests().await.unwrap();
    for request in &requests {
        assert_eq!(request.method.to_string(), "GET", "{} {}", request.method, request.url.path());
    }
    requests.iter().map(|request| request.url.path().to_owned()).collect()
}
