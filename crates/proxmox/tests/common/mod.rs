//! A Proxmox VE API served from the recorded answers of real clusters, shared
//! by the test files of this crate.

// Each test file uses its own part of these helpers.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use omnisync_proxmox::{Credentials, ProxmoxClient, ProxmoxCluster, collect};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// API path (what follows `/api2/json`) → HTTP status and body.
pub type Answers = HashMap<String, (u16, Value)>;

pub const API: &str = "/api2/json";
pub const TICKET: &str = "PVE:sync@pve:6740A1B2::dGhlLXRpY2tldA==";

/// The fixtures, from the directory of whichever crate of the workspace
/// includes this module: the command line tests read them too.
pub fn fixture(version: &str) -> Answers {
    // From the directory of this crate, whichever crate includes the file.
    let file = format!("{}/../proxmox/tests/fixtures/{version}/api.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&file).unwrap_or_else(|error| panic!("{file}: {error}"));
    let answers: HashMap<String, Value> = serde_json::from_str(&text).unwrap();
    answers
        .into_iter()
        .map(|(api_path, answer)| {
            let status = u16::try_from(answer["status"].as_u64().unwrap()).unwrap();
            (api_path, (status, answer["body"].clone()))
        })
        .collect()
}

/// How long the mock holds the answer to an API path back.
pub type Delay = Arc<dyn Fn(&str) -> Duration + Send + Sync>;

/// How the mock holds each request back, and where it notes their arrival.
#[derive(Clone, Default)]
pub struct Pace {
    pub delay: Option<Delay>,
    pub arrivals: Option<Arc<Mutex<Vec<Instant>>>>,
}

/// A Proxmox answering `answers` to whoever carries `credential` (header name, value).
pub async fn serve_as(answers: Answers, credential: (&'static str, String), pace: Pace) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{API}/access/ticket")))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data": {"ticket": TICKET, "CSRFPreventionToken": "6740A1B2:csrf", "username": "sync@pve"}}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(move |request: &Request| {
            if let Some(arrivals) = &pace.arrivals {
                arrivals.lock().unwrap().push(Instant::now());
            }
            let (name, value) = &credential;
            if request.headers.get(*name).and_then(|sent| sent.to_str().ok()) != Some(value.as_str()) {
                return ResponseTemplate::new(401).set_body_json(json!({"data": null, "message": "no ticket"}));
            }
            let api_path = request.url.path().strip_prefix(API).unwrap_or_default();
            let answer = match answers.get(api_path) {
                Some((status, body)) => ResponseTemplate::new(*status).set_body_json(body),
                None => ResponseTemplate::new(404).set_body_json(json!({"data": null, "message": "not recorded"})),
            };
            match &pace.delay {
                Some(delay) => answer.set_delay(delay(api_path)),
                None => answer,
            }
        })
        .mount(&server)
        .await;
    server
}

pub async fn serve(answers: Answers) -> MockServer {
    serve_as(answers, ("cookie", format!("PVEAuthCookie={TICKET}")), Pace::default()).await
}

pub fn client(server: &MockServer) -> ProxmoxClient {
    ProxmoxClient::new(&server.uri(), Credentials::password("sync@pve", "the-password")).unwrap()
}

pub async fn collected(answers: Answers) -> ProxmoxCluster {
    let server = serve(answers).await;
    collect(&client(&server)).await.unwrap()
}
