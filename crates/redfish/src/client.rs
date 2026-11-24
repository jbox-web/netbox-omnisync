//! A read-only client of the Redfish service of one BMC.
//!
//! The source only reads a BMC: this client sends `GET` requests, for a closed
//! list of resources ([`Call`]), and has no way to send anything else. It
//! never retries and never follows a redirect: the one redirect a BMC is known
//! to answer (iLO 4, `308` on a path written without its final `/`) is asked
//! again by the client itself, on the same BMC.
//!
//! One client is one BMC. The calls of a collection are made one after the
//! other, on one kept-alive connection: an iDRAC 7 takes two to four seconds
//! to answer and logs every connection.

use omnisync_tls::{Fingerprint, is_pin_mismatch, pinned_tls};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use reqwest::{Certificate, StatusCode};
use serde_json::Value;
use url::Url;

/// Time a request may take before it fails. Generous: the BMC of an old
/// server answers in seconds, and a run reads each one once a day.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// The root of the Redfish service, with its final `/`: what every BMC answers.
const ROOT: &str = "/redfish/v1/";

/// The systems of a BMC, as the specification writes the path. iLO 4 answers
/// `308` to it and wants the final `/`.
const SYSTEMS: &str = "/redfish/v1/Systems";

/// What a redirected path must start with to be one of a system or of a manager.
const SYSTEMS_PREFIX: &str = "/redfish/v1/Systems/";
const MANAGERS_PREFIX: &str = "/redfish/v1/Managers/";

/// The collection of the Ethernet interfaces of a system, under its path.
const ETHERNET_INTERFACES: &str = "EthernetInterfaces";

/// Characters of an error body kept in the message.
const ERROR_BODY_LIMIT: usize = 300;

/// What replaces a secret in a message.
const MASK: &str = "***";

/// One read of the closed list. A path a BMC gave (a member of a collection, a
/// link) is checked against the shape of its call before anything is sent: a
/// BMC cannot make the client ask for something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `/redfish/v1/`: the service, and its Redfish version.
    ServiceRoot,
    /// `/redfish/v1/Systems`: the systems the BMC manages.
    Systems,
    /// `/redfish/v1/Systems/<id>`: one system, as its collection names it.
    System(String),
    /// `/redfish/v1/Managers/<id>`: the BMC itself, as its system links to it.
    Manager(String),
    /// `/redfish/v1/Systems/<id>/EthernetInterfaces`: the cards of a system.
    EthernetInterfaces(String),
    /// `/redfish/v1/Systems/<id>/EthernetInterfaces/<card>`: one card.
    EthernetInterface(String),
}

/// Whether `segment` is one name of a path: letters, digits, `.`, `_` and `-`,
/// and not a step out of where it stands.
fn is_name(segment: &str) -> bool {
    let allowed = |character: char| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-');
    !segment.is_empty() && segment.chars().all(allowed) && !matches!(segment, "." | "..")
}

/// The names of `path` under `prefix`, without the final `/` iLO writes.
fn names<'p>(path: &'p str, prefix: &str) -> Option<Vec<&'p str>> {
    let rest = path.strip_prefix(prefix)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let names: Vec<&str> = rest.split('/').collect();
    names.iter().all(|name| is_name(name)).then_some(names)
}

impl Call {
    /// The path asked for; `None` when it is not one this call may read.
    pub fn path(&self) -> Option<&str> {
        let shaped = |path: &str, prefix: &str, shape: &dyn Fn(&[&str]) -> bool| {
            names(path, prefix).is_some_and(|names| shape(&names))
        };
        let one = |names: &[&str]| names.len() == 1;
        match self {
            Call::ServiceRoot => Some(ROOT),
            Call::Systems => Some(SYSTEMS),
            Call::System(path) => shaped(path, SYSTEMS_PREFIX, &one).then_some(path),
            Call::Manager(path) => shaped(path, MANAGERS_PREFIX, &one).then_some(path),
            Call::EthernetInterfaces(path) => {
                let cards = |names: &[&str]| names.len() == 2 && names[1] == ETHERNET_INTERFACES;
                shaped(path, SYSTEMS_PREFIX, &cards).then_some(path)
            }
            Call::EthernetInterface(path) => {
                let card = |names: &[&str]| names.len() == 3 && names[1] == ETHERNET_INTERFACES;
                shaped(path, SYSTEMS_PREFIX, &card).then_some(path)
            }
        }
    }

    /// What the call is, to say which one was refused without repeating a
    /// path that is not to be trusted.
    fn name(&self) -> &'static str {
        match self {
            Call::ServiceRoot => "the service root",
            Call::Systems => "the systems",
            Call::System(_) => "a system",
            Call::Manager(_) => "a manager",
            Call::EthernetInterfaces(_) => "the Ethernet interfaces of a system",
            Call::EthernetInterface(_) => "an Ethernet interface of a system",
        }
    }
}

/// The account a BMC is read with: HTTP Basic, sent with every request.
#[derive(Clone)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: &str, password: &str) -> Self {
        Credentials { username: username.to_owned(), password: password.to_owned() }
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Who logs in, never with what.
        formatter.debug_struct("Credentials").field("username", &self.username).field("password", &MASK).finish()
    }
}

/// Why a call to a BMC failed. No message carries the password, nor the user
/// it belongs to, nor the header that holds both.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The settings cannot make a client, or the call is not of the closed list: nothing was sent.
    #[error("Redfish client: {0}")]
    Config(String),
    /// The BMC answered, with an HTTP status that is not a success.
    #[error("GET {path} answered {status}: {message}")]
    Status { path: String, status: u16, message: String },
    /// No answer: refused, timed out, cut.
    #[error("GET {path}: {reason}")]
    Transport { path: String, reason: String },
    /// A successful answer that is not a JSON object.
    #[error("GET {path}: unexpected answer: {reason}")]
    Decode { path: String, reason: String },
}

/// Settings of a [`RedfishClient`].
pub struct RedfishClientBuilder {
    url: String,
    credentials: Credentials,
    timeout: Duration,
    validate_certs: bool,
    ca_file: Option<PathBuf>,
    fingerprint: Option<Fingerprint>,
}

impl RedfishClientBuilder {
    /// The SHA-256 of the one certificate the BMC may present: it replaces the
    /// authorities, `validate_certs` and `ca_file`. A BMC carries the
    /// self-signed certificate it was shipped with: pinned, its account goes
    /// to that BMC and no other, where `validate_certs = false` would send it
    /// to whatever answers.
    pub fn tls_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.fingerprint = Some(fingerprint);
        self
    }

    /// Time a request may take, 60 s by default.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether the certificate of the BMC is validated: yes by default. A BMC
    /// most often carries the self-signed certificate it was shipped with.
    pub fn validate_certs(mut self, validate: bool) -> Self {
        self.validate_certs = validate;
        self
    }

    /// A PEM file of certificate authorities trusted on top of the system ones.
    pub fn ca_file(mut self, path: impl AsRef<Path>) -> Self {
        self.ca_file = Some(path.as_ref().to_owned());
        self
    }

    /// Checks the settings and makes the client; nothing is sent.
    pub fn build(self) -> Result<RedfishClient, ClientError> {
        let base = base_url(&self.url)?;
        let Credentials { username, password } = self.credentials;
        let token = base64(format!("{username}:{password}").as_bytes());
        // The value is not shown: it is the secret.
        let mut authorization = HeaderValue::from_str(&format!("Basic {token}"))
            .map_err(|_| ClientError::Config("the account cannot be sent as an HTTP header".to_owned()))?;
        authorization.set_sensitive(true);
        // A redirect is never followed: it could send the account to another
        // host. No idle connection is kept: an iLO 4 closes its own after each
        // answer, and a request sent on it is lost ("connection closed before
        // message completed", seen on real ones).
        // Never the proxy of the environment: the Basic account would leave for another host.
        let mut http = reqwest::Client::builder()
            .no_proxy()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0);
        if !self.validate_certs {
            http = http.tls_danger_accept_invalid_certs(true);
        }
        if let Some(path) = &self.ca_file {
            let unusable = |reason: String| ClientError::Config(format!("CA file {}: {reason}", path.display()));
            let pem = std::fs::read(path).map_err(|error| unusable(error.to_string()))?;
            let certificates = Certificate::from_pem_bundle(&pem).map_err(|error| unusable(chain(&error)))?;
            if certificates.is_empty() {
                return Err(unusable("no certificate found".to_owned()));
            }
            http = http.tls_certs_merge(certificates);
        }
        if let Some(fingerprint) = self.fingerprint {
            let pinned = pinned_tls(fingerprint).map_err(|error| ClientError::Config(format!("TLS: {error}")))?;
            http = http.tls_backend_preconfigured(pinned).https_only(true);
        }
        let http = http.build().map_err(|error| ClientError::Config(format!("HTTP client: {}", chain(&error))))?;
        // Each secret as it is, and as a JSON string writes it (a BMC may quote the
        // account in an error); the longest first, so that a secret another one
        // holds does not cut it before it is masked whole.
        let mut secrets: Vec<String> = [token, password, username]
            .into_iter()
            .flat_map(|secret| {
                let quoted = serde_json::to_string(&secret).unwrap_or_default();
                let escaped = quoted.get(1..quoted.len().saturating_sub(1)).unwrap_or_default().to_owned();
                [secret, escaped]
            })
            .filter(|secret| !secret.is_empty())
            .collect();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        Ok(RedfishClient { http, base, authorization, secrets, timeout: self.timeout })
    }
}

/// `url` as a message may show it: what stands before an `@` may be a user and
/// its password, and is masked, whether or not the rest can be read as a URL.
fn shown(url: &str) -> String {
    let Some(at) = url.rfind('@') else {
        return url.to_owned();
    };
    let start = url.find("://").map(|scheme| scheme + 3).filter(|start| *start <= at).unwrap_or(0);
    format!("{}{MASK}{}", &url[..start], &url[at..])
}

/// The URL of a BMC, checked: a scheme, a host, and nothing else.
fn base_url(url: &str) -> Result<Url, ClientError> {
    let refused = |reason: &str| ClientError::Config(format!("BMC URL {:?}: {reason}", shown(url)));
    let base = Url::parse(url).map_err(|error| refused(&error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(refused("not an http or https URL"));
    }
    // The account is given apart: a user or a password in the URL would be
    // sent as well, and printed with the URL.
    if !base.username().is_empty() || base.password().is_some() {
        return Err(refused("credentials in the URL are refused"));
    }
    // The paths are the ones of the closed list, from the root of the host.
    if !matches!(base.path(), "" | "/") || base.query().is_some() || base.fragment().is_some() {
        return Err(refused("a path, a query or a fragment is refused"));
    }
    Ok(base)
}

/// An error with its causes: reqwest keeps the reason (refused, timed out) in the source.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Base64 (RFC 4648, with padding), for the `Authorization: Basic` header.
/// Written here rather than taken from a crate: it is twenty lines, and the
/// encoded account must also be known to keep it out of the messages.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let sextets = [
            group[0] >> 2,
            (group[0] & 0b11) << 4 | group[1] >> 4,
            (group[1] & 0b1111) << 2 | group[2] >> 6,
            group[2] & 0b11_1111,
        ];
        for (position, sextet) in sextets.into_iter().enumerate() {
            // One byte gives two characters, two bytes three: the rest is padding.
            let padding = position > chunk.len();
            encoded.push(if padding { '=' } else { char::from(ALPHABET[usize::from(sextet)]) });
        }
    }
    encoded
}

/// What an error answer says: the start of its body, or the name of its status.
fn said(status: StatusCode, answer: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(answer).trim().chars().take(ERROR_BODY_LIMIT).collect();
    if text.is_empty() { status.canonical_reason().unwrap_or("no message").to_owned() } else { text }
}

pub struct RedfishClient {
    http: reqwest::Client,
    /// Scheme, host and port of the BMC, without path.
    base: Url,
    /// The whole `Authorization` value.
    authorization: HeaderValue,
    /// The encoded account, the password and the user, kept to be scrubbed
    /// from the error messages only; the longest secret first.
    secrets: Vec<String>,
    timeout: Duration,
}

impl std::fmt::Debug for RedfishClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the account.
        formatter.debug_struct("RedfishClient").field("bmc", &self.base.as_str()).finish_non_exhaustive()
    }
}

impl RedfishClient {
    /// A client of the BMC at `url` (e.g. `https://drac-pve01.example.net`).
    pub fn builder(url: &str, credentials: Credentials) -> RedfishClientBuilder {
        RedfishClientBuilder {
            url: url.to_owned(),
            credentials,
            timeout: DEFAULT_TIMEOUT,
            validate_certs: true,
            ca_file: None,
            fingerprint: None,
        }
    }

    /// A client with the default settings.
    pub fn new(url: &str, credentials: Credentials) -> Result<Self, ClientError> {
        RedfishClient::builder(url, credentials).build()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Reads one resource of the closed list: `GET`, and the JSON object answered.
    ///
    /// A `308` on a path without final `/` is asked again with it, once, on
    /// the same BMC: the `Location` of the answer is never read, so that
    /// nothing a BMC says can send the account elsewhere.
    pub async fn get(&self, call: &Call) -> Result<Value, ClientError> {
        let Some(path) = call.path() else {
            // The path is not shown: it is not one the client would ask for.
            return Err(ClientError::Config(format!("{} is not at a path of the closed list", call.name())));
        };
        let (status, answer) = self.send(path).await?;
        let (path, status, answer) = if status == StatusCode::PERMANENT_REDIRECT && !path.ends_with('/') {
            let with_slash = format!("{path}/");
            let (status, answer) = self.send(&with_slash).await?;
            (with_slash, status, answer)
        } else {
            (path.to_owned(), status, answer)
        };
        if !status.is_success() {
            let message = self.scrub(&said(status, &answer));
            return Err(ClientError::Status { path, status: status.as_u16(), message });
        }
        match serde_json::from_slice::<Value>(&answer) {
            Ok(value) if value.is_object() => Ok(value),
            Ok(_) => Err(ClientError::Decode { path, reason: "not a JSON object".to_owned() }),
            Err(error) => Err(ClientError::Decode { path, reason: self.scrub(&error.to_string()) }),
        }
    }

    /// A message without the account, whatever put it there (the BMC, a proxy, a library).
    fn scrub(&self, message: &str) -> String {
        let mut message = message.to_owned();
        for secret in self.secrets.iter().filter(|secret| !secret.is_empty()) {
            message = message.replace(secret.as_str(), MASK);
        }
        message
    }

    /// Sends one `GET` to the BMC and gives the status and the body answered.
    /// Private, and the only place a request is made: the client cannot write.
    async fn send(&self, path: &str) -> Result<(StatusCode, Vec<u8>), ClientError> {
        let broken = |reason: String| ClientError::Transport { path: path.to_owned(), reason: self.scrub(&reason) };
        let mut url = self.base.clone();
        url.set_path(path);
        let request = self.http.get(url).header(ACCEPT, "application/json").header(AUTHORIZATION, &self.authorization);
        // The URL is left out of the reason: the path is already in the message.
        let lost = |error: reqwest::Error| {
            if is_pin_mismatch(&error) {
                return broken("the certificate presented is not the one of tls_fingerprints".to_owned());
            }
            broken(chain(&error.without_url()))
        };
        let response = request.send().await.map_err(lost)?;
        let status = response.status();
        Ok((status, response.bytes().await.map_err(lost)?.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    /// An account that no failure may show.
    const SENTINEL_USER: &str = "0perator-never-shown";
    const SENTINEL_PASSWORD: &str = "s3ntinel pass&word/+";
    /// `0perator-never-shown:s3ntinel pass&word/+` in base64, computed apart
    /// (`printf '%s' '0perator-never-shown:s3ntinel pass&word/+' | base64`).
    const SENTINEL_BASIC: &str = "MHBlcmF0b3ItbmV2ZXItc2hvd246czNudGluZWwgcGFzcyZ3b3JkLys=";

    fn client(server: &MockServer) -> RedfishClient {
        RedfishClient::new(&server.uri(), Credentials::new(SENTINEL_USER, SENTINEL_PASSWORD)).unwrap()
    }

    /// (method, path) of every request the mock received.
    async fn received(server: &MockServer) -> Vec<(String, String)> {
        let requests = server.received_requests().await.unwrap();
        requests.iter().map(|request| (request.method.to_string(), request.url.path().to_owned())).collect()
    }

    fn gets<const N: usize>(paths: [&str; N]) -> Vec<(String, String)> {
        paths.iter().map(|path| ("GET".to_owned(), (*path).to_owned())).collect()
    }

    /// Every way an error can be printed.
    fn printed(error: &ClientError) -> String {
        format!("{error} {error:?}")
    }

    fn assert_no_secret(text: &str) {
        for secret in [SENTINEL_USER, SENTINEL_PASSWORD, SENTINEL_BASIC, "0perator", "s3ntinel"] {
            assert!(!text.contains(secret), "{secret:?} in {text}");
        }
    }

    #[test]
    fn base64_is_the_one_of_rfc_4648() {
        // RFC 4648, section 10: the test vectors.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // RFC 7617, section 2: the account `Aladdin` with the password `open sesame`.
        assert_eq!(base64(b"Aladdin:open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        // Bytes that give `+` and `/`.
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn the_closed_list_is_six_reads() {
        let system = "/redfish/v1/Systems/System.Embedded.1";
        assert_eq!(Call::ServiceRoot.path(), Some("/redfish/v1/"));
        assert_eq!(Call::Systems.path(), Some("/redfish/v1/Systems"));
        assert_eq!(Call::System(system.to_owned()).path(), Some(system));
        // iLO 4 writes its paths with a final `/`.
        assert_eq!(Call::System("/redfish/v1/Systems/1/".to_owned()).path(), Some("/redfish/v1/Systems/1/"));
        let manager = "/redfish/v1/Managers/iDRAC.Embedded.1";
        assert_eq!(Call::Manager(manager.to_owned()).path(), Some(manager));
        let cards = format!("{system}/EthernetInterfaces");
        assert_eq!(Call::EthernetInterfaces(cards.clone()).path(), Some(cards.as_str()));
        let card = format!("{cards}/NIC.Integrated.1-3-1");
        assert_eq!(Call::EthernetInterface(card.clone()).path(), Some(card.as_str()));
    }

    #[test]
    fn a_path_a_bmc_gives_is_only_asked_when_it_has_the_shape_of_its_call() {
        let refused = |call: Call| assert_eq!(call.path(), None, "{call:?}");
        // An action, a sub-resource, another collection.
        refused(Call::System("/redfish/v1/Systems/1/Actions/ComputerSystem.Reset".to_owned()));
        refused(Call::System("/redfish/v1/Systems/1/Bios".to_owned()));
        refused(Call::System("/redfish/v1/Managers/1".to_owned()));
        refused(Call::System("/redfish/v1/Systems/".to_owned()));
        refused(Call::Manager("/redfish/v1/Systems/1".to_owned()));
        refused(Call::Manager("/redfish/v1/Managers/1/EthernetInterfaces".to_owned()));
        refused(Call::EthernetInterfaces("/redfish/v1/Systems/1/Storage".to_owned()));
        refused(Call::EthernetInterfaces("/redfish/v1/Systems/1".to_owned()));
        refused(Call::EthernetInterface("/redfish/v1/Systems/1/Storage/NIC.1".to_owned()));
        refused(Call::EthernetInterface("/redfish/v1/Systems/1/EthernetInterfaces".to_owned()));
        // A step out, a query, a fragment, an encoded character, another host.
        refused(Call::System("/redfish/v1/Systems/../AccountService".to_owned()));
        refused(Call::System("/redfish/v1/Systems/1?$expand=*".to_owned()));
        refused(Call::System("/redfish/v1/Systems/1#x".to_owned()));
        refused(Call::System("/redfish/v1/Systems/%2e%2e".to_owned()));
        refused(Call::System("https://198.51.100.9/redfish/v1/Systems/1".to_owned()));
        refused(Call::System("//198.51.100.9/redfish/v1/Systems/1".to_owned()));
        refused(Call::System(String::new()));
    }

    #[tokio::test]
    async fn a_path_outside_the_closed_list_is_refused_before_anything_is_sent() {
        let server = MockServer::start().await;
        let redfish = client(&server);
        let error = redfish
            .get(&Call::System("/redfish/v1/Systems/1/Actions/ComputerSystem.Reset".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Redfish client: a system is not at a path of the closed list");
        let error = redfish.get(&Call::Manager("/redfish/v1/AccountService/Accounts/2".to_owned())).await.unwrap_err();
        assert_eq!(error.to_string(), "Redfish client: a manager is not at a path of the closed list");
        assert_eq!(received(&server).await, []);
    }

    #[tokio::test]
    async fn every_call_is_a_get_carrying_the_basic_account() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("authorization", format!("Basic {SENTINEL_BASIC}")))
            .and(header("accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Id": "x"})))
            .mount(&server)
            .await;
        let redfish = client(&server);
        let system = "/redfish/v1/Systems/System.Embedded.1";
        let calls = [
            Call::ServiceRoot,
            Call::Systems,
            Call::System(system.to_owned()),
            Call::Manager("/redfish/v1/Managers/iDRAC.Embedded.1".to_owned()),
            Call::EthernetInterfaces(format!("{system}/EthernetInterfaces")),
            Call::EthernetInterface(format!("{system}/EthernetInterfaces/NIC.Slot.2-1-1")),
        ];
        for call in &calls {
            assert_eq!(redfish.get(call).await, Ok(json!({"Id": "x"})), "{call:?}");
        }
        assert_eq!(
            received(&server).await,
            gets([
                "/redfish/v1/",
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/System.Embedded.1",
                "/redfish/v1/Managers/iDRAC.Embedded.1",
                "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces",
                "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Slot.2-1-1",
            ])
        );
    }

    #[tokio::test]
    async fn a_308_is_asked_again_with_the_final_slash_on_the_same_bmc() {
        // What iLO 4 answers to `/redfish/v1/Systems`: 308 and an empty body.
        let server = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems"))
            // A `Location` towards another host: it must never be followed.
            .respond_with(
                ResponseTemplate::new(308)
                    .insert_header("location", format!("{}/redfish/v1/Systems/", elsewhere.uri())),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Members": []})))
            .mount(&server)
            .await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&elsewhere).await;
        assert_eq!(client(&server).get(&Call::Systems).await, Ok(json!({"Members": []})));
        assert_eq!(received(&server).await, gets(["/redfish/v1/Systems", "/redfish/v1/Systems/"]));
        // The account went to the BMC and nowhere else.
        assert_eq!(received(&elsewhere).await, []);
    }

    #[tokio::test]
    async fn a_308_is_followed_once_and_no_other_redirect_ever_is() {
        let server = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        let away = format!("{}/redfish/v1/", elsewhere.uri());
        // A path that already ends with `/` has no other writing to try.
        Mock::given(method("GET"))
            .and(path("/redfish/v1/"))
            .respond_with(ResponseTemplate::new(308).insert_header("location", away.as_str()))
            .mount(&server)
            .await;
        // A BMC that redirects in a loop is asked twice, not for ever.
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems"))
            .respond_with(ResponseTemplate::new(308))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems/"))
            .respond_with(ResponseTemplate::new(308))
            .mount(&server)
            .await;
        // Any other redirect is an error as it stands.
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Managers/1"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", away.as_str()))
            .mount(&server)
            .await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&elsewhere).await;
        let redfish = client(&server);
        let error = redfish.get(&Call::ServiceRoot).await.unwrap_err();
        assert_eq!(error.to_string(), "GET /redfish/v1/ answered 308: Permanent Redirect");
        let error = redfish.get(&Call::Systems).await.unwrap_err();
        assert_eq!(error.to_string(), "GET /redfish/v1/Systems/ answered 308: Permanent Redirect");
        let error = redfish.get(&Call::Manager("/redfish/v1/Managers/1".to_owned())).await.unwrap_err();
        assert_eq!(error.to_string(), "GET /redfish/v1/Managers/1 answered 302: Found");
        assert_eq!(
            received(&server).await,
            gets(["/redfish/v1/", "/redfish/v1/Systems", "/redfish/v1/Systems/", "/redfish/v1/Managers/1"])
        );
        assert_eq!(received(&elsewhere).await, []);
    }

    /// An answer repeating everything the request carried, as a verbose proxy would.
    fn echo(status: u16) -> impl Fn(&Request) -> ResponseTemplate + Send + Sync + 'static {
        move |request: &Request| {
            let headers: Vec<String> =
                request.headers.iter().map(|(name, value)| format!("{name}: {}", value.to_str().unwrap())).collect();
            ResponseTemplate::new(status)
                .set_body_string(format!("{} {SENTINEL_USER} {SENTINEL_PASSWORD}", headers.join(" ")))
        }
    }

    #[tokio::test]
    async fn a_refusal_names_the_path_and_the_status_never_the_account() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(echo(401)).mount(&server).await;
        let error = client(&server).get(&Call::Systems).await.unwrap_err();
        let text = printed(&error);
        assert!(text.starts_with("GET /redfish/v1/Systems answered 401: "), "{text}");
        // The header was echoed, and masked.
        assert!(text.contains("authorization: Basic ***"), "{text}");
        assert_no_secret(&text);
    }

    // A BMC that quotes the account in a JSON error writes it escaped (`\"`,
    // `\\`); and a user name holding the password must not be cut by its
    // masking, leaving the rest of the name readable.
    #[tokio::test]
    async fn the_account_is_masked_as_json_writes_it_and_whatever_holds_what() {
        let (user, password) = ("ops-pa\"ss\\w0rd", "pa\"ss\\w0rd");
        let quoted = |text: &str| serde_json::to_string(text).unwrap();
        let server = MockServer::start().await;
        let body = format!("{{\"error\": {}, \"password\": {}}}", quoted(user), quoted(password));
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(400).set_body_string(body)).mount(&server).await;
        let client = RedfishClient::new(&server.uri(), Credentials::new(user, password)).unwrap();
        let text = printed(&client.get(&Call::Systems).await.unwrap_err());
        for fragment in ["ops-", "pa\\\"ss", "w0rd"] {
            assert!(!text.contains(fragment), "{fragment:?} in {text}");
        }
    }

    #[tokio::test]
    async fn an_answer_that_is_not_a_json_object_is_an_error_without_the_account() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/redfish/v1/")).respond_with(echo(200)).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Systems"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(["a list"])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/redfish/v1/Managers/1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let redfish = client(&server);
        let error = redfish.get(&Call::ServiceRoot).await.unwrap_err();
        assert!(printed(&error).starts_with("GET /redfish/v1/: unexpected answer: "), "{error}");
        assert_no_secret(&printed(&error));
        let error = redfish.get(&Call::Systems).await.unwrap_err();
        assert_eq!(error.to_string(), "GET /redfish/v1/Systems: unexpected answer: not a JSON object");
        // An empty body is not an empty resource.
        let error = redfish.get(&Call::Manager("/redfish/v1/Managers/1".to_owned())).await.unwrap_err();
        assert!(error.to_string().starts_with("GET /redfish/v1/Managers/1: unexpected answer: "), "{error}");
    }

    #[tokio::test]
    async fn a_bmc_that_does_not_answer_is_named_by_the_path_never_the_account() {
        // A local port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let credentials = Credentials::new(SENTINEL_USER, SENTINEL_PASSWORD);
        let redfish = RedfishClient::new(&format!("http://127.0.0.1:{port}"), credentials).unwrap();
        let error = redfish.get(&Call::ServiceRoot).await.unwrap_err();
        let text = printed(&error);
        assert!(text.starts_with("GET /redfish/v1/: "), "{text}");
        assert!(matches!(error, ClientError::Transport { .. }), "{error:?}");
        assert_no_secret(&text);
    }

    #[tokio::test]
    async fn a_bmc_that_answers_too_late_fails_the_call() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let credentials = Credentials::new(SENTINEL_USER, SENTINEL_PASSWORD);
        let redfish =
            RedfishClient::builder(&server.uri(), credentials).timeout(Duration::from_millis(50)).build().unwrap();
        let error = redfish.get(&Call::ServiceRoot).await.unwrap_err();
        assert!(matches!(error, ClientError::Transport { .. }), "{error:?}");
        assert_no_secret(&printed(&error));
    }

    #[test]
    fn the_timeout_is_generous_by_default() {
        let redfish = RedfishClient::new("https://198.51.100.7", Credentials::new("sync", "pw")).unwrap();
        assert_eq!(redfish.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn credentials_in_the_url_are_refused_without_being_shown() {
        let url = format!("https://{SENTINEL_USER}:s3ntinel@198.51.100.7");
        let error = RedfishClient::new(&url, Credentials::new("sync", "pw")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Redfish client: BMC URL \"https://***@198.51.100.7\": credentials in the URL are refused"
        );
        assert_no_secret(&printed(&error));
    }

    #[test]
    fn a_url_that_is_more_than_a_host_is_refused() {
        let refused = |url: &str| RedfishClient::new(url, Credentials::new("sync", "pw")).unwrap_err().to_string();
        assert_eq!(
            refused("https://198.51.100.7/redfish/v1"),
            "Redfish client: BMC URL \"https://198.51.100.7/redfish/v1\": a path, a query or a fragment is refused"
        );
        assert_eq!(
            refused("ftp://198.51.100.7"),
            "Redfish client: BMC URL \"ftp://198.51.100.7\": not an http or https URL"
        );
    }

    #[test]
    fn nothing_printed_of_a_client_or_its_account_shows_the_password() {
        let credentials = Credentials::new(SENTINEL_USER, SENTINEL_PASSWORD);
        let shown = format!("{credentials:?}");
        assert!(shown.contains(SENTINEL_USER) && !shown.contains("s3ntinel"), "{shown}");
        let redfish = RedfishClient::new("https://198.51.100.7", credentials).unwrap();
        assert_no_secret(&format!("{redfish:?}"));
    }

    #[test]
    fn a_ca_file_that_cannot_be_used_is_refused_when_the_client_is_built() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent.pem");
        let error = RedfishClient::builder("https://198.51.100.7", Credentials::new("sync", "pw"))
            .ca_file(&absent)
            .build()
            .unwrap_err();
        assert!(error.to_string().starts_with(&format!("Redfish client: CA file {}: ", absent.display())), "{error}");
        let empty = directory.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let error = RedfishClient::builder("https://198.51.100.7", Credentials::new("sync", "pw"))
            .ca_file(&empty)
            .build()
            .unwrap_err();
        assert_eq!(error.to_string(), format!("Redfish client: CA file {}: no certificate found", empty.display()));
    }
}
