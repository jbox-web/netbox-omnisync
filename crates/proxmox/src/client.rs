//! A read-only client of the Proxmox VE API.
//!
//! The source only reads Proxmox: this client can log in and send GET
//! requests, and has no way to send anything else. It never retries: a
//! collection that cannot be read whole is abandoned by its caller.

use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, HeaderName, HeaderValue};
use reqwest::{Certificate, Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;

/// Time a request may take before it fails: without a bound, a hung Proxmox
/// would block the cron run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests in flight at once, for the whole client: the API daemon of a node
/// has a handful of workers, which a full collection must not monopolise.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 8;

/// The realm of a user name given without one, as the login page of Proxmox assumes.
pub const DEFAULT_REALM: &str = "pam";

/// What the header of an API token starts with; a token copied with it is accepted.
const TOKEN_PREFIX: &str = "PVEAPIToken=";

/// The path of the login, the only request that is not a GET.
const LOGIN_PATH: &str = "/access/ticket";

/// Characters of an error body kept in the message when Proxmox gives no `message`.
const ERROR_BODY_LIMIT: usize = 500;

/// What replaces a secret in a message.
const MASK: &str = "***";

/// How the client proves who it is.
#[derive(Clone)]
pub enum Credentials {
    /// A user and its password, exchanged for a ticket by the login.
    Password { username: String, password: String },
    /// An API token, `user@realm!name=secret`, sent with every request: no login.
    ApiToken { token: String },
}

impl Credentials {
    /// A user name without realm gets `@pam`.
    pub fn password(username: &str, password: &str) -> Self {
        Credentials::Password { username: username.to_owned(), password: password.to_owned() }
    }

    /// `token` is `user@realm!name=secret`, as Proxmox shows it once at creation.
    pub fn api_token(token: &str) -> Self {
        Credentials::ApiToken { token: token.to_owned() }
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Who logs in, never with what.
        match self {
            Credentials::Password { username, .. } => {
                formatter.debug_struct("Password").field("username", username).field("password", &MASK).finish()
            }
            Credentials::ApiToken { token } => {
                let id = token.split_once('=').map_or(MASK, |(id, _)| id);
                formatter.debug_struct("ApiToken").field("id", &id).field("secret", &MASK).finish()
            }
        }
    }
}

/// Why a call to Proxmox failed. No message carries the password, the ticket
/// or the token, nor the user they belong to. `path` is what follows `/api2/json`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The settings cannot make a client, or the path cannot make a request: nothing was sent.
    #[error("Proxmox client: {0}")]
    Config(String),
    /// Proxmox answered, with an HTTP status that is not a success.
    #[error("{method} {path} answered {status}: {message}")]
    Status { method: &'static str, path: String, status: u16, message: String },
    /// No answer: refused, timed out, cut.
    #[error("{method} {path}: {reason}")]
    Transport { method: &'static str, path: String, reason: String },
    /// A successful answer that is not what the call returns.
    #[error("{method} {path}: unexpected answer: {reason}")]
    Decode { method: &'static str, path: String, reason: String },
}

/// Settings of a [`ProxmoxClient`].
pub struct ProxmoxClientBuilder {
    url: String,
    credentials: Credentials,
    timeout: Duration,
    validate_certs: bool,
    ca_file: Option<PathBuf>,
    max_in_flight: usize,
}

impl ProxmoxClientBuilder {
    /// Time a request may take, 30 s by default.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether the certificate of Proxmox is validated: yes by default.
    pub fn validate_certs(mut self, validate: bool) -> Self {
        self.validate_certs = validate;
        self
    }

    /// A PEM file of certificate authorities trusted on top of the system ones:
    /// a Proxmox cluster signs its certificates with its own authority.
    pub fn ca_file(mut self, path: impl AsRef<Path>) -> Self {
        self.ca_file = Some(path.as_ref().to_owned());
        self
    }

    /// Requests in flight at once, 8 by default; at least one.
    pub fn max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Checks the settings and makes the client; nothing is sent.
    pub fn build(self) -> Result<ProxmoxClient, ClientError> {
        let api = api_url(&self.url)?;
        let identity = Identity::of(self.credentials)?;
        // Without a bound a request waits forever. A redirect is never followed: the API
        // does not redirect, and following one would send a request this client did not choose.
        // Never the proxy of the environment: the account would leave for another host.
        let mut http =
            reqwest::Client::builder().timeout(self.timeout).redirect(reqwest::redirect::Policy::none()).no_proxy();
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
        let http = http.build().map_err(|error| ClientError::Config(format!("HTTP client: {}", chain(&error))))?;
        let max_in_flight = self.max_in_flight.max(1);
        Ok(ProxmoxClient {
            http,
            api,
            identity,
            session: OnceCell::new(),
            timeout: self.timeout,
            max_in_flight,
            in_flight: Semaphore::new(max_in_flight),
        })
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

/// `https://pve.example:8006` → `https://pve.example:8006/api2/json/`.
fn api_url(url: &str) -> Result<Url, ClientError> {
    let refused = |reason: &str| ClientError::Config(format!("Proxmox URL {:?}: {reason}", shown(url)));
    let mut base = Url::parse(url).map_err(|error| refused(&error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(refused("not an http or https URL"));
    }
    // The credentials are given apart: a user or a password in the URL would be
    // sent as well, and printed with the URL.
    if !base.username().is_empty() || base.password().is_some() {
        return Err(refused("credentials in the URL are refused"));
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base.join("api2/json/").map_err(|error| refused(&error.to_string()))
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

/// A secret as an `application/x-www-form-urlencoded` body carries it.
fn form_encoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// A header value that reqwest and hyper never print.
fn sensitive(value: &str, what: &str) -> Result<HeaderValue, ClientError> {
    // The value is not shown: it is the secret.
    let mut header = HeaderValue::from_str(value)
        .map_err(|_| ClientError::Config(format!("the {what} cannot be sent as an HTTP header")))?;
    header.set_sensitive(true);
    Ok(header)
}

/// The credentials, checked and ready to be sent.
enum Identity {
    /// `username` carries its realm.
    Password { username: String, password: String },
    /// `header` is the whole `Authorization` value; `token` and `secret` are
    /// kept to be scrubbed from the error messages only.
    ApiToken { id: String, token: String, secret: String, header: HeaderValue },
}

impl Identity {
    fn of(credentials: Credentials) -> Result<Self, ClientError> {
        match credentials {
            Credentials::Password { username, password } => {
                let username = if username.contains('@') { username } else { format!("{username}@{DEFAULT_REALM}") };
                Ok(Identity::Password { username, password })
            }
            Credentials::ApiToken { token } => {
                let token = token.strip_prefix(TOKEN_PREFIX).unwrap_or(&token).to_owned();
                let parts = token.split_once('=').and_then(|(id, secret)| Some((id, id.split_once('!')?, secret)));
                match parts {
                    Some((id, (user, name), secret)) if !user.is_empty() && !name.is_empty() && !secret.is_empty() => {
                        let header = sensitive(&format!("{TOKEN_PREFIX}{token}"), "API token")?;
                        Ok(Identity::ApiToken { id: id.to_owned(), secret: secret.to_owned(), header, token })
                    }
                    // The token is not shown: a part of it may be the secret.
                    _ => Err(ClientError::Config("the API token is not of the form user@realm!name=secret".to_owned())),
                }
            }
        }
    }
}

/// What a login gave.
struct Session {
    /// The whole `Cookie` value.
    cookie: HeaderValue,
    /// Kept to be scrubbed from the error messages only.
    ticket: String,
}

/// Every answer of Proxmox wraps its payload in `data`.
#[derive(Deserialize)]
#[serde(bound = "T: DeserializeOwned")]
struct Envelope<T> {
    data: T,
}

/// What the client reads of the answer to a login.
#[derive(Deserialize)]
struct Ticket {
    ticket: Option<String>,
    #[serde(rename = "NeedTFA", default)]
    need_tfa: Option<serde_json::Value>,
}

/// What the client reads of an error body.
#[derive(Deserialize)]
struct Refusal {
    message: Option<String>,
}

pub struct ProxmoxClient {
    http: reqwest::Client,
    /// Ends with `/api2/json/`.
    api: Url,
    identity: Identity,
    /// The ticket of the login, asked once: the first caller logs in, the
    /// others wait for it. A ticket lives two hours, far longer than a
    /// collection: it is never renewed.
    session: OnceCell<Session>,
    timeout: Duration,
    max_in_flight: usize,
    /// Shared by every call: the nodes and the guests are read in parallel on one client.
    in_flight: Semaphore,
}

impl std::fmt::Debug for ProxmoxClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the password, the ticket or the token.
        let user = match &self.identity {
            Identity::Password { username, .. } => username,
            Identity::ApiToken { id, .. } => id,
        };
        formatter
            .debug_struct("ProxmoxClient")
            .field("api", &self.api.as_str())
            .field("user", user)
            .field("logged_in", &self.session.initialized())
            .finish_non_exhaustive()
    }
}

impl ProxmoxClient {
    /// A client of the Proxmox at `url` (e.g. `https://pve.example:8006`).
    pub fn builder(url: &str, credentials: Credentials) -> ProxmoxClientBuilder {
        ProxmoxClientBuilder {
            url: url.to_owned(),
            credentials,
            timeout: DEFAULT_TIMEOUT,
            validate_certs: true,
            ca_file: None,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }

    /// A client with the default settings.
    pub fn new(url: &str, credentials: Credentials) -> Result<Self, ClientError> {
        ProxmoxClient::builder(url, credentials).build()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// Exchanges the password for a ticket (`POST /access/ticket`), once: the
    /// first GET does it when it was not called. Nothing is sent with an API token.
    pub async fn login(&self) -> Result<(), ClientError> {
        self.credential().await.map(|_| ())
    }

    /// `GET /api2/json{path}`, and what Proxmox puts under `data`.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        self.get_with(path, &[]).await
    }

    /// [`get`](Self::get) with query parameters, each encoded.
    pub async fn get_with<T: DeserializeOwned>(&self, path: &str, query: &[(&str, &str)]) -> Result<T, ClientError> {
        // The URL is checked before the login: a refused path sends nothing at all.
        let mut url = self.url(path)?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let credential = self.credential().await?;
        let answer = self.send(Method::GET, "GET", path, url, Some(credential), None).await?;
        let envelope: Envelope<T> = serde_json::from_slice(&answer).map_err(|error| ClientError::Decode {
            method: "GET",
            path: path.to_owned(),
            reason: self.scrub(&error.to_string()),
        })?;
        Ok(envelope.data)
    }

    /// The header that authenticates a request, after the login when one is needed.
    async fn credential(&self) -> Result<(HeaderName, HeaderValue), ClientError> {
        match &self.identity {
            Identity::ApiToken { header, .. } => Ok((AUTHORIZATION, header.clone())),
            Identity::Password { username, password } => {
                let session = self.session.get_or_try_init(|| self.open_session(username, password)).await?;
                Ok((COOKIE, session.cookie.clone()))
            }
        }
    }

    async fn open_session(&self, username: &str, password: &str) -> Result<Session, ClientError> {
        let url = self.url(LOGIN_PATH)?;
        // Encoded here rather than by reqwest: its `form` feature is not one the workspace enables.
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("username", username)
            .append_pair("password", password)
            .finish();
        let answer = self.send(Method::POST, "POST", LOGIN_PATH, url, None, Some(form)).await?;
        let unexpected = |reason: &str| ClientError::Decode {
            method: "POST",
            path: LOGIN_PATH.to_owned(),
            reason: reason.to_owned(),
        };
        // The reason of serde is not kept: it quotes the answer, which holds the ticket.
        let envelope: Envelope<Ticket> =
            serde_json::from_slice(&answer).map_err(|_| unexpected("no ticket in the answer"))?;
        let ticket = envelope.data.ticket.filter(|ticket| !ticket.is_empty());
        let ticket = ticket.ok_or_else(|| unexpected("no ticket in the answer"))?;
        // A partial ticket would be refused by every call that follows, without saying why.
        let need_tfa = envelope.data.need_tfa.is_some_and(|flag| flag != false && flag != 0 && !flag.is_null());
        if need_tfa || ticket.starts_with("PVE:!tfa!") {
            return Err(unexpected("the user needs a second factor, which this client cannot give: use an API token"));
        }
        let cookie = sensitive(&format!("PVEAuthCookie={ticket}"), "ticket")
            .map_err(|_| unexpected("the ticket cannot be sent as an HTTP header"))?;
        Ok(Session { cookie, ticket })
    }

    /// `/nodes/pve01/qemu` → `…/api2/json/nodes/pve01/qemu`. Each segment is
    /// encoded, so that a name read from Proxmox cannot add a query, and none
    /// may climb out of the API.
    fn url(&self, path: &str) -> Result<Url, ClientError> {
        let refused = |reason: &str| ClientError::Config(format!("path {path:?}: {reason}"));
        let segments: Vec<&str> =
            path.strip_prefix('/').ok_or_else(|| refused("does not start with /"))?.split('/').collect();
        if segments.iter().any(|segment| matches!(*segment, "" | "." | "..")) {
            return Err(refused("has an empty or a relative segment"));
        }
        let mut url = self.api.clone();
        url.path_segments_mut()
            .map_err(|()| refused("the URL of Proxmox takes no path"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    /// A message without the secrets nor the account they belong to, whatever
    /// put them there (Proxmox, a proxy, a library), as given and as a form
    /// carries them.
    fn scrub(&self, message: &str) -> String {
        let mut secrets: Vec<&str> = match &self.identity {
            Identity::Password { username, password } => vec![password, username],
            Identity::ApiToken { id, token, secret, .. } => {
                let user = id.split_once('!').map_or(id.as_str(), |(user, _)| user);
                vec![token, secret, id, user]
            }
        };
        if let Some(session) = self.session.get() {
            secrets.push(&session.ticket);
        }
        // The longest first: a ticket and a token hold the name of their user,
        // and would no longer be recognised once it is masked.
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        let mut message = message.to_owned();
        for secret in secrets.into_iter().filter(|secret| !secret.is_empty()) {
            message = message.replace(secret, MASK).replace(&form_encoded(secret), MASK);
        }
        message
    }

    /// Sends one request and gives the body of a successful answer. Private,
    /// and called with GET for everything but the login: the client cannot write.
    async fn send(
        &self,
        method: Method,
        verb: &'static str,
        path: &str,
        url: Url,
        credential: Option<(HeaderName, HeaderValue)>,
        form: Option<String>,
    ) -> Result<Vec<u8>, ClientError> {
        let broken = |reason: String| ClientError::Transport {
            method: verb,
            path: path.to_owned(),
            reason: self.scrub(&reason),
        };
        let (status, answer) = {
            let _permit = self.in_flight.acquire().await.map_err(|_| broken("the client is closed".to_owned()))?;
            let mut request = self.http.request(method, url).header(ACCEPT, "application/json");
            if let Some((name, value)) = credential {
                request = request.header(name, value);
            }
            if let Some(form) = form {
                request = request.header(CONTENT_TYPE, "application/x-www-form-urlencoded").body(form);
            }
            // The URL is left out of the reason: the path is already in the message.
            let lost = |error: reqwest::Error| broken(chain(&error.without_url()));
            let response = request.send().await.map_err(lost)?;
            (response.status(), response.bytes().await.map_err(lost)?.to_vec())
        };
        if status.is_success() {
            return Ok(answer);
        }
        Err(ClientError::Status {
            method: verb,
            path: path.to_owned(),
            status: status.as_u16(),
            message: self.scrub(&said(status, &answer)),
        })
    }
}

/// What an error answer says: the `message` of Proxmox, or the start of the body.
fn said(status: StatusCode, answer: &[u8]) -> String {
    let message = serde_json::from_slice::<Refusal>(answer).ok().and_then(|refusal| refusal.message);
    let text = message.unwrap_or_else(|| String::from_utf8_lossy(answer).into_owned());
    let text: String = text.trim().chars().take(ERROR_BODY_LIMIT).collect();
    if text.is_empty() { status.canonical_reason().unwrap_or("no message").to_owned() } else { text }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use futures::future::join_all;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    const SENTINEL_PASSWORD: &str = "s3ntinel pass&word/+";
    /// The same password as a form carries it.
    const SENTINEL_PASSWORD_FORM: &str = "s3ntinel+pass%26word%2F%2B";
    const SENTINEL_TICKET: &str = "PVE:sync@pve:6740A1B2::s3ntinelT1cketSignature==";
    const SENTINEL_SECRET: &str = "5e471e1e-0000-4000-8000-5ec2e7000000";

    const LOGIN: &str = "/api2/json/access/ticket";

    fn ticket_answer(ticket: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(
            json!({"data": {"ticket": ticket, "CSRFPreventionToken": "6740A1B2:csrf", "username": "sync@pve"}}),
        )
    }

    async fn mount_login(server: &MockServer, ticket: &str) {
        Mock::given(method("POST")).and(path(LOGIN)).respond_with(ticket_answer(ticket)).mount(server).await;
    }

    fn password_client(server: &MockServer) -> ProxmoxClient {
        ProxmoxClient::new(&server.uri(), Credentials::password("sync@pve", SENTINEL_PASSWORD)).unwrap()
    }

    fn token_client(server: &MockServer) -> ProxmoxClient {
        let token = format!("sync@pve!netbox={SENTINEL_SECRET}");
        ProxmoxClient::new(&server.uri(), Credentials::api_token(&token)).unwrap()
    }

    /// (method, path) of every request the mock received.
    async fn received(server: &MockServer) -> Vec<(String, String)> {
        let requests = server.received_requests().await.unwrap();
        requests.iter().map(|request| (request.method.to_string(), request.url.path().to_owned())).collect()
    }

    /// An answer repeating everything the request carried, as a verbose proxy would.
    fn echo(status: u16) -> impl Fn(&Request) -> ResponseTemplate + Send + Sync + 'static {
        move |request: &Request| {
            let headers: Vec<String> =
                request.headers.iter().map(|(name, value)| format!("{name}: {}", value.to_str().unwrap())).collect();
            let body = String::from_utf8_lossy(&request.body).into_owned();
            ResponseTemplate::new(status)
                .set_body_json(json!({"data": null, "message": format!("{} {body}", headers.join(" "))}))
        }
    }

    /// Every way an error can be printed.
    fn printed(error: &ClientError) -> String {
        format!("{error} {error:?}")
    }

    fn assert_no_secret(text: &str) {
        for secret in [SENTINEL_PASSWORD, SENTINEL_PASSWORD_FORM, SENTINEL_TICKET, SENTINEL_SECRET, "s3ntinel"] {
            assert!(!text.contains(secret), "{secret:?} in {text}");
        }
    }

    #[tokio::test]
    async fn login_posts_the_form_then_every_get_carries_the_ticket_cookie() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            // application/x-www-form-urlencoded: `@` is %40, a space is `+`, `&` is %26.
            .and(body_string("username=sync%40pve&password=p%40ss+w%26rd"))
            .respond_with(ticket_answer("PVE:sync@pve:6740A1B2::c2lnbmF0dXJl"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/version"))
            .and(header("cookie", "PVEAuthCookie=PVE:sync@pve:6740A1B2::c2lnbmF0dXJl"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"version": "8.4.21"}})))
            .expect(2)
            .mount(&server)
            .await;
        let proxmox = ProxmoxClient::new(&server.uri(), Credentials::password("sync@pve", "p@ss w&rd")).unwrap();
        proxmox.login().await.unwrap();
        for _ in 0..2 {
            assert_eq!(proxmox.get::<Value>("/version").await.unwrap(), json!({"version": "8.4.21"}));
        }
        assert_eq!(
            received(&server).await,
            [("POST", LOGIN), ("GET", "/api2/json/version"), ("GET", "/api2/json/version")]
                .map(|(verb, target)| (verb.to_owned(), target.to_owned()))
        );
    }

    #[tokio::test]
    async fn a_user_name_without_realm_gets_pam() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .and(body_string("username=root%40pam&password=secret"))
            .respond_with(ticket_answer("PVE:root@pam:6740A1B2::c2ln"))
            .expect(1)
            .mount(&server)
            .await;
        let proxmox = ProxmoxClient::new(&server.uri(), Credentials::password("root", "secret")).unwrap();
        proxmox.login().await.unwrap();
    }

    #[tokio::test]
    async fn the_first_get_logs_in_and_concurrent_ones_share_a_single_login() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .respond_with(ticket_answer(SENTINEL_TICKET).set_delay(Duration::from_millis(50)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": 1})))
            .mount(&server)
            .await;
        let proxmox = password_client(&server);
        let answers = join_all((0..10).map(|_| proxmox.get::<u64>("/version"))).await;
        assert!(answers.iter().all(|answer| answer == &Ok(1)), "{answers:?}");
        let posts = received(&server).await.into_iter().filter(|(verb, _)| verb == "POST").count();
        assert_eq!(posts, 1);
    }

    #[tokio::test]
    async fn an_api_token_goes_in_the_authorization_header_and_never_logs_in() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .and(header("authorization", "PVEAPIToken=sync@pve!netbox=5e471e1e-0000-4000-8000-5ec2e7000000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [{"node": "pve01"}]})))
            .expect(1)
            .mount(&server)
            .await;
        let proxmox = token_client(&server);
        proxmox.login().await.unwrap();
        assert_eq!(proxmox.get::<Value>("/nodes").await.unwrap(), json!([{"node": "pve01"}]));
        assert_eq!(received(&server).await, [("GET".to_owned(), "/api2/json/nodes".to_owned())]);
    }

    #[tokio::test]
    async fn a_token_given_with_its_header_prefix_is_sent_once_prefixed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("authorization", "PVEAPIToken=sync@pve!netbox=uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": 1})))
            .expect(1)
            .mount(&server)
            .await;
        let credentials = Credentials::api_token("PVEAPIToken=sync@pve!netbox=uuid");
        let proxmox = ProxmoxClient::new(&server.uri(), credentials).unwrap();
        assert_eq!(proxmox.get::<u64>("/version").await, Ok(1));
    }

    #[test]
    fn a_token_that_is_not_user_name_secret_is_refused_without_being_shown() {
        for token in ["s3ntinel", "sync@pve=s3ntinel", "sync@pve!netbox", "sync@pve!netbox=", "!netbox=s3ntinel"] {
            let error = ProxmoxClient::new("https://pve.example:8006", Credentials::api_token(token)).unwrap_err();
            assert!(matches!(error, ClientError::Config(_)), "{error:?}");
            assert_no_secret(&printed(&error));
        }
    }

    #[tokio::test]
    async fn a_failing_login_shows_the_status_and_the_path_never_the_password() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path(LOGIN)).respond_with(echo(401)).mount(&server).await;
        let proxmox = password_client(&server);
        for error in [proxmox.login().await.unwrap_err(), proxmox.get::<Value>("/version").await.unwrap_err()] {
            assert!(matches!(error, ClientError::Status { status: 401, .. }), "{error:?}");
            let text = printed(&error);
            assert!(text.contains("POST /access/ticket answered 401"), "{text}");
            assert_no_secret(&text);
        }
        // The echo did carry the password: the assertion above is not vacuous.
        let sent = server.received_requests().await.unwrap();
        assert!(String::from_utf8_lossy(&sent[0].body).contains(SENTINEL_PASSWORD_FORM));
    }

    #[tokio::test]
    async fn a_failing_request_shows_the_status_and_the_path_never_the_ticket() {
        let server = MockServer::start().await;
        mount_login(&server, SENTINEL_TICKET).await;
        Mock::given(method("GET")).respond_with(echo(500)).mount(&server).await;
        let error = password_client(&server).get::<Value>("/nodes/pve01/qemu/101/config").await.unwrap_err();
        assert!(matches!(error, ClientError::Status { status: 500, .. }), "{error:?}");
        let text = printed(&error);
        assert!(text.contains("GET /nodes/pve01/qemu/101/config answered 500"), "{text}");
        assert_no_secret(&text);
        let sent = server.received_requests().await.unwrap();
        let cookie = sent[1].headers.get("cookie").unwrap().to_str().unwrap();
        assert_eq!(cookie, format!("PVEAuthCookie={SENTINEL_TICKET}"));
    }

    #[tokio::test]
    async fn a_failing_request_never_shows_the_api_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(echo(403)).mount(&server).await;
        let error = token_client(&server).get::<Value>("/cluster/status").await.unwrap_err();
        let text = printed(&error);
        assert!(text.contains("GET /cluster/status answered 403"), "{text}");
        assert_no_secret(&text);
        let sent = server.received_requests().await.unwrap();
        assert!(sent[0].headers.get("authorization").unwrap().to_str().unwrap().contains(SENTINEL_SECRET));
    }

    #[tokio::test]
    async fn an_answer_that_cannot_be_decoded_names_the_path_and_shows_no_secret() {
        let server = MockServer::start().await;
        // A login answer without ticket, repeating the password.
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": SENTINEL_PASSWORD})))
            .mount(&server)
            .await;
        let error = password_client(&server).login().await.unwrap_err();
        assert!(matches!(error, ClientError::Decode { .. }), "{error:?}");
        assert!(printed(&error).contains("POST /access/ticket"), "{error}");
        assert_no_secret(&printed(&error));

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": SENTINEL_SECRET})))
            .mount(&server)
            .await;
        let error = token_client(&server).get::<u64>("/version").await.unwrap_err();
        assert!(matches!(error, ClientError::Decode { .. }), "{error:?}");
        assert!(printed(&error).contains("GET /version"), "{error}");
        assert_no_secret(&printed(&error));
    }

    /// A local port nothing listens on.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn an_unreachable_proxmox_names_the_path_and_shows_no_secret() {
        let url = format!("http://127.0.0.1:{}", closed_port());
        let proxmox = ProxmoxClient::new(&url, Credentials::password("sync@pve", SENTINEL_PASSWORD)).unwrap();
        let error = proxmox.get::<Value>("/version").await.unwrap_err();
        assert!(matches!(error, ClientError::Transport { .. }), "{error:?}");
        assert!(printed(&error).contains("POST /access/ticket"), "{error}");
        assert_no_secret(&printed(&error));

        let token = format!("sync@pve!netbox={SENTINEL_SECRET}");
        let proxmox = ProxmoxClient::new(&url, Credentials::api_token(&token)).unwrap();
        let error = proxmox.get::<Value>("/nodes").await.unwrap_err();
        assert!(matches!(error, ClientError::Transport { .. }), "{error:?}");
        assert!(printed(&error).contains("GET /nodes"), "{error}");
        assert_no_secret(&printed(&error));
    }

    /// An account whose name must never show in an error: who logs in is not
    /// said by a failure.
    const SENTINEL_USER: &str = "0perator-never-shown@pve";
    /// The same account as a form carries it.
    const SENTINEL_USER_FORM: &str = "0perator-never-shown%40pve";

    fn assert_no_account(text: &str) {
        for account in [SENTINEL_USER, SENTINEL_USER_FORM, "0perator"] {
            assert!(!text.contains(account), "{account:?} in {text}");
        }
        assert_no_secret(text);
    }

    /// Every way an error can be printed; it has no cause to print.
    fn printed_whole(error: &ClientError) -> String {
        assert!(std::error::Error::source(error).is_none(), "{error:?}");
        printed(error)
    }

    #[tokio::test]
    async fn a_failing_login_never_shows_the_user_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path(LOGIN)).respond_with(echo(401)).mount(&server).await;
        // With its realm, then without: the latter is sent as `0perator-never-shown@pam`.
        for username in [SENTINEL_USER, "0perator-never-shown"] {
            let credentials = Credentials::password(username, SENTINEL_PASSWORD);
            let error = ProxmoxClient::new(&server.uri(), credentials).unwrap().login().await.unwrap_err();
            let text = printed_whole(&error);
            assert!(text.contains("POST /access/ticket answered 401"), "{text}");
            assert_no_account(&text);
        }
        // The echo did carry the user name: the assertion above is not vacuous.
        let sent = server.received_requests().await.unwrap();
        assert!(String::from_utf8_lossy(&sent[0].body).contains(SENTINEL_USER_FORM));
        assert!(String::from_utf8_lossy(&sent[1].body).contains("0perator-never-shown%40pam"));
    }

    #[tokio::test]
    async fn a_failing_request_never_shows_who_the_api_token_belongs_to() {
        let server = MockServer::start().await;
        // A proxy repeating the header, then Proxmox naming the token and its user.
        Mock::given(method("GET")).and(path("/api2/json/cluster/status")).respond_with(echo(403)).mount(&server).await;
        let denied =
            json!({"data": null, "message": format!("no permission for {SENTINEL_USER}!netbox ({SENTINEL_USER})")});
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(ResponseTemplate::new(403).set_body_json(denied))
            .mount(&server)
            .await;
        // An answer that is not the number asked for: the decoder quotes what it found.
        Mock::given(method("GET"))
            .and(path("/api2/json/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": format!("{SENTINEL_USER}!netbox")})))
            .mount(&server)
            .await;
        let token = format!("{SENTINEL_USER}!netbox={SENTINEL_SECRET}");
        let proxmox = ProxmoxClient::new(&server.uri(), Credentials::api_token(&token)).unwrap();
        for (target, expected) in [
            ("/cluster/status", "GET /cluster/status answered 403: "),
            ("/nodes", "GET /nodes answered 403: no permission for "),
            ("/version", "GET /version: unexpected answer: "),
        ] {
            let error = proxmox.get::<u64>(target).await.unwrap_err();
            let text = printed_whole(&error);
            assert!(text.starts_with(expected), "{text}");
            assert_no_account(&text);
        }
        let sent = server.received_requests().await.unwrap();
        assert!(sent[0].headers.get("authorization").unwrap().to_str().unwrap().contains(SENTINEL_USER));
    }

    #[tokio::test]
    async fn a_connection_that_fails_never_shows_the_account_nor_its_secret() {
        let closed = format!("http://127.0.0.1:{}", closed_port());
        // A server that does not speak TLS.
        let server = MockServer::start().await;
        let no_tls = format!("https://{}", server.address());
        // An answer that comes too late.
        let slow = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&slow)
            .await;
        let token = format!("{SENTINEL_USER}!netbox={SENTINEL_SECRET}");
        for url in [closed, no_tls, slow.uri()] {
            let by_password = Credentials::password(SENTINEL_USER, SENTINEL_PASSWORD);
            let by_token = Credentials::api_token(&token);
            for (credentials, expected) in [(by_password, "POST /access/ticket: "), (by_token, "GET /nodes: ")] {
                let proxmox =
                    ProxmoxClient::builder(&url, credentials).timeout(Duration::from_millis(300)).build().unwrap();
                let error = proxmox.get::<Value>("/nodes").await.unwrap_err();
                assert!(matches!(error, ClientError::Transport { .. }), "{url}: {error:?}");
                let text = printed_whole(&error);
                assert!(text.starts_with(expected), "{url}: {text}");
                assert_no_account(&text);
            }
        }
    }

    #[test]
    fn a_url_carrying_credentials_is_refused_without_showing_them() {
        let credentials = || Credentials::api_token("sync@pve!netbox=uuid");
        let url = format!("https://{SENTINEL_USER}:{SENTINEL_SECRET}@pve.example:8006");
        let error = ProxmoxClient::new(&url, credentials()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Proxmox client: Proxmox URL \"https://***@pve.example:8006\": credentials in the URL are refused"
        );
        let urls = [
            format!("https://root:{SENTINEL_SECRET}@pve.example:8006/pve"),
            format!("https://{SENTINEL_SECRET}@pve.example:8006"),
            format!("ftp://root:{SENTINEL_SECRET}@pve.example"),
            format!("root:{SENTINEL_SECRET}@pve.example:8006"),
            format!("https://root:{SENTINEL_SECRET}@"),
            format!("https://root:pass/{SENTINEL_SECRET}@pve.example:8006"),
        ];
        for url in urls {
            let error = ProxmoxClient::new(&url, credentials()).expect_err("a URL with credentials");
            assert!(matches!(error, ClientError::Config(_)), "{error:?}");
            let text = printed_whole(&error);
            assert_no_secret(&text);
            assert!(!text.contains("root"), "{text}");
        }
    }

    #[tokio::test]
    async fn debug_output_shows_no_secret() {
        let server = MockServer::start().await;
        mount_login(&server, SENTINEL_TICKET).await;
        let proxmox = password_client(&server);
        proxmox.login().await.unwrap();
        let text = format!("{proxmox:?} {:?} {:?}", Credentials::password("sync@pve", SENTINEL_PASSWORD), {
            Credentials::api_token(&format!("sync@pve!netbox={SENTINEL_SECRET}"))
        });
        assert_no_secret(&text);
        // Who logs in is not a secret, and tells the clients apart.
        assert!(text.contains("sync@pve"), "{text}");
    }

    #[tokio::test]
    async fn a_ticket_waiting_for_a_second_factor_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"data": {"ticket": "PVE:!tfa!s3ntinel", "NeedTFA": 1, "username": "sync@pve"}}),
                ),
            )
            .mount(&server)
            .await;
        let error = password_client(&server).login().await.unwrap_err();
        let text = printed(&error);
        assert!(text.contains("POST /access/ticket"), "{text}");
        assert!(text.contains("API token"), "{text}");
        assert_no_secret(&text);
    }

    #[tokio::test]
    async fn the_message_of_proxmox_is_kept_in_the_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_json(json!({"data": null, "message": "QEMU guest agent is not running\n"})),
            )
            .mount(&server)
            .await;
        let error = token_client(&server).get::<Value>("/nodes/pve02/qemu/151/agent/get-osinfo").await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "GET /nodes/pve02/qemu/151/agent/get-osinfo answered 500: QEMU guest agent is not running"
        );
    }

    #[tokio::test]
    async fn a_redirect_is_an_error_not_a_second_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/version"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/elsewhere"))
            .mount(&server)
            .await;
        let error = token_client(&server).get::<Value>("/version").await.unwrap_err();
        assert!(matches!(error, ClientError::Status { status: 302, .. }), "{error:?}");
        assert_eq!(received(&server).await.len(), 1);
    }

    #[tokio::test]
    async fn a_path_that_could_leave_the_api_is_refused_before_any_request() {
        let server = MockServer::start().await;
        let proxmox = token_client(&server);
        for target in ["version", "", "/", "/nodes/../access", "/nodes//qemu", "/nodes/./qemu"] {
            let error = proxmox.get::<Value>(target).await.unwrap_err();
            assert!(matches!(error, ClientError::Config(_)), "{target:?}: {error:?}");
        }
        assert_eq!(received(&server).await.len(), 0);
    }

    #[tokio::test]
    async fn a_path_segment_cannot_add_a_query_or_a_fragment() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": 1})))
            .mount(&server)
            .await;
        token_client(&server).get::<u64>("/nodes/pve01?full=1#top").await.unwrap();
        let sent = server.received_requests().await.unwrap();
        assert_eq!(sent[0].url.path(), "/api2/json/nodes/pve01%3Ffull=1%23top");
        assert_eq!(sent[0].url.query(), None);
    }

    #[tokio::test]
    async fn a_trailing_slash_or_a_prefix_in_the_url_is_kept() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": 1})))
            .mount(&server)
            .await;
        for (suffix, expected) in [("/", "/api2/json/version"), ("/pve", "/pve/api2/json/version")] {
            let url = format!("{}{suffix}", server.uri());
            let proxmox = ProxmoxClient::new(&url, Credentials::api_token("sync@pve!netbox=uuid")).unwrap();
            proxmox.get::<u64>("/version").await.unwrap();
            let sent = server.received_requests().await.unwrap();
            assert_eq!(sent.last().unwrap().url.path(), expected);
        }
    }

    #[test]
    fn a_url_that_is_not_http_is_refused() {
        for url in ["pve.example:8006", "ftp://pve.example", ""] {
            let built = ProxmoxClient::new(url, Credentials::password("root", "secret"));
            assert!(matches!(built, Err(ClientError::Config(_))), "{url}");
        }
    }

    #[test]
    fn the_defaults_are_thirty_seconds_and_eight_requests() {
        let proxmox = ProxmoxClient::new("https://pve.example:8006", Credentials::password("root", "secret")).unwrap();
        assert_eq!(proxmox.timeout(), Duration::from_secs(30));
        assert_eq!(proxmox.max_in_flight(), 8);
    }

    #[tokio::test]
    async fn a_request_longer_than_the_timeout_fails() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": 1})).set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;
        let proxmox = ProxmoxClient::builder(&server.uri(), Credentials::api_token("sync@pve!netbox=uuid"))
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        assert_eq!(proxmox.timeout(), Duration::from_millis(100));
        let started = Instant::now();
        let error = proxmox.get::<u64>("/version").await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        assert!(matches!(error, ClientError::Transport { .. }), "{error:?}");
        assert!(error.to_string().starts_with("GET /version: "), "{error}");
    }

    /// The most requests the server held at once: each is held from its arrival for `delay`.
    fn most_in_flight(arrivals: &[Instant], delay: Duration) -> usize {
        let held = |at: &Instant| arrivals.iter().filter(|start| *start <= at && *at < **start + delay).count();
        arrivals.iter().map(held).max().unwrap_or(0)
    }

    async fn most_in_flight_of(max_in_flight: Option<usize>, calls: usize) -> usize {
        let delay = Duration::from_millis(100);
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&arrivals);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(move |_: &Request| {
                seen.lock().unwrap().push(Instant::now());
                ResponseTemplate::new(200).set_body_json(json!({"data": 1})).set_delay(delay)
            })
            .mount(&server)
            .await;
        let mut builder = ProxmoxClient::builder(&server.uri(), Credentials::api_token("sync@pve!netbox=uuid"));
        if let Some(max_in_flight) = max_in_flight {
            builder = builder.max_in_flight(max_in_flight);
        }
        let proxmox = builder.build().unwrap();
        let answers = join_all((0..calls).map(|_| proxmox.get::<u64>("/version"))).await;
        assert!(answers.iter().all(|answer| answer == &Ok(1)), "{answers:?}");
        let arrivals = arrivals.lock().unwrap();
        assert_eq!(arrivals.len(), calls);
        most_in_flight(&arrivals, delay)
    }

    #[tokio::test]
    async fn at_most_eight_requests_are_in_flight_by_default() {
        assert_eq!(most_in_flight_of(None, 40).await, 8);
    }

    #[tokio::test]
    async fn the_request_cap_is_configurable() {
        assert_eq!(most_in_flight_of(Some(3), 12).await, 3);
        assert_eq!(most_in_flight_of(Some(1), 4).await, 1);
    }

    #[tokio::test]
    async fn a_cap_of_zero_still_lets_one_request_through() {
        assert_eq!(most_in_flight_of(Some(0), 3).await, 1);
    }

    /// A self-signed certificate made for the tests of the workspace; its key was thrown away.
    const TEST_CA: &str = "\
-----BEGIN CERTIFICATE-----
MIIBbTCCARKgAwIBAgIUT9H5NweEK5OeyBFRd+ElAD+A6E8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQb21uaXN5bmMgdGVzdCBDQTAgFw0yNjExMjAwNDA5MThaGA8y
MTI2MTAyNzA0MDkxOFowGzEZMBcGA1UEAwwQb21uaXN5bmMgdGVzdCBDQTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABPWLO2FrAyFdyDnwv51hlR+nH2IckZZK6pIQ
yQR/r8POKCUcAw8UE6FpDSyCDGxY95OR3A0Owp2Xdp5DVy5S9q2jMjAwMB0GA1Ud
DgQWBBRESsvts3PoSH8glo4UgJkBEI5ORzAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA0kAMEYCIQD5ps5X47gjZUVXRmXL9OPWXgxffd1+qQvhuZlmzC51ZgIh
AP4yDI9tfBZnsw7iLEDTY0tHcIn9fhHTy84Knmn0FA6V
-----END CERTIFICATE-----
";

    #[test]
    fn a_ca_file_is_read_when_the_client_is_built() {
        // Removed with the test, even when an assertion fails.
        let holder = tempfile::tempdir().unwrap();
        let directory = holder.path();
        let good = directory.join("ca.pem");
        std::fs::write(&good, TEST_CA).unwrap();
        let empty = directory.join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let missing = directory.join("missing.pem");
        let build = |file: &Path| {
            ProxmoxClient::builder("https://pve.example:8006", Credentials::password("root", "secret"))
                .ca_file(file)
                .build()
        };
        assert!(build(&good).is_ok());
        let no_certificate = build(&empty).unwrap_err().to_string();
        assert!(no_certificate.contains("empty.pem"), "{no_certificate}");
        let unreadable = build(&missing).unwrap_err().to_string();
        assert!(unreadable.contains("missing.pem"), "{unreadable}");
    }

    #[test]
    fn certificate_validation_can_be_turned_off() {
        let builder = ProxmoxClient::builder("https://pve.example:8006", Credentials::password("root", "secret"));
        assert!(builder.validate_certs(false).build().is_ok());
    }
}
