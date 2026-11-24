//! A read-only client of a vCenter: its SOAP API for the inventory, its REST
//! API for the tags.
//!
//! The source only reads vSphere. On the SOAP side this client can only send
//! the operations of [`Operation`]; on the REST side, the session calls and
//! the tag reads of [`VsphereClient::tags`]. It never retries: a collection
//! that cannot be read whole is abandoned by its caller.

use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE, COOKIE, HeaderValue, SET_COOKIE};
use reqwest::{Certificate, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;
use url::Url;

use crate::soap::{self, CardHint, NAMESPACE, ObjectContent, Operation, ServiceContent};
use crate::xml::escape;

/// Time a request may take before it fails: without a bound, a hung vCenter
/// would block the cron run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Requests in flight at once, for the whole client.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 8;

/// Objects asked for per page of a property retrieval.
pub const PAGE_SIZE: u32 = 100;

/// Characters of an error body kept in a message.
const ERROR_BODY_LIMIT: usize = 500;

/// What replaces a secret in a message.
const MASK: &str = "***";

/// The cookie a SOAP login gives.
const SESSION_COOKIE: &str = "vmware_soap_session";

/// The header a REST session is carried in.
const REST_SESSION_HEADER: &str = "vmware-api-session-id";

const SOAP_PATH: &str = "sdk";
const VERSIONS_PATH: &str = "sdk/vimServiceVersions.xml";
const REST_SESSION_PATH: &str = "rest/com/vmware/cis/session";
const REST_TAG_PATH: &str = "rest/com/vmware/cis/tagging/tag";
const REST_ASSOCIATION_PATH: &str = "rest/com/vmware/cis/tagging/tag-association";

/// The account the client logs in with.
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

/// Why a call to vCenter failed. No message carries the account, its password
/// or a session. `call` is the SOAP operation, or the method and path of a
/// REST call.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The settings cannot make a client: nothing was sent.
    #[error("vSphere client: {0}")]
    Config(String),
    /// The server speaks no dialect of the API this build was written for.
    #[error("{0}")]
    Unsupported(String),
    /// vCenter answered a SOAP fault.
    #[error("{call}: {kind}: {message}")]
    Fault { call: String, kind: String, message: String },
    /// An HTTP status that is not a success, and no fault to explain it.
    #[error("{call} answered {status}: {message}")]
    Status { call: String, status: u16, message: String },
    /// No answer: refused, timed out, cut.
    #[error("{call}: {reason}")]
    Transport { call: String, reason: String },
    /// A successful answer that is not what the call returns.
    #[error("{call}: unexpected answer: {reason}")]
    Decode { call: String, reason: String },
    /// The session was gone when the collection ended. Without a session a
    /// vCenter answers a read with an empty result, not with a fault: nothing
    /// read in that session can be told from "no such object".
    #[error("the session ended before the collection did: what was read cannot be trusted")]
    SessionLost,
}

/// Settings of a [`VsphereClient`].
pub struct VsphereClientBuilder {
    url: String,
    credentials: Credentials,
    timeout: Duration,
    validate_certs: bool,
    ca_file: Option<PathBuf>,
    max_in_flight: usize,
}

impl VsphereClientBuilder {
    /// Time a request may take, 60 s by default.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether the certificate of vCenter is validated: yes by default.
    pub fn validate_certs(mut self, validate: bool) -> Self {
        self.validate_certs = validate;
        self
    }

    /// A PEM file of certificate authorities trusted on top of the system ones.
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
    pub fn build(self) -> Result<VsphereClient, ClientError> {
        let base = base_url(&self.url)?;
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
        Ok(VsphereClient {
            http,
            base,
            credentials: self.credentials,
            timeout: self.timeout,
            in_flight: Semaphore::new(self.max_in_flight.max(1)),
        })
    }
}

/// A URL as a message may show it: what precedes the last `@` of an
/// authority is an account, maybe with its password.
fn shown(url: &str) -> String {
    let Some(at) = url.rfind('@') else {
        return url.to_owned();
    };
    let start = url.find("://").map(|scheme| scheme + 3).filter(|start| *start <= at).unwrap_or(0);
    format!("{}{MASK}{}", &url[..start], &url[at..])
}

/// `https://vcenter.example` → `https://vcenter.example/`.
fn base_url(url: &str) -> Result<Url, ClientError> {
    let refused = |reason: &str| ClientError::Config(format!("vCenter URL {:?}: {reason}", shown(url)));
    let mut base = Url::parse(url).map_err(|error| refused(&error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(refused("not an http or https URL"));
    }
    // The account is given apart: one written in the URL would be sent as
    // well, and printed with the URL.
    if !base.username().is_empty() || base.password().is_some() {
        return Err(refused("credentials in the URL are refused"));
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
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

/// What an error answer says: its text, cut; the name of the status when it says nothing.
fn said(status: StatusCode, text: &str) -> String {
    let text: String = text.trim().chars().take(ERROR_BODY_LIMIT).collect();
    if text.is_empty() { status.canonical_reason().unwrap_or("no message").to_owned() } else { text }
}

/// A header value that reqwest and hyper never print.
fn sensitive(value: &str) -> Option<HeaderValue> {
    let mut header = HeaderValue::from_str(value).ok()?;
    header.set_sensitive(true);
    Some(header)
}

/// Every answer of the REST API wraps its payload in `value`.
#[derive(Deserialize)]
#[serde(bound = "T: DeserializeOwned")]
struct RestValue<T> {
    value: T,
}

/// What the client reads of a REST error.
#[derive(Deserialize)]
struct RestError {
    value: RestMessages,
}

#[derive(Deserialize)]
struct RestMessages {
    messages: Vec<RestMessage>,
}

#[derive(Deserialize)]
struct RestMessage {
    default_message: String,
}

/// What the client reads of a tag.
#[derive(Deserialize)]
struct TagDetails {
    name: String,
    #[serde(default)]
    description: String,
}

/// What a request gave: the status, the headers and the body as text.
struct Answer {
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    text: String,
}

/// A tag of vSphere and the objects that carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub description: String,
    pub objects: Vec<Tagged>,
}

/// A managed object, as the tagging API names it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Tagged {
    /// `VirtualMachine`, `ClusterComputeResource`, `Datacenter`.
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

pub struct VsphereClient {
    http: reqwest::Client,
    /// Ends with `/`.
    base: Url,
    credentials: Credentials,
    timeout: Duration,
    /// Shared by every call: the kinds of objects are read in parallel on one client.
    in_flight: Semaphore,
}

impl std::fmt::Debug for VsphereClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the password.
        formatter
            .debug_struct("VsphereClient")
            .field("url", &self.base.as_str())
            .field("user", &self.credentials.username)
            .finish_non_exhaustive()
    }
}

impl VsphereClient {
    /// A client of the vCenter at `url` (e.g. `https://vcenter.example`).
    pub fn builder(url: &str, credentials: Credentials) -> VsphereClientBuilder {
        VsphereClientBuilder {
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
        VsphereClient::builder(url, credentials).build()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Opens a SOAP session: the dialect the server lists, what it is, then
    /// the login. The password is not sent to a server whose API this build
    /// does not speak.
    pub async fn login(&self) -> Result<Session<'_>, ClientError> {
        let call = format!("GET /{VERSIONS_PATH}");
        let answer = self.send(&call, self.http.get(self.url(VERSIONS_PATH)?), &[]).await?;
        if !answer.status.is_success() {
            let message = self.scrub(&said(answer.status, &answer.text), &[]);
            return Err(ClientError::Status { call, status: answer.status.as_u16(), message });
        }
        let versions = soap::versions(&answer.text).map_err(|reason| ClientError::Decode { call, reason })?;
        let action = format!("{NAMESPACE}/{}", soap::dialect(&versions).map_err(ClientError::Unsupported)?);

        let operation = Operation::RetrieveServiceContent;
        let answer = self.soap(&action, None, &operation, &[]).await?;
        let content = soap::service_content(&answer.text).map_err(|reason| decode(&operation, reason))?;

        let Credentials { username, password } = &self.credentials;
        let operation = Operation::Login { session_manager: &content.session_manager, username, password };
        let answer = self.soap(&action, None, &operation, &[]).await?;
        let cookies = answer.headers.get_all(SET_COOKIE).iter().filter_map(|value| value.to_str().ok());
        let cookie_text = cookies
            .filter_map(|cookie| cookie.split(';').next())
            .map(str::trim)
            .find(|cookie| cookie.starts_with(SESSION_COOKIE) && cookie[SESSION_COOKIE.len()..].starts_with('='))
            .ok_or_else(|| decode(&operation, "no session cookie".to_owned()))?
            .to_owned();
        let cookie = sensitive(&cookie_text)
            .ok_or_else(|| decode(&operation, "a session cookie that cannot be sent".to_owned()))?;
        Ok(Session { client: self, action, cookie, cookie_text, content })
    }

    /// Every tag and the objects that carry it, read in a REST session opened
    /// and closed here. A tag that cannot be read fails the whole read: "no
    /// tag" must only ever mean that vCenter said so.
    pub async fn tags(&self) -> Result<Vec<Tag>, ClientError> {
        let url = self.url(REST_SESSION_PATH)?;
        let Credentials { username, password } = &self.credentials;
        let request = self.http.post(url.clone()).basic_auth(username, Some(password));
        let token: String = self.rest("POST", &url, request, &[]).await?;
        let header = sensitive(&token).ok_or_else(|| ClientError::Decode {
            call: format!("POST {}", url.path()),
            reason: "a session that cannot be sent".to_owned(),
        })?;
        let tags = self.read_tags(&token, &header).await;
        // Whatever was read: a session left open counts against the limit of the account.
        let close = self.http.delete(url).header(REST_SESSION_HEADER, header);
        let _ = self.send("DELETE session", close, &[&token]).await;
        tags
    }

    async fn read_tags(&self, token: &str, session: &HeaderValue) -> Result<Vec<Tag>, ClientError> {
        let list = self.url(REST_TAG_PATH)?;
        let request = self.http.get(list.clone()).header(REST_SESSION_HEADER, session);
        let ids: Vec<String> = self.rest("GET", &list, request, &[token]).await?;
        let read = |id: String| async move {
            let segment = format!("id:{id}");
            let details = self.url_with(REST_TAG_PATH, &segment)?;
            let request = self.http.get(details.clone()).header(REST_SESSION_HEADER, session);
            let details: TagDetails = self.rest("GET", &details, request, &[token]).await?;
            let mut objects = self.url_with(REST_ASSOCIATION_PATH, &segment)?;
            objects.set_query(Some("~action=list-attached-objects"));
            let request = self.http.post(objects.clone()).header(REST_SESSION_HEADER, session);
            let objects: Vec<Tagged> = self.rest("POST", &objects, request, &[token]).await?;
            Ok(Tag { name: details.name, description: details.description, objects })
        };
        // Every tag is read to its end before the first failure is returned:
        // nothing is still in flight when the session is closed.
        futures::future::join_all(ids.into_iter().map(read)).await.into_iter().collect()
    }

    /// A message without the account, its password nor a session, whatever
    /// put them there (vCenter, a proxy, a library), as given and as an XML
    /// body carries them.
    fn scrub(&self, message: &str, sessions: &[&str]) -> String {
        let Credentials { username, password } = &self.credentials;
        let escaped = [escape(password), escape(username)];
        // As the REST login sends them, in its Basic `Authorization` header.
        let basic = data_encoding::BASE64.encode(format!("{username}:{}", password.as_str()).as_bytes());
        let mut secrets: Vec<&str> = vec![password, username, &escaped[0], &escaped[1], &basic];
        secrets.extend(sessions);
        // The longest first: one secret may hold another.
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        let mut message = message.to_owned();
        for secret in secrets.into_iter().filter(|secret| !secret.is_empty()) {
            message = message.replace(secret, MASK);
        }
        message
    }

    fn url(&self, path: &str) -> Result<Url, ClientError> {
        self.base.join(path).map_err(|error| ClientError::Config(format!("path {path:?}: {error}")))
    }

    /// `path` and one more segment, encoded: an identifier read from vCenter
    /// cannot add a query nor climb out of the path.
    fn url_with(&self, path: &str, segment: &str) -> Result<Url, ClientError> {
        let mut url = self.url(path)?;
        url.path_segments_mut()
            .map_err(|()| ClientError::Config("the URL of vCenter takes no path".to_owned()))?
            .pop_if_empty()
            .push(segment);
        Ok(url)
    }

    /// Sends one request, within the limit of requests in flight.
    async fn send(
        &self,
        call: &str,
        request: reqwest::RequestBuilder,
        sessions: &[&str],
    ) -> Result<Answer, ClientError> {
        let broken =
            |reason: String| ClientError::Transport { call: call.to_owned(), reason: self.scrub(&reason, sessions) };
        let _permit = self.in_flight.acquire().await.map_err(|_| broken("the client is closed".to_owned()))?;
        // The URL is left out of the reason: the call is already in the message.
        let lost = |error: reqwest::Error| broken(chain(&error.without_url()));
        let response = request.send().await.map_err(lost)?;
        let (status, headers) = (response.status(), response.headers().clone());
        let bytes = response.bytes().await.map_err(lost)?;
        Ok(Answer { status, headers, text: String::from_utf8_lossy(&bytes).into_owned() })
    }

    /// Sends one SOAP operation and gives its answer when it is a result.
    async fn soap(
        &self,
        action: &str,
        cookie: Option<&HeaderValue>,
        operation: &Operation<'_>,
        sessions: &[&str],
    ) -> Result<Answer, ClientError> {
        let call = operation.name();
        let mut request = self
            .http
            .post(self.url(SOAP_PATH)?)
            .header(CONTENT_TYPE, "text/xml; charset=utf-8")
            .header("SOAPAction", action)
            .body(operation.envelope());
        if let Some(cookie) = cookie {
            request = request.header(COOKIE, cookie);
        }
        let answer = self.send(call, request, sessions).await?;
        // A fault comes with a status 500: it is read first, it says more.
        if let Ok(Some(fault)) = soap::fault(&answer.text) {
            let message = self.scrub(&fault.message, sessions);
            return Err(ClientError::Fault { call: call.to_owned(), kind: fault.kind, message });
        }
        if !answer.status.is_success() {
            let message = self.scrub(&said(answer.status, &answer.text), sessions);
            return Err(ClientError::Status { call: call.to_owned(), status: answer.status.as_u16(), message });
        }
        Ok(answer)
    }

    /// Sends one REST call and gives what its answer holds under `value`.
    async fn rest<T: DeserializeOwned>(
        &self,
        verb: &str,
        url: &Url,
        request: reqwest::RequestBuilder,
        sessions: &[&str],
    ) -> Result<T, ClientError> {
        let call = format!("{verb} {}", url.path());
        let answer = self.send(&call, request.header(ACCEPT, "application/json"), sessions).await?;
        if !answer.status.is_success() {
            let messages = serde_json::from_str::<RestError>(&answer.text).ok().map(|error| {
                error.value.messages.into_iter().map(|message| message.default_message).collect::<Vec<_>>().join(" ")
            });
            let message = self.scrub(&said(answer.status, &messages.unwrap_or(answer.text)), sessions);
            return Err(ClientError::Status { call, status: answer.status.as_u16(), message });
        }
        // The reason of serde is not kept: it may quote the answer, which may hold a session.
        serde_json::from_str::<RestValue<T>>(&answer.text)
            .map(|wrapped| wrapped.value)
            .map_err(|_| ClientError::Decode { call, reason: "not the expected value".to_owned() })
    }
}

/// An answer to `operation` that is not what the operation returns.
fn decode(operation: &Operation<'_>, reason: String) -> ClientError {
    ClientError::Decode { call: operation.name().to_owned(), reason }
}

/// A SOAP session. It ends with [`Session::logout`]; a session left open ends
/// by itself on the server after its idle time.
pub struct Session<'c> {
    client: &'c VsphereClient,
    /// The `SOAPAction` value: the namespace and the dialect.
    action: String,
    /// The whole `Cookie` value.
    cookie: HeaderValue,
    /// Kept to be scrubbed from the error messages only.
    cookie_text: String,
    content: ServiceContent,
}

impl std::fmt::Debug for Session<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the cookie.
        formatter
            .debug_struct("Session")
            .field("action", &self.action)
            .field("server", &self.content.full_name)
            .finish()
    }
}

impl Session<'_> {
    /// What the server said it is.
    pub fn content(&self) -> &ServiceContent {
        &self.content
    }

    /// Every object of `kind` in the inventory, with these properties, in the
    /// order vCenter gives them. The view made for it is released whatever
    /// the retrieval returned.
    pub async fn objects(&self, kind: &str, properties: &[&str]) -> Result<Vec<ObjectContent>, ClientError> {
        let ServiceContent { view_manager, root_folder, .. } = &self.content;
        let operation = Operation::CreateContainerView { view_manager, root: root_folder, kind };
        let view = soap::view(&self.call(&operation).await?).map_err(|reason| decode(&operation, reason))?;
        let objects = self.pages(&view, kind, properties).await;
        // A view lives as long as the session: one that cannot be released ends with it.
        let _ = self.call(&Operation::DestroyView { view: &view }).await;
        objects
    }

    async fn pages(&self, view: &str, kind: &str, properties: &[&str]) -> Result<Vec<ObjectContent>, ClientError> {
        let collector = self.content.property_collector.as_str();
        let first = Operation::RetrieveProperties { collector, view, kind, properties, page_size: PAGE_SIZE };
        let mut page = soap::page(&self.call(&first).await?).map_err(|reason| decode(&first, reason))?;
        let mut objects = std::mem::take(&mut page.objects);
        while let Some(token) = page.token {
            let next = Operation::ContinueRetrieveProperties { collector, token: &token };
            page = soap::page(&self.call(&next).await?).map_err(|reason| decode(&next, reason))?;
            // A server that keeps promising a page and gives nothing would never end.
            if page.objects.is_empty() && page.token.is_some() {
                return Err(decode(&next, "an empty page followed by another".to_owned()));
            }
            objects.append(&mut page.objects);
        }
        Ok(objects)
    }

    /// Sends one operation in this session and gives the text of its result.
    async fn call(&self, operation: &Operation<'_>) -> Result<String, ClientError> {
        // The cookie as it is sent, and the session key it holds between quotes.
        let key = self.cookie_text.split_once('=').map_or("", |(_, value)| value.trim_matches('"'));
        let sessions = [self.cookie_text.as_str(), key];
        Ok(self.client.soap(&self.action, Some(&self.cookie), operation, &sessions).await?.text)
    }

    /// The switch port each physical card of a host hears, asked of the
    /// network system of the host (`configManager.networkSystem`).
    pub async fn network_hint(&self, network_system: &str) -> Result<Vec<CardHint>, ClientError> {
        let operation = Operation::QueryNetworkHint { network_system };
        soap::network_hints(&self.call(&operation).await?).map_err(|reason| decode(&operation, reason))
    }

    /// Fails with [`ClientError::SessionLost`] when the session is gone. To
    /// be called once everything is read: a session does not come back, so one
    /// that lives at the end lived all along.
    pub async fn ensure_alive(&self) -> Result<(), ClientError> {
        let ServiceContent { property_collector, session_manager, .. } = &self.content;
        let operation = Operation::RetrieveCurrentSession { collector: property_collector, session_manager };
        let alive =
            soap::session_is_alive(&self.call(&operation).await?).map_err(|reason| decode(&operation, reason))?;
        if alive { Ok(()) } else { Err(ClientError::SessionLost) }
    }

    /// Ends the session.
    pub async fn logout(self) -> Result<(), ClientError> {
        self.call(&Operation::Logout { session_manager: &self.content.session_manager }).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../tests/fixtures/6.7/", $name))
        };
    }

    const SENTINEL_USER: &str = "0perator-never-shown@vsphere.local";
    const SENTINEL_PASSWORD: &str = "s3ntinel <pass>&word";
    /// The same password as an XML body carries it.
    const SENTINEL_PASSWORD_XML: &str = "s3ntinel &lt;pass&gt;&amp;word";
    const SENTINEL_COOKIE: &str = "vmware_soap_session=\"5e55105e-0000-4000-8000-c00k1e000000\"";
    const SENTINEL_REST_SESSION: &str = "00000000000000000000000000000001";

    const VM_PROPERTIES: [&str; 2] = ["name", "runtime.host"];

    fn credentials() -> Credentials {
        Credentials::new(SENTINEL_USER, SENTINEL_PASSWORD)
    }

    fn client(server: &MockServer) -> VsphereClient {
        VsphereClient::new(&server.uri(), credentials()).unwrap()
    }

    fn xml(status: u16, body: &str) -> ResponseTemplate {
        ResponseTemplate::new(status).set_body_raw(body.to_owned(), "text/xml; charset=utf-8")
    }

    /// One SOAP operation, told by a piece of its body.
    async fn mount_soap(server: &MockServer, piece: &str, answer: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/sdk"))
            .and(body_string_contains(piece))
            .respond_with(answer)
            .mount(server)
            .await;
    }

    async fn mount_versions(server: &MockServer, document: &str) {
        let answer = ResponseTemplate::new(200).set_body_raw(document.to_owned(), "text/xml");
        Mock::given(method("GET")).and(path("/sdk/vimServiceVersions.xml")).respond_with(answer).mount(server).await;
    }

    /// The cookie, with the attributes a vCenter 6.7 was seen sending.
    fn login_answer() -> ResponseTemplate {
        xml(200, fixture!("Login.xml"))
            .insert_header("Set-Cookie", format!("{SENTINEL_COOKIE}; Path=/; HttpOnly; Secure; "))
    }

    /// What comes before any object is read.
    async fn mount_opening(server: &MockServer) {
        mount_versions(server, fixture!("vimServiceVersions.xml")).await;
        mount_soap(server, "<vim25:RetrieveServiceContent>", xml(200, fixture!("RetrieveServiceContent.xml"))).await;
        mount_soap(server, "<vim25:Login>", login_answer()).await;
    }

    /// A vCenter answering what the one of the fixtures answered.
    async fn vcenter() -> MockServer {
        let server = MockServer::start().await;
        mount_opening(&server).await;
        let views = [
            (
                "Datacenter",
                fixture!("CreateContainerView.Datacenter.xml"),
                fixture!("RetrievePropertiesEx.Datacenter.0.xml"),
            ),
            (
                "VirtualMachine",
                fixture!("CreateContainerView.VirtualMachine.xml"),
                fixture!("RetrievePropertiesEx.VirtualMachine.0.xml"),
            ),
            (
                "DistributedVirtualSwitch",
                fixture!("CreateContainerView.DistributedVirtualSwitch.xml"),
                fixture!("RetrievePropertiesEx.DistributedVirtualSwitch.0.xml"),
            ),
        ];
        for (kind, view, page) in views {
            let of_kind = format!("<vim25:type>{kind}</vim25:type><vim25:recursive>");
            mount_soap(&server, &of_kind, xml(200, view)).await;
            let properties = format!("<vim25:propSet><vim25:type>{kind}</vim25:type>");
            mount_soap(&server, &properties, xml(200, page)).await;
        }
        let next = "<vim25:ContinueRetrievePropertiesEx>";
        mount_soap(&server, next, xml(200, fixture!("RetrievePropertiesEx.VirtualMachine.1.xml"))).await;
        mount_soap(&server, "<vim25:DestroyView>", xml(200, fixture!("DestroyView.Datacenter.xml"))).await;
        mount_soap(
            &server,
            "<vim25:pathSet>currentSession",
            xml(200, fixture!("RetrievePropertiesEx.SessionManager.0.xml")),
        )
        .await;
        mount_soap(&server, "<vim25:Logout>", xml(200, fixture!("Logout.xml"))).await;
        server
    }

    fn body(request: &Request) -> String {
        String::from_utf8(request.body.clone()).unwrap()
    }

    /// The SOAP method of each request received, or its HTTP method and path.
    async fn calls(server: &MockServer) -> Vec<String> {
        let requests = server.received_requests().await.unwrap();
        requests
            .iter()
            .map(|request| {
                let body = body(request);
                match body.split_once("<soapenv:Body><vim25:") {
                    Some((_, rest)) => rest.split('>').next().unwrap().to_owned(),
                    None => format!("{} {}", request.method, request.url.path()),
                }
            })
            .collect()
    }

    fn header_of<'r>(request: &'r Request, name: &str) -> Option<&'r str> {
        request.headers.get(name).map(|value| value.to_str().unwrap())
    }

    /// Everything an error can show.
    fn shown(error: &ClientError) -> String {
        format!("{error} {error:?}")
    }

    fn assert_no_secret(text: &str) {
        for secret in [SENTINEL_PASSWORD, SENTINEL_PASSWORD_XML, SENTINEL_USER, "5e55105e-0000-4000-8000-c00k1e000000"]
        {
            assert!(!text.contains(secret), "{text}");
        }
    }

    // Settings

    #[test]
    fn a_url_that_cannot_be_a_vcenter_is_refused_before_anything_is_sent() {
        let refused = |url: &str| VsphereClient::new(url, credentials()).expect_err("refused").to_string();
        assert_eq!(
            refused("ftp://vc.example"),
            "vSphere client: vCenter URL \"ftp://vc.example\": not an http or https URL"
        );
        assert!(refused("vc.example").starts_with("vSphere client: vCenter URL \"vc.example\": "));
    }

    #[test]
    fn credentials_written_in_the_url_are_refused_without_being_shown() {
        let error = VsphereClient::new("https://root:hunter2@vc.example", credentials()).expect_err("refused");
        assert_eq!(
            error.to_string(),
            "vSphere client: vCenter URL \"https://***@vc.example\": credentials in the URL are refused"
        );
    }

    #[test]
    fn a_ca_file_that_cannot_be_used_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.pem");
        let error =
            VsphereClient::builder("https://vc.example", credentials()).ca_file(&missing).build().expect_err("refused");
        assert!(error.to_string().starts_with(&format!("vSphere client: CA file {}: ", missing.display())), "{error}");
        let empty = directory.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let error =
            VsphereClient::builder("https://vc.example", credentials()).ca_file(&empty).build().expect_err("refused");
        assert_eq!(error.to_string(), format!("vSphere client: CA file {}: no certificate found", empty.display()));
    }

    #[test]
    fn the_password_never_shows_in_debug_output() {
        let client = VsphereClient::new("https://vc.example", credentials()).unwrap();
        let shown = format!("{client:?} {:?}", credentials());
        assert!(!shown.contains(SENTINEL_PASSWORD), "{shown}");
        assert!(shown.contains("https://vc.example/"), "{shown}");
    }

    // The SOAP session

    #[tokio::test]
    async fn a_login_asks_the_versions_then_the_content_then_logs_in() {
        let server = vcenter().await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        assert_eq!(session.content().full_name, "VMware vCenter Server 6.7.0 build-22509751");
        assert_eq!(calls(&server).await, ["GET /sdk/vimServiceVersions.xml", "RetrieveServiceContent", "Login"]);
        let requests = server.received_requests().await.unwrap();
        // The dialect, on every SOAP request; no cookie before the login gave one.
        assert_eq!(header_of(&requests[1], "SOAPAction"), Some("urn:vim25/6.7"));
        assert_eq!(header_of(&requests[2], "SOAPAction"), Some("urn:vim25/6.7"));
        assert_eq!(header_of(&requests[1], "Content-Type"), Some("text/xml; charset=utf-8"));
        assert_eq!((header_of(&requests[1], "Cookie"), header_of(&requests[2], "Cookie")), (None, None));
        let login = body(&requests[2]);
        assert!(login.contains("<vim25:userName>0perator-never-shown@vsphere.local</vim25:userName>"), "{login}");
        assert!(login.contains(&format!("<vim25:password>{SENTINEL_PASSWORD_XML}</vim25:password>")), "{login}");
    }

    #[tokio::test]
    async fn the_objects_of_a_kind_are_read_through_a_view_released_afterwards() {
        let server = vcenter().await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        let datacenters = session.objects("Datacenter", &["name", "parent"]).await.expect("datacenters");
        assert_eq!(datacenters.len(), 1);
        assert_eq!((datacenters[0].id.as_str(), datacenters[0].text("name")), ("datacenter-2", Some("DC1")));
        assert_eq!(calls(&server).await[3..], ["CreateContainerView", "RetrievePropertiesEx", "DestroyView"]);
        let requests = server.received_requests().await.unwrap();
        // The session cookie, on every request after the login.
        for request in &requests[3..] {
            assert_eq!(header_of(request, "Cookie"), Some(SENTINEL_COOKIE));
        }
        let view = "session[00000000-0000-4000-8000-000000000001]00000000-0000-4000-8000-000000000002";
        let retrieval = body(&requests[4]);
        assert!(retrieval.contains(&format!("<vim25:obj type=\"ContainerView\">{view}</vim25:obj>")), "{retrieval}");
        assert!(
            retrieval.contains("<vim25:pathSet>name</vim25:pathSet><vim25:pathSet>parent</vim25:pathSet>"),
            "{retrieval}"
        );
        assert!(retrieval.contains("<vim25:maxObjects>100</vim25:maxObjects>"), "{retrieval}");
        let destroyed = body(&requests[5]);
        assert!(
            destroyed.contains(&format!("<vim25:_this type=\"ContainerView\">{view}</vim25:_this>")),
            "{destroyed}"
        );
    }

    #[tokio::test]
    async fn the_network_hint_of_a_host_is_asked_as_a_read_in_the_session() {
        let server = vcenter().await;
        let hint = "<vim25:_this type=\"HostNetworkSystem\">networkSystem-10</vim25:_this>";
        mount_soap(&server, hint, xml(200, fixture!("QueryNetworkHint.networkSystem-10.xml"))).await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        let cards = session.network_hint("networkSystem-10").await.expect("hint");
        // <device>vmnic0</device>, <device>vmnic1</device>, <device>vusb0</device>
        let devices: Vec<&str> = cards.iter().map(|card| card.device.as_str()).collect();
        assert_eq!(devices, ["vmnic0", "vmnic1", "vusb0"]);
        assert_eq!(calls(&server).await[3..], ["QueryNetworkHint"]);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(header_of(&requests[3], "Cookie"), Some(SENTINEL_COOKIE));
        assert!(body(&requests[3]).contains(hint), "{}", body(&requests[3]));
    }

    #[tokio::test]
    async fn every_page_is_read_in_order() {
        let server = vcenter().await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        let machines = session.objects("VirtualMachine", &VM_PROPERTIES).await.expect("machines");
        // 100 on the first page, 66 on the second.
        assert_eq!(machines.len(), 166);
        assert_eq!(machines[165].id, "vm-12265");
        assert_eq!(
            calls(&server).await[3..],
            ["CreateContainerView", "RetrievePropertiesEx", "ContinueRetrievePropertiesEx", "DestroyView"]
        );
        let requests = server.received_requests().await.unwrap();
        assert!(body(&requests[5]).contains("<vim25:token>0</vim25:token>"));
    }

    #[tokio::test]
    async fn a_kind_without_object_is_an_empty_list() {
        let server = vcenter().await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        assert_eq!(session.objects("DistributedVirtualSwitch", &["name", "uuid"]).await, Ok(Vec::new()));
    }

    #[tokio::test]
    async fn a_whole_session_only_sends_reads_and_session_operations() {
        let server = vcenter().await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        session.objects("Datacenter", &["name"]).await.expect("datacenters");
        session.objects("VirtualMachine", &VM_PROPERTIES).await.expect("machines");
        session.ensure_alive().await.expect("alive");
        session.logout().await.expect("logout");
        let allowed = [
            "GET /sdk/vimServiceVersions.xml",
            "RetrieveServiceContent",
            "Login",
            "CreateContainerView",
            "RetrievePropertiesEx",
            "ContinueRetrievePropertiesEx",
            "DestroyView",
            "Logout",
        ];
        let sent = calls(&server).await;
        assert_eq!(sent.len(), 12);
        for call in &sent {
            assert!(allowed.contains(&call.as_str()), "{call}");
        }
        assert_eq!(sent.last().map(String::as_str), Some("Logout"));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(header_of(requests.last().unwrap(), "Cookie"), Some(SENTINEL_COOKIE));
    }

    #[tokio::test]
    async fn the_password_is_not_sent_to_a_server_of_another_api() {
        let server = MockServer::start().await;
        let older = "<namespaces version=\"1.0\"><namespace><name>urn:vim25</name><version>6.5</version>\
                     <priorVersions><version>6.0</version></priorVersions></namespace></namespaces>";
        mount_versions(&server, older).await;
        let client = client(&server);
        let error = client.login().await.expect_err("unsupported");
        assert_eq!(error.to_string(), "the server speaks vSphere API 6.5, 6.0 and this build speaks 6.7");
        assert_eq!(calls(&server).await, ["GET /sdk/vimServiceVersions.xml"]);
    }

    #[tokio::test]
    async fn a_refused_login_is_a_fault_that_names_no_account() {
        let server = MockServer::start().await;
        mount_versions(&server, fixture!("vimServiceVersions.xml")).await;
        mount_soap(&server, "<vim25:RetrieveServiceContent>", xml(200, fixture!("RetrieveServiceContent.xml"))).await;
        // Written by hand in the shape of the observed faults: a wrong password
        // was never tried on a real vCenter. The server repeats what it was sent.
        let refusal = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope \
             xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><soapenv:Body><soapenv:Fault>\
             <faultcode>ServerFaultCode</faultcode><faultstring>Cannot complete login of {SENTINEL_USER} with \
             {SENTINEL_PASSWORD_XML} due to an incorrect user name or password.</faultstring><detail>\
             <InvalidLoginFault xmlns=\"urn:vim25\" xsi:type=\"InvalidLogin\"></InvalidLoginFault></detail>\
             </soapenv:Fault></soapenv:Body></soapenv:Envelope>"
        );
        mount_soap(&server, "<vim25:Login>", xml(500, &refusal)).await;
        let client = client(&server);
        let error = client.login().await.expect_err("refused");
        assert_eq!(
            error,
            ClientError::Fault {
                call: "Login".to_owned(),
                kind: "InvalidLogin".to_owned(),
                message: "Cannot complete login of *** with *** due to an incorrect user name or password.".to_owned()
            }
        );
        assert_eq!(
            error.to_string(),
            "Login: InvalidLogin: Cannot complete login of *** with *** due to an incorrect user name or password."
        );
        assert_no_secret(&shown(&error));
    }

    #[tokio::test]
    async fn a_login_without_session_cookie_is_refused() {
        let server = MockServer::start().await;
        mount_versions(&server, fixture!("vimServiceVersions.xml")).await;
        mount_soap(&server, "<vim25:RetrieveServiceContent>", xml(200, fixture!("RetrieveServiceContent.xml"))).await;
        mount_soap(&server, "<vim25:Login>", xml(200, fixture!("Login.xml"))).await;
        let client = client(&server);
        let error = client.login().await.expect_err("no cookie");
        assert_eq!(error.to_string(), "Login: unexpected answer: no session cookie");
    }

    #[tokio::test]
    async fn a_view_is_released_when_its_retrieval_fails() {
        let server = MockServer::start().await;
        mount_opening(&server).await;
        mount_soap(&server, "<vim25:CreateContainerView>", xml(200, fixture!("CreateContainerView.Datacenter.xml")))
            .await;
        mount_soap(
            &server,
            "<vim25:RetrievePropertiesEx>",
            xml(500, fixture!("fault.ContinueRetrievePropertiesEx.xml")),
        )
        .await;
        mount_soap(&server, "<vim25:DestroyView>", xml(200, fixture!("DestroyView.Datacenter.xml"))).await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        let error = session.objects("Datacenter", &["name"]).await.expect_err("fault");
        assert_eq!(
            error.to_string(),
            "RetrievePropertiesEx: InvalidArgument: A specified parameter was not correct: token"
        );
        assert_eq!(calls(&server).await[3..], ["CreateContainerView", "RetrievePropertiesEx", "DestroyView"]);
    }

    #[tokio::test]
    async fn a_view_refused_for_want_of_a_session_is_a_fault() {
        let server = MockServer::start().await;
        mount_opening(&server).await;
        mount_soap(
            &server,
            "<vim25:CreateContainerView>",
            xml(500, fixture!("CreateContainerView.unauthenticated.xml")),
        )
        .await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        let error = session.objects("Datacenter", &["name"]).await.expect_err("fault");
        assert_eq!(error.to_string(), "CreateContainerView: NotAuthenticated: The session is not authenticated.");
        // No view was made: none is released.
        assert_eq!(calls(&server).await[3..], ["CreateContainerView"]);
    }

    #[tokio::test]
    async fn the_session_cookie_is_never_shown_by_an_error() {
        let server = MockServer::start().await;
        mount_opening(&server).await;
        let echo = format!("no such session: 5e55105e-0000-4000-8000-c00k1e000000 ({SENTINEL_COOKIE})");
        mount_soap(&server, "<vim25:CreateContainerView>", ResponseTemplate::new(503).set_body_string(echo)).await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        let error = session.objects("Datacenter", &["name"]).await.expect_err("unavailable");
        assert_eq!(error.to_string(), "CreateContainerView answered 503: no such session: *** (***)");
        assert_no_secret(&format!("{} {session:?}", shown(&error)));
    }

    #[tokio::test]
    async fn a_session_that_lives_at_the_end_is_told_from_one_that_does_not() {
        let server = vcenter().await;
        let client = client(&server);
        let session = client.login().await.expect("session");
        assert_eq!(session.ensure_alive().await, Ok(()));

        let dead = MockServer::start().await;
        mount_opening(&dead).await;
        let gone = xml(200, fixture!("RetrievePropertiesEx.SessionManager.unauthenticated.xml"));
        mount_soap(&dead, "<vim25:pathSet>currentSession", gone).await;
        let client = super::tests::client(&dead);
        let session = client.login().await.expect("session");
        let error = session.ensure_alive().await.expect_err("lost");
        assert_eq!(error, ClientError::SessionLost);
        assert_eq!(error.to_string(), "the session ended before the collection did: what was read cannot be trusted");
    }

    #[tokio::test]
    async fn an_answer_that_is_not_soap_is_an_error_without_the_secrets_it_repeats() {
        let server = MockServer::start().await;
        mount_versions(&server, fixture!("vimServiceVersions.xml")).await;
        let echo = format!("<html>Bad gateway for {SENTINEL_USER} {SENTINEL_PASSWORD_XML} {SENTINEL_PASSWORD}</html>");
        mount_soap(&server, "<vim25:RetrieveServiceContent>", ResponseTemplate::new(502).set_body_string(echo)).await;
        let client = client(&server);
        let error = client.login().await.expect_err("bad gateway");
        assert_eq!(error.to_string(), "RetrieveServiceContent answered 502: <html>Bad gateway for *** *** ***</html>");
        assert_no_secret(&shown(&error));
    }

    #[tokio::test]
    async fn a_successful_answer_that_is_not_the_expected_one_is_an_error() {
        let server = MockServer::start().await;
        mount_versions(&server, fixture!("vimServiceVersions.xml")).await;
        mount_soap(&server, "<vim25:RetrieveServiceContent>", xml(200, fixture!("Logout.xml"))).await;
        let client = client(&server);
        let error = client.login().await.expect_err("not a content");
        assert_eq!(
            error.to_string(),
            "RetrieveServiceContent: unexpected answer: no RetrieveServiceContentResponse in the answer"
        );
    }

    #[tokio::test]
    async fn a_vcenter_that_cannot_be_reached_is_an_error_that_names_no_account() {
        // A port nothing listens on: bound, then released.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let uri = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = VsphereClient::new(&uri, credentials()).unwrap();
        let error = client.login().await.expect_err("unreachable");
        assert!(
            matches!(&error, ClientError::Transport { call, .. } if call == "GET /sdk/vimServiceVersions.xml"),
            "{error:?}"
        );
        assert_no_secret(&shown(&error));
    }

    // The tags, over REST

    /// The REST side of the vCenter of the fixtures.
    async fn tagging(server: &MockServer) {
        let session = "/rest/com/vmware/cis/session";
        Mock::given(method("POST"))
            .and(path(session))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture!("rest.session.json")))
            .mount(server)
            .await;
        Mock::given(method("DELETE")).and(path(session)).respond_with(ResponseTemplate::new(200)).mount(server).await;
        let list: Value = serde_json::from_str(fixture!("rest.tag.list.json")).unwrap();
        Mock::given(method("GET"))
            .and(path("/rest/com/vmware/cis/tagging/tag"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&list))
            .mount(server)
            .await;
        let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/6.7");
        for (index, id) in list["value"].as_array().unwrap().iter().enumerate() {
            let id = id.as_str().unwrap();
            let read = |name: String| std::fs::read_to_string(format!("{directory}/{name}")).unwrap();
            Mock::given(method("GET"))
                .and(path(format!("/rest/com/vmware/cis/tagging/tag/id:{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(read(format!("rest.tag.{index}.json"))))
                .mount(server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/rest/com/vmware/cis/tagging/tag-association/id:{id}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string(read(format!("rest.tag.{index}.attached-objects.json"))),
                )
                .mount(server)
                .await;
        }
    }

    #[tokio::test]
    async fn every_tag_is_read_with_the_objects_that_carry_it() {
        let server = MockServer::start().await;
        tagging(&server).await;
        let client = client(&server);
        let tags = client.tags().await.expect("tags");
        assert_eq!(tags.len(), 28);
        // In the order of the list: `rest.tag.0.json` first.
        assert_eq!(
            tags[0],
            Tag {
                name: "service-rabbit".to_owned(),
                description: String::new(),
                objects: vec![Tagged { kind: "VirtualMachine".to_owned(), id: "vm-342".to_owned() }]
            }
        );
    }

    // A vCenter, or a proxy, that echoes the request in a refusal shows the
    // Basic account of the REST login: base64 of the user and the password.
    #[tokio::test]
    async fn a_refused_rest_login_never_shows_the_encoded_account() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/com/vmware/cis/session"))
            .respond_with(|request: &Request| {
                let echoed = header_of(request, "Authorization").unwrap_or_default().to_owned();
                ResponseTemplate::new(401).set_body_string(format!("refused: {echoed}"))
            })
            .mount(&server)
            .await;
        let text = shown(&client(&server).tags().await.unwrap_err());
        assert!(!text.contains("MHBlcmF0b3ItbmV2ZXItc2hvd25AdnNwaGVyZS5sb2NhbDpzM250aW5lbCA8cGFzcz4md29yZA"), "{text}");
        assert_no_secret(&text);
    }

    #[tokio::test]
    async fn the_tags_are_read_in_a_session_opened_and_closed_for_them() {
        let server = MockServer::start().await;
        tagging(&server).await;
        let client = client(&server);
        client.tags().await.expect("tags");
        let requests = server.received_requests().await.unwrap();
        let first = &requests[0];
        assert_eq!((first.method.as_str(), first.url.path()), ("POST", "/rest/com/vmware/cis/session"));
        // base64 of the account and the password, as HTTP basic authentication carries them.
        assert_eq!(
            header_of(first, "Authorization"),
            Some("Basic MHBlcmF0b3ItbmV2ZXItc2hvd25AdnNwaGVyZS5sb2NhbDpzM250aW5lbCA8cGFzcz4md29yZA==")
        );
        let last = requests.last().unwrap();
        assert_eq!((last.method.as_str(), last.url.path()), ("DELETE", "/rest/com/vmware/cis/session"));
        for request in &requests[1..] {
            // The session, never the account again.
            assert_eq!(header_of(request, "vmware-api-session-id"), Some(SENTINEL_REST_SESSION));
            assert_eq!(header_of(request, "Authorization"), None);
        }
        // One list, then one read and one list of objects per tag, and the two session calls.
        assert_eq!(requests.len(), 2 + 1 + 2 * 28);
        for request in &requests[1..requests.len() - 1] {
            let path = request.url.path();
            let reads_a_tag = request.method.as_str() == "GET" && path.starts_with("/rest/com/vmware/cis/tagging/tag");
            let lists_objects = request.method.as_str() == "POST"
                && path.starts_with("/rest/com/vmware/cis/tagging/tag-association/id:")
                && request.url.query() == Some("~action=list-attached-objects");
            assert!(reads_a_tag || lists_objects, "{} {}", request.method, request.url);
        }
    }

    #[tokio::test]
    async fn a_tag_that_cannot_be_read_fails_the_whole_read_and_the_session_is_closed() {
        let server = MockServer::start().await;
        let refused = ResponseTemplate::new(401).set_body_string(fixture!("rest.unauthenticated.json"));
        Mock::given(method("GET"))
            .and(path("/rest/com/vmware/cis/tagging/tag/id:urn:vmomi:InventoryServiceTag:00000000-0000-4000-8000-00000000027c:GLOBAL"))
            .respond_with(refused)
            .with_priority(1)
            .mount(&server)
            .await;
        tagging(&server).await;
        let client = client(&server);
        let error = client.tags().await.expect_err("refused");
        assert_eq!(
            error.to_string(),
            "GET /rest/com/vmware/cis/tagging/tag/id:urn:vmomi:InventoryServiceTag:00000000-0000-4000-8000-00000000027c:GLOBAL \
             answered 401: This method requires authentication."
        );
        let requests = server.received_requests().await.unwrap();
        let last = requests.last().unwrap();
        assert_eq!((last.method.as_str(), last.url.path()), ("DELETE", "/rest/com/vmware/cis/session"));
    }

    #[tokio::test]
    async fn a_refused_rest_login_names_no_account() {
        let server = MockServer::start().await;
        let echo = json!({"type": "com.vmware.vapi.std.errors.unauthenticated", "value": {"messages": [
            {"args": [], "default_message": format!("Authentication of {SENTINEL_USER} with {SENTINEL_PASSWORD} failed."), "id": "x"}
        ]}});
        Mock::given(method("POST"))
            .and(path("/rest/com/vmware/cis/session"))
            .respond_with(ResponseTemplate::new(401).set_body_json(echo))
            .mount(&server)
            .await;
        let client = client(&server);
        let error = client.tags().await.expect_err("refused");
        assert_eq!(
            error.to_string(),
            "POST /rest/com/vmware/cis/session answered 401: Authentication of *** with *** failed."
        );
        assert_no_secret(&shown(&error));
        // No session was opened: none is closed.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_rest_session_is_never_shown_by_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/com/vmware/cis/session"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"value": "5e55105e5e55105e5e55105e5e55105e"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(header("vmware-api-session-id", "5e55105e5e55105e5e55105e5e55105e"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string("session 5e55105e5e55105e5e55105e5e55105e is broken"),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        let client = client(&server);
        let error = client.tags().await.expect_err("broken");
        assert_eq!(error.to_string(), "GET /rest/com/vmware/cis/tagging/tag answered 500: session *** is broken");
    }
}
