//! The four NetBox operations the tool needs, over the REST API.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::try_join_all;
use omnisync_core::{Filters, Gateway, GatewayError, Row, Write};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Certificate, Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::sync::{OnceCell, Semaphore};
use url::{Position, Url};

use crate::inventory_apply::DryRun;
use crate::version::NetboxVersion;

/// Seconds a request may take before it fails: without a bound, a hung NetBox
/// would block the cron run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Time the OpenAPI schema may take: NetBox builds it when it is asked for,
/// then keeps it a day per release (`cache_page` in `netbox/urls.py`), so the
/// first run after a start or an upgrade pays for it: 2 s on a fresh 4.5.10 or
/// 4.7.5 (Docker on a laptop, 2026-11-24), longer on a slow or busy host. The
/// bound stays well above the timeout of a request, so that a slow build never
/// stops a run.
pub const SCHEMA_TIMEOUT: Duration = Duration::from_secs(300);

/// The first wait before replaying a read; doubled at each retry.
pub const RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// How many times a read answered by a gateway error is replayed.
pub const RETRIES: u32 = 3;

/// Requests in flight at once, for the whole client.
pub const MAX_IN_FLIGHT: usize = 4;

/// Objects asked per page. NetBox may cap it (MAX_PAGE_SIZE): the size of the
/// first page it returns is then the one used for the following pages.
pub const DEFAULT_PAGE_SIZE: usize = 250;

/// Settings of a [`NetboxClient`].
pub struct NetboxClientBuilder {
    url: String,
    token: String,
    timeout: Duration,
    schema_timeout: Duration,
    retry_backoff: Duration,
    page_size: usize,
    dry_run: bool,
    validate_certs: bool,
    ca_file: Option<PathBuf>,
}

impl NetboxClientBuilder {
    /// Time a request may take, 60 s by default.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Time the OpenAPI schema may take, 300 s by default; never less than
    /// [`timeout`](Self::timeout).
    pub fn schema_timeout(mut self, timeout: Duration) -> Self {
        self.schema_timeout = timeout;
        self
    }

    /// First wait before replaying a read, 0.5 s by default; doubled at each retry.
    pub fn retry_backoff(mut self, backoff: Duration) -> Self {
        self.retry_backoff = backoff;
        self
    }

    /// Objects asked per page.
    pub fn page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size;
        self
    }

    /// A dry run refuses every write before sending anything.
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Whether the certificate of NetBox is validated: yes by default.
    pub fn validate_certs(mut self, validate: bool) -> Self {
        self.validate_certs = validate;
        self
    }

    /// A PEM file of certificate authorities trusted on top of the system ones.
    pub fn ca_file(mut self, path: impl AsRef<Path>) -> Self {
        self.ca_file = Some(path.as_ref().to_owned());
        self
    }

    pub fn build(self) -> Result<NetboxClient, GatewayError> {
        let api = api_url(&self.url)?;
        // A v2 token carries its own prefix; anything else is a v1 token.
        let scheme = if self.token.starts_with("nbt_") { "Bearer" } else { "Token" };
        // The header value is never printed: neither here nor by reqwest, which is told it is sensitive.
        let mut authorization = HeaderValue::from_str(&format!("{scheme} {}", self.token))
            .map_err(|_| GatewayError::Request("the NetBox token cannot be sent as an HTTP header".to_owned()))?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        // Without a bound a request waits forever: a hung NetBox would block the cron run.
        // Never the proxy of the environment: the token would leave for another host.
        let mut http = reqwest::Client::builder().timeout(self.timeout).default_headers(headers).no_proxy();
        if !self.validate_certs {
            http = http.tls_danger_accept_invalid_certs(true);
        }
        if let Some(path) = &self.ca_file {
            let unusable = |reason: String| GatewayError::Request(format!("CA file {}: {reason}", path.display()));
            let pem = std::fs::read(path).map_err(|error| unusable(error.to_string()))?;
            let certificates = Certificate::from_pem_bundle(&pem).map_err(|error| unusable(chain(&error)))?;
            if certificates.is_empty() {
                return Err(unusable("no certificate found".to_owned()));
            }
            http = http.tls_certs_merge(certificates);
        }
        let http = http.build().map_err(|error| GatewayError::Request(format!("HTTP client: {}", chain(&error))))?;
        Ok(NetboxClient {
            http,
            api,
            token: self.token,
            timeout: self.timeout,
            schema_timeout: self.schema_timeout.max(self.timeout),
            retry_backoff: self.retry_backoff,
            page_size: self.page_size.max(1),
            dry_run: self.dry_run,
            in_flight: Semaphore::new(MAX_IN_FLIGHT),
            schema: OnceCell::new(),
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
    format!("{}***{}", &url[..start], &url[at..])
}

/// `https://netbox.example` → `https://netbox.example/api/`.
fn api_url(url: &str) -> Result<Url, GatewayError> {
    let refused = |reason: &str| GatewayError::Request(format!("NetBox URL {:?}: {reason}", shown(url)));
    let mut base = Url::parse(url).map_err(|error| refused(&error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(refused("not an http or https URL"));
    }
    // The token writes to all of NetBox: in clear only on the loopback (a
    // NetBox of a test, the end of an SSH tunnel).
    let loopback = match base.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if base.scheme() == "http" && !loopback {
        return Err(refused("plain http would send the token in clear: use https"));
    }
    // The token is the one credential: a user or a password in the URL would be
    // sent as well, and printed with the URL.
    if !base.username().is_empty() || base.password().is_some() {
        return Err(refused("credentials in the URL are refused"));
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base.join("api/").map_err(|error| refused(&error.to_string()))
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

/// A page of a list answer.
#[derive(Deserialize)]
struct Page {
    count: u64,
    next: Option<String>,
    results: Vec<Row>,
}

/// What the client reads of the OpenAPI schema: the parameters of each list
/// operation, and the fields of the body of each write.
#[derive(Deserialize)]
struct Schema {
    paths: HashMap<String, PathItem>,
    #[serde(default)]
    components: Components,
}

#[derive(Deserialize)]
struct PathItem {
    get: Option<Operation>,
    post: Option<Operation>,
    patch: Option<Operation>,
}

#[derive(Deserialize)]
struct Operation {
    #[serde(default)]
    parameters: Vec<Parameter>,
    #[serde(rename = "requestBody")]
    request_body: Option<RequestBody>,
}

#[derive(Deserialize)]
struct RequestBody {
    #[serde(default)]
    content: HashMap<String, Media>,
}

#[derive(Deserialize)]
struct Media {
    #[serde(default)]
    schema: serde_json::Value,
}

#[derive(Deserialize, Default)]
struct Components {
    #[serde(default)]
    schemas: HashMap<String, Component>,
}

#[derive(Deserialize)]
struct Component {
    #[serde(default)]
    properties: HashMap<String, serde::de::IgnoredAny>,
}

/// The component a body refers to: `{"$ref": …}`, or the first reference of a
/// `oneOf` (a POST takes one object or a list of them).
fn referenced(schema: &serde_json::Value) -> Option<&str> {
    fn reference(value: &serde_json::Value) -> Option<&str> {
        value.get("$ref").and_then(serde_json::Value::as_str)
    }
    let name = reference(schema).or_else(|| schema.get("oneOf")?.as_array()?.iter().find_map(reference))?;
    name.strip_prefix("#/components/schemas/")
}

#[derive(Deserialize)]
struct Parameter {
    name: Option<String>,
    #[serde(rename = "in")]
    location: Option<String>,
}

/// What the schema says the client may send.
struct Known {
    /// The query parameters each list operation takes, by path (`/api/dcim/devices/`).
    filters: HashMap<String, HashSet<String>>,
    /// The fields of the body of each write, by method and path
    /// (`PATCH`, `/api/dcim/devices/{id}/`).
    fields: HashMap<(Method, String), HashSet<String>>,
}

pub struct NetboxClient {
    http: reqwest::Client,
    /// Ends with `/api/`.
    api: Url,
    /// Kept to be scrubbed from the error messages only.
    token: String,
    timeout: Duration,
    schema_timeout: Duration,
    retry_backoff: Duration,
    page_size: usize,
    dry_run: bool,
    /// Shared by every call: the reads of several devices run in parallel on one client.
    in_flight: Semaphore,
    /// Each filter is checked against the OpenAPI schema: shared, it is fetched
    /// once per run instead of once per reader. The first caller fetches it; the
    /// others wait for it.
    schema: OnceCell<Known>,
}

impl std::fmt::Debug for NetboxClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the token.
        formatter
            .debug_struct("NetboxClient")
            .field("api", &self.api.as_str())
            .field("dry_run", &self.dry_run)
            .finish_non_exhaustive()
    }
}

/// Answers of NetBox, or of its proxy, after which a read is replayed.
const GATEWAY_ERRORS: [StatusCode; 3] =
    [StatusCode::BAD_GATEWAY, StatusCode::SERVICE_UNAVAILABLE, StatusCode::GATEWAY_TIMEOUT];

/// Characters of an error body kept in the message.
const ERROR_BODY_LIMIT: usize = 2000;

impl NetboxClient {
    /// A client of the NetBox at `url` (e.g. `https://netbox.example`).
    ///
    /// A token starting with `nbt_` is a v2 token, sent as `Bearer`; any other
    /// is a v1 token, sent as `Token`.
    pub fn builder(url: &str, token: &str) -> NetboxClientBuilder {
        NetboxClientBuilder {
            url: url.to_owned(),
            token: token.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            schema_timeout: SCHEMA_TIMEOUT,
            retry_backoff: RETRY_BACKOFF,
            page_size: DEFAULT_PAGE_SIZE,
            dry_run: false,
            validate_certs: true,
            ca_file: None,
        }
    }

    /// A client with the default settings.
    pub fn new(url: &str, token: &str) -> Result<Self, GatewayError> {
        NetboxClient::builder(url, token).build()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn retry_backoff(&self) -> Duration {
        self.retry_backoff
    }

    /// An error message, without the token whatever put it there (NetBox, a proxy, a library).
    fn failure(&self, message: String) -> GatewayError {
        let message = if self.token.is_empty() { message } else { message.replace(&self.token, "***") };
        GatewayError::Request(message)
    }

    /// `dcim.mac_addresses` → `…/api/dcim/mac-addresses/`.
    fn endpoint_url(&self, endpoint: &str) -> Result<Url, GatewayError> {
        let word = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        match endpoint.split('.').collect::<Vec<_>>().as_slice() {
            [app, name] if word(app) && word(name) => self
                .api
                .join(&format!("{app}/{}/", name.replace('_', "-")))
                .map_err(|error| self.failure(format!("endpoint {endpoint}: {error}"))),
            _ => Err(self.failure(format!("endpoint {endpoint}: not of the form app.name"))),
        }
    }

    fn object_url(&self, endpoint: &str, id: u64) -> Result<Url, GatewayError> {
        let list = self.endpoint_url(endpoint)?;
        list.join(&format!("{id}/")).map_err(|error| self.failure(format!("endpoint {endpoint}: {error}")))
    }

    fn refuse_dry_run(&self, method: &Method, endpoint: &str) -> Result<(), GatewayError> {
        if self.dry_run {
            return Err(GatewayError::DryRun { method: method.to_string(), endpoint: endpoint.to_owned() });
        }
        Ok(())
    }

    /// Sends one request and gives the body of a successful answer.
    ///
    /// Under parallel reads NetBox, or its proxy, may answer a gateway error: a
    /// read is replayed, a write never (a POST answered 502 may have been
    /// applied). Still failing, the last answer is the error reported.
    /// Only those answers: a timeout or a refused connection fails at once, as
    /// without retries, or a hung NetBox would cost one timeout per attempt.
    async fn send(&self, method: Method, url: &Url, body: Option<&Row>) -> Result<Vec<u8>, GatewayError> {
        self.send_within(method, url, body, None).await
    }

    /// [`send`](Self::send), with a bound of its own instead of the client's,
    /// and then never replayed: what takes that long would be asked again from
    /// the start at each attempt (the schema, which NetBox builds when asked).
    async fn send_within(
        &self,
        method: Method,
        url: &Url,
        body: Option<&Row>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, GatewayError> {
        let target = &url[Position::BeforePath..];
        let replays = if method == Method::GET && timeout.is_none() { RETRIES } else { 0 };
        let mut wait = self.retry_backoff;
        let mut replayed = 0;
        loop {
            let (status, answer) = {
                let _permit = self.in_flight.acquire().await.expect("the semaphore is never closed");
                let mut request = self.http.request(method.clone(), url.clone());
                if let Some(timeout) = timeout {
                    request = request.timeout(timeout);
                }
                if let Some(body) = body {
                    request = request.json(body);
                }
                // No answer: the message names NetBox and its host, the URL of the error is left out.
                let host = &url[Position::BeforeHost..Position::AfterPort];
                let broken = |error: reqwest::Error| {
                    self.failure(format!("NetBox {host}: {method} {target}: {}", chain(&error.without_url())))
                };
                let response = request.send().await.map_err(broken)?;
                (response.status(), response.bytes().await.map_err(broken)?.to_vec())
            };
            if status.is_success() {
                return Ok(answer);
            }
            if GATEWAY_ERRORS.contains(&status) && replayed < replays {
                replayed += 1;
                tokio::time::sleep(wait).await;
                wait = wait.saturating_mul(2);
                continue;
            }
            // The body of NetBox explains a refused write: which field, and why.
            let said: String = String::from_utf8_lossy(&answer).trim().chars().take(ERROR_BODY_LIMIT).collect();
            let message = if said.is_empty() {
                format!("{method} {target} answered {status}")
            } else {
                format!("{method} {target} answered {status}: {said}")
            };
            return Err(self.failure(message));
        }
    }

    fn parse<T: DeserializeOwned>(&self, method: &Method, url: &Url, answer: &[u8]) -> Result<T, GatewayError> {
        serde_json::from_slice(answer).map_err(|error| {
            self.failure(format!("{method} {}: unexpected answer: {error}", &url[Position::BeforePath..]))
        })
    }

    /// Reads the OpenAPI schema now, if no call has yet: a run does it before
    /// it reads any source, so that a NetBox too slow to give it fails the run
    /// before anything is written, not at its first write.
    pub async fn load_schema(&self) -> Result<(), GatewayError> {
        self.schema.get_or_try_init(|| self.fetch_schema()).await.map(|_| ())
    }

    async fn fetch_schema(&self) -> Result<Known, GatewayError> {
        let mut url = self.api.join("schema/").map_err(|error| self.failure(format!("schema: {error}")))?;
        url.query_pairs_mut().append_pair("format", "json");
        let answer = self.send_within(Method::GET, &url, None, Some(self.schema_timeout)).await?;
        let schema: Schema = self.parse(&Method::GET, &url, &answer)?;
        let query = |parameter: Parameter| parameter.name.filter(|_| parameter.location.as_deref() == Some("query"));
        let components = &schema.components.schemas;
        // The fields of the JSON body of an operation, through the component it refers to.
        let body = |operation: &Operation| -> Option<HashSet<String>> {
            let media = operation.request_body.as_ref()?.content.get("application/json")?;
            Some(components.get(referenced(&media.schema)?)?.properties.keys().cloned().collect())
        };
        let mut known = Known { filters: HashMap::new(), fields: HashMap::new() };
        for (path, item) in schema.paths {
            for (method, operation) in [(Method::POST, &item.post), (Method::PATCH, &item.patch)] {
                if let Some(fields) = operation.as_ref().and_then(body) {
                    known.fields.insert((method, path.clone()), fields);
                }
            }
            if let Some(get) = item.get {
                known.filters.insert(path, get.parameters.into_iter().filter_map(query).collect());
            }
        }
        Ok(known)
    }

    /// The path of `url` as the schema names it, from `/api/`, also when
    /// NetBox is served under a prefix; `suffix` is appended (`{id}/`).
    fn schema_paths(&self, url: &Url, suffix: &str) -> [String; 2] {
        let bare = format!("/api/{}{suffix}", &url.as_str()[self.api.as_str().len()..]);
        [format!("{}{suffix}", url.path()), bare]
    }

    /// NetBox drops a field it does not know and answers the write as done: a
    /// field a release renamed or removed would be written again at every run.
    /// Each field must be one of the body of the operation in the schema, or
    /// nothing is sent.
    async fn check_fields<'f>(
        &self,
        write: Write,
        endpoint: &str,
        mut fields: impl Iterator<Item = &'f String>,
    ) -> Result<(), GatewayError> {
        // A creation posts to the list, an update patches the object.
        let (method, suffix) = match write {
            Write::Create => (Method::POST, ""),
            Write::Update => (Method::PATCH, "{id}/"),
        };
        let paths = self.schema_paths(&self.endpoint_url(endpoint)?, suffix);
        let schema = self.schema.get_or_try_init(|| self.fetch_schema()).await?;
        let known = paths.iter().find_map(|path| schema.fields.get(&(method.clone(), path.clone())));
        let Some(known) = known else {
            return Err(self.failure(format!("{method} {}: not an operation of the schema of NetBox", paths[1])));
        };
        match fields.find(|field| !known.contains(*field)) {
            Some(field) => Err(GatewayError::UnknownField { endpoint: endpoint.to_owned(), field: field.clone() }),
            None => Ok(()),
        }
    }

    /// NetBox ignores an unknown filter and returns every object: a typo would
    /// turn a prune into a mass deletion. Each filter must be a query parameter
    /// of the list operation in the OpenAPI schema, or nothing is sent.
    async fn check_filters(&self, endpoint: &str, url: &Url, filters: &Filters) -> Result<(), GatewayError> {
        if filters.is_empty() {
            return Ok(());
        }
        let schema = self.schema.get_or_try_init(|| self.fetch_schema()).await?;
        let known = self.schema_paths(url, "").into_iter().find_map(|path| schema.filters.get(&path));
        for (name, value) in filters {
            // The pagination is the client's: a caller setting it would read a part for the whole.
            let paging = matches!(name.as_str(), "limit" | "offset");
            if paging || !known.is_some_and(|known| known.contains(name)) {
                return Err(GatewayError::UnknownFilter { endpoint: endpoint.to_owned(), filter: name.clone() });
            }
            // NetBox drops an empty value, and the filter with it.
            if value.is_empty() {
                return Err(GatewayError::EmptyFilter { endpoint: endpoint.to_owned(), filter: name.clone() });
            }
        }
        Ok(())
    }

    /// Every page of a listing once: the count NetBox announced, and the rows given.
    async fn read_pages(&self, url: &Url, filters: &Filters) -> Result<(u64, Vec<Row>), GatewayError> {
        let first = self.page(url, filters, self.page_size, 0).await?;
        let mut rows = first.results;
        // NetBox may give fewer objects per page than asked (MAX_PAGE_SIZE): its page is the step.
        let step = rows.len();
        if first.next.is_none() || step == 0 {
            return Ok((rows.len() as u64, rows));
        }
        // The other pages are read concurrently; the semaphore bounds them with every other call.
        let offsets = (step as u64..first.count).step_by(step);
        let pages = try_join_all(offsets.map(|offset| self.page(url, filters, step, offset))).await?;
        rows.extend(pages.into_iter().flat_map(|page| page.results));
        Ok((first.count, rows))
    }

    async fn page(&self, list: &Url, filters: &Filters, limit: usize, offset: u64) -> Result<Page, GatewayError> {
        let mut url = list.clone();
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in filters {
                query.append_pair(name, value);
            }
            query.append_pair("limit", &limit.to_string()).append_pair("offset", &offset.to_string());
        }
        let answer = self.send(Method::GET, &url, None).await?;
        self.parse(&Method::GET, &url, &answer)
    }
}

impl DryRun for NetboxClient {
    fn dry_run(&self) -> bool {
        self.dry_run
    }
}

impl NetboxVersion for NetboxClient {
    async fn netbox_version(&self) -> Result<String, GatewayError> {
        let url = self.api.join("status/").map_err(|error| self.failure(format!("status: {error}")))?;
        let answer = self.send(Method::GET, &url, None).await?;
        let status: serde_json::Value = self.parse(&Method::GET, &url, &answer)?;
        match status.get("netbox-version").and_then(serde_json::Value::as_str) {
            Some(version) => Ok(version.to_owned()),
            None => Err(self.failure(format!("GET {}: no netbox-version in the answer", url.path()))),
        }
    }

    async fn load_schema(&self) -> Result<(), GatewayError> {
        NetboxClient::load_schema(self).await
    }
}

impl Gateway for NetboxClient {
    async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
        let url = self.endpoint_url(endpoint)?;
        self.check_filters(endpoint, &url, filters).await?;
        // Pages are read by offset: a write by someone else between two pages
        // shifts the objects, and one may be missed while another is read
        // twice. A listing that does not add up to the count NetBox announced
        // is read once more, then refused: an object missing from the state
        // would be created again by the run.
        let mut announced = 0;
        let mut different = 0;
        for _ in 0..2 {
            let (count, rows) = self.read_pages(&url, filters).await?;
            let mut seen = BTreeSet::new();
            let rows: Vec<Row> =
                rows.into_iter().filter(|row| row.get("id").is_none_or(|id| seen.insert(id.to_string()))).collect();
            if rows.len() as u64 == count {
                return Ok(rows);
            }
            (announced, different) = (count, rows.len());
        }
        Err(self.failure(format!(
            "GET {}: NetBox announced {announced} objects and gave {different} different ones, twice: \
             the table changed while it was read",
            url.path()
        )))
    }

    async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
        self.refuse_dry_run(&Method::POST, endpoint)?;
        self.check_fields(Write::Create, endpoint, payload.keys()).await?;
        let url = self.endpoint_url(endpoint)?;
        let answer = self.send(Method::POST, &url, Some(payload)).await?;
        self.parse(&Method::POST, &url, &answer)
    }

    async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
        self.refuse_dry_run(&Method::PATCH, endpoint)?;
        self.check_fields(Write::Update, endpoint, payload.keys()).await?;
        let url = self.object_url(endpoint, id)?;
        self.send(Method::PATCH, &url, Some(payload)).await?;
        Ok(())
    }

    // Checked as a write is, whether or not the client is in dry run: a dry
    // run tells this way what the real run would be refused.
    async fn check_write(&self, write: Write, endpoint: &str, fields: &[String]) -> Result<(), GatewayError> {
        self.check_fields(write, endpoint, fields.iter()).await
    }

    async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
        self.refuse_dry_run(&Method::DELETE, endpoint)?;
        let url = self.object_url(endpoint, id)?;
        self.send(Method::DELETE, &url, None).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use futures::future::join_all;
    use omnisync_core::gateway::filters;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    const SENTINEL: &str = "s3ntinel-token-value";

    fn row(value: Value) -> Row {
        value.as_object().expect("a JSON object").clone()
    }

    fn no_filters() -> Filters {
        Vec::new()
    }

    /// A client that does not wait between the retries.
    fn client(server: &MockServer) -> NetboxClient {
        NetboxClient::builder(&server.uri(), "token-value").retry_backoff(Duration::ZERO).build().unwrap()
    }

    // `/api/status/` of NetBox 4.7.5 (the Docker image of the integration
    // tests, 2026-11-24), cut to two of its fields. The release is read there and not in the
    // `API-Version` header, which a proxy may drop (netbox-sync #314, #446).
    #[tokio::test]
    async fn the_release_of_netbox_is_read_from_its_status() {
        let server = MockServer::start().await;
        let status = json!({"django-version": "6.1.3", "netbox-version": "4.7.5"});
        Mock::given(method("GET"))
            .and(path("/api/status/"))
            .and(header("authorization", "Token token-value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(status))
            .mount(&server)
            .await;
        assert_eq!(client(&server).netbox_version().await, Ok("4.7.5".to_owned()));
    }

    #[tokio::test]
    async fn a_status_without_the_release_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"django-version": "5.2.9"})))
            .mount(&server)
            .await;
        let error = client(&server).netbox_version().await.expect_err("no release");
        assert_eq!(error.to_string(), "GET /api/status/: no netbox-version in the answer");
    }

    fn page(results: Value) -> ResponseTemplate {
        let count = results.as_array().unwrap().len();
        ResponseTemplate::new(200)
            .set_body_json(json!({"count": count, "next": null, "previous": null, "results": results}))
    }

    /// The OpenAPI schema of a NetBox whose list operations take these query parameters.
    async fn mount_schema(server: &MockServer, endpoints: &[(&str, &[&str])]) {
        mount_full_schema(server, endpoints, &[]).await;
    }

    /// The same, whose `post` and `patch` operations also take these fields,
    /// as NetBox writes them: the body of each operation refers to a schema of
    /// the components, the one of a POST in a `oneOf` with its bulk form.
    async fn mount_full_schema(server: &MockServer, endpoints: &[(&str, &[&str])], writes: &[(&str, &str, &[&str])]) {
        let mut paths = serde_json::Map::new();
        for (endpoint_path, names) in endpoints {
            let parameters: Vec<Value> = names.iter().map(|name| json!({"name": name, "in": "query"})).collect();
            paths.insert((*endpoint_path).to_owned(), json!({"get": {"parameters": parameters}}));
        }
        let mut components = serde_json::Map::new();
        for (rank, (verb, endpoint_path, fields)) in writes.iter().enumerate() {
            let name = format!("Writable{rank}Request");
            let properties: serde_json::Map<String, Value> =
                fields.iter().map(|field| ((*field).to_owned(), json!({"type": "string"}))).collect();
            components.insert(name.clone(), json!({"type": "object", "properties": properties}));
            let reference = json!({"$ref": format!("#/components/schemas/{name}")});
            let body = if *verb == "post" {
                json!({"oneOf": [reference, {"type": "array", "items": reference}]})
            } else {
                reference
            };
            let operation = json!({"requestBody": {"content": {"application/json": {"schema": body}}}});
            let item = paths.entry((*endpoint_path).to_owned()).or_insert_with(|| json!({}));
            item[*verb] = operation;
        }
        let schema = json!({"paths": paths, "components": {"schemas": components}});
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .and(query_param("format", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(schema))
            .mount(server)
            .await;
    }

    // A dry run sends no write, yet must say what the real run would be
    // refused: the fields are checked against the schema, and nothing is sent.
    #[tokio::test]
    async fn the_fields_of_a_write_are_checked_without_sending_it_even_in_a_dry_run() {
        let server = MockServer::start().await;
        mount_full_schema(&server, &[], &[("patch", "/api/dcim/interfaces/{id}/", &["description", "mtu"])]).await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value").dry_run(true).build().unwrap();
        let fields = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect::<Vec<String>>();
        let known = netbox.check_write(Write::Update, "dcim.interfaces", &fields(&["mtu", "description"])).await;
        assert_eq!(known, Ok(()));
        let speed = netbox.check_write(Write::Update, "dcim.interfaces", &fields(&["mtu", "speed"])).await;
        assert_eq!(
            speed,
            Err(GatewayError::UnknownField { endpoint: "dcim.interfaces".to_owned(), field: "speed".to_owned() })
        );
        let created = netbox.check_write(Write::Create, "dcim.interfaces", &fields(&["name"])).await;
        assert_eq!(
            created.map_err(|error| error.to_string()),
            Err("POST /api/dcim/interfaces/: not an operation of the schema of NetBox".to_owned())
        );
        assert_eq!(received(&server).await, [] as [(String, String); 0]);
    }

    // NetBox answers 200 to a write carrying a field it does not know, and
    // drops the field (NetBox 4.5.10 and 4.7.5, a PATCH of a tag with
    // `descriptoin`, 2026-11-24): a field a release renamed or removed would be written again
    // at every run, without a word. Each field is checked against the body the
    // OpenAPI schema gives for the operation, and nothing is sent otherwise.
    #[tokio::test]
    async fn a_field_netbox_does_not_take_is_refused_before_any_write() {
        let server = MockServer::start().await;
        let writes: [(&str, &str, &[&str]); 2] = [
            ("post", "/api/ipam/ip-addresses/", &["address", "status", "description"]),
            ("patch", "/api/dcim/interfaces/{id}/", &["description", "mtu"]),
        ];
        mount_full_schema(&server, &[], &writes).await;
        let netbox = client(&server);
        let unknown = |endpoint: &str, field: &str| GatewayError::UnknownField {
            endpoint: endpoint.to_owned(),
            field: field.to_owned(),
        };
        let typo = row(json!({"address": "192.0.2.1/24", "descriptoin": "x"}));
        assert_eq!(netbox.create("ipam.ip_addresses", &typo).await, Err(unknown("ipam.ip_addresses", "descriptoin")));
        let speed = row(json!({"mtu": 9216, "speed": 1000}));
        assert_eq!(netbox.update("dcim.interfaces", 7, &speed).await, Err(unknown("dcim.interfaces", "speed")));
        // A write the schema gives no body for is refused as such, not as a field.
        let name = row(json!({"name": "a"}));
        let error = netbox.update("dcim.devices", 7, &name).await.expect_err("no body in the schema");
        assert_eq!(error.to_string(), "PATCH /api/dcim/devices/{id}/: not an operation of the schema of NetBox");
        assert_eq!(received(&server).await, [] as [(String, String); 0]);
        assert_eq!(
            unknown("dcim.devices", "name").to_string(),
            "unknown field name on dcim.devices: NetBox would drop it"
        );
    }

    /// (method, path) of every request the mock received, the schema fetch left out.
    async fn received(server: &MockServer) -> Vec<(String, String)> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() != "/api/schema/")
            .map(|request| (request.method.to_string(), request.url.path().to_owned()))
            .collect()
    }

    fn message(error: GatewayError) -> String {
        match error {
            GatewayError::Request(message) => message,
            other => panic!("expected a request error, got {other:?}"),
        }
    }

    #[test]
    fn a_client_says_whether_it_is_in_dry_run() {
        let live = NetboxClient::new("https://netbox.example", "token-value").unwrap();
        assert!(!DryRun::dry_run(&live));
        let dry = NetboxClient::builder("https://netbox.example", "token-value").dry_run(true).build().unwrap();
        assert!(DryRun::dry_run(&dry));
    }

    // Plain http sends the token, which writes to all of NetBox, in clear on
    // every request: only the loopback (a NetBox of a test, an SSH tunnel) takes it.
    #[test]
    fn plain_http_is_only_taken_on_the_loopback() {
        let refused = NetboxClient::builder("http://netbox.example", "token-value").build().unwrap_err();
        assert_eq!(
            refused,
            GatewayError::Request(
                "NetBox URL \"http://netbox.example\": plain http would send the token in clear: use https".to_owned()
            )
        );
        for url in ["http://localhost:8000", "http://127.0.0.1:8080", "http://[::1]:8000", "https://netbox.example"] {
            assert!(NetboxClient::builder(url, "token-value").build().is_ok(), "{url}");
        }
    }

    #[tokio::test]
    async fn an_endpoint_name_with_underscores_maps_to_a_dashed_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/mac-addresses/"))
            .respond_with(page(json!([{"id": 7, "mac_address": "02:08:D1:90:97:2D"}])))
            .mount(&server)
            .await;
        let rows = client(&server).list("dcim.mac_addresses", &no_filters()).await.unwrap();
        assert_eq!(rows, [row(json!({"id": 7, "mac_address": "02:08:D1:90:97:2D"}))]);
    }

    #[tokio::test]
    async fn a_trailing_slash_in_the_url_changes_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        let netbox = NetboxClient::new(&format!("{}/", server.uri()), "token-value").unwrap();
        assert_eq!(netbox.list("dcim.devices", &no_filters()).await.unwrap(), [row(json!({"id": 1}))]);
    }

    #[tokio::test]
    async fn an_endpoint_that_is_not_app_dot_name_is_refused_before_any_request() {
        let server = MockServer::start().await;
        let netbox = client(&server);
        for endpoint in ["devices", "dcim.devices.extra", "dcim.", "dcim.dev/../x"] {
            let error = message(netbox.list(endpoint, &no_filters()).await.unwrap_err());
            assert!(error.contains(endpoint), "{error}");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_sends_the_filters_as_query_parameters() {
        let server = MockServer::start().await;
        mount_schema(&server, &[("/api/dcim/interfaces/", &["device_id", "name"])]).await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/interfaces/"))
            .and(query_param("device_id", "12"))
            .and(query_param("name", "Ethernet1/12"))
            .respond_with(page(json!([{"id": 3, "name": "Ethernet1/12"}])))
            .mount(&server)
            .await;
        let rows = client(&server)
            .list(
                "dcim.interfaces",
                &vec![("device_id".to_owned(), "12".to_owned()), ("name".to_owned(), "Ethernet1/12".to_owned())],
            )
            .await
            .unwrap();
        assert_eq!(rows, [row(json!({"id": 3, "name": "Ethernet1/12"}))]);
    }

    #[tokio::test]
    async fn list_follows_the_pagination_until_every_object_is_read() {
        let server = MockServer::start().await;
        let next = format!("{}/api/dcim/devices/?limit=2&offset=2", server.uri());
        for (offset, next, ids) in [
            ("0", json!(next), json!([{"id": 1}, {"id": 2}])),
            ("2", json!(next), json!([{"id": 3}, {"id": 4}])),
            ("4", json!(null), json!([{"id": 5}])),
        ] {
            Mock::given(method("GET"))
                .and(path("/api/dcim/devices/"))
                .and(query_param("limit", "2"))
                .and(query_param("offset", offset))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"count": 5, "next": next, "results": ids})),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let netbox = NetboxClient::builder(&server.uri(), "token-value").page_size(2).build().unwrap();
        let rows = netbox.list("dcim.devices", &no_filters()).await.unwrap();
        let ids: Vec<Value> = rows.iter().map(|row| row["id"].clone()).collect();
        assert_eq!(ids, [json!(1), json!(2), json!(3), json!(4), json!(5)]);
    }

    /// One page of a listing of `count` objects, the next page announced or not.
    fn page_of(count: u64, ids: &[u64], more: bool) -> ResponseTemplate {
        let results: Vec<Value> = ids.iter().map(|id| json!({"id": id})).collect();
        let next = if more { json!("more") } else { Value::Null };
        ResponseTemplate::new(200).set_body_json(json!({"count": count, "next": next, "results": results}))
    }

    async fn answer(server: &MockServer, offset: &str, template: ResponseTemplate, times: Option<u64>) {
        let mock = Mock::given(method("GET")).and(path("/api/dcim/devices/")).and(query_param("offset", offset));
        let mock = mock.respond_with(template);
        match times {
            Some(times) => mock.up_to_n_times(times).with_priority(1).mount(server).await,
            None => mock.with_priority(2).mount(server).await,
        }
    }

    // Another writer deletes device 3 between the two pages: device 4 moves
    // to the first page and is never seen. A state without it would have the
    // run create it again; the listing is read again instead.
    #[tokio::test]
    async fn a_listing_that_changed_while_it_was_read_is_read_again() {
        let server = MockServer::start().await;
        answer(&server, "0", page_of(4, &[1, 2], true), Some(1)).await;
        answer(&server, "2", page_of(4, &[5], false), Some(1)).await;
        answer(&server, "0", page_of(3, &[1, 2], true), None).await;
        answer(&server, "2", page_of(3, &[4], false), None).await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value").page_size(2).build().unwrap();
        let rows = netbox.list("dcim.devices", &no_filters()).await.unwrap();
        let ids: Vec<Value> = rows.iter().map(|row| row["id"].clone()).collect();
        assert_eq!(ids, [json!(1), json!(2), json!(4)]);
        assert_eq!(received(&server).await.len(), 4);
    }

    // A listing that never adds up is not taken for the whole table.
    #[tokio::test]
    async fn a_listing_that_never_adds_up_fails() {
        let server = MockServer::start().await;
        answer(&server, "0", page_of(4, &[1, 2], true), None).await;
        answer(&server, "2", page_of(4, &[2], false), None).await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value").page_size(2).build().unwrap();
        assert_eq!(
            netbox.list("dcim.devices", &no_filters()).await,
            Err(GatewayError::Request(
                "GET /api/dcim/devices/: NetBox announced 4 objects and gave 2 different ones, twice: \
                 the table changed while it was read"
                    .to_owned()
            ))
        );
        assert_eq!(received(&server).await.len(), 4);
    }

    #[tokio::test]
    async fn the_following_pages_keep_the_filters() {
        let server = MockServer::start().await;
        mount_schema(&server, &[("/api/dcim/devices/", &["site_id"])]).await;
        for (offset, next, ids) in [("0", json!("more"), json!([{"id": 1}])), ("1", json!(null), json!([{"id": 2}]))] {
            Mock::given(method("GET"))
                .and(path("/api/dcim/devices/"))
                .and(query_param("site_id", "12"))
                .and(query_param("offset", offset))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"count": 2, "next": next, "results": ids})),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let netbox = NetboxClient::builder(&server.uri(), "token-value").page_size(1).build().unwrap();
        let rows = netbox.list("dcim.devices", &filters([("site_id", 12)])).await.unwrap();
        assert_eq!(rows, [row(json!({"id": 1})), row(json!({"id": 2}))]);
    }

    #[tokio::test]
    async fn a_page_size_capped_by_netbox_is_followed() {
        // Asked for 250 objects, this NetBox gives 2 per page: the next pages start where its pages do.
        let server = MockServer::start().await;
        for (offset, next, ids) in [
            ("0", json!("more"), json!([{"id": 1}, {"id": 2}])),
            ("2", json!("more"), json!([{"id": 3}, {"id": 4}])),
            ("4", json!(null), json!([{"id": 5}])),
        ] {
            Mock::given(method("GET"))
                .and(path("/api/dcim/devices/"))
                .and(query_param("offset", offset))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"count": 5, "next": next, "results": ids})),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let rows = client(&server).list("dcim.devices", &no_filters()).await.unwrap();
        let ids: Vec<Value> = rows.iter().map(|row| row["id"].clone()).collect();
        assert_eq!(ids, [json!(1), json!(2), json!(3), json!(4), json!(5)]);
        let first = &server.received_requests().await.unwrap()[0];
        assert!(first.url.query_pairs().any(|(key, value)| key == "limit" && value == "250"), "{}", first.url);
    }

    /// A NetBox of `total` objects, one per page, that takes `delay` to answer
    /// and notes when each request arrived.
    fn slow_pages(
        total: u64,
        delay: Duration,
        arrivals: Arc<Mutex<Vec<Instant>>>,
    ) -> impl Fn(&Request) -> ResponseTemplate {
        move |request: &Request| {
            arrivals.lock().unwrap().push(Instant::now());
            let offset: u64 = request
                .url
                .query_pairs()
                .find(|(key, _)| key == "offset")
                .map(|(_, value)| value.parse().unwrap())
                .unwrap();
            let next = if offset + 1 < total { json!("more") } else { json!(null) };
            ResponseTemplate::new(200)
                .set_body_json(json!({"count": total, "next": next, "results": [{"id": offset + 1}]}))
                .set_delay(delay)
        }
    }

    /// The most requests in flight at once, each taken as in flight for `delay` from its arrival.
    fn most_in_flight(arrivals: &[Instant], delay: Duration) -> usize {
        arrivals
            .iter()
            .map(|at| arrivals.iter().filter(|other| **other <= *at && *at < **other + delay).count())
            .max()
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn at_most_four_requests_are_in_flight_for_the_whole_client() {
        let server = MockServer::start().await;
        let delay = Duration::from_millis(250);
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(slow_pages(9, delay, Arc::clone(&arrivals)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/interfaces/"))
            .respond_with(slow_pages(9, delay, Arc::clone(&arrivals)))
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value").page_size(1).build().unwrap();
        let all = no_filters();
        let (devices, interfaces) =
            tokio::join!(netbox.list("dcim.devices", &all), netbox.list("dcim.interfaces", &all));
        // Every page is read, in order, whatever the order of the answers.
        let ids = |rows: Vec<Row>| rows.iter().map(|row| row["id"].as_u64().unwrap()).collect::<Vec<_>>();
        assert_eq!(ids(devices.unwrap()), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(ids(interfaces.unwrap()), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let arrivals = arrivals.lock().unwrap();
        assert_eq!(arrivals.len(), 18);
        // Four at once: the pages after the first are read concurrently, and never more than four.
        assert_eq!(most_in_flight(&arrivals, delay), 4);
    }

    #[tokio::test]
    async fn a_v1_token_is_sent_as_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .and(header("authorization", "Token 0123456789abcdef"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        let netbox = NetboxClient::new(&server.uri(), "0123456789abcdef").unwrap();
        assert_eq!(netbox.list("dcim.devices", &no_filters()).await.unwrap(), [row(json!({"id": 1}))]);
    }

    #[tokio::test]
    async fn a_v2_token_is_sent_as_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .and(header("authorization", "Bearer nbt_abcdef.0123456789"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        let netbox = NetboxClient::new(&server.uri(), "nbt_abcdef.0123456789").unwrap();
        assert_eq!(netbox.list("dcim.devices", &no_filters()).await.unwrap(), [row(json!({"id": 1}))]);
    }

    #[tokio::test]
    async fn an_unknown_filter_is_refused_before_any_list_request() {
        // NetBox ignores an unknown filter and returns every object: a typo would
        // turn a prune into a mass deletion.
        let server = MockServer::start().await;
        mount_schema(&server, &[("/api/dcim/devices/", &["name", "site_id"])]).await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        let netbox = client(&server);
        assert_eq!(
            netbox.list("dcim.devices", &filters([("site_id", "12"), ("nmae", "nexus01.lab01")])).await,
            Err(GatewayError::UnknownFilter { endpoint: "dcim.devices".to_owned(), filter: "nmae".to_owned() })
        );
        assert_eq!(received(&server).await, []);
        // A known filter goes through.
        assert_eq!(
            netbox.list("dcim.devices", &filters([("name", "nexus01.lab01")])).await.unwrap(),
            [row(json!({"id": 1}))]
        );
    }

    // NetBox drops an empty value (`multivalue_field_factory.to_python`) and
    // returns every object: the same mass deletion as an unknown filter.
    #[tokio::test]
    async fn an_empty_filter_value_is_refused_before_any_list_request() {
        let server = MockServer::start().await;
        mount_schema(&server, &[("/api/ipam/vrfs/", &["name"])]).await;
        Mock::given(method("GET"))
            .and(path("/api/ipam/vrfs/"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        assert_eq!(
            client(&server).list("ipam.vrfs", &filters([("name", "")])).await,
            Err(GatewayError::EmptyFilter { endpoint: "ipam.vrfs".to_owned(), filter: "name".to_owned() })
        );
        assert_eq!(received(&server).await, []);
    }

    #[tokio::test]
    async fn a_filter_on_an_endpoint_the_schema_does_not_know_is_refused() {
        let server = MockServer::start().await;
        mount_schema(&server, &[("/api/dcim/devices/", &["name"])]).await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/racks/"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        assert_eq!(
            client(&server).list("dcim.racks", &filters([("name", "r1")])).await,
            Err(GatewayError::UnknownFilter { endpoint: "dcim.racks".to_owned(), filter: "name".to_owned() })
        );
        assert_eq!(received(&server).await, []);
    }

    #[tokio::test]
    async fn the_pagination_parameters_are_not_filters() {
        // They are query parameters of every list operation, but the client's own:
        // a caller setting them would read a part for the whole.
        let server = MockServer::start().await;
        mount_schema(&server, &[("/api/dcim/devices/", &["name", "limit", "offset"])]).await;
        let netbox = client(&server);
        for filter in ["limit", "offset"] {
            assert_eq!(
                netbox.list("dcim.devices", &filters([(filter, "1")])).await,
                Err(GatewayError::UnknownFilter { endpoint: "dcim.devices".to_owned(), filter: filter.to_owned() })
            );
        }
        assert_eq!(received(&server).await, []);
    }

    #[tokio::test]
    async fn a_netbox_served_under_a_prefix_is_read_under_it() {
        let server = MockServer::start().await;
        // The schema names its paths from /api/ whatever the prefix.
        let schema =
            json!({"paths": {"/api/dcim/devices/": {"get": {"parameters": [{"name": "name", "in": "query"}]}}}});
        Mock::given(method("GET"))
            .and(path("/netbox/api/schema/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(schema))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/netbox/api/dcim/devices/"))
            .and(query_param("name", "nexus01.lab01"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        let netbox = NetboxClient::new(&format!("{}/netbox", server.uri()), "token-value").unwrap();
        assert_eq!(
            netbox.list("dcim.devices", &filters([("name", "nexus01.lab01")])).await,
            Ok(vec![row(json!({"id": 1}))])
        );
        assert_eq!(
            netbox.list("dcim.devices", &filters([("nmae", "nexus01.lab01")])).await,
            Err(GatewayError::UnknownFilter { endpoint: "dcim.devices".to_owned(), filter: "nmae".to_owned() })
        );
    }

    #[tokio::test]
    async fn only_the_query_parameters_of_the_list_operation_are_filters() {
        let server = MockServer::start().await;
        let schema = json!({"paths": {"/api/dcim/devices/": {
            "get": {"parameters": [{"name": "name", "in": "query"}, {"name": "x-trace", "in": "header"}]},
            "post": {"parameters": [{"name": "force", "in": "query"}]},
        }}});
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(schema))
            .mount(&server)
            .await;
        let netbox = client(&server);
        for filter in ["x-trace", "force"] {
            assert_eq!(
                netbox.list("dcim.devices", &filters([(filter, "1")])).await,
                Err(GatewayError::UnknownFilter { endpoint: "dcim.devices".to_owned(), filter: filter.to_owned() })
            );
        }
    }

    #[tokio::test]
    async fn the_schema_is_fetched_once_for_all_the_calls() {
        let server = MockServer::start().await;
        let schema =
            json!({"paths": {"/api/dcim/devices/": {"get": {"parameters": [{"name": "name", "in": "query"}]}}}});
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .and(query_param("format", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(schema).set_delay(Duration::from_millis(100)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(page(json!([{"id": 1}])))
            .mount(&server)
            .await;
        let netbox = client(&server);
        let name = filters([("name", "nexus01.lab01")]);
        // Concurrent callers wait for the one fetch.
        let answers = join_all((0..8).map(|_| netbox.list("dcim.devices", &name))).await;
        assert_eq!(answers.len(), 8);
        for answer in answers {
            assert_eq!(answer.unwrap(), [row(json!({"id": 1}))]);
        }
        // Later callers reuse it.
        netbox.list("dcim.devices", &name).await.unwrap();
        server.verify().await;
    }

    // NetBox builds its OpenAPI schema when it is asked for, and a slow or busy
    // host may take longer than the 60 s of a request to do it. The schema has
    // a bound of its own, longer.
    #[tokio::test]
    async fn the_schema_is_read_within_its_own_longer_timeout() {
        let server = MockServer::start().await;
        let schema =
            json!({"paths": {"/api/dcim/devices/": {"get": {"parameters": [{"name": "name", "in": "query"}]}}}});
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(schema).set_delay(Duration::from_millis(400)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(page(json!([{"id": 1}])).set_delay(Duration::from_millis(400)))
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value")
            .timeout(Duration::from_millis(100))
            .schema_timeout(Duration::from_secs(5))
            .retry_backoff(Duration::ZERO)
            .build()
            .unwrap();
        assert_eq!(netbox.load_schema().await, Ok(()));
        // Any other request keeps the bound of a request, the schema already read.
        let slow = netbox.list("dcim.devices", &filters([("name", "nexus01.lab01")])).await;
        assert!(matches!(slow, Err(GatewayError::Request(ref message)) if message.contains("timed out")), "{slow:?}");
        server.verify().await;
    }

    // A proxy in front of NetBox may cut the build of the schema with a 504:
    // replayed, each attempt would ask NetBox to build it again, and the run
    // would wait several times the bound before failing all the same.
    #[tokio::test]
    async fn the_schema_is_never_replayed_on_a_gateway_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(504))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"paths": {}})))
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value").retry_backoff(Duration::ZERO).build().unwrap();
        let refused = netbox.load_schema().await;
        assert!(matches!(refused, Err(GatewayError::Request(ref message)) if message.contains("504")), "{refused:?}");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_bound_of_the_schema_is_never_shorter_than_the_one_of_a_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"paths": {}})).set_delay(Duration::from_millis(300)),
            )
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value")
            .timeout(Duration::from_secs(5))
            .schema_timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        assert_eq!(netbox.load_schema().await, Ok(()));
    }

    #[tokio::test]
    async fn a_read_is_retried_on_a_gateway_error() {
        // Under parallel reads NetBox (or its proxy) may answer 502: a read is safe to replay.
        for status in [502, 503, 504] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/dcim/devices/"))
                .respond_with(ResponseTemplate::new(status))
                .up_to_n_times(2)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/dcim/devices/"))
                .respond_with(page(json!([{"id": 1}])))
                .mount(&server)
                .await;
            assert_eq!(client(&server).list("dcim.devices", &no_filters()).await.unwrap(), [row(json!({"id": 1}))]);
            let get = ("GET".to_owned(), "/api/dcim/devices/".to_owned());
            assert_eq!(received(&server).await, [get.clone(), get.clone(), get]);
        }
    }

    #[tokio::test]
    async fn a_read_still_failing_gives_the_gateway_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(ResponseTemplate::new(502).set_body_string("upstream is gone"))
            .mount(&server)
            .await;
        let error = message(client(&server).list("dcim.devices", &no_filters()).await.unwrap_err());
        assert!(error.contains("502"), "{error}");
        assert!(error.contains("upstream is gone"), "{error}");
        // The first try and three replays.
        assert_eq!(received(&server).await.len(), 4);
    }

    #[tokio::test]
    async fn the_wait_before_a_replay_starts_at_the_backoff_and_doubles() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value")
            .retry_backoff(Duration::from_millis(40))
            .build()
            .unwrap();
        let started = Instant::now();
        netbox.list("dcim.devices", &no_filters()).await.unwrap_err();
        // 40 + 80 + 160 ms.
        assert!(started.elapsed() >= Duration::from_millis(280), "{:?}", started.elapsed());
        assert_eq!(received(&server).await.len(), 4);
    }

    #[tokio::test]
    async fn another_error_answer_is_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        client(&server).list("dcim.devices", &no_filters()).await.unwrap_err();
        assert_eq!(received(&server).await.len(), 1);
    }

    #[tokio::test]
    async fn a_read_timeout_is_not_retried() {
        // A hung NetBox must cost one timeout, not one per retry, or the cron run stalls.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(page(json!([])).set_delay(Duration::from_millis(500)))
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value")
            .timeout(Duration::from_millis(100))
            .retry_backoff(Duration::ZERO)
            .build()
            .unwrap();
        netbox.list("dcim.devices", &no_filters()).await.unwrap_err();
        // Long enough for a replay to reach the mock.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(received(&server).await.len(), 1);
    }

    #[tokio::test]
    async fn a_refused_connection_fails_at_once() {
        // Nothing listens on the port once the listener is gone.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let netbox = NetboxClient::builder(&url, "token-value").retry_backoff(Duration::from_secs(3)).build().unwrap();
        let started = Instant::now();
        netbox.list("dcim.devices", &no_filters()).await.unwrap_err();
        // A replay would have waited for the backoff first.
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_write_is_never_retried() {
        // A POST that got a 502 may have been applied: replaying it could create twice.
        let server = MockServer::start().await;
        Mock::given(path("/api/dcim/devices/")).respond_with(ResponseTemplate::new(502)).mount(&server).await;
        Mock::given(path("/api/dcim/devices/7/")).respond_with(ResponseTemplate::new(503)).mount(&server).await;
        let writes: [(&str, &str, &[&str]); 2] =
            [("post", "/api/dcim/devices/", &["name"]), ("patch", "/api/dcim/devices/{id}/", &["name"])];
        mount_full_schema(&server, &[], &writes).await;
        let netbox = client(&server);
        let created = message(netbox.create("dcim.devices", &row(json!({"name": "a"}))).await.unwrap_err());
        assert!(created.contains("502"), "{created}");
        let updated = message(netbox.update("dcim.devices", 7, &row(json!({"name": "b"}))).await.unwrap_err());
        assert!(updated.contains("503"), "{updated}");
        let deleted = message(netbox.delete("dcim.devices", 7).await.unwrap_err());
        assert!(deleted.contains("503"), "{deleted}");
        assert_eq!(
            received(&server).await,
            [
                ("POST".to_owned(), "/api/dcim/devices/".to_owned()),
                ("PATCH".to_owned(), "/api/dcim/devices/7/".to_owned()),
                ("DELETE".to_owned(), "/api/dcim/devices/7/".to_owned()),
            ]
        );
    }

    #[test]
    fn every_request_is_bounded_in_time() {
        let default = NetboxClient::new("https://netbox.example", "token-value").unwrap();
        assert_eq!(default.timeout(), Duration::from_secs(60));
        assert_eq!(default.retry_backoff(), Duration::from_millis(500));
        let netbox = NetboxClient::builder("https://netbox.example", "token-value")
            .timeout(Duration::from_millis(12_500))
            .build()
            .unwrap();
        assert_eq!(netbox.timeout(), Duration::from_millis(12_500));
    }

    #[tokio::test]
    async fn create_posts_the_payload_and_returns_the_created_object() {
        let server = MockServer::start().await;
        mount_full_schema(&server, &[], &[("post", "/api/ipam/ip-addresses/", &["address", "status"])]).await;
        Mock::given(method("POST"))
            .and(path("/api/ipam/ip-addresses/"))
            .and(body_json(json!({"address": "192.0.2.1/24", "status": "active"})))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({"id": 31, "address": "192.0.2.1/24", "status": {"value": "active"}})),
            )
            .mount(&server)
            .await;
        let created = client(&server)
            .create("ipam.ip_addresses", &row(json!({"address": "192.0.2.1/24", "status": "active"})))
            .await;
        assert_eq!(created, Ok(row(json!({"id": 31, "address": "192.0.2.1/24", "status": {"value": "active"}}))));
    }

    #[tokio::test]
    async fn update_patches_the_object_by_id() {
        let server = MockServer::start().await;
        mount_full_schema(&server, &[], &[("patch", "/api/dcim/interfaces/{id}/", &["description"])]).await;
        Mock::given(method("PATCH"))
            .and(path("/api/dcim/interfaces/7/"))
            .and(body_json(json!({"description": "uplink"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 7, "description": "uplink"})))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(client(&server).update("dcim.interfaces", 7, &row(json!({"description": "uplink"}))).await, Ok(()));
        server.verify().await;
    }

    #[tokio::test]
    async fn delete_deletes_the_object_by_id() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/dcim/interfaces/7/"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(client(&server).delete("dcim.interfaces", 7).await, Ok(()));
        server.verify().await;
    }

    #[tokio::test]
    async fn a_dry_run_refuses_every_write_before_sending_anything() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/dcim/interfaces/"))
            .respond_with(page(json!([{"id": 7}])))
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), "token-value").dry_run(true).build().unwrap();
        let refusal =
            |method: &str| GatewayError::DryRun { method: method.to_owned(), endpoint: "dcim.interfaces".to_owned() };
        assert_eq!(netbox.create("dcim.interfaces", &row(json!({"name": "Ethernet1/1"}))).await, Err(refusal("POST")));
        assert_eq!(netbox.update("dcim.interfaces", 7, &row(json!({"description": "x"}))).await, Err(refusal("PATCH")));
        assert_eq!(netbox.delete("dcim.interfaces", 7).await, Err(refusal("DELETE")));
        // Reading still works.
        assert_eq!(netbox.list("dcim.interfaces", &no_filters()).await.unwrap(), [row(json!({"id": 7}))]);
        assert_eq!(received(&server).await, [("GET".to_owned(), "/api/dcim/interfaces/".to_owned())]);
    }

    #[tokio::test]
    async fn a_refused_write_reports_the_status_and_what_netbox_says() {
        let server = MockServer::start().await;
        mount_full_schema(&server, &[], &[("post", "/api/dcim/interfaces/", &["name", "type"])]).await;
        Mock::given(method("POST"))
            .and(path("/api/dcim/interfaces/"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"name": ["This field is required."]})))
            .mount(&server)
            .await;
        let netbox = NetboxClient::new(&server.uri(), SENTINEL).unwrap();
        let error = message(netbox.create("dcim.interfaces", &row(json!({"type": "other"}))).await.unwrap_err());
        assert!(error.contains("400"), "{error}");
        assert!(error.contains("This field is required."), "{error}");
        assert!(error.contains("POST"), "{error}");
        assert!(!error.contains(SENTINEL), "{error}");
    }

    #[tokio::test]
    async fn an_error_never_shows_the_token() {
        let server = MockServer::start().await;
        // A NetBox, or a proxy, that echoes the credentials it refuses.
        let echo = format!("invalid credentials: Token {SENTINEL}");
        Mock::given(path("/api/dcim/devices/"))
            .respond_with(ResponseTemplate::new(403).set_body_string(echo))
            .mount(&server)
            .await;
        Mock::given(path("/api/dcim/devices/7/"))
            .respond_with(ResponseTemplate::new(403).set_body_string(SENTINEL))
            .mount(&server)
            .await;
        Mock::given(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(403).set_body_string(SENTINEL))
            .mount(&server)
            .await;
        let netbox = NetboxClient::builder(&server.uri(), SENTINEL).retry_backoff(Duration::ZERO).build().unwrap();
        let errors = [
            netbox.list("dcim.devices", &no_filters()).await.unwrap_err(),
            netbox.list("dcim.devices", &filters([("name", "a")])).await.unwrap_err(),
            netbox.create("dcim.devices", &row(json!({"name": "a"}))).await.unwrap_err(),
            netbox.delete("dcim.devices", 7).await.unwrap_err(),
        ];
        for error in errors {
            let error = message(error);
            assert!(error.contains("403"), "{error}");
            assert!(!error.contains(SENTINEL), "{error}");
        }
        assert!(!format!("{netbox:?}").contains(SENTINEL));
    }

    #[tokio::test]
    async fn a_connection_error_never_shows_the_token() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let netbox = NetboxClient::new(&url, SENTINEL).unwrap();
        let error = message(netbox.delete("dcim.devices", 7).await.unwrap_err());
        assert!(error.contains("/api/dcim/devices/7/"), "{error}");
        assert!(!error.contains(SENTINEL), "{error}");
    }

    /// Every way an error can be printed; a request error has no cause to print.
    fn printed(error: &GatewayError) -> String {
        assert!(std::error::Error::source(error).is_none(), "{error:?}");
        format!("{error} {error:?}")
    }

    #[tokio::test]
    async fn a_connection_error_names_netbox_and_its_host_never_the_token() {
        // Nothing listens there.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        let netbox = NetboxClient::new(&format!("http://{closed}"), SENTINEL).unwrap();
        let refused = netbox.delete("dcim.devices", 7).await.unwrap_err();
        let text = printed(&refused);
        assert!(message(refused).starts_with(&format!("NetBox {closed}: DELETE /api/dcim/devices/7/: ")), "{text}");
        assert!(!text.contains(SENTINEL), "{text}");

        // A server that does not speak TLS.
        let server = MockServer::start().await;
        let netbox = NetboxClient::new(&format!("https://{}", server.address()), SENTINEL).unwrap();
        let no_tls = netbox.delete("dcim.devices", 7).await.unwrap_err();
        let text = printed(&no_tls);
        let expected = format!("NetBox {}: DELETE /api/dcim/devices/7/: ", server.address());
        assert!(message(no_tls).starts_with(&expected), "{text}");
        assert!(!text.contains(SENTINEL), "{text}");

        // An answer that comes too late.
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let netbox =
            NetboxClient::builder(&server.uri(), SENTINEL).timeout(Duration::from_millis(100)).build().unwrap();
        let late = netbox.delete("dcim.devices", 7).await.unwrap_err();
        let text = printed(&late);
        assert!(message(late).starts_with(&expected), "{text}");
        assert!(!text.contains(SENTINEL), "{text}");
    }

    #[tokio::test]
    async fn an_answer_that_cannot_be_decoded_never_shows_the_token() {
        let server = MockServer::start().await;
        // A count that is not a number: the decoder quotes what it found instead.
        Mock::given(method("GET"))
            .and(path("/api/dcim/devices/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"count": SENTINEL, "results": []})))
            .mount(&server)
            .await;
        let netbox = NetboxClient::new(&server.uri(), SENTINEL).unwrap();
        let error = netbox.list("dcim.devices", &no_filters()).await.unwrap_err();
        let text = printed(&error);
        assert!(text.contains("GET /api/dcim/devices/?limit=250&offset=0: unexpected answer: "), "{text}");
        assert!(!text.contains(SENTINEL), "{text}");
    }

    #[test]
    fn a_url_carrying_credentials_is_refused_without_showing_them() {
        let error = NetboxClient::new(&format!("https://admin:{SENTINEL}@netbox.example"), "token-value").unwrap_err();
        assert_eq!(message(error), "NetBox URL \"https://***@netbox.example\": credentials in the URL are refused");
        let urls = [
            format!("https://admin:{SENTINEL}@netbox.example/prefix"),
            format!("https://{SENTINEL}@netbox.example"),
            format!("ftp://admin:{SENTINEL}@netbox.example"),
            format!("admin:{SENTINEL}@netbox.example"),
            format!("https://admin:{SENTINEL}@"),
            format!("https://admin:pass/{SENTINEL}@netbox.example"),
        ];
        for url in urls {
            let error = NetboxClient::new(&url, "token-value").expect_err("a URL with credentials");
            let text = printed(&error);
            assert!(text.starts_with("NetBox URL \""), "{text}");
            assert!(!text.contains(SENTINEL), "{text}");
            assert!(!text.contains("admin"), "{text}");
        }
    }

    #[test]
    fn a_token_that_cannot_be_a_header_is_refused_without_being_shown() {
        let token = format!("{SENTINEL}\nX-Injected: 1");
        let error = message(NetboxClient::new("https://netbox.example", &token).unwrap_err());
        assert!(!error.contains(SENTINEL), "{error}");
    }

    #[test]
    fn a_url_that_is_not_http_is_refused() {
        for url in ["netbox.example", "ftp://netbox.example", ""] {
            assert!(matches!(NetboxClient::new(url, "token-value"), Err(GatewayError::Request(_))), "{url}");
        }
    }

    /// A self-signed certificate made for this test; its key was thrown away.
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
        let build = |file: &Path| NetboxClient::builder("https://netbox.example", "token-value").ca_file(file).build();
        let built = (build(&good).is_ok(), build(&empty), build(&missing));
        assert!(built.0);
        let no_certificate = message(built.1.unwrap_err());
        assert!(no_certificate.contains("empty.pem"), "{no_certificate}");
        let unreadable = message(built.2.unwrap_err());
        assert!(unreadable.contains("missing.pem"), "{unreadable}");
    }

    #[test]
    fn certificate_validation_can_be_turned_off() {
        assert!(NetboxClient::builder("https://netbox.example", "token-value").validate_certs(false).build().is_ok());
    }
}
