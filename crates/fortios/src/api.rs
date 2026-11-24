//! Read-only client of the FortiOS REST API, one session per collection.

use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use omnisync_core::network::collect::CollectionError;
use omnisync_core::network::inventory::{Secret, Source};
use omnisync_tls::{Fingerprint, is_pin_mismatch, pinned_tls, tls_error};
use reqwest::header::{CONTENT_TYPE, COOKIE, HeaderValue, SET_COOKIE};
use reqwest::{Method, StatusCode, redirect};

use crate::collect::Fetcher;

/// Time a request may take before it fails.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The first wait before replaying a read; doubled at each retry.
pub const RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// How many times a read answered by a gateway error is replayed.
pub const RETRIES: u32 = 3;

/// Answers of the firewall, or of what stands before it, after which a read is replayed.
const GATEWAY_ERRORS: [StatusCode; 3] =
    [StatusCode::BAD_GATEWAY, StatusCode::SERVICE_UNAVAILABLE, StatusCode::GATEWAY_TIMEOUT];

/// The configuration of every interface, restricted to the fields read.
pub const INTERFACES: &str = "cmdb/system/interface?format=name|type|alias|description|status|mtu-override|mtu|vlanid|\
                              interface|member|ip|secondary-IP|secondaryip|vdom";
/// The MAC and the link of the interfaces.
pub const MONITOR: &str = "monitor/system/interface?include_vlan=true&include_aggregate=true";
/// The host name and the serial of the unit that answers.
pub const STATUS: &str = "monitor/system/status";
/// The members of the cluster.
pub const HA: &str = "monitor/system/ha-peer";

/// The login of a session, the only route posted to with the account.
const LOGIN: &str = "api/v2/authentication";

/// The login that opened the session.
const LOGIN_SUCCESS: &str = "LOGIN_SUCCESS";

/// The statuses the login route answers (`status_message`, status_code -4 to
/// 5), with what a refusal means.
const LOGIN_STATUSES: [(&str, &str); 7] = [
    (LOGIN_SUCCESS, ""),
    ("LOGIN_FAILED", "wrong user or password"),
    ("LOGIN_LOCKED_OUT", "account locked out"),
    ("LOGIN_ACCEPT_PRE_LOGIN_DISCLAIMER", "a login disclaimer is to be accepted"),
    ("LOGIN_ACCEPT_POST_LOGIN_DISCLAIMER", "a login disclaimer is to be accepted"),
    ("LOGIN_TFA", "two-factor authentication asked"),
    ("LOGIN_CHANGE_PWD_NEEDED", "the password must be changed"),
];

/// Paths of the FortiOS REST API, under /api/v2. `format` restricts the cmdb answer
/// to the fields read, none of them a secret.
///
/// The list is closed: the client fetches nothing else.
pub const FORTIOS_COMMANDS: [(&str, &str); 4] =
    [("interfaces", INTERFACES), ("monitor", MONITOR), ("status", STATUS), ("ha", HA)];

/// Why a request got no answer. An HTTP library error may quote the request:
/// only its kind is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The certificate presented is not the one of `tls_fingerprint`.
    Pin,
    /// Any other TLS failure (protocol, cipher): not a matter of fingerprint.
    Tls,
    ConnectTimeout,
    ReadTimeout,
    Connection,
}

impl Failure {
    fn of(error: &reqwest::Error) -> Self {
        match tls_error(error) {
            Some(_) if is_pin_mismatch(error) => Failure::Pin,
            Some(_) => Failure::Tls,
            None if error.is_timeout() && error.is_connect() => Failure::ConnectTimeout,
            None if error.is_timeout() => Failure::ReadTimeout,
            None => Failure::Connection,
        }
    }

    /// The name the reference tool prints for this kind of failure.
    fn name(self) -> &'static str {
        match self {
            Failure::Pin | Failure::Tls => "SSLError",
            Failure::ConnectTimeout => "ConnectTimeout",
            Failure::ReadTimeout => "ReadTimeout",
            Failure::Connection => "ConnectionError",
        }
    }
}

/// `path` as it is sent: what a URL does not take as is (the `|` of `format`)
/// is percent-encoded, the delimiters of the path and of the query are kept.
fn requote(path: &str) -> String {
    let mut quoted = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~!#$%&'()*+,/:;=?@[]".contains(&byte) {
            quoted.push(char::from(byte));
        } else {
            quoted.push_str(&format!("%{byte:02X}"));
        }
    }
    quoted
}

/// The call a path makes, as the errors name it: no prefix, no query.
fn call_of(path: &str) -> &str {
    let call = path.split('?').next().unwrap_or(path);
    call.strip_prefix("api/v2/").unwrap_or(call)
}

/// The date of an `Expires` attribute, in seconds since 1970, read as RFC 6265
/// (5.1.1) tells: `Thu, 01 Jan 1970 00:00:00 GMT` as well as the older
/// `Thursday, 01-Jan-70 00:00:00 GMT`. None: not a date.
fn cookie_date(text: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let number = |token: &str| token.parse::<i64>().ok().filter(|_| token.bytes().all(|byte| byte.is_ascii_digit()));
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    // The first token that fits each part is that part, in this order of trial.
    for token in text.split(|c: char| !c.is_ascii_alphanumeric() && c != ':').filter(|token| !token.is_empty()) {
        let clock: Vec<&str> = token.split(':').collect();
        if time.is_none() && clock.len() == 3 && clock.iter().all(|part| matches!(part.len(), 1 | 2)) {
            time = Some((number(clock[0])?, number(clock[1])?, number(clock[2])?));
        } else if day.is_none() && matches!(token.len(), 1 | 2) && number(token).is_some() {
            day = number(token);
        } else if month.is_none()
            && let Some(found) = MONTHS.iter().position(|name| token.to_ascii_lowercase().starts_with(name))
        {
            month = i64::try_from(found + 1).ok();
        } else if year.is_none() && matches!(token.len(), 2..=4) && number(token).is_some() {
            year = number(token);
        }
    }
    let ((hour, minute, second), day, month, year) = (time?, day?, month?, year?);
    // A year of two digits is of the 1900s from 70, of the 2000s before.
    let year = match year {
        70..=99 => year + 1900,
        0..=69 => year + 2000,
        _ => year,
    };
    if !(1..=31).contains(&day) || year < 1601 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days since 1970 of a date of the Gregorian calendar, the year counted from March.
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted.rem_euclid(400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// The cookies of the session: what the firewall set, minus what it deleted.
///
/// The client talks to one host and follows no redirection: every cookie goes
/// back to that host, whatever its `Domain` and its `Path`.
#[derive(Default)]
struct Cookies(Vec<(String, String)>);

impl Cookies {
    /// Applies one `Set-Cookie` header received at `now`, in seconds since 1970.
    fn set(&mut self, header: &str, now: i64) {
        let mut parts = header.split(';');
        let Some((name, value)) = parts.next().and_then(|pair| pair.split_once('=')) else {
            return;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() {
            return;
        }
        let (mut max_age, mut expires) = (None, None);
        for attribute in parts {
            let (key, setting) = attribute.split_once('=').unwrap_or((attribute, ""));
            match key.trim().to_ascii_lowercase().as_str() {
                "max-age" => max_age = setting.trim().parse::<i64>().ok(),
                "expires" => expires = cookie_date(setting),
                _ => {}
            }
        }
        // Max-Age wins over Expires; a cookie without either lasts as long as the client.
        let expired = match (max_age, expires) {
            (Some(age), _) => age <= 0,
            (None, Some(at)) => at <= now,
            (None, None) => false,
        };
        self.0.retain(|(known, _)| known != name);
        if !expired {
            self.0.push((name.to_owned(), value.to_owned()));
        }
    }

    /// The `Cookie` header that sends them back; None without any cookie.
    fn header(&self) -> Option<String> {
        let pairs: Vec<String> = self.0.iter().map(|(name, value)| format!("{name}={value}")).collect();
        (!pairs.is_empty()).then(|| pairs.join("; "))
    }
}

/// Command runner over the REST API: a command is the path of a GET.
pub struct FortiosClient {
    http: reqwest::Client,
    /// The session, once the login opened it.
    cookies: Mutex<Cookies>,
    host: String,
    base_url: String,
    username: String,
    password: Secret,
    retry_backoff: Duration,
}

impl fmt::Debug for FortiosClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the password.
        formatter.debug_struct("FortiosClient").field("base_url", &self.base_url).finish_non_exhaustive()
    }
}

impl FortiosClient {
    /// The client of the firewall of an inventory entry; nothing is sent yet.
    pub fn for_source(source: &Source, timeout: Duration) -> Result<Self, CollectionError> {
        let (Some(password), Some(fingerprint)) = (&source.password, &source.tls_fingerprint) else {
            return Err(CollectionError("no API credentials or certificate fingerprint configured".to_owned()));
        };
        // An account the environment does not hold: the firewall was not meant
        // to be read from this host. No client is built, so that no login is
        // ever sent with an empty user or password; the refusal names the variables.
        let password = password.held().map_err(|missing| CollectionError(missing.to_string()))?;
        // `host` may carry the port of the API (`192.0.2.1:9443`).
        let host = match source.port {
            None => source.host.clone(),
            Some(port) => format!("{}:{port}", source.host),
        };
        let unusable = |why: &dyn fmt::Display| CollectionError(format!("API of {host}: {why}"));
        let fingerprint =
            Fingerprint::parse(fingerprint).map_err(|error| unusable(&format!("tls_fingerprint {error}")))?;
        let tls = pinned_tls(fingerprint).map_err(|error| unusable(&error))?;
        let base_url = format!("https://{host}");
        FortiosClient::build(&host, base_url, &source.username, password.clone(), Some(tls), timeout)
    }

    /// A client over plain HTTP, for the mock server of the tests only.
    #[cfg(test)]
    fn plain(base_url: &str, username: &str, password: &str, timeout: Duration) -> Self {
        let host = base_url.trim_start_matches("http://");
        FortiosClient::build(host, base_url.to_owned(), username, Secret::new(password), None, timeout)
            .expect("a client without TLS settings")
    }

    fn build(
        host: &str,
        base_url: String,
        username: &str,
        password: Secret,
        tls: Option<rustls::ClientConfig>,
        timeout: Duration,
    ) -> Result<Self, CollectionError> {
        let mut http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // Neither the proxy nor the .netrc of the environment (reqwest reads no
            // .netrc): through a proxy the certificate would not be pinned, and the
            // credentials would leave anyway.
            .no_proxy()
            // A redirection is never followed: it would replay the credentials elsewhere.
            .redirect(redirect::Policy::none());
        if let Some(tls) = tls {
            http = http.tls_backend_preconfigured(tls).https_only(true);
        }
        // Nothing secret was handed to the builder: its error can be printed.
        let http = http.build().map_err(|error| CollectionError(format!("API of {host}: HTTP client: {error}")))?;
        Ok(FortiosClient {
            http,
            cookies: Mutex::new(Cookies::default()),
            host: host.to_owned(),
            base_url,
            username: username.to_owned(),
            password,
            retry_backoff: RETRY_BACKOFF,
        })
    }

    /// First wait before replaying a read, 0.5 s by default; doubled at each retry.
    pub fn retry_backoff(mut self, backoff: Duration) -> Self {
        self.retry_backoff = backoff;
        self
    }

    /// Sends a request with the cookies of the session, and keeps the ones its answer sets.
    async fn send(&self, mut request: reqwest::RequestBuilder) -> Result<reqwest::Response, reqwest::Error> {
        let sent = self.cookies.lock().unwrap_or_else(PoisonError::into_inner).header();
        if let Some(mut cookies) = sent.and_then(|cookies| HeaderValue::from_str(&cookies).ok()) {
            // The session is never printed: neither here nor by reqwest, which is told it is sensitive.
            cookies.set_sensitive(true);
            request = request.header(COOKIE, cookies);
        }
        let response = request.send().await?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        let mut cookies = self.cookies.lock().unwrap_or_else(PoisonError::into_inner);
        for header in response.headers().get_all(SET_COOKIE) {
            if let Ok(header) = header.to_str() {
                cookies.set(header, now);
            }
        }
        Ok(response)
    }

    /// The two POSTs of a session, its login and its logout: nothing else is ever posted.
    async fn post(&self, path: &str, json: Option<String>) -> Result<reqwest::Response, reqwest::Error> {
        let request = self.http.post(format!("{}/{path}", self.base_url));
        match json {
            Some(json) => self.send(request.header(CONTENT_TYPE, "application/json").body(json)).await,
            None => self.send(request).await,
        }
    }

    /// Opens the session, through `POST /api/v2/authentication`.
    ///
    /// `/logincheck`, the login of the reference tool, opens no session from
    /// FortiOS 7.6.3 (Fortinet, "logincheck no longer returns a session
    /// cookie", 2026-05-28). The route that replaces it reads the password in
    /// `secretkey` on FortiOS 7.4, in `password` in the example Fortinet gives
    /// for 7.6.3: it is sent in both, which FortiOS 7.4.11 takes (forti01,
    /// 2026-11-20).
    pub async fn login(&self) -> Result<(), CollectionError> {
        let password = self.password.expose();
        let body =
            serde_json::json!({"username": self.username, "secretkey": password, "password": password}).to_string();
        // One attempt only: every extra one counts as a failed login on the firewall.
        let response = self.post(LOGIN, Some(body)).await.map_err(|error| {
            CollectionError(match Failure::of(&error) {
                Failure::Pin => {
                    format!("API of {}: the certificate presented is not the one of tls_fingerprint", self.host)
                }
                // The error may quote the request: only its kind is reported.
                other => format!("API of {}: login failed: {}", self.host, other.name()),
            })
        })?;
        if response.status() != StatusCode::OK {
            return Err(CollectionError(format!(
                "API of {}: login refused: HTTP {}",
                self.host,
                response.status().as_u16()
            )));
        }
        // A refused login is answered 200 as well: the status in the body
        // tells. Only a status of the closed list is named: the body itself
        // is never quoted, it may hold what was sent.
        let body = response.bytes().await.unwrap_or_default();
        let status = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|answer| answer.get("status_message").and_then(serde_json::Value::as_str).map(str::to_owned));
        match status.as_deref().and_then(|status| LOGIN_STATUSES.iter().find(|(known, _)| *known == status)) {
            None => Err(CollectionError(format!("API of {}: login answered 200 without a known status", self.host))),
            Some((LOGIN_SUCCESS, _)) => {
                // Taken without the cookie of a session: every read would be refused.
                if self.cookies.lock().unwrap_or_else(PoisonError::into_inner).header().is_none() {
                    return Err(CollectionError(format!("API of {}: login accepted but opened no session", self.host)));
                }
                Ok(())
            }
            Some((status, why)) => {
                Err(CollectionError(format!("API of {}: login refused: {status} ({why})", self.host)))
            }
        }
    }

    /// The body of the answer to `method` on `path`; anything but a GET is refused.
    async fn request(&self, method: &Method, path: &str) -> Result<String, CollectionError> {
        if method != Method::GET {
            return Err(CollectionError(format!("{method} refused: the firewall is read only")));
        }
        let call = call_of(path);
        // No answer: the message names the API and its host, as the one of a login does.
        let failed = |error: reqwest::Error| {
            CollectionError(format!("API of {}: {call}: {}", self.host, Failure::of(&error).name()))
        };
        let url = format!("{}/{}", self.base_url, requote(path));
        // A read answered by a gateway error is replayed, as the NetBox reads are;
        // a timeout or a refused connection fails at once.
        let mut wait = self.retry_backoff;
        let mut replayed = 0;
        loop {
            let response = self.send(self.http.get(&url)).await.map_err(failed)?;
            let status = response.status();
            if GATEWAY_ERRORS.contains(&status) && replayed < RETRIES {
                replayed += 1;
                tokio::time::sleep(wait).await;
                wait = wait.saturating_mul(2);
                continue;
            }
            // A refused login shows here too: the firewall answers 401 without a session.
            if status != StatusCode::OK {
                return Err(CollectionError(format!("API of {}: {call}: HTTP {}", self.host, status.as_u16())));
            }
            let body = response.bytes().await.map_err(failed)?;
            // A wrong decoding would write corrupted descriptions to NetBox.
            return String::from_utf8(body.to_vec())
                .map_err(|_| CollectionError(format!("{call}: answer is not UTF-8")));
        }
    }

    /// The body of the answer to one of [`FORTIOS_COMMANDS`]; any other path is refused.
    pub async fn run(&self, command: &str) -> Result<String, CollectionError> {
        if !FORTIOS_COMMANDS.iter().any(|(_, known)| *known == command) {
            return Err(CollectionError(format!(
                "{}: refused: not one of the calls of the collection",
                call_of(command)
            )));
        }
        self.request(&Method::GET, &format!("api/v2/{command}")).await
    }

    /// Closes the session.
    pub async fn logout(&self) {
        // A session left open expires on its own: a failed logout loses nothing.
        let _ = self.post("logout", None).await;
    }

    /// Opens the session, hands the client to `work`, then closes the session
    /// whatever `work` ended in.
    pub async fn session<T>(
        &mut self,
        work: impl AsyncFnOnce(&mut Self) -> Result<T, CollectionError>,
    ) -> Result<T, CollectionError> {
        self.login().await?;
        let outcome = work(self).await;
        self.logout().await;
        outcome
    }
}

impl Fetcher for FortiosClient {
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        FortiosClient::run(self, command).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use omnisync_core::network::inventory::{Kind, Wanted};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const PASSWORD: &str = "pw-forti";
    // Values that must never show in an error.
    const SENTINEL_PASSWORD: &str = "s3ntinel-p4ssword";
    const SENTINEL_COOKIE: &str = "s3ntinel-c00kie";
    const STATUS_PATH: &str = "/api/v2/monitor/system/status";
    const LOGIN_PATH: &str = "/api/v2/authentication";
    /// What FortiOS 7.4.11 (forti01) answered a login it took, whole: the
    /// session comes in its cookies.
    const LOGIN_SUCCESS: &str = r#"{"status_code":5,"status_message":"LOGIN_SUCCESS"}"#;
    const EMPTY: &str = r#"{"results": []}"#;

    /// (method, path as received, text fields of a JSON body, had the session cookie)
    type Seen = (String, String, Vec<(String, String)>, bool);

    /// A fake firewall: any login opens the session `session=<cookie>`, and only
    /// the reads of that session are answered.
    async fn firewall_with(cookie: &str) -> MockServer {
        let server = MockServer::start().await;
        let opened = format!("session={cookie}; Path=/");
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(LOGIN_SUCCESS).insert_header("set-cookie", opened.as_str()),
            )
            .with_priority(9)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/logout"))
            .respond_with(ResponseTemplate::new(200))
            .with_priority(9)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(header("cookie", format!("session={cookie}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(EMPTY))
            .with_priority(9)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .with_priority(10)
            .mount(&server)
            .await;
        server
    }

    async fn firewall() -> MockServer {
        firewall_with("open").await
    }

    /// Status codes to answer on `at` before the real answer.
    async fn fail(server: &MockServer, verb: &str, at: &str, statuses: &[u16]) {
        for (rank, status) in (1u8..).zip(statuses) {
            let mut answer = ResponseTemplate::new(*status).set_body_string("gateway error");
            if (300..400).contains(status) {
                answer = answer.insert_header("location", "/elsewhere");
            }
            Mock::given(method(verb))
                .and(path(at))
                .respond_with(answer)
                .up_to_n_times(1)
                .with_priority(rank)
                .mount(server)
                .await;
        }
    }

    /// The text fields of a JSON object body, in the order of their names.
    fn fields(body: &[u8]) -> Vec<(String, String)> {
        let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) else {
            return Vec::new();
        };
        object.into_iter().filter_map(|(name, value)| Some((name, value.as_str()?.to_owned()))).collect()
    }

    async fn requests(server: &MockServer) -> Vec<Seen> {
        let received = server.received_requests().await.expect("the requests are recorded");
        received
            .iter()
            .map(|request| {
                let mut target = request.url.path().to_owned();
                if let Some(query) = request.url.query() {
                    target = format!("{target}?{query}");
                }
                let form = fields(&request.body);
                let cookie = request.headers.get("cookie").is_some_and(|value| value.as_bytes() == b"session=open");
                (request.method.to_string(), target, form, cookie)
            })
            .collect()
    }

    /// The paths of the requests received with this method.
    async fn seen(server: &MockServer, verb: &str) -> Vec<String> {
        requests(server).await.into_iter().filter(|(method, ..)| method == verb).map(|(_, target, ..)| target).collect()
    }

    fn client_with(server: &MockServer, password: &str) -> FortiosClient {
        // No wait between two attempts of a replayed read.
        FortiosClient::plain(&server.uri(), "readonly", password, Duration::from_secs(5)).retry_backoff(Duration::ZERO)
    }

    fn client(server: &MockServer) -> FortiosClient {
        client_with(server, PASSWORD)
    }

    fn message<T: fmt::Debug>(result: Result<T, CollectionError>) -> String {
        result.expect_err("a failure").0
    }

    fn source() -> Source {
        Source {
            username: "readonly".to_owned(),
            password: Some(Wanted::Held(Secret::new(PASSWORD))),
            tls_fingerprint: Some("ab".repeat(32)),
            ..Source::new("fw01.dc1", Kind::Firewall, "fortios", "192.0.2.1")
        }
    }

    /// A local port nothing listens on.
    fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        listener.local_addr().expect("the address of the listener").port()
    }

    #[test]
    fn the_calls_are_the_closed_list_of_the_reference_in_order() {
        assert_eq!(
            FORTIOS_COMMANDS,
            [
                (
                    "interfaces",
                    "cmdb/system/interface?format=name|type|alias|description|status|mtu-override|mtu|vlanid|\
                     interface|member|ip|secondary-IP|secondaryip|vdom"
                ),
                ("monitor", "monitor/system/interface?include_vlan=true&include_aggregate=true"),
                ("status", "monitor/system/status"),
                ("ha", "monitor/system/ha-peer"),
            ]
        );
    }

    #[tokio::test]
    async fn logs_in_reads_and_logs_out() {
        let server = firewall().await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        let body = client.run(STATUS).await.expect("the read is answered");
        client.logout().await;
        assert_eq!(body, r#"{"results": []}"#);
        // The password goes in secretkey, which FortiOS 7.4 reads, and in
        // password, which Fortinet shows for 7.6.3; 7.4.11 takes both at once.
        let form = vec![
            ("password".to_owned(), PASSWORD.to_owned()),
            ("secretkey".to_owned(), PASSWORD.to_owned()),
            ("username".to_owned(), "readonly".to_owned()),
        ];
        assert_eq!(
            requests(&server).await,
            [
                ("POST".to_owned(), LOGIN_PATH.to_owned(), form, false),
                ("GET".to_owned(), "/api/v2/monitor/system/status".to_owned(), vec![], true),
                ("POST".to_owned(), "/logout".to_owned(), vec![], true),
            ]
        );
    }

    #[tokio::test]
    async fn query_string_is_percent_encoded() {
        let server = firewall().await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        client.run(INTERFACES).await.expect("the read is answered");
        client.run(MONITOR).await.expect("the read is answered");
        assert_eq!(
            seen(&server, "GET").await,
            [
                "/api/v2/cmdb/system/interface?format=name%7Ctype%7Calias%7Cdescription%7Cstatus%7Cmtu-override%7Cmtu\
                 %7Cvlanid%7Cinterface%7Cmember%7Cip%7Csecondary-IP%7Csecondaryip%7Cvdom",
                "/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true",
            ]
        );
    }

    #[tokio::test]
    async fn login_is_never_replayed() {
        let server = firewall().await;
        fail(&server, "POST", LOGIN_PATH, &[503, 503]).await;
        let refused = message(client(&server).login().await);
        assert_eq!(refused, format!("API of {}: login refused: HTTP 503", server.address()));
        assert_eq!(seen(&server, "POST").await, [LOGIN_PATH]);
        assert!(!refused.contains(PASSWORD));
    }

    #[tokio::test]
    async fn read_is_replayed_on_a_gateway_error() {
        let server = firewall().await;
        fail(&server, "GET", STATUS_PATH, &[503, 502]).await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        assert_eq!(client.run(STATUS).await.expect("the third answer"), r#"{"results": []}"#);
        assert_eq!(seen(&server, "GET").await, [STATUS_PATH; 3]);
    }

    #[tokio::test]
    async fn read_still_refused_after_three_replays_reports_the_last_answer() {
        let server = firewall().await;
        fail(&server, "GET", STATUS_PATH, &[503, 502, 504, 503, 502]).await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        assert_eq!(
            message(client.run(STATUS).await),
            format!("API of {}: monitor/system/status: HTTP 503", server.address())
        );
        // One attempt and three replays.
        assert_eq!(seen(&server, "GET").await, [STATUS_PATH; 4]);
    }

    #[tokio::test]
    async fn refused_read_names_the_call_and_the_status() {
        let server = firewall().await;
        fail(&server, "GET", STATUS_PATH, &[403]).await;
        let mut client = client(&server);
        let outcome = client.session(async |client| client.run(STATUS).await).await;
        assert_eq!(message(outcome), format!("API of {}: monitor/system/status: HTTP 403", server.address()));
        // The session is still closed after a failed read.
        assert_eq!(seen(&server, "POST").await, [LOGIN_PATH, "/logout"]);
    }

    #[tokio::test]
    async fn a_session_gives_the_outcome_of_its_work_and_closes() {
        let server = firewall().await;
        let mut client = client(&server);
        let body = client.session(async |client| client.run(STATUS).await).await;
        assert_eq!(body.expect("the read is answered"), r#"{"results": []}"#);
        let order: Vec<String> = requests(&server).await.into_iter().map(|(_, target, ..)| target).collect();
        assert_eq!(order, [LOGIN_PATH, STATUS_PATH, "/logout"]);
    }

    #[tokio::test]
    async fn a_session_that_does_not_open_runs_nothing() {
        let server = firewall().await;
        fail(&server, "POST", LOGIN_PATH, &[401]).await;
        let mut client = client(&server);
        let outcome = client.session(async |client| client.run(STATUS).await).await;
        assert_eq!(message(outcome), format!("API of {}: login refused: HTTP 401", server.address()));
        assert_eq!(seen(&server, "GET").await, [] as [&str; 0]);
        assert_eq!(seen(&server, "POST").await, [LOGIN_PATH]);
    }

    #[tokio::test]
    async fn read_without_a_session_is_refused_by_the_firewall() {
        let server = firewall().await;
        assert_eq!(
            message(client(&server).run(STATUS).await),
            format!("API of {}: monitor/system/status: HTTP 401", server.address())
        );
    }

    // A login FortiOS says it took, yet without the cookie of a session:
    // every read would be refused, as if the password were wrong.
    #[tokio::test]
    async fn a_login_that_opens_no_session_is_refused_before_any_read() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(LOGIN_SUCCESS))
            .mount(&server)
            .await;
        Mock::given(method("POST")).and(path("/logout")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        let mut client = client(&server);
        let outcome = client.session(async |client| client.run(STATUS).await).await;
        assert_eq!(message(outcome), format!("API of {}: login accepted but opened no session", server.address()));
        assert_eq!(seen(&server, "GET").await, [] as [&str; 0]);
    }

    // FortiOS 7.4.11 answers a refused login 200, without cookie, with
    // `"status_message":"LOGIN_FAILED"` (forti01, 2026-11-20); the other
    // statuses are those of the route (status_code -4 to 4). Each refusal says
    // why, and nothing is read.
    #[tokio::test]
    async fn a_login_the_firewall_refuses_says_why_and_reads_nothing() {
        for (status, why) in [
            (r#"{"status_code":-1,"status_message":"LOGIN_FAILED"}"#, "LOGIN_FAILED (wrong user or password)"),
            (r#"{"status_code":-4,"status_message":"LOGIN_LOCKED_OUT"}"#, "LOGIN_LOCKED_OUT (account locked out)"),
            (
                r#"{"status_code":-2,"status_message":"LOGIN_ACCEPT_PRE_LOGIN_DISCLAIMER"}"#,
                "LOGIN_ACCEPT_PRE_LOGIN_DISCLAIMER (a login disclaimer is to be accepted)",
            ),
            (
                r#"{"status_code":3,"status_message":"LOGIN_ACCEPT_POST_LOGIN_DISCLAIMER"}"#,
                "LOGIN_ACCEPT_POST_LOGIN_DISCLAIMER (a login disclaimer is to be accepted)",
            ),
            (r#"{"status_code":2,"status_message":"LOGIN_TFA"}"#, "LOGIN_TFA (two-factor authentication asked)"),
            (
                r#"{"status_code":4,"status_message":"LOGIN_CHANGE_PWD_NEEDED"}"#,
                "LOGIN_CHANGE_PWD_NEEDED (the password must be changed)",
            ),
        ] {
            let server = MockServer::start().await;
            let refused = ResponseTemplate::new(200).set_body_string(status);
            Mock::given(method("POST")).and(path(LOGIN_PATH)).respond_with(refused).mount(&server).await;
            let mut client = client(&server);
            let outcome = client.session(async |client| client.run(STATUS).await).await;
            assert_eq!(message(outcome), format!("API of {}: login refused: {why}", server.address()));
            assert_eq!(seen(&server, "POST").await, [LOGIN_PATH]);
        }
    }

    // An answer that is not a login status (an HTML page, a status this client
    // does not know) is refused without being quoted: it may quote the account.
    #[tokio::test]
    async fn a_login_answer_that_is_no_known_status_is_refused_without_quoting_it() {
        for answer in [
            format!("<html>bad secretkey {SENTINEL_PASSWORD}</html>"),
            format!(r#"{{"status_message":"{SENTINEL_PASSWORD}"}}"#),
        ] {
            let server = MockServer::start().await;
            let refused = ResponseTemplate::new(200).set_body_string(answer);
            Mock::given(method("POST")).and(path(LOGIN_PATH)).respond_with(refused).mount(&server).await;
            let error = client_with(&server, SENTINEL_PASSWORD).login().await.expect_err("an unknown answer");
            assert_eq!(error.0, format!("API of {}: login answered 200 without a known status", server.address()));
            assert!(!format!("{error} {error:?}").contains(SENTINEL_PASSWORD));
        }
    }

    #[tokio::test]
    async fn only_reads_go_through_the_session() {
        let server = firewall().await;
        let mut client = client(&server);
        client
            .session(async |client| {
                for verb in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
                    let refused = message(client.request(&verb, "api/v2/cmdb/system/interface/x1").await);
                    assert_eq!(refused, format!("{verb} refused: the firewall is read only"));
                }
                Ok(())
            })
            .await
            .expect("the session opens");
        // Nothing but the login and the logout was sent.
        let order: Vec<(String, String)> =
            requests(&server).await.into_iter().map(|(verb, target, ..)| (verb, target)).collect();
        assert_eq!(order, [("POST".to_owned(), LOGIN_PATH.to_owned()), ("POST".to_owned(), "/logout".to_owned())]);
    }

    #[tokio::test]
    async fn a_path_outside_the_closed_list_is_refused_before_anything_is_sent() {
        let server = firewall().await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        for (command, call) in [
            ("cmdb/system/admin", "cmdb/system/admin"),
            // A listed call without its `format`: every field, secrets included.
            ("cmdb/system/interface", "cmdb/system/interface"),
            ("monitor/system/status?vdom=*", "monitor/system/status"),
            ("monitor/system/status/../../../cmdb/system/admin", "monitor/system/status/../../../cmdb/system/admin"),
            ("", ""),
        ] {
            assert_eq!(
                message(client.run(command).await),
                format!("{call}: refused: not one of the calls of the collection")
            );
        }
        assert_eq!(seen(&server, "GET").await, [] as [&str; 0]);
    }

    #[tokio::test]
    async fn redirected_login_is_refused_without_following() {
        let server = firewall().await;
        fail(&server, "POST", LOGIN_PATH, &[307]).await;
        let refused = message(client(&server).login().await);
        assert_eq!(refused, format!("API of {}: login refused: HTTP 307", server.address()));
        let order: Vec<String> = requests(&server).await.into_iter().map(|(_, target, ..)| target).collect();
        assert_eq!(order, [LOGIN_PATH]);
    }

    #[tokio::test]
    async fn redirected_read_is_refused_without_following() {
        let server = firewall().await;
        fail(&server, "GET", STATUS_PATH, &[302]).await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        assert_eq!(
            message(client.run(STATUS).await),
            format!("API of {}: monitor/system/status: HTTP 302", server.address())
        );
        assert_eq!(seen(&server, "GET").await, [STATUS_PATH]);
    }

    #[tokio::test]
    async fn an_answer_that_is_not_utf8_is_refused() {
        let server = firewall().await;
        // `é` in Windows-1252 is the single byte E9, which is not UTF-8.
        Mock::given(method("GET"))
            .and(path(STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"{\"results\": \"r\xe9seau\"}".to_vec()))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        assert_eq!(message(client.run(STATUS).await), "monitor/system/status: answer is not UTF-8");
    }

    #[tokio::test]
    async fn a_refused_login_never_carries_the_password() {
        let server = firewall().await;
        // A firewall, or a proxy, that quotes what it received.
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(ResponseTemplate::new(503).set_body_string(format!("bad secretkey {SENTINEL_PASSWORD}")))
            .with_priority(1)
            .mount(&server)
            .await;
        let error = client_with(&server, SENTINEL_PASSWORD).login().await.expect_err("a refused login");
        assert_eq!(error.0, format!("API of {}: login refused: HTTP 503", server.address()));
        assert!(!format!("{error} {error:?}").contains(SENTINEL_PASSWORD));
    }

    #[tokio::test]
    async fn a_login_that_cannot_connect_names_the_kind_of_failure_only() {
        let port = closed_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let client = FortiosClient::plain(&base_url, "readonly", SENTINEL_PASSWORD, Duration::from_secs(5));
        let error = client.login().await.expect_err("nothing listens");
        assert_eq!(error.0, format!("API of 127.0.0.1:{port}: login failed: ConnectionError"));
        assert!(!format!("{error} {error:?}").contains(SENTINEL_PASSWORD));
    }

    #[tokio::test]
    async fn a_refused_read_never_carries_the_password_nor_the_session_cookie() {
        let server = firewall_with(SENTINEL_COOKIE).await;
        // A firewall, or a proxy, that quotes what it received.
        let quoted = format!("denied: secretkey {SENTINEL_PASSWORD}, Cookie session={SENTINEL_COOKIE}");
        Mock::given(method("GET"))
            .and(path(STATUS_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_string(quoted))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = client_with(&server, SENTINEL_PASSWORD);
        client.login().await.expect("the login is accepted");
        let error = client.run(STATUS).await.expect_err("a refused read");
        assert_eq!(error.0, format!("API of {}: monitor/system/status: HTTP 403", server.address()));
        let printed = format!("{error} {error:?}");
        assert!(!printed.contains(SENTINEL_PASSWORD) && !printed.contains(SENTINEL_COOKIE), "{printed}");
    }

    #[tokio::test]
    async fn a_read_that_times_out_names_the_call_and_the_kind_of_failure_only() {
        let server = firewall_with(SENTINEL_COOKIE).await;
        Mock::given(method("GET"))
            .and(path(STATUS_PATH))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = FortiosClient::plain(&server.uri(), "readonly", SENTINEL_PASSWORD, Duration::from_millis(300));
        client.login().await.expect("the login is accepted");
        let error = client.run(STATUS).await.expect_err("no answer in time");
        assert_eq!(error.0, format!("API of {}: monitor/system/status: ReadTimeout", server.address()));
        let printed = format!("{error} {error:?}");
        assert!(!printed.contains(SENTINEL_PASSWORD) && !printed.contains(SENTINEL_COOKIE), "{printed}");
        // A timeout fails at once: it is not replayed.
        assert_eq!(seen(&server, "GET").await, [STATUS_PATH]);
    }

    #[tokio::test]
    async fn a_read_that_cannot_connect_names_the_call_and_the_kind_of_failure_only() {
        let port = closed_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let client = FortiosClient::plain(&base_url, "readonly", SENTINEL_PASSWORD, Duration::from_secs(5));
        let error = client.run(STATUS).await.expect_err("nothing listens");
        assert_eq!(error.0, format!("API of 127.0.0.1:{port}: monitor/system/status: ConnectionError"));
    }

    /// An account whose name must never show in an error.
    const SENTINEL_USER: &str = "0perator-never-shown";

    /// Every way an error can be printed; it has no cause to print.
    fn printed(error: &CollectionError) -> String {
        assert!(std::error::Error::source(error).is_none(), "{error:?}");
        format!("{error} {error:?}")
    }

    #[tokio::test]
    async fn a_connection_error_names_the_api_and_its_host_never_the_account() {
        let port = closed_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let client = FortiosClient::plain(&base_url, SENTINEL_USER, SENTINEL_PASSWORD, Duration::from_secs(5));
        let login = client.login().await.expect_err("nothing listens");
        assert_eq!(login.0, format!("API of 127.0.0.1:{port}: login failed: ConnectionError"));
        let read = client.run(STATUS).await.expect_err("nothing listens");
        assert_eq!(read.0, format!("API of 127.0.0.1:{port}: monitor/system/status: ConnectionError"));
        let text = format!("{} {} {client:?}", printed(&login), printed(&read));
        assert!(!text.contains(SENTINEL_USER) && !text.contains(SENTINEL_PASSWORD), "{text}");
    }

    #[tokio::test]
    async fn a_refused_login_or_read_never_carries_the_account() {
        let server = firewall().await;
        // A firewall, or a proxy, that quotes what it received.
        let quoted = format!("denied: username {SENTINEL_USER}, secretkey {SENTINEL_PASSWORD}");
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(ResponseTemplate::new(401).set_body_string(quoted.as_str()))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(STATUS_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_string(quoted.as_str()))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = FortiosClient::plain(&server.uri(), SENTINEL_USER, SENTINEL_PASSWORD, Duration::from_secs(5));
        let login = client.login().await.expect_err("a refused login");
        assert_eq!(login.0, format!("API of {}: login refused: HTTP 401", server.address()));
        let read = client.run(STATUS).await.expect_err("a refused read");
        assert_eq!(read.0, format!("API of {}: monitor/system/status: HTTP 403", server.address()));
        let text = format!("{} {} {client:?}", printed(&login), printed(&read));
        assert!(!text.contains(SENTINEL_USER) && !text.contains(SENTINEL_PASSWORD), "{text}");
        // The account did leave with the login: the assertion above is not vacuous.
        let sent = requests(&server).await;
        assert_eq!(sent[0].2[2], ("username".to_owned(), SENTINEL_USER.to_owned()));
    }

    /// The `Cookie` header of each request received.
    async fn cookies_sent(server: &MockServer) -> Vec<Option<String>> {
        let received = server.received_requests().await.expect("the requests are recorded");
        let sent = |request: &wiremock::Request| {
            request.headers.get("cookie").map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        };
        received.iter().map(sent).collect()
    }

    #[tokio::test]
    async fn a_cookie_the_firewall_deletes_at_the_login_is_not_sent_back() {
        let server = firewall().await;
        let opened = ResponseTemplate::new(200)
            .set_body_string(LOGIN_SUCCESS)
            .append_header("set-cookie", "stale=1; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
            .append_header("set-cookie", "session=open; Path=/; HttpOnly")
            .append_header("set-cookie", "gone=1; Max-Age=0");
        Mock::given(method("POST")).and(path(LOGIN_PATH)).respond_with(opened).with_priority(1).mount(&server).await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        client.run(STATUS).await.expect("the read is answered");
        assert_eq!(cookies_sent(&server).await, [None, Some("session=open".to_owned())]);
    }

    #[tokio::test]
    async fn a_session_renewed_by_an_answer_replaces_the_one_sent() {
        let server = firewall().await;
        Mock::given(method("GET"))
            .and(header("cookie", "session=open"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(EMPTY)
                    .append_header("set-cookie", "session=renewed; Path=/"),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(header("cookie", "session=renewed"))
            .respond_with(ResponseTemplate::new(200).set_body_string(EMPTY))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = client(&server);
        client.login().await.expect("the login is accepted");
        client.run(STATUS).await.expect("the first read is answered");
        client.run(STATUS).await.expect("the second read is answered");
        assert_eq!(
            cookies_sent(&server).await,
            [None, Some("session=open".to_owned()), Some("session=renewed".to_owned())]
        );
    }

    #[test]
    fn cookies_go_back_in_the_order_they_were_set_without_their_attributes() {
        let mut cookies = Cookies::default();
        assert_eq!(cookies.header(), None);
        cookies.set("APSCOOKIE_1=\"Era%3D0%26Payload%3Dabc==\"; Path=/; Secure; HttpOnly; SameSite=Strict", 1_000);
        cookies.set("ccsrftoken=\"0123ABCD\"; path=/; secure", 1_000);
        assert_eq!(
            cookies.header().as_deref(),
            Some("APSCOOKIE_1=\"Era%3D0%26Payload%3Dabc==\"; ccsrftoken=\"0123ABCD\"")
        );
    }

    #[test]
    fn a_cookie_set_again_takes_its_new_value() {
        let mut cookies = Cookies::default();
        cookies.set("session=open", 1_000);
        cookies.set("other=1", 1_000);
        cookies.set("session=renewed", 1_000);
        assert_eq!(cookies.header().as_deref(), Some("other=1; session=renewed"));
    }

    #[test]
    fn a_cookie_that_expired_is_deleted() {
        let mut cookies = Cookies::default();
        for deletion in [
            "session=; Max-Age=0",
            "session=x; max-age=-1",
            "session=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            "session=x; expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/",
            // The very second it is received.
            "session=x; Expires=Thu, 01 Jan 1970 00:16:40 GMT",
        ] {
            cookies.set("session=open", 1_000);
            cookies.set("kept=1", 1_000);
            cookies.set(deletion, 1_000);
            assert_eq!(cookies.header().as_deref(), Some("kept=1"), "{deletion}");
        }
    }

    #[test]
    fn a_cookie_that_has_not_expired_is_kept() {
        for kept in [
            "session=open; Max-Age=3600",
            // One second after it is received.
            "session=open; Expires=Thu, 01 Jan 1970 00:16:41 GMT",
            // Max-Age wins over Expires (RFC 6265, 5.3).
            "session=open; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=60",
            // What is not understood is ignored (RFC 6265, 5.2.1 and 5.2.2).
            "session=open; Expires=never",
            "session=open; Max-Age=soon",
        ] {
            let mut cookies = Cookies::default();
            cookies.set(kept, 1_000);
            assert_eq!(cookies.header().as_deref(), Some("session=open"), "{kept}");
        }
    }

    #[test]
    fn what_is_not_a_cookie_is_ignored() {
        let mut cookies = Cookies::default();
        for header in ["", "session", "=open", "; Path=/"] {
            cookies.set(header, 1_000);
        }
        assert_eq!(cookies.header(), None);
    }

    #[test]
    fn cookie_dates_are_read_in_their_two_forms() {
        assert_eq!(cookie_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(cookie_date("Thu, 01-Jan-1970 00:00:01 GMT"), Some(1));
        // The example of RFC 7231 (7.1.1.1), in its preferred and in its obsolete form.
        assert_eq!(cookie_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(cookie_date("Sunday, 06-Nov-94 08:49:37 GMT"), Some(784_111_777));
        // A leap day, and a two-digit year of this century.
        assert_eq!(cookie_date("Thu, 29 Feb 2024 00:00:00 GMT"), Some(1_709_164_800));
        assert_eq!(cookie_date("Wed, 09-Jun-21 10:18:14 GMT"), Some(1_623_233_894));
    }

    #[test]
    fn what_is_not_a_cookie_date_is_no_date() {
        for text in [
            "",
            "never",
            "Thu, 01 Jan 1970",
            "00:00:00 GMT",
            "Thu, 32 Jan 1970 00:00:00 GMT",
            "Thu, 00 Jan 1970 00:00:00 GMT",
            "Thu, 01 Foo 1970 00:00:00 GMT",
            "Thu, 01 Jan 1970 24:00:00 GMT",
            "Thu, 01 Jan 1970 00:60:00 GMT",
            "Thu, 01 Jan 1600 00:00:00 GMT",
        ] {
            assert_eq!(cookie_date(text), None, "{text:?}");
        }
    }

    #[test]
    fn the_client_does_not_print_the_password() {
        let client = FortiosClient::plain("http://127.0.0.1:9", "readonly", SENTINEL_PASSWORD, DEFAULT_TIMEOUT);
        assert!(!format!("{client:?}").contains(SENTINEL_PASSWORD));
    }

    // A firewall another host launches: this one holds no account for it.
    #[test]
    fn a_source_whose_account_the_environment_does_not_hold_has_no_client_and_names_its_variables() {
        let variables = vec!["FIREWALL_FW01_DC1_USERNAME".to_owned(), "FIREWALL_FW01_DC1_PASSWORD".to_owned()];
        let unheld = Source { username: String::new(), password: Some(Wanted::Missing(variables)), ..source() };
        assert_eq!(
            message(FortiosClient::for_source(&unheld, DEFAULT_TIMEOUT)),
            "missing environment variables: FIREWALL_FW01_DC1_PASSWORD, FIREWALL_FW01_DC1_USERNAME"
        );
    }

    #[test]
    fn a_source_without_password_or_fingerprint_has_no_client() {
        for incomplete in [Source { password: None, ..source() }, Source { tls_fingerprint: None, ..source() }] {
            assert_eq!(
                message(FortiosClient::for_source(&incomplete, DEFAULT_TIMEOUT)),
                "no API credentials or certificate fingerprint configured"
            );
        }
    }

    #[test]
    fn a_source_whose_fingerprint_is_not_a_sha256_has_no_client() {
        // The length of a SHA-1: such a pin would be a weaker one.
        let sha1 = Source { tls_fingerprint: Some("ab".repeat(20)), ..source() };
        assert_eq!(
            message(FortiosClient::for_source(&sha1, DEFAULT_TIMEOUT)),
            "API of 192.0.2.1: tls_fingerprint must be the SHA-256 of the certificate \
             (64 hexadecimal digits, colons allowed)"
        );
    }

    #[test]
    fn the_client_of_a_source_speaks_https_to_its_host_and_port() {
        let client = FortiosClient::for_source(&source(), DEFAULT_TIMEOUT).expect("a complete source");
        assert_eq!(client.base_url, "https://192.0.2.1");
        // `host` may carry the port of the API.
        let other_port = Source { port: Some(9443), ..source() };
        let client = FortiosClient::for_source(&other_port, DEFAULT_TIMEOUT).expect("a complete source");
        assert_eq!(client.base_url, "https://192.0.2.1:9443");
        assert!(!format!("{client:?}").contains(PASSWORD));
    }
}
