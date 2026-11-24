//! What reads a network source that is not read from a report file: SSH for a
//! Cisco switch or router, the REST API for a FortiGate firewall.
//!
//! The run (`network::run`) hands each such source to a [`Collector`]; this is
//! the one of the real tool. It connects, runs the closed list of show commands
//! of the platform, and closes the connection whatever the outcome; for a
//! firewall it opens a session, reads the closed list of API calls, and closes
//! the session whatever the outcome. The neighbours told by the port
//! descriptions are added by the run itself, to the state of every collector:
//! they are not added a second time here.

use std::path::{Path, PathBuf};
use std::time::Duration;

use omnisync_cisco::collect::collect;
use omnisync_cisco::commands::Platform;
use omnisync_cisco::known_hosts::{KNOWN_HOSTS_ENV, KnownHosts, known_hosts_file};
use omnisync_cisco::runner::CommandRunner;
use omnisync_cisco::transport::SshRunner;
use omnisync_core::network::collect::CollectionError;
use omnisync_core::network::inventory::{Environ, Source};
use omnisync_core::network::model::DeviceState;
use omnisync_fortios::api::{DEFAULT_TIMEOUT as API_TIMEOUT, FortiosClient};
use omnisync_fortios::collect::{Fetcher, collect as collect_fortios};

use crate::network::{Collector, CommandLog, ReportingRunner};

/// Bounds the connection, the authentication, then each command: the 30 s of
/// the Python tool.
pub const SSH_TIMEOUT: Duration = Duration::from_secs(30);

/// Environment variable naming the socket of the SSH agent.
pub const AGENT_SOCKET_ENV: &str = "SSH_AUTH_SOCK";

/// The collector cannot be set up: nothing is contacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollectorError {
    /// The known hosts file lives under the home directory unless told otherwise.
    #[error("cannot locate the known hosts file: set HOME, XDG_STATE_HOME or SWITCH_KNOWN_HOSTS")]
    NoStateDirectory,
}

/// How a source is read by this collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// Over SSH, with the show commands of this platform.
    Ssh(Platform),
    /// Through the REST API of a FortiGate, with the calls of its closed list.
    Fortios,
}

/// The reader of a source, by its type; a type this collector cannot read is
/// an error naming it.
pub fn reader_of(source: &Source) -> Result<Reader, CollectionError> {
    match (Platform::from_type(&source.r#type), source.r#type.as_str()) {
        (Some(platform), _) => Ok(Reader::Ssh(platform)),
        (None, "fortios") => Ok(Reader::Fortios),
        (None, _) => Err(CollectionError(format!("type {} is not supported by this collector", source.r#type))),
    }
}

/// Reads the switches and routers over SSH, the firewalls through their REST API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCollector {
    known_hosts: KnownHosts,
    agent_socket: Option<PathBuf>,
    timeout: Duration,
}

impl NetworkCollector {
    /// The collector of a run: the known hosts file and the socket of the SSH
    /// agent come from the environment handed in, never from the process.
    pub fn from_environ(environ: &Environ) -> Result<Self, CollectorError> {
        let set = |name: &str| environ.get(name).filter(|value| !value.is_empty());
        // The home directory only serves when nothing else places the file.
        let home = match (set("HOME"), set(KNOWN_HOSTS_ENV).or(set("XDG_STATE_HOME"))) {
            (Some(home), _) => Path::new(home),
            (None, Some(_)) => Path::new(""),
            (None, None) => return Err(CollectorError::NoStateDirectory),
        };
        Ok(NetworkCollector {
            known_hosts: KnownHosts::new(known_hosts_file(environ, home)),
            agent_socket: set(AGENT_SOCKET_ENV).map(PathBuf::from),
            timeout: SSH_TIMEOUT,
        })
    }

    /// The file the host keys are recorded in.
    pub fn known_hosts(&self) -> &Path {
        self.known_hosts.path()
    }

    /// The socket of the SSH agent, None when the environment names none.
    pub fn agent_socket(&self) -> Option<&Path> {
        self.agent_socket.as_deref()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// A connection lent to the collection, so that it can be closed afterwards
/// whatever the collection returned.
struct Lent<'r>(&'r mut SshRunner);

impl CommandRunner for Lent<'_> {
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        self.0.run(command).await
    }
}

/// A session lent to the collection, so that it can be closed afterwards
/// whatever the collection returned.
struct LentSession<'c>(&'c mut FortiosClient);

impl Fetcher for LentSession<'_> {
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        self.0.run(command).await
    }
}

impl Collector for NetworkCollector {
    async fn collect(&self, source: &Source, commands: &CommandLog<'_>) -> Result<DeviceState, CollectionError> {
        // Refused before any connection: a type no reader reads is never logged into.
        match reader_of(source)? {
            Reader::Ssh(platform) => {
                let mut runner =
                    SshRunner::connect(source, &self.known_hosts, self.agent_socket.as_deref(), self.timeout).await?;
                let state = collect(platform, &mut ReportingRunner::new(Lent(&mut runner), commands)).await;
                // Whatever the collection returned: a switch has few sessions to give.
                runner.close().await;
                state
            }
            Reader::Fortios => {
                let mut client = FortiosClient::for_source(source, API_TIMEOUT)?;
                // The session is closed whatever the collection returned; each
                // request is announced as a show command is.
                client
                    .session(async |client| {
                        collect_fortios(&mut ReportingRunner::new(LentSession(client), commands), source).await
                    })
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::{Arc, Mutex};

    use omnisync_core::Outcome;
    use omnisync_core::network::inventory::{Inventory, Kind, Secret, Wanted};
    use omnisync_core::progress::Progress;
    use omnisync_netbox::testing::FakeGateway;
    use rustls::crypto::aws_lc_rs::default_provider;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::network::{Options, run};

    // Values that must never show in an error, a progress line or a report.
    const SENTINEL_USERNAME: &str = "s3ntinel-us3r";
    const SENTINEL_PASSWORD: &str = "s3ntinel-p4ssword";

    fn env(pairs: &[(&str, &str)]) -> Environ {
        pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    /// (method, path as received, body, had the session cookie)
    type Seen = (String, String, String, bool);

    /// Presents one certificate whatever the client asks.
    #[derive(Debug)]
    struct Always(Arc<CertifiedKey>);

    impl ResolvesServerCert for Always {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// What FortiOS 7.4.11 (forti01) answered a login it took, whole.
    const LOGIN_SUCCESS: &str = r#"{"status_code":5,"status_message":"LOGIN_SUCCESS"}"#;

    /// How a fake firewall answers a login.
    #[derive(Clone, Copy)]
    enum Login {
        /// 200 and `LOGIN_SUCCESS`, opening the session `session=open`.
        Opens,
        /// 200 and `LOGIN_SUCCESS` without any session: every read is then answered 401.
        OpensNothing,
        /// This status, without any session.
        Refused(u16),
    }

    /// A fake FortiGate over TLS, with a throwaway self-signed certificate. A
    /// read of the session `session=open` is answered from the recorded answers
    /// of the FortiOS crate (the firewall `LABLU-FWL01`). It stops listening
    /// when dropped.
    struct Firewall {
        port: u16,
        /// The SHA-256 of its certificate, as the inventory stores it.
        fingerprint: String,
        requests: Arc<Mutex<Vec<Seen>>>,
        server: JoinHandle<()>,
    }

    impl Drop for Firewall {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Firewall {
        /// A firewall that lets any account in.
        async fn start() -> Self {
            Firewall::answering_logins(Login::Opens).await
        }

        /// A firewall that answers every login this way.
        async fn answering_logins(login: Login) -> Self {
            let generated =
                rcgen::generate_simple_self_signed(vec!["FortiGate".to_owned()]).expect("a self-signed certificate");
            let certificate = generated.cert.der().clone();
            let provider = default_provider();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()));
            let signing_key = provider.key_provider.load_private_key(key).expect("a PKCS#8 key");
            let fingerprint = Sha256::digest(certificate.as_ref()).iter().map(|byte| format!("{byte:02x}")).collect();
            let presented = Arc::new(CertifiedKey::new(vec![certificate], signing_key));
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
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
                        // What does not speak TLS (an SSH client) is not a request.
                        if let Ok(stream) = acceptor.accept(stream).await {
                            serve(stream, login, recorded).await;
                        }
                    });
                }
            });
            Firewall { port, fingerprint, requests, server }
        }

        fn requests(&self) -> Vec<Seen> {
            self.requests.lock().unwrap().clone()
        }

        /// The inventory entry of this firewall, under the name it answers to.
        fn source(&self) -> Source {
            Source {
                username: "readonly".to_owned(),
                password: Some(Wanted::Held(Secret::new("pw-forti"))),
                tls_fingerprint: Some(self.fingerprint.clone()),
                port: Some(self.port),
                ignore_interfaces: vec!["dmz".to_owned()],
                ..Source::new("lablu-fwl01.dc1", Kind::Firewall, "fortios", "127.0.0.1")
            }
        }
    }

    /// The recorded answer to the read of `target`, None for a path never recorded.
    fn recorded_answer(target: &str) -> Option<String> {
        let command = target.strip_prefix("/api/v2/")?.replace("%7C", "|");
        // Named like the probe files.
        let name: String = command.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fortios/tests/fixtures/7.4.13");
        fs::read_to_string(fixtures.join(format!("{name}.txt"))).ok()
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

    /// Answers the HTTP/1.1 requests of one connection as a firewall would.
    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, login: Login, requests: Arc<Mutex<Vec<Seen>>>) {
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
            let body = String::from_utf8_lossy(&buffer[head_end..head_end + length]).into_owned();
            buffer.drain(..head_end + length);
            requests.lock().unwrap().push((method.clone(), target.clone(), body, cookie));
            let (status, session, answer) = match (method.as_str(), target.as_str()) {
                ("POST", "/api/v2/authentication") => match login {
                    Login::Opens => (200, "Set-Cookie: session=open; Path=/\r\n", LOGIN_SUCCESS.to_owned()),
                    Login::OpensNothing => (200, "", LOGIN_SUCCESS.to_owned()),
                    Login::Refused(status) => (status, "", String::new()),
                },
                ("POST", "/logout") => (200, "", String::new()),
                ("GET", _) if !cookie => (401, "", "unauthorized".to_owned()),
                ("GET", target) => match recorded_answer(target) {
                    Some(answer) => (200, "", answer),
                    None => (404, "", String::new()),
                },
                _ => (405, "", String::new()),
            };
            let head = format!("HTTP/1.1 {status} Answer\r\n{session}Content-Length: {}\r\n\r\n", answer.len());
            if stream.write_all(format!("{head}{answer}").as_bytes()).await.is_err() {
                return;
            }
        }
    }

    /// Everything the run shows while it goes, as (what, text).
    #[derive(Default)]
    struct Shown(Mutex<Vec<(&'static str, String)>>);

    impl Shown {
        fn record(&self, what: &'static str, text: String) {
            self.0.lock().unwrap().push((what, text));
        }

        /// The commands announced while the first source was collected, as `lane:
        /// command`: its lane ends with its collection, the NetBox reads come after.
        fn commands(&self) -> Vec<String> {
            let shown = self.0.lock().unwrap();
            let collected = shown.iter().take_while(|(what, _)| *what != "lane_end");
            collected.filter(|(what, _)| *what == "lane_doing").map(|(_, text)| text.clone()).collect()
        }

        fn printed(&self) -> String {
            format!("{:?}", self.0.lock().unwrap())
        }
    }

    impl Progress for Shown {
        fn begin(&self, total: u64) {
            self.record("begin", total.to_string());
        }

        fn resize(&self, total: u64) {
            self.record("resize", total.to_string());
        }

        fn step(&self, label: &str) {
            self.record("step", label.to_owned());
        }

        fn doing(&self, label: &str) {
            self.record("doing", label.to_owned());
        }

        fn advance(&self, lane: Option<&str>) {
            self.record("advance", lane.unwrap_or_default().to_owned());
        }

        fn lane_start(&self, lane: &str, total: u64) {
            self.record("lane_start", format!("{lane}: {total}"));
        }

        fn lane_doing(&self, lane: &str, label: &str) {
            self.record("lane_doing", format!("{lane}: {label}"));
        }

        fn lane_end(&self, lane: &str) {
            self.record("lane_end", lane.to_owned());
        }

        fn note(&self, text: &str) {
            self.record("note", text.to_owned());
        }

        fn end(&self) {
            self.record("end", String::new());
        }
    }

    /// One run of the real collector over `sources`, writing to `netbox`.
    struct Ran {
        outcome: Outcome,
        shown: Shown,
        /// Whether a host key was recorded: the trace of an SSH connection.
        host_key_recorded: bool,
    }

    async fn collect_with(sources: Vec<Source>, netbox: &FakeGateway) -> Ran {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = directory.path().join("known_hosts");
        let environ = env(&[("SWITCH_KNOWN_HOSTS", known_hosts.to_str().unwrap())]);
        let collector = NetworkCollector::from_environ(&environ).unwrap();
        let inventory = Inventory {
            sources,
            domains: Vec::new(),
            netbox_url: "https://netbox.example.net".to_owned(),
            netbox_token: Wanted::Held(Secret::new("token-value")),
            aliases: BTreeMap::new(),
        };
        let shown = Shown::default();
        let options = Options { apply: true, ..Options::default() };
        let outcome = run(&inventory, netbox, &collector, &options, &shown).await;
        Ran { outcome, shown, host_key_recorded: known_hosts.exists() }
    }

    /// A NetBox holding the device of the fake firewall, and its id.
    fn netbox_with_the_firewall() -> (FakeGateway, u64) {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "lablu-fwl01.dc1", "site": 12, "serial": ""}));
        (netbox, device)
    }

    fn seen(method: &str, target: &str, body: &str, cookie: bool) -> Seen {
        (method.to_owned(), target.to_owned(), body.to_owned(), cookie)
    }

    fn source(kind: Kind, r#type: &str) -> Source {
        Source {
            username: "sync".to_owned(),
            password: Some(Wanted::Held(Secret::new("pw-device"))),
            ..Source::new("device.dc1", kind, r#type, "192.0.2.1")
        }
    }

    #[test]
    fn a_switch_is_read_over_ssh() {
        assert_eq!(reader_of(&source(Kind::Switch, "nxos")), Ok(Reader::Ssh(Platform::Nxos)));
        assert_eq!(reader_of(&source(Kind::Switch, "ios")), Ok(Reader::Ssh(Platform::Ios)));
        assert_eq!(reader_of(&source(Kind::Router, "ios")), Ok(Reader::Ssh(Platform::Ios)));
    }

    #[test]
    fn a_firewall_is_read_through_its_api() {
        assert_eq!(reader_of(&source(Kind::Firewall, "fortios")), Ok(Reader::Fortios));
    }

    #[test]
    fn another_type_is_not_supported_by_this_collector() {
        let error = reader_of(&source(Kind::Firewall, "panos")).unwrap_err();
        assert_eq!(error, CollectionError("type panos is not supported by this collector".to_owned()));
        let error = reader_of(&source(Kind::Switch, "nipper")).unwrap_err();
        assert_eq!(error.to_string(), "type nipper is not supported by this collector");
    }

    #[test]
    fn the_refusal_of_a_type_never_carries_the_account() {
        let error = reader_of(&source(Kind::Firewall, "panos")).unwrap_err();
        let printed = format!("{error} {error:?}");
        assert!(!printed.contains("pw-device"), "{printed}");
        assert!(!printed.contains("sync"), "{printed}");
    }

    #[test]
    fn the_known_hosts_file_comes_from_the_environment() {
        let collector =
            NetworkCollector::from_environ(&env(&[("SWITCH_KNOWN_HOSTS", "/etc/sync/known_hosts")])).unwrap();
        assert_eq!(collector.known_hosts(), Path::new("/etc/sync/known_hosts"));
        let collector = NetworkCollector::from_environ(&env(&[("XDG_STATE_HOME", "/s"), ("HOME", "/h")])).unwrap();
        assert_eq!(collector.known_hosts(), Path::new("/s/netbox-omnisync/known_hosts"));
        let collector = NetworkCollector::from_environ(&env(&[("XDG_STATE_HOME", "/s")])).unwrap();
        assert_eq!(collector.known_hosts(), Path::new("/s/netbox-omnisync/known_hosts"));
        let collector = NetworkCollector::from_environ(&env(&[("HOME", "/h")])).unwrap();
        assert_eq!(collector.known_hosts(), Path::new("/h/.local/state/netbox-omnisync/known_hosts"));
    }

    #[test]
    fn without_a_home_the_known_hosts_file_must_be_named() {
        assert_eq!(NetworkCollector::from_environ(&env(&[])), Err(CollectorError::NoStateDirectory));
        assert_eq!(NetworkCollector::from_environ(&env(&[("HOME", "")])), Err(CollectorError::NoStateDirectory));
        assert_eq!(
            CollectorError::NoStateDirectory.to_string(),
            "cannot locate the known hosts file: set HOME, XDG_STATE_HOME or SWITCH_KNOWN_HOSTS"
        );
    }

    #[test]
    fn the_agent_socket_comes_from_the_environment() {
        let collector =
            NetworkCollector::from_environ(&env(&[("HOME", "/h"), ("SSH_AUTH_SOCK", "/run/agent.sock")])).unwrap();
        assert_eq!(collector.agent_socket(), Some(Path::new("/run/agent.sock")));
        let collector = NetworkCollector::from_environ(&env(&[("HOME", "/h")])).unwrap();
        assert_eq!(collector.agent_socket(), None);
        let collector = NetworkCollector::from_environ(&env(&[("HOME", "/h"), ("SSH_AUTH_SOCK", "")])).unwrap();
        assert_eq!(collector.agent_socket(), None);
    }

    #[test]
    fn a_connection_is_bounded_as_in_the_python_tool() {
        let collector = NetworkCollector::from_environ(&env(&[("HOME", "/h")])).unwrap();
        assert_eq!(collector.timeout(), Duration::from_secs(30));
    }

    // Through the run, as the tool does: the session opens, the four calls of the
    // closed list are read in order, each one announced, and the session closes.
    #[tokio::test]
    async fn a_firewall_is_collected_through_its_api() {
        let firewall = Firewall::start().await;
        let (netbox, device) = netbox_with_the_firewall();
        let ran = collect_with(vec![firewall.source()], &netbox).await;
        assert_eq!(ran.outcome.errors, [] as [&str; 0]);
        // "serial":"FG101FTK22000001" in the recorded monitor/system/status.
        assert_eq!(netbox.row("dcim.devices", device).unwrap()["serial"], json!("FG101FTK22000001"));
        assert_eq!(
            firewall.requests(),
            [
                seen(
                    "POST",
                    "/api/v2/authentication",
                    r#"{"password":"pw-forti","secretkey":"pw-forti","username":"readonly"}"#,
                    false
                ),
                seen(
                    "GET",
                    "/api/v2/cmdb/system/interface?format=name%7Ctype%7Calias%7Cdescription%7Cstatus%7Cmtu-override\
                     %7Cmtu%7Cvlanid%7Cinterface%7Cmember%7Cip%7Csecondary-IP%7Csecondaryip%7Cvdom",
                    "",
                    true
                ),
                seen("GET", "/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true", "", true),
                seen("GET", "/api/v2/monitor/system/status", "", true),
                seen("GET", "/api/v2/monitor/system/ha-peer", "", true),
                seen("POST", "/logout", "", true),
            ]
        );
        assert_eq!(
            ran.shown.commands(),
            [
                "lablu-fwl01.dc1: cmdb/system/interface?format=name|type|alias|description|status|mtu-override|mtu|\
                 vlanid|interface|member|ip|secondary-IP|secondaryip|vdom",
                "lablu-fwl01.dc1: monitor/system/interface?include_vlan=true&include_aggregate=true",
                "lablu-fwl01.dc1: monitor/system/status",
                "lablu-fwl01.dc1: monitor/system/ha-peer",
            ]
        );
    }

    #[tokio::test]
    async fn a_firewall_is_never_logged_into_over_ssh() {
        let firewall = Firewall::start().await;
        let (netbox, _) = netbox_with_the_firewall();
        let ran = collect_with(vec![firewall.source()], &netbox).await;
        assert_eq!(ran.outcome.errors, [] as [&str; 0]);
        assert!(!ran.host_key_recorded);
    }

    #[tokio::test]
    async fn a_switch_is_never_read_through_the_api() {
        // A switch whose address is the one of a firewall API: it is spoken SSH to.
        let firewall = Firewall::start().await;
        let switch = Source {
            name: "nexus01.lab01".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: Some(firewall.port),
            tls_fingerprint: Some(firewall.fingerprint.clone()),
            ..source(Kind::Switch, "nxos")
        };
        let ran = collect_with(vec![switch], &FakeGateway::new()).await;
        assert_eq!(ran.outcome.errors.len(), 1, "{:?}", ran.outcome.errors);
        let error = &ran.outcome.errors[0];
        assert!(error.starts_with("nexus01.lab01: SSH to 127.0.0.1 failed: "), "{error}");
        assert_eq!(firewall.requests(), []);
    }

    // The refusal comes before any connection, over SSH or to the API.
    #[tokio::test]
    async fn a_type_no_reader_reads_is_an_error_of_the_run_and_is_never_connected_to() {
        let firewall = Firewall::start().await;
        let unread = Source { r#type: "panos".to_owned(), ..firewall.source() };
        let netbox = FakeGateway::new();
        let ran = collect_with(vec![unread], &netbox).await;
        assert_eq!(ran.outcome.errors, ["lablu-fwl01.dc1: type panos is not supported by this collector"]);
        assert_eq!(netbox.writes(), []);
        assert_eq!(firewall.requests(), []);
        // No connection: no host key was recorded.
        assert!(!ran.host_key_recorded);
    }

    #[tokio::test]
    async fn the_session_of_a_firewall_is_closed_when_its_collection_fails() {
        // The recorded firewall answers as LABLU-FWL01: it is not fw09.
        let firewall = Firewall::start().await;
        let other = Source { name: "fw09.dc1".to_owned(), ..firewall.source() };
        let netbox = FakeGateway::new();
        let ran = collect_with(vec![other], &netbox).await;
        assert_eq!(ran.outcome.errors, ["fw09.dc1: the firewall that answers is LABLU-FWL01, not fw09.dc1"]);
        assert_eq!(netbox.writes(), []);
        assert_eq!(firewall.requests().last(), Some(&seen("POST", "/logout", "", true)));
    }

    #[tokio::test]
    async fn a_certificate_that_is_not_the_pinned_one_stops_before_the_account_leaves() {
        let firewall = Firewall::start().await;
        let pinned_elsewhere = Source { tls_fingerprint: Some("00".repeat(32)), ..firewall.source() };
        let ran = collect_with(vec![pinned_elsewhere], &FakeGateway::new()).await;
        assert_eq!(
            ran.outcome.errors,
            [format!(
                "lablu-fwl01.dc1: API of 127.0.0.1:{}: the certificate presented is not the one of tls_fingerprint",
                firewall.port
            )]
        );
        assert_eq!(firewall.requests(), []);
    }

    #[tokio::test]
    async fn a_refused_login_never_carries_the_account() {
        let firewall = Firewall::answering_logins(Login::Refused(403)).await;
        let account = Source {
            username: SENTINEL_USERNAME.to_owned(),
            password: Some(Wanted::Held(Secret::new(SENTINEL_PASSWORD))),
            ..firewall.source()
        };
        let ran = collect_with(vec![account], &FakeGateway::new()).await;
        assert_eq!(
            ran.outcome.errors,
            [format!("lablu-fwl01.dc1: API of 127.0.0.1:{}: login refused: HTTP 403", firewall.port)]
        );
        // The account did reach the firewall, and nothing else was asked of it.
        let form = format!(
            r#"{{"password":"{SENTINEL_PASSWORD}","secretkey":"{SENTINEL_PASSWORD}","username":"{SENTINEL_USERNAME}"}}"#
        );
        assert_eq!(firewall.requests(), [seen("POST", "/api/v2/authentication", &form, false)]);
        let printed = format!("{:?} {}", ran.outcome, ran.shown.printed());
        assert!(!printed.contains(SENTINEL_PASSWORD), "{printed}");
        assert!(!printed.contains(SENTINEL_USERNAME), "{printed}");
    }

    #[tokio::test]
    async fn a_login_that_opens_no_session_never_carries_the_account() {
        let firewall = Firewall::answering_logins(Login::OpensNothing).await;
        let account = Source {
            username: SENTINEL_USERNAME.to_owned(),
            password: Some(Wanted::Held(Secret::new(SENTINEL_PASSWORD))),
            ..firewall.source()
        };
        let ran = collect_with(vec![account], &FakeGateway::new()).await;
        // A login taken without a session is refused before any read: nothing
        // would be answered but 401.
        assert_eq!(
            ran.outcome.errors,
            [format!("lablu-fwl01.dc1: API of 127.0.0.1:{}: login accepted but opened no session", firewall.port)]
        );
        let asked: Vec<(String, String)> =
            firewall.requests().into_iter().map(|(method, target, ..)| (method, target)).collect();
        assert_eq!(asked, [("POST".to_owned(), "/api/v2/authentication".to_owned())]);
        let printed = format!("{:?} {}", ran.outcome, ran.shown.printed());
        assert!(!printed.contains(SENTINEL_PASSWORD), "{printed}");
        assert!(!printed.contains(SENTINEL_USERNAME), "{printed}");
    }
}
