//! SSH command runner over russh; one connection per switch.
//!
//! The Catalyst 2960 and the Nexus 3064 only speak the SSH of their time: SHA-1
//! key exchanges, `ssh-rsa` host keys, CBC ciphers and `hmac-sha1` are offered
//! in addition to the defaults. Host keys are trusted on first use, and exactly
//! one authentication attempt is made, in the configured mode: every extra
//! attempt (agent keys, default key files) counts as a failed login on the
//! switch.
//!
//! The commands are typed in one interactive session, pagination off, each
//! output read up to the next prompt. Running each command on its own (an SSH
//! `exec` request) does not work on these switches: they cut the connection as
//! soon as the command ends, at times before all its output is sent (seen on a
//! 2960 and on a Nexus 3064, 2026-11-20).

use std::path::Path;
use std::time::Duration;

use omnisync_core::network::inventory::Source;
use omnisync_ssh::known_hosts::KnownHosts;
use omnisync_ssh::{Account, Auth, Connection, Peer};
use russh::client;
use russh::{Channel, ChannelMsg};

use crate::commands::{self, Platform};
use crate::runner::{CollectionError, CommandRunner};

/// The port of a switch whose inventory entry names none.
const SSH_PORT: u16 = 22;

/// The one authentication mode of a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode<'a> {
    Agent,
    KeyFile(&'a Path),
    Password,
}

/// Only the configured mode is tried: None when the source sets no mode, or
/// more than one, so that nothing is attempted on a guess.
fn auth_mode(source: &Source) -> Option<AuthMode<'_>> {
    match (&source.password, &source.key_file, source.use_agent) {
        (Some(_), None, false) => Some(AuthMode::Password),
        (None, Some(path), false) => Some(AuthMode::KeyFile(path)),
        (None, None, true) => Some(AuthMode::Agent),
        _ => None,
    }
}

/// Convert `\r\r\n`, `\r\n` and `\n\r` to `\n`, then any `\r` left: the parsers
/// read the line feeds netmiko used to hand them.
fn normalize_linefeeds(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(current) = chars.next() {
        match current {
            '\r' => {
                while chars.peek() == Some(&'\r') {
                    chars.next();
                }
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                normalized.push('\n');
            }
            '\n' => {
                if chars.peek() == Some(&'\r') {
                    chars.next();
                }
                normalized.push('\n');
            }
            other => normalized.push(other),
        }
    }
    normalized
}

/// The text of an output, without the bytes that are not UTF-8.
fn decode(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().filter(|character| *character != char::REPLACEMENT_CHARACTER).collect()
}

/// The terminal asked for: as wide as `terminal width` allows, like netmiko.
const TERMINAL_WIDTH: u32 = 511;
const TERMINAL_HEIGHT: u32 = 1000;

/// How long the switch must stay silent after a line that looks like a prompt
/// for it to be taken as the prompt: a banner may hold such a line.
const PROMPT_SILENCE: Duration = Duration::from_millis(300);

/// Why reading the session stopped short of the prompt.
enum Lost {
    Closed,
    Failed(String),
}

/// The text read so far, as the parsers will get it.
fn text_of(bytes: &[u8]) -> String {
    normalize_linefeeds(&decode(bytes))
}

/// The last line of what was read, when it looks like a prompt (`name#`, `name>`).
fn prompt_candidate(text: &str) -> Option<&str> {
    let last = text.rsplit('\n').next()?.trim();
    (!last.is_empty() && !last.contains(' ') && (last.ends_with('#') || last.ends_with('>'))).then_some(last)
}

/// The output of a command, out of what the session printed from the echo of
/// the command up to the next prompt; None while the prompt is not back.
fn output_between(text: &str, prompt: &str) -> Option<String> {
    let body = text.trim_end().strip_suffix(prompt)?;
    if !(body.is_empty() || body.ends_with('\n')) {
        return None;
    }
    // The first line is the command, echoed by the switch.
    let (_, output) = body.split_once('\n')?;
    Some(output.to_owned())
}

/// What a command printed so far.
#[derive(Default)]
struct Answer {
    read: Vec<u8>,
}

impl Answer {
    /// Adds what the session sent; the output of the command once the prompt is back.
    ///
    /// Only the end of what was read is looked at until the prompt shows there:
    /// decoding the whole of it at every piece would cost the square of a long
    /// output, out of the time the command is given.
    fn push(&mut self, data: &[u8], prompt: &str) -> Option<String> {
        self.read.extend_from_slice(data);
        // Room for the prompt, the line feeds and spaces around it, and a
        // character cut in two at the start of the tail.
        let tail = &self.read[self.read.len().saturating_sub(prompt.len() + 64)..];
        if !text_of(tail).trim_end().ends_with(prompt) {
            return None;
        }
        output_between(&text_of(&self.read), prompt)
    }
}

/// SSH command runner over russh; one connection and one session per switch.
pub struct SshRunner {
    connection: Connection,
    session: Channel<client::Msg>,
    /// The prompt of the switch, without the space that may follow it.
    prompt: String,
    platform: Platform,
    timeout: Duration,
    /// A command got no answer: what comes next on the session cannot be trusted.
    lost: bool,
}

impl SshRunner {
    /// Connect to a switch and authenticate, once, in the mode of its inventory entry.
    ///
    /// `agent_socket` is the socket of the SSH agent, used in `agent` mode only:
    /// the caller reads it from its environment. `timeout` bounds the
    /// connection, the authentication, and then every command.
    ///
    /// A failure reads `SSH to <host> failed: <kind>`; it never carries the
    /// password nor key material.
    pub async fn connect(
        source: &Source,
        known_hosts: &KnownHosts,
        agent_socket: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, CollectionError> {
        let platform = Platform::from_type(&source.r#type)
            .ok_or_else(|| CollectionError(format!("unsupported platform '{}'", source.r#type)))?;
        let host = source.host.as_str();
        let failed = |kind: &str| CollectionError(format!("SSH to {host} failed: {kind}"));
        let no_answer = || failed(&format!("no answer after {timeout:?}"));

        // A password the environment does not hold: the source was not meant
        // to be read from this host. Nothing is attempted, and certainly not
        // an empty password; the refusal names the variable.
        let password = match &source.password {
            None => None,
            Some(wanted) => Some(wanted.held().map_err(|missing| CollectionError(missing.to_string()))?),
        };
        if let Some(why) = omnisync_ssh::unknown_disabled(source.disabled_algorithms.as_ref()) {
            return Err(failed(&why));
        }
        let auth = match auth_mode(source).ok_or_else(|| failed("no single authentication mode"))? {
            AuthMode::Password => Auth::Password(password.ok_or_else(|| failed("no single authentication mode"))?),
            AuthMode::KeyFile(path) => Auth::KeyFile(path),
            AuthMode::Agent => Auth::Agent,
        };
        let account = Account {
            username: &source.username,
            auth,
            disabled_algorithms: source.disabled_algorithms.as_ref(),
            // These switches only know RSA keys.
            agent_rsa_only: true,
        };
        let peer = Peer { host, port: source.port.unwrap_or(SSH_PORT), noun: "switch" };
        let connection = omnisync_ssh::connect(&peer, &account, known_hosts, agent_socket, timeout)
            .await
            .map_err(|kind| failed(&kind))?;
        let session = tokio::time::timeout(timeout, connection.open_shell(TERMINAL_WIDTH, TERMINAL_HEIGHT))
            .await
            .map_err(|_| no_answer())?
            .map_err(|kind| failed(&kind))?;
        let mut runner = SshRunner { connection, session, prompt: String::new(), platform, timeout, lost: false };
        runner.prompt = tokio::time::timeout(timeout, runner.find_prompt())
            .await
            .map_err(|_| no_answer())?
            .map_err(|_| failed("session closed by the switch"))?;
        for setting in commands::SESSION_SETUP {
            // Checked as a command is: nothing unchecked is typed on a switch.
            commands::check_setup(setting).map_err(|refusal| failed(&format!("{setting}: {refusal}")))?;
            runner.type_line(setting).await.map_err(|CollectionError(why)| failed(&why))?;
        }
        Ok(runner)
    }

    /// Read what the switch prints at login, up to its prompt.
    async fn find_prompt(&mut self) -> Result<String, Lost> {
        let mut read = Vec::new();
        loop {
            // A line that looks like a prompt is one only once the switch stops talking.
            let candidate = prompt_candidate(&text_of(&read)).map(str::to_owned);
            let message = match candidate {
                Some(prompt) => match tokio::time::timeout(PROMPT_SILENCE, self.session.wait()).await {
                    Ok(message) => message,
                    Err(_) => return Ok(prompt),
                },
                None => self.session.wait().await,
            };
            match message {
                Some(ChannelMsg::Data { data }) => read.extend_from_slice(&data),
                Some(_) => {}
                None => return Err(Lost::Closed),
            }
        }
    }

    /// Type one line and read what the switch prints up to its next prompt.
    async fn type_line(&mut self, line: &str) -> Result<String, CollectionError> {
        if self.lost {
            return Err(CollectionError(format!("{line}: session lost after an unanswered command")));
        }
        let timeout = self.timeout;
        match tokio::time::timeout(timeout, self.answer_to(line)).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(Lost::Closed)) => {
                self.lost = true;
                Err(CollectionError(format!("{line}: session closed by the switch")))
            }
            Ok(Err(Lost::Failed(why))) => {
                self.lost = true;
                Err(CollectionError(format!("{line}: {why}")))
            }
            Err(_) => {
                self.lost = true;
                Err(CollectionError(format!("{line}: no answer after {timeout:?}")))
            }
        }
    }

    async fn answer_to(&mut self, line: &str) -> Result<String, Lost> {
        let typed = format!("{line}\n");
        self.session.data(typed.as_bytes()).await.map_err(|error| Lost::Failed(self.connection.kind(&error)))?;
        let mut answer = Answer::default();
        loop {
            match self.session.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(output) = answer.push(&data, &self.prompt) {
                        return Ok(output);
                    }
                }
                Some(_) => {}
                None => return Err(Lost::Closed),
            }
        }
    }

    /// Close the connection; dropping the runner closes it as well.
    pub async fn close(self) {
        self.connection.close().await;
    }
}

impl CommandRunner for SshRunner {
    /// Type one command in the session and return what the switch printed
    /// between the echo of the command and its next prompt.
    ///
    /// The command goes through `commands::check` first: a refused command
    /// never reaches the wire.
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        commands::check(self.platform, command).map_err(|refusal| CollectionError(format!("{command}: {refusal}")))?;
        self.type_line(command).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{Arc, LazyLock, Mutex};

    use omnisync_core::network::inventory::{Kind, Secret, Wanted};
    use russh::keys::agent::client::AgentClient;
    use russh::keys::ssh_key::LineEnding;
    use russh::keys::ssh_key::private::RsaKeypair;
    use russh::keys::{Algorithm, PrivateKey, PublicKey};
    use russh::server::{self, Auth, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
    use russh::{Channel, ChannelId, Preferred, cipher, kex, mac};
    use tempfile::TempDir;
    use tokio::net::{TcpListener, UnixListener};
    use tokio::task::JoinHandle;

    use super::*;

    /// A password no error may ever show.
    const SENTINEL: &str = "S3ntinel-pa55word-never-shown";
    const TIMEOUT: Duration = Duration::from_secs(10);

    /// RSA keys are slow to generate: one for the account, one for a host.
    static ACCOUNT_KEY: LazyLock<PrivateKey> = LazyLock::new(rsa_key);
    static RSA_HOST_KEY: LazyLock<PrivateKey> = LazyLock::new(rsa_key);

    fn rsa_key() -> PrivateKey {
        PrivateKey::from(RsaKeypair::random(&mut russh::keys::key::safe_rng(), 2048).unwrap())
    }

    fn ed25519_key() -> PrivateKey {
        PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
    }

    enum Reply {
        Output(&'static str),
        Hang,
    }

    // A long output (a `show interfaces` of a big stack) comes in small pieces:
    // each piece must cost its own size, not the size of all that came before.
    #[test]
    fn a_long_output_in_small_pieces_is_read_in_linear_time() {
        let line = "Ethernet1/1 is up, line protocol is up (connected)\n";
        let output = line.repeat(40_000);
        let sent = format!("show interfaces\n{output}sw01#");
        let mut answer = Answer::default();
        let started = std::time::Instant::now();
        let mut read = None;
        for piece in sent.as_bytes().chunks(1024) {
            read = answer.push(piece, "sw01#");
        }
        assert_eq!(read.as_deref(), Some(output.as_str()));
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    /// What the device accepts and answers.
    #[derive(Default)]
    struct Script {
        password: Option<&'static str>,
        authorized_key: Option<PublicKey>,
        replies: Vec<(&'static str, Reply)>,
    }

    /// Everything the device received.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct Seen {
        none_attempts: usize,
        /// The user of each password attempt.
        password_attempts: Vec<String>,
        /// `<algorithm> <user>` of each public key request.
        key_requests: Vec<String>,
        /// `<algorithm> <user>` of each verified signature.
        signatures: Vec<String>,
        channels: usize,
        shells: usize,
        /// The terminal settings sent before the first command.
        setup: Vec<String>,
        commands: Vec<String>,
    }

    #[derive(Clone)]
    struct Device {
        script: Arc<Script>,
        seen: Arc<Mutex<Seen>>,
        /// What the client typed since its last line feed.
        line: Vec<u8>,
    }

    /// The prompt of the device, as a Nexus or a Catalyst prints it.
    const PROMPT: &str = "n1# ";

    impl Device {
        /// Answer one typed line as a switch does: echo, output, prompt.
        fn answer(&mut self, channel: ChannelId, line: &str, session: &mut Session) -> Result<(), russh::Error> {
            session.data(channel, format!("{line}\r\n").into_bytes())?;
            if line.starts_with("terminal ") {
                self.seen.lock().unwrap().setup.push(line.to_owned());
                session.data(channel, PROMPT.as_bytes().to_vec())?;
                return Ok(());
            }
            self.seen.lock().unwrap().commands.push(line.to_owned());
            match self.script.replies.iter().find(|(known, _)| *known == line) {
                Some((_, Reply::Hang)) => {}
                Some((_, Reply::Output(text))) => {
                    session.data(channel, text.as_bytes().to_vec())?;
                    session.data(channel, PROMPT.as_bytes().to_vec())?;
                }
                None => {
                    session.data(channel, b"% Invalid input detected at '^' marker.\r\n".to_vec())?;
                    session.data(channel, PROMPT.as_bytes().to_vec())?;
                }
            }
            Ok(())
        }
    }

    impl server::Handler for Device {
        type Error = russh::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
            self.seen.lock().unwrap().none_attempts += 1;
            Ok(Auth::reject())
        }

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            self.seen.lock().unwrap().password_attempts.push(user.to_owned());
            Ok(if self.script.password == Some(password) { Auth::Accept } else { Auth::reject() })
        }

        async fn auth_publickey_offered(&mut self, user: &str, offer: PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
            self.seen.lock().unwrap().key_requests.push(format!("{} {user}", offer.algorithm.as_str()));
            let authorized = self.script.authorized_key.as_ref().map(PublicKey::key_data);
            Ok(if authorized == Some(offer.public_key.key_data()) { Auth::Accept } else { Auth::reject() })
        }

        async fn auth_publickey(&mut self, user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
            self.seen.lock().unwrap().signatures.push(format!("{} {user}", key.algorithm.as_str()));
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.seen.lock().unwrap().channels += 1;
            reply.accept().await;
            Ok(())
        }

        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _term: &str,
            _col_width: u32,
            _row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            Ok(())
        }

        async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
            self.seen.lock().unwrap().shells += 1;
            session.channel_success(channel)?;
            // A banner, then the prompt: the client must wait for the latter.
            session.data(channel, format!("\r\nAuthorized users only#\r\n\r\n{PROMPT}").into_bytes())?;
            Ok(())
        }

        /// These switches cut the connection after a command run this way: it must never be used.
        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.seen.lock().unwrap().commands.push(format!("exec {}", String::from_utf8_lossy(data)));
            session.channel_failure(channel)?;
            Ok(())
        }

        async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            for byte in data {
                if *byte == b'\n' {
                    let line =
                        String::from_utf8_lossy(&std::mem::take(&mut self.line)).trim_end_matches('\r').to_owned();
                    self.answer(channel, &line, session)?;
                } else {
                    self.line.push(*byte);
                }
            }
            Ok(())
        }
    }

    /// An SSH server on 127.0.0.1, in this process, gone with the test.
    struct TestServer {
        port: u16,
        seen: Arc<Mutex<Seen>>,
        task: JoinHandle<()>,
    }

    impl TestServer {
        async fn start(host_key: PrivateKey, script: Script) -> Self {
            Self::start_on(0, host_key, script, Preferred::default()).await
        }

        async fn start_on(port: u16, host_key: PrivateKey, script: Script, preferred: Preferred) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let seen = Arc::new(Mutex::new(Seen::default()));
            let device = Device { script: Arc::new(script), seen: Arc::clone(&seen), line: Vec::new() };
            let config = Arc::new(server::Config {
                keys: vec![host_key],
                auth_rejection_time: Duration::ZERO,
                auth_rejection_time_initial: Some(Duration::ZERO),
                preferred,
                ..Default::default()
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (config, device) = (Arc::clone(&config), device.clone());
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, device).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            TestServer { port, seen, task }
        }

        /// Stop listening and wait until the port is free again.
        async fn stop(mut self) {
            self.task.abort();
            let _ = (&mut self.task).await;
        }

        fn seen(&self) -> std::sync::MutexGuard<'_, Seen> {
            self.seen.lock().unwrap()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// An SSH agent on a socket of its own, holding one key: the agent of the
    /// user is never spoken to.
    struct PrivateAgent {
        directory: TempDir,
        task: JoinHandle<()>,
    }

    impl PrivateAgent {
        async fn start(key: &PrivateKey) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("agent.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let incoming = Box::pin(futures::stream::unfold(listener, |listener| async move {
                let stream = listener.accept().await.map(|(stream, _)| stream);
                Some((stream, listener))
            }));
            let task = tokio::spawn(async move {
                let _ = russh::keys::agent::server::serve(incoming, ()).await;
            });
            let mut client = AgentClient::connect_uds(&socket).await.unwrap();
            client.add_identity(key, &[]).await.unwrap();
            PrivateAgent { directory, task }
        }

        fn socket(&self) -> PathBuf {
            self.directory.path().join("agent.sock")
        }
    }

    impl Drop for PrivateAgent {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn switch(r#type: &str, port: u16) -> Source {
        Source { username: "sync".to_owned(), port: Some(port), ..Source::new("n1", Kind::Switch, r#type, "127.0.0.1") }
    }

    fn with_password(r#type: &str, port: u16, password: &str) -> Source {
        Source { password: Some(Wanted::Held(Secret::new(password))), ..switch(r#type, port) }
    }

    fn rsa_sha2_disabled() -> Option<BTreeMap<String, Vec<String>>> {
        Some(BTreeMap::from([("pubkeys".to_owned(), vec!["rsa-sha2-512".to_owned(), "rsa-sha2-256".to_owned()])]))
    }

    fn password_script(replies: Vec<(&'static str, Reply)>) -> Script {
        Script { password: Some("pw"), replies, ..Script::default() }
    }

    /// The private key in a file of its own, as `key_file` names it.
    fn key_file(directory: &TempDir, key: &PrivateKey) -> PathBuf {
        let path = directory.path().join("netbox-sync");
        fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn runner_password_only() {
        let source = with_password("nxos", 22, "pw");
        assert_eq!(auth_mode(&source), Some(AuthMode::Password));
    }

    #[test]
    fn runner_key_file() {
        let source = Source { key_file: Some(PathBuf::from("/keys/netbox-sync")), ..switch("nxos", 22) };
        assert_eq!(auth_mode(&source), Some(AuthMode::KeyFile(Path::new("/keys/netbox-sync"))));
    }

    #[test]
    fn runner_ssh_agent() {
        let source = Source { use_agent: true, ..switch("nxos", 22) };
        assert_eq!(auth_mode(&source), Some(AuthMode::Agent));
    }

    #[test]
    fn no_mode_or_several_modes_is_no_mode() {
        assert_eq!(auth_mode(&switch("nxos", 22)), None);
        assert_eq!(auth_mode(&Source { use_agent: true, ..with_password("nxos", 22, "pw") }), None);
        let both = Source { key_file: Some(PathBuf::from("/keys/netbox-sync")), ..with_password("nxos", 22, "pw") };
        assert_eq!(auth_mode(&both), None);
    }

    #[test]
    fn line_feeds_are_the_ones_netmiko_handed_over() {
        assert_eq!(normalize_linefeeds("a\r\nb\r\r\nc\n\rd\r\r\r\ne\n"), "a\nb\nc\nd\ne\n");
        assert_eq!(normalize_linefeeds("a\rb"), "a\nb");
        assert_eq!(normalize_linefeeds("a\n\nb"), "a\n\nb");
    }

    #[test]
    fn bytes_that_are_not_utf8_are_left_out() {
        assert_eq!(decode(b"caf\xe9 du r\xc3\xa9seau"), "caf du réseau");
        assert_eq!(decode(b"plain"), "plain");
    }

    #[tokio::test]
    async fn an_allowed_command_returns_the_output_of_the_switch() {
        let script = password_script(vec![("show vlan brief | json", Reply::Output("{\"vlans\": []}\n"))]);
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap();
        assert_eq!(runner.run("show vlan brief | json").await, Ok("{\"vlans\": []}\n".to_owned()));
        assert_eq!(server.seen().commands, ["show vlan brief | json"]);
        assert_eq!(server.seen().channels, 1);
        runner.close().await;
    }

    #[tokio::test]
    async fn every_command_runs_in_the_one_session() {
        let script = password_script(vec![
            ("show vlan brief", Reply::Output("VLAN Name\n")),
            ("show switch", Reply::Output("Switch/Stack Mac Address\n")),
        ]);
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("ios", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap();
        assert_eq!(runner.run("show vlan brief").await, Ok("VLAN Name\n".to_owned()));
        assert_eq!(runner.run("show switch").await, Ok("Switch/Stack Mac Address\n".to_owned()));
        let seen = server.seen();
        assert_eq!(seen.commands, ["show vlan brief", "show switch"]);
        // One channel, one shell, pagination and line wrapping turned off once.
        assert_eq!((seen.channels, seen.shells), (1, 1));
        assert_eq!(seen.setup, ["terminal length 0", "terminal width 511"]);
        assert_eq!(seen.password_attempts, ["sync"]);
    }

    #[tokio::test]
    async fn the_output_comes_with_unix_line_feeds() {
        let script = password_script(vec![("show switch", Reply::Output("Switch#\r\n*1 Master\r\n"))]);
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("ios", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap();
        assert_eq!(runner.run("show switch").await, Ok("Switch#\n*1 Master\n".to_owned()));
    }

    // A switch another host launches: this one holds no password for it. The
    // server would let an empty password in: none is ever tried.
    #[tokio::test]
    async fn a_source_whose_password_the_environment_does_not_hold_is_never_contacted_and_names_its_variable() {
        let server = TestServer::start(ed25519_key(), Script { password: Some(""), ..Script::default() }).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let variables = vec!["SWITCH_N1_PASSWORD or SWITCH_PASSWORD".to_owned()];
        let source = Source { password: Some(Wanted::Missing(variables)), ..switch("nxos", server.port) };
        assert_eq!(auth_mode(&source), Some(AuthMode::Password));
        let refused = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err();
        assert_eq!(
            refused,
            Some(CollectionError("missing environment variables: SWITCH_N1_PASSWORD or SWITCH_PASSWORD".to_owned()))
        );
        let seen = server.seen();
        assert_eq!((seen.password_attempts.len(), seen.none_attempts, seen.channels), (0, 0, 0));
        // Not even a connection: the key of the switch was not recorded.
        assert!(!known_hosts.path().exists());
    }

    #[tokio::test]
    async fn a_refused_command_never_reaches_the_wire() {
        let server = TestServer::start(ed25519_key(), password_script(vec![])).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap();
        assert_eq!(
            runner.run("show running-config").await,
            Err(CollectionError("show running-config: refused, not one of the nxos commands".to_owned()))
        );
        assert_eq!(
            runner.run("show interface transceiver").await,
            Err(CollectionError(
                "show interface transceiver: refused, a transceiver command can crash and reboot the switch".to_owned()
            ))
        );
        // Listed for IOS, not for this NX-OS switch.
        assert_eq!(
            runner.run("show interfaces").await,
            Err(CollectionError("show interfaces: refused, not one of the nxos commands".to_owned()))
        );
        runner.close().await;
        assert_eq!(server.seen().commands, Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_type_that_is_not_read_over_ssh_contacts_nothing() {
        let server = TestServer::start(ed25519_key(), password_script(vec![])).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nipper", server.port, "pw");
        let error = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err();
        assert_eq!(error, Some(CollectionError("unsupported platform 'nipper'".to_owned())));
        assert_eq!(*server.seen(), Seen::default());
        assert!(!known_hosts.path().exists());
    }

    #[tokio::test]
    async fn first_connection_records_the_host_key() {
        let host_key = ed25519_key();
        let expected_key = host_key.public_key().to_openssh().unwrap();
        let server = TestServer::start(host_key, password_script(vec![])).await;
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join("state").join("known_hosts");
        let source = with_password("nxos", server.port, "pw");
        let runner = SshRunner::connect(&source, &KnownHosts::new(&path), None, TIMEOUT).await.unwrap();
        runner.close().await;
        assert!(expected_key.starts_with("ssh-ed25519 AAAA"), "{expected_key}");
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("[127.0.0.1]:{} {expected_key}\n", server.port));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn a_recorded_switch_presenting_the_same_key_is_accepted() {
        let server = TestServer::start(ed25519_key(), password_script(vec![])).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", server.port, "pw");
        SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap().close().await;
        let recorded = fs::read_to_string(known_hosts.path()).unwrap();
        SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap().close().await;
        assert_eq!(fs::read_to_string(known_hosts.path()).unwrap(), recorded);
        assert_eq!(recorded.lines().count(), 1);
    }

    #[tokio::test]
    async fn changed_host_key_names_the_file() {
        let first = TestServer::start(ed25519_key(), Script { password: Some(SENTINEL), ..Script::default() }).await;
        let port = first.port;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", port, SENTINEL);
        SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap().close().await;
        let recorded = fs::read_to_string(known_hosts.path()).unwrap();
        first.stop().await;

        // Another device answers on the same address, with a key of its own.
        let script = Script { password: Some(SENTINEL), ..Script::default() };
        let second = TestServer::start_on(port, ed25519_key(), script, Preferred::default()).await;
        let error = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err().unwrap();
        assert_eq!(
            error.to_string(),
            format!(
                "SSH to 127.0.0.1 failed: host key differs from the one recorded in {}",
                known_hosts.path().display()
            )
        );
        // The impostor is given nothing: neither the password nor a login attempt.
        assert_eq!(*second.seen(), Seen::default());
        assert_eq!(fs::read_to_string(known_hosts.path()).unwrap(), recorded);
        assert!(!format!("{error} {error:?}").contains(SENTINEL));
    }

    #[tokio::test]
    async fn password_accepted_in_one_attempt() {
        let server = TestServer::start(ed25519_key(), password_script(vec![])).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", server.port, "pw");
        SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap().close().await;
        let seen = server.seen();
        assert_eq!(seen.password_attempts, ["sync"]);
        assert_eq!((seen.none_attempts, seen.key_requests.len(), seen.signatures.len()), (0, 0, 0));
    }

    #[tokio::test]
    async fn password_refused_after_one_attempt_and_never_shown() {
        let server = TestServer::start(ed25519_key(), password_script(vec![])).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", server.port, SENTINEL);
        let error = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err().unwrap();
        assert_eq!(error.to_string(), "SSH to 127.0.0.1 failed: authentication refused");
        assert!(!format!("{error} {error:?}").contains(SENTINEL));
        let seen = server.seen();
        assert_eq!(seen.password_attempts, ["sync"]);
        assert_eq!((seen.none_attempts, seen.key_requests.len(), seen.signatures.len()), (0, 0, 0));
        // Like the Python tool, the key of a switch is recorded once the connection is up.
        assert!(!known_hosts.path().exists());
    }

    #[tokio::test]
    async fn an_rsa_key_file_signs_with_ssh_rsa_when_rsa_sha2_is_disabled() {
        let script = Script { authorized_key: Some(ACCOUNT_KEY.public_key().clone()), ..Script::default() };
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = Source {
            key_file: Some(key_file(&state, &ACCOUNT_KEY)),
            disabled_algorithms: rsa_sha2_disabled(),
            ..switch("nxos", server.port)
        };
        SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap().close().await;
        let seen = server.seen();
        assert_eq!(seen.signatures, ["ssh-rsa sync"]);
        assert_eq!(seen.key_requests, ["ssh-rsa sync"]);
        assert_eq!((seen.none_attempts, seen.password_attempts.len()), (0, 0));
    }

    #[tokio::test]
    async fn an_rsa_key_file_signs_with_rsa_sha2_512_when_nothing_is_disabled() {
        let script = Script { authorized_key: Some(ACCOUNT_KEY.public_key().clone()), ..Script::default() };
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = Source { key_file: Some(key_file(&state, &ACCOUNT_KEY)), ..switch("nxos", server.port) };
        SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap().close().await;
        assert_eq!(server.seen().signatures, ["rsa-sha2-512 sync"]);
    }

    #[tokio::test]
    async fn a_key_the_switch_does_not_know_is_refused_after_one_request() {
        let script = Script { authorized_key: Some(ed25519_key().public_key().clone()), ..Script::default() };
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = Source {
            key_file: Some(key_file(&state, &ACCOUNT_KEY)),
            disabled_algorithms: rsa_sha2_disabled(),
            ..switch("nxos", server.port)
        };
        let error = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err().unwrap();
        assert_eq!(error.to_string(), "SSH to 127.0.0.1 failed: authentication refused");
        let seen = server.seen();
        assert_eq!(seen.key_requests, ["ssh-rsa sync"]);
        assert_eq!((seen.none_attempts, seen.password_attempts.len(), seen.signatures.len()), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_key_file_that_cannot_be_read_attempts_nothing() {
        let server = TestServer::start(ed25519_key(), Script::default()).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = Source { key_file: Some(state.path().join("absent")), ..switch("nxos", server.port) };
        let error = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err().unwrap();
        assert_eq!(error.to_string(), "SSH to 127.0.0.1 failed: key file unreadable");
        assert_eq!(*server.seen(), Seen::default());
    }

    #[tokio::test]
    async fn the_agent_signs_with_ssh_rsa_in_one_attempt() {
        let agent = PrivateAgent::start(&ACCOUNT_KEY).await;
        let script = Script { authorized_key: Some(ACCOUNT_KEY.public_key().clone()), ..Script::default() };
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source =
            Source { use_agent: true, disabled_algorithms: rsa_sha2_disabled(), ..switch("nxos", server.port) };
        let socket = agent.socket();
        SshRunner::connect(&source, &known_hosts, Some(&socket), TIMEOUT).await.unwrap().close().await;
        let seen = server.seen();
        assert_eq!(seen.signatures, ["ssh-rsa sync"]);
        assert_eq!(seen.key_requests, ["ssh-rsa sync"]);
        assert_eq!((seen.none_attempts, seen.password_attempts.len()), (0, 0));
    }

    #[tokio::test]
    async fn agent_mode_without_a_socket_attempts_nothing() {
        let server = TestServer::start(ed25519_key(), Script::default()).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = Source { use_agent: true, ..switch("nxos", server.port) };
        let error = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err().unwrap();
        assert_eq!(error.to_string(), "SSH to 127.0.0.1 failed: no SSH agent socket");
        assert_eq!(*server.seen(), Seen::default());
    }

    #[tokio::test]
    async fn an_agent_without_an_rsa_key_attempts_nothing() {
        let agent = PrivateAgent::start(&ed25519_key()).await;
        let server = TestServer::start(ed25519_key(), Script::default()).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = Source { use_agent: true, ..switch("nxos", server.port) };
        let socket = agent.socket();
        let error = SshRunner::connect(&source, &known_hosts, Some(&socket), TIMEOUT).await.err().unwrap();
        assert_eq!(error.to_string(), "SSH to 127.0.0.1 failed: no RSA key in the SSH agent");
        assert_eq!(*server.seen(), Seen::default());
    }

    #[tokio::test]
    async fn a_command_the_switch_does_not_answer_times_out() {
        let script = password_script(vec![
            ("show vlan brief | json", Reply::Hang),
            ("show inventory | json", Reply::Output("{}\n")),
        ]);
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, Duration::from_millis(500)).await.unwrap();
        assert_eq!(
            runner.run("show vlan brief | json").await,
            Err(CollectionError("show vlan brief | json: no answer after 500ms".to_owned()))
        );
        // The late answer of the first command could be taken for the next one's:
        // the session is not used any more.
        assert_eq!(
            runner.run("show inventory | json").await,
            Err(CollectionError("show inventory | json: session lost after an unanswered command".to_owned()))
        );
        assert_eq!(server.seen().commands, ["show vlan brief | json"]);
    }

    #[tokio::test]
    async fn what_the_switch_answers_to_a_command_it_rejects_is_handed_over() {
        // The parser of the command is the one that knows what a valid answer is.
        let server = TestServer::start(ed25519_key(), password_script(vec![])).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap();
        assert_eq!(
            runner.run("show inventory | json").await,
            Ok("% Invalid input detected at '^' marker.\n".to_owned())
        );
    }

    #[tokio::test]
    async fn no_command_is_ever_run_outside_the_session() {
        let script = password_script(vec![("show vlan brief", Reply::Output("VLAN Name\n"))]);
        let server = TestServer::start(ed25519_key(), script).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("ios", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap();
        runner.run("show vlan brief").await.unwrap();
        let commands = server.seen().commands.clone();
        assert!(commands.iter().all(|command| !command.starts_with("exec ")), "{commands:?}");
    }

    #[tokio::test]
    async fn a_closed_port_fails_without_the_password() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", port, SENTINEL);
        let error = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.err().unwrap();
        assert_eq!(error.to_string(), "SSH to 127.0.0.1 failed: connection refused");
        assert!(!format!("{error} {error:?}").contains(SENTINEL));
    }

    /// An account whose name must never show in an error.
    const SENTINEL_USER: &str = "0perator-never-shown";

    #[tokio::test]
    async fn a_connection_error_names_ssh_and_the_host_never_the_account() {
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let account =
            |port: u16| Source { username: SENTINEL_USER.to_owned(), ..with_password("nxos", port, SENTINEL) };
        // A switch that refuses the password.
        let server = TestServer::start(ed25519_key(), password_script(vec![])).await;
        let refused = SshRunner::connect(&account(server.port), &known_hosts, None, TIMEOUT).await.err().unwrap();
        // The account did reach the switch: the assertions below are not vacuous.
        assert_eq!(server.seen().password_attempts, [SENTINEL_USER]);
        // A port nothing listens on.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let closed = SshRunner::connect(&account(port), &known_hosts, None, TIMEOUT).await.err().unwrap();
        // A listener that accepts and then says nothing, like a filtered switch.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let silent = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let late =
            SshRunner::connect(&account(port), &known_hosts, None, Duration::from_millis(500)).await.err().unwrap();
        silent.abort();
        for (error, expected) in [
            (refused, "SSH to 127.0.0.1 failed: authentication refused"),
            (closed, "SSH to 127.0.0.1 failed: connection refused"),
            (late, "SSH to 127.0.0.1 failed: no answer after 500ms"),
        ] {
            assert_eq!(error.to_string(), expected);
            // Neither the error nor a cause of it says more.
            assert!(std::error::Error::source(&error).is_none(), "{error:?}");
            let printed = format!("{error} {error:?}");
            assert!(!printed.contains(SENTINEL_USER) && !printed.contains(SENTINEL), "{printed}");
        }
    }

    #[tokio::test]
    async fn a_device_that_never_answers_times_out() {
        // A listener that accepts and then says nothing, like a filtered switch.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let silent = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("nxos", port, SENTINEL);
        let error = SshRunner::connect(&source, &known_hosts, None, Duration::from_millis(500)).await.err().unwrap();
        silent.abort();
        assert_eq!(error.to_string(), "SSH to 127.0.0.1 failed: no answer after 500ms");
    }

    #[tokio::test]
    async fn a_switch_that_only_speaks_the_old_algorithms_is_reached() {
        let old = Preferred {
            kex: vec![kex::DH_G14_SHA1].into(),
            key: vec![Algorithm::Rsa { hash: None }].into(),
            cipher: vec![cipher::AES_128_CBC].into(),
            mac: vec![mac::HMAC_SHA1].into(),
            ..Preferred::default()
        };
        let expected_key = RSA_HOST_KEY.public_key().to_openssh().unwrap();
        let script = password_script(vec![("show switch", Reply::Output("Switch/Stack Mac Address\n"))]);
        let server = TestServer::start_on(0, RSA_HOST_KEY.clone(), script, old).await;
        let state = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(state.path().join("known_hosts"));
        let source = with_password("ios", server.port, "pw");
        let mut runner = SshRunner::connect(&source, &known_hosts, None, TIMEOUT).await.unwrap();
        assert_eq!(runner.run("show switch").await, Ok("Switch/Stack Mac Address\n".to_owned()));
        assert!(expected_key.starts_with("ssh-rsa AAAA"), "{expected_key}");
        assert_eq!(
            fs::read_to_string(known_hosts.path()).unwrap(),
            format!("[127.0.0.1]:{} {expected_key}\n", server.port)
        );
    }
}
