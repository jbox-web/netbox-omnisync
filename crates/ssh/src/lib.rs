//! SSH client side shared by the sources read over SSH: the switches (an
//! interactive session) and the Proxmox nodes (one command on an `exec`
//! channel).
//!
//! What is shared is what is not about the device: the host keys, checked
//! against a file in the OpenSSH `known_hosts` format and trusted on first
//! use; the algorithms offered, the defaults of russh then the old ones some
//! switches need, minus the ones an entry disables; and exactly one
//! authentication attempt, in the configured mode: every extra attempt (agent
//! keys, default key files) counts as a failed login on the device.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use omnisync_core::network::inventory::Secret;
use russh::client;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{
    Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64, PublicKeyOrCertificate,
};
use russh::{Channel, ChannelMsg, Disconnect, Preferred, cipher, kex, mac};

pub mod known_hosts;

use known_hosts::{KnownHosts, Verdict, host_name};

/// The disabled algorithms of an entry: kind (`kex`, `keys`, `ciphers`,
/// `macs`, `pubkeys`) to names.
pub type Disabled = BTreeMap<String, Vec<String>>;

/// The one authentication mode of an account.
#[derive(Debug, Clone, Copy)]
pub enum Auth<'a> {
    /// The keys of the SSH agent at the socket handed to [`connect`].
    Agent,
    KeyFile(&'a Path),
    /// The password, already read from the environment by the caller.
    Password(&'a Secret),
}

/// The account a device is logged into with.
#[derive(Debug, Clone, Copy)]
pub struct Account<'a> {
    pub username: &'a str,
    pub auth: Auth<'a>,
    pub disabled_algorithms: Option<&'a Disabled>,
    /// In agent mode, only an RSA key is offered: the old switches know no
    /// other. Otherwise the first key of the agent is.
    pub agent_rsa_only: bool,
}

/// The device a connection goes to, and what the messages call it.
#[derive(Debug, Clone, Copy)]
pub struct Peer<'a> {
    pub host: &'a str,
    pub port: u16,
    /// `switch`, `node`: as the messages name the device.
    pub noun: &'a str,
}

/// The names disabled under one key of `disabled_algorithms`.
pub fn disabled_names<'a>(disabled: Option<&'a BTreeMap<String, Vec<String>>>, key: &str) -> &'a [String] {
    disabled.and_then(|kinds| kinds.get(key)).map_or(&[], Vec::as_slice)
}

/// The hashes an RSA key may sign with, best first; None is `ssh-rsa` (SHA-1).
///
/// Old NX-OS/IOS send no server-sig-algs and reject rsa-sha2-*: with both
/// disabled under `pubkeys`, `ssh-rsa` is all that is left.
pub fn rsa_hashes(disabled: Option<&BTreeMap<String, Vec<String>>>) -> Vec<Option<HashAlg>> {
    let off = disabled_names(disabled, "pubkeys");
    [("rsa-sha2-512", Some(HashAlg::Sha512)), ("rsa-sha2-256", Some(HashAlg::Sha256)), ("ssh-rsa", None)]
        .into_iter()
        .filter(|(name, _)| !off.iter().any(|disabled| disabled == name))
        .map(|(_, hash)| hash)
        .collect()
}

/// The defaults, then the extra ones not already there, minus the disabled ones.
fn offer<T: Clone + PartialEq>(defaults: &[T], extra: &[T], off: &[String], name: impl Fn(&T) -> &str) -> Vec<T> {
    let mut offered = defaults.to_vec();
    for item in extra {
        if !offered.contains(item) {
            offered.push(item.clone());
        }
    }
    offered.retain(|item| !off.iter().any(|disabled| disabled == name(item)));
    offered
}

/// The algorithms offered to a switch: the defaults of russh, then the old ones
/// these switches need, minus the ones the inventory disables (`kex`, `keys`,
/// `ciphers`, `macs`).
pub fn preferred(disabled: Option<&BTreeMap<String, Vec<String>>>) -> Preferred {
    let defaults = Preferred::default();
    Preferred {
        kex: offer(
            &defaults.kex,
            &[kex::DH_G14_SHA1, kex::DH_GEX_SHA1, kex::DH_G1_SHA1],
            disabled_names(disabled, "kex"),
            |name| name.as_ref(),
        )
        .into(),
        key: offer(
            &defaults.key,
            &[Algorithm::Rsa { hash: None }],
            disabled_names(disabled, "keys"),
            Algorithm::as_str,
        )
        .into(),
        cipher: offer(
            &defaults.cipher,
            &[cipher::AES_128_CBC, cipher::AES_192_CBC, cipher::AES_256_CBC],
            disabled_names(disabled, "ciphers"),
            |name| name.as_ref(),
        )
        .into(),
        mac: offer(&defaults.mac, &[mac::HMAC_SHA1], disabled_names(disabled, "macs"), |name| name.as_ref()).into(),
        ..defaults
    }
}

/// The names the client may offer for one kind of `disabled_algorithms`.
pub fn offered_names(kind: &str) -> Vec<String> {
    let all = preferred(None);
    match kind {
        "kex" => all.kex.iter().map(|name| name.as_ref().to_owned()).collect(),
        "keys" => all.key.iter().map(|algorithm| algorithm.as_str().to_owned()).collect(),
        "ciphers" => all.cipher.iter().map(|name| name.as_ref().to_owned()).collect(),
        "macs" => all.mac.iter().map(|name| name.as_ref().to_owned()).collect(),
        _ => Vec::new(),
    }
}

/// The first algorithm `disabled_algorithms` names that the client never
/// offers: it would disable nothing, and the one meant would stay offered.
/// `pubkeys` is checked when the inventory is read.
pub fn unknown_disabled(disabled: Option<&BTreeMap<String, Vec<String>>>) -> Option<String> {
    ["kex", "keys", "ciphers", "macs"].into_iter().find_map(|kind| {
        let offered = offered_names(kind);
        let unknown = disabled_names(disabled, kind).iter().find(|name| !offered.contains(name))?;
        Some(format!("ssh.disabled_algorithms: unknown {kind} algorithm {unknown}"))
    })
}

/// What the known hosts file said of the key the switch presented.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum HostKey {
    /// The switch has not presented its key yet.
    #[default]
    NotSeen,
    Trusted,
    /// First connection: recorded once the authentication has succeeded.
    New {
        key_type: String,
        key: String,
    },
    Differs,
    /// A `@revoked` line of the file names this key.
    Revoked,
    /// The host presented a certificate: nothing says which authority to trust.
    Certificate,
    Unreadable,
}

/// Why the key a host presented was refused; None when it was not.
fn refusal(host_key: &HostKey, file: &Path, noun: &str) -> Option<String> {
    match host_key {
        HostKey::Differs => Some(format!("host key differs from the one recorded in {}", file.display())),
        HostKey::Revoked => Some(format!("host key is revoked in {}", file.display())),
        HostKey::Certificate => {
            Some(format!("host key is a certificate, which is not supported: record the plain key of the {noun}"))
        }
        HostKey::Unreadable => Some("known hosts file unreadable".to_owned()),
        HostKey::NotSeen | HostKey::Trusted | HostKey::New { .. } => None,
    }
}

/// The client side of one connection: it only has the host key to judge.
struct Client {
    known_hosts: KnownHosts,
    /// The name the device is recorded under.
    name: String,
    host_key: Arc<Mutex<HostKey>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    /// Trust on first use: a host missing from the file is accepted, and
    /// recorded once the connection is up; a recorded host must present the
    /// same key.
    async fn check_server_key(&mut self, server_public_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let judged = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => judge(&self.known_hosts, &self.name, key),
            // Nothing here says which authorities to trust.
            PublicKeyOrCertificate::Certificate(_) => HostKey::Certificate,
        };
        let accepted = matches!(judged, HostKey::Trusted | HostKey::New { .. });
        *self.host_key.lock().unwrap_or_else(PoisonError::into_inner) = judged;
        Ok(accepted)
    }
}

fn judge(known_hosts: &KnownHosts, name: &str, key: &PublicKey) -> HostKey {
    let (key_type, base64) = (key.algorithm().as_str().to_owned(), key.public_key_base64());
    match known_hosts.verdict(name, &key_type, &base64) {
        Ok(Verdict::Same) => HostKey::Trusted,
        Ok(Verdict::Unknown) => HostKey::New { key_type, key: base64 },
        Ok(Verdict::Differs) => HostKey::Differs,
        Ok(Verdict::Revoked) => HostKey::Revoked,
        Err(_) => HostKey::Unreadable,
    }
}

/// What the one authentication attempt is made with, prepared before the
/// device is contacted: a mode that cannot work attempts nothing.
enum Credentials {
    Password(String),
    Key(PrivateKeyWithHashAlg),
    Agent(Box<AgentClient<tokio::net::UnixStream>>, PublicKey, Option<HashAlg>),
}

async fn credentials(account: &Account<'_>, agent_socket: Option<&Path>) -> Result<Credentials, &'static str> {
    let hashes = rsa_hashes(account.disabled_algorithms);
    let hash_for = |rsa: bool| if rsa { hashes.first().copied().flatten() } else { None };
    match account.auth {
        Auth::Password(password) => Ok(Credentials::Password(password.expose().to_owned())),
        Auth::KeyFile(path) => {
            let key: PrivateKey = russh::keys::load_secret_key(path, None).map_err(|_| "key file unreadable")?;
            let hash = hash_for(key.algorithm().is_rsa());
            Ok(Credentials::Key(PrivateKeyWithHashAlg::new(Arc::new(key), hash)))
        }
        Auth::Agent => {
            let socket = agent_socket.ok_or("no SSH agent socket")?;
            let mut agent = AgentClient::connect_uds(socket).await.map_err(|_| "SSH agent unreachable")?;
            let identities = agent.request_identities().await.map_err(|_| "SSH agent unreachable")?;
            // The old switches only know RSA keys: the first one is the one attempt.
            let key = identities
                .into_iter()
                .find_map(|identity| match identity {
                    AgentIdentity::PublicKey { key, .. } if !account.agent_rsa_only || key.algorithm().is_rsa() => {
                        Some(key)
                    }
                    _ => None,
                })
                .ok_or(if account.agent_rsa_only {
                    "no RSA key in the SSH agent"
                } else {
                    "no key in the SSH agent"
                })?;
            let hash = hash_for(key.algorithm().is_rsa());
            Ok(Credentials::Agent(Box::new(agent), key, hash))
        }
    }
}

/// What went wrong, in words that carry neither the password nor key material.
pub fn kind(error: &russh::Error, noun: &str) -> String {
    match error {
        russh::Error::IO(error) if error.kind() == ErrorKind::ConnectionRefused => "connection refused".to_owned(),
        russh::Error::IO(error) => error.kind().to_string(),
        russh::Error::NoCommonAlgo { .. } => "no common algorithm".to_owned(),
        russh::Error::Disconnect | russh::Error::HUP => format!("connection closed by the {noun}"),
        _ => "SSH protocol error".to_owned(),
    }
}

/// What a command run with [`Connection::exec`] gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// None when the device ended the channel without telling a status.
    pub status: Option<u32>,
    pub stdout: String,
    pub stderr: String,
}

/// Everything a channel says until the device closes it.
async fn read_to_end(mut channel: Channel<client::Msg>) -> Result<Output, String> {
    let (mut stdout, mut stderr, mut status) = (Vec::new(), Vec::new(), None);
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Failure => return Err("the command was refused".to_owned()),
            _ => {}
        }
    }
    let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
    Ok(Output { status, stdout: text(stdout), stderr: text(stderr) })
}

/// An authenticated connection to a device.
pub struct Connection {
    handle: client::Handle<Client>,
    noun: String,
}

/// Connects to a device and authenticates, once, with `account`.
///
/// `agent_socket` is the socket of the SSH agent, used in agent mode only:
/// the caller reads it from its environment. `timeout` bounds the connection
/// and the authentication, each. A failure is a few words that carry neither
/// the password nor key material.
pub async fn connect(
    peer: &Peer<'_>,
    account: &Account<'_>,
    known_hosts: &KnownHosts,
    agent_socket: Option<&Path>,
    timeout: Duration,
) -> Result<Connection, String> {
    let no_answer = || format!("no answer after {timeout:?}");
    if let Some(why) = unknown_disabled(account.disabled_algorithms) {
        return Err(why);
    }
    let credentials = credentials(account, agent_socket).await.map_err(str::to_owned)?;
    let (host, port, noun) = (peer.host, peer.port, peer.noun);
    let host_key = Arc::new(Mutex::new(HostKey::default()));
    let client =
        Client { known_hosts: known_hosts.clone(), name: host_name(host, port), host_key: Arc::clone(&host_key) };
    let config = client::Config { preferred: preferred(account.disabled_algorithms), ..Default::default() };
    let seen = || host_key.lock().unwrap_or_else(PoisonError::into_inner).clone();

    let connected = tokio::time::timeout(timeout, client::connect(Arc::new(config), (host, port), client)).await;
    let mut handle = match connected.map_err(|_| no_answer())? {
        Ok(handle) => handle,
        Err(error) => {
            return Err(refusal(&seen(), known_hosts.path(), noun).unwrap_or_else(|| kind(&error, noun)));
        }
    };

    let user = account.username;
    let attempt = async {
        match credentials {
            Credentials::Password(password) => {
                handle.authenticate_password(user, password).await.map_err(|error| kind(&error, noun))
            }
            Credentials::Key(key) => handle.authenticate_publickey(user, key).await.map_err(|error| kind(&error, noun)),
            Credentials::Agent(mut agent, key, hash) => handle
                .authenticate_publickey_with(user, key, hash, agent.as_mut())
                .await
                .map_err(|_| "SSH agent refused to sign".to_owned()),
        }
    };
    let authenticated = tokio::time::timeout(timeout, attempt).await.map_err(|_| no_answer())?;
    if !authenticated?.success() {
        return Err("authentication refused".to_owned());
    }
    if let HostKey::New { key_type, key } = seen() {
        known_hosts.record(&host_name(host, port), &key_type, &key).map_err(|_| "known hosts file not writable")?;
    }
    Ok(Connection { handle, noun: noun.to_owned() })
}

impl Connection {
    /// An interactive session: a terminal of this size, then a shell.
    pub async fn open_shell(&self, width: u32, height: u32) -> Result<Channel<client::Msg>, String> {
        let noun = self.noun.as_str();
        let session = self.handle.channel_open_session().await.map_err(|error| kind(&error, noun))?;
        session.request_pty(false, "vt100", width, height, 0, 0, &[]).await.map_err(|error| kind(&error, noun))?;
        session.request_shell(false).await.map_err(|error| kind(&error, noun))?;
        Ok(session)
    }

    /// Runs one command on a channel of its own, without a terminal nor a
    /// shell, and gives its exit status and what it wrote, once it ended.
    /// `timeout` bounds the whole command.
    pub async fn exec(&self, command: &str, timeout: Duration) -> Result<Output, String> {
        let noun = self.noun.as_str();
        let run = async {
            let channel = self.handle.channel_open_session().await.map_err(|error| kind(&error, noun))?;
            // `want_reply`: a device that refuses the command says so.
            channel.exec(true, command).await.map_err(|error| kind(&error, noun))?;
            read_to_end(channel).await
        };
        tokio::time::timeout(timeout, run).await.map_err(|_| format!("no answer after {timeout:?}"))?
    }

    /// What a failure of this connection is, in words.
    pub fn kind(&self, error: &russh::Error) -> String {
        kind(error, &self.noun)
    }

    /// Close the connection; dropping it closes it as well.
    pub async fn close(self) {
        // The device may already have hung up: there is nothing left to do then.
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names<T: AsRef<str>>(list: &[T]) -> Vec<&str> {
        list.iter().map(AsRef::as_ref).collect()
    }

    fn rsa_sha2_disabled() -> Option<BTreeMap<String, Vec<String>>> {
        Some(BTreeMap::from([("pubkeys".to_owned(), vec!["rsa-sha2-512".to_owned(), "rsa-sha2-256".to_owned()])]))
    }

    // A name russh does not offer disables nothing: `aes128-cbcx` would leave
    // aes128-cbc offered without a word.
    #[test]
    fn a_failure_is_told_by_its_category_alone() {
        // What russh says of a failure may quote what was exchanged: only the
        // category leaves the transport.
        let refused = russh::Error::IO(std::io::Error::from(ErrorKind::ConnectionRefused));
        assert_eq!(kind(&refused, "switch"), "connection refused");
        let reset = russh::Error::IO(std::io::Error::new(ErrorKind::ConnectionReset, "peer 192.0.2.7 said s3cret"));
        assert_eq!(kind(&reset, "switch"), "connection reset");
        assert_eq!(kind(&russh::Error::Disconnect, "switch"), "connection closed by the switch");
        assert_eq!(kind(&russh::Error::HUP, "switch"), "connection closed by the switch");
        assert_eq!(kind(&russh::Error::NotAuthenticated, "switch"), "SSH protocol error");
    }

    #[test]
    fn a_disabled_algorithm_the_client_does_not_offer_is_refused() {
        let disabled = |kind: &str, name: &str| Some(BTreeMap::from([(kind.to_owned(), vec![name.to_owned()])]));
        assert_eq!(unknown_disabled(disabled("ciphers", "aes128-cbc").as_ref()), None);
        assert_eq!(unknown_disabled(disabled("kex", "diffie-hellman-group1-sha1").as_ref()), None);
        assert_eq!(unknown_disabled(disabled("macs", "hmac-sha1").as_ref()), None);
        assert_eq!(unknown_disabled(disabled("keys", "ssh-rsa").as_ref()), None);
        assert_eq!(
            unknown_disabled(disabled("ciphers", "aes128-cbcx").as_ref()).as_deref(),
            Some("ssh.disabled_algorithms: unknown ciphers algorithm aes128-cbcx")
        );
        assert_eq!(unknown_disabled(None), None);
    }

    // Each refusal of a host key says what it is about: a key that differs
    // from the recorded one, a revoked key, a certificate (nothing says which
    // authority to trust), not the same sentence for the three.
    #[test]
    fn each_refused_host_key_says_why() {
        let file = Path::new("/state/known_hosts");
        assert_eq!(
            refusal(&HostKey::Differs, file, "switch").as_deref(),
            Some("host key differs from the one recorded in /state/known_hosts")
        );
        assert_eq!(
            refusal(&HostKey::Revoked, file, "switch").as_deref(),
            Some("host key is revoked in /state/known_hosts")
        );
        assert_eq!(
            refusal(&HostKey::Certificate, file, "switch").as_deref(),
            Some("host key is a certificate, which is not supported: record the plain key of the switch")
        );
        assert_eq!(refusal(&HostKey::Unreadable, file, "switch").as_deref(), Some("known hosts file unreadable"));
        assert_eq!(refusal(&HostKey::Trusted, file, "switch"), None);
    }

    #[test]
    fn an_rsa_key_signs_with_ssh_rsa_once_rsa_sha2_is_disabled() {
        assert_eq!(rsa_hashes(rsa_sha2_disabled().as_ref()), [None]);
        assert_eq!(rsa_hashes(None), [Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]);
        let only_512 = BTreeMap::from([("pubkeys".to_owned(), vec!["rsa-sha2-512".to_owned()])]);
        assert_eq!(rsa_hashes(Some(&only_512)), [Some(HashAlg::Sha256), None]);
        let other_kind = BTreeMap::from([("kex".to_owned(), vec!["rsa-sha2-512".to_owned()])]);
        assert_eq!(rsa_hashes(Some(&other_kind)), [Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]);
    }

    #[test]
    fn the_old_algorithms_are_offered_in_addition_to_the_defaults() {
        let offered = preferred(None);
        let kex = names(&offered.kex);
        for name in ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"]
        {
            assert!(kex.contains(&name), "{name} in {kex:?}");
        }
        let keys: Vec<&str> = offered.key.iter().map(Algorithm::as_str).collect();
        assert!(keys.contains(&"ssh-rsa"), "{keys:?}");
        let ciphers = names(&offered.cipher);
        for name in ["aes128-cbc", "aes192-cbc", "aes256-cbc"] {
            assert!(ciphers.contains(&name), "{name} in {ciphers:?}");
        }
        assert!(names(&offered.mac).contains(&"hmac-sha1"));
        // The defaults stay, and stay first.
        let defaults = Preferred::default();
        assert_eq!(kex[..defaults.kex.len()], names(&defaults.kex));
        assert_eq!(ciphers[..defaults.cipher.len()], names(&defaults.cipher));
        assert!(kex.contains(&"curve25519-sha256"));
        assert!(keys.contains(&"ssh-ed25519"));
    }

    #[test]
    fn disabled_algorithms_are_not_offered() {
        let disabled = BTreeMap::from([
            ("kex".to_owned(), vec!["diffie-hellman-group1-sha1".to_owned()]),
            ("ciphers".to_owned(), vec!["aes128-cbc".to_owned()]),
            ("macs".to_owned(), vec!["hmac-sha1".to_owned()]),
            ("keys".to_owned(), vec!["ssh-ed25519".to_owned()]),
        ]);
        let offered = preferred(Some(&disabled));
        let kex = names(&offered.kex);
        assert!(!kex.contains(&"diffie-hellman-group1-sha1"));
        assert!(kex.contains(&"diffie-hellman-group14-sha1"));
        assert!(!names(&offered.cipher).contains(&"aes128-cbc"));
        assert!(names(&offered.cipher).contains(&"aes256-cbc"));
        assert!(!names(&offered.mac).contains(&"hmac-sha1"));
        let keys: Vec<&str> = offered.key.iter().map(Algorithm::as_str).collect();
        assert!(!keys.contains(&"ssh-ed25519"));
        assert!(keys.contains(&"ssh-rsa"));
    }
}

#[cfg(test)]
mod exec_tests {
    use std::sync::{Arc, Mutex};

    use russh::keys::{Algorithm, PrivateKey};
    use russh::server::{self, Auth as Accepted, Msg, Session};
    use russh::{Channel, ChannelId};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(10);

    /// What the node received.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct Seen {
        ptys: usize,
        shells: usize,
        commands: Vec<String>,
    }

    /// A node that answers each command it knows with what lldpd wrote, and
    /// any other with an error on stderr and the status 127 of a shell.
    #[derive(Clone)]
    struct Node {
        seen: Arc<Mutex<Seen>>,
        answers: Arc<Vec<(&'static str, &'static str, &'static str, u32)>>,
    }

    impl server::Handler for Node {
        type Error = russh::Error;

        async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Accepted, Self::Error> {
            Ok(if password == "pw" { Accepted::Accept } else { Accepted::reject() })
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
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
            self.seen.lock().unwrap().ptys += 1;
            session.channel_success(channel)?;
            Ok(())
        }

        async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
            self.seen.lock().unwrap().shells += 1;
            session.channel_success(channel)?;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let command = String::from_utf8_lossy(data).into_owned();
            self.seen.lock().unwrap().commands.push(command.clone());
            session.channel_success(channel)?;
            let known = self.answers.iter().find(|(asked, ..)| *asked == command);
            let (stdout, stderr, status) = match known {
                Some((_, stdout, stderr, status)) => (*stdout, *stderr, *status),
                None => ("", "sh: 1: no such command\n", 127),
            };
            // In pieces: the client must read up to the end, not the first packet.
            for piece in stdout.as_bytes().chunks(7) {
                session.data(channel, piece.to_vec())?;
            }
            if !stderr.is_empty() {
                session.extended_data(channel, 1, stderr.as_bytes().to_vec())?;
            }
            session.exit_status_request(channel, status)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    struct TestNode {
        port: u16,
        seen: Arc<Mutex<Seen>>,
        task: JoinHandle<()>,
    }

    impl TestNode {
        async fn start(answers: Vec<(&'static str, &'static str, &'static str, u32)>) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let seen = Arc::new(Mutex::new(Seen::default()));
            let node = Node { seen: Arc::clone(&seen), answers: Arc::new(answers) };
            let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
            let config = Arc::new(server::Config {
                keys: vec![key],
                auth_rejection_time: Duration::ZERO,
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (config, node) = (Arc::clone(&config), node.clone());
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, node).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            TestNode { port, seen, task }
        }

        async fn connect(&self, directory: &tempfile::TempDir) -> Connection {
            let known_hosts = KnownHosts::new(directory.path().join("known_hosts"));
            let password = Secret::new("pw");
            let account = Account {
                username: "lldp",
                auth: Auth::Password(&password),
                disabled_algorithms: None,
                agent_rsa_only: false,
            };
            let peer = Peer { host: "127.0.0.1", port: self.port, noun: "node" };
            connect(&peer, &account, &known_hosts, None, TIMEOUT).await.expect("connected")
        }
    }

    impl Drop for TestNode {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    const NEIGHBORS: &str = "lldpcli -f json show neighbors";

    #[tokio::test]
    async fn one_command_is_run_without_a_terminal_and_its_output_is_given() {
        let answer = "{\n  \"lldp\": {\n    \n  }\n}\n";
        let node = TestNode::start(vec![(NEIGHBORS, answer, "", 0)]).await;
        let directory = tempfile::tempdir().unwrap();
        let connection = node.connect(&directory).await;
        let output = connection.exec(NEIGHBORS, TIMEOUT).await.expect("the command ran");
        assert_eq!(output, Output { status: Some(0), stdout: answer.to_owned(), stderr: String::new() });
        connection.close().await;
        let seen = node.seen.lock().unwrap();
        assert_eq!(*seen, Seen { ptys: 0, shells: 0, commands: vec![NEIGHBORS.to_owned()] });
    }

    #[tokio::test]
    async fn a_command_that_fails_gives_its_status_and_what_it_wrote() {
        let refused = "unable to connect to socket /run/lldpd.socket: Permission denied\n";
        let node = TestNode::start(vec![(NEIGHBORS, "", refused, 1)]).await;
        let directory = tempfile::tempdir().unwrap();
        let connection = node.connect(&directory).await;
        let output = connection.exec(NEIGHBORS, TIMEOUT).await.expect("the command ran");
        assert_eq!(output, Output { status: Some(1), stdout: String::new(), stderr: refused.to_owned() });
        let unknown = connection.exec("lldpctl", TIMEOUT).await.expect("the command ran");
        assert_eq!(unknown.status, Some(127));
    }
}
