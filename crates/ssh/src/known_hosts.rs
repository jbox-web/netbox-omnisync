//! Host keys trusted on first use, kept in a file in the OpenSSH `known_hosts`
//! format (`host keytype base64`).
//!
//! The key of a switch seen for the first time is accepted and recorded; from
//! then on a recorded switch must present the same key. After a legitimate key
//! change (switch replaced, key regenerated), its line is deleted from the file
//! by hand.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use data_encoding::BASE64;
use hmac::{Hmac, KeyInit, Mac};
use omnisync_core::network::inventory::Environ;
use sha1::Sha1;

/// Environment variable naming the file, instead of the one under the state directory.
pub const KNOWN_HOSTS_ENV: &str = "SWITCH_KNOWN_HOSTS";

/// Switches are collected in parallel: every read and write of the known_hosts
/// file goes through this lock, so a switch never reads a half-written file (and
/// takes a recorded host for a new one) nor overwrites another switch's new key.
static KNOWN_HOSTS_LOCK: Mutex<()> = Mutex::new(());

/// Host keys recorded at the first connection to each switch: machine state, not config.
///
/// `$SWITCH_KNOWN_HOSTS` when set, else `netbox-omnisync/known_hosts` under
/// `$XDG_STATE_HOME`, which defaults to `~/.local/state`. The environment is
/// handed in by the caller: nothing is read from the process here.
pub fn known_hosts_file(environ: &Environ, home: &Path) -> PathBuf {
    let set = |name: &str| environ.get(name).filter(|value| !value.is_empty());
    if let Some(path) = set(KNOWN_HOSTS_ENV) {
        return PathBuf::from(path);
    }
    let state = match set("XDG_STATE_HOME") {
        Some(directory) => PathBuf::from(directory),
        None => home.join(".local").join("state"),
    };
    state.join("netbox-omnisync").join("known_hosts")
}

/// The name a host is recorded under: the host alone on the SSH port, `[host]:port`
/// on any other, as OpenSSH writes it.
pub fn host_name(host: &str, port: u16) -> String {
    if port == 22 { host.to_owned() } else { format!("[{host}]:{port}") }
}

/// What the file says of the key a host presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The host is not in the file: first connection.
    Unknown,
    /// The host is recorded with this very key.
    Same,
    /// The host is recorded, with another key.
    Differs,
    /// A `@revoked` line names this key for this host: refused whatever else
    /// the file records, as OpenSSH does.
    Revoked,
}

/// The file could not be read or rewritten.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("known hosts file {}: {reason}", path.display())]
pub struct KnownHostsError {
    pub path: PathBuf,
    pub reason: String,
}

/// One line of the file that records a key: its hosts, key type and key.
struct Entry<'a> {
    hosts: Vec<&'a str>,
    key_type: &'a str,
    key: &'a str,
}

/// The entry a line holds; None for a blank line, a comment, a marker line
/// (`@revoked`, `@cert-authority`) or a line too short to hold a key.
fn entry(line: &str) -> Option<Entry<'_>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
        return None;
    }
    let mut words = line.split_whitespace();
    let (hosts, key_type, key) = (words.next()?, words.next()?, words.next()?);
    Some(Entry { hosts: hosts.split(',').collect(), key_type, key })
}

/// Whether one host field of a line names `host`: written as is, or hashed
/// as `ssh-keyscan -H` and `HashKnownHosts yes` write it (`|1|salt|hash`, the
/// HMAC-SHA1 of the name keyed by the salt, both in base64).
fn names(pattern: &str, host: &str) -> bool {
    let Some(hashed) = pattern.strip_prefix("|1|") else {
        return pattern == host;
    };
    let Some((salt, hash)) = hashed.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(hash)) = (BASE64.decode(salt.as_bytes()), BASE64.decode(hash.as_bytes())) else {
        return false;
    };
    Hmac::<Sha1>::new_from_slice(&salt).is_ok_and(|mac| mac.chain_update(host.as_bytes()).verify_slice(&hash).is_ok())
}

/// The entry of a `@revoked` line: the key it names for its hosts.
fn revoked(line: &str) -> Option<Entry<'_>> {
    let rest = line.trim().strip_prefix("@revoked")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    entry(rest)
}

fn lock() -> MutexGuard<'static, ()> {
    // The lock guards a file, not memory: a panic in another thread leaves nothing to distrust.
    KNOWN_HOSTS_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The file of the recorded host keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        KnownHosts { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Compare the key a host presents with the ones recorded for it. A missing
    /// file records nothing: every host is then seen for the first time.
    pub fn verdict(&self, host: &str, key_type: &str, key_base64: &str) -> Result<Verdict, KnownHostsError> {
        let text = {
            let _guard = lock();
            self.read()?
        };
        // A revoked key is refused first, whatever else the file records.
        let names_host = |known: &Entry<'_>| known.hosts.iter().any(|name| *name == "*" || names(name, host));
        if text
            .lines()
            .filter_map(revoked)
            .any(|known| names_host(&known) && known.key_type == key_type && known.key == key_base64)
        {
            return Ok(Verdict::Revoked);
        }
        let mut recorded = false;
        for known in text.lines().filter_map(entry).filter(|known| known.hosts.iter().any(|name| names(name, host))) {
            if known.key_type == key_type && known.key == key_base64 {
                return Ok(Verdict::Same);
            }
            recorded = true;
        }
        Ok(if recorded { Verdict::Differs } else { Verdict::Unknown })
    }

    /// Add one key to the file as it is now, then replace the file in one step.
    ///
    /// The file is written next to itself under a temporary name, readable by
    /// its owner only, then renamed: a reader sees the old file or the new one,
    /// never half of it. The parent directory is created when missing. A key
    /// already recorded for this host and this key type is replaced.
    pub fn record(&self, host: &str, key_type: &str, key_base64: &str) -> Result<(), KnownHostsError> {
        let _guard = lock();
        let text = self.read()?;
        let line = format!("{host} {key_type} {key_base64}");
        let mut lines: Vec<&str> = Vec::new();
        let mut replaced = false;
        for current in text.lines() {
            let same = entry(current).is_some_and(|known| known.hosts == [host] && known.key_type == key_type);
            if same && !replaced {
                lines.push(&line);
                replaced = true;
            } else if !same {
                lines.push(current);
            }
        }
        if !replaced {
            lines.push(&line);
        }
        let mut content = lines.join("\n");
        content.push('\n');

        let directory = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        fs::create_dir_all(directory).map_err(|error| self.error(&error))?;
        // A temporary file is created readable by its owner only.
        let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|error| self.error(&error))?;
        temporary.write_all(content.as_bytes()).map_err(|error| self.error(&error))?;
        temporary.persist(&self.path).map_err(|error| self.error(&error.error))?;
        Ok(())
    }

    /// The text of the file, empty when the file does not exist yet.
    fn read(&self) -> Result<String, KnownHostsError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Ok(text),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(self.error(&error)),
        }
    }

    fn error(&self, error: &std::io::Error) -> KnownHostsError {
        KnownHostsError { path: self.path.clone(), reason: error.kind().to_string() }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    const KEY: &str = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDKEYOFSWITCHONE";
    const OTHER_KEY: &str = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDKEYOFSWITCHTWO";

    fn environ(pairs: &[(&str, &str)]) -> Environ {
        pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("the file exists").permissions().mode() & 0o777
    }

    // `ssh-keyscan -H` and `HashKnownHosts yes` (the default of Debian, set on
    // the cron host) write `|1|salt|hash`. This line names example.com:
    // `ssh-keygen -F example.com` finds it, `ssh-keygen -F other.example` does not.
    const HASHED: &str = "|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 \
                          AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n";
    const HASHED_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF";

    #[test]
    fn a_hashed_entry_pins_the_key_of_the_host_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        fs::write(&path, HASHED).unwrap();
        let known = KnownHosts::new(&path);
        assert_eq!(known.verdict("example.com", "ssh-ed25519", HASHED_KEY), Ok(Verdict::Same));
        assert_eq!(known.verdict("example.com", "ssh-ed25519", OTHER_KEY), Ok(Verdict::Differs));
        assert_eq!(known.verdict("other.example", "ssh-ed25519", HASHED_KEY), Ok(Verdict::Unknown));
    }

    // OpenSSH refuses a key a `@revoked` line names, for the hosts of that line
    // (`*` for every host), whatever else the file records.
    #[test]
    fn a_key_a_revoked_line_names_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        for hosts in ["n1", "*", "other,n1"] {
            fs::write(&path, format!("@revoked {hosts} ssh-rsa {KEY}\nn1 ssh-rsa {KEY}\n")).unwrap();
            let known = KnownHosts::new(&path);
            assert_eq!(known.verdict("n1", "ssh-rsa", KEY), Ok(Verdict::Revoked), "{hosts}");
            assert_eq!(known.verdict("n1", "ssh-rsa", OTHER_KEY), Ok(Verdict::Differs), "{hosts}");
        }
        fs::write(&path, format!("@revoked other ssh-rsa {KEY}\n")).unwrap();
        assert_eq!(KnownHosts::new(&path).verdict("n1", "ssh-rsa", KEY), Ok(Verdict::Unknown));
    }

    #[test]
    fn known_hosts_location() {
        assert_eq!(
            known_hosts_file(&environ(&[("SWITCH_KNOWN_HOSTS", "/etc/sync/known_hosts")]), Path::new("/h")),
            Path::new("/etc/sync/known_hosts")
        );
        assert_eq!(
            known_hosts_file(&environ(&[("XDG_STATE_HOME", "/s")]), Path::new("/h")),
            Path::new("/s/netbox-omnisync/known_hosts")
        );
        assert_eq!(
            known_hosts_file(&environ(&[]), Path::new("/h")),
            Path::new("/h/.local/state/netbox-omnisync/known_hosts")
        );
    }

    #[test]
    fn an_empty_variable_is_not_a_location() {
        assert_eq!(
            known_hosts_file(&environ(&[("SWITCH_KNOWN_HOSTS", ""), ("XDG_STATE_HOME", "")]), Path::new("/h")),
            Path::new("/h/.local/state/netbox-omnisync/known_hosts")
        );
    }

    #[test]
    fn a_host_is_named_with_its_port_off_the_ssh_port() {
        assert_eq!(host_name("10.0.0.1", 22), "10.0.0.1");
        assert_eq!(host_name("127.0.0.1", 2222), "[127.0.0.1]:2222");
    }

    #[test]
    fn without_a_file_every_host_is_new() {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(directory.path().join("known_hosts"));
        assert_eq!(known_hosts.verdict("10.0.0.1", "ssh-rsa", KEY), Ok(Verdict::Unknown));
        assert!(!known_hosts.path().exists());
    }

    #[test]
    fn first_connection_records_the_host_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state").join("known_hosts");
        let known_hosts = KnownHosts::new(&path);
        known_hosts.record("10.0.0.1", "ssh-rsa", KEY).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "10.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDKEYOFSWITCHONE\n"
        );
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn known_host_is_checked_strictly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        fs::write(&path, format!("10.0.0.1 ssh-rsa {KEY}\n")).unwrap();
        let known_hosts = KnownHosts::new(&path);
        assert_eq!(known_hosts.verdict("10.0.0.1", "ssh-rsa", KEY), Ok(Verdict::Same));
        assert_eq!(known_hosts.verdict("10.0.0.1", "ssh-rsa", OTHER_KEY), Ok(Verdict::Differs));
        assert_eq!(known_hosts.verdict("10.0.0.2", "ssh-rsa", KEY), Ok(Verdict::Unknown));
    }

    #[test]
    fn a_recorded_host_presenting_another_key_type_differs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        fs::write(&path, format!("10.0.0.1 ssh-rsa {KEY}\n")).unwrap();
        assert_eq!(KnownHosts::new(&path).verdict("10.0.0.1", "ssh-ed25519", KEY), Ok(Verdict::Differs));
    }

    #[test]
    fn a_line_names_several_hosts_and_may_end_with_a_comment() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        fs::write(&path, format!("nexus01.lab01,10.0.0.1 ssh-rsa {KEY} recorded by hand\n")).unwrap();
        let known_hosts = KnownHosts::new(&path);
        assert_eq!(known_hosts.verdict("10.0.0.1", "ssh-rsa", KEY), Ok(Verdict::Same));
        assert_eq!(known_hosts.verdict("nexus01.lab01", "ssh-rsa", OTHER_KEY), Ok(Verdict::Differs));
        assert_eq!(known_hosts.verdict("nexus01", "ssh-rsa", KEY), Ok(Verdict::Unknown));
    }

    #[test]
    fn comments_markers_and_short_lines_record_no_host() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let text = format!("# 10.0.0.1 ssh-rsa {KEY}\n\n@revoked 10.0.0.1 ssh-rsa {KEY}\n10.0.0.1 ssh-rsa\n");
        fs::write(&path, text).unwrap();
        // A marker line records no host: another key is a first connection.
        // The revoked key itself is refused (`a_key_a_revoked_line_names_is_refused`).
        assert_eq!(KnownHosts::new(&path).verdict("10.0.0.1", "ssh-rsa", OTHER_KEY), Ok(Verdict::Unknown));
    }

    #[test]
    fn recording_keeps_the_other_lines_as_they_are() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        fs::write(&path, format!("# switches of lab01\n10.0.0.1 ssh-rsa {KEY} nexus01")).unwrap();
        KnownHosts::new(&path).record("10.0.0.2", "ssh-rsa", OTHER_KEY).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# switches of lab01\n\
             10.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDKEYOFSWITCHONE nexus01\n\
             10.0.0.2 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDKEYOFSWITCHTWO\n"
        );
    }

    #[test]
    fn recording_again_replaces_the_key_of_that_host_and_type() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        fs::write(&path, format!("10.0.0.1 ssh-rsa {KEY}\n10.0.0.2 ssh-rsa {KEY}\n")).unwrap();
        let known_hosts = KnownHosts::new(&path);
        known_hosts.record("10.0.0.1", "ssh-rsa", OTHER_KEY).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "10.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDKEYOFSWITCHTWO\n\
             10.0.0.2 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDKEYOFSWITCHONE\n"
        );
        assert_eq!(known_hosts.verdict("10.0.0.1", "ssh-rsa", OTHER_KEY), Ok(Verdict::Same));
    }

    #[test]
    fn the_rewritten_file_is_private_and_alone_in_its_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        KnownHosts::new(&path).record("10.0.0.1", "ssh-rsa", KEY).unwrap();
        assert_eq!(mode(&path), 0o600);
        let names: Vec<String> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["known_hosts"]);
    }

    #[test]
    fn switches_recorded_at_once_keep_all_their_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let hosts: Vec<String> = (1..=16).map(|number| format!("10.0.0.{number}")).collect();
        // Every thread is ready before any records its key: each must add to
        // the file, not overwrite it with what it read before.
        let barrier = Arc::new(Barrier::new(hosts.len()));
        let threads: Vec<_> = hosts
            .iter()
            .map(|host| {
                let (host, path, barrier) = (host.clone(), path.clone(), Arc::clone(&barrier));
                thread::spawn(move || {
                    let known_hosts = KnownHosts::new(path);
                    barrier.wait();
                    known_hosts.record(&host, "ssh-rsa", &format!("{KEY}{host}"))
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), Ok(()));
        }
        let known_hosts = KnownHosts::new(&path);
        for host in &hosts {
            assert_eq!(known_hosts.verdict(host, "ssh-rsa", &format!("{KEY}{host}")), Ok(Verdict::Same), "{host}");
        }
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 16);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_naming_it() {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = KnownHosts::new(directory.path());
        let error = known_hosts.verdict("10.0.0.1", "ssh-rsa", KEY).unwrap_err();
        assert_eq!(error.path, directory.path());
        assert!(
            error.to_string().starts_with(&format!("known hosts file {}: ", directory.path().display())),
            "{error}"
        );
        assert!(known_hosts.record("10.0.0.1", "ssh-rsa", KEY).is_err());
    }
}
