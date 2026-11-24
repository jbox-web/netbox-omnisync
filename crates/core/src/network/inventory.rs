//! Versioned configuration: NetBox URL, SSH settings, switches, routers and firewalls.
//!
//! Secrets (NetBox token, switch passwords) come from the environment only. One
//! the environment does not hold is not an error of the load: it is kept as
//! [`Wanted::Missing`], with the name of its variable, and only the run that
//! selects its source needs it. A
//! `nipper` switch is read from its configuration report instead of over SSH: it
//! needs neither a host nor SSH settings. A `fortios` firewall, of kind
//! `firewall`, is read through its REST API: it needs a host and the fingerprint
//! of its certificate, no SSH settings.
//!
//! The file is TOML. Every device is an entry of `[[sources]]` with its `kind`;
//! the `hypervisor` and `bmc` entries are loaded by another module and skipped here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use toml::{Table, Value};

pub const TYPES: [&str; 4] = ["nxos", "ios", "nipper", "fortios"];
/// Read from a configuration report file, not over SSH.
pub const REPORT_TYPES: [&str; 1] = ["nipper"];
/// Read through the device's REST API, not over SSH.
pub const API_TYPES: [&str; 1] = ["fortios"];
pub const AUTH_MODES: [&str; 3] = ["agent", "key", "password"];
/// Environment variables overriding the common ssh block of the file.
pub const SSH_ENV: [(&str, &str); 3] =
    [("username", "SWITCH_USERNAME"), ("auth", "SWITCH_SSH_AUTH"), ("key_file", "SWITCH_KEY_FILE")];

/// The environment the secrets and the overrides are read from, handed in by the caller.
pub type Environ = BTreeMap<String, String>;

/// The inventory or the environment is incomplete: nothing is contacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InventoryError(pub String);

/// A token or a password: readable through `expose` only, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: &str) -> Self {
        Secret(value.to_owned())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

/// The secrets a run needs and the environment does not hold, by the name of
/// their variable: sorted, each once. Never a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("missing environment variables: {}", .0.join(", "))]
pub struct MissingVariables(pub Vec<String>);

impl MissingVariables {
    /// `None` when `variables` is empty: nothing is missing.
    pub fn of(variables: impl IntoIterator<Item = String>) -> Option<Self> {
        let mut variables: Vec<String> = variables.into_iter().collect();
        variables.sort();
        variables.dedup();
        if variables.is_empty() { None } else { Some(MissingVariables(variables)) }
    }
}

/// What the environment is asked for to read a source or to write to NetBox.
///
/// The same file is loaded on every host, and each host only holds the secrets
/// of the sources it launches: a secret that is not there is not an error of
/// the load. It is not an empty value either: what is missing can only be
/// told apart, by the name of its variables, never read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted<T> {
    /// The environment holds it.
    Held(T),
    /// The environment does not: the variables to set, as an error names them
    /// (`A`, `A or B`, `A (or B and C)`).
    Missing(Vec<String>),
}

impl<T> Wanted<T> {
    /// The value, or the refusal that names the variables to set: the only way to read it.
    pub fn held(&self) -> Result<&T, MissingVariables> {
        match self {
            Wanted::Held(value) => Ok(value),
            Wanted::Missing(variables) => {
                let mut variables = variables.clone();
                variables.sort();
                variables.dedup();
                Err(MissingVariables(variables))
            }
        }
    }

    /// The variables to set; none when the value is held.
    pub fn missing(&self) -> &[String] {
        match self {
            Wanted::Held(_) => &[],
            Wanted::Missing(variables) => variables,
        }
    }
}

/// What a source is in NetBox terms; a `hypervisor` or `bmc` entry is not a network source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Switch,
    Router,
    Firewall,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Switch => "switch",
            Kind::Router => "router",
            Kind::Firewall => "firewall",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Source {
    /// NetBox device name, or for a stack the host name it announces to its neighbours.
    pub name: String,
    pub kind: Kind,
    pub host: String,
    /// One of `TYPES`: how the device is read.
    pub r#type: String,
    /// NetBox virtual chassis name, for a stack only.
    pub virtual_chassis: Option<String>,
    /// Empty for a firewall whose account the environment does not hold:
    /// `password` is then missing, and says so.
    pub username: String,
    /// Exactly one authentication mode is set: password, key file, or SSH agent.
    /// A password the environment does not hold is still the mode of the
    /// source, and names its variables: only a run that selects the source
    /// needs it.
    pub password: Option<Wanted<Secret>>,
    pub key_file: Option<PathBuf>,
    pub use_agent: bool,
    /// Handed to the SSH client as is, e.g. {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]}.
    pub disabled_algorithms: Option<BTreeMap<String, Vec<String>>>,
    /// nipper only: the report file.
    pub report: Option<PathBuf>,
    /// How port descriptions name the neighbours (named groups `host` and optional
    /// `port`, `neighbor_suffix` appended to the host): the only cable source of a
    /// nipper switch, a complement to LLDP and CDP on an SSH one.
    pub neighbor_pattern: Option<Regex>,
    pub neighbor_suffix: String,
    /// API types only: SHA-256 of the certificate the API must present, as 64
    /// lower-case hexadecimal digits.
    pub tls_fingerprint: Option<String>,
    /// fortios only: host name of each HA cluster member -> its NetBox device, in
    /// the order of the file.
    pub ha_peers: Vec<(String, String)>,
    /// fortios only: interfaces left out of the sync, by their exact name.
    pub ignore_interfaces: Vec<String>,
    /// API types only: port of the API, None for the default HTTPS one.
    pub port: Option<u16>,
}

impl Source {
    /// A source with no credentials and every optional setting left out.
    pub fn new(name: &str, kind: Kind, r#type: &str, host: &str) -> Self {
        Source {
            name: name.to_owned(),
            kind,
            host: host.to_owned(),
            r#type: r#type.to_owned(),
            virtual_chassis: None,
            username: String::new(),
            password: None,
            key_file: None,
            use_agent: false,
            disabled_algorithms: None,
            report: None,
            neighbor_pattern: None,
            neighbor_suffix: String::new(),
            tls_fingerprint: None,
            ha_peers: Vec::new(),
            ignore_interfaces: Vec::new(),
            port: None,
        }
    }

    /// The variables this source needs and the environment does not hold.
    pub fn missing(&self) -> &[String] {
        self.password.as_ref().map_or(&[], Wanted::missing)
    }
}

#[derive(Debug, Clone)]
pub struct Inventory {
    /// The switches, routers and firewalls, in the order of the file.
    pub sources: Vec<Source>,
    pub domains: Vec<String>,
    pub netbox_url: String,
    /// Needed by every run, whatever it selects.
    pub netbox_token: Wanted<Secret>,
    /// Name announced by a neighbour (LLDP/CDP) -> NetBox device name.
    pub aliases: BTreeMap<String, String>,
}

impl Inventory {
    /// The variables a run of the sources `selected` lets through needs and the
    /// environment does not hold: the NetBox token, always, and the secrets
    /// of those sources. A password shared by the switches is only missing
    /// for a run that selects a switch that needs it.
    pub fn missing(&self, selected: impl Fn(&Source) -> bool) -> Vec<String> {
        let sources = self.sources.iter().filter(|source| selected(source)).flat_map(|source| source.missing());
        self.netbox_token.missing().iter().chain(sources).cloned().collect()
    }
}

/// `SWITCH_<NAME>` for a switch, `FIREWALL_<NAME>` for a firewall.
pub fn env_prefix(name: &str, kind: &str) -> String {
    let name: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
    format!("{}_{name}", kind.to_uppercase())
}

fn fail<T>(message: String) -> Result<T, InventoryError> {
    Err(InventoryError(message))
}

/// A scalar of the file as text: a name or a host written as a number is still a name.
fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// A value as the errors quote it: text between single quotes, `None` when absent.
fn quoted(value: Option<&Value>) -> String {
    match value {
        None => "None".to_owned(),
        Some(Value::String(text)) => format!("'{text}'"),
        Some(other) => other.to_string(),
    }
}

/// A key that is absent or set to an empty string is missing.
fn blank(value: Option<&Value>) -> bool {
    match value {
        None => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(_) => false,
    }
}

/// A value that is set to something: neither absent, empty, zero nor false.
fn set(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Integer(number)) => *number != 0,
        Some(Value::Float(number)) => *number != 0.0,
        Some(Value::Boolean(flag)) => *flag,
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Table(table)) => !table.is_empty(),
        Some(Value::Datetime(_)) => true,
    }
}

/// The value of a variable of the environment, None when unset or empty.
fn variable<'e>(environ: &'e Environ, name: &str) -> Option<&'e str> {
    environ.get(name).map(String::as_str).filter(|value| !value.is_empty())
}

/// A secret of the environment; a variable that is unset or empty is missing, by its name.
fn secret(environ: &Environ, name: &str) -> Wanted<Secret> {
    match variable(environ, name) {
        Some(value) => Wanted::Held(Secret::new(value)),
        None => Wanted::Missing(vec![name.to_owned()]),
    }
}

/// Replace a leading `~` by the `HOME` of the environment handed in.
pub fn expand_user(path: &str, environ: &Environ) -> Result<PathBuf, InventoryError> {
    let Some(rest) = path.strip_prefix('~') else {
        return Ok(PathBuf::from(path));
    };
    // `~user/…` is the home of another user: never a relative path.
    if !(rest.is_empty() || rest.starts_with('/')) {
        let user = rest.split('/').next().unwrap_or(rest);
        return fail(format!("cannot expand {path}: ~{user} is the home of another user, write the path in full"));
    }
    match variable(environ, "HOME") {
        Some(home) => Ok(Path::new(home).join(rest.trim_start_matches('/'))),
        None => fail(format!("cannot expand {path}: HOME is not set")),
    }
}

/// The kind of an entry and its table once the required keys are checked; None
/// for a `hypervisor` or `bmc` entry, which another module loads.
fn check_entry<'v>(path: &Path, number: usize, entry: &'v Value) -> Result<Option<(Kind, &'v Table)>, InventoryError> {
    let mut location = format!("{}: source entry {number}", path.display());
    let Value::Table(entry) = entry else {
        return fail(format!("{location} must be a mapping"));
    };
    if let Some(name) = entry.get("name") {
        location = format!("{location} ({})", text(name));
    }
    if blank(entry.get("kind")) {
        return fail(format!("{location}: missing kind"));
    }
    let kind = match entry.get("kind") {
        Some(Value::String(kind)) if kind == "switch" => Kind::Switch,
        Some(Value::String(kind)) if kind == "router" => Kind::Router,
        Some(Value::String(kind)) if kind == "firewall" => Kind::Firewall,
        Some(Value::String(kind)) if kind == "hypervisor" || kind == "bmc" => return Ok(None),
        other => return fail(format!("{location}: unsupported kind {}", quoted(other))),
    };
    let report = matches!(entry.get("type"), Some(Value::String(r#type)) if REPORT_TYPES.contains(&r#type.as_str()));
    for key in ["name", "type", if report { "report" } else { "host" }] {
        if blank(entry.get(key)) {
            return fail(format!("{location}: missing {key}"));
        }
    }
    Ok(Some((kind, entry)))
}

fn neighbor_pattern(name: &str, value: Option<&Value>) -> Result<Option<Regex>, InventoryError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let pattern = match Regex::new(&text(value)) {
        Ok(pattern) => pattern,
        Err(error) => return fail(format!("{name}: neighbor_pattern is not a valid regular expression: {error}")),
    };
    if !pattern.capture_names().flatten().any(|group| group == "host") {
        return fail(format!("{name}: neighbor_pattern needs a named group 'host'"));
    }
    Ok(Some(pattern))
}

/// The keys of every network entry. `runner`, the host that launches the
/// source, is read with those of every other kind of entry by the command.
const ENTRY_KEYS: [&str; 4] = ["name", "kind", "type", "runner"];
/// The keys an `ssh` block takes, the common one or that of a source.
const SSH_BLOCK_KEYS: [&str; 4] = ["username", "auth", "key_file", "disabled_algorithms"];
/// The keys of a switch or router read over SSH.
const SSH_KEYS: [&str; 5] = ["host", "ssh", "virtual_chassis", "neighbor_pattern", "neighbor_suffix"];
/// The keys of a switch read from a report.
const REPORT_KEYS: [&str; 5] = ["report", "host", "virtual_chassis", "neighbor_pattern", "neighbor_suffix"];
/// The keys of a firewall read over its API.
const API_KEYS: [&str; 5] = ["host", "port", "tls_fingerprint", "ha_peers", "ignore_interfaces"];

/// The text of an optional key, empty when the key is absent.
fn optional_text(entry: &Table, key: &str) -> String {
    entry.get(key).map(text).unwrap_or_default()
}

fn report_source(
    path: &Path,
    kind: Kind,
    name: &str,
    entry: &Table,
    environ: &Environ,
) -> Result<Source, InventoryError> {
    // A relative report path is relative to the configuration file.
    let report = expand_user(&optional_text(entry, "report"), environ)?;
    let report = match path.parent() {
        Some(directory) if !report.is_absolute() => directory.join(report),
        _ => report,
    };
    Ok(Source {
        virtual_chassis: entry.get("virtual_chassis").map(text),
        report: Some(report),
        neighbor_pattern: neighbor_pattern(name, entry.get("neighbor_pattern"))?,
        neighbor_suffix: optional_text(entry, "neighbor_suffix"),
        ..Source::new(name, kind, &optional_text(entry, "type"), &optional_text(entry, "host"))
    })
}

fn fingerprint(name: &str, value: &str) -> Result<String, InventoryError> {
    // `openssl x509 -fingerprint -sha256` prints upper-case pairs joined by colons.
    let digits = value.replace(':', "").to_lowercase();
    if digits.len() != 64 || !digits.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return fail(format!(
            "{name}: tls_fingerprint must be the SHA-256 of the certificate (64 hexadecimal digits, colons allowed)"
        ));
    }
    Ok(digits)
}

/// A table whose values are all non-empty names, as ordered pairs; None otherwise.
fn names_by_key(value: &Value) -> Option<Vec<(String, String)>> {
    let Value::Table(table) = value else {
        return None;
    };
    table
        .iter()
        .map(|(key, value)| match value {
            Value::String(name) if !name.is_empty() => Some((key.clone(), name.clone())),
            _ => None,
        })
        .collect()
}

fn ha_peers(name: &str, value: Option<&Value>) -> Result<Vec<(String, String)>, InventoryError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(peers) = names_by_key(value) else {
        return fail(format!("{name}: ha_peers must map the host name of a cluster member to a Netbox device name"));
    };
    // Host names are matched without case: two such names would be one member.
    let mut hosts: Vec<&str> = peers.iter().map(|(host, _)| host.as_str()).collect();
    hosts.sort_by_key(|host| host.to_lowercase());
    for pair in hosts.windows(2) {
        if pair[0].to_lowercase() == pair[1].to_lowercase() {
            return fail(format!("{name}: ha_peers names {} and {} differ by case only", pair[0], pair[1]));
        }
    }
    Ok(peers)
}

fn ignore_interfaces(name: &str, value: Option<&Value>) -> Result<Vec<String>, InventoryError> {
    let names = match value {
        None => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|item| item.as_str().map(str::to_owned)).collect(),
        Some(_) => None,
    };
    names.ok_or_else(|| InventoryError(format!("{name}: ignore_interfaces must be a list of interface names")))
}

fn port(name: &str, value: Option<&Value>) -> Result<Option<u16>, InventoryError> {
    match value {
        None => Ok(None),
        Some(Value::Integer(number)) if (1..=65535).contains(number) => Ok(u16::try_from(*number).ok()),
        Some(_) => fail(format!("{name}: port must be a number from 1 to 65535")),
    }
}

fn api_source(name: &str, entry: &Table, environ: &Environ) -> Result<Source, InventoryError> {
    if blank(entry.get("tls_fingerprint")) {
        return fail(format!("{name}: missing tls_fingerprint"));
    }
    // Its own account, never the one shared by the switches: a missing variable
    // must not send the SSH credentials to the firewall.
    let prefix = env_prefix(name, "firewall");
    let ha_peers = ha_peers(name, entry.get("ha_peers"))?;
    // The interfaces of the cluster are synced onto the entry: it is one of the members.
    for (_, device) in &ha_peers {
        // Each member is its own Netbox device: two on one would fight over its serial.
        if ha_peers.iter().filter(|(_, other)| other == device).count() > 1 {
            return fail(format!("{name}: ha_peers maps two members to {device}"));
        }
    }
    if !ha_peers.is_empty() && !ha_peers.iter().any(|(_, device)| device == name) {
        return fail(format!("{name}: ha_peers must name {name} as the device of one member"));
    }
    let (user_variable, password_variable) = (format!("{prefix}_USERNAME"), format!("{prefix}_PASSWORD"));
    // Half an account is none: without its user the password is not kept,
    // so that nothing can log in with an empty user name.
    let (username, password) = match (variable(environ, &user_variable), secret(environ, &password_variable)) {
        (Some(username), password) => (username.to_owned(), password),
        (None, password) => {
            let mut variables = vec![user_variable];
            variables.extend_from_slice(password.missing());
            (String::new(), Wanted::Missing(variables))
        }
    };
    Ok(Source {
        username,
        password: Some(password),
        tls_fingerprint: Some(fingerprint(name, &optional_text(entry, "tls_fingerprint"))?),
        ha_peers,
        ignore_interfaces: ignore_interfaces(name, entry.get("ignore_interfaces"))?,
        port: port(name, entry.get("port"))?,
        ..Source::new(name, Kind::Firewall, &optional_text(entry, "type"), &optional_text(entry, "host"))
    })
}

/// Merge an `ssh` block over `base`, the settings it overrides.
fn ssh_settings(path: &Path, location: &str, block: Option<&Value>, base: &Table) -> Result<Table, InventoryError> {
    match block {
        None => Ok(base.clone()),
        Some(Value::Table(block)) => {
            let mut merged = base.clone();
            merged.extend(block.iter().map(|(key, value)| (key.clone(), value.clone())));
            Ok(merged)
        }
        Some(_) => fail(format!("{}: {location}ssh must be a mapping", path.display())),
    }
}

/// The `disabled_algorithms` of an ssh block: a kind -> a list of algorithm names; None if malformed.
fn disabled_algorithms(value: &Value) -> Option<BTreeMap<String, Vec<String>>> {
    let Value::Table(kinds) = value else {
        return None;
    };
    kinds
        .iter()
        .map(|(kind, algorithms)| {
            // A misspelt kind would disable nothing, without a word.
            if !ALGORITHM_KINDS.contains(&kind.as_str()) {
                return None;
            }
            let names: Option<Vec<String>> =
                algorithms.as_array()?.iter().map(|algorithm| algorithm.as_str().map(str::to_owned)).collect();
            Some((kind.clone(), names?))
        })
        .collect()
}

/// The kinds `disabled_algorithms` takes.
const ALGORITHM_KINDS: [&str; 5] = ["pubkeys", "macs", "kex", "ciphers", "keys"];
/// How an RSA key signs, the names `pubkeys` takes.
const RSA_SIGNATURES: [&str; 3] = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"];

/// The authentication mode of checked ssh settings, with the algorithms they disable.
pub type CheckedSsh<'s> = (&'s str, Option<BTreeMap<String, Vec<String>>>);

fn check_ssh<'s>(path: &Path, location: &str, ssh: &'s Table) -> Result<CheckedSsh<'s>, InventoryError> {
    ssh_block(ssh).map_err(|problem| InventoryError(format!("{}: {location}{problem}", path.display())))
}

/// The authentication mode of an ssh block and the algorithms it disables,
/// or what is wrong with it, without the place of the block: the caller says it.
pub fn ssh_block(ssh: &Table) -> Result<CheckedSsh<'_>, String> {
    if let Some(key) = ssh.keys().find(|key| !SSH_BLOCK_KEYS.contains(&key.as_str())) {
        return Err(format!("unknown key ssh.{key} ({})", SSH_BLOCK_KEYS.join(", ")));
    }
    if !set(ssh.get("username")) {
        return Err("ssh.username is missing".to_owned());
    }
    let auth = match ssh.get("auth") {
        Some(Value::String(auth)) if AUTH_MODES.contains(&auth.as_str()) => auth.as_str(),
        other => {
            return Err(format!("ssh.auth must be one of {} (got {})", AUTH_MODES.join(", "), quoted(other)));
        }
    };
    if auth == "key" && !set(ssh.get("key_file")) {
        return Err("ssh.key_file is missing (ssh.auth is key)".to_owned());
    }
    let disabled = match ssh.get("disabled_algorithms") {
        None => None,
        Some(value) => match disabled_algorithms(value) {
            Some(disabled) => Some(disabled),
            None => {
                return Err("ssh.disabled_algorithms must map a kind (pubkeys, macs, kex, ciphers, keys) \
                            to a list of algorithm names"
                    .to_owned());
            }
        },
    };
    let pubkeys = disabled.as_ref().and_then(|kinds| kinds.get("pubkeys")).map_or(&[][..], Vec::as_slice);
    if let Some(unknown) = pubkeys.iter().find(|name| !RSA_SIGNATURES.contains(&name.as_str())) {
        return Err(format!(
            "ssh.disabled_algorithms: unknown pubkeys algorithm {unknown} ({})",
            RSA_SIGNATURES.join(", ")
        ));
    }
    if RSA_SIGNATURES.iter().all(|signature| pubkeys.iter().any(|name| name == signature)) {
        return Err("ssh.disabled_algorithms disables every RSA signature: an RSA key could not sign".to_owned());
    }
    Ok((auth, disabled))
}

fn aliases(path: &Path, value: Option<&Value>) -> Result<BTreeMap<String, String>, InventoryError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    match names_by_key(value) {
        Some(aliases) => Ok(aliases.into_iter().collect()),
        None => {
            fail(format!("{}: aliases must map an announced neighbour name to a Netbox device name", path.display()))
        }
    }
}

/// Read the inventory file at `path`; see `parse_inventory`.
pub fn load_inventory(path: &Path, environ: &Environ) -> Result<Inventory, InventoryError> {
    match fs::read_to_string(path) {
        Ok(text) => parse_inventory(path, &text, environ),
        Err(error) => fail(format!("{}: cannot read the file: {error}", path.display())),
    }
}

/// Build the inventory from the `text` of the file at `path`, which only serves
/// to name the file in the errors and to resolve the relative report paths.
///
/// A secret the environment does not hold is not refused here: the source is
/// loaded and checked like any other, and carries the name of what it misses
/// ([`Source::missing`], [`Inventory::missing`]).
pub fn parse_inventory(path: &Path, text_of_file: &str, environ: &Environ) -> Result<Inventory, InventoryError> {
    let file = path.display();
    let data: Table = match text_of_file.parse() {
        Ok(data) => data,
        Err(error) => return fail(format!("{file}: not valid TOML: {error}")),
    };
    // Each device with its kind, in the order of the file.
    let entries: &[Value] = match data.get("sources") {
        Some(Value::Array(entries)) => entries,
        listed if set(listed) => return fail(format!("{file}: sources must be a list")),
        _ => &[],
    };
    let mut common_ssh = ssh_settings(path, "", data.get("ssh"), &Table::new())?;
    // The environment overrides the common block; a switch's own block still wins.
    for (key, name) in SSH_ENV {
        if let Some(value) = variable(environ, name) {
            common_ssh.insert(key.to_owned(), Value::String(value.to_owned()));
        }
    }
    if let Some(auth) = variable(environ, "SWITCH_SSH_AUTH")
        && !AUTH_MODES.contains(&auth)
    {
        return fail(format!("SWITCH_SSH_AUTH must be one of {} (got '{auth}')", AUTH_MODES.join(", ")));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut prefixes: BTreeMap<String, String> = BTreeMap::new();
    let mut sources: Vec<Source> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some((kind, entry)) = check_entry(path, index + 1, entry)? else {
            continue;
        };
        let name = optional_text(entry, "name");
        // NetBox reads a device name caselessly: two such entries are one device.
        if !seen.insert(name.to_lowercase()) {
            return fail(format!("duplicate device name {name}"));
        }
        // The variables of a source are named from its name, folded: two names
        // that fold alike would read each other's password.
        let variables = env_prefix(&name, "");
        if let Some(other) = prefixes.get(&variables) {
            return fail(format!("{name}: its variables are named as those of {other}"));
        }
        prefixes.insert(variables, name.clone());
        let r#type = optional_text(entry, "type");
        if !TYPES.contains(&r#type.as_str()) {
            return fail(format!("{name}: unsupported type {}", quoted(entry.get("type"))));
        }
        // A firewall has its own account and no SSH settings: its kind says so.
        let api = API_TYPES.contains(&r#type.as_str());
        if api != (kind == Kind::Firewall) {
            let expected = if api { "firewall" } else { "switch or router" };
            return fail(format!("{name}: a {type} source must be of kind {expected}"));
        }
        // As for a hypervisor entry, a key the entry does not take is refused:
        // ignored, a misspelt `ignore_interfaces` would leave its interface to the prune.
        let report = REPORT_TYPES.contains(&r#type.as_str());
        let taken: &[&str] = if report {
            &REPORT_KEYS
        } else if api {
            &API_KEYS
        } else {
            &SSH_KEYS
        };
        if let Some(key) =
            entry.keys().find(|key| !ENTRY_KEYS.contains(&key.as_str()) && !taken.contains(&key.as_str()))
        {
            return fail(format!("{name}: unknown key {key} for a {type} source"));
        }
        if report {
            sources.push(report_source(path, kind, &name, entry, environ)?);
            continue;
        }
        if api {
            sources.push(api_source(&name, entry, environ)?);
            continue;
        }
        // The switch's own ssh block overrides the common one, key by key.
        let own = entry.get("ssh");
        let location = format!("{name}: ");
        let ssh = ssh_settings(path, &location, own, &common_ssh)?;
        let (auth, disabled_algorithms) = check_ssh(path, if own.is_none() { "" } else { &location }, &ssh)?;
        let mut password = None;
        if auth == "password" {
            let prefix = env_prefix(&name, "switch");
            // Per-switch variable first, then the one shared by every switch.
            let own_variable = format!("{prefix}_PASSWORD");
            password = Some(match variable(environ, &own_variable).or_else(|| variable(environ, "SWITCH_PASSWORD")) {
                Some(value) => Wanted::Held(Secret::new(value)),
                None => Wanted::Missing(vec![format!("{own_variable} or SWITCH_PASSWORD")]),
            });
        }
        sources.push(Source {
            virtual_chassis: entry.get("virtual_chassis").map(text),
            username: optional_text(&ssh, "username"),
            password,
            key_file: if auth == "key" { Some(expand_user(&optional_text(&ssh, "key_file"), environ)?) } else { None },
            use_agent: auth == "agent",
            disabled_algorithms,
            // Descriptions complete LLDP and CDP on the ports they leave silent.
            neighbor_pattern: neighbor_pattern(&name, entry.get("neighbor_pattern"))?,
            neighbor_suffix: optional_text(entry, "neighbor_suffix"),
            ..Source::new(&name, kind, &r#type, &optional_text(entry, "host"))
        });
    }
    // The URL is not a secret: it lives in the file, NETBOX_URL overriding it.
    let netbox = match data.get("netbox") {
        Some(Value::Table(netbox)) => Some(netbox),
        block if set(block) => return fail(format!("{file}: netbox must be a mapping")),
        _ => None,
    };
    let from_file = netbox.and_then(|netbox| netbox.get("url")).filter(|url| set(Some(url))).map(text);
    let Some(netbox_url) = variable(environ, "NETBOX_URL").map(str::to_owned).or(from_file) else {
        return fail(format!("{file}: netbox.url is missing (or set NETBOX_URL)"));
    };
    let netbox_token = secret(environ, "NETBOX_TOKEN");
    let domains = match data.get("domains") {
        Some(Value::Array(domains)) => domains.iter().map(text).collect(),
        listed if set(listed) => return fail(format!("{file}: domains must be a list")),
        _ => Vec::new(),
    };
    Ok(Inventory { sources, domains, netbox_url, netbox_token, aliases: aliases(path, data.get("aliases"))? })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "/etc/omnisync/config.toml";

    const TOML: &str = r#"
domains = ["switch.example.com"]

[ssh]
username = "sync"
auth = "password"

[netbox]
url = "https://netbox.example"

[[sources]]
name = "nexus01.lab01"
kind = "switch"
host = "192.0.2.239"
type = "nxos"

[[sources]]
name = "2960-stack.lab01"
kind = "switch"
host = "192.0.2.252"
type = "ios"
virtual_chassis = "2960-stack"
"#;

    const SSH_BLOCK: &str = "[ssh]\nusername = \"sync\"\nauth = \"password\"\n";
    const NETBOX_BLOCK: &str = "[netbox]\nurl = \"https://netbox.example\"\n";
    const CHASSIS_LINE: &str = "virtual_chassis = \"2960-stack\"\n";

    const ENV: [(&str, &str); 3] = [
        ("NETBOX_TOKEN", "token-value"),
        ("SWITCH_NEXUS01_LAB01_PASSWORD", "pw-nexus"),
        ("SWITCH_2960_STACK_LAB01_PASSWORD", "pw-stack"),
    ];
    const NETBOX_ONLY: [(&str, &str); 1] = [("NETBOX_TOKEN", "token-value")];

    fn env(pairs: &[(&str, &str)]) -> Environ {
        pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    /// `text` with `old` replaced by `new`; fails if `old` is not there to replace.
    fn swap(text: &str, old: &str, new: &str) -> String {
        assert!(text.contains(old), "{old:?} is not in the text");
        text.replace(old, new)
    }

    fn ssh(block: &str) -> String {
        swap(TOML, SSH_BLOCK, block)
    }

    fn load(text: &str, environ: &[(&str, &str)]) -> Inventory {
        parse_inventory(Path::new(CONFIG), text, &env(environ)).unwrap()
    }

    fn error(text: &str, environ: &[(&str, &str)]) -> String {
        parse_inventory(Path::new(CONFIG), text, &env(environ)).unwrap_err().to_string()
    }

    fn two(inventory: Inventory) -> (Source, Source) {
        let [first, second]: [Source; 2] = inventory.sources.try_into().unwrap();
        (first, second)
    }

    fn one(inventory: Inventory) -> Source {
        let [only]: [Source; 1] = inventory.sources.try_into().unwrap();
        only
    }

    /// The password the source holds; None when it is read without one.
    fn password(source: &Source) -> Option<&str> {
        source.password.as_ref().map(|password| password.held().unwrap().expose())
    }

    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn names(inventory: &Inventory) -> Vec<&str> {
        inventory.sources.iter().map(|source| source.name.as_str()).collect()
    }

    fn groups<'h>(source: &Source, haystack: &'h str) -> (Option<&'h str>, Option<&'h str>) {
        let captures = source.neighbor_pattern.as_ref().unwrap().captures(haystack).unwrap();
        (captures.name("host").map(|group| group.as_str()), captures.name("port").map(|group| group.as_str()))
    }

    #[test]
    fn env_prefix_upper_cases_the_name() {
        assert_eq!(env_prefix("2960-stack.lab01", "switch"), "SWITCH_2960_STACK_LAB01");
        assert_eq!(env_prefix("fw01.dc1", "firewall"), "FIREWALL_FW01_DC1");
    }

    #[test]
    fn loads_the_sources_and_their_secrets() {
        let inventory = load(TOML, &ENV);
        assert_eq!(inventory.domains, ["switch.example.com"]);
        assert_eq!(inventory.netbox_url, "https://netbox.example");
        assert_eq!(inventory.netbox_token.held().unwrap().expose(), "token-value");
        assert!(!format!("{inventory:?}").contains("token-value"));
        let (nexus, stack) = two(inventory);
        assert_eq!(
            (nexus.name.as_str(), nexus.host.as_str(), nexus.r#type.as_str(), nexus.virtual_chassis.as_deref()),
            ("nexus01.lab01", "192.0.2.239", "nxos", None)
        );
        assert_eq!((nexus.kind, stack.kind), (Kind::Switch, Kind::Switch));
        assert_eq!(stack.virtual_chassis.as_deref(), Some("2960-stack"));
        assert_eq!((nexus.username.as_str(), stack.username.as_str()), ("sync", "sync"));
        assert_eq!(password(&stack), Some("pw-stack"));
        assert!(!format!("{stack:?}").contains("pw-stack"));
    }

    #[test]
    fn a_secret_prints_as_stars() {
        assert_eq!(format!("{:?}", Secret::new("hunter2")), "***");
        let inventory = load(TOML, &ENV);
        let printed = format!("{inventory:?}");
        assert!(printed.contains("netbox_token: Held(***)"), "{printed}");
        assert!(printed.contains("password: Some(Held(***))"), "{printed}");
        for secret in ["token-value", "pw-nexus", "pw-stack"] {
            assert!(!printed.contains(secret), "{secret} is printed");
        }
        let pretty = format!("{inventory:#?}");
        for secret in ["token-value", "pw-nexus", "pw-stack"] {
            assert!(!pretty.contains(secret), "{secret} is printed");
        }
    }

    // The same file is loaded on every host: a switch whose password this
    // host does not hold is loaded, and only names the variable it misses.
    #[test]
    fn missing_secret_names_variable_only() {
        let environ: Vec<(&str, &str)> =
            ENV.into_iter().filter(|(name, _)| *name != "SWITCH_NEXUS01_LAB01_PASSWORD").collect();
        let inventory = load(TOML, &environ);
        assert_eq!(names(&inventory), ["nexus01.lab01", "2960-stack.lab01"]);
        let printed = format!("{inventory:?}");
        let (nexus, stack) = two(inventory);
        assert_eq!(nexus.missing(), ["SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD"]);
        assert_eq!(stack.missing(), [] as [&str; 0]);
        assert_eq!(password(&stack), Some("pw-stack"));
        // Still a source read with a password, and one that cannot be read.
        let failure = nexus.password.as_ref().expect("the mode of the source").held().unwrap_err();
        let message = failure.to_string();
        assert_eq!(message, "missing environment variables: SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD");
        assert!(printed.contains("Missing([\"SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD\"])"), "{printed}");
        for secret in ["pw-stack", "token-value"] {
            assert!(!message.contains(secret));
            assert!(!format!("{failure:?}").contains(secret));
            assert!(!printed.contains(secret));
        }
    }

    #[test]
    fn a_run_misses_the_token_and_the_secrets_of_the_sources_it_selects_only() {
        let nexus = "SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD";
        let stack = "SWITCH_2960_STACK_LAB01_PASSWORD or SWITCH_PASSWORD";
        // Nothing at all in the environment: the file is loaded all the same.
        let inventory = load(TOML, &[]);
        assert_eq!(inventory.missing(|_| true), ["NETBOX_TOKEN", nexus, stack]);
        assert_eq!(inventory.missing(|source| source.name == "2960-stack.lab01"), ["NETBOX_TOKEN", stack]);
        // The token is needed by a run that selects no source of this inventory.
        assert_eq!(inventory.missing(|_| false), ["NETBOX_TOKEN"]);
        assert_eq!(
            inventory.netbox_token.held().unwrap_err().to_string(),
            "missing environment variables: NETBOX_TOKEN"
        );
        // The token held, and the password of one switch.
        let inventory = load(TOML, &[ENV[0], ENV[2]]);
        assert_eq!(inventory.missing(|_| true), [nexus]);
        assert_eq!(inventory.missing(|source| source.name == "2960-stack.lab01"), [] as [&str; 0]);
    }

    // SWITCH_PASSWORD is not a secret of its own: it is missing for the
    // switches that have no other, and for nothing else.
    #[test]
    fn the_shared_password_is_missing_for_the_switches_that_need_it_only() {
        let own = "virtual_chassis = \"2960-stack\"\nssh = { auth = \"agent\" }\n";
        let text = swap(TOML, CHASSIS_LINE, own);
        let inventory = load(&text, &NETBOX_ONLY);
        assert_eq!(inventory.missing(|source| source.name == "2960-stack.lab01"), [] as [&str; 0]);
        assert_eq!(inventory.missing(|_| true), ["SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD"]);
        let inventory = load(&text, &[("NETBOX_TOKEN", "token-value"), ("SWITCH_PASSWORD", "pw-all")]);
        assert_eq!(inventory.missing(|_| true), [] as [&str; 0]);
    }

    #[test]
    fn the_variables_of_a_refusal_are_sorted_and_named_once() {
        let wanted: Wanted<Secret> = Wanted::Missing(strings(&["B_PASSWORD", "A_USERNAME", "B_PASSWORD"]));
        assert_eq!(wanted.held().unwrap_err().to_string(), "missing environment variables: A_USERNAME, B_PASSWORD");
        assert_eq!(wanted.missing(), ["B_PASSWORD", "A_USERNAME", "B_PASSWORD"]);
        let refusal = MissingVariables::of(strings(&["B (or C and D)", "A or Z", "B (or C and D)"])).unwrap();
        assert_eq!(refusal.to_string(), "missing environment variables: A or Z, B (or C and D)");
        assert_eq!(MissingVariables::of(Vec::new()), None);
        let held = Wanted::Held(Secret::new("hunter2"));
        assert_eq!(held.missing(), [] as [&str; 0]);
        assert_eq!(held.held().map(Secret::expose), Ok("hunter2"));
    }

    // A typo in the file is an error on every host, whatever secrets it holds.
    #[test]
    fn an_entry_is_checked_in_full_without_any_secret() {
        let text = swap(TOML, "type = \"nxos\"", "type = \"eos\"");
        assert_eq!(error(&text, &[]), "nexus01.lab01: unsupported type 'eos'");
        let text = swap(TOML, CHASSIS_LINE, "neighbor_pattern = \"(\"\n");
        let message = error(&text, &[]);
        assert!(
            message.starts_with("2960-stack.lab01: neighbor_pattern is not a valid regular expression: "),
            "{message}"
        );
        let text = swap(FORTIOS_TOML, "tls_fingerprint = \"AB:AB", "tls_fingerprint = \"AB");
        assert_eq!(
            error(&text, &[]),
            "fw01.dc1: tls_fingerprint must be the SHA-256 of the certificate (64 hexadecimal digits, colons allowed)"
        );
    }

    #[test]
    fn unknown_type() {
        let text = swap(TOML, "type = \"nxos\"", "type = \"eos\"");
        assert_eq!(error(&text, &ENV), "nexus01.lab01: unsupported type 'eos'");
    }

    #[test]
    fn duplicate_name() {
        let text = swap(TOML, "2960-stack.lab01", "nexus01.lab01");
        assert_eq!(error(&text, &ENV), "duplicate device name nexus01.lab01");
    }

    // NetBox reads a device name caselessly: two such entries are one device.
    #[test]
    fn a_name_that_differs_only_by_its_case_is_a_duplicate() {
        let text = swap(TOML, "2960-stack.lab01", "NEXUS01.lab01");
        assert_eq!(error(&text, &ENV), "duplicate device name NEXUS01.lab01");
    }

    // `nexus01-lab01` and `nexus01.lab01` would both read SWITCH_NEXUS01_LAB01_PASSWORD.
    #[test]
    fn two_names_that_read_the_same_variables_are_refused() {
        let text = swap(TOML, "2960-stack.lab01", "nexus01-lab01");
        assert_eq!(error(&text, &ENV), "nexus01-lab01: its variables are named as those of nexus01.lab01");
    }

    #[test]
    fn ssh_agent_needs_no_secret() {
        let text = ssh("[ssh]\nusername = \"alice\"\nauth = \"agent\"\n");
        let (nexus, stack) = two(load(&text, &NETBOX_ONLY));
        assert_eq!(
            (nexus.username.as_str(), password(&nexus), nexus.key_file.as_deref(), nexus.use_agent),
            ("alice", None, None, true)
        );
        assert_eq!((stack.username.as_str(), stack.use_agent), ("alice", true));
    }

    #[test]
    fn key_file_home_is_expanded() {
        let text = ssh("[ssh]\nusername = \"netbox-sync\"\nauth = \"key\"\nkey_file = \"~/.ssh/netbox-sync\"\n");
        let (nexus, _) = two(load(&text, &[("NETBOX_TOKEN", "token-value"), ("HOME", "/home/sync")]));
        assert_eq!(
            (nexus.key_file.as_deref(), password(&nexus), nexus.use_agent),
            (Some(Path::new("/home/sync/.ssh/netbox-sync")), None, false)
        );
    }

    #[test]
    fn home_is_needed_to_expand_a_tilde() {
        let text = ssh("[ssh]\nusername = \"netbox-sync\"\nauth = \"key\"\nkey_file = \"~/.ssh/netbox-sync\"\n");
        assert_eq!(error(&text, &NETBOX_ONLY), "cannot expand ~/.ssh/netbox-sync: HOME is not set");
    }

    #[test]
    fn source_overrides_the_common_ssh_settings() {
        let text = swap(
            &ssh("[ssh]\nusername = \"alice\"\nauth = \"agent\"\n"),
            CHASSIS_LINE,
            "virtual_chassis = \"2960-stack\"\n\
             ssh = { username = \"admin-2960\", auth = \"key\", key_file = \"/keys/2960\" }\n",
        );
        let (nexus, stack) = two(load(&text, &NETBOX_ONLY));
        assert_eq!((nexus.username.as_str(), nexus.use_agent, nexus.key_file.as_deref()), ("alice", true, None));
        assert_eq!(
            (stack.username.as_str(), stack.use_agent, stack.key_file.as_deref()),
            ("admin-2960", false, Some(Path::new("/keys/2960")))
        );
    }

    #[test]
    fn common_password_variable() {
        let environ = [
            ("NETBOX_TOKEN", "token-value"),
            ("SWITCH_PASSWORD", "pw-all"),
            ("SWITCH_2960_STACK_LAB01_PASSWORD", "pw-2960"),
        ];
        let (nexus, stack) = two(load(TOML, &environ));
        assert_eq!((password(&nexus), password(&stack)), (Some("pw-all"), Some("pw-2960")));
    }

    #[test]
    fn environment_overrides_the_common_ssh_block() {
        let environ = [("NETBOX_TOKEN", "token-value"), ("SWITCH_USERNAME", "jdoe"), ("SWITCH_SSH_AUTH", "agent")];
        let (nexus, stack) = two(load(TOML, &environ));
        assert_eq!((nexus.username.as_str(), nexus.use_agent, password(&nexus)), ("jdoe", true, None));
        assert_eq!((stack.username.as_str(), stack.use_agent), ("jdoe", true));
    }

    #[test]
    fn environment_key_file() {
        let environ =
            [("NETBOX_TOKEN", "token-value"), ("SWITCH_SSH_AUTH", "key"), ("SWITCH_KEY_FILE", "/keys/netbox-sync")];
        let (nexus, _) = two(load(TOML, &environ));
        assert_eq!(
            (nexus.username.as_str(), nexus.key_file.as_deref(), nexus.use_agent),
            ("sync", Some(Path::new("/keys/netbox-sync")), false)
        );
    }

    #[test]
    fn environment_completes_a_file_without_ssh_block() {
        let environ = [("NETBOX_TOKEN", "token-value"), ("SWITCH_USERNAME", "jdoe"), ("SWITCH_SSH_AUTH", "agent")];
        let (nexus, _) = two(load(&ssh(""), &environ));
        assert_eq!((nexus.username.as_str(), nexus.use_agent), ("jdoe", true));
    }

    // A misspelt `key_file` would leave the key out and the run would try
    // another way in: a key an ssh block does not take is refused.
    #[test]
    fn a_key_an_ssh_block_does_not_take_is_refused() {
        let text = ssh("[ssh]\nusername = \"sync\"\nauth = \"agent\"\nkeyfile = \"/keys/sync\"\n");
        assert_eq!(
            error(&text, &NETBOX_ONLY),
            "/etc/omnisync/config.toml: unknown key ssh.keyfile (username, auth, key_file, disabled_algorithms)"
        );
        let text = swap(TOML, CHASSIS_LINE, "virtual_chassis = \"2960-stack\"\nssh = { user = \"admin-2960\" }\n");
        assert_eq!(
            error(&text, &ENV),
            "/etc/omnisync/config.toml: 2960-stack.lab01: unknown key ssh.user (username, auth, key_file, \
             disabled_algorithms)"
        );
    }

    #[test]
    fn source_ssh_block_wins_over_the_environment() {
        let text = swap(TOML, CHASSIS_LINE, "virtual_chassis = \"2960-stack\"\nssh = { username = \"admin-2960\" }\n");
        let mut environ = ENV.to_vec();
        environ.push(("SWITCH_USERNAME", "jdoe"));
        let (nexus, stack) = two(load(&text, &environ));
        assert_eq!((nexus.username.as_str(), stack.username.as_str()), ("jdoe", "admin-2960"));
    }

    #[test]
    fn invalid_auth_from_the_environment_names_the_variable() {
        let mut environ = ENV.to_vec();
        environ.push(("SWITCH_SSH_AUTH", "kerberos"));
        assert_eq!(error(TOML, &environ), "SWITCH_SSH_AUTH must be one of agent, key, password (got 'kerberos')");
    }

    #[test]
    fn invalid_ssh_settings() {
        let cases = [
            ("", "/etc/omnisync/config.toml: ssh.username is missing"),
            ("[ssh]\nauth = \"agent\"\n", "/etc/omnisync/config.toml: ssh.username is missing"),
            (
                "[ssh]\nusername = \"sync\"\nauth = \"kerberos\"\n",
                "/etc/omnisync/config.toml: ssh.auth must be one of agent, key, password (got 'kerberos')",
            ),
            (
                "[ssh]\nusername = \"sync\"\n",
                "/etc/omnisync/config.toml: ssh.auth must be one of agent, key, password (got None)",
            ),
            (
                "[ssh]\nusername = \"sync\"\nauth = \"key\"\n",
                "/etc/omnisync/config.toml: ssh.key_file is missing (ssh.auth is key)",
            ),
            ("ssh = \"agent\"\n", "/etc/omnisync/config.toml: ssh must be a mapping"),
        ];
        for (block, message) in cases {
            assert_eq!(error(&ssh(block), &ENV), message, "{block:?}");
        }
    }

    #[test]
    fn invalid_ssh_settings_of_a_source_name_it() {
        let text = swap(TOML, CHASSIS_LINE, "ssh = { auth = \"kerberos\" }\n");
        assert_eq!(
            error(&text, &ENV),
            "/etc/omnisync/config.toml: 2960-stack.lab01: ssh.auth must be one of agent, key, password \
             (got 'kerberos')"
        );
        let text = swap(TOML, CHASSIS_LINE, "ssh = \"agent\"\n");
        assert_eq!(error(&text, &ENV), "/etc/omnisync/config.toml: 2960-stack.lab01: ssh must be a mapping");
    }

    #[test]
    fn netbox_url_environment_overrides_the_file() {
        let mut environ = ENV.to_vec();
        environ.push(("NETBOX_URL", "https://staging.example"));
        assert_eq!(load(TOML, &environ).netbox_url, "https://staging.example");
        let text = swap(TOML, NETBOX_BLOCK, "");
        assert_eq!(load(&text, &environ).netbox_url, "https://staging.example");
    }

    #[test]
    fn missing_netbox_url() {
        let text = swap(TOML, NETBOX_BLOCK, "");
        assert_eq!(error(&text, &ENV), "/etc/omnisync/config.toml: netbox.url is missing (or set NETBOX_URL)");
    }

    #[test]
    fn malformed_file_is_an_inventory_error() {
        let cases = [
            (
                "sources = \"nexus01\"\n[netbox]\nurl = \"https://n\"\n",
                "/etc/omnisync/config.toml: sources must be a list",
            ),
            (
                "sources = [\"nexus01\"]\n[netbox]\nurl = \"https://n\"\n",
                "/etc/omnisync/config.toml: source entry 1 must be a mapping",
            ),
            (
                "[netbox]\nurl = \"https://n\"\n[[sources]]\nname = \"nexus01.lab01\"\nkind = \"switch\"\n\
                 type = \"nxos\"\n",
                "/etc/omnisync/config.toml: source entry 1 (nexus01.lab01): missing host",
            ),
            (
                "[netbox]\nurl = \"https://n\"\n[[sources]]\nkind = \"switch\"\nhost = \"10.0.0.1\"\n",
                "/etc/omnisync/config.toml: source entry 1: missing name",
            ),
            (
                "[netbox]\nurl = \"https://n\"\n[[sources]]\nname = \"nexus01.lab01\"\nkind = \"switch\"\n\
                 host = \"10.0.0.1\"\n",
                "/etc/omnisync/config.toml: source entry 1 (nexus01.lab01): missing type",
            ),
        ];
        for (text, message) in cases {
            assert_eq!(error(text, &ENV), message, "{text:?}");
        }
    }

    #[test]
    fn invalid_toml_is_an_inventory_error() {
        let message = error("netbox = [unclosed\n", &ENV);
        assert!(message.starts_with("/etc/omnisync/config.toml: not valid TOML: "), "{message}");
    }

    #[test]
    fn an_empty_file_lacks_the_netbox_url() {
        assert_eq!(error("", &ENV), "/etc/omnisync/config.toml: netbox.url is missing (or set NETBOX_URL)");
    }

    #[test]
    fn missing_kind() {
        let text = swap(TOML, "kind = \"switch\"\nhost = \"192.0.2.239\"\n", "host = \"192.0.2.239\"\n");
        assert_eq!(error(&text, &ENV), "/etc/omnisync/config.toml: source entry 1 (nexus01.lab01): missing kind");
        let text = swap(TOML, "kind = \"switch\"\nhost = \"192.0.2.239\"\n", "kind = \"\"\nhost = \"192.0.2.239\"\n");
        assert_eq!(error(&text, &ENV), "/etc/omnisync/config.toml: source entry 1 (nexus01.lab01): missing kind");
    }

    #[test]
    fn unknown_kind() {
        let text =
            swap(TOML, "kind = \"switch\"\nhost = \"192.0.2.252\"\n", "kind = \"balancer\"\nhost = \"192.0.2.252\"\n");
        assert_eq!(
            error(&text, &ENV),
            "/etc/omnisync/config.toml: source entry 2 (2960-stack.lab01): unsupported kind 'balancer'"
        );
    }

    #[test]
    fn hypervisor_entries_are_skipped() {
        // Neither its type, its missing host nor its repeated name is looked at.
        let hypervisor = "[[sources]]\nname = \"nexus01.lab01\"\nkind = \"hypervisor\"\ntype = \"proxmox\"\n\n";
        let text = swap(
            TOML,
            "[[sources]]\nname = \"2960-stack.lab01\"\n",
            &format!("{hypervisor}[[sources]]\nname = \"2960-stack.lab01\"\n"),
        );
        let inventory = load(&text, &ENV);
        assert_eq!(names(&inventory), ["nexus01.lab01", "2960-stack.lab01"]);
        assert_eq!(inventory.sources[1].kind, Kind::Switch);
    }

    #[test]
    fn bmc_entries_are_skipped() {
        // An entry that has no host, and keys no network source has: none of it is looked at.
        let bmc = "[[sources]]\nname = \"bmc.lab01\"\nkind = \"bmc\"\ntype = \"redfish\"\n\
                   devices = [\"pve01.lab01\"]\nbmc_pattern = \"drac-{name}\"\n\n";
        let text = swap(
            TOML,
            "[[sources]]\nname = \"2960-stack.lab01\"\n",
            &format!("{bmc}[[sources]]\nname = \"2960-stack.lab01\"\n"),
        );
        let inventory = load(&text, &ENV);
        assert_eq!(names(&inventory), ["nexus01.lab01", "2960-stack.lab01"]);
        // Any other kind is still refused.
        let text = "[netbox]\nurl = \"https://n\"\n[[sources]]\nname = \"x\"\nkind = \"ipmi\"\n";
        assert_eq!(error(text, &ENV), "/etc/omnisync/config.toml: source entry 1 (x): unsupported kind 'ipmi'");
    }

    #[test]
    fn a_skipped_hypervisor_still_counts_in_the_entry_numbers() {
        let text = "[netbox]\nurl = \"https://n\"\n[[sources]]\nkind = \"hypervisor\"\n\
                    [[sources]]\nkind = \"switch\"\nhost = \"10.0.0.1\"\n";
        assert_eq!(error(text, &ENV), "/etc/omnisync/config.toml: source entry 2: missing name");
    }

    #[test]
    fn a_file_of_hypervisors_only_gives_no_source() {
        let text = "[netbox]\nurl = \"https://n\"\n[[sources]]\nname = \"pve01\"\nkind = \"hypervisor\"\n";
        assert!(load(text, &NETBOX_ONLY).sources.is_empty());
    }

    #[test]
    fn a_router_is_read_like_a_switch() {
        let text =
            swap(TOML, "kind = \"switch\"\nhost = \"192.0.2.239\"\n", "kind = \"router\"\nhost = \"192.0.2.239\"\n");
        let (router, stack) = two(load(&text, &ENV));
        assert_eq!((router.name.as_str(), router.kind, stack.kind), ("nexus01.lab01", Kind::Router, Kind::Switch));
        assert_eq!((router.username.as_str(), password(&router)), ("sync", Some("pw-nexus")));
    }

    #[test]
    fn kinds_print_as_their_configuration_value() {
        assert_eq!(Kind::Switch.as_str(), "switch");
        assert_eq!(Kind::Router.as_str(), "router");
        assert_eq!(Kind::Firewall.as_str(), "firewall");
    }

    // The Python test loads the versioned `config.example.yml`: its content is
    // translated here. The example of this repository, `config.example.toml`, is
    // loaded by `config::tests::the_example_file_loads_through_both_loaders`.
    const EXAMPLE: &str = r#"
domains = ["switch.example.com"]

[netbox]
url = "https://netbox.example.net"

[ssh]
username = "netbox-sync"
auth = "agent"

[[sources]]
name = "nexus01.lab01"
kind = "switch"
host = "192.0.2.239"
type = "nxos"

[[sources]]
name = "nexus02.lab01"
kind = "switch"
host = "192.0.2.240"
type = "nxos"

[[sources]]
name = "2960-admin.lab01"
kind = "switch"
host = "192.0.2.251"
type = "ios"

[[sources]]
name = "2960-stack.lab01"
kind = "switch"
host = "192.0.2.252"
type = "ios"
virtual_chassis = "2960-stack"

[[sources]]
name = "fplab1-sw001"
kind = "switch"
type = "nipper"
report = "reports/fplab1-sw001.html"
virtual_chassis = "fplab1-sw001"
neighbor_pattern = '(?i)\b(?P<host>lab1-(?:pve|esx)\d+)(?:\.prod)?(?:[\s_-]+(?P<port>[a-z0-9]+))?'
neighbor_suffix = ".prod"

[[sources]]
name = "fw01.lab01"
kind = "firewall"
host = "192.0.2.1"
type = "fortios"
tls_fingerprint = "3A:7F:0C:91:5E:B2:44:D8:6A:19:F3:20:8B:C7:E1:55:09:AD:62:FE:71:38:C4:9B:0D:E6:2A:83:F5:14:BC:67"
ignore_interfaces = ["dmz"]

[sources.ha_peers]
FW-LAB-A = "fw01.lab01"
FW-LAB-B = "fw02.lab01"
"#;

    #[test]
    fn the_example_of_the_python_tool_loads() {
        let environ = [
            ("NETBOX_TOKEN", "token-value"),
            ("FIREWALL_FW01_LAB01_USERNAME", "readonly"),
            ("FIREWALL_FW01_LAB01_PASSWORD", "pw-forti"),
        ];
        let inventory = load(EXAMPLE, &environ);
        assert_eq!(
            names(&inventory),
            ["nexus01.lab01", "nexus02.lab01", "2960-admin.lab01", "2960-stack.lab01", "fplab1-sw001", "fw01.lab01"]
        );
        let firewall = &inventory.sources[5];
        assert_eq!(
            (firewall.r#type.as_str(), firewall.host.as_str(), firewall.kind),
            ("fortios", "192.0.2.1", Kind::Firewall)
        );
        assert_eq!(
            firewall.ha_peers,
            [("FW-LAB-A".to_owned(), "fw01.lab01".to_owned()), ("FW-LAB-B".to_owned(), "fw02.lab01".to_owned())]
        );
        assert_eq!(firewall.ignore_interfaces, ["dmz"]);
        assert_eq!(inventory.netbox_url, "https://netbox.example.net");
        assert_eq!(inventory.domains, ["switch.example.com"]);
        assert_eq!(inventory.sources[3].virtual_chassis.as_deref(), Some("2960-stack"));
        let report = &inventory.sources[4];
        assert_eq!((report.r#type.as_str(), report.virtual_chassis.as_deref()), ("nipper", Some("fplab1-sw001")));
        assert_eq!(groups(report, "VMWARE-lab1-esx01-vmnic2"), (Some("lab1-esx01"), Some("vmnic2")));
    }

    #[test]
    fn disabled_algorithms_common_and_per_source() {
        // NX-OS 7.0(3) sends no server-sig-algs: the client would sign with rsa-sha2-512.
        let common = "[ssh]\nusername = \"nrodriguez\"\nauth = \"agent\"\n\
                      disabled_algorithms = { pubkeys = [\"rsa-sha2-512\", \"rsa-sha2-256\"] }\n";
        let text =
            swap(&ssh(common), CHASSIS_LINE, "virtual_chassis = \"2960-stack\"\nssh = { disabled_algorithms = {} }\n");
        let (nexus, stack) = two(load(&text, &NETBOX_ONLY));
        assert_eq!(
            nexus.disabled_algorithms,
            Some(BTreeMap::from([("pubkeys".to_owned(), vec!["rsa-sha2-512".to_owned(), "rsa-sha2-256".to_owned()])]))
        );
        assert_eq!(stack.disabled_algorithms, Some(BTreeMap::new()));
    }

    #[test]
    fn no_disabled_algorithms_by_default() {
        let (nexus, _) = two(load(TOML, &ENV));
        assert_eq!(nexus.disabled_algorithms, None);
    }

    #[test]
    fn invalid_disabled_algorithms() {
        for value in ["\"rsa-sha2-512\"", "[\"rsa-sha2-512\"]", "{ pubkeys = \"rsa-sha2-512\" }", "{ pubkeys = [1] }"] {
            let block = format!("[ssh]\nusername = \"sync\"\nauth = \"password\"\ndisabled_algorithms = {value}\n");
            assert_eq!(
                error(&ssh(&block), &ENV),
                "/etc/omnisync/config.toml: ssh.disabled_algorithms must map a kind (pubkeys, macs, kex, ciphers, \
                 keys) to a list of algorithm names",
                "{value}"
            );
        }
    }

    // `cipher` for `ciphers` would leave CBC offered without a word.
    #[test]
    fn a_kind_of_algorithm_that_does_not_exist_is_refused() {
        let block =
            "[ssh]\nusername = \"sync\"\nauth = \"password\"\ndisabled_algorithms = { cipher = [\"aes128-cbc\"] }\n";
        assert_eq!(
            error(&ssh(block), &ENV),
            "/etc/omnisync/config.toml: ssh.disabled_algorithms must map a kind (pubkeys, macs, kex, ciphers, \
             keys) to a list of algorithm names"
        );
    }

    // `pubkeys` chooses how an RSA key signs: rsa-sha2-512, rsa-sha2-256 or
    // ssh-rsa. Another name disables nothing; all three leave nothing to sign with.
    #[test]
    fn the_rsa_signatures_disabled_are_known_and_one_is_left() {
        let with = |names: &str| {
            format!(
                "[ssh]\nusername = \"sync\"\nauth = \"password\"\ndisabled_algorithms = {{ pubkeys = [{names}] }}\n"
            )
        };
        assert_eq!(
            error(&ssh(&with("\"rsa-sha2-384\"")), &ENV),
            "/etc/omnisync/config.toml: ssh.disabled_algorithms: unknown pubkeys algorithm rsa-sha2-384 \
             (rsa-sha2-512, rsa-sha2-256, ssh-rsa)"
        );
        assert_eq!(
            error(&ssh(&with("\"rsa-sha2-512\", \"rsa-sha2-256\", \"ssh-rsa\"")), &ENV),
            "/etc/omnisync/config.toml: ssh.disabled_algorithms disables every RSA signature: an RSA key could not sign"
        );
    }

    #[test]
    fn aliases() {
        let text = format!("{TOML}\n[aliases]\nFGT-81-Acme-Primaire = \"forti01.lab01\"\n");
        let inventory = load(&text, &ENV);
        assert_eq!(
            inventory.aliases,
            BTreeMap::from([("FGT-81-Acme-Primaire".to_owned(), "forti01.lab01".to_owned())])
        );
        assert_eq!(load(TOML, &ENV).aliases, BTreeMap::new());
    }

    #[test]
    fn invalid_aliases() {
        for value in ["\"forti01.lab01\"", "[\"a\", \"b\"]", "{ FGT = \"\" }", "{ FGT = [\"forti01\"] }"] {
            assert_eq!(
                error(&format!("aliases = {value}\n{TOML}"), &ENV),
                "/etc/omnisync/config.toml: aliases must map an announced neighbour name to a Netbox device name",
                "{value}"
            );
        }
    }

    #[test]
    fn domains_must_be_a_list() {
        let text = swap(TOML, "domains = [\"switch.example.com\"]", "domains = \"switch.example.com\"");
        assert_eq!(error(&text, &ENV), "/etc/omnisync/config.toml: domains must be a list");
    }

    #[test]
    fn netbox_must_be_a_mapping() {
        let text = format!("netbox = \"https://netbox.example\"\n{}", swap(TOML, NETBOX_BLOCK, ""));
        assert_eq!(error(&text, &ENV), "/etc/omnisync/config.toml: netbox must be a mapping");
    }

    const NIPPER_TOML: &str = r#"
[netbox]
url = "https://netbox.example"

[[sources]]
name = "fplab1-sw001"
kind = "switch"
type = "nipper"
report = "reports/fplab1-sw001.html"
virtual_chassis = "fplab1-sw001"
neighbor_pattern = '(?i)\b(?P<host>lab1-pve\d+)(?:[\s_-]+(?P<port>[a-z0-9]+))?'
neighbor_suffix = ".prod"
"#;

    #[test]
    fn nipper_switch_needs_no_ssh() {
        let source = one(load(NIPPER_TOML, &NETBOX_ONLY));
        assert_eq!(source.r#type, "nipper");
        assert_eq!(source.host, "");
        assert_eq!(password(&source), None);
        assert_eq!(source.virtual_chassis.as_deref(), Some("fplab1-sw001"));
        // Relative to the configuration file, like a path written next to it.
        assert_eq!(source.report.as_deref(), Some(Path::new("/etc/omnisync/reports/fplab1-sw001.html")));
        assert_eq!(source.neighbor_suffix, ".prod");
        assert_eq!(groups(&source, "N:lab1-pve01 enp129s0").1, Some("enp129s0"));
    }

    // `~bob/…` is the home of another user for a shell: read as a relative
    // path, it would be a file next to the configuration.
    #[test]
    fn the_home_of_another_user_is_refused() {
        let text = swap(NIPPER_TOML, "reports/fplab1-sw001.html", "~bob/reports/fplab1-sw001.html");
        assert_eq!(
            error(&text, &[("NETBOX_TOKEN", "t"), ("HOME", "/home/sync")]),
            "cannot expand ~bob/reports/fplab1-sw001.html: ~bob is the home of another user, write the path in full"
        );
    }

    #[test]
    fn an_absolute_or_home_report_path_is_not_moved_next_to_the_file() {
        let text = swap(NIPPER_TOML, "reports/fplab1-sw001.html", "/srv/reports/fplab1-sw001.html");
        let source = one(load(&text, &NETBOX_ONLY));
        assert_eq!(source.report.as_deref(), Some(Path::new("/srv/reports/fplab1-sw001.html")));
        let text = swap(NIPPER_TOML, "reports/fplab1-sw001.html", "~/reports/fplab1-sw001.html");
        let source = one(load(&text, &[("NETBOX_TOKEN", "t"), ("HOME", "/home/sync")]));
        assert_eq!(source.report.as_deref(), Some(Path::new("/home/sync/reports/fplab1-sw001.html")));
    }

    #[test]
    fn nipper_switch_without_pattern_has_no_neighbours() {
        let text = swap(NIPPER_TOML, "neighbor_pattern =", "# neighbor_pattern =");
        let source = one(load(&text, &[("NETBOX_TOKEN", "t")]));
        assert!(source.neighbor_pattern.is_none());
    }

    #[test]
    fn nipper_switch_errors() {
        let text = swap(NIPPER_TOML, "report = \"reports/fplab1-sw001.html\"\n", "");
        assert_eq!(
            error(&text, &[("NETBOX_TOKEN", "t")]),
            "/etc/omnisync/config.toml: source entry 1 (fplab1-sw001): missing report"
        );
        let text = swap(NIPPER_TOML, r"(?P<host>lab1-pve\d+)", r"(lab1-pve\d+)");
        assert_eq!(error(&text, &[("NETBOX_TOKEN", "t")]), "fplab1-sw001: neighbor_pattern needs a named group 'host'");
        let text = swap(NIPPER_TOML, r"(?P<host>lab1-pve\d+)", r"(?P<host>lab1-pve\d+");
        let message = error(&text, &[("NETBOX_TOKEN", "t")]);
        assert!(message.starts_with("fplab1-sw001: neighbor_pattern is not a valid regular expression: "), "{message}");
    }

    #[test]
    fn ssh_switch_with_description_neighbours() {
        let text = swap(
            TOML,
            "type = \"nxos\"\n",
            "type = \"nxos\"\n\
             neighbor_pattern = '(?i)^(?:i?drac[-\\s]+)?(?P<host>[a-z0-9][a-z0-9.-]*)(?:/(?P<port>[^/\\s]+))?'\n\
             neighbor_suffix = ''\n",
        );
        let (nexus, stack) = two(load(&text, &ENV));
        assert_eq!(groups(&nexus, "c190-ctrl01.lab01/e0M"), (Some("c190-ctrl01.lab01"), Some("e0M")));
        assert_eq!(groups(&nexus, "drac-lab1-pve02"), (Some("lab1-pve02"), None));
        assert!(stack.neighbor_pattern.is_none());
    }

    // What Python's `re` accepts and the `regex` crate refuses comes out as the
    // error of an invalid pattern, never as a pattern that silently matches nothing.
    #[test]
    fn python_only_pattern_syntax_is_refused() {
        let patterns = [
            ("look-ahead", r"(?P<host>lab1-pve\d+)(?=-ilo)"),
            ("negative look-ahead", r"(?P<host>lab1-pve\d+)(?!-old)"),
            ("look-behind", r"(?<=N:)(?P<host>lab1-pve\d+)"),
            ("negative look-behind", r"(?<!old-)(?P<host>lab1-pve\d+)"),
            ("numbered backreference", r"(?P<host>lab1-pve\d+)-\1"),
            ("named backreference", r"(?P<host>lab1-pve\d+)-(?P=host)"),
            ("conditional group", r"(<)?(?P<host>lab1-pve\d+)(?(1)>)"),
            ("atomic group", r"(?>N:)(?P<host>lab1-pve\d+)"),
            ("end of text \\Z", r"(?P<host>lab1-pve\d+)\Z"),
        ];
        let mut accepted = Vec::new();
        for (what, pattern) in patterns {
            let text = swap(NIPPER_TOML, r"(?i)\b(?P<host>lab1-pve\d+)(?:[\s_-]+(?P<port>[a-z0-9]+))?", pattern);
            match parse_inventory(Path::new(CONFIG), &text, &env(&NETBOX_ONLY)) {
                Ok(_) => accepted.push(what),
                Err(failure) => assert!(
                    failure
                        .to_string()
                        .starts_with("fplab1-sw001: neighbor_pattern is not a valid regular expression: "),
                    "{what}: {failure}"
                ),
            }
        }
        assert_eq!(accepted, Vec::<&str>::new());
    }

    // The one Python-only construct the `regex` crate lets through: it reads `\d++`
    // as a repetition of a repetition, which finds the same host without being
    // possessive.
    #[test]
    fn possessive_quantifier_is_read_as_a_plain_repetition() {
        let text =
            swap(NIPPER_TOML, r"(?i)\b(?P<host>lab1-pve\d+)(?:[\s_-]+(?P<port>[a-z0-9]+))?", r"(?P<host>lab1-pve\d++)");
        let source = one(load(&text, &NETBOX_ONLY));
        assert_eq!(groups(&source, "N:lab1-pve01 enp129s0"), (Some("lab1-pve01"), None));
    }

    const FINGERPRINT: &str =
        "AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB";

    const FORTIOS_TOML: &str = r#"
[netbox]
url = "https://netbox.example"

[[sources]]
name = "fw01.dc1"
kind = "firewall"
host = "192.0.2.1"
type = "fortios"
tls_fingerprint = "AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB"
ha_peers = { FW-A = "fw01.dc1", FW-B = "fw02.dc1" }
ignore_interfaces = ["dmz"]
"#;

    const FORTIOS_ENV: [(&str, &str); 3] = [
        ("NETBOX_TOKEN", "token-value"),
        ("FIREWALL_FW01_DC1_USERNAME", "readonly"),
        ("FIREWALL_FW01_DC1_PASSWORD", "pw-forti"),
    ];

    fn both() -> Vec<(&'static str, &'static str)> {
        ENV.into_iter().chain(FORTIOS_ENV).collect()
    }

    fn peers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(host, device)| ((*host).to_owned(), (*device).to_owned())).collect()
    }

    #[test]
    fn fortios_entry_needs_no_ssh_block() {
        let firewall = one(load(FORTIOS_TOML, &FORTIOS_ENV));
        assert_eq!(
            (firewall.name.as_str(), firewall.host.as_str(), firewall.r#type.as_str(), firewall.kind),
            ("fw01.dc1", "192.0.2.1", "fortios", Kind::Firewall)
        );
        assert_eq!((firewall.username.as_str(), password(&firewall)), ("readonly", Some("pw-forti")));
        // Stored as 64 lower-case hexadecimal digits, whatever the spelling in the file.
        assert_eq!(
            firewall.tls_fingerprint.as_deref(),
            Some("abababababababababababababababababababababababababababababababab")
        );
        assert_eq!(firewall.ha_peers, peers(&[("FW-A", "fw01.dc1"), ("FW-B", "fw02.dc1")]));
        assert_eq!(firewall.ignore_interfaces, ["dmz"]);
        assert_eq!(firewall.virtual_chassis, None);
        assert!(!format!("{firewall:?}").contains("pw-forti"));
    }

    #[test]
    fn fortios_cluster_members_keep_the_order_of_the_file() {
        let text = swap(
            FORTIOS_TOML,
            "{ FW-A = \"fw01.dc1\", FW-B = \"fw02.dc1\" }",
            "{ b = \"fw02.dc1\", a = \"fw01.dc1\" }",
        );
        assert_eq!(one(load(&text, &FORTIOS_ENV)).ha_peers, peers(&[("b", "fw02.dc1"), ("a", "fw01.dc1")]));
    }

    #[test]
    fn fortios_optional_keys_default_to_empty() {
        let text = FORTIOS_TOML.split("ha_peers").next().unwrap();
        assert!(text.ends_with("AB\"\n"));
        let firewall = one(load(text, &FORTIOS_ENV));
        assert_eq!(firewall.ha_peers, peers(&[]));
        assert_eq!(firewall.ignore_interfaces, Vec::<String>::new());
    }

    #[test]
    fn fortios_credentials_never_fall_back_to_the_switch_ones() {
        let environ = [("NETBOX_TOKEN", "token-value"), ("SWITCH_USERNAME", "sync"), ("SWITCH_PASSWORD", "pw-ssh")];
        let firewall = one(load(FORTIOS_TOML, &environ));
        assert_eq!(firewall.missing(), ["FIREWALL_FW01_DC1_USERNAME", "FIREWALL_FW01_DC1_PASSWORD"]);
        let message = firewall.password.as_ref().expect("the account of the firewall").held().unwrap_err().to_string();
        assert_eq!(message, "missing environment variables: FIREWALL_FW01_DC1_PASSWORD, FIREWALL_FW01_DC1_USERNAME");
        assert_eq!(firewall.username, "");
        assert!(!format!("{firewall:?}").contains("sync"));
        assert!(!format!("{firewall:?}").contains("pw-ssh"));
    }

    // Half an account is none: what is held of it cannot be used alone.
    #[test]
    fn a_firewall_with_half_its_account_cannot_be_read_and_names_the_other_half() {
        let user_only = [FORTIOS_ENV[1]];
        let firewall = one(load(FORTIOS_TOML, &user_only));
        assert_eq!(firewall.missing(), ["FIREWALL_FW01_DC1_PASSWORD"]);
        assert_eq!(firewall.username, "readonly");
        let password_only = [FORTIOS_ENV[2]];
        let firewall = one(load(FORTIOS_TOML, &password_only));
        assert_eq!(firewall.missing(), ["FIREWALL_FW01_DC1_USERNAME"]);
        assert_eq!(firewall.password, Some(Wanted::Missing(strings(&["FIREWALL_FW01_DC1_USERNAME"]))));
        // The password that was there is not kept next to an empty user name.
        assert!(!format!("{firewall:?}").contains("pw-forti"));
        // A firewall that holds its account misses nothing.
        assert_eq!(one(load(FORTIOS_TOML, &FORTIOS_ENV)).missing(), [] as [&str; 0]);
    }

    // A key the entry does not take is refused, as for a hypervisor entry: a
    // misspelt `ignore_interfaces` would leave the interface to the prune.
    #[test]
    fn a_key_a_network_entry_does_not_take_is_refused() {
        let text = swap(FORTIOS_TOML, "ignore_interfaces =", "ignore_interface =");
        assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: unknown key ignore_interface for a fortios source");
        // Only a firewall reads ignore_interfaces: on a switch it would protect nothing.
        let text = swap(TOML, "kind = \"switch\"\n", "kind = \"switch\"\nignore_interfaces = [\"mgmt0\"]\n");
        assert_eq!(error(&text, &ENV), "nexus01.lab01: unknown key ignore_interfaces for a nxos source");
    }

    #[test]
    fn fortios_needs_a_fingerprint() {
        let text = swap(FORTIOS_TOML, &format!("tls_fingerprint = \"{FINGERPRINT}\"\n"), "");
        assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: missing tls_fingerprint");
    }

    #[test]
    fn fortios_malformed_fingerprint() {
        let zz = "zz".repeat(32);
        let short = "ab".repeat(20);
        for value in ["abcd", zz.as_str(), short.as_str()] {
            let text = swap(FORTIOS_TOML, FINGERPRINT, value);
            assert_eq!(
                error(&text, &FORTIOS_ENV),
                "fw01.dc1: tls_fingerprint must be the SHA-256 of the certificate (64 hexadecimal digits, colons \
                 allowed)",
                "{value}"
            );
        }
    }

    #[test]
    fn fortios_ha_peers_must_be_a_mapping() {
        let text = swap(FORTIOS_TOML, "{ FW-A = \"fw01.dc1\", FW-B = \"fw02.dc1\" }", "[\"FW-A\"]");
        assert_eq!(
            error(&text, &FORTIOS_ENV),
            "fw01.dc1: ha_peers must map the host name of a cluster member to a Netbox device name"
        );
    }

    #[test]
    fn fortios_ignore_interfaces_must_be_a_list() {
        let text = swap(FORTIOS_TOML, "ignore_interfaces = [\"dmz\"]", "ignore_interfaces = \"dmz\"");
        assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: ignore_interfaces must be a list of interface names");
    }

    #[test]
    fn fortios_ha_peers_must_name_the_entry_itself() {
        let text = swap(FORTIOS_TOML, "FW-A = \"fw01.dc1\"", "FW-A = \"fw03.dc1\"");
        assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: ha_peers must name fw01.dc1 as the device of one member");
    }

    fn firewall_entry() -> &'static str {
        FORTIOS_TOML.split("url = \"https://netbox.example\"\n").nth(1).unwrap()
    }

    // The Python file lists the firewalls in their own section, read after the
    // switches; here the single list is kept in the order of the file.
    #[test]
    fn sources_keep_the_order_of_the_file() {
        let text = format!("{TOML}{}", firewall_entry());
        assert_eq!(names(&load(&text, &both())), ["nexus01.lab01", "2960-stack.lab01", "fw01.dc1"]);
        let (first, second) = TOML.split_once("[[sources]]").unwrap();
        let text = format!("{first}{}\n[[sources]]{second}", firewall_entry().trim_start());
        assert_eq!(names(&load(&text, &both())), ["fw01.dc1", "nexus01.lab01", "2960-stack.lab01"]);
    }

    #[test]
    fn firewall_of_another_kind_is_refused() {
        for kind in ["switch", "router"] {
            let text = swap(FORTIOS_TOML, "kind = \"firewall\"", &format!("kind = \"{kind}\""));
            assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: a fortios source must be of kind firewall", "{kind}");
        }
    }

    #[test]
    fn switch_of_kind_firewall_is_refused() {
        let text = swap(FORTIOS_TOML, "type = \"fortios\"", "type = \"nxos\"");
        assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: a nxos source must be of kind switch or router");
    }

    #[test]
    fn malformed_firewall_entry_is_named_like_any_source() {
        let text = "[netbox]\nurl = \"https://n\"\n[[sources]]\nkind = \"firewall\"\ntype = \"fortios\"\n";
        assert_eq!(error(text, &FORTIOS_ENV), "/etc/omnisync/config.toml: source entry 1: missing name");
    }

    #[test]
    fn same_name_for_a_switch_and_a_firewall_is_refused() {
        let text = format!("{TOML}{}", swap(firewall_entry(), "name = \"fw01.dc1\"\n", "name = \"nexus01.lab01\"\n"));
        assert_eq!(error(&text, &both()), "duplicate device name nexus01.lab01");
    }

    #[test]
    fn firewall_api_port() {
        let default = one(load(FORTIOS_TOML, &FORTIOS_ENV));
        assert_eq!(default.port, None);
        let text = swap(FORTIOS_TOML, "type = \"fortios\"\n", "type = \"fortios\"\nport = 9443\n");
        let firewall = one(load(&text, &FORTIOS_ENV));
        assert_eq!((firewall.host.as_str(), firewall.port), ("192.0.2.1", Some(9443)));
    }

    #[test]
    fn firewall_api_port_must_be_a_port() {
        for value in ["\"https\"", "0", "70000", "true", "443.0"] {
            let text = swap(FORTIOS_TOML, "type = \"fortios\"\n", &format!("type = \"fortios\"\nport = {value}\n"));
            assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: port must be a number from 1 to 65535", "{value}");
        }
    }

    #[test]
    fn fortios_two_cluster_members_cannot_be_one_device() {
        let text = swap(FORTIOS_TOML, "FW-B = \"fw02.dc1\"", "FW-B = \"fw01.dc1\"");
        assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: ha_peers maps two members to fw01.dc1");
    }

    #[test]
    fn fortios_cluster_host_names_differ_by_more_than_case() {
        let text = swap(FORTIOS_TOML, "FW-B = \"fw02.dc1\"", "fw-a = \"fw02.dc1\"");
        assert_eq!(error(&text, &FORTIOS_ENV), "fw01.dc1: ha_peers names FW-A and fw-a differ by case only");
    }

    #[test]
    fn load_inventory_reads_the_file_and_resolves_reports_next_to_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(&path, NIPPER_TOML).unwrap();
        let source = one(load_inventory(&path, &env(&NETBOX_ONLY)).unwrap());
        assert_eq!(source.name, "fplab1-sw001");
        assert_eq!(source.report, Some(directory.path().join("reports").join("fplab1-sw001.html")));
    }

    #[test]
    fn an_unreadable_file_is_an_inventory_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent.toml");
        let message = load_inventory(&path, &env(&NETBOX_ONLY)).unwrap_err().to_string();
        assert!(message.starts_with(&format!("{}: cannot read the file: ", path.display())), "{message}");
    }
}
