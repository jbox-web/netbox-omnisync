//! The configuration of a run: the hypervisor and BMC sources and the NetBox
//! settings, read from the same TOML file as the network inventory.
//!
//! The network loader (`omnisync_core::network::inventory`) reads the switches,
//! routers and firewalls and skips the `hypervisor` and `bmc` entries; this
//! module reads those, and the keys of `[netbox]` the network loader has no
//! use for.
//!
//! Secrets come from the environment only, handed in as a map: nothing is read
//! from the process here. Everything is checked before anything is contacted:
//! an error names the file, the entry and the key, never a value that could be
//! a secret.
//!
//! The same file is loaded on every host that runs the tool, each launching
//! its own sources (those the file gives it: [`Runners`]) and holding only
//! their secrets. A secret the environment
//! does not hold is therefore not an error of the load: the source is checked
//! in full and kept, with the names of the variables it misses
//! ([`Wanted::Missing`]). [`Config::require`] refuses the run once the
//! selection is known, for the selected sources only.

use omnisync_netbox::version::UnsupportedVersion;
use omnisync_tls::Fingerprint;
use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use omnisync_core::inventory::model::VlanGroups;
use omnisync_core::network::inventory::{
    Environ, Inventory, InventoryError, MissingVariables, Secret, Wanted, env_prefix, expand_user, parse_inventory,
    ssh_block,
};
use regex::Regex;
use toml::{Table, Value};

/// What a `hypervisor` entry may be read with.
pub const HYPERVISOR_TYPES: [&str; 2] = ["proxmox", "vmware"];

/// The keys of a `hypervisor` entry: any other is refused, so that a typo
/// never silently leaves a setting at its default.
const HYPERVISOR_KEYS: [&str; 23] = [
    "name",
    "kind",
    "type",
    "runner",
    "host",
    "port",
    "validate_certs",
    "ca_file",
    "site",
    "tenant",
    "host_role",
    "vm_role",
    "domain",
    "ignore_templates",
    "ignored_subnets",
    "permitted_subnets",
    "interface_filter",
    "dns_name_lookup",
    "dns_servers",
    "create_devices",
    "prune",
    "neighbors",
    "ssh",
];

/// What `neighbors` takes: the daemon asked on each node.
const NEIGHBORS_LLDPD: &str = "lldpd";

/// The keys of the `ssh` block of a Proxmox entry: those of the switches, and
/// the address of a node whose name does not lead to it.
const NODE_SSH_KEYS: [&str; 5] = ["username", "auth", "key_file", "disabled_algorithms", "hosts"];

/// The port of a DNS resolver written without one.
const DNS_PORT: u16 = 53;

/// What a `bmc` entry may be read with.
pub const BMC_TYPES: [&str; 1] = ["redfish"];

/// The keys of a `bmc` entry: any other is refused. It has no `host`: one
/// entry reads the BMC of each device it lists.
const BMC_KEYS: [&str; 11] = [
    "name",
    "kind",
    "type",
    "runner",
    "port",
    "validate_certs",
    "ca_file",
    "devices",
    "bmc_pattern",
    "bmcs",
    "tls_fingerprints",
];

/// The keys of a hypervisor that a `bmc` entry must not carry, whatever their
/// value: a BMC completes devices that exist, and owns nothing it could delete.
const BMC_REFUSED_KEYS: [&str; 2] = ["create_devices", "prune"];

/// Where `bmc_pattern` takes the name of the device.
const DEVICE_NAME: &str = "{name}";

/// The keys of a `[[vlan_groups]]` table.
const VLAN_GROUP_KEYS: [&str; 2] = ["name", "sites"];

/// The keys of `[netbox]`.
const NETBOX_KEYS: [&str; 6] =
    ["url", "timeout", "validate_certs", "ca_file", "source_priority", "unsupported_version"];

/// The configuration or the environment is invalid or incomplete: nothing is contacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The file, the entry and the key at fault.
    #[error("{0}")]
    Invalid(String),
    /// Secrets the run needs and the environment does not hold, by the name
    /// of their variable.
    #[error(transparent)]
    MissingVariables(#[from] MissingVariables),
    /// What the network loader refused, in its own words.
    #[error(transparent)]
    Inventory(#[from] InventoryError),
}

/// How a hypervisor or a BMC is read: the `type` of its entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HypervisorType {
    Proxmox,
    Vmware,
    /// The BMCs of servers, read through Redfish: an entry of kind `bmc`.
    Redfish,
}

impl HypervisorType {
    pub fn as_str(self) -> &'static str {
        match self {
            HypervisorType::Proxmox => "proxmox",
            HypervisorType::Vmware => "vmware",
            HypervisorType::Redfish => "redfish",
        }
    }

    /// Whether the entry is of kind `bmc`, not `hypervisor`.
    pub fn is_bmc(self) -> bool {
        self == HypervisorType::Redfish
    }
}

/// The BMC of one device, in a `bmc` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bmc {
    /// Name of the device in NetBox.
    pub device: String,
    /// Host name or address of its BMC.
    pub host: String,
    /// The SHA-256 of the certificate its BMC presents, when it is pinned
    /// (`tls_fingerprints`): it replaces `validate_certs` and `ca_file`.
    pub fingerprint: Option<Fingerprint>,
}

/// The account a hypervisor is read with, from `<NAME>_USERNAME`,
/// `<NAME>_PASSWORD` and `<NAME>_TOKEN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credentials {
    /// A user and its password.
    Password { username: String, password: Secret },
    /// An API token, which names its account itself (Proxmox:
    /// `user@realm!name=secret`).
    Token { token: Secret },
}

/// One `[[sources]]` entry of kind `hypervisor` or `bmc`: a source whose
/// reports are reconciled with NetBox, all of them together.
#[derive(Debug, Clone)]
pub struct Hypervisor {
    /// Unique among all the sources of the file, whatever their kind.
    pub name: String,
    pub r#type: HypervisorType,
    /// Empty for a `bmc` entry, which has one address per device (`bmcs`).
    pub host: String,
    /// None: the default port of the API of that type.
    pub port: Option<u16>,
    pub validate_certs: bool,
    /// A PEM file of certificate authorities; relative to the configuration file.
    pub ca_file: Option<PathBuf>,
    /// NetBox objects, by name.
    pub site: Option<String>,
    pub tenant: Option<String>,
    pub host_role: Option<String>,
    pub vm_role: Option<String>,
    /// Suffix appended to the host names (Proxmox).
    pub domain: Option<String>,
    pub ignore_templates: bool,
    /// Addresses of these networks are left out.
    pub ignored_subnets: Vec<IpNet>,
    /// When not empty, only the addresses of these networks are kept.
    pub permitted_subnets: Vec<IpNet>,
    /// Compiled at load: an invalid expression stops the run before it starts.
    pub interface_filter: Option<Regex>,
    /// Fill the DNS name of each address with its reverse lookup (PTR).
    pub dns_name_lookup: bool,
    /// The resolvers asked for those lookups; empty: the ones of the system.
    pub dns_servers: Vec<SocketAddr>,
    /// Create the NetBox device of a host that has none. Always off for a
    /// `bmc` entry.
    pub create_devices: bool,
    /// Delete what NetBox holds from this source and the source no longer has.
    /// Always off for a `bmc` entry.
    pub prune: bool,
    /// The NetBox VLAN group the VLANs of `site` are kept in, when
    /// `[[vlan_groups]]` puts the site in one; None: at the site itself.
    pub vlan_group: Option<String>,
    /// The devices a `bmc` entry documents, each with its BMC, in the order
    /// of the file; empty for a hypervisor.
    pub bmcs: Vec<Bmc>,
    /// Missing on a host that does not launch this source: it is then known
    /// to the run (its tag is not a leftover) and cannot be read.
    pub credentials: Wanted<Credentials>,
    /// Ask `lldpd` on each node what its cards hear (`neighbors = "lldpd"`):
    /// a Proxmox entry only, and never without its `ssh` block.
    pub neighbors: bool,
    /// The account the nodes are logged into with, to ask `lldpd`.
    pub ssh: Option<NodeSsh>,
}

/// How a node is logged into: one mode, as for the switches.
#[derive(Debug, Clone)]
pub enum NodeAuth {
    Agent,
    KeyFile(PathBuf),
    /// From `<PREFIX>_SSH_PASSWORD`.
    Password(Wanted<Secret>),
}

/// The `ssh` block of a Proxmox entry.
#[derive(Debug, Clone)]
pub struct NodeSsh {
    pub username: String,
    pub auth: NodeAuth,
    pub disabled_algorithms: Option<BTreeMap<String, Vec<String>>>,
    /// A node -> the address it is reached at, when its name does not lead to it.
    pub hosts: BTreeMap<String, String>,
}

impl Hypervisor {
    /// The variables this source needs and the environment does not hold.
    pub fn missing(&self) -> &[String] {
        self.credentials.missing()
    }

    /// The variables a run needs for this source, the password of its nodes
    /// only when the run reads what their cards hear.
    pub fn missing_reading(&self, neighbours: bool) -> Vec<String> {
        let mut missing = self.missing().to_vec();
        if neighbours && let Some(NodeSsh { auth: NodeAuth::Password(password), .. }) = &self.ssh {
            missing.extend(password.missing().iter().cloned());
        }
        missing
    }
}

/// The `[netbox]` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Netbox {
    pub url: String,
    /// Needed by every run, whatever it selects.
    pub token: Wanted<Secret>,
    /// Time a request may take; None: the default of the client.
    pub timeout: Option<Duration>,
    pub validate_certs: bool,
    /// A PEM file of certificate authorities; relative to the configuration file.
    pub ca_file: Option<PathBuf>,
    /// Source names, the one that wins a conflict first.
    pub source_priority: Vec<String>,
    /// What a run does with a NetBox of a release this build was not tested with.
    pub unsupported_version: UnsupportedVersion,
}

/// Everything the file and the environment say.
#[derive(Debug, Clone)]
pub struct Config {
    /// The switches, routers and firewalls, as the network loader reads them.
    pub inventory: Inventory,
    pub hypervisors: Vec<Hypervisor>,
    pub netbox: Netbox,
    /// The journal of the runs, as the file names it (`journal`), relative
    /// to the file; None: the default one, next to the lock.
    pub journal: Option<PathBuf>,
    /// The sites that keep their VLANs in a NetBox VLAN group (`[[vlan_groups]]`).
    pub vlan_groups: VlanGroups,
    /// Which host launches each source (`runners`, and the `runner` of each entry).
    pub runners: Runners,
}

/// Which host launches each source, when the same file is on several hosts:
/// the hosts the top of the file lists (`runners`), and the one each entry
/// names (`runner`). Empty when the file says neither: one host runs everything.
///
/// A host is the name its system gives it in full (`hostname -f`), compared
/// as it is written: a short name is never taken for a full one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Runners {
    hosts: Vec<String>,
    by_source: BTreeMap<String, String>,
}

impl Runners {
    /// Whether the file names no host: every source is run by whoever runs the tool.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// The hosts, in the order of the file.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The host that launches the source of this name; None when the file names no host.
    pub fn of(&self, source: &str) -> Option<&str> {
        self.by_source.get(source).map(String::as_str)
    }
}

impl Config {
    /// Refuses a run of the sources `selected` lets through, by their name,
    /// when the environment lacks one of their secrets or the NetBox token:
    /// every missing variable at once, and none of a source left out.
    ///
    /// To be called once the selection is known and before anything is
    /// contacted. A password shared by the switches is only needed by a run
    /// that selects a switch read with it; the password of the nodes of a
    /// Proxmox only by a run that reads what their cards hear (`neighbours`).
    pub fn require(&self, selected: impl Fn(&str) -> bool, neighbours: bool) -> Result<(), ConfigError> {
        let network = self.inventory.missing(|source| selected(&source.name));
        let hypervisors = self.hypervisors.iter().filter(|source| selected(&source.name));
        let inventory = hypervisors.flat_map(|source| source.missing_reading(neighbours));
        let token = self.netbox.token.missing().iter().cloned();
        match MissingVariables::of(network.into_iter().chain(inventory).chain(token)) {
            Some(missing) => Err(ConfigError::MissingVariables(missing)),
            None => Ok(()),
        }
    }
}

/// The prefix of the variables of a source: its name upper-cased, every
/// non-alphanumeric character replaced by `_`.
pub fn variable_prefix(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect()
}

fn invalid<T>(message: String) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(message))
}

/// The value of a variable of the environment, None when unset or empty.
fn variable<'e>(environ: &'e Environ, name: &str) -> Option<&'e str> {
    environ.get(name).map(String::as_str).filter(|value| !value.is_empty())
}

/// A scalar of the file as text, as the network loader reads a name.
fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// A table of the file, with where it is: every error starts with `location`.
struct Block<'t> {
    location: String,
    /// Prefix of a key in an error: `netbox.` in the NetBox block, nothing in an entry.
    prefix: &'static str,
    table: &'t Table,
    /// The directory of the file and the environment: to resolve the paths.
    directory: &'t Path,
    environ: &'t Environ,
}

impl Block<'_> {
    fn fail<T>(&self, problem: &str) -> Result<T, ConfigError> {
        invalid(format!("{}: {problem}", self.location))
    }

    /// An error about `key`.
    fn refuse<T>(&self, key: &str, problem: &str) -> Result<T, ConfigError> {
        self.fail(&format!("{}{key} {problem}", self.prefix))
    }

    /// Only the keys of `known` are allowed; `separator` comes between the
    /// location and the refusal. The value of an unknown key is never printed:
    /// it may be a secret written in the file by mistake.
    fn only(&self, known: &[&str], separator: &str) -> Result<(), ConfigError> {
        match self.table.keys().find(|key| !known.contains(&key.as_str())) {
            Some(key) => invalid(format!("{}{separator}unknown key '{key}'", self.location)),
            None => Ok(()),
        }
    }

    /// A string; an empty one counts as absent.
    fn string(&self, key: &str) -> Result<Option<String>, ConfigError> {
        match self.table.get(key) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone()).filter(|text| !text.is_empty())),
            Some(_) => self.refuse(key, "must be a string"),
        }
    }

    fn flag(&self, key: &str, default: bool) -> Result<bool, ConfigError> {
        match self.table.get(key) {
            None => Ok(default),
            Some(Value::Boolean(flag)) => Ok(*flag),
            Some(_) => self.refuse(key, "must be true or false"),
        }
    }

    /// A path: `~` is the `HOME` of the environment, and a relative path is
    /// relative to the configuration file, as the report of a switch is.
    fn path(&self, key: &str) -> Result<Option<PathBuf>, ConfigError> {
        let Some(written) = self.string(key)? else {
            return Ok(None);
        };
        // `~user/…` is the home of another user for a shell: never a relative path.
        if let Some(rest) = written.strip_prefix('~')
            && !(rest.is_empty() || rest.starts_with('/'))
        {
            let user = rest.split('/').next().unwrap_or(rest);
            return self
                .fail(&format!("{}{key}: ~{user} is the home of another user: write the path in full", self.prefix));
        }
        let path = match written.strip_prefix('~').filter(|rest| rest.is_empty() || rest.starts_with('/')) {
            None => PathBuf::from(&written),
            Some(rest) => match variable(self.environ, "HOME") {
                Some(home) => Path::new(home).join(rest.trim_start_matches('/')),
                None => return self.fail(&format!("{}{key}: cannot expand ~: HOME is not set", self.prefix)),
            },
        };
        Ok(Some(if path.is_absolute() { path } else { self.directory.join(path) }))
    }

    fn port(&self) -> Result<Option<u16>, ConfigError> {
        match self.table.get("port") {
            None => Ok(None),
            Some(Value::Integer(number)) if (1..=65535).contains(number) => Ok(u16::try_from(*number).ok()),
            Some(_) => self.refuse("port", "must be a number from 1 to 65535"),
        }
    }

    /// A list of networks; one written with host bits is its network.
    fn subnets(&self, key: &str) -> Result<Vec<IpNet>, ConfigError> {
        let items = match self.table.get(key) {
            None => return Ok(Vec::new()),
            Some(Value::Array(items)) => items,
            Some(_) => return self.refuse(key, "must be a list of CIDR"),
        };
        let mut subnets = Vec::new();
        for item in items {
            let Value::String(written) = item else {
                return self.refuse(key, "must be a list of CIDR");
            };
            match written.parse::<IpNet>() {
                Ok(subnet) => subnets.push(subnet.trunc()),
                Err(_) => return self.fail(&format!("{}{key}: '{written}' is not a CIDR", self.prefix)),
            }
        }
        Ok(subnets)
    }

    /// A list of DNS resolvers, each by its address: `192.0.2.53`, or with a
    /// port `192.0.2.53:5353`, `[2001:db8::53]:5353`. A name is refused:
    /// resolving it would need a resolver.
    fn resolvers(&self, key: &str) -> Result<Vec<SocketAddr>, ConfigError> {
        let items = match self.table.get(key) {
            None => return Ok(Vec::new()),
            Some(Value::Array(items)) => items,
            Some(_) => return self.refuse(key, "must be a list of IP addresses"),
        };
        let mut resolvers = Vec::new();
        for item in items {
            let Value::String(written) = item else {
                return self.refuse(key, "must be a list of IP addresses");
            };
            let alone = written.parse::<IpAddr>().map(|address| SocketAddr::new(address, DNS_PORT));
            match alone.or_else(|_| written.parse::<SocketAddr>()) {
                Ok(resolver) if resolver.port() != 0 => resolvers.push(resolver),
                _ => {
                    let problem = format!("'{written}' is not an IP address, with or without a port");
                    return self.fail(&format!("{}{key}: {problem}", self.prefix));
                }
            }
        }
        Ok(resolvers)
    }

    fn regex(&self, key: &str) -> Result<Option<Regex>, ConfigError> {
        let Some(pattern) = self.string(key)? else {
            return Ok(None);
        };
        match Regex::new(&pattern) {
            Ok(regex) => Ok(Some(regex)),
            Err(error) => self.refuse(key, &format!("is not a valid regular expression: {error}")),
        }
    }
}

/// The account of a hypervisor, from the three variables of its name.
///
/// Only names of variables are ever reported: an account the environment
/// lacks is missing by the ones to set, and a conflict names the two
/// variables, not their values.
fn credentials(block: &Block<'_>, name: &str, r#type: HypervisorType) -> Result<Wanted<Credentials>, ConfigError> {
    let environ = block.environ;
    let prefix = variable_prefix(name);
    let names = [format!("{prefix}_USERNAME"), format!("{prefix}_PASSWORD"), format!("{prefix}_TOKEN")];
    let [username, password, token] = &names;
    let found = (variable(environ, username), variable(environ, password), variable(environ, token));
    match found {
        // Two secrets for one account: which one is meant cannot be guessed.
        (_, Some(_), Some(_)) => block.fail(&format!("set {password} or {token}, not both")),
        // Nothing reads an account next to a Proxmox token: it names its own.
        (Some(_), None, Some(_)) if r#type == HypervisorType::Proxmox => block.fail(&format!(
            "{username} is not read with {token}: the token names its account (user@realm!name=secret)"
        )),
        // A vCenter takes no token: its reader refuses it, naming the
        // variables of the account it takes.
        (_, None, Some(secret)) => Ok(Wanted::Held(Credentials::Token { token: Secret::new(secret) })),
        (Some(account), Some(secret), None) => {
            Ok(Wanted::Held(Credentials::Password { username: account.to_owned(), password: Secret::new(secret) }))
        }
        (None, Some(_), None) => Ok(Wanted::Missing(vec![username.clone()])),
        (Some(_), None, None) => Ok(Wanted::Missing(vec![format!("{password} or {token}")])),
        (None, None, None) => Ok(Wanted::Missing(vec![format!("{token} (or {username} and {password})")])),
    }
}

/// The variables read for something else than a hypervisor: variable -> what it is.
///
/// A hypervisor whose name gives one of these would be handed the secret of
/// something else (the NetBox token for a source named `netbox`).
fn reserved_variables(entries: &[Value]) -> BTreeMap<String, String> {
    let mut reserved: BTreeMap<String, String> = [
        ("NETBOX_TOKEN", "the NetBox token"),
        ("SWITCH_USERNAME", "the user name common to the switches"),
        ("SWITCH_PASSWORD", "the password common to the switches"),
    ]
    .into_iter()
    .map(|(variable, usage)| (variable.to_owned(), usage.to_owned()))
    .collect();
    for entry in entries {
        let (Some(Value::String(kind)), Some(name)) = (entry.get("kind"), entry.get("name").map(text)) else {
            continue;
        };
        let variables: &[&str] = match kind.as_str() {
            "switch" | "router" => &["PASSWORD"],
            "firewall" => &["USERNAME", "PASSWORD"],
            _ => continue,
        };
        let prefix = env_prefix(&name, if kind == "firewall" { "firewall" } else { "switch" });
        for variable in variables {
            reserved.insert(format!("{prefix}_{variable}"), format!("read for source {name}"));
        }
    }
    reserved
}

/// Takes the three variables of the source `name`, refusing one that is
/// already read for something else.
fn reserve(block: &Block<'_>, name: &str, reserved: &mut BTreeMap<String, String>) -> Result<(), ConfigError> {
    let prefix = variable_prefix(name);
    for suffix in ["USERNAME", "PASSWORD", "TOKEN"] {
        let variable = format!("{prefix}_{suffix}");
        if let Some(usage) = reserved.get(&variable) {
            return block.fail(&format!("its variable {variable} is also {usage}: rename the source"));
        }
        reserved.insert(variable, format!("read for source {name}"));
    }
    Ok(())
}

/// The account of a `bmc` entry: a BMC is read with HTTP Basic, a user and
/// its password, shared by every BMC of the entry. Only names of variables
/// are ever reported.
fn bmc_credentials(block: &Block<'_>, name: &str) -> Result<Wanted<Credentials>, ConfigError> {
    let prefix = variable_prefix(name);
    let (username, password, token) =
        (format!("{prefix}_USERNAME"), format!("{prefix}_PASSWORD"), format!("{prefix}_TOKEN"));
    if variable(block.environ, &token).is_some() {
        return block.fail(&format!("a bmc source logs in with {username} and {password}: unset {token}"));
    }
    // Half an account is none: the half that is held is not kept.
    Ok(match (variable(block.environ, &username), variable(block.environ, &password)) {
        (Some(account), Some(secret)) => {
            Wanted::Held(Credentials::Password { username: account.to_owned(), password: Secret::new(secret) })
        }
        (account, secret) => {
            let absent = [(account, username), (secret, password)];
            Wanted::Missing(absent.into_iter().filter(|(found, _)| found.is_none()).map(|(_, name)| name).collect())
        }
    })
}

/// Whether `text` can be the address of a BMC: a host name or an IPv4
/// address, and nothing a URL could read as an account, a port or a path.
fn is_host(text: &str) -> bool {
    let allowed = |character: char| character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_');
    !text.is_empty() && text.chars().all(allowed)
}

/// The devices of a `bmc` entry and the address of the BMC of each: the ones
/// of `devices`, named after `bmc_pattern`, then the ones of `bmcs`.
///
/// A value is never printed: an address written with an account in it would
/// show the account.
fn bmcs(block: &Block<'_>) -> Result<Vec<Bmc>, ConfigError> {
    let devices: Vec<String> = match block.table.get("devices") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            let names: Option<Vec<String>> = items
                .iter()
                .map(|item| item.as_str().map(str::trim).filter(|name| !name.is_empty()).map(str::to_owned))
                .collect();
            match names {
                Some(names) => names,
                None => return block.refuse("devices", "must be a list of device names"),
            }
        }
        Some(_) => return block.refuse("devices", "must be a list of device names"),
    };
    let pattern = block.string("bmc_pattern")?;
    if pattern.as_ref().is_some_and(|pattern| !pattern.contains(DEVICE_NAME)) {
        return block.refuse("bmc_pattern", "must contain {name}, replaced by the name of each device");
    }
    let mut found: Vec<Bmc> = Vec::new();
    match (&pattern, devices.is_empty()) {
        (None, false) => {
            return block.refuse("devices", "needs bmc_pattern to name their BMC (or give each address in bmcs)");
        }
        (Some(_), true) => return block.refuse("bmc_pattern", "is set and devices lists no device"),
        (Some(pattern), false) => {
            let named = |device: String| Bmc { host: pattern.replace(DEVICE_NAME, &device), device, fingerprint: None };
            found.extend(devices.into_iter().map(named));
        }
        (None, true) => {}
    }
    match block.table.get("bmcs") {
        None => {}
        Some(Value::Table(table)) => {
            for (device, host) in table {
                let Value::String(host) = host else {
                    return block.refuse("bmcs", "must give the address of the BMC of each device, as a string");
                };
                found.push(Bmc { device: device.trim().to_owned(), host: host.trim().to_owned(), fingerprint: None });
            }
        }
        Some(_) => return block.refuse("bmcs", "must be a table: device name = address of its BMC"),
    }
    if found.is_empty() {
        return block.fail("no device: list them in devices with bmc_pattern, or in bmcs");
    }
    let mut seen: Vec<String> = Vec::new();
    for bmc in &found {
        if bmc.device.is_empty() {
            return block.refuse("bmcs", "names a device with an empty name");
        }
        // NetBox names a device once, whatever the letter case.
        if seen.contains(&bmc.device.to_lowercase()) {
            return block.fail(&format!("device '{}' is listed twice", bmc.device));
        }
        seen.push(bmc.device.to_lowercase());
        if !is_host(&bmc.host) {
            return block.fail(&format!("the BMC of device '{}' must be a host name or an IPv4 address", bmc.device));
        }
    }
    // The certificate of each BMC, pinned by the name of its device.
    match block.table.get("tls_fingerprints") {
        None => {}
        Some(Value::Table(table)) => {
            for (device, pin) in table {
                let Some(bmc) = found.iter_mut().find(|bmc| bmc.device.eq_ignore_ascii_case(device.trim())) else {
                    return block.fail(&format!("tls_fingerprints names {device}, which is not one of its devices"));
                };
                if bmc.fingerprint.is_some() {
                    return block.fail(&format!("tls_fingerprints names {} twice", bmc.device));
                }
                let parsed = pin.as_str().map(Fingerprint::parse);
                let Some(Ok(fingerprint)) = parsed else {
                    let why = omnisync_tls::FingerprintError;
                    return block.fail(&format!("tls_fingerprints of {device} {why}"));
                };
                bmc.fingerprint = Some(fingerprint);
            }
        }
        Some(_) => {
            return block.refuse("tls_fingerprints", "must be a table: device name = SHA-256 of its certificate");
        }
    }
    Ok(found)
}

/// One `bmc` entry, checked in full whether or not the environment holds its
/// account.
///
/// `create_devices` and `prune` are refused rather than ignored: written in
/// a `bmc` entry they would read as a promise the source does not keep.
fn bmc(block: &Block<'_>, name: &str, reserved: &mut BTreeMap<String, String>) -> Result<Hypervisor, ConfigError> {
    if let Some(key) = BMC_REFUSED_KEYS.iter().find(|key| block.table.contains_key(**key)) {
        return block.fail(&format!("a bmc source never creates a device and never deletes anything: remove {key}"));
    }
    block.only(&BMC_KEYS, ": ")?;
    match block.table.get("type") {
        None => return block.fail("missing type"),
        Some(Value::String(r#type)) if r#type == "redfish" => {}
        Some(Value::String(r#type)) if r#type.is_empty() => return block.fail("missing type"),
        Some(other) => {
            let known = BMC_TYPES.join(" or ");
            return block.fail(&format!("unsupported type '{}' (a bmc is {known})", text(other)));
        }
    }
    reserve(block, name, reserved)?;
    let credentials = bmc_credentials(block, name)?;
    Ok(Hypervisor {
        name: name.to_owned(),
        r#type: HypervisorType::Redfish,
        host: String::new(),
        port: block.port()?,
        validate_certs: block.flag("validate_certs", true)?,
        ca_file: block.path("ca_file")?,
        site: None,
        tenant: None,
        host_role: None,
        vm_role: None,
        domain: None,
        ignore_templates: true,
        ignored_subnets: Vec::new(),
        permitted_subnets: Vec::new(),
        interface_filter: None,
        // A BMC reports no IP address: there is nothing to look up.
        dns_name_lookup: false,
        dns_servers: Vec::new(),
        create_devices: false,
        prune: false,
        // A BMC reports no VLAN.
        vlan_group: None,
        bmcs: bmcs(block)?,
        credentials,
        neighbors: false,
        ssh: None,
    })
}

/// One hypervisor entry, checked in full whether or not the environment holds
/// its account.
fn hypervisor(
    block: &Block<'_>,
    name: &str,
    reserved: &mut BTreeMap<String, String>,
) -> Result<Hypervisor, ConfigError> {
    block.only(&HYPERVISOR_KEYS, ": ")?;
    let r#type = match block.table.get("type") {
        None => return block.fail("missing type"),
        Some(Value::String(r#type)) if r#type == "proxmox" => HypervisorType::Proxmox,
        Some(Value::String(r#type)) if r#type == "vmware" => HypervisorType::Vmware,
        Some(Value::String(r#type)) if r#type.is_empty() => return block.fail("missing type"),
        Some(other) => {
            let known = HYPERVISOR_TYPES.join(" or ");
            return block.fail(&format!("unsupported type '{}' (a hypervisor is {known})", text(other)));
        }
    };
    let Some(host) = block.string("host")? else {
        return block.fail("missing host");
    };
    reserve(block, name, reserved)?;
    let credentials = credentials(block, name, r#type)?;
    let dns_name_lookup = block.flag("dns_name_lookup", false)?;
    let dns_servers = block.resolvers("dns_servers")?;
    if !dns_servers.is_empty() && !dns_name_lookup {
        return block.refuse("dns_servers", "is set but dns_name_lookup is not true");
    }
    let (neighbors, ssh) = node_ssh(block, name, r#type, reserved)?;
    Ok(Hypervisor {
        name: name.to_owned(),
        r#type,
        host,
        port: block.port()?,
        validate_certs: block.flag("validate_certs", true)?,
        ca_file: block.path("ca_file")?,
        site: block.string("site")?,
        tenant: block.string("tenant")?,
        host_role: block.string("host_role")?,
        vm_role: block.string("vm_role")?,
        domain: block.string("domain")?,
        ignore_templates: block.flag("ignore_templates", true)?,
        ignored_subnets: block.subnets("ignored_subnets")?,
        permitted_subnets: block.subnets("permitted_subnets")?,
        interface_filter: block.regex("interface_filter")?,
        dns_name_lookup,
        dns_servers,
        create_devices: block.flag("create_devices", true)?,
        prune: block.flag("prune", true)?,
        // Known once the `[[vlan_groups]]` tables are read.
        vlan_group: None,
        bmcs: Vec::new(),
        credentials,
        neighbors,
        ssh,
    })
}

/// `neighbors` and the `ssh` block of a hypervisor entry: only a Proxmox
/// takes them, and one never goes without the other.
fn node_ssh(
    block: &Block<'_>,
    name: &str,
    r#type: HypervisorType,
    reserved: &mut BTreeMap<String, String>,
) -> Result<(bool, Option<NodeSsh>), ConfigError> {
    let neighbors = match block.string("neighbors")?.as_deref() {
        None => false,
        Some(NEIGHBORS_LLDPD) => true,
        Some(other) => return block.fail(&format!("neighbors must be \"{NEIGHBORS_LLDPD}\" (got '{other}')")),
    };
    let ssh = block.table.get("ssh");
    if r#type != HypervisorType::Proxmox {
        if neighbors {
            return block.fail("neighbors is only read on a proxmox entry: a vCenter tells what its hosts hear");
        }
        if ssh.is_some() {
            return block.fail("ssh is only read on a proxmox entry");
        }
        return Ok((false, None));
    }
    let table = match ssh {
        None if neighbors => return block.fail(&format!("neighbors = \"{NEIGHBORS_LLDPD}\" needs an ssh block")),
        None => return Ok((false, None)),
        Some(_) if !neighbors => {
            return block.fail(&format!("ssh is set but neighbors is not \"{NEIGHBORS_LLDPD}\""));
        }
        Some(Value::Table(table)) => table,
        Some(_) => return block.fail("ssh must be a mapping"),
    };
    if let Some(key) = table.keys().find(|key| !NODE_SSH_KEYS.contains(&key.as_str())) {
        return block.fail(&format!("unknown key ssh.{key} ({})", NODE_SSH_KEYS.join(", ")));
    }
    let hosts = match table.get("hosts") {
        None => BTreeMap::new(),
        Some(Value::Table(hosts)) => {
            let mut found = BTreeMap::new();
            for (node, address) in hosts {
                match address {
                    Value::String(address) if is_host(address) => {
                        found.insert(node.clone(), address.clone());
                    }
                    _ => return block.fail(&format!("ssh.hosts.{node} must be a host name or an address")),
                }
            }
            found
        }
        Some(_) => return block.fail("ssh.hosts must map a node to its address"),
    };
    let mut account = table.clone();
    account.remove("hosts");
    let (auth, disabled_algorithms) = match ssh_block(&account) {
        Ok(checked) => checked,
        Err(problem) => return block.fail(&problem),
    };
    let auth = match auth {
        "agent" => NodeAuth::Agent,
        "key" => {
            let path = account.get("key_file").map(text).unwrap_or_default();
            let path = match expand_user(&path, block.environ) {
                Ok(path) => path,
                Err(InventoryError(problem)) => return block.fail(&problem),
            };
            NodeAuth::KeyFile(block.directory.join(path))
        }
        _ => {
            let variable_name = format!("{}_SSH_PASSWORD", variable_prefix(name));
            // Reserved only when it is read: another source may name its own variables so.
            if let Some(usage) = reserved.get(&variable_name) {
                return block.fail(&format!("its variable {variable_name} is also {usage}: rename the source"));
            }
            reserved.insert(variable_name.clone(), format!("read for source {name}"));
            NodeAuth::Password(match variable(block.environ, &variable_name) {
                Some(value) => Wanted::Held(Secret::new(value)),
                None => Wanted::Missing(vec![variable_name]),
            })
        }
    };
    let username = account.get("username").map(text).unwrap_or_default();
    Ok((true, Some(NodeSsh { username, auth, disabled_algorithms, hosts })))
}

/// What a run does with a NetBox of a release this build was not tested with.
fn unsupported_version(block: &Block<'_>) -> Result<UnsupportedVersion, ConfigError> {
    match block.string("unsupported_version")?.as_deref() {
        None | Some("refuse") => Ok(UnsupportedVersion::Refuse),
        Some("warn") => Ok(UnsupportedVersion::Warn),
        Some(other) => block.refuse("unsupported_version", &format!("must be refuse or warn (got '{other}')")),
    }
}

/// The time a NetBox request may take.
fn timeout(block: &Block<'_>) -> Result<Option<Duration>, ConfigError> {
    let seconds = match block.table.get("timeout") {
        None => return Ok(None),
        Some(Value::Integer(seconds)) => u64::try_from(*seconds).ok().map(Duration::from_secs),
        Some(Value::Float(seconds)) => Duration::try_from_secs_f64(*seconds).ok(),
        Some(_) => None,
    };
    match seconds.filter(|seconds| !seconds.is_zero()) {
        Some(seconds) => Ok(Some(seconds)),
        None => block.refuse("timeout", "must be a positive number of seconds"),
    }
}

/// The names `source_priority` ranks: each one is a source of the file, once.
fn source_priority(block: &Block<'_>, names: &[String]) -> Result<Vec<String>, ConfigError> {
    let key = "source_priority";
    let items = match block.table.get(key) {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return block.refuse(key, "must be a list of source names"),
    };
    let mut ranked: Vec<String> = Vec::new();
    for item in items {
        let Value::String(name) = item else {
            return block.refuse(key, "must be a list of source names");
        };
        if !names.contains(name) {
            return block.refuse(key, &format!("names an unknown source '{name}'"));
        }
        if ranked.contains(name) {
            return block.refuse(key, &format!("names '{name}' twice"));
        }
        ranked.push(name.clone());
    }
    Ok(ranked)
}

/// The `[netbox]` block; the token the environment lacks is missing by the
/// name of its variable.
fn netbox(
    file: &str,
    data: &Table,
    directory: &Path,
    environ: &Environ,
    names: &[String],
) -> Result<Netbox, ConfigError> {
    let empty = Table::new();
    let table = match data.get("netbox") {
        None => &empty,
        Some(Value::Table(table)) => table,
        Some(_) => return invalid(format!("{file}: netbox must be a mapping")),
    };
    let block = Block { location: file.to_owned(), prefix: "netbox.", table, directory, environ };
    block.only(&NETBOX_KEYS, ": netbox: ")?;
    // The URL is not a secret: it lives in the file, NETBOX_URL overriding it.
    let Some(url) = variable(environ, "NETBOX_URL").map(str::to_owned).or(block.string("url")?) else {
        return block.fail("netbox.url is missing (or set NETBOX_URL)");
    };
    let token = match variable(environ, "NETBOX_TOKEN") {
        Some(token) => Wanted::Held(Secret::new(token)),
        None => Wanted::Missing(vec!["NETBOX_TOKEN".to_owned()]),
    };
    Ok(Netbox {
        url,
        token,
        timeout: timeout(&block)?,
        validate_certs: block.flag("validate_certs", true)?,
        ca_file: block.path("ca_file")?,
        source_priority: source_priority(&block, names)?,
        unsupported_version: unsupported_version(&block)?,
    })
}

/// The hypervisor entries and the `[netbox]` block of the `text` of the file
/// at `path`, which only serves to name the file in the errors and to resolve
/// the relative paths. The entries of another kind are left to the network
/// loader; only their names are read, to tell a duplicate.
///
/// A secret the environment does not hold is not refused here: see [`Config::require`].
pub fn parse_hypervisors(
    path: &Path,
    text_of_file: &str,
    environ: &Environ,
) -> Result<(Vec<Hypervisor>, Netbox), ConfigError> {
    let file = path.display().to_string();
    let data: Table = match text_of_file.parse() {
        Ok(data) => data,
        Err(error) => return invalid(format!("{file}: not valid TOML: {error}")),
    };
    let directory = path.parent().unwrap_or(Path::new(""));
    // A `sources` that is not a list is the network loader's to refuse.
    let entries: &[Value] = match data.get("sources") {
        Some(Value::Array(entries)) => entries,
        _ => &[],
    };
    let mut reserved = reserved_variables(entries);
    let mut names: Vec<String> = Vec::new();
    let mut tags: BTreeMap<String, String> = BTreeMap::new();
    let mut hypervisors: Vec<Hypervisor> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        // An entry that is not a table is the network loader's to refuse.
        let Value::Table(table) = entry else {
            continue;
        };
        let is_bmc = matches!(table.get("kind"), Some(Value::String(kind)) if kind == "bmc");
        let is_hypervisor = is_bmc || matches!(table.get("kind"), Some(Value::String(kind)) if kind == "hypervisor");
        let mut location = format!("{file}: source entry {}", index + 1);
        let name = match table.get("name") {
            Some(Value::String(name)) if !name.is_empty() => name.clone(),
            // The name of a network source may be written as a number.
            Some(other) if !is_hypervisor => text(other),
            None if !is_hypervisor => continue,
            Some(Value::String(_)) | None => return invalid(format!("{location}: missing name")),
            Some(_) => return invalid(format!("{location}: name must be a string")),
        };
        location = format!("{location} ({name})");
        if names.contains(&name) {
            return invalid(format!("{location}: duplicate source name"));
        }
        names.push(name.clone());
        // The ownership tag drops the case and what a slug cannot hold: two
        // names that end on one tag would own each other's objects, and a
        // source that runs alone would orphan those of the other.
        if is_hypervisor {
            let tag = crate::hypervisors::source_tag(&name);
            if let Some(owner) = tags.get(&tag) {
                return invalid(format!("{location}: its tag {tag} is the one of {owner}"));
            }
            tags.insert(tag, name.clone());
        }
        if is_hypervisor {
            let block = Block { location, prefix: "", table, directory, environ };
            let read = if is_bmc { bmc } else { hypervisor };
            hypervisors.push(read(&block, &name, &mut reserved)?);
        }
    }
    let netbox = netbox(&file, &data, directory, environ, &names)?;
    Ok((hypervisors, netbox))
}

/// Read the configuration file at `path`; see [`parse`].
pub fn load(path: &Path, environ: &Environ) -> Result<Config, ConfigError> {
    match fs::read_to_string(path) {
        Ok(text) => parse(path, &text, environ),
        Err(error) => invalid(format!("{}: cannot read the file: {error}", path.display())),
    }
}

/// Build the whole configuration from the `text` of the file at `path`: the
/// network inventory, the hypervisors and the NetBox settings.
///
/// The file is checked in full, every source of it, whatever the environment
/// holds: the secrets it lacks are told by [`Config::require`], for the
/// sources a run selects.
pub fn parse(path: &Path, text: &str, environ: &Environ) -> Result<Config, ConfigError> {
    let inventory = parse_inventory(path, text, environ)?;
    let (mut hypervisors, netbox) = parse_hypervisors(path, text, environ)?;
    let journal = journal(path, text, environ)?;
    let vlan_groups = parse_vlan_groups(path, text)?;
    // A property of the sites, not of the sources: each source follows its site.
    for source in &mut hypervisors {
        source.vlan_group = source.site.as_deref().and_then(|site| vlan_groups.group_of(site)).map(str::to_owned);
    }
    let runners = parse_runners(path, text)?;
    Ok(Config { inventory, hypervisors, netbox, journal, vlan_groups, runners })
}

/// The `runners` list of the top of the `text` of the file at `path`, and
/// the `runner` of each of its `[[sources]]`, whatever loader reads the entry:
/// which host launches which source.
///
/// All or nothing. A file with neither is run by one host. A file with a list
/// names a host of it in every entry: a misspelt `runner`, an entry without
/// one or a host that runs nothing would leave sources nobody launches, on
/// every host, without a word. The names are compared as they are written.
pub fn parse_runners(path: &Path, text_of_file: &str) -> Result<Runners, ConfigError> {
    let file = path.display().to_string();
    let data: Table = match text_of_file.parse() {
        Ok(data) => data,
        Err(error) => return invalid(format!("{file}: not valid TOML: {error}")),
    };
    let mut hosts: Vec<String> = Vec::new();
    let listed = match data.get("runners") {
        None => false,
        Some(Value::Array(names)) if !names.is_empty() => {
            for name in names {
                match name {
                    Value::String(name) if !name.is_empty() => {
                        if hosts.contains(name) {
                            return invalid(format!("{file}: runners names {name} twice"));
                        }
                        hosts.push(name.clone());
                    }
                    _ => return invalid(format!("{file}: runners must be a list of host names")),
                }
            }
            true
        }
        Some(_) => return invalid(format!("{file}: runners must be a list of host names")),
    };
    // A `sources` that is not a list is the network loader's to refuse.
    let entries: &[Value] = match data.get("sources") {
        Some(Value::Array(entries)) => entries,
        _ => &[],
    };
    let mut by_source: BTreeMap<String, String> = BTreeMap::new();
    let mut without: Vec<String> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        // An entry that is not a table or has no name is its loader's to refuse.
        let Value::Table(table) = entry else {
            continue;
        };
        let Some(name) = table.get("name").map(text) else {
            continue;
        };
        let location = format!("{file}: source entry {} ({name})", index + 1);
        let runner = match table.get("runner") {
            None => {
                without.push(name);
                continue;
            }
            Some(Value::String(runner)) if !runner.is_empty() => runner,
            Some(_) => return invalid(format!("{location}: runner must be the name of a host")),
        };
        if !listed {
            return invalid(format!(
                "{location}: runner '{runner}' without the list of the hosts (runners, at the top of the file)"
            ));
        }
        if !hosts.contains(runner) {
            return invalid(format!("{location}: runner '{runner}' is not one of runners ({})", hosts.join(", ")));
        }
        by_source.insert(name, runner.clone());
    }
    if !listed {
        return Ok(Runners::default());
    }
    if !without.is_empty() {
        return invalid(format!("{file}: runners is set and these sources have no runner: {}", without.join(", ")));
    }
    let idle: Vec<&str> =
        hosts.iter().filter(|host| !by_source.values().any(|runner| runner == *host)).map(String::as_str).collect();
    if !idle.is_empty() {
        let verb = if idle.len() == 1 { "runs" } else { "run" };
        return invalid(format!("{file}: runners names {}, which {verb} no source", idle.join(", ")));
    }
    Ok(Runners { hosts, by_source })
}

/// The `[[vlan_groups]]` tables of the `text` of the file at `path`: each
/// names a NetBox VLAN group (`name`) and the NetBox sites whose VLANs are
/// kept in it (`sites`). A site is in one group at most.
///
/// Neither the group nor the sites are created: they are checked against
/// NetBox by the run that needs them.
pub fn parse_vlan_groups(path: &Path, text_of_file: &str) -> Result<VlanGroups, ConfigError> {
    let file = path.display().to_string();
    let data: Table = match text_of_file.parse() {
        Ok(data) => data,
        Err(error) => return invalid(format!("{file}: not valid TOML: {error}")),
    };
    let tables = match data.get("vlan_groups") {
        None => return Ok(VlanGroups::default()),
        Some(Value::Array(tables)) => tables,
        Some(_) => return invalid(format!("{file}: vlan_groups must be a list of tables ([[vlan_groups]])")),
    };
    let mut groups = VlanGroups::default();
    let mut names: Vec<String> = Vec::new();
    for (index, table) in tables.iter().enumerate() {
        let mut location = format!("{file}: vlan group {}", index + 1);
        let Value::Table(table) = table else {
            return invalid(format!("{location}: must be a table"));
        };
        if let Some(key) = table.keys().find(|key| !VLAN_GROUP_KEYS.contains(&key.as_str())) {
            return invalid(format!("{location}: unknown key '{key}'"));
        }
        let name = match table.get("name") {
            Some(Value::String(name)) if !name.trim().is_empty() => name.trim().to_owned(),
            Some(Value::String(_)) | None => return invalid(format!("{location}: missing name")),
            Some(_) => return invalid(format!("{location}: name must be a string")),
        };
        location = format!("{location} ({name})");
        // Both runs find a VLAN group whatever the case of its name: two
        // names that differ by case only would name one group.
        if names.contains(&name.to_lowercase()) {
            return invalid(format!("{location}: duplicate VLAN group name"));
        }
        names.push(name.to_lowercase());
        let sites: Option<Vec<&str>> = match table.get("sites") {
            Some(Value::Array(sites)) if !sites.is_empty() => {
                sites.iter().map(|site| site.as_str().map(str::trim).filter(|site| !site.is_empty())).collect()
            }
            Some(Value::Array(_)) | None => return invalid(format!("{location}: missing sites")),
            Some(_) => None,
        };
        let Some(sites) = sites else {
            return invalid(format!("{location}: sites must be a list of NetBox site names"));
        };
        for site in sites {
            match groups.insert(site, &name) {
                None => {}
                Some(other) if other == name => {
                    return invalid(format!("{location}: site '{site}' is listed twice"));
                }
                Some(other) => {
                    return invalid(format!(
                        "{location}: site '{site}' is already in VLAN group '{other}': a site is in one group at most"
                    ));
                }
            }
        }
    }
    Ok(groups)
}

/// The `journal` key of the top of the file at `path`, whose `text` the
/// loaders above have already found to be TOML.
fn journal(path: &Path, text: &str, environ: &Environ) -> Result<Option<PathBuf>, ConfigError> {
    let file = path.display().to_string();
    let data: Table = match text.parse() {
        Ok(data) => data,
        Err(error) => return invalid(format!("{file}: not valid TOML: {error}")),
    };
    let directory = path.parent().unwrap_or(Path::new(""));
    let block = Block { location: file, prefix: "", table: &data, directory, environ };
    block.path("journal")
}

#[cfg(test)]
mod tests {
    use omnisync_core::network::inventory::load_inventory;

    use super::*;

    const FILE: &str = "/etc/omnisync/config.toml";
    const AT: &str = "/etc/omnisync/config.toml: source entry 1 (pve01.lab01)";
    const NETBOX: &str = "[netbox]\nurl = \"https://netbox.example.net\"\n";
    const PVE: &str =
        "\n[[sources]]\nname = \"pve01.lab01\"\nkind = \"hypervisor\"\ntype = \"proxmox\"\nhost = \"192.0.2.10\"\n";
    const SWITCH: &str =
        "\n[[sources]]\nname = \"nexus01.lab01\"\nkind = \"switch\"\ntype = \"nxos\"\nhost = \"192.0.2.239\"\n";
    const SSH: &str = "[ssh]\nusername = \"sync\"\nauth = \"password\"\n";
    const ENV: [(&str, &str); 2] = [("NETBOX_TOKEN", "token-value"), ("PVE01_LAB01_TOKEN", "pve-secret")];

    fn env(pairs: &[(&str, &str)]) -> Environ {
        pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    /// The NetBox block, the Proxmox entry, and `extra` keys of that entry.
    fn entry(extra: &str) -> String {
        format!("{NETBOX}{PVE}{extra}")
    }

    fn read(text: &str, environ: &[(&str, &str)]) -> (Vec<Hypervisor>, Netbox) {
        parse_hypervisors(Path::new(FILE), text, &env(environ)).unwrap()
    }

    fn one_of(hypervisors: Vec<Hypervisor>) -> Hypervisor {
        let [only]: [Hypervisor; 1] = hypervisors.try_into().unwrap();
        only
    }

    fn one(text: &str) -> Hypervisor {
        one_of(read(text, &ENV).0)
    }

    fn netbox(block: &str, environ: &[(&str, &str)]) -> Netbox {
        read(&format!("[netbox]\nurl = \"https://netbox.example.net\"\n{block}{PVE}"), environ).1
    }

    fn failure(text: &str, environ: &[(&str, &str)]) -> ConfigError {
        parse_hypervisors(Path::new(FILE), text, &env(environ)).unwrap_err()
    }

    fn message(text: &str) -> String {
        failure(text, &ENV).to_string()
    }

    fn nets(texts: &[&str]) -> Vec<IpNet> {
        texts.iter().map(|text| text.parse().unwrap()).collect()
    }

    fn vlan_groups(text: &str) -> Result<VlanGroups, String> {
        parse_vlan_groups(Path::new(FILE), text).map_err(|error| error.to_string())
    }

    #[test]
    fn a_file_without_vlan_group_keeps_every_vlan_at_its_site() {
        let config = parse(Path::new(FILE), &entry("site = \"east-02\"\n"), &env(&ENV)).unwrap();
        assert!(config.vlan_groups.is_empty());
        assert_eq!(config.hypervisors[0].vlan_group, None);
    }

    #[test]
    fn a_vlan_group_names_the_sites_whose_vlans_it_holds_and_each_source_follows_its_site() {
        let groups = "\n[[vlan_groups]]\nname = \"East\"\nsites = [\"east-02\", \"east-01\"]\n";
        let other = "\n[[sources]]\nname = \"pve02.lab01\"\nkind = \"hypervisor\"\ntype = \"proxmox\"\n\
                     host = \"192.0.2.11\"\nsite = \"Harbor\"\n";
        // The site of the source is written in another case than in the group: NetBox reads both alike.
        let text = format!("{}{other}{groups}", entry("site = \"East-02\"\n"));
        let environ = env(&[("NETBOX_TOKEN", "t"), ("PVE01_LAB01_TOKEN", "a"), ("PVE02_LAB01_TOKEN", "b")]);
        let config = parse(Path::new(FILE), &text, &environ).unwrap();
        assert_eq!(config.vlan_groups.group_of("east-02"), Some("East"));
        assert_eq!(config.vlan_groups.group_of("east-01"), Some("East"));
        assert_eq!(config.vlan_groups.group_of("Harbor"), None);
        assert_eq!(config.hypervisors[0].vlan_group.as_deref(), Some("East"));
        assert_eq!(config.hypervisors[1].vlan_group, None);
    }

    #[test]
    fn a_vlan_group_needs_a_name_and_sites_and_takes_no_other_key() {
        let at = "/etc/omnisync/config.toml: vlan group 1";
        let group = |body: &str| vlan_groups(&format!("[[vlan_groups]]\n{body}")).unwrap_err();
        assert_eq!(group("sites = [\"east-02\"]\n"), format!("{at}: missing name"));
        assert_eq!(group("name = \"\"\nsites = [\"east-02\"]\n"), format!("{at}: missing name"));
        assert_eq!(group("name = 7\nsites = [\"east-02\"]\n"), format!("{at}: name must be a string"));
        assert_eq!(group("name = \"East\"\n"), format!("{at} (East): missing sites"));
        assert_eq!(group("name = \"East\"\nsites = []\n"), format!("{at} (East): missing sites"));
        let not_names = format!("{at} (East): sites must be a list of NetBox site names");
        assert_eq!(group("name = \"East\"\nsites = \"east-02\"\n"), not_names);
        assert_eq!(group("name = \"East\"\nsites = [\"east-02\", 7]\n"), not_names);
        assert_eq!(group("name = \"East\"\nsites = [\"\"]\n"), not_names);
        assert_eq!(
            group("name = \"East\"\nsites = [\"east-02\"]\nscope = \"Paris\"\n"),
            format!("{at}: unknown key 'scope'")
        );
        assert_eq!(
            vlan_groups("vlan_groups = \"East\"\n").unwrap_err(),
            "/etc/omnisync/config.toml: vlan_groups must be a list of tables ([[vlan_groups]])"
        );
    }

    #[test]
    fn a_site_in_two_vlan_groups_is_refused_naming_the_site_and_both_groups() {
        let text = "[[vlan_groups]]\nname = \"East\"\nsites = [\"east-02\", \"east-01\"]\n\
                    [[vlan_groups]]\nname = \"Paris\"\nsites = [\"harbor\", \"East-01\"]\n";
        assert_eq!(
            vlan_groups(text).unwrap_err(),
            "/etc/omnisync/config.toml: vlan group 2 (Paris): site 'East-01' is already in VLAN group 'East': \
             a site is in one group at most"
        );
        let twice = "[[vlan_groups]]\nname = \"East\"\nsites = [\"east-02\", \"EAST-02\"]\n";
        assert_eq!(
            vlan_groups(twice).unwrap_err(),
            "/etc/omnisync/config.toml: vlan group 1 (East): site 'EAST-02' is listed twice"
        );
        let homonyms = "[[vlan_groups]]\nname = \"East\"\nsites = [\"east-02\"]\n\
                        [[vlan_groups]]\nname = \"east\"\nsites = [\"east-01\"]\n";
        assert_eq!(
            vlan_groups(homonyms).unwrap_err(),
            "/etc/omnisync/config.toml: vlan group 2 (east): duplicate VLAN group name"
        );
    }

    #[test]
    fn the_variable_prefix_is_the_upper_cased_name() {
        assert_eq!(variable_prefix("2960-stack.lab01"), "2960_STACK_LAB01");
        assert_eq!(variable_prefix("pve01.lab01"), "PVE01_LAB01");
    }

    #[test]
    fn a_minimal_entry_gets_the_defaults() {
        let pve = one(&entry(""));
        assert_eq!(
            (pve.name.as_str(), pve.r#type, pve.host.as_str()),
            ("pve01.lab01", HypervisorType::Proxmox, "192.0.2.10")
        );
        assert_eq!((pve.port, pve.validate_certs, pve.ca_file), (None, true, None));
        assert_eq!((pve.site, pve.tenant, pve.host_role, pve.vm_role, pve.domain), (None, None, None, None, None));
        assert!(pve.ignore_templates);
        assert_eq!((pve.ignored_subnets, pve.permitted_subnets), (vec![], vec![]));
        assert!(pve.interface_filter.is_none());
        // Names are not looked up unless asked.
        assert!(!pve.dns_name_lookup);
        assert_eq!(pve.dns_servers, Vec::<SocketAddr>::new());
        assert!(pve.create_devices);
        assert!(pve.prune);
    }

    #[test]
    fn every_key_of_an_entry_is_read() {
        let pve = one(&entry(concat!(
            "port = 8006\n",
            "validate_certs = false\n",
            "ca_file = \"/etc/ssl/lab-ca.pem\"\n",
            "site = \"lab01\"\n",
            "tenant = \"infra\"\n",
            "host_role = \"Hypervisor\"\n",
            "vm_role = \"Server\"\n",
            "domain = \"example.net\"\n",
            "ignore_templates = false\n",
            "ignored_subnets = [\"192.0.2.0/24\", \"2001:db8::/32\"]\n",
            "permitted_subnets = [\"198.51.100.0/24\"]\n",
            "interface_filter = \"^(lo|docker)\"\n",
            "dns_name_lookup = true\n",
            "dns_servers = [\"192.0.2.53\", \"2001:db8::53\", \"192.0.2.54:5353\", \"[2001:db8::54]:5353\"]\n",
            "create_devices = false\n",
            "prune = false\n",
        )));
        assert_eq!((pve.port, pve.validate_certs), (Some(8006), false));
        assert_eq!(pve.ca_file.as_deref(), Some(Path::new("/etc/ssl/lab-ca.pem")));
        assert_eq!(
            (pve.site.as_deref(), pve.tenant.as_deref(), pve.host_role.as_deref(), pve.vm_role.as_deref()),
            (Some("lab01"), Some("infra"), Some("Hypervisor"), Some("Server"))
        );
        assert_eq!(pve.domain.as_deref(), Some("example.net"));
        assert!(!pve.ignore_templates);
        assert_eq!(pve.ignored_subnets, nets(&["192.0.2.0/24", "2001:db8::/32"]));
        assert_eq!(pve.permitted_subnets, nets(&["198.51.100.0/24"]));
        let filter = pve.interface_filter.unwrap();
        assert!(filter.is_match("lo0"));
        assert!(!filter.is_match("eth0"));
        assert!(pve.dns_name_lookup);
        // Port 53 unless one is written.
        let servers: Vec<String> = pve.dns_servers.iter().map(ToString::to_string).collect();
        assert_eq!(servers, ["192.0.2.53:53", "[2001:db8::53]:53", "192.0.2.54:5353", "[2001:db8::54]:5353"]);
        assert!(!pve.create_devices);
        assert!(!pve.prune);
    }

    #[test]
    fn a_vmware_entry_is_a_hypervisor_too() {
        let text = entry("").replace("type = \"proxmox\"", "type = \"vmware\"");
        assert_eq!(one(&text).r#type, HypervisorType::Vmware);
    }

    #[test]
    fn a_hypervisor_is_proxmox_or_vmware() {
        let text = entry("").replace("type = \"proxmox\"", "type = \"kvm\"");
        assert_eq!(message(&text), format!("{AT}: unsupported type 'kvm' (a hypervisor is proxmox or vmware)"));
        let text = entry("").replace("type = \"proxmox\"", "type = \"nxos\"");
        assert_eq!(message(&text), format!("{AT}: unsupported type 'nxos' (a hypervisor is proxmox or vmware)"));
    }

    #[test]
    fn name_type_and_host_are_required() {
        let text = entry("").replace("name = \"pve01.lab01\"\n", "");
        assert_eq!(message(&text), format!("{FILE}: source entry 1: missing name"));
        let text = entry("").replace("type = \"proxmox\"\n", "");
        assert_eq!(message(&text), format!("{AT}: missing type"));
        let text = entry("").replace("host = \"192.0.2.10\"\n", "");
        assert_eq!(message(&text), format!("{AT}: missing host"));
        let text = entry("").replace("host = \"192.0.2.10\"", "host = \"\"");
        assert_eq!(message(&text), format!("{AT}: missing host"));
    }

    #[test]
    fn an_unknown_key_is_refused() {
        assert_eq!(message(&entry("validate_cert = false\n")), format!("{AT}: unknown key 'validate_cert'"));
        assert_eq!(message(&entry("virtual_chassis = \"x\"\n")), format!("{AT}: unknown key 'virtual_chassis'"));
    }

    const NEIGHBORS: &str = "neighbors = \"lldpd\"\n";
    const NODE_SSH: &str = "[sources.ssh]\nusername = \"lldp\"\nauth = \"password\"\n";

    #[test]
    fn a_proxmox_entry_opens_no_ssh_session_unless_it_asks_for_its_neighbours() {
        let config = parse(Path::new(FILE), &entry(""), &env(&ENV)).unwrap();
        assert!(!config.hypervisors[0].neighbors);
        assert!(config.hypervisors[0].ssh.is_none());
        // An account without the neighbours would be one that nothing uses.
        assert_eq!(message(&entry(NODE_SSH)), format!("{AT}: ssh is set but neighbors is not \"lldpd\""));
        let text = entry(&format!("{NEIGHBORS}{NODE_SSH}[sources.ssh.hosts]\npve02 = \"192.0.2.12\"\n"));
        let config = parse(Path::new(FILE), &text, &env(&ENV)).unwrap();
        let source = &config.hypervisors[0];
        assert!(source.neighbors);
        let ssh = source.ssh.as_ref().expect("the account of the nodes");
        assert_eq!(ssh.username, "lldp");
        assert_eq!(ssh.hosts, BTreeMap::from([("pve02".to_owned(), "192.0.2.12".to_owned())]));
        assert_eq!(message(&entry("neighbors = \"cdp\"\n")), format!("{AT}: neighbors must be \"lldpd\" (got 'cdp')"));
    }

    #[test]
    fn neighbours_asked_without_an_account_are_refused() {
        assert_eq!(message(&entry(NEIGHBORS)), format!("{AT}: neighbors = \"lldpd\" needs an ssh block"));
        let unknown = format!("{NEIGHBORS}[sources.ssh]\nusername = \"lldp\"\nauth = \"password\"\nport = 2222\n");
        assert!(message(&entry(&unknown)).contains("unknown key ssh.port"), "{}", message(&entry(&unknown)));
    }

    #[test]
    fn the_ssh_password_of_a_proxmox_entry_is_only_needed_by_a_run_that_reads_its_neighbours() {
        let config = parse(Path::new(FILE), &entry(&format!("{NEIGHBORS}{NODE_SSH}")), &env(&ENV)).unwrap();
        // The hypervisors alone: no node is logged into.
        assert_eq!(config.require(|_| true, false).map_err(|error| error.to_string()), Ok(()));
        assert_eq!(
            config.require(|_| true, true).unwrap_err().to_string(),
            "missing environment variables: PVE01_LAB01_SSH_PASSWORD"
        );
        let environ = [ENV[0], ENV[1], ("PVE01_LAB01_SSH_PASSWORD", "node-secret")];
        let config = parse(Path::new(FILE), &entry(&format!("{NEIGHBORS}{NODE_SSH}")), &env(&environ)).unwrap();
        assert_eq!(config.require(|_| true, true).map_err(|error| error.to_string()), Ok(()));
    }

    #[test]
    fn the_ssh_password_of_the_nodes_is_reserved_only_when_it_is_read() {
        // pve01.lab01-ssh reads PVE01_LAB01_SSH_PASSWORD as its own password.
        let other = PVE.replace("pve01.lab01", "pve01.lab01-ssh").replace("192.0.2.10", "192.0.2.11");
        assert!(parse(Path::new(FILE), &format!("{}{other}", entry("")), &env(&ENV)).is_ok());
        let reading = format!("{}{other}", entry(&format!("{NEIGHBORS}{NODE_SSH}")));
        assert_eq!(
            failure(&reading, &ENV).to_string(),
            "/etc/omnisync/config.toml: source entry 2 (pve01.lab01-ssh): its variable PVE01_LAB01_SSH_PASSWORD is \
             also read for source pve01.lab01: rename the source"
        );
    }

    #[test]
    fn a_vmware_entry_takes_no_ssh_block() {
        let vcenter = |extra: &str| entry(extra).replace("proxmox", "vmware");
        assert_eq!(
            message(&vcenter(&format!("{NEIGHBORS}{NODE_SSH}"))),
            format!("{AT}: neighbors is only read on a proxmox entry: a vCenter tells what its hosts hear")
        );
        assert_eq!(message(&vcenter(NODE_SSH)), format!("{AT}: ssh is only read on a proxmox entry"));
    }

    #[test]
    fn a_secret_written_in_the_file_is_refused_without_being_printed() {
        let error = failure(&entry("password = \"hunter2\"\n"), &ENV);
        assert_eq!(error.to_string(), format!("{AT}: unknown key 'password'"));
        assert!(!format!("{error:?}").contains("hunter2"));
    }

    #[test]
    fn a_port_is_a_number_from_1_to_65535() {
        for port in ["0", "70000", "-1", "\"8006\"", "8006.0"] {
            assert_eq!(
                message(&entry(&format!("port = {port}\n"))),
                format!("{AT}: port must be a number from 1 to 65535"),
                "{port}"
            );
        }
    }

    #[test]
    fn a_flag_is_true_or_false() {
        for key in ["validate_certs", "ignore_templates", "create_devices", "prune"] {
            assert_eq!(message(&entry(&format!("{key} = \"no\"\n"))), format!("{AT}: {key} must be true or false"));
            assert_eq!(message(&entry(&format!("{key} = 0\n"))), format!("{AT}: {key} must be true or false"));
        }
    }

    #[test]
    fn a_name_is_a_string() {
        for key in ["host", "ca_file", "site", "tenant", "host_role", "vm_role", "domain", "interface_filter"] {
            let text = entry(&format!("{key} = 12\n")).replace("host = \"192.0.2.10\"\n", "");
            let text = if key == "host" { text } else { format!("{text}host = \"192.0.2.10\"\n") };
            assert_eq!(message(&text), format!("{AT}: {key} must be a string"));
        }
    }

    #[test]
    fn an_empty_optional_name_is_left_out() {
        let pve = one(&entry("site = \"\"\ndomain = \"\"\n"));
        assert_eq!((pve.site, pve.domain), (None, None));
    }

    #[test]
    fn subnets_are_lists_of_cidr() {
        for key in ["ignored_subnets", "permitted_subnets"] {
            assert_eq!(
                message(&entry(&format!("{key} = \"192.0.2.0/24\"\n"))),
                format!("{AT}: {key} must be a list of CIDR")
            );
            assert_eq!(
                message(&entry(&format!("{key} = [\"192.0.2.0/24\", \"192.0.2.7\"]\n"))),
                format!("{AT}: {key}: '192.0.2.7' is not a CIDR")
            );
            assert_eq!(
                message(&entry(&format!("{key} = [\"192.0.2.0/33\"]\n"))),
                format!("{AT}: {key}: '192.0.2.0/33' is not a CIDR")
            );
            assert_eq!(message(&entry(&format!("{key} = [24]\n"))), format!("{AT}: {key} must be a list of CIDR"));
        }
    }

    #[test]
    fn dns_name_lookup_is_true_or_false() {
        assert_eq!(
            message(&entry("dns_name_lookup = \"yes\"\n")),
            format!("{AT}: dns_name_lookup must be true or false")
        );
        assert!(!one(&entry("dns_name_lookup = false\n")).dns_name_lookup);
    }

    #[test]
    fn dns_servers_are_a_list_of_addresses() {
        let expected = format!("{AT}: dns_servers must be a list of IP addresses");
        assert_eq!(message(&entry("dns_servers = \"192.0.2.53\"\n")), expected);
        assert_eq!(message(&entry("dns_servers = [53]\n")), expected);
        // A resolver is named by its address: resolving its name would need a resolver.
        assert_eq!(
            message(&entry("dns_servers = [\"192.0.2.53\", \"ns1.example.net\"]\n")),
            format!("{AT}: dns_servers: 'ns1.example.net' is not an IP address, with or without a port")
        );
        assert_eq!(
            message(&entry("dns_servers = [\"192.0.2.53:0\"]\n")),
            format!("{AT}: dns_servers: '192.0.2.53:0' is not an IP address, with or without a port")
        );
    }

    #[test]
    fn dns_servers_without_dns_name_lookup_are_refused() {
        // Servers that would never be asked: the key was forgotten, or the lookup turned off by mistake.
        assert_eq!(
            message(&entry("dns_servers = [\"192.0.2.53\"]\n")),
            format!("{AT}: dns_servers is set but dns_name_lookup is not true")
        );
        assert_eq!(
            message(&entry("dns_name_lookup = false\ndns_servers = [\"192.0.2.53\"]\n")),
            format!("{AT}: dns_servers is set but dns_name_lookup is not true")
        );
        // An empty list is the system resolver, asked or not.
        assert_eq!(one(&entry("dns_servers = []\n")).dns_servers, Vec::<SocketAddr>::new());
    }

    #[test]
    fn a_subnet_written_with_host_bits_is_its_network() {
        let pve = one(&entry("ignored_subnets = [\"192.0.2.7/24\"]\n"));
        assert_eq!(pve.ignored_subnets, nets(&["192.0.2.0/24"]));
    }

    #[test]
    fn an_invalid_interface_filter_is_refused_at_load() {
        let error = message(&entry("interface_filter = \"(lo\"\n"));
        let expected = format!("{AT}: interface_filter is not a valid regular expression: ");
        assert!(error.starts_with(&expected), "{error}");
    }

    #[test]
    fn a_relative_ca_file_is_relative_to_the_configuration_file() {
        let pve = one(&entry("ca_file = \"ca/lab.pem\"\n"));
        assert_eq!(pve.ca_file.as_deref(), Some(Path::new("/etc/omnisync/ca/lab.pem")));
    }

    // `~bob/ca.pem` is the home of bob for a shell; read as a relative path it
    // would become a file under the directory of the configuration.
    #[test]
    fn the_home_of_another_user_is_refused() {
        let environ = [ENV[0], ENV[1], ("HOME", "/home/sync")];
        assert_eq!(
            failure(&entry("ca_file = \"~bob/ca.pem\"\n"), &environ).to_string(),
            format!("{AT}: ca_file: ~bob is the home of another user: write the path in full")
        );
    }

    #[test]
    fn the_home_of_a_ca_file_is_expanded() {
        let environ = [ENV[0], ENV[1], ("HOME", "/home/sync")];
        let (hypervisors, _) = read(&entry("ca_file = \"~/ca/lab.pem\"\n"), &environ);
        assert_eq!(hypervisors[0].ca_file.as_deref(), Some(Path::new("/home/sync/ca/lab.pem")));
        assert_eq!(
            message(&entry("ca_file = \"~/ca/lab.pem\"\n")),
            format!("{AT}: ca_file: cannot expand ~: HOME is not set")
        );
    }

    #[test]
    fn a_token_alone_is_enough() {
        let pve = one(&entry(""));
        let token = Credentials::Token { token: Secret::new("pve-secret") };
        assert_eq!(pve.credentials, Wanted::Held(token));
        assert_eq!(pve.missing(), [] as [&str; 0]);
    }

    // A Proxmox token names its account itself (user@realm!name=secret): a
    // user name given with it would be read by nothing, and a token missing
    // its account would fail without a hint.
    #[test]
    fn a_user_name_given_with_a_token_is_refused() {
        let environ = [ENV[0], ENV[1], ("PVE01_LAB01_USERNAME", "sync@pve!omnisync")];
        let error = failure(&entry(""), &environ);
        assert_eq!(
            error.to_string(),
            format!(
                "{AT}: PVE01_LAB01_USERNAME is not read with PVE01_LAB01_TOKEN: the token names its account \
                 (user@realm!name=secret)"
            )
        );
    }

    // vSphere takes no token at all: the reader refuses it naming the user and
    // password variables, and the load never answers with the account syntax
    // of a Proxmox token.
    #[test]
    fn a_vmware_entry_given_a_user_name_and_a_token_is_left_to_its_reader() {
        let text = entry("").replace("type = \"proxmox\"", "type = \"vmware\"");
        let environ = [ENV[0], ENV[1], ("PVE01_LAB01_USERNAME", "sync@vsphere.local")];
        let (hypervisors, _) = read(&text, &environ);
        let token = Credentials::Token { token: Secret::new("pve-secret") };
        assert_eq!(one_of(hypervisors).credentials, Wanted::Held(token));
    }

    #[test]
    fn a_user_and_its_password() {
        let environ = [ENV[0], ("PVE01_LAB01_USERNAME", "sync@pve"), ("PVE01_LAB01_PASSWORD", "pve-password")];
        let (hypervisors, _) = read(&entry(""), &environ);
        let account = Credentials::Password { username: "sync@pve".to_owned(), password: Secret::new("pve-password") };
        assert_eq!(hypervisors[0].credentials, Wanted::Held(account));
    }

    #[test]
    fn a_password_and_a_token_together_are_refused_without_being_printed() {
        let environ = [ENV[0], ENV[1], ("PVE01_LAB01_USERNAME", "sync@pve"), ("PVE01_LAB01_PASSWORD", "pve-password")];
        let error = failure(&entry(""), &environ);
        assert_eq!(error.to_string(), format!("{AT}: set PVE01_LAB01_PASSWORD or PVE01_LAB01_TOKEN, not both"));
        for secret in ["pve-password", "pve-secret", "token-value"] {
            assert!(!format!("{error} {error:?}").contains(secret), "{secret} is printed");
        }
    }

    // The source is loaded all the same: the host that does not launch it
    // must still know it. What it misses is named, never guessed.
    #[test]
    fn missing_credentials_name_their_variables() {
        let missing = |environ: &[(&str, &str)]| {
            let (hypervisors, netbox) = read(&entry(""), environ);
            let pve = one_of(hypervisors);
            assert_eq!((pve.name.as_str(), pve.host.as_str()), ("pve01.lab01", "192.0.2.10"));
            [pve.missing(), netbox.token.missing()].concat()
        };
        assert_eq!(missing(&ENV), [] as [&str; 0]);
        assert_eq!(missing(&[ENV[0]]), ["PVE01_LAB01_TOKEN (or PVE01_LAB01_USERNAME and PVE01_LAB01_PASSWORD)"]);
        assert_eq!(
            missing(&[ENV[0], ("PVE01_LAB01_USERNAME", "sync@pve")]),
            ["PVE01_LAB01_PASSWORD or PVE01_LAB01_TOKEN"]
        );
        assert_eq!(missing(&[ENV[0], ("PVE01_LAB01_PASSWORD", "pve-password")]), ["PVE01_LAB01_USERNAME"]);
        // An empty variable is an unset one.
        assert_eq!(
            missing(&[ENV[0], ("PVE01_LAB01_TOKEN", "")]),
            ["PVE01_LAB01_TOKEN (or PVE01_LAB01_USERNAME and PVE01_LAB01_PASSWORD)"]
        );
        assert_eq!(missing(&[ENV[1]]), ["NETBOX_TOKEN"]);
    }

    #[test]
    fn missing_variables_print_as_one_sorted_line() {
        let config = parse(Path::new(FILE), &entry(""), &env(&[])).unwrap();
        let error = config.require(|_| true, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "missing environment variables: NETBOX_TOKEN, \
             PVE01_LAB01_TOKEN (or PVE01_LAB01_USERNAME and PVE01_LAB01_PASSWORD)"
        );
    }

    // What cannot be read cannot be mistaken for an account: there is no
    // value to take, only the refusal that names the variables.
    #[test]
    fn a_source_without_its_account_holds_none_and_says_which_variables_would_give_it() {
        let pve = one_of(read(&entry(""), &[ENV[0], ("PVE01_LAB01_USERNAME", "sentinel-user")]).0);
        assert_eq!(pve.credentials, Wanted::Missing(vec!["PVE01_LAB01_PASSWORD or PVE01_LAB01_TOKEN".to_owned()]));
        let refusal = pve.credentials.held().unwrap_err();
        assert_eq!(refusal.to_string(), "missing environment variables: PVE01_LAB01_PASSWORD or PVE01_LAB01_TOKEN");
        // Half an account is not kept.
        assert!(!format!("{pve:?} {refusal:?}").contains("sentinel-user"));
    }

    #[test]
    fn secrets_never_show_in_debug_output() {
        let environ = [ENV[0], ("PVE01_LAB01_USERNAME", "sync@pve"), ("PVE01_LAB01_PASSWORD", "pve-password")];
        let with_password = parse(Path::new(FILE), &entry(""), &env(&environ)).unwrap();
        let with_token = parse(Path::new(FILE), &entry(""), &env(&ENV)).unwrap();
        for config in [with_password, with_token] {
            let printed = format!("{config:?} {config:#?}");
            for secret in ["token-value", "pve-password", "pve-secret"] {
                assert!(!printed.contains(secret), "{secret} is printed");
            }
        }
    }

    #[test]
    fn two_sources_cannot_share_a_name() {
        let text = format!("{}{PVE}", entry(""));
        assert_eq!(message(&text), format!("{FILE}: source entry 2 (pve01.lab01): duplicate source name"));
    }

    // The ownership tag drops the case and what a slug cannot hold: two such
    // names would own each other's objects, and one orphan the other's.
    #[test]
    fn two_sources_cannot_share_an_ownership_tag() {
        for other in ["pve01lab01", "PVE01.LAB01"] {
            let text = format!("{}{}", entry(""), PVE.replace("\"pve01.lab01\"", &format!("\"{other}\"")));
            assert_eq!(
                message(&text),
                format!("{FILE}: source entry 2 ({other}): its tag source-pve01lab01 is the one of pve01.lab01")
            );
        }
    }

    #[test]
    fn a_hypervisor_cannot_take_the_name_of_a_network_source() {
        let switch = SWITCH.replace("nexus01.lab01", "pve01.lab01");
        let text = format!("{NETBOX}{switch}{PVE}");
        assert_eq!(message(&text), format!("{FILE}: source entry 2 (pve01.lab01): duplicate source name"));
        let text = format!("{NETBOX}{PVE}{switch}");
        assert_eq!(message(&text), format!("{FILE}: source entry 2 (pve01.lab01): duplicate source name"));
    }

    #[test]
    fn two_hypervisors_cannot_read_the_same_variables() {
        let text = format!("{}{}", entry(""), PVE.replace("pve01.lab01", "pve01-lab01"));
        assert_eq!(
            message(&text),
            format!(
                "{FILE}: source entry 2 (pve01-lab01): its variable PVE01_LAB01_USERNAME is also read for source \
                 pve01.lab01: rename the source"
            )
        );
    }

    #[test]
    fn a_hypervisor_never_reads_the_variables_of_netbox_or_of_the_switches() {
        let named = |name: &str| format!("{NETBOX}{SWITCH}{}", PVE.replace("pve01.lab01", name));
        let at = |name: &str| format!("{FILE}: source entry 2 ({name})");
        assert_eq!(
            message(&named("netbox")),
            format!("{}: its variable NETBOX_TOKEN is also the NetBox token: rename the source", at("netbox"))
        );
        assert_eq!(
            message(&named("switch")),
            format!(
                "{}: its variable SWITCH_USERNAME is also the user name common to the switches: rename the source",
                at("switch")
            )
        );
        assert_eq!(
            message(&named("switch-nexus01.lab01")),
            format!(
                "{}: its variable SWITCH_NEXUS01_LAB01_PASSWORD is also read for source nexus01.lab01: \
                 rename the source",
                at("switch-nexus01.lab01")
            )
        );
        let firewall = "\n[[sources]]\nname = \"fw01.lab01\"\nkind = \"firewall\"\ntype = \"fortios\"\n";
        let text = format!("{NETBOX}{firewall}{}", PVE.replace("pve01.lab01", "firewall-fw01.lab01"));
        assert_eq!(
            message(&text),
            format!(
                "{}: its variable FIREWALL_FW01_LAB01_USERNAME is also read for source fw01.lab01: rename the source",
                at("firewall-fw01.lab01")
            )
        );
        // The variables of a switch are not those of a firewall of the same name.
        let (hypervisors, _) = read(&named("firewall-nexus01.lab01"), &[ENV[0], ("FIREWALL_NEXUS01_LAB01_TOKEN", "x")]);
        assert_eq!(hypervisors[0].name, "firewall-nexus01.lab01");
    }

    #[test]
    fn the_netbox_block_defaults() {
        let netbox = netbox("", &ENV);
        assert_eq!(
            netbox,
            Netbox {
                url: "https://netbox.example.net".to_owned(),
                token: Wanted::Held(Secret::new("token-value")),
                timeout: None,
                validate_certs: true,
                ca_file: None,
                source_priority: vec![],
                unsupported_version: UnsupportedVersion::Refuse,
            }
        );
    }

    #[test]
    fn every_key_of_the_netbox_block_is_read() {
        let block = "timeout = 30\nvalidate_certs = false\nca_file = \"ca.pem\"\nsource_priority = [\"pve01.lab01\"]\n";
        let netbox = netbox(block, &ENV);
        assert_eq!(netbox.timeout, Some(Duration::from_secs(30)));
        assert!(!netbox.validate_certs);
        assert_eq!(netbox.ca_file.as_deref(), Some(Path::new("/etc/omnisync/ca.pem")));
        assert_eq!(netbox.source_priority, ["pve01.lab01"]);
    }

    // A NetBox release this build was not tested with is refused unless the
    // file says to warn: after an upgrade of NetBox, the operator chooses
    // between a stopped sync and a sync that may write wrong values.
    #[test]
    fn what_to_do_with_an_untested_netbox_release_is_refuse_unless_told_to_warn() {
        assert_eq!(netbox("", &ENV).unsupported_version, UnsupportedVersion::Refuse);
        assert_eq!(netbox("unsupported_version = \"refuse\"\n", &ENV).unsupported_version, UnsupportedVersion::Refuse);
        assert_eq!(netbox("unsupported_version = \"warn\"\n", &ENV).unsupported_version, UnsupportedVersion::Warn);
        let text = format!("[netbox]\nurl = \"https://netbox.example.net\"\nunsupported_version = \"ignore\"\n{PVE}");
        assert_eq!(message(&text), format!("{FILE}: netbox.unsupported_version must be refuse or warn (got 'ignore')"));
    }

    #[test]
    fn netbox_url_of_the_environment_wins() {
        let environ = [ENV[0], ENV[1], ("NETBOX_URL", "https://other.example.net")];
        assert_eq!(netbox("", &environ).url, "https://other.example.net");
        let text = format!("[netbox]\ntimeout = 30\n{PVE}");
        assert_eq!(read(&text, &environ).1.url, "https://other.example.net");
        assert_eq!(message(&text), format!("{FILE}: netbox.url is missing (or set NETBOX_URL)"));
        assert_eq!(message(PVE), format!("{FILE}: netbox.url is missing (or set NETBOX_URL)"));
    }

    #[test]
    fn the_netbox_timeout_is_a_positive_number_of_seconds() {
        assert_eq!(netbox("timeout = 2.5\n", &ENV).timeout, Some(Duration::from_millis(2500)));
        for timeout in ["0", "-1", "\"30\"", "0.0", "nan", "inf"] {
            let text = format!("[netbox]\nurl = \"https://netbox.example.net\"\ntimeout = {timeout}\n{PVE}");
            assert_eq!(
                message(&text),
                format!("{FILE}: netbox.timeout must be a positive number of seconds"),
                "{timeout}"
            );
        }
    }

    #[test]
    fn the_netbox_flag_and_path_are_typed() {
        let block = |line: &str| format!("[netbox]\nurl = \"https://netbox.example.net\"\n{line}\n{PVE}");
        assert_eq!(
            message(&block("validate_certs = \"false\"")),
            format!("{FILE}: netbox.validate_certs must be true or false")
        );
        assert_eq!(message(&block("ca_file = 12")), format!("{FILE}: netbox.ca_file must be a string"));
    }

    #[test]
    fn an_unknown_netbox_key_is_refused() {
        let text = format!("[netbox]\nurl = \"https://netbox.example.net\"\nsource_priorty = []\n{PVE}");
        assert_eq!(message(&text), format!("{FILE}: netbox: unknown key 'source_priorty'"));
        let text = format!("[netbox]\nurl = \"https://netbox.example.net\"\ntoken = \"hunter2\"\n{PVE}");
        let error = failure(&text, &ENV);
        assert_eq!(error.to_string(), format!("{FILE}: netbox: unknown key 'token'"));
        assert!(!format!("{error:?}").contains("hunter2"));
    }

    #[test]
    fn the_source_priority_names_existing_sources() {
        let block = |line: &str| format!("[netbox]\nurl = \"https://netbox.example.net\"\n{line}\n{SWITCH}{PVE}");
        let (_, netbox) = read(&block("source_priority = [\"pve01.lab01\", \"nexus01.lab01\"]"), &ENV);
        assert_eq!(netbox.source_priority, ["pve01.lab01", "nexus01.lab01"]);
        assert_eq!(
            message(&block("source_priority = [\"pve01.lab01\", \"pve02.lab01\"]")),
            format!("{FILE}: netbox.source_priority names an unknown source 'pve02.lab01'")
        );
        assert_eq!(
            message(&block("source_priority = [\"pve01.lab01\", \"pve01.lab01\"]")),
            format!("{FILE}: netbox.source_priority names 'pve01.lab01' twice")
        );
        assert_eq!(
            message(&block("source_priority = \"pve01.lab01\"")),
            format!("{FILE}: netbox.source_priority must be a list of source names")
        );
        assert_eq!(
            message(&block("source_priority = [1]")),
            format!("{FILE}: netbox.source_priority must be a list of source names")
        );
    }

    // A key of the top of the file, written before the first table: a path
    // read as `ca_file` is, relative to the configuration file.
    #[test]
    fn the_journal_is_a_path_relative_to_the_configuration_file() {
        let journal = |line: &str| parse(Path::new(FILE), &format!("{line}{NETBOX}{PVE}"), &env(&ENV)).unwrap().journal;
        assert_eq!(journal(""), None);
        assert_eq!(
            journal("journal = \"state/journal.jsonl\"\n"),
            Some(PathBuf::from("/etc/omnisync/state/journal.jsonl"))
        );
        assert_eq!(
            journal("journal = \"/var/lib/netbox-omnisync/journal.jsonl\"\n"),
            Some(PathBuf::from("/var/lib/netbox-omnisync/journal.jsonl"))
        );
        let refused = parse(Path::new(FILE), &format!("journal = 12\n{NETBOX}{PVE}"), &env(&ENV)).unwrap_err();
        assert_eq!(refused.to_string(), format!("{FILE}: journal must be a string"));
    }

    const RUNNERS: &str = "runners = [\"sync01.lab01\", \"sat01.lab02\"]\n";
    const ON_SYNC01: &str = "runner = \"sync01.lab01\"\n";
    const ON_SAT01: &str = "runner = \"sat01.lab02\"\n";

    fn runners(text: &str) -> Result<Runners, String> {
        parse(Path::new(FILE), text, &env(&ENV)).map(|config| config.runners).map_err(|error| error.to_string())
    }

    // The same file on every host: each entry says which one launches it,
    // whatever reads the entry (the network loader, a hypervisor, a BMC).
    #[test]
    fn a_source_names_the_host_that_runs_it() {
        let bmc = format!("{BMC}{BY_PATTERN}");
        let text = format!("{RUNNERS}{NETBOX}{SSH}{SWITCH}{ON_SYNC01}{PVE}{ON_SAT01}{bmc}{ON_SAT01}");
        let runners = runners(&text).unwrap();
        assert_eq!(runners.hosts(), ["sync01.lab01", "sat01.lab02"]);
        assert_eq!(runners.of("nexus01.lab01"), Some("sync01.lab01"));
        assert_eq!(runners.of("pve01.lab01"), Some("sat01.lab02"));
        assert_eq!(runners.of("bmc.lab01"), Some("sat01.lab02"));
        assert_eq!(runners.of("pve09.lab01"), None);
        assert!(!runners.is_empty());
    }

    #[test]
    fn a_file_without_runner_is_run_by_one_host() {
        let runners = runners(&format!("{NETBOX}{SSH}{SWITCH}{PVE}")).unwrap();
        assert!(runners.is_empty());
        assert_eq!(runners.hosts(), [] as [&str; 0]);
        assert_eq!((runners.of("nexus01.lab01"), runners.of("pve01.lab01")), (None, None));
    }

    #[test]
    fn a_runner_on_some_sources_only_is_refused_naming_the_others() {
        let bmc = format!("{BMC}{BY_PATTERN}");
        let text = format!("{RUNNERS}{NETBOX}{SSH}{SWITCH}{PVE}{ON_SAT01}{bmc}");
        assert_eq!(
            runners(&text).unwrap_err(),
            format!("{FILE}: runners is set and these sources have no runner: nexus01.lab01, bmc.lab01")
        );
    }

    #[test]
    fn a_runner_that_is_not_in_the_list_is_refused() {
        let text = format!("{RUNNERS}{NETBOX}{PVE}runner = \"sat1.lab02\"\n");
        assert_eq!(
            runners(&text).unwrap_err(),
            format!("{AT}: runner 'sat1.lab02' is not one of runners (sync01.lab01, sat01.lab02)")
        );
        // The short name of a host of the list is not its name.
        let text = format!("{RUNNERS}{NETBOX}{PVE}runner = \"sat01\"\n");
        assert_eq!(
            runners(&text).unwrap_err(),
            format!("{AT}: runner 'sat01' is not one of runners (sync01.lab01, sat01.lab02)")
        );
        for wrong in ["runner = 12\n", "runner = \"\"\n", "runner = [\"sat01.lab02\"]\n"] {
            let text = format!("{RUNNERS}{NETBOX}{PVE}{wrong}");
            assert_eq!(runners(&text).unwrap_err(), format!("{AT}: runner must be the name of a host"), "{wrong}");
        }
    }

    #[test]
    fn a_runner_without_a_list_is_refused() {
        let text = format!("{NETBOX}{PVE}{ON_SAT01}");
        assert_eq!(
            runners(&text).unwrap_err(),
            format!("{AT}: runner 'sat01.lab02' without the list of the hosts (runners, at the top of the file)")
        );
        // The network loader takes the key too, and the list is asked for all the same.
        let text = format!("{NETBOX}{SSH}{SWITCH}{ON_SYNC01}");
        assert_eq!(
            runners(&text).unwrap_err(),
            format!(
                "{FILE}: source entry 1 (nexus01.lab01): runner 'sync01.lab01' without the list of the hosts \
                 (runners, at the top of the file)"
            )
        );
    }

    #[test]
    fn a_host_of_the_list_that_runs_no_source_is_refused() {
        let text = format!("{RUNNERS}{NETBOX}{SSH}{SWITCH}{ON_SYNC01}{PVE}{ON_SYNC01}");
        assert_eq!(runners(&text).unwrap_err(), format!("{FILE}: runners names sat01.lab02, which runs no source"));
        let text = format!("runners = [\"sync01.lab01\", \"sat01.lab02\", \"sat02.lab03\"]\n{NETBOX}{PVE}{ON_SYNC01}");
        assert_eq!(
            runners(&text).unwrap_err(),
            format!("{FILE}: runners names sat01.lab02, sat02.lab03, which run no source")
        );
    }

    #[test]
    fn a_host_listed_twice_or_empty_is_refused() {
        let listed = |list: &str| runners(&format!("runners = {list}\n{NETBOX}{PVE}{ON_SYNC01}")).unwrap_err();
        assert_eq!(listed("[\"sync01.lab01\", \"sync01.lab01\"]"), format!("{FILE}: runners names sync01.lab01 twice"));
        assert_eq!(listed("[\"sync01.lab01\", \"\"]"), format!("{FILE}: runners must be a list of host names"));
        assert_eq!(listed("[\"sync01.lab01\", 12]"), format!("{FILE}: runners must be a list of host names"));
        assert_eq!(listed("\"sync01.lab01\""), format!("{FILE}: runners must be a list of host names"));
        // A list without a host says nothing of who runs what.
        assert_eq!(listed("[]"), format!("{FILE}: runners must be a list of host names"));
    }

    #[test]
    fn a_file_that_is_not_toml_is_refused() {
        let error = message("[netbox\n");
        assert!(error.starts_with(&format!("{FILE}: not valid TOML: ")), "{error}");
    }

    #[test]
    fn the_network_sources_are_left_to_the_network_loader() {
        let text = format!("{NETBOX}{SSH}{SWITCH}{PVE}");
        let environ = [ENV[0], ENV[1], ("SWITCH_PASSWORD", "pw-switch")];
        let config = parse(Path::new(FILE), &text, &env(&environ)).unwrap();
        let network: Vec<&str> = config.inventory.sources.iter().map(|source| source.name.as_str()).collect();
        let hypervisors: Vec<&str> = config.hypervisors.iter().map(|source| source.name.as_str()).collect();
        assert_eq!((network, hypervisors), (vec!["nexus01.lab01"], vec!["pve01.lab01"]));
        assert_eq!(config.netbox.url, "https://netbox.example.net");
        assert_eq!(config.inventory.netbox_url, "https://netbox.example.net");
    }

    #[test]
    fn a_file_without_hypervisors_is_a_configuration() {
        let text = format!("{NETBOX}{SSH}{SWITCH}");
        let config = parse(Path::new(FILE), &text, &env(&[ENV[0], ("SWITCH_PASSWORD", "pw-switch")])).unwrap();
        assert_eq!(config.inventory.sources.len(), 1);
        assert!(config.hypervisors.is_empty());
    }

    #[test]
    fn every_missing_variable_is_reported_at_once() {
        let text = format!("{NETBOX}{SSH}{SWITCH}{PVE}");
        let config = parse(Path::new(FILE), &text, &env(&[])).unwrap();
        let error = config.require(|_| true, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "missing environment variables: NETBOX_TOKEN, \
             PVE01_LAB01_TOKEN (or PVE01_LAB01_USERNAME and PVE01_LAB01_PASSWORD), \
             SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD"
        );
    }

    /// A Proxmox, a vCenter, a BMC entry, a switch read with a password and a firewall.
    fn five_sources() -> String {
        let vcenter = PVE.replace("pve01.lab01", "vc01.lab01").replace("proxmox", "vmware");
        let firewall = "\n[[sources]]\nname = \"fw01.lab01\"\nkind = \"firewall\"\ntype = \"fortios\"\n\
                        host = \"192.0.2.1\"\ntls_fingerprint = \"abababababababababababababababababababababababababababababababab\"\n";
        format!("{NETBOX}{SSH}{SWITCH}{PVE}{vcenter}{BMC}{BY_PATTERN}{firewall}")
    }

    const PVE_VARIABLES: &str = "PVE01_LAB01_TOKEN (or PVE01_LAB01_USERNAME and PVE01_LAB01_PASSWORD)";
    const VCENTER_VARIABLES: &str = "VC01_LAB01_TOKEN (or VC01_LAB01_USERNAME and VC01_LAB01_PASSWORD)";
    const SWITCH_VARIABLES: &str = "SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD";

    /// The variables a run of the sources named in `selected` is refused for.
    fn required(config: &Config, selected: &[&str]) -> Vec<String> {
        match config.require(|name| selected.contains(&name), false) {
            Ok(()) => Vec::new(),
            Err(ConfigError::MissingVariables(MissingVariables(variables))) => variables,
            Err(other) => panic!("{other}"),
        }
    }

    // The same file on every host: each one holds the secrets of the sources
    // it launches, and is asked for no other.
    #[test]
    fn a_run_is_only_refused_for_the_secrets_of_the_sources_it_selects() {
        // A host that holds nothing but the token of NetBox still loads the five sources.
        let config = parse(Path::new(FILE), &five_sources(), &env(&[ENV[0]])).unwrap();
        let network: Vec<&str> = config.inventory.sources.iter().map(|source| source.name.as_str()).collect();
        let hypervisors: Vec<&str> = config.hypervisors.iter().map(|source| source.name.as_str()).collect();
        assert_eq!(network, ["nexus01.lab01", "fw01.lab01"]);
        assert_eq!(hypervisors, ["pve01.lab01", "vc01.lab01", "bmc.lab01"]);
        // Each kind of secret, for its source alone.
        assert_eq!(required(&config, &["pve01.lab01"]), [PVE_VARIABLES]);
        assert_eq!(required(&config, &["vc01.lab01"]), [VCENTER_VARIABLES]);
        assert_eq!(required(&config, &["bmc.lab01"]), ["BMC_LAB01_PASSWORD", "BMC_LAB01_USERNAME"]);
        assert_eq!(required(&config, &["nexus01.lab01"]), [SWITCH_VARIABLES]);
        assert_eq!(
            required(&config, &["fw01.lab01"]),
            ["FIREWALL_FW01_LAB01_PASSWORD", "FIREWALL_FW01_LAB01_USERNAME"]
        );
        // Several sources: all their variables, sorted.
        assert_eq!(
            required(&config, &["vc01.lab01", "nexus01.lab01", "bmc.lab01"]),
            ["BMC_LAB01_PASSWORD", "BMC_LAB01_USERNAME", SWITCH_VARIABLES, VCENTER_VARIABLES]
        );
        // Every source: every secret.
        let every = ["nexus01.lab01", "fw01.lab01", "pve01.lab01", "vc01.lab01", "bmc.lab01"];
        assert_eq!(
            required(&config, &every),
            [
                "BMC_LAB01_PASSWORD",
                "BMC_LAB01_USERNAME",
                "FIREWALL_FW01_LAB01_PASSWORD",
                "FIREWALL_FW01_LAB01_USERNAME",
                PVE_VARIABLES,
                SWITCH_VARIABLES,
                VCENTER_VARIABLES
            ]
        );
        // The host that holds the secrets of one source runs it, and only it.
        let config = parse(Path::new(FILE), &five_sources(), &env(&ENV)).unwrap();
        assert_eq!(required(&config, &["pve01.lab01"]), [] as [&str; 0]);
        assert_eq!(required(&config, &["pve01.lab01", "vc01.lab01"]), [VCENTER_VARIABLES]);
    }

    #[test]
    fn the_netbox_token_is_required_whatever_is_selected() {
        let config = parse(Path::new(FILE), &five_sources(), &env(&[ENV[1]])).unwrap();
        assert_eq!(required(&config, &["pve01.lab01"]), ["NETBOX_TOKEN"]);
        assert_eq!(required(&config, &[]), ["NETBOX_TOKEN"]);
        assert_eq!(required(&config, &["nexus01.lab01"]), ["NETBOX_TOKEN", SWITCH_VARIABLES]);
    }

    #[test]
    fn the_password_shared_by_the_switches_is_required_by_a_selected_switch_only() {
        let shared = [ENV[0], ("SWITCH_PASSWORD", "pw-switch")];
        let config = parse(Path::new(FILE), &five_sources(), &env(&shared)).unwrap();
        assert_eq!(required(&config, &["nexus01.lab01"]), [] as [&str; 0]);
        let config = parse(Path::new(FILE), &five_sources(), &env(&ENV)).unwrap();
        assert_eq!(required(&config, &["pve01.lab01"]), [] as [&str; 0]);
        assert_eq!(required(&config, &["nexus01.lab01"]), [SWITCH_VARIABLES]);
    }

    // A typo is an error on every host, whichever sources it launches and
    // whatever secrets it holds.
    #[test]
    fn an_invalid_entry_is_refused_whatever_the_environment_holds() {
        let refused = |text: &str| parse(Path::new(FILE), text, &env(&[])).unwrap_err().to_string();
        let text = five_sources().replace("type = \"vmware\"\n", "type = \"vmware\"\ninterface_filter = \"(\"\n");
        let message = refused(&text);
        let expected =
            format!("{FILE}: source entry 3 (vc01.lab01): interface_filter is not a valid regular expression: ");
        assert!(message.starts_with(&expected), "{message}");
        let text =
            five_sources().replace("type = \"vmware\"\n", "type = \"vmware\"\nignored_subnets = [\"10.0.0.0/33\"]\n");
        assert_eq!(
            refused(&text),
            format!("{FILE}: source entry 3 (vc01.lab01): ignored_subnets: '10.0.0.0/33' is not a CIDR")
        );
        let text = five_sources().replace(BY_PATTERN, "devices = [\"pve01.lab01\"]\n");
        assert_eq!(
            refused(&text),
            format!(
                "{FILE}: source entry 4 (bmc.lab01): \
                 devices needs bmc_pattern to name their BMC (or give each address in bmcs)"
            )
        );
        let text = five_sources().replace("abab", "xyxy");
        assert_eq!(
            refused(&text),
            "fw01.lab01: tls_fingerprint must be the SHA-256 of the certificate \
             (64 hexadecimal digits, colons allowed)"
        );
        let text = five_sources().replace("type = \"nxos\"", "type = \"eos\"");
        assert_eq!(refused(&text), "nexus01.lab01: unsupported type 'eos'");
        let text = five_sources().replace(NETBOX, "[netbox]\nurl = \"https://netbox.example.net\"\ntimeout = 0\n");
        assert_eq!(refused(&text), format!("{FILE}: netbox.timeout must be a positive number of seconds"));
    }

    #[test]
    fn no_secret_a_host_holds_shows_in_the_refusal_of_a_run_nor_in_what_is_loaded() {
        let environ = [
            ("NETBOX_TOKEN", "sentinel-token"),
            ("PVE01_LAB01_TOKEN", "sentinel-pve"),
            ("VC01_LAB01_PASSWORD", "sentinel-vc"),
            ("BMC_LAB01_USERNAME", "sentinel-bmc"),
            ("FIREWALL_FW01_LAB01_PASSWORD", "sentinel-forti"),
        ];
        let config = parse(Path::new(FILE), &five_sources(), &env(&environ)).unwrap();
        let error = config.require(|_| true, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "missing environment variables: BMC_LAB01_PASSWORD, FIREWALL_FW01_LAB01_USERNAME, \
             SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD, VC01_LAB01_USERNAME"
        );
        let printed = format!("{error} {error:?} {config:?} {config:#?}");
        for (_, value) in environ {
            assert!(!printed.contains(value), "{value} is printed");
        }
    }

    #[test]
    fn an_error_of_the_network_loader_comes_in_its_own_words() {
        let text = format!("{NETBOX}{SSH}{SWITCH}{PVE}").replace("type = \"nxos\"", "type = \"eos\"");
        let error = parse(Path::new(FILE), &text, &env(&ENV)).unwrap_err();
        assert_eq!(error.to_string(), "nexus01.lab01: unsupported type 'eos'");
    }

    #[test]
    fn an_invalid_hypervisor_stops_a_valid_network_inventory() {
        let text = format!("{NETBOX}{SSH}{SWITCH}{PVE}prune = \"yes\"\n");
        let environ = [ENV[0], ENV[1], ("SWITCH_PASSWORD", "pw-switch")];
        let error = parse(Path::new(FILE), &text, &env(&environ)).unwrap_err();
        assert_eq!(error.to_string(), format!("{FILE}: source entry 2 (pve01.lab01): prune must be true or false"));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent.toml");
        let error = load(&path, &env(&ENV)).unwrap_err().to_string();
        assert!(error.starts_with(&format!("{}: cannot read the file: ", path.display())), "{error}");
    }

    // The `bmc` entries

    const BMC: &str = "\n[[sources]]\nname = \"bmc.lab01\"\nkind = \"bmc\"\ntype = \"redfish\"\n";
    const BMC_AT: &str = "/etc/omnisync/config.toml: source entry 1 (bmc.lab01)";
    const BMC_ENV: [(&str, &str); 3] =
        [("NETBOX_TOKEN", "token-value"), ("BMC_LAB01_USERNAME", "netbox-ro"), ("BMC_LAB01_PASSWORD", "pw-bmc")];
    const BY_PATTERN: &str = "devices = [\"pve01.lab01\", \"pve02.lab01\"]\nbmc_pattern = \"drac-{name}\"\n";

    /// The NetBox block, the bmc entry, and `extra` keys of that entry.
    fn bmc_entry(extra: &str) -> String {
        format!("{NETBOX}{BMC}{extra}")
    }

    fn one_bmc(text: &str) -> Hypervisor {
        let (hypervisors, _) = read(text, &BMC_ENV);
        let [only]: [Hypervisor; 1] = hypervisors.try_into().unwrap();
        only
    }

    fn bmc_message(extra: &str) -> String {
        failure(&bmc_entry(extra), &BMC_ENV).to_string()
    }

    fn documented(source: &Hypervisor) -> Vec<(&str, &str)> {
        source.bmcs.iter().map(|bmc| (bmc.device.as_str(), bmc.host.as_str())).collect()
    }

    #[test]
    fn a_bmc_entry_names_the_bmc_of_each_device_after_the_pattern() {
        let source = one_bmc(&bmc_entry(BY_PATTERN));
        assert_eq!((source.name.as_str(), source.r#type), ("bmc.lab01", HypervisorType::Redfish));
        assert!(source.r#type.is_bmc() && !HypervisorType::Proxmox.is_bmc() && !HypervisorType::Vmware.is_bmc());
        // The site convention: the BMC of `<name>.<domain>` is `drac-<name>.<domain>`.
        assert_eq!(documented(&source), [("pve01.lab01", "drac-pve01.lab01"), ("pve02.lab01", "drac-pve02.lab01")]);
        // Nothing of a hypervisor: no host, no site.
        assert_eq!((source.host.as_str(), source.site.as_deref()), ("", None));
        assert_eq!((source.port, source.validate_certs, source.ca_file.as_ref()), (None, true, None));
        let account = Credentials::Password { username: "netbox-ro".to_owned(), password: Secret::new("pw-bmc") };
        assert_eq!(source.credentials, Wanted::Held(account));
    }

    // A BMC carries the self-signed certificate it was shipped with: each one
    // is pinned by the SHA-256 of its own, as `openssl x509 -fingerprint -sha256`
    // prints it.
    #[test]
    fn the_certificate_of_each_bmc_is_pinned_by_its_device() {
        let pin = "AB:".repeat(31) + "AB";
        let extra = format!("{BY_PATTERN}tls_fingerprints = {{ \"pve02.lab01\" = \"{pin}\" }}\n");
        let source = one_bmc(&bmc_entry(&extra));
        let pinned: Vec<(&str, bool)> =
            source.bmcs.iter().map(|bmc| (bmc.device.as_str(), bmc.fingerprint.is_some())).collect();
        assert_eq!(pinned, [("pve01.lab01", false), ("pve02.lab01", true)]);
        assert_eq!(source.bmcs[1].fingerprint, Some(omnisync_tls::Fingerprint::parse(&pin).unwrap()));

        let elsewhere = format!("{BY_PATTERN}tls_fingerprints = {{ \"pve09.lab01\" = \"{pin}\" }}\n");
        assert_eq!(
            bmc_message(&elsewhere),
            format!("{BMC_AT}: tls_fingerprints names pve09.lab01, which is not one of its devices")
        );
        let sha1 = format!("{BY_PATTERN}tls_fingerprints = {{ \"pve01.lab01\" = \"{}\" }}\n", "ab".repeat(20));
        assert_eq!(
            bmc_message(&sha1),
            format!(
                "{BMC_AT}: tls_fingerprints of pve01.lab01 must be the SHA-256 of the certificate \
                 (64 hexadecimal digits, colons allowed)"
            )
        );
        // Two keys for one device, read caselessly: the last would win silently.
        let other = "CD:".repeat(31) + "CD";
        let twice = format!(
            "{BY_PATTERN}tls_fingerprints = {{ \"pve01.lab01\" = \"{pin}\", \"PVE01.lab01\" = \"{other}\" }}\n"
        );
        assert_eq!(bmc_message(&twice), format!("{BMC_AT}: tls_fingerprints names pve01.lab01 twice"));
    }

    #[test]
    fn a_bmc_entry_gives_the_address_of_a_bmc_that_does_not_follow_the_pattern() {
        let table = "\n[sources.bmcs]\n\"esx01.lab01\" = \"ilo-esx01.example.net\"\n\"esx02.lab01\" = \"192.0.2.62\"\n";
        // Alone.
        let source = one_bmc(&bmc_entry(table));
        assert_eq!(documented(&source), [("esx01.lab01", "ilo-esx01.example.net"), ("esx02.lab01", "192.0.2.62")]);
        // With the devices of the pattern, which come first.
        let source = one_bmc(&bmc_entry(&format!("{BY_PATTERN}{table}")));
        assert_eq!(
            documented(&source),
            [
                ("pve01.lab01", "drac-pve01.lab01"),
                ("pve02.lab01", "drac-pve02.lab01"),
                ("esx01.lab01", "ilo-esx01.example.net"),
                ("esx02.lab01", "192.0.2.62"),
            ]
        );
        // The pattern may be an address scheme as well as a name.
        let source = one_bmc(&bmc_entry("devices = [\"pve01\"]\nbmc_pattern = \"{name}.oob.example.net\"\n"));
        assert_eq!(documented(&source), [("pve01", "pve01.oob.example.net")]);
    }

    #[test]
    fn the_connection_keys_of_a_bmc_entry_are_read() {
        let extra = format!("{BY_PATTERN}port = 8443\nvalidate_certs = false\nca_file = \"ca/oob.pem\"\n");
        let source = one_bmc(&bmc_entry(&extra));
        assert_eq!((source.port, source.validate_certs), (Some(8443), false));
        assert_eq!(source.ca_file.as_deref(), Some(Path::new("/etc/omnisync/ca/oob.pem")));
    }

    #[test]
    fn a_bmc_entry_never_creates_nor_prunes_and_refuses_to_be_told_to() {
        // Left out: both are off, where a hypervisor has them on.
        let source = one_bmc(&bmc_entry(BY_PATTERN));
        assert_eq!((source.create_devices, source.prune), (false, false));
        // Written, with any value: refused, rather than read as a promise that is not kept.
        for key in ["create_devices", "prune"] {
            for value in ["true", "false"] {
                assert_eq!(
                    bmc_message(&format!("{BY_PATTERN}{key} = {value}\n")),
                    format!("{BMC_AT}: a bmc source never creates a device and never deletes anything: remove {key}"),
                    "{key} = {value}"
                );
            }
        }
    }

    #[test]
    fn a_key_of_a_hypervisor_is_unknown_in_a_bmc_entry() {
        for key in ["host", "site", "tenant", "domain", "host_role"] {
            assert_eq!(bmc_message(&format!("{BY_PATTERN}{key} = \"x\"\n")), format!("{BMC_AT}: unknown key '{key}'"));
        }
        // And the keys of a bmc entry are unknown in a hypervisor one.
        assert_eq!(message(&entry("bmc_pattern = \"drac-{name}\"\n")), format!("{AT}: unknown key 'bmc_pattern'"));
        assert_eq!(message(&entry("devices = [\"pve01\"]\n")), format!("{AT}: unknown key 'devices'"));
    }

    #[test]
    fn a_bmc_entry_takes_no_reverse_dns_lookup() {
        // A BMC reports no IP address: there is no name to look up, and the keys are refused
        // rather than read and ignored.
        assert_eq!(
            bmc_message(&format!("{BY_PATTERN}dns_name_lookup = true\n")),
            format!("{BMC_AT}: unknown key 'dns_name_lookup'")
        );
        assert_eq!(
            bmc_message(&format!("{BY_PATTERN}dns_servers = [\"192.0.2.53\"]\n")),
            format!("{BMC_AT}: unknown key 'dns_servers'")
        );
        let source = one_bmc(&bmc_entry(BY_PATTERN));
        assert!(!source.dns_name_lookup);
        assert_eq!(source.dns_servers, Vec::<SocketAddr>::new());
    }

    #[test]
    fn a_bmc_is_redfish() {
        let text = bmc_entry(BY_PATTERN).replace("type = \"redfish\"", "type = \"ipmi\"");
        assert_eq!(
            failure(&text, &BMC_ENV).to_string(),
            format!("{BMC_AT}: unsupported type 'ipmi' (a bmc is redfish)")
        );
        let text = bmc_entry(BY_PATTERN).replace("type = \"redfish\"\n", "");
        assert_eq!(failure(&text, &BMC_ENV).to_string(), format!("{BMC_AT}: missing type"));
        // A hypervisor is not read through Redfish, nor a BMC as a hypervisor.
        let text = entry("").replace("type = \"proxmox\"", "type = \"redfish\"");
        assert_eq!(message(&text), format!("{AT}: unsupported type 'redfish' (a hypervisor is proxmox or vmware)"));
        let text = bmc_entry(BY_PATTERN).replace("type = \"redfish\"", "type = \"proxmox\"");
        assert_eq!(
            failure(&text, &BMC_ENV).to_string(),
            format!("{BMC_AT}: unsupported type 'proxmox' (a bmc is redfish)")
        );
    }

    #[test]
    fn a_bmc_entry_without_device_is_refused() {
        assert_eq!(bmc_message(""), format!("{BMC_AT}: no device: list them in devices with bmc_pattern, or in bmcs"));
        assert_eq!(
            bmc_message("devices = []\n"),
            format!("{BMC_AT}: no device: list them in devices with bmc_pattern, or in bmcs")
        );
    }

    #[test]
    fn devices_and_their_pattern_go_together() {
        assert_eq!(
            bmc_message("devices = [\"pve01.lab01\"]\n"),
            format!("{BMC_AT}: devices needs bmc_pattern to name their BMC (or give each address in bmcs)")
        );
        assert_eq!(
            bmc_message("bmc_pattern = \"drac-{name}\"\n"),
            format!("{BMC_AT}: bmc_pattern is set and devices lists no device")
        );
        // A pattern without `{name}` would give every device the same BMC.
        assert_eq!(
            bmc_message("devices = [\"pve01.lab01\"]\nbmc_pattern = \"drac-pve01.lab01\"\n"),
            format!("{BMC_AT}: bmc_pattern must contain {{name}}, replaced by the name of each device")
        );
        for devices in ["\"pve01.lab01\"", "[1]", "[\"\"]", "[\"pve01\", \" \"]"] {
            assert_eq!(
                bmc_message(&format!("devices = {devices}\nbmc_pattern = \"drac-{{name}}\"\n")),
                format!("{BMC_AT}: devices must be a list of device names"),
                "{devices}"
            );
        }
        assert_eq!(
            bmc_message("devices = [\"pve01\"]\nbmc_pattern = 12\n"),
            format!("{BMC_AT}: bmc_pattern must be a string")
        );
    }

    #[test]
    fn the_table_of_bmcs_maps_a_device_to_an_address() {
        assert_eq!(
            bmc_message("bmcs = [\"drac-pve01\"]\n"),
            format!("{BMC_AT}: bmcs must be a table: device name = address of its BMC")
        );
        assert_eq!(
            bmc_message("\n[sources.bmcs]\n\"pve01.lab01\" = 12\n"),
            format!("{BMC_AT}: bmcs must give the address of the BMC of each device, as a string")
        );
    }

    #[test]
    fn a_device_is_listed_once_whatever_the_case() {
        assert_eq!(
            bmc_message("devices = [\"pve01.lab01\", \"PVE01.lab01\"]\nbmc_pattern = \"drac-{name}\"\n"),
            format!("{BMC_AT}: device 'PVE01.lab01' is listed twice")
        );
        let table = "\n[sources.bmcs]\n\"pve01.lab01\" = \"192.0.2.61\"\n";
        assert_eq!(
            bmc_message(&format!("{BY_PATTERN}{table}")),
            format!("{BMC_AT}: device 'pve01.lab01' is listed twice")
        );
    }

    #[test]
    fn the_address_of_a_bmc_is_a_host_and_is_never_printed_when_it_is_not() {
        // An account, a scheme, a port or a path written in the address: refused, and not shown.
        for address in ["root:hunter2@192.0.2.61", "https://192.0.2.61", "192.0.2.61:8443", "192.0.2.61/redfish", ""] {
            let error = failure(&bmc_entry(&format!("\n[sources.bmcs]\n\"pve01.lab01\" = \"{address}\"\n")), &BMC_ENV);
            assert_eq!(
                error.to_string(),
                format!("{BMC_AT}: the BMC of device 'pve01.lab01' must be a host name or an IPv4 address"),
                "{address}"
            );
            assert!(!format!("{error:?}").contains("hunter2"));
        }
        // The same through the pattern.
        let error = failure(&bmc_entry("devices = [\"pve01\"]\nbmc_pattern = \"root:hunter2@{name}\"\n"), &BMC_ENV);
        assert_eq!(
            error.to_string(),
            format!("{BMC_AT}: the BMC of device 'pve01' must be a host name or an IPv4 address")
        );
        assert!(!format!("{error:?}").contains("hunter2"));
    }

    #[test]
    fn a_bmc_entry_logs_in_with_a_user_and_its_password() {
        // The entry is loaded all the same, with the names of what it misses.
        let missing = |environ: &[(&str, &str)]| {
            let bmc = one_of(read(&bmc_entry(BY_PATTERN), environ).0);
            assert_eq!(documented(&bmc), [("pve01.lab01", "drac-pve01.lab01"), ("pve02.lab01", "drac-pve02.lab01")]);
            bmc.missing().to_vec()
        };
        assert_eq!(missing(&BMC_ENV), [] as [&str; 0]);
        assert_eq!(missing(&[BMC_ENV[0]]), ["BMC_LAB01_USERNAME", "BMC_LAB01_PASSWORD"]);
        assert_eq!(missing(&[BMC_ENV[0], BMC_ENV[1]]), ["BMC_LAB01_PASSWORD"]);
        assert_eq!(missing(&[BMC_ENV[0], BMC_ENV[2]]), ["BMC_LAB01_USERNAME"]);
        // A token is no account of a BMC: refused by the names of the variables, never their values.
        let environ = [BMC_ENV[0], BMC_ENV[1], BMC_ENV[2], ("BMC_LAB01_TOKEN", "bmc-secret")];
        let error = failure(&bmc_entry(BY_PATTERN), &environ);
        assert_eq!(
            error.to_string(),
            format!(
                "{BMC_AT}: a bmc source logs in with BMC_LAB01_USERNAME and BMC_LAB01_PASSWORD: unset BMC_LAB01_TOKEN"
            )
        );
        for secret in ["bmc-secret", "pw-bmc", "token-value"] {
            assert!(!format!("{error} {error:?}").contains(secret), "{secret} is printed");
        }
    }

    #[test]
    fn a_bmc_entry_shares_the_rules_of_the_names_and_of_the_variables() {
        // Its name is unique among every source, and may be ranked.
        let text = format!("{NETBOX}{PVE}{}", BMC.replace("bmc.lab01", "pve01.lab01"));
        assert_eq!(
            failure(&format!("{text}{BY_PATTERN}"), &ENV).to_string(),
            format!("{FILE}: source entry 2 (pve01.lab01): duplicate source name")
        );
        let ranked = format!(
            "[netbox]\nurl = \"https://netbox.example.net\"\nsource_priority = [\"bmc.lab01\", \"pve01.lab01\"]\n\
             {PVE}{BMC}{BY_PATTERN}"
        );
        let environ = [ENV[0], ENV[1], BMC_ENV[1], BMC_ENV[2]];
        let (hypervisors, netbox) = read(&ranked, &environ);
        assert_eq!(netbox.source_priority, ["bmc.lab01", "pve01.lab01"]);
        let types: Vec<&str> = hypervisors.iter().map(|source| source.r#type.as_str()).collect();
        assert_eq!(types, ["proxmox", "redfish"]);
        // Two sources never read the same variables.
        let text = format!("{NETBOX}{PVE}{}{BY_PATTERN}", BMC.replace("bmc.lab01", "pve01-lab01"));
        assert_eq!(
            failure(&text, &environ).to_string(),
            format!(
                "{FILE}: source entry 2 (pve01-lab01): its variable PVE01_LAB01_USERNAME is also read for source \
                 pve01.lab01: rename the source"
            )
        );
    }

    #[test]
    fn a_bmc_entry_is_left_to_this_loader_by_the_network_one() {
        let text = format!("{NETBOX}{SSH}{SWITCH}{BMC}{BY_PATTERN}");
        let environ = [BMC_ENV[0], BMC_ENV[1], BMC_ENV[2], ("SWITCH_PASSWORD", "pw-switch")];
        let config = parse(Path::new(FILE), &text, &env(&environ)).unwrap();
        let network: Vec<&str> = config.inventory.sources.iter().map(|source| source.name.as_str()).collect();
        let others: Vec<&str> = config.hypervisors.iter().map(|source| source.name.as_str()).collect();
        assert_eq!((network, others), (vec!["nexus01.lab01"], vec!["bmc.lab01"]));
    }

    #[test]
    fn the_secrets_of_a_bmc_entry_never_show_in_debug_output() {
        let config = parse(Path::new(FILE), &bmc_entry(BY_PATTERN), &env(&BMC_ENV)).unwrap();
        let printed = format!("{config:?} {config:#?}");
        assert!(!printed.contains("pw-bmc") && !printed.contains("token-value"), "{printed}");
    }

    #[test]
    fn the_example_file_loads_through_both_loaders() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
        let environ = env(&[
            ("NETBOX_TOKEN", "token-value"),
            ("HOME", "/home/sync"),
            ("FIREWALL_FW01_LAB01_USERNAME", "readonly"),
            ("FIREWALL_FW01_LAB01_PASSWORD", "pw-forti"),
            ("PVE01_LAB01_TOKEN", "sync@pve!omnisync=pve-secret"),
            ("VCENTER01_LAB01_USERNAME", "sync@vsphere.local"),
            ("VCENTER01_LAB01_PASSWORD", "pw-vcenter"),
            ("BMC_LAB01_USERNAME", "netbox-ro"),
            ("BMC_LAB01_PASSWORD", "pw-bmc"),
        ]);
        let inventory = load_inventory(&path, &environ).unwrap();
        let mut network: Vec<&str> = inventory.sources.iter().map(|source| source.r#type.as_str()).collect();
        network.sort_unstable();
        network.dedup();
        assert_eq!(network, ["fortios", "ios", "nipper", "nxos"]);
        let text = fs::read_to_string(&path).unwrap();
        let (hypervisors, netbox) = parse_hypervisors(&path, &text, &environ).unwrap();
        let types: Vec<&str> = hypervisors.iter().map(|source| source.r#type.as_str()).collect();
        assert_eq!(types, ["proxmox", "vmware", "redfish"]);
        // The bmc entry sets every key a bmc takes, but the CA file and the pinned certificates.
        let bmc = &hypervisors[2];
        assert_eq!((bmc.name.as_str(), bmc.host.as_str()), ("bmc.lab01", ""));
        assert_eq!((bmc.port, bmc.validate_certs, bmc.ca_file.as_ref()), (Some(443), false, None));
        let documented: Vec<(&str, &str)> =
            bmc.bmcs.iter().map(|bmc| (bmc.device.as_str(), bmc.host.as_str())).collect();
        assert_eq!(
            documented,
            [
                ("pve01.lab01", "drac-pve01.lab01"),
                ("pve02.lab01", "drac-pve02.lab01"),
                ("pve03.lab01", "drac-pve03.lab01"),
                ("esx01.lab01", "ilo-esx01.example.net"),
                ("esx02.lab01", "192.0.2.62"),
            ]
        );
        assert_eq!((bmc.create_devices, bmc.prune), (false, false));
        // A BMC reports no address: nothing is looked up for it.
        assert_eq!((bmc.dns_name_lookup, bmc.dns_servers.len()), (false, 0));
        let account = Credentials::Password { username: "netbox-ro".to_owned(), password: Secret::new("pw-bmc") };
        assert_eq!(bmc.credentials, Wanted::Held(account));
        // The vCenter entry sets every key a vCenter takes.
        let vcenter = &hypervisors[1];
        assert_eq!((vcenter.name.as_str(), vcenter.host.as_str()), ("vcenter01.lab01", "vcenter01.example.net"));
        assert_eq!((vcenter.port, vcenter.validate_certs, vcenter.ca_file.as_ref()), (Some(443), false, None));
        assert_eq!((vcenter.site.as_deref(), vcenter.tenant.as_deref()), (Some("lab01"), Some("infrastructure")));
        assert_eq!(
            (vcenter.host_role.as_deref(), vcenter.vm_role.as_deref()),
            (Some("Hypervisor ESX"), Some("Virtual Machine ESX"))
        );
        assert_eq!(vcenter.domain, None);
        assert_eq!((vcenter.ignore_templates, vcenter.create_devices, vcenter.prune), (true, true, true));
        assert_eq!(vcenter.ignored_subnets, ["10.255.0.0/16".parse::<IpNet>().unwrap()]);
        assert_eq!(vcenter.permitted_subnets, ["10.0.0.0/8".parse::<IpNet>().unwrap()]);
        assert_eq!(vcenter.interface_filter.as_ref().map(Regex::as_str), Some("^vusb"));
        // The example turns the lookup on for the vCenter, with the resolvers of the system; the Proxmox
        // entry leaves the key out.
        assert!(vcenter.dns_name_lookup);
        assert_eq!(vcenter.dns_servers, Vec::<SocketAddr>::new());
        assert!(!hypervisors[0].dns_name_lookup);
        let account =
            Credentials::Password { username: "sync@vsphere.local".to_owned(), password: Secret::new("pw-vcenter") };
        assert_eq!(vcenter.credentials, Wanted::Held(account));
        assert_eq!(netbox.url, "https://netbox.example.net");
        let config = load(&path, &environ).unwrap();
        assert_eq!(config.inventory.sources.len() + config.hypervisors.len(), inventory.sources.len() + 3);
        // Every source of the example is ranked.
        assert_eq!(config.netbox.source_priority.len(), inventory.sources.len() + 3);
        // The journal is shown commented out: the default one.
        assert_eq!(config.journal, None);
        assert!(text.contains("\n# journal = \"/var/lib/netbox-omnisync/journal.jsonl\"\n"), "{text}");
        // So is the list of the hosts: the example is a file one host runs.
        assert!(config.runners.is_empty());
        assert!(text.contains("\n# runners = [\"sync01.lab01\", \"sat01.lab02\"]\n"), "{text}");
        // Uncommented, with a host on every entry, it is a file two hosts share.
        let mut shared = text.replace("\n# runners = [", "\nrunners = [");
        shared = shared.replace("\nkind = \"", "\nrunner = \"sync01.lab01\"\nkind = \"");
        shared = shared.replacen("runner = \"sync01.lab01\"", "runner = \"sat01.lab02\"", 1);
        let runners = parse(&path, &shared, &environ).unwrap().runners;
        assert_eq!(runners.hosts(), ["sync01.lab01", "sat01.lab02"]);
        assert_eq!(runners.of("pve01.lab01"), Some("sat01.lab02"));
        assert_eq!(runners.of("nexus01.lab01"), Some("sync01.lab01"));
    }
}
