//! One run over the hypervisor and BMC sources: read every source at once,
//! load what NetBox holds, compare, write.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use futures::StreamExt;
use futures::future::join_all;
use omnisync_core::Gateway;
use omnisync_core::inventory::dns::{Asked, ReverseDns};
use omnisync_core::inventory::guard::{Guarded, admit};
use omnisync_core::inventory::model::{Desired, Kind, LEGACY_TAG_MARKERS, SOURCE_TAG_PREFIX, VlanGroups};
use omnisync_core::inventory::reconcile::{
    Run, SourceFacts, SourceStatus, ownership_tags, reconcile, site_vlan_leftovers,
};
use omnisync_core::network::hosts::Heard;
use omnisync_core::outcome::Outcome;
use omnisync_core::progress::Progress;
use omnisync_netbox::inventory_apply::{DryRun, apply};
use omnisync_netbox::inventory_state::load_shown;
use omnisync_proxmox::translate::{Settings, desired};
use omnisync_proxmox::{Credentials as ProxmoxCredentials, ProxmoxClient, collect};
use omnisync_redfish::translate::Translation as BmcTranslation;
use omnisync_redfish::{Credentials as RedfishCredentials, RedfishClient};
use omnisync_vmware::client::{Credentials as VsphereCredentials, VsphereClient};
use omnisync_vmware::collect::Wanted as VmwareWanted;
use omnisync_vmware::translate::{Settings as VmwareSettings, TAG_MARKER};

use crate::config::{Bmc, Credentials, Hypervisor, HypervisorType, NodeAuth, NodeSsh, variable_prefix};
use crate::dns::ReverseLookups;
use omnisync_proxmox::neighbors::{self, Shell, read_neighbors};
use omnisync_ssh::known_hosts::KnownHosts;
use omnisync_ssh::{Account, Auth, Peer};

/// The default port of the Proxmox VE API.
const PROXMOX_PORT: u16 = 8006;

/// The default port of the vSphere API.
const VSPHERE_PORT: u16 = 443;

/// The default port of the Redfish service of a BMC.
const REDFISH_PORT: u16 = 443;

/// BMCs read at once by one source. Small: a BMC is a slow, single-minded
/// machine on a management network, and the source runs once a day.
const BMCS_IN_FLIGHT: usize = 4;

/// What a source reports: the objects it wants in NetBox, and what it left out.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reading {
    pub objects: Vec<Desired>,
    pub warnings: Vec<String>,
    /// What the source reports on the word of a BMC: written only once NetBox
    /// shows the device to be the server of that BMC.
    pub guarded: Vec<Guarded>,
    /// The parts of the source that could not be read (one BMC out of ten),
    /// each an error of the run. The rest is written; what the source does
    /// not report this time says nothing.
    pub errors: Vec<String>,
    /// The switch port each physical card of each host hears, when the run
    /// asked for it: what the cable step of the network sources is told.
    pub heard: Vec<Heard>,
}

/// Reads one hypervisor source. A failure is the reason, without the name of
/// the source: the run adds it.
pub trait Reader: Sync {
    fn read(&self, source: &Hypervisor) -> impl Future<Output = Result<Reading, String>> + Send;

    /// Reads one source, and what its hosts hear of their switches when
    /// `neighbours` is set: only a run that also reads switches asks for it.
    /// A reader that cannot hear anything reads the source alone.
    fn read_hearing(
        &self,
        source: &Hypervisor,
        neighbours: bool,
    ) -> impl Future<Output = Result<Reading, String>> + Send {
        let _ = neighbours;
        self.read(source)
    }

    /// What the reader has to say of the run as a whole, once every source
    /// is read: what concerns no source in particular, said once.
    fn warnings(&self) -> Vec<String> {
        Vec::new()
    }
}

/// The real hypervisors, read through their API, read-only, and the reverse
/// DNS lookups of the sources that ask for them.
#[derive(Debug)]
pub struct Apis {
    lookups: ReverseLookups,
    /// How the nodes of a Proxmox are logged into, to ask `lldpd`: None when
    /// the environment gives no place for their known hosts.
    nodes: Option<NodeAccess>,
}

impl Default for Apis {
    fn default() -> Self {
        Apis { lookups: ReverseLookups::system(), nodes: None }
    }
}

impl Apis {
    /// The readers of a run, the nodes of a Proxmox reachable with `nodes`.
    pub fn with_nodes(nodes: Option<NodeAccess>) -> Self {
        Apis { nodes, ..Apis::default() }
    }
}

/// What the nodes of a Proxmox are logged into with, besides the account of
/// their entry: the known hosts file and the agent of the switches.
#[derive(Debug, Clone)]
pub struct NodeAccess {
    pub known_hosts: KnownHosts,
    pub agent_socket: Option<PathBuf>,
    pub timeout: Duration,
}

/// The port of the SSH of a node.
const NODE_SSH_PORT: u16 = 22;

/// Runs the one command of [`omnisync_proxmox::neighbors`] on a node, over
/// SSH, with the account of its entry.
struct NodeShell<'a> {
    ssh: &'a NodeSsh,
    /// The suffix of the node names (`.lab.example`), to reach a node by its name.
    domain: String,
    access: &'a NodeAccess,
}

impl Shell for NodeShell<'_> {
    async fn run(&self, node: &str, command: &str) -> Result<String, String> {
        // Checked before anything is contacted: nothing else is ever run on a node.
        neighbors::check(command)?;
        let address = self.ssh.hosts.get(node).cloned().unwrap_or_else(|| format!("{node}{}", self.domain));
        let auth = match &self.ssh.auth {
            NodeAuth::Agent => Auth::Agent,
            NodeAuth::KeyFile(path) => Auth::KeyFile(path),
            // Only the name of the variable is said, never what it holds.
            NodeAuth::Password(password) => Auth::Password(password.held().map_err(|missing| missing.to_string())?),
        };
        let account = Account {
            username: &self.ssh.username,
            auth,
            disabled_algorithms: self.ssh.disabled_algorithms.as_ref(),
            agent_rsa_only: false,
        };
        let peer = Peer { host: &address, port: NODE_SSH_PORT, noun: "node" };
        let access = self.access;
        let failed = |kind: String| format!("SSH to {address} failed: {kind}");
        let connection =
            omnisync_ssh::connect(&peer, &account, &access.known_hosts, access.agent_socket.as_deref(), access.timeout)
                .await
                .map_err(failed)?;
        let output = connection.exec(command, access.timeout).await;
        connection.close().await;
        let output = output.map_err(failed)?;
        let said = output.stderr.lines().next().unwrap_or_default().trim().to_owned();
        match output.status {
            Some(0) => Ok(output.stdout),
            Some(status) => Err(format!("{command} exited with {status}: {said}")),
            None => Err(format!("{command} ended without an exit status: {said}")),
        }
    }
}

/// A shell for a reader that logs into no node.
struct NoShell;

impl Shell for NoShell {
    async fn run(&self, _node: &str, _command: &str) -> Result<String, String> {
        Err("no node is logged into".to_owned())
    }
}

/// The DNS names of the addresses a source reports, when it asks for them
/// (`dns_name_lookup`): otherwise none, and NetBox keeps the names it has.
///
/// A translation is pure and a lookup is not: `translate` is run once with a
/// resolver that only notes the addresses it is asked, those are looked up,
/// and the translation is then done with the answers.
async fn looked_up(
    lookups: &ReverseLookups,
    source: &Hypervisor,
    translate: impl FnOnce(&dyn ReverseDns),
) -> BTreeMap<IpAddr, String> {
    if !source.dns_name_lookup {
        return BTreeMap::new();
    }
    let asked = Asked::default();
    translate(&asked);
    lookups.resolve(&source.dns_servers, &asked.into_addresses()).await
}

/// A reader for a build, or a test, that has no hypervisor to read.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unavailable;

fn not_implemented(source: &Hypervisor) -> String {
    format!("{} sources are not implemented in this build", source.r#type.as_str())
}

impl Reader for Unavailable {
    async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
        Err(not_implemented(source))
    }
}

/// The settings of the Proxmox translation, from the configuration entry.
fn proxmox_settings(source: &Hypervisor) -> Result<Settings, String> {
    let site = source.site.as_deref().ok_or("a proxmox source needs a site")?;
    // The suffix of a host name: the domain after one dot, written in the file or not.
    let domain = source.domain.as_deref().map(|domain| format!(".{}", domain.trim_start_matches('.')));
    Ok(Settings {
        tenant: source.tenant.clone(),
        host_role: source.host_role.clone(),
        vm_role: source.vm_role.clone(),
        domain: domain.unwrap_or_default(),
        ignore_templates: source.ignore_templates,
        ignored_subnets: source.ignored_subnets.clone(),
        permitted_subnets: source.permitted_subnets.clone(),
        interface_filter: source.interface_filter.clone(),
        vlan_group: source.vlan_group.clone(),
        ..Settings::new(&source.name, site)
    })
}

/// Whether the nodes of `source` are asked what their cards hear: only by a
/// run that reads switches (`neighbours`), for an entry that asks for it.
fn asks_its_nodes(source: &Hypervisor, neighbours: bool) -> bool {
    neighbours && source.neighbors
}

/// The suffix of the names of the nodes of `source`, as the translation adds it.
fn node_domain(source: &Hypervisor) -> String {
    source.domain.as_deref().map(|domain| format!(".{}", domain.trim_start_matches('.'))).unwrap_or_default()
}

/// The account `source` is read with.
///
/// A source this host does not launch has none (the file is the same on every
/// host, the secrets are not): it is refused by the names of the variables to
/// set, before a client is built, and nothing is sent in its name.
fn held(source: &Hypervisor) -> Result<&Credentials, String> {
    source.credentials.held().map_err(|missing| missing.to_string())
}

/// Reads the Proxmox of `source`, whose API is at `url`: given apart for the
/// tests, whose fake Proxmox does not speak TLS.
///
/// A collection that fails names the type of the source and its host, never the
/// account: the client keeps the user, the password and the token out of its
/// messages.
pub async fn read_proxmox_at(source: &Hypervisor, url: &str, lookups: &ReverseLookups) -> Result<Reading, String> {
    read_proxmox_hearing_at(source, url, lookups, None::<&NoShell>).await
}

/// Reads the Proxmox of `source` at `url`, and asks each node what its cards
/// hear through `shell` when one is given: the caller gives one only to a run
/// that reads switches, for an entry that asks for it. A node whose
/// neighbours cannot be read is a warning.
pub async fn read_proxmox_hearing_at<S: Shell>(
    source: &Hypervisor,
    url: &str,
    lookups: &ReverseLookups,
    shell: Option<&S>,
) -> Result<Reading, String> {
    let settings = proxmox_settings(source)?;
    let credentials = match held(source)? {
        Credentials::Password { username, password } => ProxmoxCredentials::password(username, password.expose()),
        Credentials::Token { token, .. } => ProxmoxCredentials::api_token(token.expose()),
    };
    let mut builder = ProxmoxClient::builder(url, credentials).validate_certs(source.validate_certs);
    if let Some(ca_file) = &source.ca_file {
        builder = builder.ca_file(ca_file);
    }
    let client = builder.build().map_err(|error| error.to_string())?;
    let address = format!("{}:{}", source.host, source.port.unwrap_or(PROXMOX_PORT));
    let cluster = collect(&client).await.map_err(|error| format!("{} {address}: {error}", source.r#type.as_str()))?;
    let names = looked_up(lookups, source, |asked| {
        desired(&cluster, &settings, asked);
    })
    .await;
    let translation = desired(&cluster, &settings, &names);
    // A node Proxmox says is offline is not read: an error of the run, and a
    // source read in part, which says nothing of what it did not report.
    let errors =
        cluster.offline.iter().map(|node| format!("node {node} is offline: its guests are not read")).collect();
    let mut warnings = translation.warnings;
    let heard = match shell {
        Some(shell) => {
            let read = read_neighbors(&cluster, shell).await;
            warnings.extend(read.warnings.iter().cloned());
            omnisync_proxmox::translate::heard(&read, &settings)
        }
        None => Vec::new(),
    };
    Ok(Reading { objects: translation.objects, warnings, errors, heard, ..Reading::default() })
}

/// The settings of the VMware translation, from the configuration entry.
///
/// The production settings of netbox-sync that have no key here are constants
/// of the translation: the tags of a machine, of its cluster and of its
/// datacenter, the primary address written only when NetBox has none, the
/// sizes in powers of ten.
fn vmware_settings(source: &Hypervisor) -> Result<VmwareSettings, String> {
    let site = source.site.as_deref().ok_or("a vmware source needs a site")?;
    // vCenter names its hosts in full: a suffix would rename every device.
    if source.domain.is_some() {
        return Err("a vmware source takes no domain: vCenter gives the full name of its hosts".to_owned());
    }
    Ok(VmwareSettings {
        tenant: source.tenant.clone(),
        host_role: source.host_role.clone(),
        vm_role: source.vm_role.clone(),
        ignore_templates: source.ignore_templates,
        ignored_subnets: source.ignored_subnets.clone(),
        permitted_subnets: source.permitted_subnets.clone(),
        interface_filter: source.interface_filter.clone(),
        vlan_group: source.vlan_group.clone(),
        ..VmwareSettings::new(&source.name, site)
    })
}

async fn read_vmware(source: &Hypervisor, lookups: &ReverseLookups, neighbours: bool) -> Result<Reading, String> {
    let url = format!("https://{}:{}", source.host, source.port.unwrap_or(VSPHERE_PORT));
    read_vmware_hearing_at(source, &url, lookups, neighbours).await
}

/// Reads the vCenter of `source`, whose API is at `url`: given apart for the
/// tests, whose fake vCenter does not speak TLS.
///
/// A failure names the type of the source and its host, never the account:
/// the client keeps the user, the password and the sessions out of its
/// messages.
pub async fn read_vmware_at(source: &Hypervisor, url: &str, lookups: &ReverseLookups) -> Result<Reading, String> {
    read_vmware_hearing_at(source, url, lookups, false).await
}

/// Reads the vCenter of `source` at `url`, and the switch port each card of
/// its hosts hears when `neighbours` is set. A host whose hint cannot be read
/// is a warning: the cables of its ports are then left as they are.
pub async fn read_vmware_hearing_at(
    source: &Hypervisor,
    url: &str,
    lookups: &ReverseLookups,
    neighbours: bool,
) -> Result<Reading, String> {
    let settings = vmware_settings(source)?;
    let credentials = match held(source)? {
        Credentials::Password { username, password } => VsphereCredentials::new(username, password.expose()),
        // Only the names of the variables are said, never what they hold.
        Credentials::Token { .. } => {
            let prefix = variable_prefix(&source.name);
            return Err(format!("a vmware source logs in with {prefix}_USERNAME and {prefix}_PASSWORD, not a token"));
        }
    };
    let mut builder = VsphereClient::builder(url, credentials).validate_certs(source.validate_certs);
    if let Some(ca_file) = &source.ca_file {
        builder = builder.ca_file(ca_file);
    }
    let client = builder.build().map_err(|error| error.to_string())?;
    let address = format!("{}:{}", source.host, source.port.unwrap_or(VSPHERE_PORT));
    let named = |error: String| format!("{} {address}: {error}", source.r#type.as_str());
    let wanted = VmwareWanted { hints: neighbours };
    let inventory =
        omnisync_vmware::collect::collect_with(&client, &wanted).await.map_err(|error| named(error.to_string()))?;
    let names = looked_up(lookups, source, |asked| {
        // A translation that fails here fails the same way below, where it is reported.
        let _ = omnisync_vmware::translate::desired(&inventory, &settings, asked);
    })
    .await;
    let translation =
        omnisync_vmware::translate::desired(&inventory, &settings, &names).map_err(|error| named(error.to_string()))?;
    let mut warnings = inventory.warnings.clone();
    warnings.extend(translation.warnings);
    Ok(Reading { objects: translation.objects, warnings, heard: translation.heard, ..Reading::default() })
}

async fn read_redfish(source: &Hypervisor) -> Result<Reading, String> {
    let port = source.port.unwrap_or(REDFISH_PORT);
    read_redfish_at(source, &|host: &str| format!("https://{host}:{port}")).await
}

/// Reads one BMC and translates what it says of `bmc.device`.
///
/// A failure names the type of the source and the BMC, never the account: the
/// client keeps the user and the password out of its messages.
async fn read_bmc(
    source: &Hypervisor,
    bmc: &Bmc,
    url: String,
    credentials: RedfishCredentials,
) -> Result<BmcTranslation, String> {
    let mut builder = RedfishClient::builder(&url, credentials).validate_certs(source.validate_certs);
    if let Some(ca_file) = &source.ca_file {
        builder = builder.ca_file(ca_file);
    }
    // Pinned: the certificate of this BMC and no other, whatever validate_certs says.
    if let Some(fingerprint) = bmc.fingerprint {
        builder = builder.tls_fingerprint(fingerprint);
    }
    // Not prefixed with the address: one the client refuses may hold an account.
    let client = builder.build().map_err(|error| error.to_string())?;
    let address = format!("{}:{}", bmc.host, source.port.unwrap_or(REDFISH_PORT));
    let answer = omnisync_redfish::collect(&client)
        .await
        .map_err(|error| format!("{} {address}: {error}", source.r#type.as_str()))?;
    Ok(omnisync_redfish::translate::desired(&source.name, &bmc.device, &bmc.host, &answer))
}

/// Reads the BMCs of `source`, the one of each device at `url_of(its host)`:
/// given apart for the tests, whose fake BMCs do not speak TLS.
///
/// The unit of failure is the BMC, not the source: one that cannot be read is
/// an error of the reading, and the others are reported. A few are read at
/// once, each on its own connection, its calls one after the other.
pub async fn read_redfish_at(source: &Hypervisor, url_of: &(dyn Fn(&str) -> String + Sync)) -> Result<Reading, String> {
    let Credentials::Password { username, password } = held(source)? else {
        // Only the names of the variables are said, never what they hold.
        let prefix = variable_prefix(&source.name);
        return Err(format!("a redfish source logs in with {prefix}_USERNAME and {prefix}_PASSWORD, not a token"));
    };
    // Built before they are driven: nothing is sent until the stream polls them.
    let mut readings = Vec::with_capacity(source.bmcs.len());
    for bmc in &source.bmcs {
        let credentials = RedfishCredentials::new(username, password.expose());
        readings.push(read_bmc(source, bmc, url_of(&bmc.host), credentials));
    }
    // `buffered` keeps the order of the configuration, whatever answers first.
    let translations: Vec<Result<BmcTranslation, String>> =
        futures::stream::iter(readings).buffered(BMCS_IN_FLIGHT).collect().await;
    let mut reading = Reading::default();
    for translation in translations {
        match translation {
            Ok(translation) => {
                reading.warnings.extend(translation.warnings);
                reading.guarded.push(translation.report);
            }
            Err(reason) => reading.errors.push(reason),
        }
    }
    Ok(reading)
}

impl Reader for Apis {
    async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
        self.read_hearing(source, false).await
    }

    async fn read_hearing(&self, source: &Hypervisor, neighbours: bool) -> Result<Reading, String> {
        match source.r#type {
            HypervisorType::Proxmox => {
                let url = format!("https://{}:{}", source.host, source.port.unwrap_or(PROXMOX_PORT));
                let asked = asks_its_nodes(source, neighbours);
                match (asked, &source.ssh, &self.nodes) {
                    (true, Some(ssh), Some(access)) => {
                        let shell = NodeShell { ssh, domain: node_domain(source), access };
                        read_proxmox_hearing_at(source, &url, &self.lookups, Some(&shell)).await
                    }
                    (true, _, None) => {
                        let mut reading =
                            read_proxmox_hearing_at(source, &url, &self.lookups, None::<&NoShell>).await?;
                        reading.warnings.push(
                            "its nodes are not logged into: no state directory to hold their known hosts".to_owned(),
                        );
                        Ok(reading)
                    }
                    _ => read_proxmox_hearing_at(source, &url, &self.lookups, None::<&NoShell>).await,
                }
            }
            HypervisorType::Vmware => read_vmware(source, &self.lookups, neighbours).await,
            HypervisorType::Redfish => read_redfish(source).await,
        }
    }

    fn warnings(&self) -> Vec<String> {
        self.lookups.warning().into_iter().collect()
    }
}

/// The ownership tag of a source: `source-` then its name, in lower case,
/// without what a slug cannot hold. The tools this one replaces named their
/// tags the same way, so a source that keeps its name keeps its tag.
pub fn source_tag(name: &str) -> String {
    let kept = |character: &char| matches!(character, 'a'..='z' | '0'..='9' | '_' | '-');
    let slug: String = name.trim().to_lowercase().replace(' ', "-").chars().filter(kept).collect();
    format!("{SOURCE_TAG_PREFIX}{slug}")
}

/// What a BMC tells of a device, and a hypervisor may know as well.
const HARDWARE_FIELDS: [&str; 2] = ["device_type", "serial"];

/// The endpoint of the custom field definitions.
const CUSTOM_FIELDS: &str = "extras.custom_fields";

/// Refuses custom fields NetBox does not define for the kind of object they
/// are reported on. NetBox refuses a write that carries one
/// (`extras/api/customfields.py`, 4.5 to 4.7): met at its write, the run would
/// stop half way through its plan, after the writes before it.
async fn undefined_custom_fields<G: Gateway>(gateway: &G, desired: &[Desired]) -> Result<(), String> {
    let used: BTreeSet<(Kind, &str)> = desired
        .iter()
        .flat_map(|object| object.custom_fields.keys().map(move |name| (object.kind, name.as_str())))
        .collect();
    if used.is_empty() {
        return Ok(());
    }
    let definitions =
        gateway.list(CUSTOM_FIELDS, &Vec::new()).await.map_err(|error| format!("reading {CUSTOM_FIELDS}: {error}"))?;
    let defined = |kind: Kind, name: &str| {
        definitions.iter().any(|definition| {
            let types = definition.get("object_types").and_then(|types| types.as_array());
            definition.get("name").and_then(|held| held.as_str()) == Some(name)
                && types.is_some_and(|types| types.iter().any(|held| held.as_str() == Some(kind.content_type())))
        })
    };
    let missing: Vec<String> = used
        .into_iter()
        .filter(|(kind, name)| !defined(*kind, name))
        .map(|(kind, name)| format!("{name} on {}", kind.label()))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let plural = if missing.len() == 1 { "it" } else { "them" };
    Err(format!(
        "NetBox defines no custom field {}: create {plural} before syncing; nothing was written",
        missing.join(", ")
    ))
}

/// Sync the `selected` hypervisor and BMC sources into NetBox. `configured`
/// lists every one of the configuration, the ones left out of this run
/// included: their objects are never orphans of this run.
///
/// A BMC source never creates a device and never deletes anything, whatever
/// its entry says: it completes devices that exist.
pub async fn run<G, R>(
    configured: &[Hypervisor],
    selected: &[&Hypervisor],
    priority: &[String],
    gateway: &G,
    reader: &R,
    progress: &dyn Progress,
) -> Outcome
where
    G: Gateway + DryRun,
    R: Reader,
{
    // The groups of the sites the sources are at: what a configuration that
    // only knows its sources can tell.
    let mut groups = VlanGroups::default();
    for source in configured {
        if let (Some(site), Some(group)) = (&source.site, &source.vlan_group) {
            groups.insert(site, group);
        }
    }
    run_with_groups(configured, selected, priority, &groups, gateway, reader, progress).await
}

/// `run`, told the VLAN groups of `[[vlan_groups]]`: the leftover VLANs of a
/// site of a group are told whether or not a hypervisor source is at it.
pub async fn run_with_groups<G, R>(
    configured: &[Hypervisor],
    selected: &[&Hypervisor],
    priority: &[String],
    vlan_groups: &VlanGroups,
    gateway: &G,
    reader: &R,
    progress: &dyn Progress,
) -> Outcome
where
    G: Gateway + DryRun,
    R: Reader,
{
    let scope = Scope { vlan_groups, neighbours: false };
    run_hearing(configured, selected, priority, &scope, gateway, reader, progress).await.0
}

/// What a run of the hypervisors is asked besides its sources.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// The VLAN group of each site of the configuration.
    pub vlan_groups: &'a VlanGroups,
    /// Ask the sources what their hosts hear of their switches: only a run
    /// that also reads switches does.
    pub neighbours: bool,
}

/// [`run_with_groups`], which also asks the sources what their hosts hear of
/// their switches when the scope says so, and gives it: what the sources that
/// were read said, in the order of the selection. A source that failed says
/// nothing.
pub async fn run_hearing<G, R>(
    configured: &[Hypervisor],
    selected: &[&Hypervisor],
    priority: &[String],
    scope: &Scope<'_>,
    gateway: &G,
    reader: &R,
    progress: &dyn Progress,
) -> (Outcome, Vec<Heard>)
where
    G: Gateway + DryRun,
    R: Reader,
{
    if selected.is_empty() {
        return (Outcome::default(), Vec::new());
    }
    // A unit for each source to read, one for each list of NetBox and one for
    // the comparison; the writes are added once they are known. Nothing is
    // drawn on a terminal before this.
    progress.begin(selected.len() as u64 + STEPS);
    let (outcome, heard) = sync(configured, selected, priority, scope, gateway, reader, progress).await;
    progress.end();
    (outcome, heard)
}

/// Reads one source, with its own row of progress while it is read.
async fn read_shown<R: Reader>(
    reader: &R,
    source: &Hypervisor,
    progress: &dyn Progress,
    neighbours: bool,
) -> Result<Reading, String> {
    progress.lane_start(&source.name, 1);
    let reading = reader.read_hearing(source, neighbours).await;
    progress.advance(Some(&source.name));
    progress.lane_end(&source.name);
    reading
}

/// The units of a run besides its sources and its writes: every list read
/// from NetBox, and the comparison.
const STEPS: u64 = Kind::ALL.len() as u64 + 1;

/// The most lists still awaited from NetBox that a run names.
const NAMED_LISTS: usize = 3;

/// What a run says of the lists it still waits for: how many, and which once
/// few are left, a slow one being then the one to know about.
fn lists_left(left: &BTreeSet<&str>) -> String {
    let count = format!("{} list(s) left", left.len());
    if left.is_empty() || left.len() > NAMED_LISTS {
        return count;
    }
    format!("{count}: {}", left.iter().copied().collect::<Vec<_>>().join(", "))
}

/// The run itself, between the start and the end of its progress.
async fn sync<G, R>(
    configured: &[Hypervisor],
    selected: &[&Hypervisor],
    priority: &[String],
    scope: &Scope<'_>,
    gateway: &G,
    reader: &R,
    progress: &dyn Progress,
) -> (Outcome, Vec<Heard>)
where
    G: Gateway + DryRun,
    R: Reader,
{
    let Scope { vlan_groups, neighbours } = *scope;
    let mut outcome = Outcome::default();
    let mut heard: Vec<Heard> = Vec::new();
    if selected.is_empty() {
        return (outcome, heard);
    }
    let fail = |outcome: &mut Outcome, message: String| {
        progress.note(&format!("error: {message}"));
        outcome.errors.push(message);
    };

    // Every source at once: they are independent, and each caps its own requests.
    progress.step(&format!("read {} source(s)", selected.len()));
    let readings = join_all(selected.iter().map(|source| read_shown(reader, source, progress, neighbours))).await;
    let mut desired: Vec<Desired> = Vec::new();
    let mut guarded: Vec<(&str, Vec<Guarded>)> = Vec::new();
    let mut succeeded: BTreeSet<&str> = BTreeSet::new();
    let mut partial: BTreeSet<&str> = BTreeSet::new();
    for (source, reading) in selected.iter().zip(readings) {
        match reading {
            Ok(reading) => {
                succeeded.insert(&source.name);
                outcome
                    .warnings
                    .extend(reading.warnings.into_iter().map(|warning| format!("{}: {warning}", source.name)));
                // A part that could not be read is an error of the run; the
                // source is then no longer one that can say an object is gone.
                if !reading.errors.is_empty() {
                    partial.insert(&source.name);
                }
                for error in reading.errors {
                    fail(&mut outcome, format!("{}: {error}", source.name));
                }
                desired.extend(reading.objects);
                guarded.push((&source.name, reading.guarded));
                heard.extend(reading.heard);
            }
            // A source that could not be read is left out: what NetBox holds from it stays.
            Err(reason) => fail(&mut outcome, format!("{}: {reason}", source.name)),
        }
    }
    outcome.warnings.extend(reader.warnings());
    if succeeded.is_empty() {
        return (outcome, heard);
    }

    // Every kind is read, not only the reported ones: what a source stopped
    // reporting altogether (its last disk, its last cluster) is an orphan of a
    // kind that is no longer among the desired objects.
    progress.step("read NetBox");
    let kinds: BTreeSet<Kind> = Kind::ALL.into();
    // One unit for each list: they answer one by one, the largest last.
    let left: Mutex<BTreeSet<&str>> = Mutex::new(kinds.iter().map(|kind| kind.endpoint()).collect());
    let listed = |endpoint: &str| {
        let mut left = left.lock().unwrap_or_else(PoisonError::into_inner);
        left.remove(endpoint);
        progress.advance(None);
        progress.doing(&lists_left(&left));
    };
    let loaded = match load_shown(gateway, &kinds, &listed).await {
        Ok(loaded) => loaded,
        Err(error) => {
            fail(&mut outcome, error.to_string());
            return (outcome, heard);
        }
    };
    outcome.warnings.extend(loaded.warnings);

    // The VLAN group a source keeps its VLANs in is a prerequisite, as its
    // site is not: nothing creates it. A source that refers to one NetBox
    // does not hold fails alone, before anything is compared: written without
    // it, its VLANs would belong to no site and to no group.
    let groups_held: BTreeSet<&[String]> = loaded
        .current
        .iter()
        .filter(|object| object.kind == Kind::VlanGroup)
        .map(|object| object.identity.key())
        .collect();
    for source in selected {
        let missing: BTreeSet<&str> = desired
            .iter()
            .filter(|object| object.source == source.name)
            .flat_map(|object| object.references.values().flatten())
            .filter(|target| target.kind == Kind::VlanGroup && !groups_held.contains(target.identity.key()))
            .map(|target| target.identity.label())
            .collect();
        if missing.is_empty() {
            continue;
        }
        let missing: Vec<&str> = missing.into_iter().collect();
        let message = format!(
            "{}: VLAN group {} is not in NetBox: create it, the VLANs of the sites of [[vlan_groups]] are kept in \
             it; nothing is written for this source",
            source.name,
            missing.join(", ")
        );
        fail(&mut outcome, message);
        // Failed: what it reported is dropped, and what NetBox holds from it stays.
        succeeded.remove(source.name.as_str());
        partial.remove(source.name.as_str());
        desired.retain(|object| object.source != source.name);
        guarded.retain(|(name, _)| *name != source.name);
    }
    if succeeded.is_empty() {
        return (outcome, heard);
    }

    // What a BMC says is only written for a device NetBox shows to be its server.
    for (source, reports) in guarded {
        let (objects, warnings) = admit(reports, &loaded.current);
        desired.extend(objects);
        outcome.warnings.extend(warnings.into_iter().map(|warning| format!("{source}: {warning}")));
    }

    // The hardware of a device a BMC documents is the BMC's to tell, in this
    // run or in another: a hypervisor that reports the device only fills what
    // NetBox does not have, so that the two never write over one another.
    let documented: BTreeSet<&str> =
        configured.iter().flat_map(|source| source.bmcs.iter().map(|bmc| bmc.device.as_str())).collect();
    for object in &mut desired {
        if object.kind == Kind::Device && !object.complement && documented.contains(object.identity.label()) {
            for hardware in HARDWARE_FIELDS {
                object.only_when_empty.insert(hardware.to_owned());
            }
        }
    }

    if let Err(message) = undefined_custom_fields(gateway, &desired).await {
        fail(&mut outcome, message);
        return (outcome, heard);
    }

    let chosen: BTreeSet<&str> = selected.iter().map(|source| source.name.as_str()).collect();
    let facts = configured.iter().map(|source| SourceFacts {
        name: source.name.clone(),
        tag: source_tag(&source.name),
        status: if partial.contains(source.name.as_str()) {
            SourceStatus::Partial
        } else if succeeded.contains(source.name.as_str()) {
            SourceStatus::Succeeded
        } else if chosen.contains(source.name.as_str()) {
            SourceStatus::Failed
        } else {
            SourceStatus::Skipped
        },
        // Forced off for a BMC source, whatever was read from the file.
        prune: source.prune && !source.r#type.is_bmc(),
        create_devices: source.create_devices && !source.r#type.is_bmc(),
    });
    let run = Run {
        sources: facts.collect(),
        priority: priority.to_vec(),
        unique_ip_vrfs: loaded.unique_ip_vrfs,
        // How the sources mark the tags they create, and how netbox-sync
        // marked the ones it made from vSphere tags: such a tag leaves a
        // machine once its source no longer tags it. Any other tag is somebody's.
        source_tag_markers: std::iter::once(TAG_MARKER).chain(LEGACY_TAG_MARKERS).map(str::to_owned).collect(),
    };
    // The tags every object carries have to exist before they are attached. A
    // BMC source that has nothing to write this time asks for none: a run that
    // completes no device leaves NetBox as it found it.
    let reporting: BTreeSet<&str> = desired.iter().map(|object| object.source.as_str()).collect();
    let silent = |source: &&Hypervisor| source.r#type.is_bmc() && !reporting.contains(source.name.as_str());
    let silent: BTreeSet<&str> = configured.iter().filter(silent).map(|source| source.name.as_str()).collect();
    let tagging = Run {
        sources: run.sources.iter().filter(|facts| !silent.contains(facts.name.as_str())).cloned().collect(),
        ..run.clone()
    };
    desired.extend(ownership_tags(&tagging, &loaded.current));
    progress.step("compare");
    let plan = reconcile(&desired, &loaded.current, &run);
    outcome.changes = plan.changes();
    // Each starts with the source it is about, as its errors do: the check
    // takes it back at the next run of that source alone.
    outcome.warnings.extend(plan.warnings.iter().map(ToString::to_string));
    // What a source asks for and NetBox would refuse: left out of the plan, and an error of the run.
    for error in &plan.errors {
        fail(&mut outcome, error.clone());
    }
    // The VLANs of a site nobody owns that the group of the site now holds: never touched, only told.
    outcome.warnings.extend(site_vlan_leftovers(&loaded.current, vlan_groups));
    progress.advance(None);

    // A dry run writes nothing: its units are all done.
    if !gateway.dry_run() {
        progress.resize(selected.len() as u64 + STEPS + plan.steps.len() as u64);
    }
    progress.step(if gateway.dry_run() { "nothing is written: dry run" } else { "write" });
    match apply(gateway, &plan, || progress.advance(None)).await {
        Ok(applied) => outcome.applied = applied.written,
        Err(error) => {
            outcome.applied = error.applied;
            fail(&mut outcome, error.message);
        }
    }
    (outcome, heard)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use omnisync_core::change::Action;
    use omnisync_core::inventory::model::{Identity, Target};

    use omnisync_core::network::inventory::{Secret, Wanted};
    use omnisync_core::progress::NullProgress;
    use omnisync_netbox::testing::FakeGateway;

    use super::*;
    use crate::dns::testing as dns;
    use crate::fake_pve;

    fn hypervisor(name: &str, r#type: HypervisorType) -> Hypervisor {
        Hypervisor {
            name: name.to_owned(),
            r#type,
            host: "192.0.2.10".to_owned(),
            port: None,
            validate_certs: true,
            ca_file: None,
            site: Some("Paris".to_owned()),
            tenant: None,
            host_role: None,
            vm_role: None,
            domain: None,
            ignore_templates: true,
            ignored_subnets: Vec::new(),
            permitted_subnets: Vec::new(),
            interface_filter: None,
            dns_name_lookup: false,
            dns_servers: Vec::new(),
            create_devices: true,
            prune: true,
            vlan_group: None,
            bmcs: Vec::new(),
            credentials: Wanted::Held(Credentials::Password {
                username: "sync".to_owned(),
                password: Secret::new("pw"),
            }),
            neighbors: false,
            ssh: None,
        }
    }

    /// A reader that answers from a table, by source name, and remembers who was read.
    #[derive(Default)]
    struct Scripted {
        answers: BTreeMap<String, Result<Reading, String>>,
        read: Mutex<Vec<String>>,
        /// What the reader says of the run as a whole.
        said: Vec<String>,
    }

    impl Scripted {
        fn answering<const N: usize>(answers: [(&str, Result<Reading, String>); N]) -> Self {
            Scripted {
                answers: answers.into_iter().map(|(name, answer)| (name.to_owned(), answer)).collect(),
                read: Mutex::new(Vec::new()),
                said: Vec::new(),
            }
        }
    }

    impl Reader for Scripted {
        async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
            self.read.lock().unwrap().push(source.name.clone());
            self.answers[&source.name].clone()
        }

        fn warnings(&self) -> Vec<String> {
            self.said.clone()
        }
    }

    /// A cluster type and a cluster of that type, as a source reports them.
    fn cluster(source: &str, name: &str) -> Reading {
        let kind = Desired::new(Kind::ClusterType, Identity::named("Proxmox"), source)
            .field("name", "Proxmox")
            .create_only("slug", "proxmox");
        let cluster = Desired::new(Kind::Cluster, Identity::named(name), source).field("name", name).reference(
            "type",
            Kind::ClusterType,
            Identity::named("Proxmox"),
        );
        Reading { objects: vec![kind, cluster], ..Reading::default() }
    }

    /// `cluster()` and the VLAN `vid` of the VLAN group `East`, as a source whose site is in that group reports it.
    fn cluster_with_group_vlan(source: &str, name: &str, vid: u64, vlan_name: &str) -> Reading {
        let mut reading = cluster(source, name);
        let identity = Identity::vlan(omnisync_core::inventory::model::VlanScope::Group("East"), vid);
        reading.objects.push(
            Desired::new(Kind::Vlan, identity, source)
                .field("vid", vid)
                .create_only("name", vlan_name)
                .ensure_only()
                .reference("group", Kind::VlanGroup, Identity::named("East")),
        );
        reading
    }

    fn in_east(name: &str) -> Hypervisor {
        Hypervisor {
            site: Some("east-01".to_owned()),
            vlan_group: Some("East".to_owned()),
            ..hypervisor(name, HypervisorType::Proxmox)
        }
    }

    #[tokio::test]
    async fn a_source_whose_vlan_group_netbox_does_not_hold_fails_alone_and_writes_nothing() {
        let sources = [in_east("pve-a"), hypervisor("pve-b", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let reader = Scripted::answering([
            ("pve-a", Ok(cluster_with_group_vlan("pve-a", "lab-a", 10, "VLAN10"))),
            ("pve-b", Ok(cluster("pve-b", "lab-b"))),
        ]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(
            outcome.errors,
            ["pve-a: VLAN group East is not in NetBox: create it, the VLANs of the sites of [[vlan_groups]] are kept \
              in it; nothing is written for this source"]
        );
        // The other source is written; nothing of the first one is, and no group is created for it.
        assert_eq!(created(&outcome, "cluster"), ["lab-b"]);
        assert_eq!(created(&outcome, "vlan"), Vec::<String>::new());
        assert_eq!(created(&outcome, "vlan_group"), Vec::<String>::new());
        assert!(netbox.find("virtualization.clusters", "name", &serde_json::json!("lab-a")).is_none());
        assert!(netbox.find("ipam.vlans", "vid", &serde_json::json!(10)).is_none());
    }

    #[tokio::test]
    async fn a_source_whose_vlan_group_is_gone_orphans_nothing_it_wrote_before() {
        let sources = [in_east("pve-a")];
        let netbox = FakeGateway::new();
        let group = netbox.add("ipam.vlan_groups", serde_json::json!({"name": "East", "slug": "east"}));
        let reader = Scripted::answering([("pve-a", Ok(cluster_with_group_vlan("pve-a", "lab-a", 10, "VLAN10")))]);
        let first = run_all(&sources, &netbox, &reader).await;
        assert_eq!(first.errors, Vec::<String>::new());
        assert_eq!(created(&first, "vlan"), ["10"]);
        // The VLAN is in the group, and at no site.
        let vlan = netbox.find("ipam.vlans", "vid", &serde_json::json!(10)).expect("the VLAN");
        let vlan = netbox.row("ipam.vlans", vlan).expect("its row");
        assert_eq!(vlan.get("group"), Some(&serde_json::json!(group)));
        assert!(vlan.get("site").is_none_or(serde_json::Value::is_null), "{vlan:?}");
        // A second run writes nothing.
        assert_eq!(run_all(&sources, &netbox, &reader).await.changes, []);
    }

    #[tokio::test]
    async fn a_vlan_name_the_group_already_has_is_an_error_of_its_source_and_the_rest_is_written() {
        let sources = [in_east("pve-a")];
        let netbox = FakeGateway::new();
        let group = netbox.add("ipam.vlan_groups", serde_json::json!({"name": "East", "slug": "east"}));
        netbox.add("ipam.vlans", serde_json::json!({"group": group, "vid": 120, "name": "dmz"}));
        let reader = Scripted::answering([("pve-a", Ok(cluster_with_group_vlan("pve-a", "lab-a", 130, "dmz")))]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(
            outcome.errors,
            ["pve-a: vlan 130: its name dmz is the one of VLAN 120 in VLAN group East; the VLAN is not created"]
        );
        assert_eq!(created(&outcome, "vlan"), Vec::<String>::new());
        assert_eq!(created(&outcome, "cluster"), ["lab-a"]);
    }

    #[tokio::test]
    async fn a_vlan_of_a_site_nobody_owns_that_its_group_holds_too_is_told_and_left_alone() {
        let sources = [in_east("pve-a")];
        let netbox = FakeGateway::new();
        let site = netbox.add("dcim.sites", serde_json::json!({"name": "east-01", "slug": "east-01"}));
        let group = netbox.add("ipam.vlan_groups", serde_json::json!({"name": "East", "slug": "east"}));
        let by_hand = netbox.add("ipam.vlans", serde_json::json!({"site": site, "vid": 15, "name": "housing"}));
        netbox.add("ipam.vlans", serde_json::json!({"group": group, "vid": 15, "name": "housing"}));
        let reader = Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab-a")))]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(
            outcome.warnings,
            ["vlan 15 of site east-01: VLAN group East holds this VLAN, and nobody owns the one of the site; no \
              interface points to it any more: delete it by hand"]
        );
        assert!(netbox.row("ipam.vlans", by_hand).is_some());
        assert!(!outcome.changes.iter().any(|change| change.kind == "vlan"));
    }

    // The VLAN groups come from the table, not from the sources: a site of the
    // group that no hypervisor source is at is told all the same.
    #[tokio::test]
    async fn a_leftover_vlan_of_a_site_no_hypervisor_is_at_is_told_from_the_table() {
        let sources = [in_east("pve-a")];
        let netbox = FakeGateway::new();
        let site = netbox.add("dcim.sites", serde_json::json!({"name": "east-02", "slug": "east-02"}));
        let group = netbox.add("ipam.vlan_groups", serde_json::json!({"name": "East", "slug": "east"}));
        netbox.add("ipam.vlans", serde_json::json!({"site": site, "vid": 15, "name": "housing"}));
        netbox.add("ipam.vlans", serde_json::json!({"group": group, "vid": 15, "name": "housing"}));
        let mut table = VlanGroups::default();
        table.insert("east-02", "East");
        table.insert("east-01", "East");
        let reader = Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab-a")))]);
        let selected: Vec<&Hypervisor> = sources.iter().collect();
        let outcome = run_with_groups(&sources, &selected, &[], &table, &netbox, &reader, &NullProgress).await;
        assert_eq!(
            outcome.warnings,
            ["vlan 15 of site east-02: VLAN group East holds this VLAN, and nobody owns the one of the site; no \
              interface points to it any more: delete it by hand"]
        );
    }

    fn created(outcome: &Outcome, kind: &str) -> Vec<String> {
        outcome
            .changes
            .iter()
            .filter(|change| change.kind == kind && change.action == Action::Create)
            .map(|change| change.key.clone())
            .collect()
    }

    async fn run_all(sources: &[Hypervisor], netbox: &FakeGateway, reader: &Scripted) -> Outcome {
        run_all_with(sources, netbox, reader).await
    }

    async fn run_all_with<R: Reader>(sources: &[Hypervisor], netbox: &FakeGateway, reader: &R) -> Outcome {
        let selected: Vec<&Hypervisor> = sources.iter().collect();
        run(sources, &selected, &[], netbox, reader, &NullProgress).await
    }

    #[test]
    fn the_tag_of_a_source_is_the_one_the_old_tools_gave_it() {
        // netbox-ssot: "source-" + Slugify("proxmox.lab01"); netbox-sync: the slug of "Source: vcenter60.lab01".
        assert_eq!(source_tag("proxmox.lab01"), "source-proxmoxlab01");
        assert_eq!(source_tag("lab02-vcenter-cluster0.example"), "source-lab02-vcenter-cluster0example");
    }

    #[test]
    fn the_domain_of_a_source_is_appended_after_a_dot_written_or_not() {
        let suffix = |domain: Option<&str>| {
            let source =
                Hypervisor { domain: domain.map(str::to_owned), ..hypervisor("pve-a", HypervisorType::Proxmox) };
            proxmox_settings(&source).unwrap().domain
        };
        assert_eq!(suffix(Some("example.net")), ".example.net");
        assert_eq!(suffix(Some(".lab01")), ".lab01");
        assert_eq!(suffix(None), "");
    }

    #[test]
    fn a_proxmox_source_without_site_is_refused() {
        let source = Hypervisor { site: None, ..hypervisor("pve-a", HypervisorType::Proxmox) };
        assert_eq!(proxmox_settings(&source).unwrap_err(), "a proxmox source needs a site");
    }

    #[tokio::test]
    async fn a_source_is_read_compared_and_written() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let reader = Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab")))]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(created(&outcome, "cluster"), ["lab"]);
        assert_eq!(created(&outcome, "cluster_type"), ["Proxmox"]);
        assert!(netbox.find("virtualization.clusters", "name", &serde_json::json!("lab")).is_some());
        // Every change of the report was written.
        assert_eq!(outcome.applied, outcome.changes.len());
    }

    /// A cluster carrying a custom field, as a source that fills one reports it.
    fn cluster_with_custom_field() -> Reading {
        let mut reading = cluster("pve-a", "lab");
        let with_field = reading.objects.pop().unwrap().custom_field("source_id", "cluster/lab");
        reading.objects.push(with_field);
        reading
    }

    #[tokio::test]
    async fn a_custom_field_netbox_does_not_define_stops_the_run_before_any_write() {
        // NetBox refuses a write that carries a custom field it does not define:
        // met at that write, the run would stop half way through its plan.
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        netbox.add("extras.custom_fields", serde_json::json!({"name": "source_id", "object_types": ["dcim.device"]}));
        let reader = Scripted::answering([("pve-a", Ok(cluster_with_custom_field()))]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(
            outcome.errors,
            ["NetBox defines no custom field source_id on cluster: create it before syncing; nothing was written"]
        );
        assert_eq!(outcome.changes, []);
        assert_eq!(netbox.writes(), []);
    }

    #[tokio::test]
    async fn a_custom_field_netbox_defines_is_written() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let types = serde_json::json!(["dcim.device", "virtualization.cluster"]);
        netbox.add("extras.custom_fields", serde_json::json!({"name": "source_id", "object_types": types}));
        let reader = Scripted::answering([("pve-a", Ok(cluster_with_custom_field()))]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(created(&outcome, "cluster"), ["lab"]);
    }

    /// A host as a vCenter reports it, with the serial the vCenter knows.
    fn host_with_serial(source: &str, name: &str, serial: &str) -> Reading {
        let host =
            Desired::new(Kind::Device, Identity::device(name), source).field("name", name).field("serial", serial);
        Reading { objects: vec![host], ..Reading::default() }
    }

    #[tokio::test]
    async fn the_hardware_of_a_device_a_bmc_documents_is_the_bmc_s_to_tell() {
        // A vCenter runs every five minutes, a BMC source once a day: each
        // alone would write the serial it knows over the other's. The BMC is
        // the hardware: where one is configured for a device, a hypervisor only
        // fills a serial NetBox does not have.
        let vcenter = hypervisor("vc-a", HypervisorType::Vmware);
        let bmcs = Hypervisor {
            bmcs: vec![Bmc { device: "esx01".to_owned(), host: "drac-esx01".to_owned(), fingerprint: None }],
            ..hypervisor("bmc-a", HypervisorType::Redfish)
        };
        let reader = Scripted::answering([("vc-a", Ok(host_with_serial("vc-a", "esx01", "FROM-VCENTER")))]);
        let serial_after = |configured: Vec<Hypervisor>, held: &'static str| {
            let reader = &reader;
            async move {
                let netbox = FakeGateway::new();
                // Held by this tool for the vCenter, as a first run leaves it.
                let tool = netbox
                    .add("extras.tags", serde_json::json!({"name": "netbox-omnisync", "slug": "netbox-omnisync"}));
                let source =
                    netbox.add("extras.tags", serde_json::json!({"name": "source-vc-a", "slug": "source-vc-a"}));
                let device = serde_json::json!({"name": "esx01", "site": 12, "serial": held, "tags": [tool, source]});
                let id = netbox.add("dcim.devices", device);
                let outcome = run(&configured, &[&configured[0]], &[], &netbox, reader, &NullProgress).await;
                assert_eq!(outcome.errors, Vec::<String>::new());
                netbox.row("dcim.devices", id).unwrap()["serial"].clone()
            }
        };
        // The BMC source is configured, though left out of this run.
        assert_eq!(serial_after(vec![vcenter.clone(), bmcs.clone()], "FROM-BMC").await, "FROM-BMC");
        assert_eq!(serial_after(vec![vcenter.clone(), bmcs], "").await, "FROM-VCENTER");
        // No BMC documents the device: the vCenter tells its serial.
        assert_eq!(serial_after(vec![vcenter], "FROM-BMC").await, "FROM-VCENTER");
    }

    /// A progress that writes down what it is told.
    #[derive(Default)]
    struct Told(Mutex<Vec<String>>);

    impl Told {
        fn told(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }

        fn tell(&self, event: String) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl Progress for Told {
        fn begin(&self, total: u64) {
            self.tell(format!("begin {total}"));
        }

        fn resize(&self, total: u64) {
            self.tell(format!("resize {total}"));
        }

        fn step(&self, label: &str) {
            self.tell(format!("step {label}"));
        }

        fn doing(&self, label: &str) {
            self.tell(format!("doing {label}"));
        }

        fn advance(&self, lane: Option<&str>) {
            self.tell(format!("advance {}", lane.unwrap_or("-")));
        }

        fn lane_start(&self, lane: &str, total: u64) {
            self.tell(format!("lane {lane} {total}"));
        }

        fn lane_doing(&self, _lane: &str, _label: &str) {}

        fn lane_end(&self, lane: &str) {
            self.tell(format!("lane end {lane}"));
        }

        fn note(&self, _text: &str) {}

        fn end(&self) {
            self.tell("end".to_owned());
        }
    }

    #[tokio::test]
    async fn a_run_shows_its_progress_from_the_first_read_to_the_last_write() {
        // On a terminal nothing is drawn before `begin`: a run that never
        // begins looks hung for as long as it reads.
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox), hypervisor("pve-b", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let reader = Scripted::answering([
            ("pve-a", Ok(cluster("pve-a", "lab-a"))),
            ("pve-b", Err("connection refused".to_owned())),
        ]);
        let selected: Vec<&Hypervisor> = sources.iter().collect();
        let told = Told::default();
        let outcome = run(&sources, &selected, &[], &netbox, &reader, &told).await;
        let events = told.told();
        // Two sources to read, the 21 lists of NetBox, the comparison: 24 units, known from the start.
        assert_eq!(events.first().map(String::as_str), Some("begin 24"));
        assert_eq!(events.last().map(String::as_str), Some("end"));
        // Each source has its row while it is read, whatever its read gives.
        for name in ["pve-a", "pve-b"] {
            let position =
                |event: String| events.iter().position(|told| *told == event).unwrap_or_else(|| panic!("{event}"));
            let (start, done, end) = (
                position(format!("lane {name} 1")),
                position(format!("advance {name}")),
                position(format!("lane end {name}")),
            );
            assert!(start < done && done < end, "{events:?}");
        }
        // The writes are counted once the comparison knows them, then one unit each.
        let writes = outcome.applied as u64;
        assert!(writes > 0);
        assert!(events.contains(&format!("resize {}", 24 + writes)), "{events:?}");
        // One unit for each list of NetBox, one for the comparison, one for each write.
        assert_eq!(events.iter().filter(|event| *event == "advance -").count() as u64, 22 + writes);
        // While NetBox is read the run says how many lists it still waits for,
        // and names them once few are left.
        assert!(events.contains(&"doing 20 list(s) left".to_owned()), "{events:?}");
        assert_eq!(events.iter().filter(|event| event.starts_with("doing 1 list(s) left: ")).count(), 1, "{events:?}");
    }

    #[tokio::test]
    async fn a_run_that_stops_early_still_ends_its_progress() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let reader = Scripted::answering([("pve-a", Err("connection refused".to_owned()))]);
        let told = Told::default();
        run(&sources, &[&sources[0]], &[], &netbox, &reader, &told).await;
        assert_eq!(told.told().last().map(String::as_str), Some("end"));
        // No source selected: nothing is shown at all.
        let nothing = Told::default();
        run(&sources, &[], &[], &netbox, &reader, &nothing).await;
        assert_eq!(nothing.told(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_second_run_changes_nothing() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let reader = Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab")))]);
        run_all(&sources, &netbox, &reader).await;
        let again = run_all(&sources, &netbox, &reader).await;
        assert_eq!(again.changes, []);
        assert_eq!((again.errors.len(), again.applied), (0, 0));
    }

    #[tokio::test]
    async fn a_dry_run_reports_the_changes_and_writes_nothing() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        netbox.refuse_writes(true);
        let reader = Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab")))]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(created(&outcome, "cluster"), ["lab"]);
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(netbox.writes(), []);
        assert_eq!(netbox.refused(), []);
    }

    #[tokio::test]
    async fn a_source_that_fails_is_an_error_and_the_others_go_on() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox), hypervisor("pve-b", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let reader = Scripted::answering([
            ("pve-a", Err("GET /version answered 401".to_owned())),
            ("pve-b", Ok(cluster("pve-b", "lab-b"))),
        ]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(outcome.errors, ["pve-a: GET /version answered 401"]);
        assert_eq!(created(&outcome, "cluster"), ["lab-b"]);
    }

    #[tokio::test]
    async fn a_source_that_fails_keeps_what_netbox_holds_from_it() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox), hypervisor("pve-b", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let both =
            Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab-a"))), ("pve-b", Ok(cluster("pve-b", "lab-b")))]);
        run_all(&sources, &netbox, &both).await;
        let failing = Scripted::answering([
            ("pve-a", Err("connection refused".to_owned())),
            ("pve-b", Ok(cluster("pve-b", "lab-b"))),
        ]);
        let outcome = run_all(&sources, &netbox, &failing).await;
        assert_eq!(outcome.changes, []);
        assert!(netbox.find("virtualization.clusters", "name", &serde_json::json!("lab-a")).is_some());
    }

    /// The scope of a run without VLAN group, asking the hosts what they hear or not.
    fn hearing(neighbours: bool) -> Scope<'static> {
        static NO_GROUPS: std::sync::LazyLock<VlanGroups> = std::sync::LazyLock::new(VlanGroups::default);
        Scope { vlan_groups: &NO_GROUPS, neighbours }
    }

    #[tokio::test]
    async fn a_vcenter_that_fails_leaves_the_cables_of_its_hosts_alone() {
        let sources = [hypervisor("vc-a", HypervisorType::Vmware), hypervisor("vc-b", HypervisorType::Vmware)];
        let netbox = FakeGateway::new();
        let heard = |host: &str| Heard {
            host: host.to_owned(),
            card: "vmnic0".to_owned(),
            switch: "nexus01".to_owned(),
            port: "Ethernet1/3".to_owned(),
        };
        let reading = |host: &str| Reading { heard: vec![heard(host)], ..Reading::default() };
        let failing =
            Scripted::answering([("vc-a", Err("connection refused".to_owned())), ("vc-b", Ok(reading("esx02")))]);
        let selected: Vec<&Hypervisor> = sources.iter().collect();
        let (_, told) = run_hearing(&sources, &selected, &[], &hearing(true), &netbox, &failing, &NullProgress).await;
        // What the hosts of vc-a hear is not known: nothing is said of their cables.
        assert_eq!(told, [heard("esx02")]);
    }

    #[tokio::test]
    async fn a_source_left_out_of_the_run_keeps_what_netbox_holds_from_it() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox), hypervisor("pve-b", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let both =
            Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab-a"))), ("pve-b", Ok(cluster("pve-b", "lab-b")))]);
        run_all(&sources, &netbox, &both).await;
        let only_b = Scripted::answering([("pve-b", Ok(cluster("pve-b", "lab-b")))]);
        let outcome = run(&sources, &[&sources[1]], &[], &netbox, &only_b, &NullProgress).await;
        assert_eq!(outcome.changes, []);
        assert_eq!(*only_b.read.lock().unwrap(), ["pve-b"]);
        assert!(netbox.find("virtualization.clusters", "name", &serde_json::json!("lab-a")).is_some());
    }

    #[tokio::test]
    async fn what_a_source_no_longer_reports_is_deleted_when_it_prunes() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        run_all(&sources, &netbox, &Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab")))])).await;
        // The cluster is gone from the source; its type stays.
        let mut without = cluster("pve-a", "lab");
        without.objects.truncate(1);
        let outcome = run_all(&sources, &netbox, &Scripted::answering([("pve-a", Ok(without))])).await;
        let deleted: Vec<&str> = outcome
            .changes
            .iter()
            .filter(|change| change.action == Action::Delete)
            .map(|change| change.key.as_str())
            .collect();
        assert_eq!(deleted, ["lab"]);
        assert!(netbox.find("virtualization.clusters", "name", &serde_json::json!("lab")).is_none());
    }

    #[tokio::test]
    async fn the_warnings_of_a_source_are_reported() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let mut reading = cluster("pve-a", "lab");
        reading.warnings.push("vm 205: name already used by vmid 101".to_owned());
        let outcome = run_all(&sources, &netbox, &Scripted::answering([("pve-a", Ok(reading))])).await;
        assert_eq!(outcome.warnings, ["pve-a: vm 205: name already used by vmid 101"]);
    }

    #[tokio::test]
    async fn what_the_reader_says_of_the_whole_run_is_reported_once_under_no_source() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox), hypervisor("pve-b", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let mut reader =
            Scripted::answering([("pve-a", Ok(cluster("pve-a", "lab-a"))), ("pve-b", Ok(cluster("pve-b", "lab-b")))]);
        reader.said = vec!["reverse DNS: 3 of 40 lookups failed (3 timed out)".to_owned()];
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(outcome.warnings, ["reverse DNS: 3 of 40 lookups failed (3 timed out)"]);
        assert_eq!(outcome.errors, Vec::<String>::new());
    }

    /// Reads the fake Proxmox of the fixtures as the tool reads a real one, with the lookups of one run.
    struct Fixtures {
        url: String,
        lookups: ReverseLookups,
    }

    impl Reader for Fixtures {
        async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
            read_proxmox_at(source, &self.url, &self.lookups).await
        }

        fn warnings(&self) -> Vec<String> {
            self.lookups.warning().into_iter().collect()
        }
    }

    /// A shell that answers each node of the 8.4 fixtures with what lldpcli
    /// printed there, and remembers what it was asked.
    #[derive(Default)]
    struct Lldpd {
        ran: Mutex<Vec<String>>,
    }

    impl Shell for Lldpd {
        async fn run(&self, node: &str, command: &str) -> Result<String, String> {
            self.ran.lock().unwrap().push(format!("{node}: {command}"));
            let file = format!("{}/../proxmox/tests/fixtures/lldpd/{node}.json", env!("CARGO_MANIFEST_DIR"));
            std::fs::read_to_string(&file).map_err(|error| error.to_string())
        }
    }

    /// Reads the fake Proxmox of the fixtures, and its nodes through `shell`
    /// when the run and the entry ask for it, as [`Apis`] does.
    struct Nodes {
        url: String,
        shell: Lldpd,
    }

    impl Reader for Nodes {
        async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
            self.read_hearing(source, false).await
        }

        async fn read_hearing(&self, source: &Hypervisor, neighbours: bool) -> Result<Reading, String> {
            let shell = asks_its_nodes(source, neighbours).then_some(&self.shell);
            read_proxmox_hearing_at(source, &self.url, &ReverseLookups::system(), shell).await
        }
    }

    fn hearing_source(neighbors: bool) -> Hypervisor {
        Hypervisor { neighbors, domain: Some("lab.example".to_owned()), ..fixture_source("pve-a", false) }
    }

    #[tokio::test]
    async fn a_node_is_only_logged_into_when_the_entry_asks_for_it() {
        let server = fake_pve::serve(fake_pve::fixture("8.4")).await;
        let netbox = netbox_of_netbox_ssot();
        let silent = [hearing_source(false)];
        let reader = Nodes { url: server.uri(), shell: Lldpd::default() };
        let selected: Vec<&Hypervisor> = silent.iter().collect();
        let (_, heard) = run_hearing(&silent, &selected, &[], &hearing(true), &netbox, &reader, &NullProgress).await;
        assert_eq!((heard.len(), reader.shell.ran.lock().unwrap().len()), (0, 0));
        let asking = [hearing_source(true)];
        let selected: Vec<&Hypervisor> = asking.iter().collect();
        let (_, heard) = run_hearing(&asking, &selected, &[], &hearing(true), &netbox, &reader, &NullProgress).await;
        let mut ran = reader.shell.ran.lock().unwrap().clone();
        ran.sort();
        assert_eq!(
            ran,
            [
                "pve01: lldpcli -f json show neighbors",
                "pve02: lldpcli -f json show neighbors",
                "pve03: lldpcli -f json show neighbors",
            ]
        );
        // pve01.json: "eno1" ... "nexus04.lab.example" ... "Ethernet1/27"; the node is named with its domain.
        let first = Heard {
            host: "pve01.lab.example".to_owned(),
            card: "eno1".to_owned(),
            switch: "nexus04.lab.example".to_owned(),
            port: "Ethernet1/27".to_owned(),
        };
        assert!(heard.contains(&first), "{heard:?}");
        assert_eq!(heard.len(), 18);
    }

    #[tokio::test]
    async fn a_run_of_the_hypervisors_alone_never_logs_into_a_node() {
        let server = fake_pve::serve(fake_pve::fixture("8.4")).await;
        let netbox = netbox_of_netbox_ssot();
        let sources = [hearing_source(true)];
        let reader = Nodes { url: server.uri(), shell: Lldpd::default() };
        let selected: Vec<&Hypervisor> = sources.iter().collect();
        let (_, heard) = run_hearing(&sources, &selected, &[], &hearing(false), &netbox, &reader, &NullProgress).await;
        assert_eq!(heard, []);
        assert_eq!(*reader.shell.ran.lock().unwrap(), Vec::<String>::new());
    }

    /// A NetBox that defines the custom fields netbox-ssot filled, on everything.
    fn netbox_of_netbox_ssot() -> FakeGateway {
        let netbox = FakeGateway::new();
        let everything: Vec<&str> = Kind::ALL.into_iter().map(Kind::content_type).collect();
        for name in ["source", "source_id", "host_cpu_cores", "host_memory", "arp_entry"] {
            netbox.add("extras.custom_fields", serde_json::json!({"name": name, "object_types": everything}));
        }
        netbox
    }

    /// The Proxmox 8.4 of the fixtures with the interface filter of production (the bridges of the
    /// Docker hosts carry the same addresses on several machines), read with or without the lookups.
    fn fixture_source(name: &str, dns_name_lookup: bool) -> Hypervisor {
        let filter = regex::Regex::new("veth|docker|br-|isatap|vEthernet|Loopback").unwrap();
        Hypervisor { dns_name_lookup, interface_filter: Some(filter), ..hypervisor(name, HypervisorType::Proxmox) }
    }

    /// The `dns_name` NetBox holds for an address; `None` when it holds none.
    fn held_name(netbox: &FakeGateway, address: &str) -> Option<String> {
        let id = netbox.find("ipam.ip_addresses", "address", &serde_json::json!(address)).expect("the address");
        let row = netbox.row("ipam.ip_addresses", id).unwrap();
        row.get("dns_name").and_then(|name| name.as_str()).filter(|name| !name.is_empty()).map(str::to_owned)
    }

    #[tokio::test]
    async fn a_source_that_asks_for_it_gets_its_dns_names_written_and_a_second_run_changes_nothing() {
        let server = fake_pve::serve(fake_pve::fixture("8.4")).await;
        let sources = [fixture_source("pve-a", true)];
        let netbox = netbox_of_netbox_ssot();
        // "ip-address": "198.18.0.70" of "ens18" of vm042.example; "198.18.0.71" has no record here.
        let resolver = dns::Scripted::answering([("198.18.0.70", "VM042.Infra.Example.")]);
        let reader = Fixtures { url: server.uri(), lookups: resolver.lookups() };
        let outcome = run_all_with(&sources, &netbox, &reader).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(outcome.warnings, Vec::<String>::new());
        assert_eq!(held_name(&netbox, "198.18.0.70/26").as_deref(), Some("vm042.infra.example"));
        // Each address was asked once, and none of the link-local ones ("169.254.210.12", "fe80::96").
        let asked = resolver.asked.lock().unwrap().clone();
        assert_eq!(asked[&"198.18.0.70".parse::<IpAddr>().unwrap()], 1);
        assert_eq!(asked.values().copied().collect::<BTreeSet<usize>>(), BTreeSet::from([1]));
        assert!(!asked.contains_key(&"169.254.210.12".parse::<IpAddr>().unwrap()));
        assert!(!asked.contains_key(&"fe80::96".parse::<IpAddr>().unwrap()));

        // The next run is another process: it looks everything up again, and writes nothing.
        let reader = Fixtures { url: server.uri(), lookups: resolver.lookups() };
        let again = run_all_with(&sources, &netbox, &reader).await;
        assert_eq!(again.changes, []);
        assert_eq!((again.errors.len(), again.applied), (0, 0));
        assert_eq!(resolver.asked.lock().unwrap()[&"198.18.0.70".parse::<IpAddr>().unwrap()], 2);
    }

    // Proxmox says pve02 is offline ("status": "offline" in GET /nodes): its
    // guests cannot be read. The run fails for that node, writes what the
    // others report, and deletes nothing of what NetBox holds from pve02.
    #[tokio::test]
    async fn a_node_proxmox_says_is_offline_is_an_error_and_orphans_nothing() {
        let sources = [fixture_source("pve-a", false)];
        let netbox = netbox_of_netbox_ssot();
        let resolver = dns::Scripted::answering([]);
        let whole = fake_pve::serve(fake_pve::fixture("8.4")).await;
        let first = run_all_with(&sources, &netbox, &Fixtures { url: whole.uri(), lookups: resolver.lookups() }).await;
        assert_eq!(first.errors, Vec::<String>::new());

        let mut answers = fake_pve::fixture("8.4");
        let (_, nodes) = answers.get_mut("/nodes").unwrap();
        for entry in nodes["data"].as_array_mut().unwrap() {
            if entry["node"] == "pve02" {
                entry["status"] = serde_json::json!("offline");
            }
        }
        let degraded = fake_pve::serve(answers).await;
        let outcome =
            run_all_with(&sources, &netbox, &Fixtures { url: degraded.uri(), lookups: resolver.lookups() }).await;
        assert_eq!(outcome.errors, ["pve-a: node pve02 is offline: its guests are not read"]);
        let deleted: Vec<&omnisync_core::Change> =
            outcome.changes.iter().filter(|change| change.action == omnisync_core::Action::Delete).collect();
        assert_eq!(deleted, Vec::<&omnisync_core::Change>::new());
    }

    #[tokio::test]
    async fn names_are_not_looked_up_unless_the_source_asks_for_it() {
        let server = fake_pve::serve(fake_pve::fixture("8.4")).await;
        let sources = [fixture_source("pve-a", false)];
        let netbox = netbox_of_netbox_ssot();
        let resolver = dns::Scripted::answering([("198.18.0.70", "vm042.infra.example.")]);
        let reader = Fixtures { url: server.uri(), lookups: resolver.lookups() };
        let outcome = run_all_with(&sources, &netbox, &reader).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(held_name(&netbox, "198.18.0.70/26"), None);
        // Nothing was asked, and no resolver was even built.
        assert_eq!(*resolver.asked.lock().unwrap(), BTreeMap::new());
        assert_eq!(*resolver.built.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn lookups_that_fail_clear_no_name_fail_no_source_and_give_one_warning() {
        let server = fake_pve::serve(fake_pve::fixture("8.4")).await;
        let sources = [fixture_source("pve-a", true)];
        let netbox = netbox_of_netbox_ssot();
        let resolver = dns::Scripted::answering([("198.18.0.70", "vm042.infra.example.")]);
        run_all_with(&sources, &netbox, &Fixtures { url: server.uri(), lookups: resolver.lookups() }).await;
        assert_eq!(held_name(&netbox, "198.18.0.70/26").as_deref(), Some("vm042.infra.example"));

        // The resolver is down: every lookup fails.
        let down = dns::Scripted::failing("server failure");
        let outcome = run_all_with(&sources, &netbox, &Fixtures { url: server.uri(), lookups: down.lookups() }).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(outcome.changes, []);
        assert_eq!(held_name(&netbox, "198.18.0.70/26").as_deref(), Some("vm042.infra.example"));
        // One line for all of them, under no source: every lookup that was made failed.
        let [warning] = outcome.warnings.as_slice() else {
            panic!("one warning, not {:?}", outcome.warnings);
        };
        let asked = down.asked.lock().unwrap().len();
        assert!(asked > 1, "{asked}");
        let lowest = down.asked.lock().unwrap().keys().next().copied().unwrap();
        assert_eq!(
            *warning,
            format!(
                "reverse DNS: {asked} of {asked} lookups failed ({asked} in error, the first one {lowest}: \
                 server failure); the DNS names NetBox holds for these addresses are kept"
            )
        );

        // And a record that is gone (no answer at all) leaves the name too.
        let empty = dns::Scripted::answering([]);
        let outcome = run_all_with(&sources, &netbox, &Fixtures { url: server.uri(), lookups: empty.lookups() }).await;
        assert_eq!((outcome.changes.len(), outcome.warnings.len()), (0, 0));
        assert_eq!(held_name(&netbox, "198.18.0.70/26").as_deref(), Some("vm042.infra.example"));
    }

    #[tokio::test]
    async fn an_address_two_sources_report_is_looked_up_once_in_a_run() {
        let server = fake_pve::serve(fake_pve::fixture("8.4")).await;
        // Two entries that read the same cluster: every address is reported twice.
        let sources = [fixture_source("pve-a", true), fixture_source("pve-b", true)];
        let resolver = dns::Scripted::answering([("198.18.0.70", "vm042.infra.example.")]);
        let reader = Fixtures { url: server.uri(), lookups: resolver.lookups() };
        let readings = join_all(sources.iter().map(|source| reader.read(source))).await;
        for reading in readings {
            let named = reading.unwrap().objects.into_iter().filter(|object| object.fields.contains_key("dns_name"));
            let names: Vec<serde_json::Value> = named.map(|object| object.fields["dns_name"].clone()).collect();
            assert_eq!(names, [serde_json::json!("vm042.infra.example")]);
        }
        let asked = resolver.asked.lock().unwrap().clone();
        assert!(asked.len() > 1, "{}", asked.len());
        assert_eq!(asked.values().copied().collect::<BTreeSet<usize>>(), BTreeSet::from([1]));
        assert_eq!(*resolver.built.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn no_source_selected_reads_and_writes_nothing() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox)];
        let netbox = FakeGateway::new();
        let reader = Scripted::default();
        let outcome = run(&sources, &[], &[], &netbox, &reader, &NullProgress).await;
        assert_eq!(outcome, Outcome::default());
        assert_eq!(*reader.read.lock().unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_build_without_reader_says_so_for_each_source() {
        let sources = [hypervisor("pve01.lab01", HypervisorType::Proxmox), hypervisor("vc01", HypervisorType::Vmware)];
        let netbox = FakeGateway::new();
        let selected: Vec<&Hypervisor> = sources.iter().collect();
        let outcome = run(&sources, &selected, &[], &netbox, &Unavailable, &NullProgress).await;
        assert_eq!(
            outcome.errors,
            [
                "pve01.lab01: proxmox sources are not implemented in this build",
                "vc01: vmware sources are not implemented in this build"
            ]
        );
        assert_eq!(netbox.writes(), []);
    }

    #[test]
    fn a_vmware_source_takes_its_settings_from_its_entry() {
        let source = Hypervisor {
            tenant: Some("Example Tenant".to_owned()),
            host_role: Some("Hypervisor ESX".to_owned()),
            vm_role: Some("Virtual Machine ESX".to_owned()),
            ignore_templates: false,
            ignored_subnets: vec!["10.9.0.0/16".parse().unwrap()],
            permitted_subnets: vec!["10.0.0.0/8".parse().unwrap()],
            interface_filter: Some(regex::Regex::new("^vusb").unwrap()),
            ..hypervisor("vc01", HypervisorType::Vmware)
        };
        let settings = vmware_settings(&source).unwrap();
        assert_eq!((settings.source.as_str(), settings.site.as_str()), ("vc01", "Paris"));
        assert_eq!(settings.tenant.as_deref(), Some("Example Tenant"));
        assert_eq!(settings.host_role.as_deref(), Some("Hypervisor ESX"));
        assert_eq!(settings.vm_role.as_deref(), Some("Virtual Machine ESX"));
        assert!(!settings.ignore_templates);
        assert_eq!(settings.ignored_subnets, source.ignored_subnets);
        assert_eq!(settings.permitted_subnets, source.permitted_subnets);
        assert_eq!(settings.interface_filter.map(|filter| filter.to_string()), Some("^vusb".to_owned()));
    }

    #[tokio::test]
    async fn a_vmware_source_without_site_or_with_a_domain_is_refused_before_anything_is_contacted() {
        let source = Hypervisor { site: None, ..hypervisor("vc01", HypervisorType::Vmware) };
        assert_eq!(Apis::default().read(&source).await, Err("a vmware source needs a site".to_owned()));
        let source =
            Hypervisor { domain: Some("example.net".to_owned()), ..hypervisor("vc01", HypervisorType::Vmware) };
        assert_eq!(
            Apis::default().read(&source).await,
            Err("a vmware source takes no domain: vCenter gives the full name of its hosts".to_owned())
        );
    }

    #[tokio::test]
    async fn a_vmware_source_given_a_token_names_the_variables_it_needs_never_the_token() {
        let token = Secret::new(SENTINEL_SECRET);
        let source = Hypervisor {
            credentials: Wanted::Held(Credentials::Token { token }),
            ..hypervisor("vc01.lab01", HypervisorType::Vmware)
        };
        let reason = Apis::default().read(&source).await.unwrap_err();
        assert_eq!(reason, "a vmware source logs in with VC01_LAB01_USERNAME and VC01_LAB01_PASSWORD, not a token");
    }

    #[tokio::test]
    async fn a_vcenter_that_cannot_be_reached_names_its_type_and_host_never_the_account() {
        // A local port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let credentials = Wanted::Held(Credentials::Password {
            username: SENTINEL_USER.to_owned(),
            password: Secret::new(SENTINEL_SECRET),
        });
        let source = Hypervisor {
            host: "127.0.0.1".to_owned(),
            port: Some(port),
            credentials,
            ..hypervisor("vc01", HypervisorType::Vmware)
        };
        let reason = Apis::default().read(&source).await.unwrap_err();
        assert!(reason.starts_with(&format!("vmware 127.0.0.1:{port}: ")), "{reason}");
        assert!(!reason.contains("0perator") && !reason.contains("s3ntinel"), "{reason}");
    }

    #[tokio::test]
    async fn credentials_written_in_the_host_of_a_vcenter_are_refused_without_being_shown() {
        let source = Hypervisor {
            host: format!("0perator:{SENTINEL_SECRET}@192.0.2.10"),
            ..hypervisor("vc01", HypervisorType::Vmware)
        };
        // Refused when the client is built: nothing is contacted.
        let reason = Apis::default().read(&source).await.unwrap_err();
        assert_eq!(
            reason,
            "vSphere client: vCenter URL \"https://***@192.0.2.10:443\": credentials in the URL are refused"
        );
    }

    /// A machine tagged in vSphere, as the VMware source reports it.
    fn tagged_machine(source: &str, tags: &[&str]) -> Reading {
        let mut reading = cluster(source, "lab");
        let machine = Desired::new(Kind::VirtualMachine, Identity::virtual_machine("web01", "lab"), source)
            .field("name", "web01")
            .reference("cluster", Kind::Cluster, Identity::named("lab"))
            .tags(tags.iter().copied());
        reading.objects.push(machine);
        reading
    }

    #[tokio::test]
    async fn a_tag_netbox_sync_made_leaves_a_machine_once_vsphere_no_longer_tags_it() {
        let sources = [hypervisor("vc01", HypervisorType::Vmware)];
        let netbox = FakeGateway::new();
        // `module/sources/vmware/connection.py:690-700`: the description of a tag made from a vSphere tag
        // is `NetBox-synced`, followed by `: ` and the vSphere description when there is one.
        let add = |name: &str, description: &str| {
            netbox.add("extras.tags", serde_json::json!({"name": name, "slug": name, "description": description}))
        };
        let apache = add("service-apache", "NetBox-synced");
        let nginx = add("service-nginx", "NetBox-synced: reverse proxy");
        // The marker this tool writes, in lower case, with a description after it.
        let redis = add("service-redis", "netbox-omnisync: Icinga: Check Redis");
        let manual = add("set-by-hand", "Never monitored");
        run_all(&sources, &netbox, &Scripted::answering([("vc01", Ok(tagged_machine("vc01", &["service-apache"])))]))
            .await;
        let machine = netbox.find("virtualization.virtual_machines", "name", &serde_json::json!("web01")).unwrap();
        // Somebody adds a tag by hand, and vSphere tags that netbox-sync had synced before.
        let held = netbox.row("virtualization.virtual_machines", machine).unwrap()["tags"].clone();
        let mut tags = held.as_array().unwrap().clone();
        tags.extend([serde_json::json!(nginx), serde_json::json!(redis), serde_json::json!(manual)]);
        netbox.set("virtualization.virtual_machines", machine, "tags", serde_json::json!(tags));
        // vSphere tags the machine with service-apache alone.
        let outcome = run_all(
            &sources,
            &netbox,
            &Scripted::answering([("vc01", Ok(tagged_machine("vc01", &["service-apache"])))]),
        )
        .await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        let held = netbox.row("virtualization.virtual_machines", machine).unwrap()["tags"].clone();
        let held: Vec<u64> = held.as_array().unwrap().iter().map(|tag| tag.as_u64().unwrap()).collect();
        // The tag made from vSphere is gone, the one set by hand stays.
        assert!(held.contains(&apache) && held.contains(&manual), "{held:?}");
        assert!(!held.contains(&nginx) && !held.contains(&redis), "{held:?}");
    }

    /// An account and a secret that no failure may show.
    const SENTINEL_USER: &str = "0perator-never-shown@pve";
    const SENTINEL_SECRET: &str = "s3ntinel-never-shown";

    #[tokio::test]
    async fn a_proxmox_that_cannot_be_reached_names_its_type_and_host_never_the_account() {
        // A local port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let by_password = Wanted::Held(Credentials::Password {
            username: SENTINEL_USER.to_owned(),
            password: Secret::new(SENTINEL_SECRET),
        });
        let token = Secret::new(&format!("{SENTINEL_USER}!netbox={SENTINEL_SECRET}"));
        let by_token = Wanted::Held(Credentials::Token { token });
        for (credentials, request) in [(by_password, "POST /access/ticket"), (by_token, "GET /version")] {
            let source = Hypervisor {
                host: "127.0.0.1".to_owned(),
                port: Some(port),
                credentials,
                ..hypervisor("pve-a", HypervisorType::Proxmox)
            };
            let reason = Apis::default().read(&source).await.unwrap_err();
            assert!(reason.starts_with(&format!("proxmox 127.0.0.1:{port}: {request}: ")), "{reason}");
            assert!(!reason.contains("0perator") && !reason.contains("s3ntinel"), "{reason}");
        }
    }

    #[tokio::test]
    async fn credentials_written_in_the_host_of_a_source_are_refused_without_being_shown() {
        let source = Hypervisor {
            host: format!("0perator:{SENTINEL_SECRET}@192.0.2.10"),
            ..hypervisor("pve-a", HypervisorType::Proxmox)
        };
        // Refused when the client is built: nothing is contacted.
        let reason = Apis::default().read(&source).await.unwrap_err();
        assert_eq!(
            reason,
            "Proxmox client: Proxmox URL \"https://***@192.0.2.10:8006\": credentials in the URL are refused"
        );
    }

    #[tokio::test]
    async fn a_proxmox_source_without_site_is_refused_before_anything_is_contacted() {
        let source = Hypervisor { site: None, ..hypervisor("pve-a", HypervisorType::Proxmox) };
        assert_eq!(Apis::default().read(&source).await, Err("a proxmox source needs a site".to_owned()));
    }

    // The BMC sources

    use omnisync_redfish::model::{Bmc as BmcAnswer, System};

    use crate::config::Bmc;
    use crate::fake_bmc;

    const BMCS: &str = "bmc.lab01";

    /// A `bmc` entry whose struct says it creates and prunes, which the loader
    /// never gives: the run must not trust it.
    fn bmc_source(devices: &[(&str, &str)]) -> Hypervisor {
        let bmcs = devices.iter().map(|(device, host)| Bmc {
            device: (*device).to_owned(),
            host: (*host).to_owned(),
            fingerprint: None,
        });
        Hypervisor {
            host: String::new(),
            site: None,
            validate_certs: false,
            create_devices: true,
            prune: true,
            vlan_group: None,
            bmcs: bmcs.collect(),
            ..hypervisor(BMCS, HypervisorType::Redfish)
        }
    }

    /// What the BMC of a Dell server says, translated as the real reader translates it.
    fn told(device: &str, model: &str, service_tag: &str, macs: &[&str]) -> Guarded {
        let answer = BmcAnswer {
            system: System {
                manufacturer: Some("Dell Inc.".to_owned()),
                model: Some(model.to_owned()),
                sku: Some(service_tag.to_owned()),
                serial_number: Some("CN0000000A0001".to_owned()),
                host_name: None,
                mac_addresses: macs.iter().map(|mac| (*mac).to_owned()).collect(),
            },
            ..BmcAnswer::default()
        };
        omnisync_redfish::translate::desired(BMCS, device, &format!("drac-{device}"), &answer).report
    }

    fn telling<const N: usize>(reports: [Guarded; N]) -> Scripted {
        Scripted::answering([(BMCS, Ok(Reading { guarded: reports.into(), ..Reading::default() }))])
    }

    /// A server as a hypervisor source left it: a generic device type, no
    /// serial, and one interface whose MAC address NetBox holds when `mac` is given.
    fn server(netbox: &FakeGateway, name: &str, mac: Option<&str>) -> u64 {
        let find = |endpoint: &str, field: &str, value: &str| netbox.find(endpoint, field, &serde_json::json!(value));
        let manufacturer = find("dcim.manufacturers", "name", "Generic Manufacturer").unwrap_or_else(|| {
            netbox.add("dcim.manufacturers", serde_json::json!({"name": "Generic Manufacturer", "slug": "generic"}))
        });
        let generic = find("dcim.device_types", "model", "Generic Model").unwrap_or_else(|| {
            let fields = serde_json::json!({"model": "Generic Model", "slug": "generic", "manufacturer": manufacturer});
            netbox.add("dcim.device_types", fields)
        });
        let site = find("dcim.sites", "name", "Paris")
            .unwrap_or_else(|| netbox.add("dcim.sites", serde_json::json!({"name": "Paris", "slug": "paris"})));
        let fields = serde_json::json!({"name": name, "site": site, "device_type": generic, "serial": ""});
        let device = netbox.add("dcim.devices", fields);
        let interface =
            netbox.add("dcim.interfaces", serde_json::json!({"device": device, "name": "eno1", "type": "other"}));
        if let Some(mac) = mac {
            let assigned = serde_json::json!({
                "mac_address": mac, "assigned_object_type": "dcim.interface", "assigned_object_id": interface
            });
            netbox.add("dcim.mac_addresses", assigned);
        }
        device
    }

    /// The model of the device type and the serial NetBox holds for a device.
    fn hardware(netbox: &FakeGateway, device: u64) -> (String, String) {
        let row = netbox.row("dcim.devices", device).unwrap();
        let device_type = netbox.row("dcim.device_types", row["device_type"].as_u64().unwrap()).unwrap();
        (device_type["model"].as_str().unwrap().to_owned(), row["serial"].as_str().unwrap().to_owned())
    }

    #[tokio::test]
    async fn what_a_bmc_says_completes_the_device_it_is_proven_to_manage() {
        let sources = [bmc_source(&[])];
        let netbox = FakeGateway::new();
        let device = server(&netbox, "pve01.lab01", Some("02:00:00:00:00:0E"));
        // The BMC lists two cards; NetBox knows the address of one, in another letter case.
        let reader =
            telling([told("pve01.lab01", "PowerEdge R630", "SVCTAG1", &["02:00:00:00:00:0e", "02:00:00:00:00:0f"])]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!((outcome.errors.clone(), outcome.warnings.clone()), (vec![], vec![]));
        assert_eq!(hardware(&netbox, device), ("PowerEdge R630".to_owned(), "SVCTAG1".to_owned()));
        // The type was made under its manufacturer, named as for a host of a vCenter.
        let dell = netbox.find("dcim.manufacturers", "name", &serde_json::json!("Dell")).expect("manufacturer written");
        let r630 = netbox.find("dcim.device_types", "model", &serde_json::json!("PowerEdge R630")).unwrap();
        assert_eq!(netbox.row("dcim.device_types", r630).unwrap()["manufacturer"], serde_json::json!(dell));
        // The device is completed, not adopted: no tag, and nothing but the two fields.
        let row = netbox.row("dcim.devices", device).unwrap();
        assert!(row.get("tags").is_none_or(|tags| tags == &serde_json::json!([])), "{row:?}");
        assert_eq!(row["name"], serde_json::json!("pve01.lab01"));
        // Neither an interface nor an address was written.
        let touched: BTreeSet<&str> = outcome.changes.iter().map(|change| change.kind.as_str()).collect();
        assert_eq!(touched.into_iter().collect::<Vec<_>>(), ["device", "device_type", "manufacturer", "tag"]);
        // The same answer again: nothing to write.
        let again = run_all(&sources, &netbox, &reader).await;
        assert_eq!(again.changes, []);
        assert_eq!((again.errors.len(), again.applied), (0, 0));
    }

    #[tokio::test]
    async fn a_device_that_is_not_in_netbox_is_never_created_from_its_bmc() {
        let sources = [bmc_source(&[])];
        let netbox = FakeGateway::new();
        let reader = telling([told("pve09.lab01", "PowerEdge R630", "SVCTAG9", &["02:00:00:00:00:99"])]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(
            outcome.warnings,
            ["bmc.lab01: device pve09.lab01: not in NetBox; BMC drac-pve09.lab01 is left out (a device is never \
              created from its BMC); nothing is written for it"]
        );
        // Not even its device type.
        assert_eq!(outcome.changes, []);
        assert_eq!(netbox.writes(), []);
    }

    #[tokio::test]
    async fn the_bmc_of_another_server_writes_nothing() {
        let sources = [bmc_source(&[])];
        let netbox = FakeGateway::new();
        let device = server(&netbox, "pve02.lab01", Some("02:00:00:00:00:AA"));
        // The address configured for pve02 answers with the cards of another server.
        let reader = telling([told("pve02.lab01", "PowerEdge R630", "SVCTAG1", &["02:00:00:00:00:0E"])]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(
            outcome.warnings,
            ["bmc.lab01: device pve02.lab01: none of the 1 MAC address(es) BMC drac-pve02.lab01 reports is on its 1 \
              NetBox interface address(es): wrong BMC for this device?; nothing is written for it"]
        );
        assert_eq!(netbox.writes(), []);
        assert_eq!(hardware(&netbox, device), ("Generic Model".to_owned(), String::new()));
    }

    #[tokio::test]
    async fn a_device_whose_mac_addresses_netbox_does_not_hold_yet_is_left_alone() {
        let sources = [bmc_source(&[])];
        let netbox = FakeGateway::new();
        let device = server(&netbox, "pve01.lab01", None);
        let reader = telling([told("pve01.lab01", "PowerEdge R630", "SVCTAG1", &["02:00:00:00:00:0E"])]);
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(
            outcome.warnings,
            ["bmc.lab01: device pve01.lab01: NetBox holds no MAC address on its interfaces yet: BMC drac-pve01.lab01 \
              cannot be checked against it; nothing is written for it"]
        );
        assert_eq!(netbox.writes(), []);
        assert_eq!(hardware(&netbox, device), ("Generic Model".to_owned(), String::new()));
    }

    #[tokio::test]
    async fn a_bmc_that_cannot_be_read_is_an_error_and_the_others_are_written() {
        let sources = [bmc_source(&[])];
        let netbox = FakeGateway::new();
        let first = server(&netbox, "pve01.lab01", Some("02:00:00:00:00:0E"));
        let second = server(&netbox, "pve02.lab01", Some("02:00:00:00:00:15"));
        let refused = "redfish drac-pve02.lab01:443: GET /redfish/v1/Systems answered 401: Unauthorized";
        let reading = Reading {
            guarded: vec![told("pve01.lab01", "PowerEdge R630", "SVCTAG1", &["02:00:00:00:00:0E"])],
            errors: vec![refused.to_owned()],
            ..Reading::default()
        };
        let outcome = run_all(&sources, &netbox, &Scripted::answering([(BMCS, Ok(reading))])).await;
        // The failure is the BMC's, named with its source; the run exits 1 on it.
        assert_eq!(outcome.errors, [format!("bmc.lab01: {refused}")]);
        assert_eq!(hardware(&netbox, first), ("PowerEdge R630".to_owned(), "SVCTAG1".to_owned()));
        assert_eq!(hardware(&netbox, second), ("Generic Model".to_owned(), String::new()));
    }

    /// A host and its device type as a source that knows its hardware reports them (a vCenter).
    fn known_host(source: &str, name: &str, model: &str, serial: &str) -> Reading {
        let device_type = Identity::device_type("Dell", model);
        let objects = vec![
            Desired::new(Kind::Manufacturer, Identity::named("Dell"), source)
                .field("name", "Dell")
                .create_only("slug", "dell"),
            Desired::new(Kind::DeviceType, device_type.clone(), source)
                .field("model", model)
                .create_only("slug", "the-type")
                .reference("manufacturer", Kind::Manufacturer, Identity::named("Dell")),
            Desired::new(Kind::Device, Identity::device(name), source)
                .field("name", name)
                .field("serial", serial)
                .reference("device_type", Kind::DeviceType, device_type),
        ];
        Reading { objects, ..Reading::default() }
    }

    #[tokio::test]
    async fn a_bmc_that_fails_after_a_good_run_clears_and_orphans_nothing() {
        // A vCenter and the BMCs report the same host, and so share its device type.
        let sources = [hypervisor("vc01", HypervisorType::Vmware), bmc_source(&[])];
        let netbox = FakeGateway::new();
        let device = server(&netbox, "esx01.lab01", Some("02:00:00:00:00:15"));
        let good = Reading {
            guarded: vec![told("esx01.lab01", "PowerEdge R640", "SVCTAG2", &["02:00:00:00:00:15"])],
            ..Reading::default()
        };
        let vcenter = || ("vc01", Ok(known_host("vc01", "esx01.lab01", "PowerEdge R640", "SVCTAG2")));
        let outcome = run_all(&sources, &netbox, &Scripted::answering([vcenter(), (BMCS, Ok(good))])).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        let r640 = netbox.find("dcim.device_types", "model", &serde_json::json!("PowerEdge R640")).unwrap();
        let tags_of_the_type = || netbox.row("dcim.device_types", r640).unwrap()["tags"].clone();
        let shared = tags_of_the_type();
        // The tool, the vCenter and the BMC source.
        assert_eq!(shared.as_array().map(Vec::len), Some(3), "{shared}");
        // The next day the BMC does not answer: the source reports nothing of that host.
        let unread = Reading {
            errors: vec!["redfish drac-esx01.lab01:443: GET /redfish/v1/: timed out".to_owned()],
            ..Reading::default()
        };
        let writes = netbox.writes().len();
        let outcome = run_all(&sources, &netbox, &Scripted::answering([vcenter(), (BMCS, Ok(unread))])).await;
        assert_eq!(outcome.errors, ["bmc.lab01: redfish drac-esx01.lab01:443: GET /redfish/v1/: timed out"]);
        // Nothing moved: neither the device, nor the tag of the BMC source on the type they share.
        assert_eq!(outcome.changes, []);
        assert_eq!(netbox.writes().len(), writes);
        assert_eq!(tags_of_the_type(), shared);
        assert_eq!(hardware(&netbox, device), ("PowerEdge R640".to_owned(), "SVCTAG2".to_owned()));
    }

    #[tokio::test]
    async fn a_bmc_source_never_creates_a_device_nor_deletes_whatever_its_entry_says() {
        // `bmc_source` says `create_devices` and `prune`, which the loader refuses: the run forces both off.
        let sources = [bmc_source(&[])];
        assert!(sources[0].create_devices && sources[0].prune);
        let netbox = FakeGateway::new();
        // A manufacturer the source made on an earlier run, and no longer reports.
        let tag = |slug: &str| netbox.add("extras.tags", serde_json::json!({"name": slug, "slug": slug}));
        let tags = [tag("netbox-omnisync"), tag("source-bmclab01")];
        netbox.add("dcim.manufacturers", serde_json::json!({"name": "Dell", "slug": "dell", "tags": tags}));
        // A device reported as a hypervisor would report one, which NetBox does not hold.
        let ghost = Desired::new(Kind::Device, Identity::device("ghost01"), BMCS).field("name", "ghost01");
        let reading = Reading { objects: vec![ghost], ..Reading::default() };
        let outcome = run_all(&sources, &netbox, &Scripted::answering([(BMCS, Ok(reading))])).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(
            outcome.warnings,
            ["bmc.lab01: device ghost01: not in NetBox and create_devices is off for bmc.lab01; skipped with its \
              dependents"]
        );
        assert_eq!(outcome.changes, []);
        assert!(netbox.find("dcim.devices", "name", &serde_json::json!("ghost01")).is_none());
        assert!(netbox.find("dcim.manufacturers", "name", &serde_json::json!("Dell")).is_some());
    }

    #[tokio::test]
    async fn the_bmcs_of_a_source_are_read_each_at_its_address_in_the_order_of_the_file() {
        // idrac8-2.86.86.86: "SKU": "878X8Z3", "Model": "PowerEdge R630", first card "02:00:00:00:00:0E".
        // ilo4-2.82: "SerialNumber": "CBQ260112M", "Model": "ProLiant DL360 Gen9", "HostName": "corp-siteb-pve02".
        let idrac = fake_bmc::bmc("idrac8-2.86.86.86").await;
        let ilo = fake_bmc::bmc("ilo4-2.82").await;
        let credentials = Wanted::Held(Credentials::Password {
            username: fake_bmc::USER.to_owned(),
            password: Secret::new(fake_bmc::PASSWORD),
        });
        let source = Hypervisor {
            credentials,
            ..bmc_source(&[("pve02.lab01", "ilo-pve02.lab01"), ("pve01.lab01", "drac-pve01.lab01")])
        };
        let url_of = |host: &str| if host.starts_with("ilo-") { ilo.uri() } else { idrac.uri() };
        let reading = read_redfish_at(&source, &url_of).await.unwrap();
        assert_eq!(reading.errors, Vec::<String>::new());
        assert_eq!(reading.objects, []);
        let told: Vec<(&str, &str, usize)> = reading
            .guarded
            .iter()
            .map(|report| (report.device.as_str(), report.witness.as_str(), report.macs.len()))
            .collect();
        assert_eq!(told, [("pve02.lab01", "BMC ilo-pve02.lab01", 4), ("pve01.lab01", "BMC drac-pve01.lab01", 6)]);
        let serial = |report: &Guarded| report.objects.last().unwrap().fields["serial"].clone();
        assert_eq!(serial(&reading.guarded[0]), serde_json::json!("CBQ260112M"));
        assert_eq!(serial(&reading.guarded[1]), serde_json::json!("878X8Z3"));
        // The iLO was told another name than the device has: a warning, and its report all the same.
        assert_eq!(
            reading.warnings,
            ["device pve02.lab01: BMC ilo-pve02.lab01 says its server is named corp-siteb-pve02"]
        );
    }

    #[tokio::test]
    async fn a_bmc_that_cannot_be_reached_names_its_type_and_host_never_the_account_and_the_others_are_read() {
        // A local port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);
        let idrac = fake_bmc::bmc("idrac8-2.86.86.86").await;
        let credentials = Wanted::Held(Credentials::Password {
            username: fake_bmc::USER.to_owned(),
            password: Secret::new(fake_bmc::PASSWORD),
        });
        let source = Hypervisor {
            credentials,
            ..bmc_source(&[("pve09.lab01", "drac-pve09.lab01"), ("pve01.lab01", "drac-pve01.lab01")])
        };
        let url_of = |host: &str| if host == "drac-pve09.lab01" { closed.clone() } else { idrac.uri() };
        let reading = read_redfish_at(&source, &url_of).await.unwrap();
        let [reason] = reading.errors.as_slice() else {
            panic!("{:?}", reading.errors);
        };
        assert!(reason.starts_with("redfish drac-pve09.lab01:443: GET /redfish/v1/: "), "{reason}");
        assert!(!reason.contains("0perator") && !reason.contains("s3ntinel"), "{reason}");
        // The BMC that answers is reported.
        let devices: Vec<&str> = reading.guarded.iter().map(|report| report.device.as_str()).collect();
        assert_eq!(devices, ["pve01.lab01"]);
    }

    #[tokio::test]
    async fn a_few_bmcs_are_read_at_once_never_all_of_them() {
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Ten BMCs that all take their time to answer the first call, and noting when it arrives.
        let server = MockServer::start().await;
        let arrivals: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let noted = Arc::clone(&arrivals);
        Mock::given(method("GET"))
            .respond_with(move |_: &wiremock::Request| {
                noted.lock().unwrap().push(Instant::now());
                ResponseTemplate::new(503).set_delay(Duration::from_millis(400))
            })
            .mount(&server)
            .await;
        let devices: Vec<(String, String)> =
            (1..=10).map(|number| (format!("pve{number:02}.lab01"), format!("drac-pve{number:02}.lab01"))).collect();
        let listed: Vec<(&str, &str)> = devices.iter().map(|(device, host)| (device.as_str(), host.as_str())).collect();
        let source = bmc_source(&listed);
        let reading = read_redfish_at(&source, &|_| server.uri()).await.unwrap();
        // Each BMC failed on its own, and is named: ten errors, in the order of the file.
        assert_eq!(reading.errors.len(), 10);
        assert_eq!(
            reading.errors[0],
            "redfish drac-pve01.lab01:443: GET /redfish/v1/ answered 503: Service Unavailable"
        );
        assert_eq!(
            reading.errors[9],
            "redfish drac-pve10.lab01:443: GET /redfish/v1/ answered 503: Service Unavailable"
        );
        // While the first answers were held back, four BMCs had been asked, not ten.
        let arrivals = arrivals.lock().unwrap();
        let first = arrivals[0];
        let early =
            arrivals.iter().filter(|arrival| arrival.duration_since(first) < Duration::from_millis(200)).count();
        assert_eq!((arrivals.len(), early), (10, BMCS_IN_FLIGHT));
        assert_eq!(BMCS_IN_FLIGHT, 4);
    }

    #[tokio::test]
    async fn a_bmc_that_refuses_the_account_names_its_type_and_host_never_the_account() {
        let idrac = fake_bmc::bmc("idrac8-2.86.86.86").await;
        let credentials = Wanted::Held(Credentials::Password {
            username: SENTINEL_USER.to_owned(),
            password: Secret::new(SENTINEL_SECRET),
        });
        let source = Hypervisor { credentials, port: Some(8443), ..bmc_source(&[("pve01.lab01", "drac-pve01.lab01")]) };
        let reading = read_redfish_at(&source, &|_| idrac.uri()).await.unwrap();
        assert_eq!(
            reading.errors,
            ["redfish drac-pve01.lab01:8443: GET /redfish/v1/Systems answered 401: Unauthorized"]
        );
        assert_eq!(reading.guarded, []);
    }

    // The file is the same on every host, and this one holds no account for
    // these sources: they are known, and cannot be read. Each server here
    // would answer anything; none is asked anything.
    #[tokio::test]
    async fn a_source_whose_account_the_environment_does_not_hold_is_never_contacted_and_names_its_variables() {
        let server = wiremock::MockServer::start().await;
        let lookups = ReverseLookups::system();
        let token_or_account = "PVE_A_TOKEN (or PVE_A_USERNAME and PVE_A_PASSWORD)";
        let missing = |variables: &[&str]| Wanted::Missing(variables.iter().map(|name| (*name).to_owned()).collect());

        let proxmox =
            Hypervisor { credentials: missing(&[token_or_account]), ..hypervisor("pve-a", HypervisorType::Proxmox) };
        assert_eq!(
            read_proxmox_at(&proxmox, &server.uri(), &lookups).await.unwrap_err(),
            "missing environment variables: PVE_A_TOKEN (or PVE_A_USERNAME and PVE_A_PASSWORD)"
        );
        let vcenter = Hypervisor {
            credentials: missing(&["VC01_PASSWORD or VC01_TOKEN"]),
            ..hypervisor("vc01", HypervisorType::Vmware)
        };
        assert_eq!(
            read_vmware_at(&vcenter, &server.uri(), &lookups).await.unwrap_err(),
            "missing environment variables: VC01_PASSWORD or VC01_TOKEN"
        );
        let bmcs = Hypervisor {
            credentials: missing(&["BMC_LAB01_USERNAME", "BMC_LAB01_PASSWORD"]),
            ..bmc_source(&[("pve01.lab01", "drac-pve01.lab01"), ("pve02.lab01", "drac-pve02.lab01")])
        };
        // The source as a whole, not one error per BMC: none of them was asked.
        assert_eq!(
            read_redfish_at(&bmcs, &|_| server.uri()).await.unwrap_err(),
            "missing environment variables: BMC_LAB01_PASSWORD, BMC_LAB01_USERNAME"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
        // The same through the readers of the tool, which would go to the real addresses.
        for source in [&proxmox, &vcenter, &bmcs] {
            let reason = Apis::default().read(source).await.unwrap_err();
            assert!(reason.starts_with("missing environment variables: "), "{reason}");
        }
    }

    #[tokio::test]
    async fn a_redfish_source_given_a_token_names_the_variables_it_needs_never_the_token() {
        let token = Secret::new(SENTINEL_SECRET);
        let source = Hypervisor {
            credentials: Wanted::Held(Credentials::Token { token }),
            ..bmc_source(&[("pve01.lab01", "drac-pve01.lab01")])
        };
        let reason = Apis::default().read(&source).await.unwrap_err();
        assert_eq!(reason, "a redfish source logs in with BMC_LAB01_USERNAME and BMC_LAB01_PASSWORD, not a token");
    }

    #[tokio::test]
    async fn credentials_written_in_the_address_of_a_bmc_are_refused_without_being_shown() {
        let host = format!("0perator:{SENTINEL_SECRET}@192.0.2.61");
        let source = bmc_source(&[("pve01.lab01", &host)]);
        // Refused when the client is built: nothing is contacted.
        let reading = Apis::default().read(&source).await.unwrap();
        assert_eq!(
            reading.errors,
            ["Redfish client: BMC URL \"https://***@192.0.2.61:443\": credentials in the URL are refused"]
        );
    }

    // A host renamed in its hypervisor, and its BMC

    const ENO1: &str = "02:00:00:00:00:0E";

    /// A server the Proxmox source `pve-a` holds: as [`server`] leaves it, with the tags of
    /// the tool and of the source on the device, its interface and its MAC address.
    fn held_server(netbox: &FakeGateway, name: &str) -> u64 {
        let tag = |slug: &str| netbox.add("extras.tags", serde_json::json!({"name": slug, "slug": slug}));
        let tags = [tag("netbox-omnisync"), tag("source-pve-a")];
        let manufacturer =
            netbox.add("dcim.manufacturers", serde_json::json!({"name": "Generic Manufacturer", "slug": "generic"}));
        let fields = serde_json::json!({"model": "Generic Model", "slug": "generic", "manufacturer": manufacturer});
        let generic = netbox.add("dcim.device_types", fields);
        let site = netbox.add("dcim.sites", serde_json::json!({"name": "Paris", "slug": "paris"}));
        let fields =
            serde_json::json!({"name": name, "site": site, "device_type": generic, "serial": "", "tags": tags});
        let device = netbox.add("dcim.devices", fields);
        let fields = serde_json::json!({"device": device, "name": "eno1", "type": "other", "tags": tags});
        let interface = netbox.add("dcim.interfaces", fields);
        let assigned = serde_json::json!({
            "mac_address": ENO1, "assigned_object_type": "dcim.interface", "assigned_object_id": interface,
            "tags": tags
        });
        netbox.add("dcim.mac_addresses", assigned);
        device
    }

    /// The same server as `pve-a` reports it under `name`: the device, `eno1` and its address.
    fn host_reading(name: &str) -> Reading {
        let eno1 = Identity::interface(name, "eno1");
        let target = Target::new(Kind::Interface, eno1.clone());
        let objects = vec![
            Desired::new(Kind::Device, Identity::device(name), "pve-a").field("name", name),
            Desired::new(Kind::Interface, eno1.clone(), "pve-a").field("name", "eno1").reference(
                "device",
                Kind::Device,
                Identity::device(name),
            ),
            Desired::new(Kind::MacAddress, Identity::mac_address(ENO1, Some(&target)), "pve-a")
                .field("mac_address", ENO1)
                .reference("assigned_object", Kind::Interface, eno1),
        ];
        Reading { objects, ..Reading::default() }
    }

    /// The hypervisor reports the host as `host`, and the BMC entry names the device `device`.
    fn renaming(host: &str, device: &str) -> Scripted {
        let bmc = Reading { guarded: vec![told(device, "PowerEdge R630", "SVCTAG1", &[ENO1])], ..Reading::default() };
        Scripted::answering([("pve-a", Ok(host_reading(host))), (BMCS, Ok(bmc))])
    }

    fn device_named(netbox: &FakeGateway, name: &str) -> Option<u64> {
        netbox.find("dcim.devices", "name", &serde_json::json!(name))
    }

    #[tokio::test]
    async fn a_host_renamed_in_its_hypervisor_is_renamed_in_place_and_its_bmc_follows_once_it_names_it_so() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox), bmc_source(&[])];
        let netbox = FakeGateway::new();
        let device = held_server(&netbox, "pve01.lab01");
        // The hypervisor now calls the host pve02; the bmc entry still says pve01, which NetBox
        // holds with the address the BMC reports: the guard admits it.
        let outcome = run_all(&sources, &netbox, &renaming("pve02.lab01", "pve01.lab01")).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(
            outcome.warnings,
            ["bmc.lab01: device pve01.lab01: renamed pve02.lab01 by this run, and bmc.lab01 only completes it \
              under the name it had; skipped"]
        );
        // The same device under its new name: neither a second one, nor anything deleted.
        assert_eq!(device_named(&netbox, "pve02.lab01"), Some(device));
        assert_eq!(device_named(&netbox, "pve01.lab01"), None);
        let deleted: Vec<&str> = outcome
            .changes
            .iter()
            .filter(|change| change.action == Action::Delete)
            .map(|change| change.kind.as_str())
            .collect();
        assert_eq!(deleted, Vec::<&str>::new());
        assert_eq!(created(&outcome, "device"), Vec::<String>::new());
        assert_eq!(hardware(&netbox, device), ("Generic Model".to_owned(), String::new()));
        // The entry now names the device as it is called: it is completed.
        let outcome = run_all(&sources, &netbox, &renaming("pve02.lab01", "pve02.lab01")).await;
        assert_eq!((outcome.errors, outcome.warnings), (vec![], vec![]));
        assert_eq!(device_named(&netbox, "pve02.lab01"), Some(device));
        assert_eq!(hardware(&netbox, device), ("PowerEdge R630".to_owned(), "SVCTAG1".to_owned()));
    }

    #[tokio::test]
    async fn a_bmc_told_the_new_name_of_a_host_waits_for_the_run_that_renames_it() {
        let sources = [hypervisor("pve-a", HypervisorType::Proxmox), bmc_source(&[])];
        let netbox = FakeGateway::new();
        let device = held_server(&netbox, "pve01.lab01");
        // Both already say pve02, which NetBox does not hold yet: the BMC is checked against
        // what NetBox holds before the run, so it is left out of the run that renames the device.
        let reader = renaming("pve02.lab01", "pve02.lab01");
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!(outcome.errors, Vec::<String>::new());
        assert_eq!(
            outcome.warnings,
            ["bmc.lab01: device pve02.lab01: not in NetBox; BMC drac-pve02.lab01 is left out (a device is never \
              created from its BMC); nothing is written for it"]
        );
        assert_eq!(device_named(&netbox, "pve02.lab01"), Some(device));
        assert_eq!(device_named(&netbox, "pve01.lab01"), None);
        assert_eq!(hardware(&netbox, device), ("Generic Model".to_owned(), String::new()));
        // The next run finds the device under its name, and completes it.
        let outcome = run_all(&sources, &netbox, &reader).await;
        assert_eq!((outcome.errors, outcome.warnings), (vec![], vec![]));
        assert_eq!(hardware(&netbox, device), ("PowerEdge R630".to_owned(), "SVCTAG1".to_owned()));
    }
}
