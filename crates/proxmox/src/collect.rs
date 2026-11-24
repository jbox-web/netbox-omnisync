//! Reads a whole Proxmox VE cluster into plain data.
//!
//! One call, [`collect`], reads everything the source needs and returns it as
//! a [`ProxmoxCluster`]. It returns the whole cluster or an error, never a
//! part of it: the caller deletes from NetBox what a collection does not
//! hold, so a guest that could not be read must not look like a guest that is
//! gone. The one exception is what a guest says about itself (its interfaces,
//! its system): when it cannot be asked, that is `None`, "unknown", and the
//! caller keeps what NetBox has.
//!
//! # Adding a Proxmox VE version
//!
//! Everything that depends on the version is in one place of this file, the
//! private type `Dialect`, between the two `VERSION SEAM` banners. Its
//! documentation lists the steps.

use futures::future::{join, join_all, join3, try_join, try_join_all, try_join4};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::client::{ClientError, ProxmoxClient};
use crate::model::{
    Container, ContainerInterface, Disk, DiskBus, GuestAddress, GuestInterface, GuestNic, GuestNics, GuestOsInfo, Node,
    NodeNetwork, NodeVlan, ProxmoxCluster, ProxmoxVersion, RUNNING, Vm,
};

/// Why a collection returned nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollectError {
    /// A call failed; the message names its path.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// The version is not one the collection was written and tested for.
    #[error("Proxmox VE {version} is not supported (supported major versions: {supported})")]
    UnsupportedVersion { version: String, supported: String },
}

// ===========================================================================
// VERSION SEAM — begin
// ===========================================================================

/// The major versions of Proxmox VE the collection knows how to read.
pub const SUPPORTED_MAJORS: [u32; 2] = [8, 9];

/// The one place where Proxmox VE versions are told apart.
///
/// `collect` reads the version first, makes a `Dialect` of it, and asks the
/// dialect for every path it calls and every choice that could depend on the
/// version. Nothing else in the crate looks at the version.
///
/// Versions 8 and 9 answer alike for everything the collection reads (checked
/// on the recorded answers of an 8.4 and of a 9.2 cluster, in
/// `tests/fixtures`): no method below branches yet. A version outside
/// [`SUPPORTED_MAJORS`] is refused rather than read with rules that were
/// never checked against it: a field that changed its name would be read as
/// absent, and the caller would act on it.
///
/// To add a version:
///
/// 1. record its answers in `tests/fixtures/<version>/api.json` (same layout
///    as the existing ones) and add its tests to `tests/collection.rs`, next
///    to those of 8.4 and 9.2;
/// 2. add its major to [`SUPPORTED_MAJORS`] and a variant to this enum, picked
///    in [`Dialect::of`];
/// 3. where it needs another call, `match self` in the method that gives the
///    path, or add a method for a new choice (as `asks_guest`);
/// 4. where a field changed its name or its type, say it on the field of the
///    `Wire…` struct below (`#[serde(alias = …)]`, or a lenient reader such
///    as `flag`) — those structs are the only code that names JSON fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    V8,
    V9,
}

impl Dialect {
    fn of(version: &ProxmoxVersion) -> Result<Self, CollectError> {
        match version.major() {
            Some(8) => Ok(Dialect::V8),
            Some(9) => Ok(Dialect::V9),
            _ => {
                let supported: Vec<String> = SUPPORTED_MAJORS.iter().map(u32::to_string).collect();
                Err(CollectError::UnsupportedVersion {
                    version: version.version.clone(),
                    supported: supported.join(", "),
                })
            }
        }
    }

    /// The version itself: asked before a dialect exists, so the same for all.
    const VERSION: &'static str = "/version";

    /// One entry of type `cluster` carries the name; a standalone node has none.
    fn cluster_status(self) -> String {
        "/cluster/status".to_owned()
    }

    fn nodes(self) -> String {
        "/nodes".to_owned()
    }

    /// CPU count and total memory.
    fn node_status(self, node: &str) -> String {
        format!("/nodes/{node}/status")
    }

    /// The list carries `type`, `active`, `slaves` and `ovs_bonds`: the
    /// interfaces are not asked one by one.
    fn node_networks(self, node: &str) -> String {
        format!("/nodes/{node}/network")
    }

    /// The list carries `vmid`, `name`, `status`, `template`, `cpus`, `maxmem`
    /// and `tags`: `status/current` is not asked.
    fn vms(self, node: &str) -> String {
        format!("/nodes/{node}/qemu")
    }

    /// `ostype`, the disks and the network cards (`netN`).
    fn vm_config(self, node: &str, vmid: u64) -> String {
        format!("/nodes/{node}/qemu/{vmid}/config")
    }

    fn vm_interfaces(self, node: &str, vmid: u64) -> String {
        format!("/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
    }

    fn vm_os_info(self, node: &str, vmid: u64) -> String {
        format!("/nodes/{node}/qemu/{vmid}/agent/get-osinfo")
    }

    fn containers(self, node: &str) -> String {
        format!("/nodes/{node}/lxc")
    }

    fn container_interfaces(self, node: &str, vmid: u64) -> String {
        format!("/nodes/{node}/lxc/{vmid}/interfaces")
    }

    /// The network cards (`netN`), which say the VLAN of each.
    fn container_config(self, node: &str, vmid: u64) -> String {
        format!("/nodes/{node}/lxc/{vmid}/config")
    }

    /// Whether a guest in this status can be asked about itself. Only a
    /// running one: the others have no agent and no network to report, and
    /// asking them would turn "unknown" into an error or an empty answer.
    fn asks_guest(self, status: &str) -> bool {
        status == RUNNING
    }
}

/// `GET /version`.
#[derive(Deserialize)]
struct WireVersion {
    version: String,
    #[serde(default)]
    release: String,
}

/// An entry of `GET /cluster/status`: the cluster, or one of its nodes.
#[derive(Deserialize)]
struct WireClusterEntry {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    name: String,
}

/// An entry of `GET /nodes`.
#[derive(Deserialize)]
struct WireNodeEntry {
    node: String,
    /// `online`, `offline` or `unknown` (pve-manager `PVE/API2/Nodes.pm`).
    #[serde(default)]
    status: Option<String>,
}

/// `GET /nodes/{node}/status`.
#[derive(Deserialize)]
struct WireNodeStatus {
    cpuinfo: WireCpuInfo,
    memory: WireMemory,
}

#[derive(Deserialize)]
struct WireCpuInfo {
    cpus: u64,
}

#[derive(Deserialize)]
struct WireMemory {
    total: u64,
}

/// An entry of `GET /nodes/{node}/network`.
#[derive(Deserialize)]
struct WireNetwork {
    iface: String,
    #[serde(rename = "type", default)]
    kind: String,
    /// Left out by Proxmox for an interface that is down.
    #[serde(default, deserialize_with = "flag")]
    active: bool,
    #[serde(default)]
    slaves: String,
    #[serde(default)]
    ovs_bonds: String,
    /// The VLAN of an entry of type `vlan`: a string (`"25"`) on 8.4 and 9.2.
    #[serde(rename = "vlan-id", default)]
    vlan_id: Option<Value>,
    #[serde(rename = "vlan-raw-device", default)]
    vlan_raw_device: Option<String>,
}

/// An entry of `GET /nodes/{node}/qemu`.
#[derive(Deserialize)]
struct WireVm {
    #[serde(deserialize_with = "vmid")]
    vmid: u64,
    name: String,
    status: String,
    /// Left out by Proxmox for a VM that is not a template.
    #[serde(default, deserialize_with = "flag")]
    template: bool,
    cpus: u64,
    maxmem: u64,
    /// Left out by Proxmox for a VM without tag.
    #[serde(default)]
    tags: String,
}

/// What an agent call wraps its answer in.
#[derive(Deserialize)]
#[serde(bound = "T: Deserialize<'de>")]
struct WireAgent<T> {
    result: Option<T>,
}

/// An entry of `agent/network-get-interfaces`.
#[derive(Deserialize)]
struct WireGuestInterface {
    #[serde(default)]
    name: String,
    #[serde(rename = "hardware-address")]
    mac: Option<String>,
    /// Left out by the agent for an interface without address.
    #[serde(rename = "ip-addresses")]
    addresses: Option<Vec<WireGuestAddress>>,
}

#[derive(Deserialize)]
struct WireGuestAddress {
    #[serde(rename = "ip-address")]
    address: String,
    #[serde(rename = "ip-address-type", default)]
    family: String,
    prefix: u8,
}

/// `agent/get-osinfo`.
#[derive(Deserialize)]
struct WireOsInfo {
    id: Option<String>,
    name: Option<String>,
    #[serde(rename = "pretty-name")]
    pretty_name: Option<String>,
    version: Option<String>,
    #[serde(rename = "version-id")]
    version_id: Option<String>,
    #[serde(rename = "kernel-release")]
    kernel_release: Option<String>,
    machine: Option<String>,
    /// Set instead of the fields above when the agent refused the command: an
    /// agent too old for `guest-get-osinfo` answers 200 with this inside.
    error: Option<serde_json::Value>,
}

/// An entry of `GET /nodes/{node}/lxc`.
#[derive(Deserialize)]
struct WireContainer {
    #[serde(deserialize_with = "vmid")]
    vmid: u64,
    name: String,
    status: String,
    cpus: u64,
    maxmem: u64,
    maxdisk: u64,
    #[serde(default)]
    tags: String,
}

/// An entry of `GET /nodes/{node}/lxc/{vmid}/interfaces`.
#[derive(Deserialize)]
struct WireContainerInterface {
    #[serde(default)]
    name: String,
    hwaddr: Option<String>,
    inet: Option<String>,
    inet6: Option<String>,
}

/// A number that Proxmox may write as text.
#[derive(Deserialize)]
#[serde(untagged)]
enum NumberOrText {
    Number(u64),
    Text(String),
}

/// A VMID: a number in the list of VMs, a number or a string in the list of containers.
fn vmid<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    match NumberOrText::deserialize(deserializer)? {
        NumberOrText::Number(vmid) => Ok(vmid),
        NumberOrText::Text(text) => text.parse().map_err(|_| serde::de::Error::custom("a VMID that is not a number")),
    }
}

/// A boolean, which Proxmox writes `1` or `0`.
fn flag<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flag {
        Bool(bool),
        Number(u64),
        Text(String),
    }
    Ok(match Flag::deserialize(deserializer)? {
        Flag::Bool(flag) => flag,
        Flag::Number(number) => number != 0,
        Flag::Text(text) => text == "1",
    })
}

// ===========================================================================
// VERSION SEAM — end
// ===========================================================================

/// The loopback of a Linux guest, which the agent lists first: it is no
/// interface of the VM, and the tool this one replaces never saw it.
const LOOPBACK: &str = "lo";

/// Bytes in a mebibyte.
const MIB: f64 = 1_048_576.0;

/// Reads the cluster `client` points at: its version, its name, its nodes
/// with their networks, VMs and containers.
///
/// Logs in when the client has not, then only sends GET requests, as many at
/// once as the client allows. The result does not depend on the order of the
/// answers: nodes are sorted by name, networks by name, guests by VMID.
///
/// Fails, naming the path, as soon as a call fails — except the calls that
/// ask a guest about itself, whose failure leaves `None` in the guest.
pub async fn collect(client: &ProxmoxClient) -> Result<ProxmoxCluster, CollectError> {
    client.login().await?;
    // Alone and first: what follows is asked the way this version wants it.
    let version: WireVersion = client.get(Dialect::VERSION).await?;
    let version = ProxmoxVersion { version: version.version, release: version.release };
    let dialect = Dialect::of(&version)?;
    let (name, (nodes, offline)) = try_join(cluster_name(client, dialect), nodes(client, dialect)).await?;
    Ok(ProxmoxCluster { version, name, nodes, offline })
}

/// Empty on a standalone node: no entry is the cluster.
async fn cluster_name(client: &ProxmoxClient, dialect: Dialect) -> Result<String, CollectError> {
    let entries: Vec<WireClusterEntry> = client.get(&dialect.cluster_status()).await?;
    Ok(entries.into_iter().find(|entry| entry.kind == "cluster").map(|entry| entry.name).unwrap_or_default())
}

/// The nodes that can be read, sorted by name, and the names of those Proxmox
/// says are offline: pveproxy relays a call to its node, and a node that is
/// down answers nothing but an error. One node down is not a cluster unread.
async fn nodes(client: &ProxmoxClient, dialect: Dialect) -> Result<(Vec<Node>, Vec<String>), CollectError> {
    let entries: Vec<WireNodeEntry> = client.get(&dialect.nodes()).await?;
    // `offline` and `unknown` alike: only a node the cluster says is online is
    // asked, the calls pveproxy relays to another one fail with 595.
    let (down, up): (Vec<WireNodeEntry>, Vec<WireNodeEntry>) =
        entries.into_iter().partition(|entry| entry.status.as_deref().is_some_and(|status| status != "online"));
    let mut nodes = try_join_all(up.into_iter().map(|entry| node(client, dialect, entry.node))).await?;
    nodes.sort_by(|a, b| a.name.cmp(&b.name));
    let mut offline: Vec<String> = down.into_iter().map(|entry| entry.node).collect();
    offline.sort();
    Ok((nodes, offline))
}

async fn node(client: &ProxmoxClient, dialect: Dialect, name: String) -> Result<Node, CollectError> {
    let status = async { Ok(client.get::<WireNodeStatus>(&dialect.node_status(&name)).await?) };
    let (status, networks, vms, containers) = try_join4(
        status,
        networks(client, dialect, &name),
        vms(client, dialect, &name),
        containers(client, dialect, &name),
    )
    .await?;
    Ok(Node { cpus: status.cpuinfo.cpus, memory_total_bytes: status.memory.total, networks, vms, containers, name })
}

async fn networks(client: &ProxmoxClient, dialect: Dialect, node: &str) -> Result<Vec<NodeNetwork>, CollectError> {
    let entries: Vec<WireNetwork> = client.get(&dialect.node_networks(node)).await?;
    let network = |entry: WireNetwork| NodeNetwork {
        bond_members: bond_members(&entry.kind, &entry.slaves, &entry.ovs_bonds),
        vlan: node_vlan(&entry.kind, entry.vlan_id.as_ref(), entry.vlan_raw_device),
        name: entry.iface,
        kind: entry.kind,
        active: entry.active,
    };
    let mut networks: Vec<NodeNetwork> = entries.into_iter().map(network).collect();
    networks.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(networks)
}

async fn vms(client: &ProxmoxClient, dialect: Dialect, node: &str) -> Result<Vec<Vm>, CollectError> {
    let entries: Vec<WireVm> = client.get(&dialect.vms(node)).await?;
    let mut vms = try_join_all(entries.into_iter().map(|entry| vm(client, dialect, node, entry))).await?;
    vms.sort_by_key(|vm| vm.vmid);
    Ok(vms)
}

async fn vm(client: &ProxmoxClient, dialect: Dialect, node: &str, entry: WireVm) -> Result<Vm, CollectError> {
    let asked = dialect.asks_guest(&entry.status);
    let config_path = dialect.vm_config(node, entry.vmid);
    // The configuration in force, not the one with the pending changes applied
    // (the default of the API): a disk resize waiting for a restart is not done yet.
    let config = client.get_with::<Map<String, Value>>(&config_path, &[("current", "1")]);
    let interfaces =
        async { if asked { guest_interfaces(client, &dialect.vm_interfaces(node, entry.vmid)).await } else { None } };
    let os_info =
        async { if asked { guest_os_info(client, &dialect.vm_os_info(node, entry.vmid)).await } else { None } };
    let (config, interfaces, os_info) = join3(config, interfaces, os_info).await;
    // A VM whose configuration cannot be read is not left out: the collection fails.
    let config = config?;
    Ok(Vm {
        vmid: entry.vmid,
        name: entry.name,
        status: entry.status,
        template: entry.template,
        cpus: entry.cpus,
        max_memory_bytes: entry.maxmem,
        tags: split_tags(&entry.tags),
        os_type: config.get("ostype").and_then(Value::as_str).map(str::to_owned),
        disks: disks_of(&config),
        nics: nics_of(&config),
        interfaces,
        os_info,
    })
}

/// What the agent of a VM lists, or `None` when it did not answer: whatever
/// the failure (agent not running, not installed, timed out), the interfaces
/// are unknown, never empty.
async fn guest_interfaces(client: &ProxmoxClient, path: &str) -> Option<Vec<GuestInterface>> {
    let answer = client.get::<WireAgent<Vec<WireGuestInterface>>>(path).await.ok()?;
    let interface = |entry: WireGuestInterface| GuestInterface {
        name: entry.name,
        mac: entry.mac.filter(|mac| !mac.is_empty()),
        addresses: entry.addresses.unwrap_or_default().into_iter().map(guest_address).collect(),
    };
    Some(answer.result?.into_iter().filter(|entry| entry.name != LOOPBACK).map(interface).collect())
}

fn guest_address(entry: WireGuestAddress) -> GuestAddress {
    GuestAddress { address: entry.address, family: entry.family, prefix: entry.prefix }
}

/// What the agent of a VM says of its system, or `None` when it did not answer.
async fn guest_os_info(client: &ProxmoxClient, path: &str) -> Option<GuestOsInfo> {
    let info = client.get::<WireAgent<WireOsInfo>>(path).await.ok()?.result?;
    // A refused command says nothing of the system: unknown, not empty.
    if info.error.is_some() {
        return None;
    }
    Some(GuestOsInfo {
        id: info.id,
        name: info.name,
        pretty_name: info.pretty_name,
        version: info.version,
        version_id: info.version_id,
        kernel_release: info.kernel_release,
        machine: info.machine,
    })
}

async fn containers(client: &ProxmoxClient, dialect: Dialect, node: &str) -> Result<Vec<Container>, CollectError> {
    let entries: Vec<WireContainer> = client.get(&dialect.containers(node)).await?;
    let container = |entry: WireContainer| async move {
        // A container that is not running has no interface to report, hence
        // none to put a VLAN on: its configuration is not asked either.
        let (interfaces, nics) = if dialect.asks_guest(&entry.status) {
            join(
                container_interfaces(client, &dialect.container_interfaces(node, entry.vmid)),
                container_nics(client, &dialect.container_config(node, entry.vmid)),
            )
            .await
        } else {
            (None, None)
        };
        Container {
            vmid: entry.vmid,
            name: entry.name,
            status: entry.status,
            cpus: entry.cpus,
            max_memory_bytes: entry.maxmem,
            max_disk_bytes: entry.maxdisk,
            tags: split_tags(&entry.tags),
            interfaces,
            nics,
        }
    };
    let mut containers = join_all(entries.into_iter().map(container)).await;
    containers.sort_by_key(|container| container.vmid);
    Ok(containers)
}

/// The interfaces of a container, or `None` when they could not be read.
async fn container_interfaces(client: &ProxmoxClient, path: &str) -> Option<Vec<ContainerInterface>> {
    let entries = client.get::<Vec<WireContainerInterface>>(path).await.ok()?;
    let present = |text: Option<String>| text.filter(|text| !text.is_empty());
    let interface = |entry: WireContainerInterface| ContainerInterface {
        name: entry.name,
        mac: present(entry.hwaddr),
        inet: present(entry.inet),
        inet6: present(entry.inet6),
    };
    Some(entries.into_iter().filter(|entry| entry.name != LOOPBACK).map(interface).collect())
}

/// The network cards of the configuration of a container, or `None` when it
/// could not be read: its VLANs are then unknown, and nothing else is lost —
/// unlike the configuration of a VM, which also holds its disks.
async fn container_nics(client: &ProxmoxClient, path: &str) -> Option<GuestNics> {
    // The configuration in force, as for a VM.
    let config = client.get_with::<Map<String, Value>>(path, &[("current", "1")]).await.ok()?;
    Some(nics_of(&config))
}

/// `"a; b;;c"` → `["a", "b", "c"]`: Proxmox separates the tags of a guest with `;`.
fn split_tags(raw: &str) -> Vec<String> {
    raw.split(';').map(str::trim).filter(|tag| !tag.is_empty()).map(str::to_owned).collect()
}

/// The interfaces of a bond: a Linux bond lists them in `slaves`, an Open
/// vSwitch bond in `ovs_bonds`. Anything else aggregates nothing.
fn bond_members(kind: &str, slaves: &str, ovs_bonds: &str) -> Vec<String> {
    let members = match kind {
        "bond" => slaves,
        "OVSBond" => ovs_bonds,
        _ => "",
    };
    members.split_whitespace().map(str::to_owned).collect()
}

/// The lowest and the highest VLAN id (IEEE 802.1Q: 0 and 4095 are reserved).
const VLAN_IDS: std::ops::RangeInclusive<u16> = 1..=4094;

/// A VLAN id written in decimal; `None` for anything else.
fn vlan_id(text: &str) -> Option<u16> {
    let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    text.parse().ok().filter(|id| digits && VLAN_IDS.contains(id))
}

/// The VLAN of a node interface of type `vlan`, from its `vlan-id` (a string
/// on the versions read, a number accepted as well) and its
/// `vlan-raw-device`. `None` for another type, and for an id that is not one:
/// unknown, never "no VLAN".
fn node_vlan(kind: &str, id: Option<&Value>, raw_device: Option<String>) -> Option<NodeVlan> {
    if kind != "vlan" {
        return None;
    }
    let id = match id? {
        Value::String(text) => vlan_id(text)?,
        Value::Number(number) => vlan_id(&number.to_string())?,
        _ => return None,
    };
    Some(NodeVlan { id, raw_device: raw_device.filter(|device| !device.is_empty()) })
}

/// `BC:24:11:00:00:01`, in upper case; `None` for what is not a MAC address.
fn mac_address(text: &str) -> Option<String> {
    let groups: Vec<&str> = text.split(':').collect();
    let hex = |group: &&str| group.len() == 2 && group.bytes().all(|byte| byte.is_ascii_hexdigit());
    (groups.len() == 6 && groups.iter().all(hex)).then(|| text.to_uppercase())
}

/// `10;20-22` → `[(10, 10), (20, 22)]`: the `trunks` of a network card, VLAN
/// ids and ranges separated by `;` (`man qm`, `man pct`). `None` when a part
/// is not a VLAN id or a range in ascending order.
fn trunk_ranges(text: &str) -> Option<Vec<(u16, u16)>> {
    let range = |part: &str| match part.split_once('-') {
        Some((first, last)) => Some((vlan_id(first)?, vlan_id(last)?)).filter(|(first, last)| first <= last),
        None => vlan_id(part).map(|id| (id, id)),
    };
    text.split(';').map(range).collect()
}

/// `net3` → 3; `None` for any other key (`netmask`, `nameserver`…).
fn nic_key(key: &str) -> Option<u32> {
    let index = key.strip_prefix("net")?;
    let numbered = !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit());
    index.parse().ok().filter(|_| numbered)
}

/// One `netN` line: options separated by commas. A VM names the address of
/// its card after its model (`virtio=BC:24:11:00:00:01`) or with `macaddr=`,
/// a container with `hwaddr=`. `None` when the line gives no MAC address, or
/// a `tag` or `trunks` that cannot be read.
fn nic(key: &str, value: &str) -> Option<GuestNic> {
    let (mut mac, mut bridge, mut tag, mut trunks) = (None, None, None, Vec::new());
    for option in value.split(',') {
        // A word alone (a model without address) says nothing read here.
        let Some((name, written)) = option.split_once('=') else {
            continue;
        };
        match name {
            "bridge" => bridge = Some(written.to_owned()).filter(|bridge| !bridge.is_empty()),
            "tag" => tag = Some(vlan_id(written)?),
            "trunks" => trunks = trunk_ranges(written)?,
            "macaddr" | "hwaddr" => mac = Some(mac_address(written)?),
            // `<model>=<MAC>`: any other option whose value is an address.
            _ => mac = mac.or_else(|| mac_address(written)),
        }
    }
    Some(GuestNic { key: key.to_owned(), mac: mac?, bridge, tag, trunks })
}

/// The network cards of a guest configuration: every `netN` key, sorted by
/// its number. A line that cannot be read is named, never dropped in silence:
/// what it says of a VLAN is unknown.
fn nics_of(config: &Map<String, Value>) -> GuestNics {
    let mut lines: Vec<(u32, &String, &Value)> =
        config.iter().filter_map(|(key, value)| Some((nic_key(key)?, key, value))).collect();
    lines.sort_by_key(|(index, _, _)| *index);
    let mut nics = GuestNics::default();
    for (_, key, value) in lines {
        match value.as_str().and_then(|value| nic(key, value)) {
            Some(nic) => nics.read.push(nic),
            None => nics.unread.push(key.clone()),
        }
    }
    nics
}

/// A size as Proxmox writes it (`parse_size` of pve-common): a decimal number
/// and an optional binary unit `K`, `M`, `G` or `T`, a bare number being
/// bytes. Whole mebibytes, rounded down; `None` when it is not a size.
fn parse_size_mib(value: &str) -> Option<u64> {
    let (number, unit) = match value.char_indices().last() {
        Some((at, 'K')) => (&value[..at], 1024.0),
        Some((at, 'M')) => (&value[..at], MIB),
        Some((at, 'G')) => (&value[..at], MIB * 1024.0),
        Some((at, 'T')) => (&value[..at], MIB * MIB),
        _ => (value, 1.0),
    };
    // Checked by hand: the float parser of Rust also takes signs, exponents and `inf`.
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let well_formed = match number.split_once('.') {
        Some((whole, fraction)) => digits(whole) && digits(fraction),
        None => digits(number),
    };
    if !well_formed {
        return None;
    }
    let bytes = number.parse::<f64>().ok()? * unit;
    // The cast rounds down, and saturates on a size no disk has.
    Some((bytes / MIB) as u64)
}

/// The buses a disk can be attached to, with the prefix of their configuration keys.
const DISK_BUSES: [(&str, DiskBus); 4] =
    [("virtio", DiskBus::Virtio), ("scsi", DiskBus::Scsi), ("sata", DiskBus::Sata), ("ide", DiskBus::Ide)];

/// `scsi1` → the SCSI bus, index 1; `None` for any other key (`scsihw`, `unused0`…).
fn disk_key(key: &str) -> Option<(DiskBus, u32)> {
    DISK_BUSES.iter().find_map(|(prefix, bus)| {
        let index = key.strip_prefix(prefix)?;
        let numbered = !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit());
        Some((*bus, index.parse().ok().filter(|_| numbered)?))
    })
}

/// The disks of a VM configuration: every `virtioN`, `scsiN`, `sataN` and
/// `ideN` key whose value carries a size.
fn disks_of(config: &Map<String, Value>) -> Vec<Disk> {
    let disk = |(key, value): (&String, &Value)| {
        let (bus, index) = disk_key(key)?;
        // `volume,option=value,…`: the volume comes first, whatever it looks like.
        let mut tokens = value.as_str()?.split(',');
        let name = tokens.next()?.to_owned();
        let options: Vec<&str> = tokens.collect();
        let mut sizes = options.iter().filter_map(|option| parse_size_mib(option.strip_prefix("size=")?));
        // A drive without size is an empty or a pass-through drive: there is no disk to describe.
        let size_mib = sizes.rfind(|size| *size > 0)?;
        Some(Disk { bus, index, name, size_mib, cdrom: options.contains(&"media=cdrom") })
    };
    let mut disks: Vec<Disk> = config.iter().filter_map(disk).collect();
    disks.sort_by_key(|disk| (disk.bus, disk.index));
    disks
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::DiskBus;

    #[test]
    fn tags_are_split_on_semicolons_trimmed_and_never_empty() {
        assert_eq!(split_tags("service-docker;service-seeq-queue"), ["service-docker", "service-seeq-queue"]);
        assert_eq!(split_tags(" a ; b;;c; "), ["a", "b", "c"]);
        assert_eq!(split_tags(""), Vec::<String>::new());
        assert_eq!(split_tags(" ; "), Vec::<String>::new());
    }

    #[test]
    fn a_linux_bond_lists_its_members_in_slaves_an_ovs_bond_in_ovs_bonds() {
        assert_eq!(bond_members("bond", "eno1 eno2", ""), ["eno1", "eno2"]);
        assert_eq!(bond_members("OVSBond", "", "enp1s0  enp2s0"), ["enp1s0", "enp2s0"]);
        // Each kind reads its own field only.
        assert_eq!(bond_members("OVSBond", "eno1 eno2", ""), Vec::<String>::new());
        assert_eq!(bond_members("bond", "", "enp1s0"), Vec::<String>::new());
    }

    #[test]
    fn only_a_bond_has_members() {
        for kind in ["eth", "bridge", "vlan", "OVSBridge", "OVSIntPort", "alias", ""] {
            assert_eq!(bond_members(kind, "eno1 eno2", "eno3"), Vec::<String>::new(), "{kind}");
        }
    }

    #[test]
    fn sizes_follow_the_units_of_proxmox() {
        // Binary units: 1G = 1024 MiB, 1T = 1024 * 1024 MiB.
        assert_eq!(parse_size_mib("25G"), Some(25 * 1024));
        assert_eq!(parse_size_mib("632M"), Some(632));
        assert_eq!(parse_size_mib("2T"), Some(2 * 1024 * 1024));
        // 5384344 KiB = 5258.14 MiB, rounded down.
        assert_eq!(parse_size_mib("5384344K"), Some(5258));
        // A bare number is bytes: 3 MiB and a half.
        assert_eq!(parse_size_mib("3670016"), Some(3));
        assert_eq!(parse_size_mib("0.5G"), Some(512));
        assert_eq!(parse_size_mib("1.5T"), Some(1_572_864));
        // Less than a mebibyte.
        assert_eq!(parse_size_mib("512K"), Some(0));
    }

    #[test]
    fn what_is_not_a_size_is_refused() {
        for value in ["", "G", "25g", "25GB", "25 G", "-1G", "+1G", "1e3", ".5G", "5.G", "1.2.3G", "inf", "NaN", "0x10"]
        {
            assert_eq!(parse_size_mib(value), None, "{value:?}");
        }
    }

    fn config(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().unwrap().clone()
    }

    fn disk(bus: DiskBus, index: u32, name: &str, size_mib: u64) -> Disk {
        Disk { bus, index, name: name.to_owned(), size_mib, cdrom: false }
    }

    #[test]
    fn disks_are_listed_by_bus_then_index() {
        let disks = disks_of(&config(json!({
            "ide0": "local:vm-1-disk-5,size=1G",
            "scsi10": "local:vm-1-disk-3,size=3G",
            "scsi2": "local:vm-1-disk-2,size=2G",
            "sata1": "local:vm-1-disk-4,size=4G",
            "virtio0": "local:vm-1-disk-0,iothread=1,size=32G,ssd=1",
            "cores": 2,
            "name": "vm",
        })));
        assert_eq!(
            disks,
            [
                disk(DiskBus::Virtio, 0, "local:vm-1-disk-0", 32 * 1024),
                disk(DiskBus::Scsi, 2, "local:vm-1-disk-2", 2 * 1024),
                disk(DiskBus::Scsi, 10, "local:vm-1-disk-3", 3 * 1024),
                disk(DiskBus::Sata, 1, "local:vm-1-disk-4", 4 * 1024),
                disk(DiskBus::Ide, 0, "local:vm-1-disk-5", 1024),
            ]
        );
    }

    #[test]
    fn a_drive_without_size_is_not_a_disk() {
        let disks = disks_of(&config(json!({
            "ide2": "none,media=cdrom",
            "ide0": "local:vm-1-cloudinit,media=cdrom",
            "scsi0": "local:vm-1-disk-0",
            "scsi1": "local:vm-1-disk-1,size=banana",
            "scsi2": "local:vm-1-disk-2,size=512K",
        })));
        assert_eq!(disks, []);
    }

    #[test]
    fn a_cdrom_with_a_size_is_kept_and_flagged() {
        let disks = disks_of(&config(json!({
            "ide2": "local:iso/debian.iso,media=cdrom,size=632M",
            "scsi0": "local:vm-1-disk-0,size=1G",
        })));
        assert_eq!(
            disks,
            [
                disk(DiskBus::Scsi, 0, "local:vm-1-disk-0", 1024),
                Disk {
                    bus: DiskBus::Ide,
                    index: 2,
                    name: "local:iso/debian.iso".to_owned(),
                    size_mib: 632,
                    cdrom: true
                },
            ]
        );
    }

    #[test]
    fn only_drive_keys_are_read() {
        // `scsihw` is the controller model, `unused0` a detached volume, `efidisk0` and `tpmstate0` firmware state.
        let disks = disks_of(&config(json!({
            "scsihw": "virtio-scsi-pci,size=1G",
            "unused0": "local:vm-1-disk-9,size=1G",
            "efidisk0": "local:vm-1-disk-8,size=4M",
            "tpmstate0": "local:vm-1-disk-7,size=4M",
            "scsi": "local:vm-1-disk-6,size=1G",
            "scsi0x": "local:vm-1-disk-5,size=1G",
            "virtio1": 7,
        })));
        assert_eq!(disks, []);
    }

    fn card(key: &str, mac: &str, bridge: Option<&str>, tag: Option<u16>, trunks: &[(u16, u16)]) -> GuestNic {
        GuestNic {
            key: key.to_owned(),
            mac: mac.to_owned(),
            bridge: bridge.map(str::to_owned),
            tag,
            trunks: trunks.to_vec(),
        }
    }

    fn read(cards: Vec<GuestNic>) -> GuestNics {
        GuestNics { read: cards, unread: vec![] }
    }

    #[test]
    fn the_card_of_a_vm_gives_its_address_its_bridge_and_its_tag() {
        // As read on a Proxmox VE 9.2 node on 2026-11-22: "net0": "virtio=<MAC>,bridge=vmbr0,tag=10".
        let nics = nics_of(&config(json!({"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=10"})));
        assert_eq!(nics, read(vec![card("net0", "BC:24:11:00:00:01", Some("vmbr0"), Some(10), &[])]));
    }

    #[test]
    fn the_address_of_a_card_is_read_under_its_model_or_its_own_key_and_put_in_upper_case() {
        // `man qm`: `net[n]: [model=]<enum> [,bridge=<bridge>] … [,macaddr=<XX:XX:XX:XX:XX:XX>]`.
        let nics = nics_of(&config(json!({
            "net0": "e1000=bc:24:11:00:00:0a,bridge=vmbr1,firewall=1",
            "net1": "model=virtio,macaddr=BC:24:11:00:00:0B,bridge=vmbr1",
            // `man pct`: `net[n]: name=<string> [,bridge=<bridge>] … [,hwaddr=<XX:XX:XX:XX:XX:XX>]`.
            "net2": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:0C,ip=dhcp,type=veth",
        })));
        assert_eq!(
            nics,
            read(vec![
                card("net0", "BC:24:11:00:00:0A", Some("vmbr1"), None, &[]),
                card("net1", "BC:24:11:00:00:0B", Some("vmbr1"), None, &[]),
                card("net2", "BC:24:11:00:00:0C", Some("vmbr0"), None, &[]),
            ])
        );
    }

    #[test]
    fn the_trunks_of_a_card_are_ids_and_ranges_in_the_order_written() {
        // `man qm`: `trunks=<vlanid[;vlanid...]>`; never observed on a real guest.
        let nics = nics_of(&config(json!({
            "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,trunks=10;20-22",
            "net1": "virtio=BC:24:11:00:00:02,bridge=vmbr0,tag=5,trunks=30",
        })));
        assert_eq!(
            nics,
            read(vec![
                card("net0", "BC:24:11:00:00:01", Some("vmbr0"), None, &[(10, 10), (20, 22)]),
                card("net1", "BC:24:11:00:00:02", Some("vmbr0"), Some(5), &[(30, 30)]),
            ])
        );
    }

    #[test]
    fn a_card_that_cannot_be_read_is_named_and_the_others_are_kept() {
        let nics = nics_of(&config(json!({
            // Not a VLAN id: a word, the two reserved ids, a sign.
            "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=banana",
            "net1": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=0",
            "net2": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=4095",
            "net3": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=+7",
            // Not ranges: backwards, empty, open.
            "net4": "virtio=BC:24:11:00:00:01,bridge=vmbr0,trunks=30-20",
            "net5": "virtio=BC:24:11:00:00:01,bridge=vmbr0,trunks=",
            "net6": "virtio=BC:24:11:00:00:01,bridge=vmbr0,trunks=10;",
            // No address, or one that is not an address.
            "net7": "virtio,bridge=vmbr0,tag=10",
            "net8": "name=eth0,hwaddr=BC:24:11:00:00,tag=10",
            // Not even a text.
            "net9": 7,
            "net10": "virtio=BC:24:11:00:00:0A,bridge=vmbr0,tag=4094",
        })));
        assert_eq!(nics.read, [card("net10", "BC:24:11:00:00:0A", Some("vmbr0"), Some(4094), &[])]);
        assert_eq!(nics.unread, ["net0", "net1", "net2", "net3", "net4", "net5", "net6", "net7", "net8", "net9"]);
    }

    #[test]
    fn only_the_keys_of_a_network_card_are_read_and_they_are_sorted_by_number() {
        let nics = nics_of(&config(json!({
            "net10": "virtio=BC:24:11:00:00:0A",
            "net2": "virtio=BC:24:11:00:00:02",
            "net": "virtio=BC:24:11:00:00:0B",
            "net0x": "virtio=BC:24:11:00:00:0C",
            "netmask": "virtio=BC:24:11:00:00:0D",
            "nameserver": "192.0.2.53",
        })));
        let keys: Vec<&str> = nics.read.iter().map(|nic| nic.key.as_str()).collect();
        assert_eq!(keys, ["net2", "net10"]);
        assert_eq!(nics.unread, Vec::<String>::new());
    }

    #[test]
    fn the_first_token_is_the_name_whatever_follows() {
        // The size is read from the options only: a volume cannot pass for one.
        let disks = disks_of(&config(json!({"sata0": "size=9G,size=2G"})));
        assert_eq!(disks, [disk(DiskBus::Sata, 0, "size=9G", 2 * 1024)]);
    }
}
