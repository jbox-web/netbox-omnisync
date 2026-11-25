//! Turns what was read from a Proxmox VE cluster into the NetBox objects the
//! source asks for.
//!
//! One pure function, [`desired`]: no I/O, no clock, the reverse DNS lookup
//! being handed in. It replaces the sync half of netbox-ssot (commit
//! `604930e`, `internal/source/proxmox/proxmox_sync.go`), whose names, slugs,
//! units, truncations and defaults it keeps to the letter: the first run on a
//! NetBox that netbox-ssot filled must change nothing but ownership tags.
//!
//! Two rules of that tool shape the whole module. It never wrote an empty
//! value (a zero, an empty text, a missing reference were left out of its
//! requests), so what Proxmox does not say is not declared here either and
//! NetBox keeps what it has. And what could not be read is unknown, never
//! empty: a guest whose interfaces are `None` declares none and marks them as
//! unknown dependents.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;
use omnisync_core::inventory::custom_fields;
use omnisync_core::inventory::dns::Names;
// The lookup is shared with the other hypervisor sources; it is named here as it always was.
pub use omnisync_core::inventory::dns::{NoReverseDns, ReverseDns};
use omnisync_core::inventory::model::{Desired, Identity, Kind, TAG_MARKER, Target, VlanScope, VrfKey};
use omnisync_core::network::hosts::Heard;

use crate::neighbors::NodeNeighbors;
use regex::Regex;

use crate::model::{
    Container, ContainerInterface, Disk, GuestAddress, GuestInterface, GuestNic, GuestNics, Node, ProxmoxCluster, Vm,
};

/// Name of the cluster type; its slug is the slug of this name.
const CLUSTER_TYPE: &str = "Proxmox";

/// The manufacturer and the device type of every host: Proxmox does not say
/// what hardware a node is. Named after the tool that created them, and kept
/// so: they are the ones NetBox already has.
const GENERIC_MANUFACTURER: &str = "Generic Manufacturer";
const GENERIC_MANUFACTURER_DESCRIPTION: &str = "Generic Manufacturer created by netbox-ssot";
const GENERIC_MODEL: &str = "Generic Model";
const GENERIC_MODEL_DESCRIPTION: &str = "Generic Device Type created by netbox-ssot";

/// A role netbox-ssot created itself when its configuration named none.
struct DefaultRole {
    name: &'static str,
    description: &'static str,
    color: &'static str,
    /// Sent only when true: netbox-ssot left a false out of its requests, so
    /// NetBox applied its own default to the two other roles.
    vm_role: bool,
}

const SERVER_ROLE: DefaultRole =
    DefaultRole { name: "Server", description: "Device role for marking server.", color: "00add8", vm_role: false };
const VM_ROLE: DefaultRole =
    DefaultRole { name: "VM", description: "Role for representing VMs.", color: "81eaea", vm_role: false };
const CONTAINER_ROLE: DefaultRole = DefaultRole {
    name: "Container",
    description: "VM role for separating containers from VMs.",
    color: "0db7ed",
    vm_role: true,
};

/// Colour of a tag created from the tag of a guest (`ColorGreen`).
const GUEST_TAG_COLOR: &str = "4caf50";

/// The longest name NetBox takes for a device, a virtual machine, an
/// interface or a virtual disk, in bytes as netbox-ssot counted them.
const MAX_NAME_LENGTH: usize = 64;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// The status Proxmox gives a guest that does not run.
const STOPPED: &str = "stopped";

/// The families a guest agent names.
const IPV4: &str = "ipv4";
const IPV6: &str = "ipv6";

/// The VMware guest names netbox-ssot gave a VM from its `ostype` when the
/// agent did not tell the system, so that both hypervisors share platforms.
const OSTYPE_PLATFORMS: [(&str, &str); 10] = [
    ("wxp", "Microsoft Windows XP (32-bit)"),
    ("w2k", "Microsoft Windows 2000 Server"),
    ("w2k3", "Microsoft Windows Server 2003 Standard (32-bit)"),
    ("w2k8", "Microsoft Windows Server 2008 (64-bit)"),
    ("wvista", "Microsoft Windows Vista (32-bit)"),
    ("win7", "Microsoft Windows 7 (64-bit)"),
    ("win8", "Microsoft Windows 8 (64-bit)"),
    ("win10", "Microsoft Windows 10 (64-bit)"),
    ("win11", "Microsoft Windows 11 (64-bit)"),
    ("l26", "Other 2.6.x Linux (64-bit)"),
];

/// The platform of a VM whose `ostype` has no name above, or that has none.
const UNKNOWN_PLATFORM: &str = "Unknown";

/// The VLAN ids a trunk may carry: one that carries them all (from the first
/// or the second, the first being the default untagged one) is a port of
/// every VLAN, and none is listed for it.
const FIRST_VLAN: u16 = 1;
const LAST_VLAN: u16 = 4094;

/// The most VLANs a trunk is listed with. A wider range (`trunks=2-4000`)
/// would have one VLAN declared, so created, for each id: such a card is a
/// warning, and its interfaces keep what NetBox has.
const MAX_TRUNK_VLANS: usize = 64;

/// Why a setting cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    #[error("{value:?} is not a subnet: {reason}")]
    Subnet { value: String, reason: String },
    #[error("interface filter {pattern:?} is not a regular expression: {reason}")]
    InterfaceFilter { pattern: String, reason: String },
}

/// How one Proxmox source is translated. The configuration loader fills it.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Name of the source: it names the cluster of a standalone node and
    /// fills the `source` custom field.
    pub source: String,
    /// The NetBox site of the cluster, of its hosts and of their guests.
    pub site: String,
    /// The NetBox VLAN group the VLANs of that site are kept in, when it
    /// shares them with other sites; `None`: the VLANs are those of the site.
    pub vlan_group: Option<String>,
    /// The NetBox tenant of the cluster, of its hosts, of their guests and of
    /// the guests' addresses; `None` leaves the tenants as NetBox has them.
    pub tenant: Option<String>,
    /// The NetBox role of the hosts; `None` is netbox-ssot's `Server` role.
    pub host_role: Option<String>,
    /// The NetBox role of the virtual machines; `None` is netbox-ssot's `VM`
    /// role. Containers always get the `Container` role.
    pub vm_role: Option<String>,
    /// Appended as it is to the name of each node (`assignDomainName`).
    pub domain: String,
    /// Leave the templates out (`ignoreVMTemplates`).
    pub ignore_templates: bool,
    /// An address inside one of these is not synced; wins over `permitted_subnets`.
    pub ignored_subnets: Vec<IpNet>,
    /// When not empty, only an address inside one of these is synced.
    pub permitted_subnets: Vec<IpNet>,
    /// An interface, of a host or of a guest, whose name matches anywhere is
    /// not synced, nor are its addresses.
    pub interface_filter: Option<Regex>,
}

impl Settings {
    /// The settings of a source that sets nothing but its name and its site:
    /// the defaults of netbox-ssot.
    pub fn new(source: &str, site: &str) -> Self {
        Settings {
            source: source.to_owned(),
            site: site.to_owned(),
            vlan_group: None,
            tenant: None,
            host_role: None,
            vm_role: None,
            domain: String::new(),
            ignore_templates: false,
            ignored_subnets: Vec::new(),
            permitted_subnets: Vec::new(),
            interface_filter: None,
        }
    }

    /// Parses subnets written as `10.0.0.0/8` or `::/0`. Host bits are
    /// dropped, as netbox-ssot did: `172.31.4.145/25` is `172.31.4.128/25`.
    pub fn subnets<S: AsRef<str>>(values: &[S]) -> Result<Vec<IpNet>, SettingsError> {
        let subnet = |value: &S| {
            let value = value.as_ref();
            let parsed: Result<IpNet, _> = value.trim().parse();
            parsed
                .map(|subnet| subnet.trunc())
                .map_err(|error| SettingsError::Subnet { value: value.to_owned(), reason: error.to_string() })
        };
        values.iter().map(subnet).collect()
    }

    /// Compiles an interface filter; an empty pattern filters nothing.
    pub fn interface_filter(pattern: &str) -> Result<Option<Regex>, SettingsError> {
        if pattern.is_empty() {
            return Ok(None);
        }
        let compiled = Regex::new(pattern).map_err(|error| SettingsError::InterfaceFilter {
            pattern: pattern.to_owned(),
            reason: error.to_string(),
        })?;
        Ok(Some(compiled))
    }

    /// Whether an interface of that name is left out.
    fn filters(&self, interface: &str) -> bool {
        self.interface_filter.as_ref().is_some_and(|filter| filter.is_match(interface))
    }

    /// Whether an address is synced: outside every ignored subnet, and inside
    /// a permitted one when some are given.
    fn permits(&self, address: IpAddr) -> bool {
        // An IPv4-mapped IPv6 address is the IPv4 address it carries, as in Go's `IPNet.Contains`.
        let address = address.to_canonical();
        let within = |subnets: &[IpNet]| subnets.iter().any(|subnet| subnet.contains(&address));
        !within(&self.ignored_subnets) && (self.permitted_subnets.is_empty() || within(&self.permitted_subnets))
    }
}

/// What a cluster asks of NetBox.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Translation {
    /// Every object once, in a stable order; an address two guests hold is
    /// one object per guest.
    pub objects: Vec<Desired>,
    /// What was left out, and why.
    pub warnings: Vec<String>,
}

/// What the physical cards of each node hear, under the NetBox name of the
/// node: the one its device is written under. A card `interface_filter`
/// leaves out is left out here too.
pub fn heard(neighbors: &NodeNeighbors, settings: &Settings) -> Vec<Heard> {
    let mut heard = Vec::new();
    for (node, cards) in &neighbors.by_node {
        let host = truncate(&format!("{node}{}", settings.domain)).to_owned();
        // A card the filter leaves out has no interface in NetBox.
        heard.extend(cards.iter().filter(|card| !settings.filters(&card.card)).map(|card| Heard {
            host: host.clone(),
            card: card.card.clone(),
            switch: card.switch.clone(),
            port: card.port.clone(),
        }));
    }
    heard
}

/// The NetBox objects `cluster` asks for.
///
/// Everything netbox-ssot added for a Proxmox source: the cluster type and
/// the cluster, the hosts with their interfaces, the virtual machines and the
/// containers with their interfaces, MAC and IP addresses, prefixes and
/// virtual disks, and what those refer to (site, tenant, roles, platforms,
/// tags, the generic manufacturer and device type).
pub fn desired(cluster: &ProxmoxCluster, settings: &Settings, resolver: &dyn ReverseDns) -> Translation {
    // A standalone node has no cluster name: the cluster is named after the source.
    let cluster_name = if cluster.name.is_empty() { settings.source.as_str() } else { cluster.name.as_str() };
    let mut translator = Translator {
        settings,
        names: Names::new(resolver),
        cluster: cluster_name,
        objects: Vec::new(),
        shared: BTreeSet::new(),
        warnings: Vec::new(),
    };
    translator.cluster();
    let kept = kept_guests(cluster, settings);
    let hosts: Vec<String> = cluster.nodes.iter().map(|node| translator.host(node)).collect();
    for (node, host) in cluster.nodes.iter().zip(&hosts) {
        for vm in &node.vms {
            if settings.ignore_templates && vm.template {
                continue;
            }
            match kept.get(&homonym_key(&vm.name)) {
                Some(&vmid) if vmid != vm.vmid => translator.warnings.push(format!(
                    "skipping vm {} (vmid {}): name already used by vmid {vmid} in the cluster",
                    vm.name, vm.vmid
                )),
                _ => translator.vm(vm, host),
            }
        }
    }
    for (node, host) in cluster.nodes.iter().zip(&hosts) {
        for container in &node.containers {
            match kept.get(&homonym_key(&container.name)) {
                Some(&vmid) if vmid != container.vmid => translator.warnings.push(format!(
                    "skipping container {} (vmid {}): name already used by vmid {vmid} in the cluster",
                    container.name, container.vmid
                )),
                _ => translator.container(container, host),
            }
        }
    }
    translator.warnings.extend(translator.names.warning());
    Translation { objects: translator.objects, warnings: translator.warnings }
}

/// `utils.Slugify` of netbox-ssot: trimmed, in lower case, each space turned
/// into a hyphen, then everything but `a-z`, `0-9`, `_` and `-` removed.
fn slugify(name: &str) -> String {
    let kept = |character: &char| matches!(character, 'a'..='z' | '0'..='9' | '_' | '-');
    name.trim().to_lowercase().replace(' ', "-").chars().filter(kept).collect()
}

/// A name cut to what NetBox accepts: 64 bytes, as netbox-ssot counted, but
/// never inside a character, which it did not check.
fn truncate(name: &str) -> &str {
    if name.len() <= MAX_NAME_LENGTH {
        return name;
    }
    let mut end = MAX_NAME_LENGTH;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// The NetBox type of a node network, `None` for a physical NIC, whose real
/// type Proxmox does not expose.
fn node_interface_type(kind: &str) -> Option<&'static str> {
    match kind {
        "bond" | "OVSBond" => Some("lag"),
        "bridge" | "OVSBridge" => Some("bridge"),
        "vlan" | "OVSIntPort" | "alias" => Some("virtual"),
        _ => None,
    }
}

/// The platform of a VM whose agent says nothing, from its `ostype`.
fn ostype_platform_name(os_type: Option<&str>) -> &'static str {
    let named = OSTYPE_PLATFORMS.iter().find(|(known, _)| Some(*known) == os_type);
    named.map_or(UNKNOWN_PLATFORM, |(_, name)| name)
}

/// `active`, or `offline` for a guest Proxmox says is stopped.
fn guest_status(status: &str) -> &'static str {
    if status == STOPPED { "offline" } else { "active" }
}

/// What two guests must not share: the name NetBox stores, whatever its
/// letter case — NetBox refuses two virtual machines of a cluster whose names
/// differ by case only.
fn homonym_key(name: &str) -> String {
    truncate(name).to_lowercase()
}

/// For each guest name of the cluster, the VMID that is synced under it.
///
/// NetBox names a virtual machine once per cluster where Proxmox identifies
/// its guests by VMID: among VMs and containers of the same name only the
/// lowest VMID is synced. Only the guests that would be synced compete: an
/// ignored template does not shadow its namesake.
fn kept_guests(cluster: &ProxmoxCluster, settings: &Settings) -> BTreeMap<String, u64> {
    let mut kept: BTreeMap<String, u64> = BTreeMap::new();
    let mut keep = |name: &str, vmid: u64| {
        let lowest = kept.entry(homonym_key(name)).or_insert(vmid);
        *lowest = (*lowest).min(vmid);
    };
    for node in &cluster.nodes {
        for vm in node.vms.iter().filter(|vm| !(settings.ignore_templates && vm.template)) {
            keep(&vm.name, vm.vmid);
        }
        for container in &node.containers {
            keep(&container.name, container.vmid);
        }
    }
    kept
}

/// An address of a guest, as its agent or Proxmox gives it.
struct RawAddress<'a> {
    /// The host part, which may carry a zone index (`fe80::1%eth0`).
    host: &'a str,
    /// The mask as it was given; `None` when the address came without one.
    prefix: Option<Cow<'a, str>>,
    /// `ipv4` or `ipv6` as the source says, which decides the primary
    /// address and the prefix; anything else is reported.
    family: &'a str,
    /// Whether netbox-ssot declared the prefix of such an address: it did not
    /// for the IPv6 address of a container.
    with_prefix: bool,
}

/// An interface of a guest, whatever the guest.
struct RawInterface<'a> {
    name: &'a str,
    mac: Option<&'a str>,
    addresses: Vec<RawAddress<'a>>,
}

/// An address given with its mask (`192.0.2.10/24`), as a container has them.
fn masked<'a>(address: &'a str, family: &'a str, with_prefix: bool) -> RawAddress<'a> {
    match address.split_once('/') {
        Some((host, prefix)) => RawAddress { host, prefix: Some(Cow::Borrowed(prefix)), family, with_prefix },
        None => RawAddress { host: address, prefix: None, family, with_prefix },
    }
}

/// An address as the agent of a VM gives it: with its family and its mask.
fn agent_address(address: &GuestAddress) -> RawAddress<'_> {
    RawAddress {
        host: address.address.as_str(),
        prefix: Some(Cow::Owned(address.prefix.to_string())),
        family: address.family.as_str(),
        with_prefix: true,
    }
}

/// An interface as the agent of a VM lists it.
fn agent_interface(interface: &GuestInterface) -> RawInterface<'_> {
    RawInterface {
        name: interface.name.as_str(),
        mac: interface.mac.as_deref(),
        addresses: interface.addresses.iter().map(agent_address).collect(),
    }
}

/// An interface as Proxmox lists it for a container: one IPv4 and one IPv6 address at most.
fn container_interface(interface: &ContainerInterface) -> RawInterface<'_> {
    let inet = interface.inet.as_deref().map(|address| masked(address, IPV4, true));
    // netbox-ssot declared no prefix for the IPv6 address of a container.
    let inet6 = interface.inet6.as_deref().map(|address| masked(address, IPV6, false));
    RawInterface {
        name: interface.name.as_str(),
        mac: interface.mac.as_deref(),
        addresses: inet.into_iter().chain(inet6).collect(),
    }
}

/// A guest, VM or container, once its own object is built.
struct Guest<'a> {
    /// `vm` or `container`, for the warnings.
    sort: &'static str,
    /// The name as Proxmox has it, for the warnings.
    name: &'a str,
    identity: Identity,
    /// `None` when the interfaces could not be read.
    interfaces: Option<Vec<RawInterface<'a>>>,
    /// The network cards of the configuration, which say the VLAN of the
    /// interfaces that have their address; `None` when they could not be read.
    nics: Option<&'a GuestNics>,
}

/// What a network card says of the VLANs of its interface.
enum Dot1q {
    /// `tag` alone: an access port of that VLAN.
    Access(u16),
    /// `trunks`: the VLANs carried tagged, in ascending order, and the
    /// untagged one when the card has a `tag` as well.
    Tagged { untagged: Option<u16>, tagged: Vec<u16> },
    /// `trunks` over every VLAN.
    TaggedAll { untagged: Option<u16> },
}

/// What `nic` says: `Ok(None)` when it has neither `tag` nor `trunks` (the
/// card is then in whatever VLAN its bridge puts it, which is not read), and
/// `Err` with the number of VLANs of a trunk wider than `MAX_TRUNK_VLANS`.
fn dot1q(nic: &GuestNic) -> Result<Option<Dot1q>, usize> {
    if nic.trunks.is_empty() {
        return Ok(nic.tag.map(Dot1q::Access));
    }
    if nic.trunks.iter().any(|(first, last)| *first <= FIRST_VLAN + 1 && *last >= LAST_VLAN) {
        return Ok(Some(Dot1q::TaggedAll { untagged: nic.tag }));
    }
    let listed: BTreeSet<u16> = nic.trunks.iter().flat_map(|(first, last)| *first..=*last).collect();
    if listed.len() > MAX_TRUNK_VLANS {
        return Err(listed.len());
    }
    let tagged = listed.into_iter().filter(|vid| Some(*vid) != nic.tag).collect();
    Ok(Some(Dot1q::Tagged { untagged: nic.tag, tagged }))
}

struct Translator<'a> {
    settings: &'a Settings,
    /// The DNS names of the addresses, from the reverse lookup handed in.
    names: Names<'a>,
    /// Name of the NetBox cluster.
    cluster: &'a str,
    objects: Vec<Desired>,
    /// The objects several others refer to, declared once.
    shared: BTreeSet<(Kind, Vec<String>)>,
    warnings: Vec<String>,
}

impl Translator<'_> {
    fn new_object(&self, kind: Kind, identity: Identity) -> Desired {
        Desired::new(kind, identity, &self.settings.source)
    }

    /// Declares an object several others may refer to, the first time only.
    fn share(&mut self, object: Desired) {
        if self.shared.insert((object.kind, object.identity.key().to_vec())) {
            self.objects.push(object);
        }
    }

    /// Declares a reference that is only written when NetBox holds no value for
    /// it, and the object it points to.
    ///
    /// Two references are so: the generic device type of a host (netbox-ssot
    /// kept a type set by hand) and the platform of a VM whose agent is silent
    /// (netbox-ssot kept the one an agent had reported, and only fell back on
    /// the `ostype`).
    fn reference_when_unset(&mut self, object: Desired, field: &str, target: Desired) -> Desired {
        let (kind, identity) = (target.kind, target.identity.clone());
        self.share(target);
        object.reference(field, kind, identity).only_when_empty(field)
    }

    /// An object the source only needs to exist: found in NetBox and owned by
    /// no tool, it is used as it is.
    fn existing(&self, kind: Kind, name: &str) -> Desired {
        self.new_object(kind, Identity::named(name))
            .field("name", name)
            .create_only("slug", slugify(name))
            .ensure_only()
    }

    fn with_site(&self, object: Desired) -> Desired {
        object.reference("site", Kind::Site, Identity::named(&self.settings.site))
    }

    /// The VLAN `vid` of the site of the cluster, declared so that it exists:
    /// one found in NetBox is used as it is, its name included, and one
    /// NetBox lacks is created as `VLAN<vid>`, Proxmox naming no VLAN.
    ///
    /// A site that shares its VLANs keeps them in its VLAN group: the VLAN is
    /// then the one of the group, and has no site — NetBox refuses a VLAN of
    /// a site on an interface of another one. The group itself is only
    /// referred to: it is a prerequisite, never created here.
    fn vlan(&mut self, vid: u16) -> Target {
        let settings = self.settings;
        let scope = match &settings.vlan_group {
            Some(group) => VlanScope::Group(group),
            None => VlanScope::Site(&settings.site),
        };
        let identity = Identity::vlan(scope, u64::from(vid));
        let object = self
            .new_object(Kind::Vlan, identity.clone())
            .field("vid", vid)
            .create_only("name", format!("VLAN{vid}"))
            .ensure_only();
        let object = match &settings.vlan_group {
            Some(group) => object.reference("group", Kind::VlanGroup, Identity::named(group)),
            None => self.with_site(object),
        };
        self.share(object);
        Target::new(Kind::Vlan, identity)
    }

    /// Sets the mode and the VLANs a network card gives its interface.
    fn with_dot1q(&mut self, interface: Desired, dot1q: &Dot1q) -> Desired {
        let (mode, untagged, tagged): (_, _, &[u16]) = match dot1q {
            Dot1q::Access(vid) => ("access", Some(*vid), &[]),
            Dot1q::Tagged { untagged, tagged } => ("tagged", *untagged, tagged),
            Dot1q::TaggedAll { untagged } => ("tagged-all", *untagged, &[]),
        };
        let mut interface = interface.field("mode", mode);
        // A port without untagged VLAN says so: the one NetBox has is cleared.
        interface = match untagged {
            Some(vid) => {
                let vlan = self.vlan(vid);
                interface.reference("untagged_vlan", Kind::Vlan, vlan.identity)
            }
            None => interface.no_reference("untagged_vlan"),
        };
        // Always said, empty included: NetBox refuses an access or tagged-all
        // port that keeps the tagged VLANs of the trunk it was.
        let vlans: Vec<Target> = tagged.iter().map(|vid| self.vlan(*vid)).collect();
        interface.reference_list("tagged_vlans", vlans)
    }

    /// Sets the tenant of the settings; without one nothing is said, and
    /// NetBox keeps the tenant it has.
    fn with_tenant(&self, object: Desired) -> Desired {
        match &self.settings.tenant {
            Some(tenant) => object.reference("tenant", Kind::Tenant, Identity::named(tenant)),
            None => object,
        }
    }

    fn with_source(&self, object: Desired) -> Desired {
        object.custom_field(&custom_fields::SOURCE, self.settings.source.as_str())
    }

    /// Declares the role of the settings, or the one netbox-ssot created
    /// itself, and returns its name.
    fn role(&mut self, configured: Option<&str>, default: &DefaultRole) -> String {
        let Some(name) = configured else {
            let mut role = self
                .new_object(Kind::Role, Identity::named(default.name))
                .field("name", default.name)
                .field("description", default.description)
                .create_only("slug", slugify(default.name))
                .create_only("color", default.color);
            if default.vm_role {
                role = role.field("vm_role", true);
            }
            self.share(role);
            return default.name.to_owned();
        };
        let role = self.existing(Kind::Role, name);
        self.share(role);
        name.to_owned()
    }

    /// The site, the tenant, the cluster type and the cluster.
    fn cluster(&mut self) {
        let settings = self.settings;
        let site = self.existing(Kind::Site, &settings.site);
        self.share(site);
        if let Some(tenant) = &settings.tenant {
            let tenant = self.existing(Kind::Tenant, tenant);
            self.share(tenant);
        }
        let cluster_type = self
            .new_object(Kind::ClusterType, Identity::named(CLUSTER_TYPE))
            .field("name", CLUSTER_TYPE)
            .create_only("slug", slugify(CLUSTER_TYPE));
        self.share(cluster_type);
        let cluster = self
            .new_object(Kind::Cluster, Identity::named(self.cluster))
            .field("name", self.cluster)
            .reference("type", Kind::ClusterType, Identity::named(CLUSTER_TYPE))
            .reference("scope", Kind::Site, Identity::named(&self.settings.site));
        let cluster = self.with_source(self.with_tenant(cluster));
        self.share(cluster);
    }

    fn platform(&self, name: &str) -> Desired {
        self.new_object(Kind::Platform, Identity::named(name)).field("name", name).create_only("slug", slugify(name))
    }

    /// The generic device type every host falls back on, with its manufacturer.
    fn generic_device_type(&mut self) -> Desired {
        let manufacturer = self
            .new_object(Kind::Manufacturer, Identity::named(GENERIC_MANUFACTURER))
            .field("name", GENERIC_MANUFACTURER)
            .field("description", GENERIC_MANUFACTURER_DESCRIPTION)
            .create_only("slug", slugify(GENERIC_MANUFACTURER));
        self.share(manufacturer);
        // The slug is the one of both names glued: netbox-ssot put no separator.
        let device_type = self
            .new_object(Kind::DeviceType, Identity::device_type(GENERIC_MANUFACTURER, GENERIC_MODEL))
            .field("model", GENERIC_MODEL)
            .field("description", GENERIC_MODEL_DESCRIPTION)
            .create_only("slug", slugify(&format!("{GENERIC_MANUFACTURER}{GENERIC_MODEL}")))
            .reference("manufacturer", Kind::Manufacturer, Identity::named(GENERIC_MANUFACTURER));
        self.share(device_type.clone());
        device_type
    }

    /// A node as a device, with its interfaces; returns the name of the device.
    fn host(&mut self, node: &Node) -> String {
        let full_name = format!("{}{}", node.name, self.settings.domain);
        let name = truncate(&full_name);
        if name.len() < full_name.len() {
            self.warnings
                .push(format!("device name {full_name} is too long, truncated to {MAX_NAME_LENGTH} characters"));
        }
        let settings = self.settings;
        let role = self.role(settings.host_role.as_deref(), &SERVER_ROLE);
        let device_type = self.generic_device_type();
        let device = self
            .new_object(Kind::Device, Identity::device(name))
            .field("name", name)
            .reference("role", Kind::Role, Identity::named(&role))
            .reference("cluster", Kind::Cluster, Identity::named(self.cluster))
            .custom_field(&custom_fields::HOST_CPU_CORES, node.cpus.to_string())
            .custom_field(&custom_fields::HOST_MEMORY, format!("{} GiB", node.memory_total_bytes / GIB));
        let device = self.with_source(self.with_tenant(self.with_site(device)));
        let device = self.reference_when_unset(device, "device_type", device_type);
        self.objects.push(device);
        self.host_interfaces(node, name);
        name.to_owned()
    }

    fn host_interfaces(&mut self, node: &Node, host: &str) {
        let is_bond = |kind: &str| node_interface_type(kind) == Some("lag");
        // The bond each member belongs to; a bond that is filtered out is not
        // synced, and the LAG of its members is then left as NetBox has it.
        let mut bond_of: BTreeMap<&str, Option<&str>> = BTreeMap::new();
        for bond in node.networks.iter().filter(|network| is_bond(&network.kind)) {
            let synced = (!self.settings.filters(&bond.name)).then_some(truncate(&bond.name));
            for member in &bond.bond_members {
                bond_of.insert(member.as_str(), synced);
            }
        }
        for network in &node.networks {
            if self.settings.filters(&network.name) {
                continue;
            }
            let name = truncate(&network.name);
            let mut interface = self
                .new_object(Kind::Interface, Identity::interface(host, name))
                .field("name", name)
                .field("enabled", network.active)
                .reference("device", Kind::Device, Identity::device(host));
            interface = match node_interface_type(&network.kind) {
                Some(kind) => interface.field("type", kind),
                // The type of a physical NIC is better known to whoever set
                // it in NetBox: `other` only fills a new interface.
                None => interface.create_only("type", "other"),
            };
            // An interface in no bond says nothing of its LAG: netbox-ssot
            // only detached it from a bond it had synced itself, and kept a
            // LAG set by hand, which the inventory model cannot tell apart.
            if let Some(Some(bond)) = bond_of.get(network.name.as_str()) {
                interface = interface.reference("lag", Kind::Interface, Identity::interface(host, bond));
            }
            // A VLAN sub-interface (`bond2.25`) is an access port of its VLAN,
            // under the interface that carries it when that one is synced.
            if let Some(vlan) = &network.vlan {
                interface = self.with_dot1q(interface, &Dot1q::Access(vlan.id));
                let synced =
                    |raw: &&str| !self.settings.filters(raw) && node.networks.iter().any(|other| other.name == **raw);
                if let Some(raw) = vlan.raw_device.as_deref().filter(synced) {
                    interface =
                        interface.reference("parent", Kind::Interface, Identity::interface(host, truncate(raw)));
                }
            }
            let interface = self.with_source(interface);
            self.objects.push(interface);
        }
    }

    /// What a VM and a container have in common as NetBox virtual machines.
    fn guest_object(&self, identity: &Identity, name: &str, status: &str, cpus: u64, memory_bytes: u64) -> Desired {
        let mut guest = self
            .new_object(Kind::VirtualMachine, identity.clone())
            .field("name", name)
            .field("status", guest_status(status))
            .reference("cluster", Kind::Cluster, Identity::named(self.cluster));
        // A zero was never sent by netbox-ssot: NetBox keeps what it has.
        if cpus > 0 {
            guest = guest.field("vcpus", cpus);
        }
        if memory_bytes / MIB > 0 {
            guest = guest.field("memory", memory_bytes / MIB);
        }
        self.with_tenant(self.with_site(guest))
    }

    /// Reports the tags of a guest and declares each of them: a tag only has
    /// to exist, the colour and description chosen in NetBox are kept. One
    /// this tool creates carries the marker of a tag made from a source, so
    /// that it leaves a guest once Proxmox no longer tags it.
    fn with_tags(&mut self, guest: Desired, tags: &[String]) -> Desired {
        for tag in tags {
            let tag = self
                .existing(Kind::Tag, tag)
                .create_only("color", GUEST_TAG_COLOR)
                .create_only("description", TAG_MARKER);
            self.share(tag);
        }
        guest.tags(tags.iter().cloned())
    }

    fn vm(&mut self, vm: &Vm, host: &str) {
        let name = truncate(&vm.name);
        let identity = Identity::virtual_machine(name, self.cluster);
        let settings = self.settings;
        let role = self.role(settings.vm_role.as_deref(), &VM_ROLE);
        let mut object = self
            .guest_object(&identity, name, &vm.status, vm.cpus, vm.max_memory_bytes)
            .reference("device", Kind::Device, Identity::device(host))
            .reference("role", Kind::Role, Identity::named(&role))
            .custom_field(&custom_fields::SOURCE_ID, vm.vmid.to_string());
        object = self.with_source(object);
        object = self.with_tags(object, &vm.tags);

        let reported = vm.os_info.as_ref().and_then(|os| os.pretty_name.as_deref()).filter(|name| !name.is_empty());
        object = match reported {
            Some(name) => {
                let platform = self.platform(name);
                self.share(platform);
                object.reference("platform", Kind::Platform, Identity::named(name))
            }
            // The agent says nothing: the platform NetBox has is kept, and
            // only a VM without one gets the name derived from its `ostype`.
            None => {
                let fallback = self.platform(ostype_platform_name(vm.os_type.as_deref()));
                self.reference_when_unset(object, "platform", fallback)
            }
        };

        let interfaces = vm.interfaces.as_ref().map(|interfaces| interfaces.iter().map(agent_interface).collect());
        let guest = Guest { sort: "vm", name: &vm.name, identity, interfaces, nics: Some(&vm.nics) };
        self.guest(object, &guest);
        self.disks(&guest, &vm.disks);
    }

    fn container(&mut self, container: &Container, host: &str) {
        let name = truncate(&container.name);
        let identity = Identity::virtual_machine(name, self.cluster);
        let role = self.role(None, &CONTAINER_ROLE);
        let mut object = self
            .guest_object(&identity, name, &container.status, container.cpus, container.max_memory_bytes)
            .reference("device", Kind::Device, Identity::device(host))
            .reference("role", Kind::Role, Identity::named(&role))
            .custom_field(&custom_fields::SOURCE_ID, container.vmid.to_string());
        if container.max_disk_bytes / MIB > 0 {
            object = object.field("disk", container.max_disk_bytes / MIB);
        }
        object = self.with_source(object);
        object = self.with_tags(object, &container.tags);
        let interfaces =
            container.interfaces.as_ref().map(|interfaces| interfaces.iter().map(container_interface).collect());
        let guest =
            Guest { sort: "container", name: &container.name, identity, interfaces, nics: container.nics.as_ref() };
        self.guest(object, &guest);
    }

    /// Declares a guest with its interfaces, their MAC and IP addresses, the
    /// prefixes of those and its primary addresses.
    fn guest(&mut self, object: Desired, guest: &Guest<'_>) {
        let Some(interfaces) = &guest.interfaces else {
            // Unknown is not empty: what NetBox has under this guest is kept.
            self.objects.push(object.unknown_dependents([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]));
            return;
        };
        // A card that could not be read says nothing: unknown is not "no VLAN".
        if let Some(unread) = guest.nics.map(|nics| &nics.unread).filter(|unread| !unread.is_empty()) {
            self.warnings.push(format!(
                "{} {}: {} could not be read; the VLAN of its interfaces is left as NetBox has it",
                guest.sort,
                guest.name,
                unread.join(", ")
            ));
        }
        let mut network = GuestNetwork::default();
        for interface in interfaces {
            self.guest_interface(guest, interface, &mut network);
        }
        let mut object = object;
        // The first address of each family that reaches the guest, in the order they were listed.
        for (field, primary) in [("primary_ip4", &network.first_ipv4), ("primary_ip6", &network.first_ipv6)] {
            if let Some(primary) = primary {
                object = object.reference(field, Kind::IpAddress, primary.clone());
            }
        }
        self.objects.push(object);
        for (_, interface) in network.interfaces {
            self.objects.push(interface);
        }
        self.objects.extend(network.addresses);
        for prefix in network.prefixes {
            self.share(prefix);
        }
    }

    fn guest_interface(&mut self, guest: &Guest<'_>, interface: &RawInterface<'_>, network: &mut GuestNetwork) {
        let who = format!("{} {}", guest.sort, guest.name);
        if interface.name.is_empty() {
            self.warnings.push(format!("{who}: an interface without name is skipped"));
            return;
        }
        if self.settings.filters(interface.name) {
            return;
        }
        let name = truncate(interface.name);
        let identity = Identity::vm_interface(&guest.identity, name);
        let target = Target::new(Kind::VmInterface, identity.clone());
        let at = match network.interfaces.iter().position(|(known, _)| known == name) {
            Some(at) => at,
            None => {
                let object = self.new_object(Kind::VmInterface, identity.clone()).field("name", name).reference(
                    "virtual_machine",
                    Kind::VirtualMachine,
                    guest.identity.clone(),
                );
                network.interfaces.push((name.to_owned(), self.with_source(object)));
                network.interfaces.len() - 1
            }
        };
        if let Some(mac) = interface.mac.map(str::to_uppercase).filter(|mac| !mac.is_empty()) {
            let mac_identity = Identity::mac_address(&mac, Some(&target));
            if network.macs.insert(mac_identity.key().to_vec()) {
                let object = self
                    .new_object(Kind::MacAddress, mac_identity.clone())
                    .field("mac_address", mac.as_str())
                    .reference("assigned_object", Kind::VmInterface, identity.clone());
                network.addresses.push(object);
            }
            // The last MAC listed for an interface is its primary one, as in netbox-ssot.
            let (_, object) = &mut network.interfaces[at];
            *object = object.clone().reference("primary_mac_address", Kind::MacAddress, mac_identity);
            // The card of the configuration that has this address says the
            // VLAN of the interface, and of every interface that shares the
            // address (a bond inside the guest and its members).
            let card = guest.nics.and_then(|nics| nics.read.iter().find(|nic| nic.mac == mac));
            match card.map(|card| (card, dot1q(card))) {
                Some((_, Ok(Some(dot1q)))) => {
                    let (_, object) = &mut network.interfaces[at];
                    *object = self.with_dot1q(object.clone(), &dot1q);
                }
                // Told once per card, whatever number of interfaces share its address.
                Some((card, Err(count))) if network.wide_trunks.insert(card.key.clone()) => {
                    self.warnings.push(format!(
                        "{who}: {} carries {count} VLANs, more than {MAX_TRUNK_VLANS}; the VLANs of its interfaces \
                         are left as NetBox has them",
                        card.key
                    ));
                }
                _ => {}
            }
        }
        for address in &interface.addresses {
            self.guest_address(&who, name, &identity, address, network);
        }
    }

    fn guest_address(
        &mut self,
        who: &str,
        interface: &str,
        interface_identity: &Identity,
        address: &RawAddress<'_>,
        network: &mut GuestNetwork,
    ) {
        // `fe80::1%eth0` is the address `fe80::1`.
        let host = address.host.split('%').next().unwrap_or(address.host);
        let parsed = host.parse::<IpAddr>().ok().and_then(|ip| {
            let full = if ip.is_ipv4() { 32 } else { 128 };
            let length = match &address.prefix {
                Some(prefix) => prefix.parse::<u8>().ok()?,
                None => full,
            };
            Some((ip, IpNet::new(ip, length).ok()?, length == full))
        });
        let Some((ip, masked, is_host)) = parsed else {
            let written = address.prefix.as_ref().map_or_else(|| host.to_owned(), |prefix| format!("{host}/{prefix}"));
            self.warnings.push(format!("{who}: {written} on {interface} is not an IP address; skipped"));
            return;
        };
        if !self.settings.permits(ip) {
            return;
        }
        if !network.hosts.insert(ip) {
            self.warnings.push(format!("{who}: {ip} is listed twice; the one on {interface} is skipped"));
            return;
        }
        let text = masked.to_string();
        // The source knows no VRF: the address is looked up in every table.
        let identity = Identity::ip_address(&text, VrfKey::Unknown);
        let mut object = self
            .new_object(Kind::IpAddress, identity.clone())
            .field("address", text.as_str())
            .field("status", "active")
            .reference("assigned_object", Kind::VmInterface, interface_identity.clone())
            .custom_field(&custom_fields::ARP_ENTRY, false);
        // A lookup that gives nothing, or a name NetBox would refuse, writes no name: NetBox keeps the one it has.
        if let Some(dns_name) = self.names.of(ip) {
            object = object.field("dns_name", dns_name);
        }
        let object = self.with_source(self.with_tenant(object));
        network.addresses.push(object);
        // A link-local, loopback or unspecified address is the same on every
        // machine, or reaches none: it is synced, but never the primary one.
        let reachable = omnisync_core::inventory::dns::is_looked_up(ip);
        match address.family {
            IPV4 => {
                if reachable {
                    network.first_ipv4.get_or_insert(identity);
                }
            }
            IPV6 => {
                if reachable {
                    network.first_ipv6.get_or_insert(identity);
                }
            }
            other => {
                self.warnings.push(format!("{who}: wrong IP type: {other} for ip {ip}"));
                return;
            }
        }
        // The network of a host address is the address itself: no prefix.
        if address.with_prefix && !is_host {
            let prefix = masked.trunc().to_string();
            let object = self
                .new_object(Kind::Prefix, Identity::prefix(&prefix, VrfKey::Unknown))
                .field("prefix", prefix.as_str())
                .ensure_only();
            network.prefixes.push(self.with_source(object));
        }
    }

    /// The virtual disks of a VM. A CD-ROM drive that has a size (an ISO
    /// image, a cloud-init drive) is one, as it was for netbox-ssot.
    fn disks(&mut self, guest: &Guest<'_>, disks: &[Disk]) {
        let mut seen = BTreeSet::new();
        for disk in disks {
            let name = truncate(&disk.name);
            if !seen.insert(name) {
                self.warnings.push(format!(
                    "{} {}: disk {name} is listed twice; the second one is skipped",
                    guest.sort, guest.name
                ));
                continue;
            }
            let object = self
                .new_object(Kind::VirtualDisk, Identity::virtual_disk(&guest.identity, name))
                .field("name", name)
                .field("size", disk.size_mib)
                .field("description", disk.name.as_str())
                .reference("virtual_machine", Kind::VirtualMachine, guest.identity.clone());
            let object = self.with_source(object);
            self.objects.push(object);
        }
    }
}

/// The network objects of one guest, as they are gathered.
#[derive(Default)]
struct GuestNetwork {
    /// The interfaces by name, in the order they were listed.
    interfaces: Vec<(String, Desired)>,
    /// MAC and IP addresses, in the order they were listed.
    addresses: Vec<Desired>,
    prefixes: Vec<Desired>,
    /// The MAC addresses already declared, by identity.
    macs: BTreeSet<Vec<String>>,
    /// The hosts already declared: NetBox identifies an address by its host,
    /// so the same one on two interfaces of a guest is one object.
    hosts: BTreeSet<IpAddr>,
    first_ipv4: Option<Identity>,
    first_ipv6: Option<Identity>,
    /// The cards whose trunk was too wide to list, already told.
    wide_trunks: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    //! Every expected value below comes from the Go source of netbox-ssot at
    //! commit `604930e` (the line is quoted above the assertion) or from the
    //! requirements of the port; none was copied from what the code returns.

    use std::collections::{BTreeMap, BTreeSet};

    use omnisync_core::inventory::model::{Identity, Kind, VlanScope, VrfKey};
    use serde_json::json;

    use super::*;
    use crate::model::{
        Container, ContainerInterface, Disk, DiskBus, GuestAddress, GuestInterface, GuestNic, GuestNics, GuestOsInfo,
        Node, NodeNetwork, NodeVlan, ProxmoxVersion, Vm,
    };

    const SOURCE: &str = "pve-lab";
    const SITE: &str = "Harbor";
    const CLUSTER: &str = "pve-cluster";

    fn settings() -> Settings {
        Settings::new(SOURCE, SITE)
    }

    /// The filter and the subnets of production.
    fn production() -> Settings {
        Settings {
            ignored_subnets: Settings::subnets(&["::/0"]).unwrap(),
            interface_filter: Settings::interface_filter("veth|docker|br-|isatap|vEthernet|Loopback").unwrap(),
            ..settings()
        }
    }

    fn cluster(nodes: Vec<Node>) -> ProxmoxCluster {
        ProxmoxCluster {
            version: ProxmoxVersion { version: "8.4.21".to_owned(), release: "8.4".to_owned() },
            name: CLUSTER.to_owned(),
            nodes,
            offline: Vec::new(),
        }
    }

    /// 32 CPUs and 236538687488 bytes, as the first node of the 8.4 fixture.
    fn node(name: &str) -> Node {
        Node {
            name: name.to_owned(),
            cpus: 32,
            memory_total_bytes: 236_538_687_488,
            networks: vec![],
            vms: vec![],
            containers: vec![],
        }
    }

    fn network(name: &str, kind: &str) -> NodeNetwork {
        NodeNetwork { name: name.to_owned(), kind: kind.to_owned(), active: true, bond_members: vec![], vlan: None }
    }

    fn bond(name: &str, kind: &str, members: &[&str]) -> NodeNetwork {
        NodeNetwork { bond_members: members.iter().map(|member| (*member).to_owned()).collect(), ..network(name, kind) }
    }

    /// A running VM with 2 CPUs and 2 GiB whose agent lists no interface and
    /// does not tell its system.
    fn vm(vmid: u64, name: &str) -> Vm {
        Vm {
            vmid,
            name: name.to_owned(),
            status: "running".to_owned(),
            template: false,
            cpus: 2,
            max_memory_bytes: 2_147_483_648,
            tags: vec![],
            os_type: Some("l26".to_owned()),
            disks: vec![],
            nics: GuestNics::default(),
            interfaces: Some(vec![]),
            os_info: None,
        }
    }

    fn nic(name: &str, mac: &str, addresses: &[(&str, &str, u8)]) -> GuestInterface {
        let addresses = addresses
            .iter()
            .map(|(address, family, prefix)| GuestAddress {
                address: (*address).to_owned(),
                family: (*family).to_owned(),
                prefix: *prefix,
            })
            .collect();
        GuestInterface { name: name.to_owned(), mac: Some(mac.to_owned()).filter(|mac| !mac.is_empty()), addresses }
    }

    fn with_nics(vmid: u64, name: &str, nics: Vec<GuestInterface>) -> Vm {
        Vm { interfaces: Some(nics), ..vm(vmid, name) }
    }

    /// A running container with 1 CPU, 512 MiB of memory and a root disk of 8 GiB.
    fn container(vmid: u64, name: &str) -> Container {
        Container {
            vmid,
            name: name.to_owned(),
            status: "running".to_owned(),
            cpus: 1,
            max_memory_bytes: 536_870_912,
            max_disk_bytes: 8_589_934_592,
            tags: vec![],
            interfaces: Some(vec![]),
            nics: Some(GuestNics::default()),
        }
    }

    /// A card of the configuration on `vmbr0`.
    fn card(key: &str, mac: &str, tag: Option<u16>, trunks: &[(u16, u16)]) -> GuestNic {
        GuestNic {
            key: key.to_owned(),
            mac: mac.to_owned(),
            bridge: Some("vmbr0".to_owned()),
            tag,
            trunks: trunks.to_vec(),
        }
    }

    fn cards(read: Vec<GuestNic>) -> GuestNics {
        GuestNics { read, unread: vec![] }
    }

    fn site_vlan(vid: u64) -> Identity {
        Identity::vlan(VlanScope::Site(SITE), vid)
    }

    fn untagged(interface: &Desired) -> Option<Identity> {
        interface.references.get("untagged_vlan").cloned().flatten().map(|target| target.identity)
    }

    fn tagged(interface: &Desired) -> Option<Vec<String>> {
        let vlans = interface.reference_lists.get("tagged_vlans")?;
        Some(vlans.iter().map(|vlan| vlan.identity.label().to_owned()).collect())
    }

    #[test]
    fn the_tag_of_a_card_puts_the_interface_that_has_its_address_in_that_vlan() {
        // The agent writes the address in lower case, the configuration in upper case.
        let nics = vec![nic("eth0", "bc:24:11:00:00:01", &[]), nic("eth1", "bc:24:11:00:00:02", &[])];
        let vm =
            Vm { nics: cards(vec![card("net0", "BC:24:11:00:00:01", Some(10), &[])]), ..with_nics(101, "web01", nics) };
        let objects = objects(&host_of(vec![vm]), &settings());
        let eth0 = one(&objects, Kind::VmInterface, &nic_identity("web01", "eth0"));
        assert_eq!(eth0.fields["mode"], json!("access"));
        assert_eq!(untagged(&eth0), Some(site_vlan(10)));
        assert_eq!(tagged(&eth0), Some(vec![]));
        // No card of the configuration has the address of eth1: nothing is said of its VLAN.
        let eth1 = one(&objects, Kind::VmInterface, &nic_identity("web01", "eth1"));
        assert!(!eth1.fields.contains_key("mode") && !eth1.references.contains_key("untagged_vlan"));
        // The VLAN only has to exist at the site of the cluster: one NetBox
        // lacks is created under the name `VLAN<id>`, Proxmox naming none.
        assert_eq!(
            of_kind(&objects, Kind::Vlan),
            [&site_reference(
                Desired::new(Kind::Vlan, site_vlan(10), SOURCE)
                    .field("vid", 10)
                    .create_only("name", "VLAN10")
                    .ensure_only()
            )]
        );
    }

    // NetBox refuses an access or tagged-all port that keeps tagged VLANs
    // (dcim InterfaceSerializer.validate, NetBox 4.5.10 and 4.7.5): a port that is not
    // tagged says it carries none, so that a trunk turned access is written.
    #[test]
    fn a_port_that_is_not_tagged_says_it_carries_no_tagged_vlan() {
        let nics = vec![nic("eth0", "bc:24:11:00:00:01", &[]), nic("eth1", "bc:24:11:00:00:02", &[])];
        let configured = cards(vec![
            card("net0", "BC:24:11:00:00:01", Some(10), &[]),
            card("net1", "BC:24:11:00:00:02", None, &[(1, 4094)]),
        ]);
        let sub = NodeNetwork { vlan: Some(NodeVlan { id: 25, raw_device: None }), ..network("bond2.25", "vlan") };
        let vm = Vm { nics: configured, ..with_nics(101, "web01", nics) };
        let objects =
            objects(&cluster(vec![Node { networks: vec![sub], vms: vec![vm], ..node("pve01") }]), &settings());
        for port in [
            one(&objects, Kind::VmInterface, &nic_identity("web01", "eth0")),
            one(&objects, Kind::VmInterface, &nic_identity("web01", "eth1")),
            one(&objects, Kind::Interface, &Identity::interface("pve01", "bond2.25")),
        ] {
            assert_eq!(tagged(&port), Some(vec![]), "{:?}", port.identity.label());
        }
    }

    // A trunk without `tag` has no untagged VLAN: the one NetBox has is cleared.
    #[test]
    fn a_trunk_without_tag_has_no_untagged_vlan() {
        let nics = vec![nic("eth0", "bc:24:11:00:00:01", &[]), nic("eth1", "bc:24:11:00:00:02", &[])];
        let configured = cards(vec![
            card("net0", "BC:24:11:00:00:01", None, &[(20, 21)]),
            card("net1", "BC:24:11:00:00:02", None, &[(1, 4094)]),
        ]);
        let objects = objects(&host_of(vec![Vm { nics: configured, ..with_nics(101, "web01", nics) }]), &settings());
        for name in ["eth0", "eth1"] {
            let port = one(&objects, Kind::VmInterface, &nic_identity("web01", name));
            assert_eq!(port.references.get("untagged_vlan"), Some(&None), "{name}");
        }
    }

    // `trunks=2-4000` would create 3999 VLANs: past 64 the card is a warning,
    // its interfaces keep what NetBox has, and no VLAN is declared for it.
    #[test]
    fn a_trunk_of_more_than_64_vlans_is_a_warning_and_leaves_its_interfaces_as_they_are() {
        let mac = "bc:24:11:00:00:01";
        let nics = vec![nic("bond0", mac, &[]), nic("eth0", mac, &[])];
        let configured = cards(vec![card("net0", "BC:24:11:00:00:01", Some(5), &[(2, 4000)])]);
        let translation =
            translate(&host_of(vec![Vm { nics: configured, ..with_nics(101, "web01", nics) }]), &settings());
        assert_eq!(
            translation.warnings,
            [
                "vm web01: net0 carries 3999 VLANs, more than 64; the VLANs of its interfaces are left as NetBox has them"
            ]
        );
        for name in ["bond0", "eth0"] {
            let port = one(&translation.objects, Kind::VmInterface, &nic_identity("web01", name));
            assert!(!port.fields.contains_key("mode") && !port.references.contains_key("untagged_vlan"), "{name}");
            assert!(!port.reference_lists.contains_key("tagged_vlans"), "{name}");
        }
        assert_eq!(labels(&translation.objects, Kind::Vlan), Vec::<String>::new());
        // 64 VLANs are still listed.
        let nics = vec![nic("eth0", mac, &[])];
        let configured = cards(vec![card("net0", "BC:24:11:00:00:01", None, &[(100, 163)])]);
        let objects = objects(&host_of(vec![Vm { nics: configured, ..with_nics(101, "web01", nics) }]), &settings());
        assert_eq!(
            tagged(&one(&objects, Kind::VmInterface, &nic_identity("web01", "eth0"))).map(|vlans| vlans.len()),
            Some(64)
        );
    }

    #[test]
    fn the_vlans_of_a_site_that_is_in_a_vlan_group_are_declared_in_the_group_and_at_no_site() {
        let grouped = Settings { vlan_group: Some("East".to_owned()), ..settings() };
        let nics = vec![nic("eth0", "bc:24:11:00:00:01", &[])];
        let vm =
            Vm { nics: cards(vec![card("net0", "BC:24:11:00:00:01", Some(10), &[])]), ..with_nics(101, "web01", nics) };
        let sub = NodeNetwork { vlan: Some(NodeVlan { id: 25, raw_device: None }), ..network("bond2.25", "vlan") };
        let objects = objects(&cluster(vec![Node { networks: vec![sub], vms: vec![vm], ..node("pve01") }]), &grouped);
        let in_group = |vid: u64| Identity::vlan(VlanScope::Group("East"), vid);
        assert_eq!(untagged(&one(&objects, Kind::VmInterface, &nic_identity("web01", "eth0"))), Some(in_group(10)));
        assert_eq!(
            untagged(&one(&objects, Kind::Interface, &Identity::interface("pve01", "bond2.25"))),
            Some(in_group(25))
        );
        // A VLAN several sites share has no site: NetBox would refuse it on an interface of another one.
        assert_eq!(
            one(&objects, Kind::Vlan, &in_group(10)),
            Desired::new(Kind::Vlan, in_group(10), SOURCE)
                .field("vid", 10)
                .create_only("name", "VLAN10")
                .ensure_only()
                .reference("group", Kind::VlanGroup, Identity::named("East"))
        );
        // The group is a prerequisite, as the custom fields are: it is referred to, never declared, so never created.
        assert_eq!(labels(&objects, Kind::VlanGroup), Vec::<String>::new());
        // The hosts and the guests stay at their site.
        assert_eq!(guest(&objects, "web01").references["site"].as_ref().unwrap().identity, Identity::named(SITE));
    }

    #[test]
    fn every_interface_that_has_the_address_of_a_card_is_in_its_vlan() {
        // A bond inside the guest and its members share the address of the card.
        let mac = "bc:24:11:00:00:01";
        let nics = vec![nic("bond0", mac, &[]), nic("eth0", mac, &[]), nic("eth1", "bc:24:11:00:00:09", &[])];
        let vm =
            Vm { nics: cards(vec![card("net0", "BC:24:11:00:00:01", Some(11), &[])]), ..with_nics(101, "web01", nics) };
        let objects = objects(&host_of(vec![vm]), &settings());
        for name in ["bond0", "eth0"] {
            let interface = one(&objects, Kind::VmInterface, &nic_identity("web01", name));
            assert_eq!(
                (interface.fields.get("mode"), untagged(&interface)),
                (Some(&json!("access")), Some(site_vlan(11)))
            );
        }
        assert_eq!(untagged(&one(&objects, Kind::VmInterface, &nic_identity("web01", "eth1"))), None);
        assert_eq!(labels(&objects, Kind::Vlan), ["11"]);
    }

    #[test]
    fn the_trunks_of_a_card_make_a_tagged_port_of_its_interface() {
        let nics = vec![
            nic("eth0", "bc:24:11:00:00:01", &[]),
            nic("eth1", "bc:24:11:00:00:02", &[]),
            nic("eth2", "bc:24:11:00:00:03", &[]),
        ];
        let configured = cards(vec![
            card("net0", "BC:24:11:00:00:01", None, &[(10, 10), (20, 22)]),
            // The tag of a trunk is its untagged VLAN, which is not listed twice.
            card("net1", "BC:24:11:00:00:02", Some(5), &[(5, 5), (30, 30)]),
            // Every VLAN: none is listed, and none is created for it.
            card("net2", "BC:24:11:00:00:03", None, &[(1, 4094)]),
        ]);
        let objects = objects(&host_of(vec![Vm { nics: configured, ..with_nics(101, "web01", nics) }]), &settings());
        let eth0 = one(&objects, Kind::VmInterface, &nic_identity("web01", "eth0"));
        assert_eq!(eth0.fields["mode"], json!("tagged"));
        assert_eq!(tagged(&eth0), Some(vec!["10".to_owned(), "20".to_owned(), "21".to_owned(), "22".to_owned()]));
        assert_eq!(untagged(&eth0), None);
        let eth1 = one(&objects, Kind::VmInterface, &nic_identity("web01", "eth1"));
        assert_eq!(eth1.fields["mode"], json!("tagged"));
        assert_eq!(untagged(&eth1), Some(site_vlan(5)));
        assert_eq!(tagged(&eth1), Some(vec!["30".to_owned()]));
        let eth2 = one(&objects, Kind::VmInterface, &nic_identity("web01", "eth2"));
        assert_eq!(eth2.fields["mode"], json!("tagged-all"));
        assert_eq!((untagged(&eth2), tagged(&eth2)), (None, Some(vec![])));
        let mut vlans = labels(&objects, Kind::Vlan);
        vlans.sort_by_key(|label| label.parse::<u16>().unwrap());
        assert_eq!(vlans, ["5", "10", "20", "21", "22", "30"]);
    }

    #[test]
    fn a_card_without_tag_nor_trunks_says_nothing_of_the_vlan_of_its_interface() {
        let nics = vec![nic("eth0", "bc:24:11:00:00:01", &[])];
        let vm =
            Vm { nics: cards(vec![card("net0", "BC:24:11:00:00:01", None, &[])]), ..with_nics(101, "web01", nics) };
        let objects = objects(&host_of(vec![vm]), &settings());
        let eth0 = one(&objects, Kind::VmInterface, &nic_identity("web01", "eth0"));
        assert!(!eth0.fields.contains_key("mode"));
        assert!(!eth0.references.contains_key("untagged_vlan") && !eth0.reference_lists.contains_key("tagged_vlans"));
        assert_eq!(labels(&objects, Kind::Vlan), Vec::<String>::new());
    }

    #[test]
    fn a_card_that_could_not_be_read_is_a_warning_naming_the_guest_and_says_nothing() {
        let nics = vec![nic("eth0", "bc:24:11:00:00:01", &[])];
        let unread = GuestNics { read: vec![], unread: vec!["net0".to_owned(), "net3".to_owned()] };
        let translation = translate(&host_of(vec![Vm { nics: unread, ..with_nics(101, "web01", nics) }]), &settings());
        assert_eq!(
            translation.warnings,
            ["vm web01: net0, net3 could not be read; the VLAN of its interfaces is left as NetBox has it"]
        );
        let eth0 = one(&translation.objects, Kind::VmInterface, &nic_identity("web01", "eth0"));
        assert!(!eth0.fields.contains_key("mode") && !eth0.references.contains_key("untagged_vlan"));
    }

    #[test]
    fn the_tag_of_the_card_of_a_container_puts_its_interface_in_that_vlan() {
        let eth0 = ContainerInterface {
            name: "eth0".to_owned(),
            mac: Some("bc:24:11:00:00:01".to_owned()),
            inet: None,
            inet6: None,
        };
        let web = Container {
            interfaces: Some(vec![eth0]),
            nics: Some(cards(vec![card("net0", "BC:24:11:00:00:01", Some(30), &[])])),
            ..container(200, "ct-web")
        };
        let objects = objects(&cluster(vec![Node { containers: vec![web], ..node("pve01") }]), &settings());
        let eth0 = one(&objects, Kind::VmInterface, &nic_identity("ct-web", "eth0"));
        assert_eq!((eth0.fields.get("mode"), untagged(&eth0)), (Some(&json!("access")), Some(site_vlan(30))));
        // A configuration that could not be read: nothing is said, and nothing is warned about.
        let eth0 = ContainerInterface { name: "eth0".to_owned(), mac: None, inet: None, inet6: None };
        let unknown = Container { interfaces: Some(vec![eth0]), nics: None, ..container(200, "ct-web") };
        let translation = translate(&cluster(vec![Node { containers: vec![unknown], ..node("pve01") }]), &settings());
        assert_eq!(translation.warnings, Vec::<String>::new());
        assert_eq!(labels(&translation.objects, Kind::Vlan), Vec::<String>::new());
    }

    #[test]
    fn a_vlan_sub_interface_of_a_node_is_an_access_port_of_its_vlan_under_its_raw_device() {
        let sub = |name: &str, id: u16, raw: Option<&str>| NodeNetwork {
            vlan: Some(NodeVlan { id, raw_device: raw.map(str::to_owned) }),
            ..network(name, "vlan")
        };
        let networks = vec![
            bond("bond2", "bond", &["eno3", "eno4"]),
            sub("bond2.25", 25, Some("bond2")),
            // Its raw device is not an interface of the node: no parent is said.
            sub("vlan30", 30, Some("eno9")),
            sub("vlan31", 31, None),
            // A sub-interface whose VLAN id could not be read.
            network("bond2.x", "vlan"),
        ];
        let objects = objects(&cluster(vec![Node { networks, ..node("pve01") }]), &settings());
        let interface = |name: &str| one(&objects, Kind::Interface, &Identity::interface("pve01", name));
        let nfs = interface("bond2.25");
        assert_eq!(nfs.fields["type"], json!("virtual"));
        assert_eq!(nfs.fields["mode"], json!("access"));
        assert_eq!(untagged(&nfs), Some(site_vlan(25)));
        assert_eq!(
            nfs.references["parent"].as_ref().map(|parent| (parent.kind, parent.identity.clone())),
            Some((Kind::Interface, Identity::interface("pve01", "bond2")))
        );
        for (name, vid) in [("vlan30", 30), ("vlan31", 31)] {
            assert_eq!(untagged(&interface(name)), Some(site_vlan(vid)));
            assert!(!interface(name).references.contains_key("parent"), "{name}");
        }
        let unknown = interface("bond2.x");
        assert!(!unknown.fields.contains_key("mode") && !unknown.references.contains_key("untagged_vlan"));
        // A bond is in no VLAN.
        assert!(!interface("bond2").fields.contains_key("mode"));
        assert_eq!(labels(&objects, Kind::Vlan), ["25", "30", "31"]);
    }

    #[test]
    fn a_sub_interface_whose_raw_device_is_filtered_out_has_no_parent() {
        let networks = vec![
            bond("bond2", "bond", &[]),
            NodeNetwork {
                vlan: Some(NodeVlan { id: 25, raw_device: Some("bond2".to_owned()) }),
                ..network("vlan25", "vlan")
            },
        ];
        let filtered = Settings { interface_filter: Settings::interface_filter("^bond").unwrap(), ..settings() };
        let objects = objects(&cluster(vec![Node { networks, ..node("pve01") }]), &filtered);
        let sub = one(&objects, Kind::Interface, &Identity::interface("pve01", "vlan25"));
        assert_eq!(untagged(&sub), Some(site_vlan(25)));
        assert!(!sub.references.contains_key("parent"));
    }

    fn host_of(vms: Vec<Vm>) -> ProxmoxCluster {
        cluster(vec![Node { vms, ..node("pve01") }])
    }

    fn translate(cluster: &ProxmoxCluster, settings: &Settings) -> Translation {
        desired(cluster, settings, &NoReverseDns)
    }

    fn objects(cluster: &ProxmoxCluster, settings: &Settings) -> Vec<Desired> {
        translate(cluster, settings).objects
    }

    fn of_kind(objects: &[Desired], kind: Kind) -> Vec<&Desired> {
        objects.iter().filter(|object| object.kind == kind).collect()
    }

    fn labels(objects: &[Desired], kind: Kind) -> Vec<String> {
        of_kind(objects, kind).iter().map(|object| object.identity.label().to_owned()).collect()
    }

    /// The one object of that kind and identity.
    fn one(objects: &[Desired], kind: Kind, identity: &Identity) -> Desired {
        let found: Vec<&Desired> =
            objects.iter().filter(|object| object.kind == kind && &object.identity == identity).collect();
        assert_eq!(found.len(), 1, "{} object(s) of kind {kind:?} with identity {:?}", found.len(), identity.key());
        found[0].clone()
    }

    fn named(objects: &[Desired], kind: Kind, name: &str) -> Desired {
        one(objects, kind, &Identity::named(name))
    }

    fn vm_identity(name: &str) -> Identity {
        Identity::virtual_machine(name, CLUSTER)
    }

    fn guest(objects: &[Desired], name: &str) -> Desired {
        one(objects, Kind::VirtualMachine, &vm_identity(name))
    }

    fn nic_identity(vm: &str, name: &str) -> Identity {
        Identity::vm_interface(&vm_identity(vm), name)
    }

    fn address_identity(address: &str) -> Identity {
        Identity::ip_address(address, VrfKey::Unknown)
    }

    fn mac_identity(mac: &str, vm: &str, nic: &str) -> Identity {
        let target = omnisync_core::inventory::model::Target::new(Kind::VmInterface, nic_identity(vm, nic));
        Identity::mac_address(mac, Some(&target))
    }

    fn site_reference(object: Desired) -> Desired {
        object.reference("site", Kind::Site, Identity::named(SITE))
    }

    fn cluster_reference(object: Desired) -> Desired {
        object.reference("cluster", Kind::Cluster, Identity::named(CLUSTER))
    }

    /// The VM of `vm()` as netbox-ssot's defaults want it, platform apart.
    fn expected_vm(vmid: u64, name: &str) -> Desired {
        let object = Desired::new(Kind::VirtualMachine, vm_identity(name), SOURCE)
            .field("name", name)
            // proxmox_sync.go: vmStatus := &objects.VMStatusActive; virtualization.go: Choice{Value: "active"}
            .field("status", "active")
            // proxmox_sync.go: VCPUs: float32(vm.CPUs)
            .field("vcpus", 2)
            // proxmox_sync.go: Memory: int(vm.MaxMem / constants.MiB) — 2147483648 / 1048576 = 2048
            .field("memory", 2048)
            // proxmox_sync.go: Host: nbHost
            .reference("device", Kind::Device, Identity::device("pve01"))
            // add_predefined_items.go, AddVMDeviceRole: Name: constants.DeviceRoleVM — DeviceRoleVM = "VM"
            .reference("role", Kind::Role, Identity::named("VM"))
            // proxmox_sync.go: for _, tag := range splitProxmoxTags(vm.Tags) — none here.
            .tags(Vec::<String>::new())
            // proxmox_sync.go: constants.CustomFieldSourceName: ps.SourceConfig.Name — CustomFieldSourceName = "source"
            .custom_field(&custom_fields::SOURCE, SOURCE)
            // proxmox_sync.go: constants.CustomFieldSourceIDName: fmt.Sprintf("%d", vm.VMID) — "source_id"
            .custom_field(&custom_fields::SOURCE_ID, vmid.to_string())
            // proxmox_sync.go, vmPlatformName: the agent of `vm()` is silent, so the platform is the one of its
            // ostype — proxmoxOSTypePlatformNames: "l26": "Other 2.6.x Linux (64-bit)" — and only fills an
            // empty field: "the platform NetBox has is kept when an agent reported it".
            .reference("platform", Kind::Platform, Identity::named("Other 2.6.x Linux (64-bit)"))
            .only_when_empty("platform");
        cluster_reference(site_reference(object))
    }

    // -----------------------------------------------------------------------
    // Names, slugs and truncations
    // -----------------------------------------------------------------------

    #[test]
    fn a_slug_is_the_one_of_netbox_ssot() {
        // utils.go, Slugify: e.g. "My Name" -> "my-name"
        assert_eq!(slugify("My Name"), "my-name");
        // utils.go, Slugify: e.g. "  @Test@ " -> "test"
        assert_eq!(slugify("  @Test@ "), "test");
        // utils.go: reg := regexp.MustCompile("[^a-z0-9_-]+") — the slash, the dot and the brackets go.
        assert_eq!(slugify("Debian GNU/Linux 12 (bookworm)"), "debian-gnulinux-12-bookworm");
        assert_eq!(slugify("Ubuntu 24.04.3 LTS"), "ubuntu-24043-lts");
        // Underscores and hyphens stay; an inner space becomes a hyphen each.
        assert_eq!(slugify("service_a-b  c"), "service_a-b--c");
    }

    #[test]
    fn a_name_is_cut_at_64_bytes() {
        // constants.go: MaxVMNameLength = 64; get_items.go, TruncateVMName: return name[:constants.MaxVMNameLength]
        let long = "a".repeat(70);
        assert_eq!(truncate(&long), "a".repeat(64));
        let exact = "b".repeat(64);
        assert_eq!(truncate(&exact), exact);
        assert_eq!(truncate("web01"), "web01");
    }

    #[test]
    fn a_name_is_never_cut_inside_a_character() {
        // Go cuts at byte 64 whatever stands there, which leaves half a
        // character and a name NetBox refuses. 63 bytes then a two-byte "é":
        // the cut falls back to the 63 bytes before it.
        let name = format!("{}é", "a".repeat(63));
        assert_eq!(truncate(&name), "a".repeat(63));
    }

    // -----------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------

    #[test]
    fn the_default_settings_are_those_of_netbox_ssot() {
        let settings = Settings::new("pve-lab", "Harbor");
        assert_eq!(settings.source, "pve-lab");
        assert_eq!(settings.site, "Harbor");
        assert_eq!(settings.tenant, None);
        assert_eq!(settings.host_role, None);
        assert_eq!(settings.vm_role, None);
        assert_eq!(settings.domain, "");
        assert!(!settings.ignore_templates);
        assert!(settings.ignored_subnets.is_empty());
        assert!(settings.permitted_subnets.is_empty());
        assert!(settings.interface_filter.is_none());
    }

    #[test]
    fn subnets_are_parsed_or_refused_by_name() {
        let subnets = Settings::subnets(&["::/0", "10.0.0.0/8"]).unwrap();
        assert_eq!(subnets.iter().map(ToString::to_string).collect::<Vec<_>>(), ["::/0", "10.0.0.0/8"]);
        // networking.go, SubnetContainsIPAddress takes "172.31.4.145/25" for the subnet 172.31.4.128/25.
        assert_eq!(Settings::subnets(&["172.31.4.145/25"]).unwrap()[0].to_string(), "172.31.4.128/25");
        let error = Settings::subnets(&["10.0.0.0/8", "ten"]).unwrap_err();
        assert!(matches!(&error, SettingsError::Subnet { value, .. } if value == "ten"), "{error:?}");
        assert!(error.to_string().starts_with("\"ten\" is not a subnet: "), "{error}");
    }

    #[test]
    fn an_interface_filter_is_compiled_or_refused() {
        // utils.go, FilterInterfaceName: if ifaceFilter == "" { return false }
        assert!(Settings::interface_filter("").unwrap().is_none());
        let filter = Settings::interface_filter("veth|docker").unwrap().unwrap();
        assert!(filter.is_match("veth12ab"));
        assert!(!filter.is_match("eth0"));
        let error = Settings::interface_filter("veth(").unwrap_err();
        assert!(matches!(&error, SettingsError::InterfaceFilter { pattern, .. } if pattern == "veth("), "{error:?}");
    }

    // -----------------------------------------------------------------------
    // Cluster, site, tenant
    // -----------------------------------------------------------------------

    #[test]
    fn the_cluster_type_is_proxmox() {
        let objects = objects(&cluster(vec![node("pve01")]), &settings());
        // proxmox_sync.go, syncCluster: Name: "Proxmox", Slug: utils.Slugify("Proxmox")
        let expected = Desired::new(Kind::ClusterType, Identity::named("Proxmox"), SOURCE)
            .field("name", "Proxmox")
            .create_only("slug", "proxmox");
        assert_eq!(named(&objects, Kind::ClusterType, "Proxmox"), expected);
    }

    #[test]
    fn the_cluster_is_scoped_to_the_site() {
        let objects = objects(&cluster(vec![node("pve01")]), &settings());
        // proxmox_sync.go, syncCluster: Name: ps.Cluster.Name, Type: clusterType,
        //   ScopeType: constants.ContentTypeDcimSite, ScopeID: clusterSite.ID
        // add_items.go, AddCluster: addSourceNameCustomField(ctx, &newCluster.NetboxObject)
        let expected = Desired::new(Kind::Cluster, Identity::named(CLUSTER), SOURCE)
            .field("name", CLUSTER)
            .reference("type", Kind::ClusterType, Identity::named("Proxmox"))
            .reference("scope", Kind::Site, Identity::named(SITE))
            .custom_field(&custom_fields::SOURCE, SOURCE);
        assert_eq!(named(&objects, Kind::Cluster, CLUSTER), expected);
        assert_eq!(of_kind(&objects, Kind::Cluster).len(), 1);
    }

    #[test]
    fn the_cluster_of_a_standalone_node_is_named_after_the_source() {
        let standalone = ProxmoxCluster { name: String::new(), ..host_of(vec![vm(101, "web01")]) };
        let objects = objects(&standalone, &settings());
        // proxmox_sync.go: if ps.Cluster.Name == "" { ps.Cluster.Name = ps.SourceConfig.Name }
        assert_eq!(labels(&objects, Kind::Cluster), [SOURCE]);
        let host = one(&objects, Kind::Device, &Identity::device("pve01"));
        assert_eq!(host.references["cluster"].as_ref().unwrap().identity, Identity::named(SOURCE));
        // The virtual machine is identified in that cluster.
        let web = one(&objects, Kind::VirtualMachine, &Identity::virtual_machine("web01", SOURCE));
        assert_eq!(web.references["cluster"].as_ref().unwrap().identity, Identity::named(SOURCE));
    }

    #[test]
    fn the_site_only_has_to_exist() {
        let objects = objects(&cluster(vec![node("pve01")]), &settings());
        // utils.go (common), MatchClusterToSite: nbi.AddSite(ctx, &objects.Site{Name: siteName, Slug:
        //   utils.Slugify(siteName)})
        // when the site is missing, and the site as it is when NetBox has it.
        let expected = Desired::new(Kind::Site, Identity::named(SITE), SOURCE)
            .field("name", SITE)
            .create_only("slug", "harbor")
            .ensure_only();
        assert_eq!(named(&objects, Kind::Site, SITE), expected);
    }

    #[test]
    fn without_a_tenant_no_tenant_is_declared_nor_referred_to() {
        let objects = objects(
            &host_of(vec![with_nics(101, "web01", vec![nic("eth0", "", &[("10.0.0.5", "ipv4", 24)])])]),
            &settings(),
        );
        assert_eq!(of_kind(&objects, Kind::Tenant).len(), 0);
        // utils.go (common), MatchClusterToTenant: if clusterTenantRelations == nil { return nil, nil }: a nil
        // tenant is left out of the request, and NetBox keeps the one it has.
        assert!(objects.iter().all(|object| !object.references.contains_key("tenant")));
    }

    #[test]
    fn the_tenant_only_has_to_exist_and_is_set_on_cluster_hosts_guests_and_addresses() {
        let with_tenant = Settings { tenant: Some("Acme Corp".to_owned()), ..settings() };
        let ct = Container {
            interfaces: Some(vec![ContainerInterface {
                name: "eth0".to_owned(),
                mac: None,
                inet: Some("192.0.2.10/24".to_owned()),
                inet6: None,
            }]),
            ..container(200, "ct01")
        };
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("10.0.0.5", "ipv4", 24)])]);
        let objects =
            objects(&cluster(vec![Node { vms: vec![web], containers: vec![ct], ..node("pve01") }]), &with_tenant);
        // utils.go (common), MatchVMToTenant: nbi.AddTenant(ctx, &objects.Tenant{Name: tenantName, Slug:
        //   utils.Slugify(tenantName)})
        let expected = Desired::new(Kind::Tenant, Identity::named("Acme Corp"), SOURCE)
            .field("name", "Acme Corp")
            .create_only("slug", "acme-corp")
            .ensure_only();
        assert_eq!(named(&objects, Kind::Tenant, "Acme Corp"), expected);
        // proxmox_sync.go: Cluster{Tenant: clusterTenant}, Device{Tenant: hostTenant}, VM{Tenant: vmTenant},
        //   IPAddress{Tenant: nbVM.Tenant}; nothing else carries a tenant.
        let with_reference: BTreeSet<(Kind, String)> = objects
            .iter()
            .filter(|object| object.references.contains_key("tenant"))
            .map(|object| (object.kind, object.identity.label().to_owned()))
            .collect();
        let expected: BTreeSet<(Kind, String)> = [
            (Kind::Cluster, CLUSTER),
            (Kind::Device, "pve01"),
            (Kind::VirtualMachine, "web01"),
            (Kind::VirtualMachine, "ct01"),
            (Kind::IpAddress, "10.0.0.5/24"),
            (Kind::IpAddress, "192.0.2.10/24"),
        ]
        .into_iter()
        .map(|(kind, label)| (kind, label.to_owned()))
        .collect();
        assert_eq!(with_reference, expected);
        let tenant = objects.iter().filter_map(|object| object.references.get("tenant")).next().unwrap();
        assert_eq!(tenant.as_ref().unwrap().kind, Kind::Tenant);
        assert_eq!(tenant.as_ref().unwrap().identity, Identity::named("Acme Corp"));
    }

    // -----------------------------------------------------------------------
    // Manufacturer, device type, roles
    // -----------------------------------------------------------------------

    #[test]
    fn hosts_get_the_generic_manufacturer_and_device_type() {
        let objects = objects(&cluster(vec![node("pve01"), node("pve02")]), &settings());
        // constants.go: DefaultManufacturer = "Generic Manufacturer",
        //   DefaultManufacturerDescription = "Generic Manufacturer created by netbox-ssot"
        // proxmox_sync.go: Slug: utils.Slugify(constants.DefaultManufacturer)
        let manufacturer = Desired::new(Kind::Manufacturer, Identity::named("Generic Manufacturer"), SOURCE)
            .field("name", "Generic Manufacturer")
            .field("description", "Generic Manufacturer created by netbox-ssot")
            .create_only("slug", "generic-manufacturer");
        assert_eq!(named(&objects, Kind::Manufacturer, "Generic Manufacturer"), manufacturer);
        // constants.go: DefaultModel = "Generic Model",
        //   DefaultDeviceTypeDescription = "Generic Device Type created by netbox-ssot"
        // proxmox_sync.go: Slug: utils.Slugify(hostManufacturer.Name + constants.DefaultModel) — no separator.
        let identity = Identity::device_type("Generic Manufacturer", "Generic Model");
        let device_type = Desired::new(Kind::DeviceType, identity.clone(), SOURCE)
            .field("model", "Generic Model")
            .field("description", "Generic Device Type created by netbox-ssot")
            .create_only("slug", "generic-manufacturergeneric-model")
            .reference("manufacturer", Kind::Manufacturer, Identity::named("Generic Manufacturer"));
        assert_eq!(one(&objects, Kind::DeviceType, &identity), device_type);
        assert_eq!(of_kind(&objects, Kind::Manufacturer).len(), 1);
        assert_eq!(of_kind(&objects, Kind::DeviceType).len(), 1);
    }

    #[test]
    fn a_cluster_without_node_declares_no_manufacturer_nor_device_type() {
        // proxmox_sync.go, syncNodes: both are added inside "for _, node := range ps.Nodes".
        let objects = objects(&cluster(vec![]), &settings());
        assert_eq!(of_kind(&objects, Kind::Manufacturer).len(), 0);
        assert_eq!(of_kind(&objects, Kind::DeviceType).len(), 0);
        assert_eq!(of_kind(&objects, Kind::Role).len(), 0);
    }

    #[test]
    fn without_roles_in_the_settings_the_default_roles_of_netbox_ssot_are_declared() {
        let objects = objects(&host_of(vec![vm(101, "web01")]), &settings());
        // constants.go: DeviceRoleServer = "Server", DeviceRoleServerDescription = "Device role for marking server.",
        //   DeviceRoleServerColor = "00add8"; add_predefined_items.go: Slug: utils.Slugify(constants.DeviceRoleServer),
        //   VMRole: false — and dcim.go: VMRole bool `json:"vm_role,omitempty"`: false is never sent.
        let server = Desired::new(Kind::Role, Identity::named("Server"), SOURCE)
            .field("name", "Server")
            .field("description", "Device role for marking server.")
            .create_only("slug", "server")
            .create_only("color", "00add8");
        assert_eq!(named(&objects, Kind::Role, "Server"), server);
        // constants.go: DeviceRoleVM = "VM", DeviceRoleVMDescription = "Role for representing VMs.",
        //   DeviceRoleVMColor = "81eaea"
        let virtual_machine = Desired::new(Kind::Role, Identity::named("VM"), SOURCE)
            .field("name", "VM")
            .field("description", "Role for representing VMs.")
            .create_only("slug", "vm")
            .create_only("color", "81eaea");
        assert_eq!(named(&objects, Kind::Role, "VM"), virtual_machine);
        assert_eq!(of_kind(&objects, Kind::Role).len(), 2);
    }

    #[test]
    fn the_roles_of_the_settings_only_have_to_exist() {
        let with_roles = Settings {
            host_role: Some("Hypervisor PVE".to_owned()),
            vm_role: Some("Virtual Machine".to_owned()),
            ..settings()
        };
        let objects = objects(&host_of(vec![vm(101, "web01")]), &with_roles);
        // utils.go (common), MatchHostToRole: nbi.AddDeviceRole(ctx, &objects.DeviceRole{Name: roleName, Slug:
        //   utils.Slugify(roleName)})
        let host_role = Desired::new(Kind::Role, Identity::named("Hypervisor PVE"), SOURCE)
            .field("name", "Hypervisor PVE")
            .create_only("slug", "hypervisor-pve")
            .ensure_only();
        assert_eq!(named(&objects, Kind::Role, "Hypervisor PVE"), host_role);
        let vm_role = Desired::new(Kind::Role, Identity::named("Virtual Machine"), SOURCE)
            .field("name", "Virtual Machine")
            .create_only("slug", "virtual-machine")
            .ensure_only();
        assert_eq!(named(&objects, Kind::Role, "Virtual Machine"), vm_role);
        // proxmox_sync.go: if hostRole == nil { nbi.AddServerDeviceRole } — and the same for the VM role.
        assert_eq!(of_kind(&objects, Kind::Role).len(), 2);
        let host = one(&objects, Kind::Device, &Identity::device("pve01"));
        assert_eq!(host.references["role"].as_ref().unwrap().identity, Identity::named("Hypervisor PVE"));
        let web = guest(&objects, "web01");
        assert_eq!(web.references["role"].as_ref().unwrap().identity, Identity::named("Virtual Machine"));
    }

    #[test]
    fn the_vm_role_is_declared_only_when_a_vm_is_synced() {
        // proxmox_sync.go, syncVM: the role is added VM by VM; without a VM nothing adds it.
        let objects = objects(&cluster(vec![node("pve01")]), &settings());
        assert_eq!(labels(&objects, Kind::Role), ["Server"]);
    }

    #[test]
    fn the_container_role_is_declared_only_when_there_is_a_container() {
        // Fixed defect: syncContainers tests "len(ps.Containers) > 0" on a map that has one entry per node,
        // so netbox-ssot created the role on every cluster. Its comment ("Create container role") and the
        // loop below it show the role is meant for the containers.
        let without = objects(&host_of(vec![vm(101, "web01")]), &settings());
        assert_eq!(labels(&without, Kind::Role), ["Server", "VM"]);
        let with_container = cluster(vec![Node { containers: vec![container(200, "ct01")], ..node("pve01") }]);
        let objects = objects(&with_container, &settings());
        // constants.go: DeviceRoleContainer = "Container", DeviceRoleContainerColor = "0db7ed",
        //   DeviceRoleContainerDescription = "VM role for separating containers from VMs."
        // add_predefined_items.go, AddContainerDeviceRole: VMRole: true
        let expected = Desired::new(Kind::Role, Identity::named("Container"), SOURCE)
            .field("name", "Container")
            .field("description", "VM role for separating containers from VMs.")
            .field("vm_role", true)
            .create_only("slug", "container")
            .create_only("color", "0db7ed");
        assert_eq!(named(&objects, Kind::Role, "Container"), expected);
    }

    // -----------------------------------------------------------------------
    // Hosts and their interfaces
    // -----------------------------------------------------------------------

    #[test]
    fn a_host_is_a_device_with_its_cpu_and_memory_custom_fields() {
        let with_domain = Settings { domain: ".lab.example".to_owned(), ..settings() };
        let objects = objects(&cluster(vec![node("pve01")]), &with_domain);
        // proxmox_sync.go: hostName := node.Name + ps.SourceConfig.AssignDomainName
        let name = "pve01.lab.example";
        let expected = Desired::new(Kind::Device, Identity::device(name), SOURCE)
            .field("name", name)
            // add_predefined_items.go, AddServerDeviceRole: Name: constants.DeviceRoleServer
            .reference("role", Kind::Role, Identity::named("Server"))
            // proxmox_sync.go: hostSite = nbi.GetSiteByID(ps.NetboxCluster.ScopeID)
            .reference("site", Kind::Site, Identity::named(SITE))
            // proxmox_sync.go: Cluster: ps.NetboxCluster
            .reference("cluster", Kind::Cluster, Identity::named(CLUSTER))
            // proxmox_sync.go: constants.CustomFieldHostCPUCoresName: fmt.Sprintf("%d", node.CPUInfo.CPUs) —
            //   "host_cpu_cores"
            .custom_field(&custom_fields::HOST_CPU_CORES, "32")
            // proxmox_sync.go: constants.CustomFieldHostMemoryName: fmt.Sprintf("%d GiB",
            //   node.Memory.Total/constants.GiB)
            //   — "host_memory"; 236538687488 / 1073741824 = 220.29…, an integer division.
            .custom_field(&custom_fields::HOST_MEMORY, "220 GiB")
            // add_items.go, AddDevice: addSourceNameCustomField
            .custom_field(&custom_fields::SOURCE, SOURCE)
            // add_items.go, AddDevice: "Allow manual override device type" — the generic type only fills an
            // empty field. constants.go: DefaultManufacturer, DefaultModel.
            .reference("device_type", Kind::DeviceType, Identity::device_type("Generic Manufacturer", "Generic Model"))
            .only_when_empty("device_type");
        assert_eq!(one(&objects, Kind::Device, &Identity::device(name)), expected);
    }

    #[test]
    fn a_host_gets_the_generic_device_type_only_when_netbox_has_none() {
        // netbox-ssot kept a device type set by hand (add_items.go, AddDevice: "Allow manual override device
        // type"), and Proxmox knows no hardware: the generic type only fills an empty field.
        let objects = objects(&cluster(vec![node("pve01")]), &settings());
        let host = one(&objects, Kind::Device, &Identity::device("pve01"));
        // constants.go: DefaultManufacturer = "Generic Manufacturer", DefaultModel = "Generic Model"
        let generic = Identity::device_type("Generic Manufacturer", "Generic Model");
        assert_eq!(host.references.get("device_type"), Some(&Some(Target::new(Kind::DeviceType, generic))));
        assert!(host.only_when_empty.contains("device_type"));
    }

    #[test]
    fn a_host_name_too_long_is_cut_with_a_warning() {
        let name = format!("pve01.{}", "d".repeat(70));
        let translation =
            translate(&cluster(vec![Node { networks: vec![network("eno1", "eth")], ..node(&name) }]), &settings());
        // add_items.go, applyDeviceFieldLengthLimitations: device.Name = device.Name[:constants.MaxDeviceNameLength]
        //   (64)
        let cut = format!("pve01.{}", "d".repeat(58));
        assert_eq!(labels(&translation.objects, Kind::Device), [cut.as_str()]);
        // The interfaces hang under the name NetBox stores.
        assert_eq!(of_kind(&translation.objects, Kind::Interface)[0].identity, Identity::interface(&cut, "eno1"));
        // add_items.go: "Device name %s is too long, truncating to %d characters"
        assert_eq!(translation.warnings, [format!("device name {name} is too long, truncated to 64 characters")]);
    }

    #[test]
    fn a_node_network_type_maps_to_a_netbox_interface_type() {
        // proxmox_sync.go, nodeInterfaceType: case "bond", "OVSBond": LAGInterfaceType — dcim.go: Value: "lag"
        assert_eq!(node_interface_type("bond"), Some("lag"));
        assert_eq!(node_interface_type("OVSBond"), Some("lag"));
        // case "bridge", "OVSBridge": BridgeInterfaceType — dcim.go: Value: "bridge"
        assert_eq!(node_interface_type("bridge"), Some("bridge"));
        assert_eq!(node_interface_type("OVSBridge"), Some("bridge"));
        // case "vlan", "OVSIntPort", "alias": VirtualInterfaceType — dcim.go: Value: "virtual"
        assert_eq!(node_interface_type("vlan"), Some("virtual"));
        assert_eq!(node_interface_type("OVSIntPort"), Some("virtual"));
        assert_eq!(node_interface_type("alias"), Some("virtual"));
        // default: return nil — a physical NIC, whose real type Proxmox does not expose.
        assert_eq!(node_interface_type("eth"), None);
        assert_eq!(node_interface_type("OVSPort"), None);
    }

    #[test]
    fn a_bridge_of_a_host_is_an_interface_of_its_device() {
        let networks = vec![NodeNetwork { active: false, ..network("vmbr0", "bridge") }];
        let objects = objects(&cluster(vec![Node { networks, ..node("pve01") }]), &settings());
        let identity = Identity::interface("pve01", "vmbr0");
        let expected = Desired::new(Kind::Interface, identity.clone(), SOURCE)
            .field("name", "vmbr0")
            // proxmox_sync.go: Status: new(active) — dcim.go: Status *bool `json:"enabled,omitempty"`: a pointer,
            // so false is sent too.
            .field("enabled", false)
            .field("type", "bridge")
            .reference("device", Kind::Device, Identity::device("pve01"))
            // add_items.go, AddInterface: addSourceNameCustomField
            .custom_field(&custom_fields::SOURCE, SOURCE);
        assert_eq!(one(&objects, Kind::Interface, &identity), expected);
    }

    #[test]
    fn a_physical_nic_gets_the_type_other_at_creation_only() {
        let objects =
            objects(&cluster(vec![Node { networks: vec![network("eno1", "eth")], ..node("pve01") }]), &settings());
        let nic = one(&objects, Kind::Interface, &Identity::interface("pve01", "eno1"));
        // proxmox_sync.go: "Keep the type of an existing physical interface, it is more accurate than ours."
        //   if _, exists := nbi.GetInterface(…); !exists { ifaceType = &objects.OtherInterfaceType } — Value: "other"
        assert!(!nic.fields.contains_key("type"));
        assert_eq!(nic.create_only.get("type"), Some(&serde_json::json!("other")));
        assert_eq!(nic.fields["enabled"], serde_json::json!(true));
    }

    #[test]
    fn the_members_of_a_bond_refer_to_it_as_their_lag() {
        let networks = vec![
            bond("bond0", "bond", &["eno1", "eno2"]),
            bond("bond1", "OVSBond", &["eno3"]),
            network("eno1", "eth"),
            network("eno2", "eth"),
            network("eno3", "eth"),
            network("eno4", "eth"),
        ];
        let objects = objects(&cluster(vec![Node { networks, ..node("pve01") }]), &settings());
        let lag_of = |name: &str| {
            let nic = one(&objects, Kind::Interface, &Identity::interface("pve01", name));
            nic.references.get("lag").cloned()
        };
        // proxmox_sync.go: LAG: nbLAGs[bondOfMember[nodeNetwork.Iface]]
        let bond0 =
            omnisync_core::inventory::model::Target::new(Kind::Interface, Identity::interface("pve01", "bond0"));
        let bond1 =
            omnisync_core::inventory::model::Target::new(Kind::Interface, Identity::interface("pve01", "bond1"));
        assert_eq!(lag_of("eno1"), Some(Some(bond0.clone())));
        assert_eq!(lag_of("eno2"), Some(Some(bond0)));
        assert_eq!(lag_of("eno3"), Some(Some(bond1)));
        // proxmox_sync.go: "A nil LAG leaves the NetBox one in place": netbox-ssot only detached an interface from
        // a bond this run synced, which the model cannot say; the LAG of an interface in no bond is not reported.
        assert_eq!(lag_of("eno4"), None);
        assert_eq!(lag_of("bond0"), None);
        let bond = one(&objects, Kind::Interface, &Identity::interface("pve01", "bond0"));
        assert_eq!(bond.fields["type"], serde_json::json!("lag"));
    }

    #[test]
    fn the_interface_filter_applies_to_the_interfaces_of_a_host() {
        let networks = vec![
            bond("br-bond", "bond", &["eno1"]),
            network("docker0", "bridge"),
            network("eno1", "eth"),
            network("vmbr0", "bridge"),
        ];
        let objects = objects(&cluster(vec![Node { networks, ..node("pve01") }]), &production());
        // proxmox_sync.go: if utils.FilterInterfaceName(nodeNetwork.Iface, ps.SourceConfig.InterfaceFilter) {
        //   continue }
        assert_eq!(labels(&objects, Kind::Interface), ["eno1", "vmbr0"]);
        // The member of a bond that is filtered out: nbLAGs has no such bond, the LAG is nil and left in place.
        let member = one(&objects, Kind::Interface, &Identity::interface("pve01", "eno1"));
        assert!(!member.references.contains_key("lag"));
    }

    #[test]
    fn a_host_interface_name_is_cut_at_64_bytes() {
        let name = "v".repeat(70);
        let objects =
            objects(&cluster(vec![Node { networks: vec![network(&name, "vlan")], ..node("pve01") }]), &settings());
        // add_items.go, AddInterface: newInterface.Name = newInterface.Name[:constants.MaxInterfaceNameLength] (64)
        assert_eq!(labels(&objects, Kind::Interface), ["v".repeat(64)]);
        assert_eq!(of_kind(&objects, Kind::Interface)[0].fields["name"], serde_json::json!("v".repeat(64)));
    }

    // -----------------------------------------------------------------------
    // Virtual machines
    // -----------------------------------------------------------------------

    #[test]
    fn a_running_vm_whose_agent_tells_its_system() {
        let debian = Vm {
            os_info: Some(GuestOsInfo {
                pretty_name: Some("Debian GNU/Linux 12 (bookworm)".to_owned()),
                ..GuestOsInfo::default()
            }),
            ..vm(101, "web01")
        };
        let objects = objects(&host_of(vec![debian]), &settings());
        // proxmox_sync.go, vmPlatformName: if agentOsInfo != nil && agentOsInfo.PrettyName != "" { return
        //   agentOsInfo.PrettyName, false }
        let mut expected = expected_vm(101, "web01").reference(
            "platform",
            Kind::Platform,
            Identity::named("Debian GNU/Linux 12 (bookworm)"),
        );
        // What an agent reports is written whatever NetBox has: only the fallback waits for an empty field.
        expected.only_when_empty.clear();
        assert_eq!(guest(&objects, "web01"), expected);
        // proxmox_sync.go: platformStruct := &objects.Platform{Name: platformName, Slug: utils.Slugify(platformName)}
        let platform = Desired::new(Kind::Platform, Identity::named("Debian GNU/Linux 12 (bookworm)"), SOURCE)
            .field("name", "Debian GNU/Linux 12 (bookworm)")
            .create_only("slug", "debian-gnulinux-12-bookworm");
        assert_eq!(named(&objects, Kind::Platform, "Debian GNU/Linux 12 (bookworm)"), platform);
    }

    #[test]
    fn a_vm_whose_agent_is_silent_keeps_the_platform_netbox_has() {
        // proxmox_sync.go, vmPlatformName: "an agent that does not answer (stopped VM, agent down) says nothing
        // about the platform": the platform NetBox has is kept when an agent reported it. Which platform NetBox
        // has is not known here: the one of the ostype is declared, to be written only when NetBox has none.
        for os_info in [
            None,
            Some(GuestOsInfo::default()),
            Some(GuestOsInfo { pretty_name: Some(String::new()), ..GuestOsInfo::default() }),
        ] {
            let silent = Vm { os_info, ..vm(101, "web01") };
            let objects = objects(&host_of(vec![silent]), &settings());
            let found = guest(&objects, "web01");
            assert_eq!(found, expected_vm(101, "web01"));
            assert!(found.only_when_empty.contains("platform"));
            // proxmoxOSTypePlatformNames: "l26": "Other 2.6.x Linux (64-bit)"
            assert_eq!(labels(&objects, Kind::Platform), ["Other 2.6.x Linux (64-bit)"]);
        }
    }

    #[test]
    fn the_platform_of_a_silent_agent_is_derived_from_the_ostype() {
        // proxmox_sync.go, proxmoxOSTypePlatformNames
        assert_eq!(ostype_platform_name(Some("wxp")), "Microsoft Windows XP (32-bit)");
        assert_eq!(ostype_platform_name(Some("w2k")), "Microsoft Windows 2000 Server");
        assert_eq!(ostype_platform_name(Some("w2k3")), "Microsoft Windows Server 2003 Standard (32-bit)");
        assert_eq!(ostype_platform_name(Some("w2k8")), "Microsoft Windows Server 2008 (64-bit)");
        assert_eq!(ostype_platform_name(Some("wvista")), "Microsoft Windows Vista (32-bit)");
        assert_eq!(ostype_platform_name(Some("win7")), "Microsoft Windows 7 (64-bit)");
        assert_eq!(ostype_platform_name(Some("win8")), "Microsoft Windows 8 (64-bit)");
        assert_eq!(ostype_platform_name(Some("win10")), "Microsoft Windows 10 (64-bit)");
        assert_eq!(ostype_platform_name(Some("win11")), "Microsoft Windows 11 (64-bit)");
        assert_eq!(ostype_platform_name(Some("l26")), "Other 2.6.x Linux (64-bit)");
        // proxmox_sync.go, vmPlatformName: return "Unknown", false — "other", "l24" and "solaris" have no name.
        assert_eq!(ostype_platform_name(Some("other")), "Unknown");
        assert_eq!(ostype_platform_name(Some("l24")), "Unknown");
        assert_eq!(ostype_platform_name(None), "Unknown");
    }

    #[test]
    fn a_stopped_vm_is_offline_and_any_other_status_is_active() {
        let vms = vec![
            Vm { status: "stopped".to_owned(), interfaces: None, ..vm(101, "stopped01") },
            Vm { status: "paused".to_owned(), interfaces: None, ..vm(102, "paused01") },
        ];
        let objects = objects(&host_of(vms), &settings());
        // proxmox_sync.go: if vm.Status == "stopped" { vmStatus = &objects.VMStatusOffline } — Value: "offline"
        assert_eq!(guest(&objects, "stopped01").fields["status"], serde_json::json!("offline"));
        assert_eq!(guest(&objects, "paused01").fields["status"], serde_json::json!("active"));
    }

    #[test]
    fn a_vm_without_cpu_or_memory_does_not_report_them() {
        // virtualization.go: VCPUs float32 `json:"vcpus,omitempty"`, Memory int `json:"memory,omitempty"`:
        // a zero is left out of the request, and NetBox keeps what it has.
        let empty = Vm { cpus: 0, max_memory_bytes: 1_048_575, ..vm(101, "web01") };
        let web = guest(&objects(&host_of(vec![empty]), &settings()), "web01");
        assert!(!web.fields.contains_key("vcpus"));
        // 1048575 bytes is less than one MiB: int(vm.MaxMem / constants.MiB) = 0.
        assert!(!web.fields.contains_key("memory"));
    }

    #[test]
    fn the_memory_of_a_vm_is_in_whole_mebibytes() {
        // proxmox_sync.go: Memory: int(vm.MaxMem / constants.MiB) — 8589934592 / 1048576 = 8192;
        // one byte less is 8191.99…, rounded down.
        let vms = vec![
            Vm { max_memory_bytes: 8_589_934_592, ..vm(101, "even") },
            Vm { max_memory_bytes: 8_589_934_591, ..vm(102, "odd") },
        ];
        let objects = objects(&host_of(vms), &settings());
        assert_eq!(guest(&objects, "even").fields["memory"], serde_json::json!(8192));
        assert_eq!(guest(&objects, "odd").fields["memory"], serde_json::json!(8191));
    }

    #[test]
    fn a_vm_name_too_long_is_cut_at_64_bytes() {
        let name = format!("web.{}", "n".repeat(70));
        let objects = objects(&host_of(vec![vm(101, &name)]), &settings());
        // add_items.go, AddVM: newVM.Name = TruncateVMName(newVM.Name)
        let cut = format!("web.{}", "n".repeat(60));
        let web = guest(&objects, &cut);
        assert_eq!(web.fields["name"], serde_json::json!(cut));
    }

    #[test]
    fn the_tags_of_a_vm_are_reported_and_only_have_to_exist() {
        let tagged = Vm { tags: vec!["service-apache".to_owned(), "Tier 1".to_owned()], ..vm(101, "web01") };
        let objects = objects(&host_of(vec![tagged, vm(102, "db01")]), &settings());
        let web = guest(&objects, "web01");
        let reported: Vec<&str> = web.tags.iter().flatten().map(String::as_str).collect();
        assert_eq!(reported, ["Tier 1", "service-apache"]);
        // A VM without tag has none, which is not "unknown".
        assert_eq!(guest(&objects, "db01").tags, Some(BTreeSet::new()));
        // proxmox_sync.go: nbi.AddTagIfMissing(ctx, &objects.Tag{Name: tag, Slug: utils.Slugify(tag), Color:
        //   constants.ColorGreen})
        // constants.go: ColorGreen = "4caf50"; add_items.go, AddTagIfMissing: an existing tag is returned untouched.
        let apache = Desired::new(Kind::Tag, Identity::named("service-apache"), SOURCE)
            .field("name", "service-apache")
            .create_only("slug", "service-apache")
            .create_only("color", "4caf50")
            .create_only("description", "netbox-omnisync")
            .ensure_only();
        assert_eq!(named(&objects, Kind::Tag, "service-apache"), apache);
        let tier = Desired::new(Kind::Tag, Identity::named("Tier 1"), SOURCE)
            .field("name", "Tier 1")
            .create_only("slug", "tier-1")
            .create_only("color", "4caf50")
            .create_only("description", "netbox-omnisync")
            .ensure_only();
        assert_eq!(named(&objects, Kind::Tag, "Tier 1"), tier);
        assert_eq!(of_kind(&objects, Kind::Tag).len(), 2);
    }

    #[test]
    fn a_tag_shared_by_two_guests_is_declared_once() {
        let tagged = |vmid, name: &str| Vm { tags: vec!["service-apache".to_owned()], ..vm(vmid, name) };
        let objects = objects(&host_of(vec![tagged(101, "web01"), tagged(102, "web02")]), &settings());
        assert_eq!(labels(&objects, Kind::Tag), ["service-apache"]);
    }

    // -----------------------------------------------------------------------
    // Templates and homonyms
    // -----------------------------------------------------------------------

    #[test]
    fn a_template_is_left_out_only_when_templates_are_ignored() {
        let vms = || {
            vec![
                Vm { template: true, status: "stopped".to_owned(), interfaces: None, ..vm(100, "debian-tpl") },
                vm(101, "web01"),
            ]
        };
        // proxmox_sync.go: if ps.SourceConfig.IgnoreVMTemplates && isTemplate { return nil }
        let ignoring = Settings { ignore_templates: true, ..settings() };
        assert_eq!(labels(&objects(&host_of(vms()), &ignoring), Kind::VirtualMachine), ["web01"]);
        // A template that is synced is a VM like another: the proxmox source never used the "VM Template" role.
        let keeping = objects(&host_of(vms()), &settings());
        assert_eq!(labels(&keeping, Kind::VirtualMachine), ["debian-tpl", "web01"]);
        assert_eq!(guest(&keeping, "debian-tpl").references["role"].as_ref().unwrap().identity, Identity::named("VM"));
    }

    #[test]
    fn among_homonym_vms_only_the_lowest_vmid_is_synced() {
        let nodes = vec![
            Node { vms: vec![Vm { cpus: 8, ..vm(205, "web01") }], ..node("pve01") },
            Node { vms: vec![Vm { cpus: 4, ..vm(101, "web01") }, vm(102, "db01")], ..node("pve02") },
        ];
        let translation = translate(&cluster(nodes), &settings());
        // proxmox_sync.go, keptGuestIDs: "among homonym VMs and containers only the lowest VMID is synced"
        assert_eq!(labels(&translation.objects, Kind::VirtualMachine), ["web01", "db01"]);
        let web = guest(&translation.objects, "web01");
        assert_eq!(web.custom_fields["source_id"], serde_json::json!("101"));
        assert_eq!(web.fields["vcpus"], serde_json::json!(4));
        assert_eq!(web.references["device"].as_ref().unwrap().identity, Identity::device("pve02"));
        // proxmox_sync.go: "skipping vm %s (vmid %d): name already used by vmid %d in the cluster"
        assert_eq!(
            translation.warnings,
            ["skipping vm web01 (vmid 205): name already used by vmid 101 in the cluster"]
        );
    }

    #[test]
    fn a_skipped_homonym_declares_none_of_its_dependents() {
        let loser = Vm {
            disks: vec![Disk {
                bus: DiskBus::Scsi,
                index: 0,
                name: "local:vm-205-disk-0".to_owned(),
                size_mib: 1024,
                cdrom: false,
            }],
            tags: vec!["loser-tag".to_owned()],
            os_info: Some(GuestOsInfo { pretty_name: Some("Loser OS".to_owned()), ..GuestOsInfo::default() }),
            ..with_nics(205, "web01", vec![nic("eth0", "bc:24:11:00:00:02", &[("10.0.9.9", "ipv4", 24)])])
        };
        let objects = objects(&host_of(vec![vm(101, "web01"), loser]), &settings());
        for kind in [Kind::VmInterface, Kind::MacAddress, Kind::IpAddress, Kind::Prefix, Kind::VirtualDisk, Kind::Tag] {
            assert_eq!(of_kind(&objects, kind).len(), 0, "{kind:?}");
        }
        // The only platform is the one of the VM that is kept (its agent is silent: the one of its ostype),
        // never the "Loser OS" the skipped one reports.
        assert_eq!(labels(&objects, Kind::Platform), ["Other 2.6.x Linux (64-bit)"]);
    }

    #[test]
    fn a_vm_and_a_container_compete_for_a_name() {
        let nodes =
            vec![Node { vms: vec![vm(300, "shared")], containers: vec![container(200, "shared")], ..node("pve01") }];
        let translation = translate(&cluster(nodes), &settings());
        assert_eq!(labels(&translation.objects, Kind::VirtualMachine), ["shared"]);
        assert_eq!(guest(&translation.objects, "shared").custom_fields["source_id"], serde_json::json!("200"));
        assert_eq!(
            translation.warnings,
            ["skipping vm shared (vmid 300): name already used by vmid 200 in the cluster"]
        );

        let nodes =
            vec![Node { vms: vec![vm(100, "shared")], containers: vec![container(200, "shared")], ..node("pve01") }];
        let translation = translate(&cluster(nodes), &settings());
        assert_eq!(guest(&translation.objects, "shared").custom_fields["source_id"], serde_json::json!("100"));
        // proxmox_sync.go: "skipping container %s (vmid %d): name already used by vmid %d in the cluster"
        assert_eq!(
            translation.warnings,
            ["skipping container shared (vmid 200): name already used by vmid 100 in the cluster"]
        );
    }

    #[test]
    fn an_ignored_template_does_not_shadow_its_homonym() {
        // proxmox_sync.go, keptGuestIDs: "Only guests that are actually synced compete for a name"
        let vms = vec![Vm { template: true, ..vm(100, "web01") }, vm(101, "web01")];
        let ignoring = Settings { ignore_templates: true, ..settings() };
        let translation = translate(&host_of(vms), &ignoring);
        assert_eq!(guest(&translation.objects, "web01").custom_fields["source_id"], serde_json::json!("101"));
        assert_eq!(translation.warnings, Vec::<String>::new());
    }

    #[test]
    fn names_that_are_alike_once_cut_are_homonyms() {
        // proxmox_sync.go: keptGuestIDs[inventory.TruncateVMName(vm.Name)]
        let first = format!("{}-a", "x".repeat(64));
        let second = format!("{}-b", "x".repeat(64));
        let translation = translate(&host_of(vec![vm(101, &first), vm(102, &second)]), &settings());
        assert_eq!(labels(&translation.objects, Kind::VirtualMachine), ["x".repeat(64)]);
        assert_eq!(
            translation.warnings,
            [format!("skipping vm {second} (vmid 102): name already used by vmid 101 in the cluster")]
        );
    }

    #[test]
    fn names_that_differ_by_case_only_are_homonyms() {
        // Fixed defect: netbox-ssot compared the names as written, while NetBox refuses two virtual machines of
        // a cluster whose names differ by letter case only: the second one failed at every run.
        let translation = translate(&host_of(vec![vm(101, "Web01"), vm(102, "web01")]), &settings());
        assert_eq!(labels(&translation.objects, Kind::VirtualMachine), ["Web01"]);
        assert_eq!(
            translation.warnings,
            ["skipping vm web01 (vmid 102): name already used by vmid 101 in the cluster"]
        );
    }

    // -----------------------------------------------------------------------
    // Interfaces, MAC and IP addresses of a virtual machine
    // -----------------------------------------------------------------------

    #[test]
    fn a_vm_interface_with_its_mac_and_address() {
        let web = with_nics(101, "web01", vec![nic("eth0", "bc:24:11:aa:bb:cc", &[("10.0.0.5", "ipv4", 24)])]);
        let objects = objects(&host_of(vec![web]), &settings());

        // proxmox_sync.go, syncVMNetworks: vmInterfaceStruct := &objects.VMInterface{Name: vmNetwork.Name, VM: nbVM}
        // add_items.go, AddVMInterface: addSourceNameCustomField
        // utils.go (common), SetPrimaryMACForInterface: vmInterfaceCopy.PrimaryMACAddress = mac
        let interface = Desired::new(Kind::VmInterface, nic_identity("web01", "eth0"), SOURCE)
            .field("name", "eth0")
            .reference("virtual_machine", Kind::VirtualMachine, vm_identity("web01"))
            .reference("primary_mac_address", Kind::MacAddress, mac_identity("BC:24:11:AA:BB:CC", "web01", "eth0"))
            .custom_field(&custom_fields::SOURCE, SOURCE);
        assert_eq!(one(&objects, Kind::VmInterface, &nic_identity("web01", "eth0")), interface);

        // proxmox_sync.go: vmIfaceMAC := strings.ToUpper(vmNetwork.HardwareAddress)
        // utils.go (common), CreateMACAddressForObjectType: MAC: mac, AssignedObjectType, AssignedObjectID —
        // and add_items.go, AddMACAddress adds no source custom field.
        let mac = Desired::new(Kind::MacAddress, mac_identity("BC:24:11:AA:BB:CC", "web01", "eth0"), SOURCE)
            .field("mac_address", "BC:24:11:AA:BB:CC")
            .reference("assigned_object", Kind::VmInterface, nic_identity("web01", "eth0"));
        assert_eq!(one(&objects, Kind::MacAddress, &mac_identity("BC:24:11:AA:BB:CC", "web01", "eth0")), mac);

        // proxmox_sync.go: Address: fmt.Sprintf("%s/%d", ipAddress.IPAddress, ipAddress.Prefix),
        //   Status: &objects.IPAddressStatusActive (ipam.go: Value: "active"),
        //   CustomFields: constants.CustomFieldArpEntryName: false ("arp_entry"),
        //   AssignedObjectType: constants.ContentTypeVirtualizationVMInterface, VRF: ipVRF (nil: looked up in every
        //   table)
        // add_items.go, AddIPAddress: addSourceNameCustomField
        let address = Desired::new(Kind::IpAddress, address_identity("10.0.0.5/24"), SOURCE)
            .field("address", "10.0.0.5/24")
            .field("status", "active")
            .reference("assigned_object", Kind::VmInterface, nic_identity("web01", "eth0"))
            .custom_field(&custom_fields::ARP_ENTRY, false)
            .custom_field(&custom_fields::SOURCE, SOURCE);
        let found = one(&objects, Kind::IpAddress, &address_identity("10.0.0.5/24"));
        assert_eq!(found, address);
        // An identity compares its key only: the table is "any" (the source knows no VRF).
        assert_eq!(found.identity.key(), ["10.0.0.5", "*"]);

        // proxmox_sync.go: nbVMCopy.PrimaryIPv4 = vmIPv4Addresses[0]
        let web = guest(&objects, "web01");
        assert_eq!(
            web,
            expected_vm(101, "web01").reference("primary_ip4", Kind::IpAddress, address_identity("10.0.0.5/24"))
        );
    }

    #[test]
    fn an_interface_without_mac_declares_no_mac_address() {
        let web = with_nics(101, "web01", vec![nic("wg0", "", &[])]);
        let objects = objects(&host_of(vec![web]), &settings());
        // proxmox_sync.go: if vmIfaceMAC != "" { … }
        assert_eq!(of_kind(&objects, Kind::MacAddress).len(), 0);
        let interface = one(&objects, Kind::VmInterface, &nic_identity("web01", "wg0"));
        assert!(!interface.references.contains_key("primary_mac_address"));
    }

    #[test]
    fn a_vm_whose_interfaces_are_unknown_declares_none_and_marks_them_unknown() {
        let stopped = Vm { status: "stopped".to_owned(), interfaces: None, ..vm(101, "web01") };
        let objects = objects(&host_of(vec![stopped]), &settings());
        // proxmox_sync.go: "Sync VM networks, or keep the known ones when the guest agent did not answer"
        //   } else if existingVM != nil { nbi.KeepVMNetworkObjects(existingVM) }
        // keep_items.go, KeepVMNetworkObjects: "its interfaces, their IP and MAC addresses, and the prefixes of
        //   those IPs"
        let web = guest(&objects, "web01");
        assert_eq!(web.unknown_dependents, BTreeSet::from([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]));
        for kind in [Kind::VmInterface, Kind::MacAddress, Kind::IpAddress, Kind::Prefix] {
            assert_eq!(of_kind(&objects, kind).len(), 0, "{kind:?}");
        }
        // The primary addresses NetBox has are kept: nothing is said of them.
        assert!(!web.references.contains_key("primary_ip4"));
        assert!(!web.references.contains_key("primary_ip6"));
    }

    #[test]
    fn a_vm_known_to_have_no_interface_marks_nothing_unknown() {
        let objects = objects(&host_of(vec![vm(101, "web01")]), &settings());
        assert_eq!(guest(&objects, "web01").unknown_dependents, BTreeSet::new());
    }

    #[test]
    fn the_interface_filter_drops_an_interface_with_its_mac_and_addresses() {
        let web = with_nics(
            101,
            "web01",
            vec![
                nic("ens18", "bc:24:11:00:00:01", &[("10.0.0.5", "ipv4", 24)]),
                nic("docker0", "bc:24:11:00:00:02", &[("172.17.0.1", "ipv4", 16)]),
                nic("veth75354c3", "bc:24:11:00:00:03", &[]),
                nic("br-2f0c1d9e8a7b", "bc:24:11:00:00:04", &[("172.18.0.1", "ipv4", 16)]),
                nic("Loopback Pseudo-Interface 1", "", &[("127.0.0.1", "ipv4", 8)]),
                nic("isatap.{72D0E75B}", "00:00:00:00:00:00", &[]),
                nic("vEthernet (WSL)", "bc:24:11:00:00:05", &[("172.20.0.1", "ipv4", 20)]),
            ],
        );
        let objects = objects(&host_of(vec![web]), &production());
        // proxmox_sync.go, syncVMNetworks: if utils.FilterInterfaceName(vmNetwork.Name, …) { continue }
        assert_eq!(labels(&objects, Kind::VmInterface), ["ens18"]);
        assert_eq!(labels(&objects, Kind::MacAddress), ["BC:24:11:00:00:01"]);
        assert_eq!(labels(&objects, Kind::IpAddress), ["10.0.0.5/24"]);
        assert_eq!(labels(&objects, Kind::Prefix), ["10.0.0.0/24"]);
    }

    #[test]
    fn ipv6_is_dropped_when_every_ipv6_subnet_is_ignored() {
        let web = with_nics(
            101,
            "web01",
            vec![nic(
                "eth0",
                "bc:24:11:aa:bb:cc",
                &[("198.18.0.3", "ipv4", 26), ("fe80::30", "ipv6", 64), ("2001:db8::30", "ipv6", 64)],
            )],
        );
        let objects = objects(&host_of(vec![web]), &production());
        // networking.go, IsPermittedIPAddress: if subnetsContainIPAddress(ipAddress, ignoredSubnets) { return false }
        // — "::/0" holds every IPv6 address and no IPv4 one.
        assert_eq!(labels(&objects, Kind::IpAddress), ["198.18.0.3/26"]);
        assert_eq!(labels(&objects, Kind::Prefix), ["198.18.0.0/26"]);
        let web = guest(&objects, "web01");
        assert!(web.references.contains_key("primary_ip4"));
        assert!(!web.references.contains_key("primary_ip6"));
    }

    #[test]
    fn without_ignored_subnets_ipv6_is_synced_with_its_prefix_and_primary_address() {
        let web = with_nics(
            101,
            "web01",
            vec![
                nic("eth0", "bc:24:11:aa:bb:cc", &[("fe80::30", "ipv6", 64), ("198.18.0.3", "ipv4", 26)]),
                nic("eth1", "bc:24:11:aa:bb:cd", &[("198.18.1.3", "ipv4", 24), ("2001:db8::30", "ipv6", 128)]),
            ],
        );
        let objects = objects(&host_of(vec![web]), &settings());
        assert_eq!(
            labels(&objects, Kind::IpAddress),
            ["fe80::30/64", "198.18.0.3/26", "198.18.1.3/24", "2001:db8::30/128"]
        );
        // proxmox_sync.go: (ipAddress.IPAddressType == "ipv6" && mask != constants.MaxIPv6MaskBits) → AddPrefix
        assert_eq!(labels(&objects, Kind::Prefix), ["fe80::/64", "198.18.0.0/26", "198.18.1.0/24"]);
        // proxmox_sync.go: nbVMCopy.PrimaryIPv4 = vmIPv4Addresses[0]; nbVMCopy.PrimaryIPv6 = vmIPv6Addresses[0]
        // — the first of each family in the order of the agent, whatever the interface; unlike
        // netbox-ssot, a link-local one is skipped: it reaches no guest.
        let web = guest(&objects, "web01");
        assert_eq!(web.references["primary_ip4"].as_ref().unwrap().identity, address_identity("198.18.0.3"));
        assert_eq!(web.references["primary_ip6"].as_ref().unwrap().identity, address_identity("2001:db8::30"));
        assert_eq!(web.references["primary_ip6"].as_ref().unwrap().kind, Kind::IpAddress);
    }

    #[test]
    fn only_permitted_subnets_are_synced_and_an_ignored_one_wins() {
        let web = with_nics(
            101,
            "web01",
            vec![nic("eth0", "", &[("10.1.0.5", "ipv4", 24), ("10.2.0.5", "ipv4", 24), ("192.168.1.5", "ipv4", 24)])],
        );
        let restricted = Settings {
            permitted_subnets: Settings::subnets(&["10.0.0.0/8"]).unwrap(),
            ignored_subnets: Settings::subnets(&["10.2.0.0/16"]).unwrap(),
            ..settings()
        };
        // networking.go, IsPermittedIPAddress: ignored first, then
        //   if len(permittedSubnets) == 0 { return true }; return subnetsContainIPAddress(ipAddress, permittedSubnets)
        assert_eq!(labels(&objects(&host_of(vec![web]), &restricted), Kind::IpAddress), ["10.1.0.5/24"]);
    }

    #[test]
    fn the_zone_index_of_an_address_is_removed() {
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("fe80::be24:11ff:feaa:bbcc%eth0", "ipv6", 64)])]);
        let objects = objects(&host_of(vec![web]), &settings());
        // networking.go, RemoveZoneIndexFromIPAddress: e.g. 2001:db8::1%eth0 -> 2001:db8::1
        assert_eq!(labels(&objects, Kind::IpAddress), ["fe80::be24:11ff:feaa:bbcc/64"]);
        assert_eq!(
            of_kind(&objects, Kind::IpAddress)[0].fields["address"],
            serde_json::json!("fe80::be24:11ff:feaa:bbcc/64")
        );
    }

    #[test]
    fn an_address_with_a_zone_index_is_filtered_like_the_address_itself() {
        // networking.go, SubnetContainsIPAddress: ipAddress = RemoveZoneIndexFromIPAddress(ipAddress)
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("fe80::1%eth0", "ipv6", 64)])]);
        assert_eq!(of_kind(&objects(&host_of(vec![web]), &production()), Kind::IpAddress).len(), 0);
    }

    #[test]
    fn the_dns_name_comes_from_the_resolver_and_is_not_reported_when_the_lookup_fails() {
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("10.0.0.5", "ipv4", 24), ("10.0.0.6", "ipv4", 24)])]);
        let names: BTreeMap<IpAddr, String> =
            BTreeMap::from([("10.0.0.5".parse().unwrap(), "web01.lab.example.".to_owned())]);
        let objects = desired(&host_of(vec![web]), &settings(), &names).objects;
        // networking.go, ReverseLookup: domain := strings.TrimSuffix(names[0], ".")
        let resolved = one(&objects, Kind::IpAddress, &address_identity("10.0.0.5"));
        assert_eq!(resolved.fields["dns_name"], serde_json::json!("web01.lab.example"));
        // networking.go, ReverseLookup: if err != nil || len(names) == 0 { return "" } — and ipam.go:
        // DNSName string `json:"dns_name,omitempty"`: an empty name is left out, NetBox keeps the one it has.
        let unresolved = one(&objects, Kind::IpAddress, &address_identity("10.0.0.6"));
        assert!(!unresolved.fields.contains_key("dns_name"));
    }

    #[test]
    fn a_resolver_may_be_a_closure() {
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("10.0.0.5", "ipv4", 24)])]);
        let resolver = |address: IpAddr| Some(format!("host-{address}.example"));
        let objects = desired(&host_of(vec![web]), &settings(), &resolver).objects;
        assert_eq!(
            of_kind(&objects, Kind::IpAddress)[0].fields["dns_name"],
            serde_json::json!("host-10.0.0.5.example")
        );
    }

    #[test]
    fn the_dns_name_is_written_in_lower_case() {
        // support.py, reverse_lookup (netbox-sync): resolved_name = response.name.lower()
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("10.0.0.5", "ipv4", 24)])]);
        let resolver = |_: IpAddr| Some("WEB01.Lab.Example.".to_owned());
        let objects = desired(&host_of(vec![web]), &settings(), &resolver).objects;
        assert_eq!(of_kind(&objects, Kind::IpAddress)[0].fields["dns_name"], serde_json::json!("web01.lab.example"));
    }

    #[test]
    fn an_ipv6_address_gets_its_name_too() {
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("2001:db8::5", "ipv6", 64)])]);
        let names: BTreeMap<IpAddr, String> =
            BTreeMap::from([("2001:db8::5".parse().unwrap(), "web01.v6.example.".to_owned())]);
        let objects = desired(&host_of(vec![web]), &settings(), &names).objects;
        let address = one(&objects, Kind::IpAddress, &address_identity("2001:db8::5"));
        assert_eq!(address.fields["dns_name"], serde_json::json!("web01.v6.example"));
    }

    #[test]
    fn a_link_local_or_loopback_address_is_never_looked_up() {
        let addresses = [
            ("10.0.0.5", "ipv4", 24),
            ("169.254.7.7", "ipv4", 16),
            ("127.0.0.1", "ipv4", 8),
            ("fe80::be24:11ff:feaa:bbcc", "ipv6", 64),
            ("::1", "ipv6", 128),
            ("2001:db8::5", "ipv6", 64),
        ];
        let web = with_nics(101, "web01", vec![nic("eth0", "", &addresses)]);
        let asked = std::sync::Mutex::new(Vec::new());
        let resolver = |address: IpAddr| {
            asked.lock().unwrap().push(address.to_string());
            Some("answered.example".to_owned())
        };
        let objects = desired(&host_of(vec![web]), &settings(), &resolver).objects;
        assert_eq!(*asked.lock().unwrap(), ["10.0.0.5", "2001:db8::5"]);
        // The six addresses are synced as before; the four that are not looked up report no name.
        let named: Vec<&str> = of_kind(&objects, Kind::IpAddress)
            .into_iter()
            .filter(|address| address.fields.contains_key("dns_name"))
            .map(|address| address.fields["address"].as_str().unwrap())
            .collect();
        assert_eq!(of_kind(&objects, Kind::IpAddress).len(), 6);
        assert_eq!(named, ["10.0.0.5/24", "2001:db8::5/64"]);
    }

    #[test]
    fn a_link_local_or_loopback_address_listed_first_is_never_the_primary_one() {
        // A Windows guest lists the APIPA address of a disconnected adapter
        // before the one it is reached at.
        let web = with_nics(
            101,
            "web01",
            vec![
                nic("Ethernet 3", "", &[("169.254.210.12", "ipv4", 16), ("fe80::be24:11ff:feaa:bbcc", "ipv6", 64)]),
                nic("Loopback", "", &[("127.0.0.1", "ipv4", 8), ("::1", "ipv6", 128)]),
                nic("Ethernet", "", &[("10.3.29.130", "ipv4", 26), ("2001:db8::5", "ipv6", 64)]),
            ],
        );
        let objects = objects(&host_of(vec![web]), &settings());
        let web = guest(&objects, "web01");
        assert_eq!(web.references["primary_ip4"].as_ref().unwrap().identity, address_identity("10.3.29.130/26"));
        assert_eq!(web.references["primary_ip6"].as_ref().unwrap().identity, address_identity("2001:db8::5/64"));
    }

    #[test]
    fn a_guest_with_only_link_local_addresses_declares_no_primary_one() {
        let web = with_nics(
            101,
            "web01",
            vec![nic("Ethernet 2", "", &[("169.254.129.166", "ipv4", 16), ("fe80::1", "ipv6", 64)])],
        );
        let objects = objects(&host_of(vec![web]), &settings());
        let web = guest(&objects, "web01");
        assert!(!web.references.contains_key("primary_ip4"));
        assert!(!web.references.contains_key("primary_ip6"));
        // The addresses themselves are still synced.
        assert_eq!(of_kind(&objects, Kind::IpAddress).len(), 2);
    }

    #[test]
    fn a_name_netbox_would_refuse_is_not_reported_and_all_of_them_give_one_warning() {
        let addresses = [("10.0.0.5", "ipv4", 24), ("10.0.0.6", "ipv4", 24), ("10.0.0.7", "ipv4", 24)];
        let web = with_nics(101, "web01", vec![nic("eth0", "", &addresses)]);
        let names: BTreeMap<IpAddr, String> = BTreeMap::from([
            ("10.0.0.5".parse().unwrap(), "web 01.lab.example.".to_owned()),
            ("10.0.0.6".parse().unwrap(), "web01.lab.example.".to_owned()),
            ("10.0.0.7".parse().unwrap(), "web01..example.".to_owned()),
        ]);
        let translation = desired(&host_of(vec![web]), &settings(), &names);
        let name = |address: &str| {
            one(&translation.objects, Kind::IpAddress, &address_identity(address)).fields.get("dns_name").cloned()
        };
        assert_eq!(name("10.0.0.5"), None);
        assert_eq!(name("10.0.0.6"), Some(serde_json::json!("web01.lab.example")));
        assert_eq!(name("10.0.0.7"), None);
        assert_eq!(
            translation.warnings,
            ["reverse DNS: 2 names NetBox would refuse are not written \
              (10.0.0.5: \"web 01.lab.example.\", 10.0.0.7: \"web01..example.\")"]
        );
    }

    #[test]
    fn the_address_of_a_container_gets_its_name() {
        let eth0 = ContainerInterface {
            name: "eth0".to_owned(),
            mac: None,
            inet: Some("10.0.0.9/24".to_owned()),
            inet6: Some("2001:db8::9/64".to_owned()),
        };
        let web = Container { interfaces: Some(vec![eth0]), ..container(200, "ct-web") };
        let names: BTreeMap<IpAddr, String> = BTreeMap::from([
            ("10.0.0.9".parse().unwrap(), "CT-Web.lab.example.".to_owned()),
            ("2001:db8::9".parse().unwrap(), "ct-web.v6.example.".to_owned()),
        ]);
        let cluster = cluster(vec![Node { containers: vec![web], ..node("pve01") }]);
        let objects = desired(&cluster, &settings(), &names).objects;
        let address = one(&objects, Kind::IpAddress, &address_identity("2001:db8::9"));
        assert_eq!(address.fields["dns_name"], serde_json::json!("ct-web.v6.example"));
        let address = one(&objects, Kind::IpAddress, &address_identity("10.0.0.9"));
        assert_eq!(address.fields["dns_name"], serde_json::json!("ct-web.lab.example"));
    }

    #[test]
    fn a_prefix_only_has_to_exist_and_a_host_mask_gives_none() {
        let web = with_nics(
            101,
            "web01",
            vec![nic("eth0", "", &[("10.0.0.5", "ipv4", 24), ("10.9.9.9", "ipv4", 32), ("10.0.0.6", "ipv4", 24)])],
        );
        let objects = objects(
            &host_of(vec![web, with_nics(102, "db01", vec![nic("eth0", "", &[("10.0.0.7", "ipv4", 24)])])]),
            &settings(),
        );
        // networking.go, GetPrefixAndMaskFromIPAddress: 192.168.1.1/24 --> (192.168.1.0/24, 24)
        // proxmox_sync.go: ipAddress.IPAddressType == "ipv4" && mask != constants.MaxIPv4MaskBits (32)
        //   → nbi.AddPrefix(ps.Ctx, &objects.Prefix{Prefix: prefix, VRF: ipVRF})
        // add_items.go, AddPrefix: newPrefix.CustomFields[constants.CustomFieldSourceName] = source
        let expected = Desired::new(Kind::Prefix, Identity::prefix("10.0.0.0/24", VrfKey::Unknown), SOURCE)
            .field("prefix", "10.0.0.0/24")
            .custom_field(&custom_fields::SOURCE, SOURCE)
            .ensure_only();
        let found = of_kind(&objects, Kind::Prefix);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], &expected);
        assert_eq!(found[0].identity.key(), ["10.0.0.0/24", "*"]);
    }

    #[test]
    fn an_address_of_an_unknown_family_is_synced_without_prefix_nor_primary_and_warned_about() {
        let web = with_nics(101, "web01", vec![nic("eth0", "", &[("10.0.0.5", "inet", 24)])]);
        let translation = translate(&host_of(vec![web]), &settings());
        assert_eq!(labels(&translation.objects, Kind::IpAddress), ["10.0.0.5/24"]);
        assert_eq!(of_kind(&translation.objects, Kind::Prefix).len(), 0);
        assert!(!guest(&translation.objects, "web01").references.contains_key("primary_ip4"));
        // proxmox_sync.go: "wrong IP type: %s for ip %s"
        assert_eq!(translation.warnings, ["vm web01: wrong IP type: inet for ip 10.0.0.5"]);
    }

    #[test]
    fn an_address_that_is_not_one_is_skipped_with_a_warning() {
        let web =
            with_nics(101, "web01", vec![nic("eth0", "", &[("not-an-address", "ipv4", 24), ("10.0.0.5", "ipv4", 33)])]);
        let translation = translate(&host_of(vec![web]), &settings());
        assert_eq!(of_kind(&translation.objects, Kind::IpAddress).len(), 0);
        assert_eq!(
            translation.warnings,
            [
                "vm web01: not-an-address/24 on eth0 is not an IP address; skipped",
                "vm web01: 10.0.0.5/33 on eth0 is not an IP address; skipped",
            ]
        );
    }

    #[test]
    fn an_address_listed_twice_in_a_guest_is_declared_once_with_a_warning() {
        // NetBox identifies an address by its host: the same one on two interfaces of a guest is one object.
        let web = with_nics(
            101,
            "web01",
            vec![nic("eth0", "", &[("10.0.0.5", "ipv4", 24)]), nic("eth1", "", &[("10.0.0.5", "ipv4", 32)])],
        );
        let translation = translate(&host_of(vec![web]), &settings());
        let addresses = of_kind(&translation.objects, Kind::IpAddress);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].fields["address"], serde_json::json!("10.0.0.5/24"));
        assert_eq!(
            addresses[0].references["assigned_object"].as_ref().unwrap().identity,
            nic_identity("web01", "eth0")
        );
        assert_eq!(translation.warnings, ["vm web01: 10.0.0.5 is listed twice; the one on eth1 is skipped"]);
    }

    #[test]
    fn the_same_address_on_two_guests_is_two_objects() {
        let vms = vec![
            with_nics(101, "web01", vec![nic("eth0", "", &[("10.0.0.100", "ipv4", 24)])]),
            with_nics(102, "web02", vec![nic("eth0", "", &[("10.0.0.100", "ipv4", 24)])]),
        ];
        let translation = translate(&host_of(vms), &settings());
        let holders: Vec<Identity> = of_kind(&translation.objects, Kind::IpAddress)
            .iter()
            .map(|address| address.references["assigned_object"].as_ref().unwrap().identity.clone())
            .collect();
        assert_eq!(holders, [nic_identity("web01", "eth0"), nic_identity("web02", "eth0")]);
        assert_eq!(translation.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_interface_listed_twice_is_one_interface_whose_last_mac_is_the_primary_one() {
        let web = with_nics(
            101,
            "web01",
            vec![
                nic("Ethernet", "bc:24:11:00:00:01", &[("10.0.0.5", "ipv4", 24)]),
                nic("Ethernet", "bc:24:11:00:00:02", &[("10.0.0.6", "ipv4", 24)]),
            ],
        );
        let objects = objects(&host_of(vec![web]), &settings());
        // add_items.go, AddVMInterface: the interface is found again by its name
        //   (nbi.vmInterfacesIndexByVMIdAndName[newVMInterface.VM.ID][newVMInterface.Name]) and both MAC
        //   addresses are created for it; utils.go (common), SetPrimaryMACForInterface runs for each: the last wins.
        assert_eq!(labels(&objects, Kind::VmInterface), ["Ethernet"]);
        assert_eq!(labels(&objects, Kind::MacAddress), ["BC:24:11:00:00:01", "BC:24:11:00:00:02"]);
        assert_eq!(labels(&objects, Kind::IpAddress), ["10.0.0.5/24", "10.0.0.6/24"]);
        let interface = one(&objects, Kind::VmInterface, &nic_identity("web01", "Ethernet"));
        assert_eq!(
            interface.references["primary_mac_address"].as_ref().unwrap().identity,
            mac_identity("BC:24:11:00:00:02", "web01", "Ethernet")
        );
    }

    #[test]
    fn an_interface_without_name_is_skipped_with_a_warning() {
        let web = with_nics(101, "web01", vec![nic("", "bc:24:11:00:00:01", &[("10.0.0.5", "ipv4", 24)])]);
        let translation = translate(&host_of(vec![web]), &settings());
        for kind in [Kind::VmInterface, Kind::MacAddress, Kind::IpAddress] {
            assert_eq!(of_kind(&translation.objects, kind).len(), 0, "{kind:?}");
        }
        assert_eq!(translation.warnings, ["vm web01: an interface without name is skipped"]);
    }

    #[test]
    fn a_vm_interface_name_is_cut_at_64_bytes() {
        let name = "e".repeat(70);
        let web = with_nics(101, "web01", vec![nic(&name, "bc:24:11:00:00:01", &[("10.0.0.5", "ipv4", 24)])]);
        let objects = objects(&host_of(vec![web]), &settings());
        // add_items.go, AddVMInterface: newVMInterface.Name =
        //   newVMInterface.Name[:constants.MaxVMInterfaceNameLength] (64)
        let cut = "e".repeat(64);
        assert_eq!(labels(&objects, Kind::VmInterface), [cut.as_str()]);
        let address = of_kind(&objects, Kind::IpAddress)[0];
        assert_eq!(address.references["assigned_object"].as_ref().unwrap().identity, nic_identity("web01", &cut));
    }

    // -----------------------------------------------------------------------
    // Virtual disks
    // -----------------------------------------------------------------------

    #[test]
    fn a_disk_is_a_virtual_disk_named_after_its_volume_in_mebibytes() {
        let disks = vec![Disk {
            bus: DiskBus::Scsi,
            index: 0,
            name: "local-lvm:vm-101-disk-0".to_owned(),
            size_mib: 32_768,
            cdrom: false,
        }];
        let objects = objects(&host_of(vec![Vm { disks, ..vm(101, "web01") }]), &settings());
        // proxmox_sync.go, collectDisks: diskName := diskData[0];
        //   &objects.VirtualDisk{NetboxObject: objects.NetboxObject{Description: diskName}, Name: diskName, Size:
        //   diskSize}
        //   — diskSize from parseDiskSizeMiB: "size=32G" is 32 * 1024 MiB.
        // add_items.go, AddVirtualDisk: addSourceNameCustomField
        let identity = Identity::virtual_disk(&vm_identity("web01"), "local-lvm:vm-101-disk-0");
        let expected = Desired::new(Kind::VirtualDisk, identity.clone(), SOURCE)
            .field("name", "local-lvm:vm-101-disk-0")
            .field("size", 32_768)
            .field("description", "local-lvm:vm-101-disk-0")
            .reference("virtual_machine", Kind::VirtualMachine, vm_identity("web01"))
            .custom_field(&custom_fields::SOURCE, SOURCE);
        assert_eq!(one(&objects, Kind::VirtualDisk, &identity), expected);
    }

    #[test]
    fn a_cdrom_that_has_a_size_is_a_virtual_disk_too() {
        let disks = vec![
            Disk {
                bus: DiskBus::Scsi,
                index: 0,
                name: "store1:vm-disk-0.qcow2".to_owned(),
                size_mib: 15_360,
                cdrom: false,
            },
            Disk {
                bus: DiskBus::Ide,
                index: 1,
                name: "store1:vm-105-cloudinit.raw".to_owned(),
                size_mib: 4,
                cdrom: true,
            },
        ];
        let objects = objects(&host_of(vec![Vm { disks, ..vm(105, "web01") }]), &settings());
        // proxmox_sync.go, collectDisks: "Can't add disk with size == 0": the size alone decides, and a cloud-init
        // drive or an ISO image has one.
        assert_eq!(labels(&objects, Kind::VirtualDisk), ["store1:vm-disk-0.qcow2", "store1:vm-105-cloudinit.raw"]);
        let cloud_init = one(
            &objects,
            Kind::VirtualDisk,
            &Identity::virtual_disk(&vm_identity("web01"), "store1:vm-105-cloudinit.raw"),
        );
        assert_eq!(cloud_init.fields["size"], serde_json::json!(4));
    }

    #[test]
    fn a_disk_name_is_cut_at_64_bytes_and_its_description_is_not() {
        let volume = format!("store1:{}", "d".repeat(70));
        let disks = vec![Disk { bus: DiskBus::Virtio, index: 0, name: volume.clone(), size_mib: 1024, cdrom: false }];
        let objects = objects(&host_of(vec![Vm { disks, ..vm(101, "web01") }]), &settings());
        // add_items.go, AddVirtualDisk: newVirtualDisk.Name =
        //   newVirtualDisk.Name[:constants.MaxVirtualDiskNameLength] (64)
        let cut = format!("store1:{}", "d".repeat(57));
        let disk = of_kind(&objects, Kind::VirtualDisk)[0];
        assert_eq!(disk.fields["name"], serde_json::json!(cut));
        assert_eq!(disk.identity, Identity::virtual_disk(&vm_identity("web01"), &cut));
        // proxmox_sync.go, collectDisks: Description: diskName — only the name is cut.
        assert_eq!(disk.fields["description"], serde_json::json!(volume));
    }

    #[test]
    fn two_disks_of_a_vm_with_the_same_volume_are_declared_once_with_a_warning() {
        let disk = |index| Disk {
            bus: DiskBus::Scsi,
            index,
            name: "store1:shared.raw".to_owned(),
            size_mib: 1024 * (u64::from(index) + 1),
            cdrom: false,
        };
        let translation =
            translate(&host_of(vec![Vm { disks: vec![disk(0), disk(1)], ..vm(101, "web01") }]), &settings());
        let disks = of_kind(&translation.objects, Kind::VirtualDisk);
        assert_eq!(disks.len(), 1);
        // The first one in the order of the buses, where netbox-ssot kept whichever its map gave last.
        assert_eq!(disks[0].fields["size"], serde_json::json!(1024));
        assert_eq!(
            translation.warnings,
            ["vm web01: disk store1:shared.raw is listed twice; the second one is skipped"]
        );
    }

    // -----------------------------------------------------------------------
    // Containers
    // -----------------------------------------------------------------------

    #[test]
    fn a_container_is_a_virtual_machine_with_the_container_role() {
        let ct = Container {
            tags: vec!["service-dns".to_owned()],
            interfaces: Some(vec![ContainerInterface {
                name: "eth0".to_owned(),
                mac: Some("bc:24:11:00:00:c8".to_owned()),
                inet: Some("192.0.2.10/24".to_owned()),
                inet6: Some("2001:db8::10/64".to_owned()),
            }]),
            ..container(200, "ct01")
        };
        let objects = objects(&cluster(vec![Node { containers: vec![ct], ..node("pve01") }]), &settings());

        let expected = Desired::new(Kind::VirtualMachine, vm_identity("ct01"), SOURCE)
            .field("name", "ct01")
            // proxmox_sync.go, syncContainers: containerStatus := &objects.VMStatusActive
            .field("status", "active")
            // VCPUs: float32(container.CPUs)
            .field("vcpus", 1)
            // Memory: int(container.MaxMem / constants.MiB) — 536870912 / 1048576 = 512
            .field("memory", 512)
            // Disk: int(container.MaxDisk / constants.MiB) — 8589934592 / 1048576 = 8192
            .field("disk", 8192)
            // Host: nbHost
            .reference("device", Kind::Device, Identity::device("pve01"))
            // Role: containerRole — AddContainerDeviceRole: Name: constants.DeviceRoleContainer ("Container")
            .reference("role", Kind::Role, Identity::named("Container"))
            .reference("primary_ip4", Kind::IpAddress, address_identity("192.0.2.10"))
            .reference("primary_ip6", Kind::IpAddress, address_identity("2001:db8::10"))
            .tags(["service-dns"])
            // CustomFields: constants.CustomFieldSourceIDName: fmt.Sprintf("%d", container.VMID); AddVM adds "source".
            .custom_field(&custom_fields::SOURCE, SOURCE)
            .custom_field(&custom_fields::SOURCE_ID, "200");
        // No platform: syncContainers sets none, and a nil platform is left as NetBox has it.
        assert_eq!(guest(&objects, "ct01"), cluster_reference(site_reference(expected)));

        assert_eq!(labels(&objects, Kind::VmInterface), ["eth0"]);
        // proxmox_sync.go, syncContainerNetworks: vmIfaceMAC := strings.ToUpper(containerIface.HWAddr)
        assert_eq!(labels(&objects, Kind::MacAddress), ["BC:24:11:00:00:C8"]);
        // Address: containerIface.Inet — the address comes with its mask.
        let inet = Desired::new(Kind::IpAddress, address_identity("192.0.2.10"), SOURCE)
            .field("address", "192.0.2.10/24")
            .field("status", "active")
            .reference("assigned_object", Kind::VmInterface, nic_identity("ct01", "eth0"))
            .custom_field(&custom_fields::ARP_ENTRY, false)
            .custom_field(&custom_fields::SOURCE, SOURCE);
        assert_eq!(one(&objects, Kind::IpAddress, &address_identity("192.0.2.10")), inet);
        assert_eq!(
            one(&objects, Kind::IpAddress, &address_identity("2001:db8::10")).fields["address"],
            serde_json::json!("2001:db8::10/64")
        );
        // proxmox_sync.go, syncContainerNetworks: AddPrefix is only called for the IPv4 address
        // ("} else if mask != constants.MaxIPv4MaskBits {"); the IPv6 branch adds no prefix.
        assert_eq!(labels(&objects, Kind::Prefix), ["192.0.2.0/24"]);
        assert_eq!(labels(&objects, Kind::Tag), ["service-dns"]);
        assert_eq!(of_kind(&objects, Kind::Platform).len(), 0);
    }

    #[test]
    fn a_stopped_container_is_offline_and_its_interfaces_are_unknown() {
        let ct = Container { status: "stopped".to_owned(), interfaces: None, ..container(200, "ct01") };
        let objects = objects(&cluster(vec![Node { containers: vec![ct], ..node("pve01") }]), &settings());
        let found = guest(&objects, "ct01");
        // proxmox_sync.go: if container.Status == "stopped" { containerStatus = &objects.VMStatusOffline }
        assert_eq!(found.fields["status"], serde_json::json!("offline"));
        // proxmox_sync.go: "Sync container networks, or keep the known ones when they could not be read"
        assert_eq!(found.unknown_dependents, BTreeSet::from([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]));
        assert_eq!(of_kind(&objects, Kind::VmInterface).len(), 0);
    }

    #[test]
    fn a_container_follows_the_subnets_and_the_interface_filter() {
        let interface = |name: &str, inet: &str, inet6: &str| ContainerInterface {
            name: name.to_owned(),
            mac: None,
            inet: Some(inet.to_owned()),
            inet6: Some(inet6.to_owned()),
        };
        let ct = Container {
            interfaces: Some(vec![
                interface("eth0", "192.0.2.10/24", "fe80::10%eth0/64"),
                interface("veth0", "192.0.2.11/24", "fe80::11/64"),
            ]),
            ..container(200, "ct01")
        };
        let nodes = || cluster(vec![Node { containers: vec![ct.clone()], ..node("pve01") }]);
        assert_eq!(labels(&objects(&nodes(), &production()), Kind::IpAddress), ["192.0.2.10/24"]);
        // networking.go, RemoveZoneIndexFromIPAddress: e.g. 2001:db8::1%2/64 -> 2001:db8::1/64
        assert_eq!(
            labels(&objects(&nodes(), &settings()), Kind::IpAddress),
            ["192.0.2.10/24", "fe80::10/64", "192.0.2.11/24", "fe80::11/64"]
        );
    }

    #[test]
    fn a_container_without_root_disk_size_does_not_report_it() {
        // virtualization.go: Disk int `json:"disk,omitempty"`
        let ct = Container { max_disk_bytes: 0, ..container(200, "ct01") };
        let objects = objects(&cluster(vec![Node { containers: vec![ct], ..node("pve01") }]), &settings());
        assert!(!guest(&objects, "ct01").fields.contains_key("disk"));
    }

    // -----------------------------------------------------------------------
    // The whole
    // -----------------------------------------------------------------------

    #[test]
    fn every_object_is_declared_once_by_the_source() {
        let debian = |vmid, name: &str| Vm {
            tags: vec!["service-apache".to_owned()],
            os_info: Some(GuestOsInfo {
                pretty_name: Some("Debian GNU/Linux 12 (bookworm)".to_owned()),
                ..GuestOsInfo::default()
            }),
            ..with_nics(vmid, name, vec![nic("eth0", "bc:24:11:00:00:01", &[("10.0.0.5", "ipv4", 24)])])
        };
        let nodes = vec![
            Node { vms: vec![debian(101, "web01")], networks: vec![network("eno1", "eth")], ..node("pve01") },
            Node { vms: vec![debian(102, "web02")], networks: vec![network("eno1", "eth")], ..node("pve02") },
        ];
        let objects = objects(&cluster(nodes), &settings());
        assert!(objects.iter().all(|object| object.source == SOURCE));
        // Two guests may hold the same address: an address is told apart by its interface.
        let mut seen = BTreeSet::new();
        for object in &objects {
            let holder = object
                .references
                .get("assigned_object")
                .and_then(Option::as_ref)
                .map(|target| target.identity.key().to_vec());
            assert!(
                seen.insert((object.kind, object.identity.key().to_vec(), holder)),
                "{:?} {:?} twice",
                object.kind,
                object.identity.key()
            );
        }
        // The same MAC and address on both guests, and everything they share once.
        let count = |kind| of_kind(&objects, kind).len();
        assert_eq!(
            [
                Kind::Tag,
                Kind::Site,
                Kind::Manufacturer,
                Kind::DeviceType,
                Kind::Platform,
                Kind::Role,
                Kind::ClusterType,
                Kind::Cluster,
                Kind::Prefix
            ]
            .map(count),
            [1, 1, 1, 1, 1, 2, 1, 1, 1]
        );
        assert_eq!(
            [Kind::Device, Kind::VirtualMachine, Kind::Interface, Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]
                .map(count),
            [2; 6]
        );
    }
}
