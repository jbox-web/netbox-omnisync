//! Turns what was read from a vCenter into the NetBox objects the source asks
//! for.
//!
//! One pure function, [`desired`]: no I/O, no clock. It replaces the VMware
//! source of netbox-sync v1.8.0 (`module/sources/vmware/connection.py`), whose
//! names, units, truncations and texts it keeps to the letter, as inventoried
//! in `docs/vmware-reference.md`: the first run on a NetBox that netbox-sync
//! filled must change nothing but ownership tags.
//!
//! Three rules shape the module. What vCenter did not report is unknown, never
//! empty: it is not declared, NetBox keeps what it has, and the dependents
//! that could not be read (the addresses of a guest whose tools do not run)
//! are marked unknown instead of absent. What netbox-sync did wrong is not
//! reproduced: `docs/reference-defects.md` lists each case. And what was never
//! observed on a real vCenter (a distributed switch) is not guessed: it stays
//! unreported, with a warning.
//!
//! Not done here, because it needs NetBox or the network: the reverse DNS
//! lookup (it is handed in; an address it knows no name for declares no
//! `dns_name`, and NetBox keeps the one it has), the VRF of an address (looked
//! up in every table), and the matching of a renamed host or machine: the
//! reconciliation recognises it by its MAC addresses, and nothing matches it
//! by its serial.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use omnisync_core::inventory::custom_fields;
use omnisync_core::inventory::dns::{Names, ReverseDns};
use omnisync_core::inventory::hardware::{format_slug, manufacturer_name};
use omnisync_core::inventory::model::{Desired, Identity, Kind, Target, VlanScope, VrfKey};
use omnisync_core::network::hosts::Heard;
use regex::Regex;

use crate::collect::{DistributedPortGroup, Inventory};
use crate::model::{Disk, Host, Machine, MachineNic, NicBacking, PhysicalNic, PortGroup, VirtualNic, VirtualSwitch};

/// What follows the name of a Windows in what its tools report: `Windows 11 Pro, 64-bit (Build 22631.6783)`.
const WINDOWS_BUILD: &str = " (Build";

/// Name of the cluster type; its slug is the slug of this name.
const CLUSTER_TYPE: &str = "VMware ESXi";

/// What netbox-sync named the hardware of a host that tells none.
const GENERIC_VENDOR: &str = "Generic Vendor";
const GENERIC_MODEL: &str = "Generic Model";

/// The role netbox-sync gave a host when its configuration named none.
const DEFAULT_HOST_ROLE: &str = "Server";

/// The marker written in the description of a tag made from a vSphere tag
/// (see the constant in the model), followed by `: ` and the vSphere
/// description when there is one. The reconciliation tells such a tag from one
/// set by hand by this very text (`Run::source_tag_markers`).
pub use omnisync_core::inventory::model::TAG_MARKER;

/// The longest texts NetBox takes, in characters as netbox-sync counted them.
const MAX_NAME: usize = 64;
const MAX_LONG_NAME: usize = 100;
const MAX_DESCRIPTION: usize = 200;
const MAX_SERIAL: usize = 50;

/// The states vCenter gives a host that answers and a machine that runs.
const CONNECTED: &str = "connected";
const POWERED_ON: &str = "poweredOn";
/// Only tools in this state tell the addresses of a guest.
const TOOLS_RUNNING: &str = "guestToolsRunning";

/// A vmkernel interface whose description holds one of these carries the
/// primary address of its host (`host_management_interface_match`).
const MANAGEMENT_MARKS: [&str; 2] = ["management", "mgmt"];

/// The identifiers of a host that are its serial, the first one found winning.
const SERIAL_IDENTIFIERS: [&str; 3] = ["SerialNumberTag", "ServiceTag", "EnclosureSerialNumberTag"];
const ASSET_TAG_IDENTIFIER: &str = "AssetTag";

/// What a firmware answers when nobody set an asset tag: not an asset tag.
const BANNED_ASSET_TAGS: [&str; 9] =
    ["default string", "na", "n/a", "none", "null", "oem", "o.e.m", "to be filled by o.e.m.", "unknown"];

/// "Every VLAN" on a port group; neither it nor anything above is a VLAN.
const ALL_VLANS: u32 = 4095;

/// The NetBox interface type netbox-sync gave a physical card of that speed, in Mb/s.
const SPEED_TYPES: [(u64, &str); 11] = [
    (100, "100base-tx"),
    (1_000, "1000base-t"),
    (2_500, "2.5gbase-t"),
    (5_000, "5gbase-t"),
    (10_000, "10gbase-x-sfpp"),
    (25_000, "25gbase-x-sfp28"),
    (40_000, "40gbase-x-qsfpp"),
    (50_000, "50gbase-x-sfp28"),
    (100_000, "100gbase-x-qsfp28"),
    (200_000, "200gbase-x-qsfp56"),
    (400_000, "400gbase-x-qsfpdd"),
];

/// Why a vCenter cannot be translated at all.
///
/// An object that cannot be placed (a machine whose host was not reported)
/// cannot be named in NetBox either, so it could not even be protected: the
/// run would take it for gone and delete it. Nothing is synced instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranslateError {
    #[error("{what}: {reason}; nothing is synced from this vCenter")]
    Unplaced { what: String, reason: String },
}

fn unplaced<T>(what: String, reason: &str) -> Result<T, TranslateError> {
    Err(TranslateError::Unplaced { what, reason: reason.to_owned() })
}

/// How one vCenter is translated. The configuration loader fills it.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Name of the source.
    pub source: String,
    /// The NetBox site of the clusters, of their hosts, of their machines and
    /// of the VLANs the tool creates.
    pub site: String,
    /// The NetBox VLAN group the VLANs of that site are kept in, when it
    /// shares them with other sites; `None`: the VLANs are those of the site.
    pub vlan_group: Option<String>,
    /// The NetBox tenant of the clusters, of their hosts, of their machines
    /// and of the addresses of both; `None` leaves the tenants as NetBox has them.
    pub tenant: Option<String>,
    /// The NetBox role of the hosts; `None` is netbox-sync's `Server`.
    pub host_role: Option<String>,
    /// The NetBox role of the virtual machines; `None` leaves it as NetBox has it.
    pub vm_role: Option<String>,
    /// Leave the templates out (`skip_vm_templates`).
    pub ignore_templates: bool,
    /// An address inside one of these is not synced; wins over `permitted_subnets`.
    pub ignored_subnets: Vec<IpNet>,
    /// When not empty, only an address inside one of these is synced.
    pub permitted_subnets: Vec<IpNet>,
    /// An interface, of a host or of a machine, whose name matches anywhere
    /// is not synced, nor are its addresses.
    pub interface_filter: Option<Regex>,
}

impl Settings {
    /// The settings of a source that sets nothing but its name and its site:
    /// the defaults of netbox-sync.
    pub fn new(source: &str, site: &str) -> Self {
        Settings {
            source: source.to_owned(),
            site: site.to_owned(),
            vlan_group: None,
            tenant: None,
            host_role: None,
            vm_role: None,
            ignore_templates: true,
            ignored_subnets: Vec::new(),
            permitted_subnets: Vec::new(),
            interface_filter: None,
        }
    }

    /// Whether an interface of that name is left out.
    fn filters(&self, interface: &str) -> bool {
        self.interface_filter.as_ref().is_some_and(|filter| filter.is_match(interface))
    }

    /// Whether an address is synced: never a link-local or a loopback one,
    /// outside every ignored subnet, and inside a permitted one when some are given.
    fn permits(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        let link_local = match address {
            IpAddr::V4(address) => address.is_link_local(),
            IpAddr::V6(address) => address.is_unicast_link_local(),
        };
        let within = |subnets: &[IpNet]| subnets.iter().any(|subnet| subnet.contains(&address));
        !link_local
            && !address.is_loopback()
            && !within(&self.ignored_subnets)
            && (self.permitted_subnets.is_empty() || within(&self.permitted_subnets))
    }
}

/// What a vCenter asks of NetBox.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Translation {
    /// Every object once, in a stable order.
    pub objects: Vec<Desired>,
    /// What was left out, and why.
    pub warnings: Vec<String>,
    /// The switch port each physical card of each host hears, when the hints
    /// were read, under the NetBox name of the host.
    pub heard: Vec<Heard>,
}

/// A text cut to `max` characters, as netbox-sync cut its strings.
fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// A text without the spaces around it; `None` when nothing is left.
fn stripped(text: Option<&str>) -> Option<&str> {
    text.map(str::trim).filter(|text| !text.is_empty())
}

fn hex(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).and_then(|digit| u8::try_from(digit).ok())
}

/// A name as it was typed: vSphere writes `%2f` for the `/` of a network or
/// switch name. Python's `urllib.parse.unquote`: what is not an escape is kept.
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped =
            (bytes[at] == b'%').then(|| Some(hex(*bytes.get(at + 1)?)? * 16 + hex(*bytes.get(at + 2)?)?)).flatten();
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                at += 3;
            }
            None => {
                decoded.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// A link speed in kbit/s, as NetBox takes it, from one in Mbit/s; None when
/// the value cannot be one (an absurd one, read from XML).
fn kilobits(speed_mb: u64) -> Option<u64> {
    speed_mb.checked_mul(1000)
}

/// MiB as megabytes in powers of ten, as netbox-sync wrote them
/// (`vm_disk_and_ram_in_decimal`): 4096 MiB is 4000.
fn decimal_megabytes(mib: u64) -> Option<u64> {
    mib.checked_mul(1000).map(|scaled| scaled / 1024)
}

/// A MAC address in upper case, with colons; empty for anything that is not
/// twelve hexadecimal digits (with colons, dashes or dots, or without).
fn normalized_mac(mac: &str) -> String {
    let digits: Vec<char> = mac.trim().chars().filter(|character| !matches!(character, ':' | '-' | '.')).collect();
    if digits.len() != 12 || !digits.iter().all(char::is_ascii_hexdigit) {
        return String::new();
    }
    let digits: String = digits.into_iter().collect::<String>().to_uppercase();
    let pairs: Vec<&str> = (0..12).step_by(2).map(|start| &digits[start..start + 2]).collect();
    pairs.join(":")
}

/// The NetBox type of a physical card of that speed.
fn interface_type(speed_mb: Option<u64>) -> &'static str {
    let known = speed_mb.and_then(|speed| SPEED_TYPES.iter().find(|(known, _)| *known == speed));
    known.map_or("other", |(_, name)| name)
}

/// The memory of a host as netbox-sync wrote it: whole GB, or TB from 1024 GB up.
fn host_memory(bytes: u64) -> String {
    // Python's `round`: to the nearest, a tie to the even one.
    #[allow(clippy::cast_precision_loss)]
    let gigabytes = (bytes as f64 / 1024_f64.powi(3)).round_ties_even();
    if gigabytes >= 1024.0 {
        // Python prints the quotient as a float: `1.5`, `2.0`.
        format!("{:?} TB", gigabytes / 1024.0)
    } else {
        format!("{gigabytes} GB")
    }
}

/// The number at the end of a managed object id (`vm-4513`): the lower, the
/// older the object.
fn object_number(id: &str) -> u64 {
    id.rsplit('-').next().and_then(|number| number.parse().ok()).unwrap_or(u64::MAX)
}

/// The mode of an interface on a standard port group of that VLAN.
fn port_group_mode(vlan_id: u32) -> &'static str {
    if vlan_id == ALL_VLANS { "tagged-all" } else { "access" }
}

/// An address with its mask, as vSphere gave them.
struct Address {
    ip: IpAddr,
    net: IpNet,
}

/// Parses an address and its prefix length; `None` when either is not one.
fn address(host: &str, prefix: Option<u8>) -> Option<Address> {
    let ip: IpAddr = host.trim().parse().ok()?;
    let net = IpNet::new(ip, prefix?).ok()?;
    Some(Address { ip, net })
}

/// The interfaces of one device or machine, as they are gathered.
#[derive(Default)]
struct Network {
    /// The interfaces by name, in the order they were listed.
    interfaces: Vec<(String, Desired)>,
    /// MAC and IP addresses, in the order they were listed.
    addresses: Vec<Desired>,
    /// The addresses declared: NetBox identifies an address by its host, so
    /// the same one on two interfaces of an object is one object.
    declared: Vec<Address>,
}

struct Translator<'a> {
    inventory: &'a Inventory,
    settings: &'a Settings,
    /// The DNS names of the addresses, from the reverse lookup handed in.
    names: Names<'a>,
    objects: Vec<Desired>,
    /// The objects several others refer to, declared once.
    shared: BTreeSet<(Kind, Vec<String>)>,
    warnings: Vec<String>,
    /// The NetBox cluster of each cluster or compute resource, by vSphere id.
    clusters: BTreeMap<&'a str, String>,
    /// The NetBox device of each host, by vSphere id.
    devices: BTreeMap<&'a str, String>,
    /// What the cards of the hosts hear, host by host as they are translated.
    heard: Vec<Heard>,
}

/// The NetBox objects `inventory` asks for.
///
/// Everything netbox-sync wrote for a vCenter with the production settings:
/// the cluster groups, the cluster type and the clusters, the hosts with their
/// interfaces, MAC and IP addresses, the virtual machines with theirs and
/// their disks, the VLANs of the port groups, and what those refer to (site,
/// tenant, roles, platforms, manufacturers, device types, tags).
pub fn desired(
    inventory: &Inventory,
    settings: &Settings,
    resolver: &dyn ReverseDns,
) -> Result<Translation, TranslateError> {
    let mut translator = Translator {
        inventory,
        settings,
        names: Names::new(resolver),
        objects: Vec::new(),
        shared: BTreeSet::new(),
        warnings: Vec::new(),
        clusters: BTreeMap::new(),
        devices: BTreeMap::new(),
        heard: Vec::new(),
    };
    translator.base();
    translator.clusters()?;
    translator.hosts()?;
    translator.machines()?;
    translator.distributed_switches();
    translator.warnings.extend(translator.names.warning());
    Ok(Translation { objects: translator.objects, warnings: translator.warnings, heard: translator.heard })
}

impl<'a> Translator<'a> {
    fn new_object(&self, kind: Kind, identity: Identity) -> Desired {
        Desired::new(kind, identity, &self.settings.source)
    }

    /// Declares an object several others may refer to, the first time only.
    fn share(&mut self, object: Desired) {
        if self.shared.insert((object.kind, object.identity.key().to_vec())) {
            self.objects.push(object);
        }
    }

    /// An object identified by its name, with the slug netbox-sync gave one it created.
    fn named(&self, kind: Kind, name: &str) -> Desired {
        self.new_object(kind, Identity::named(name))
            .field("name", name)
            .create_only("slug", format_slug(name, MAX_LONG_NAME))
    }

    /// An object the source only needs to exist: found in NetBox and owned by
    /// no tool, it is used as it is.
    fn existing(&self, kind: Kind, name: &str) -> Desired {
        self.named(kind, name).ensure_only()
    }

    fn with_site(&self, object: Desired) -> Desired {
        object.reference("site", Kind::Site, Identity::named(&self.settings.site))
    }

    /// Sets the tenant of the settings; without one nothing is said, and
    /// NetBox keeps the tenant it has.
    fn with_tenant(&self, object: Desired) -> Desired {
        match &self.settings.tenant {
            Some(tenant) => object.reference("tenant", Kind::Tenant, Identity::named(tenant)),
            None => object,
        }
    }

    /// The site, the tenant and the cluster type.
    fn base(&mut self) {
        let settings = self.settings;
        let site = self.existing(Kind::Site, &settings.site);
        self.share(site);
        if let Some(tenant) = &settings.tenant {
            let tenant = self.existing(Kind::Tenant, tenant);
            self.share(tenant);
        }
        let cluster_type = self.named(Kind::ClusterType, CLUSTER_TYPE);
        self.share(cluster_type);
    }

    /// Each datacenter as a cluster group, each cluster and each standalone
    /// compute resource as a cluster of that group.
    fn clusters(&mut self) -> Result<(), TranslateError> {
        let inventory = self.inventory;
        // The datacenter of each NetBox cluster name: NetBox names a cluster once.
        let mut declared: BTreeMap<String, String> = BTreeMap::new();
        for cluster in &inventory.clusters {
            let what = format!("cluster {}", cluster.name.as_deref().unwrap_or(&cluster.id));
            let Some(name) = stripped(cluster.name.as_deref()) else {
                return unplaced(what, "vCenter reports no name for it");
            };
            let name = cut(name, MAX_LONG_NAME);
            let datacenter = cluster.parent.as_ref().and_then(|parent| inventory.datacenter_of(parent));
            let Some(group) = datacenter.and_then(|datacenter| stripped(datacenter.name.as_deref())) else {
                return unplaced(what, "its datacenter is not reported");
            };
            let group = cut(group, MAX_LONG_NAME);
            self.clusters.insert(cluster.id.as_str(), name.clone());
            let group_object = self.named(Kind::ClusterGroup, &group);
            self.share(group_object);
            match declared.get(&name.to_lowercase()) {
                Some(other) if *other != group => self.warnings.push(format!(
                    "cluster {name} exists in datacenters {other} and {group}: NetBox names a cluster once, \
                     both are synced as the one of {other}"
                )),
                Some(_) => {}
                None => {
                    declared.insert(name.to_lowercase(), group.clone());
                }
            }
            let object = self
                .new_object(Kind::Cluster, Identity::named(&name))
                .field("name", name.as_str())
                .reference("type", Kind::ClusterType, Identity::named(CLUSTER_TYPE))
                .reference("group", Kind::ClusterGroup, Identity::named(&group))
                .reference("scope", Kind::Site, Identity::named(&self.settings.site));
            let object = self.with_tenant(object);
            self.share(object);
        }
        Ok(())
    }

    /// The switch port each physical card of a host hears, under the names
    /// NetBox has for the host and for its card.
    fn heard_by(&mut self, host: &Host, name: &str) {
        let Some(cards) = self.inventory.hints.get(&host.id) else {
            return;
        };
        for card in cards {
            let Some(port) = &card.switch_port else {
                continue;
            };
            self.heard.push(Heard {
                host: name.to_owned(),
                card: cut(&unquote(&card.device), MAX_NAME),
                switch: port.device_id.trim().to_owned(),
                port: port.port_id.trim().to_owned(),
            });
        }
    }

    /// The hosts, by name: the order vCenter lists them in decides nothing.
    fn hosts(&mut self) -> Result<(), TranslateError> {
        let inventory = self.inventory;
        let mut hosts: Vec<(&str, &Host)> = Vec::new();
        for host in &inventory.hosts {
            let Some(name) = stripped(host.name.as_deref()) else {
                return unplaced(format!("host {}", host.id), "vCenter reports no name for it");
            };
            hosts.push((name, host));
        }
        hosts.sort_by_key(|(name, host)| (name.to_lowercase(), object_number(&host.id), host.id.as_str()));
        let mut declared: BTreeMap<String, &str> = BTreeMap::new();
        for (full_name, host) in hosts {
            let what = format!("host {full_name}");
            let Some(cluster) = inventory.cluster_of(host).and_then(|cluster| self.clusters.get(cluster.id.as_str()))
            else {
                return unplaced(what, "its cluster is not reported");
            };
            let cluster = cluster.clone();
            let name = cut(full_name, MAX_NAME);
            self.devices.insert(host.id.as_str(), name.clone());
            // NetBox names a device once: a second host of that name is the same device.
            if let Some(kept) = declared.get(&name.to_lowercase()) {
                self.warnings.push(format!(
                    "skipping host {full_name} ({}): name already used by {kept}; host names must be unique",
                    host.id
                ));
                continue;
            }
            declared.insert(name.to_lowercase(), host.id.as_str());
            self.host(host, &name, &cluster);
            self.heard_by(host, &name);
        }
        Ok(())
    }

    /// The manufacturer and the device type of a host; returns the identity of the type.
    fn device_type(&mut self, host: &Host) -> Identity {
        let vendor = stripped(host.vendor.as_deref()).unwrap_or(GENERIC_VENDOR);
        let manufacturer = cut(manufacturer_name(vendor), MAX_LONG_NAME);
        let model = cut(stripped(host.model.as_deref()).unwrap_or(GENERIC_MODEL), MAX_LONG_NAME);
        let manufacturer_object = self.named(Kind::Manufacturer, &manufacturer);
        self.share(manufacturer_object);
        let identity = Identity::device_type(&manufacturer, &model);
        let device_type = self
            .new_object(Kind::DeviceType, identity.clone())
            .field("model", model.as_str())
            .create_only("slug", format_slug(&model, MAX_LONG_NAME))
            .reference("manufacturer", Kind::Manufacturer, Identity::named(&manufacturer));
        self.share(device_type);
        identity
    }

    /// The serial and the asset tag of a host, from its identifiers.
    fn identifiers(host: &Host) -> (Option<String>, Option<String>) {
        // For a kind listed twice the last value wins; an empty one is no value.
        let mut values: BTreeMap<&str, &str> = BTreeMap::new();
        for (kind, value) in &host.identifiers {
            if !value.trim().is_empty() {
                values.insert(kind.as_str(), value.trim());
            }
        }
        let serial = SERIAL_IDENTIFIERS.iter().find_map(|kind| values.get(kind)).map(|serial| cut(serial, MAX_SERIAL));
        let asset_tag = values
            .get(ASSET_TAG_IDENTIFIER)
            .filter(|tag| !BANNED_ASSET_TAGS.contains(&tag.to_lowercase().as_str()))
            .map(|tag| cut(tag, MAX_SERIAL));
        (serial, asset_tag)
    }

    /// A host as a device, with its interfaces and their addresses.
    fn host(&mut self, host: &Host, name: &str, cluster: &str) {
        let settings = self.settings;
        let device_type = self.device_type(host);
        let role = settings.host_role.as_deref().unwrap_or(DEFAULT_HOST_ROLE);
        let role_object = self.existing(Kind::Role, role);
        self.share(role_object);
        let identity = Identity::device(name);
        let mut device = self
            .new_object(Kind::Device, identity)
            .field("name", name)
            .reference("device_type", Kind::DeviceType, device_type)
            .reference("cluster", Kind::Cluster, Identity::named(cluster))
            .reference("role", Kind::Role, Identity::named(role));
        device = self.with_tenant(self.with_site(device));
        // A state that was not reported says nothing: the status NetBox has is kept.
        if let Some(state) = host.connection_state.as_deref() {
            device = device.field("status", if state == CONNECTED { "active" } else { "offline" });
        }
        let (serial, asset_tag) = Self::identifiers(host);
        if let Some(serial) = serial {
            device = device.field("serial", serial);
        }
        if let Some(asset_tag) = asset_tag {
            device = device.field("asset_tag", asset_tag);
        }
        // `VMware ESXi 6.7.0`; without the product or its version nothing is said.
        let product = stripped(host.product_name.as_deref()).zip(stripped(host.product_version.as_deref()));
        if let Some((product, version)) = product {
            let platform = cut(&format!("{product} {version}"), MAX_LONG_NAME);
            let platform_object = self.named(Kind::Platform, &platform);
            self.share(platform_object);
            device = device.reference("platform", Kind::Platform, Identity::named(&platform));
        }
        if let Some((cores, model)) = host.cpu_cores.zip(host.cpu_model.as_deref()) {
            device = device.custom_field(&custom_fields::HOST_CPU_CORES, format!("{cores} {model}"));
        }
        if let Some(bytes) = host.memory_bytes {
            device = device.custom_field(&custom_fields::HOST_MEMORY, host_memory(bytes));
        }

        let mut network = Network::default();
        let mut primary = (None, None);
        let mut unknown = false;
        match &host.pnics {
            Some(pnics) => {
                for pnic in pnics {
                    self.physical_nic(host, name, pnic, &mut network);
                }
            }
            None => unknown = true,
        }
        match &host.vnics {
            Some(vnics) => {
                for vnic in vnics {
                    self.vmkernel_nic(host, name, vnic, &mut network, &mut primary);
                }
            }
            None => unknown = true,
        }
        if unknown {
            // Unknown is not empty: what NetBox has under this host is kept.
            device = device.unknown_dependents([Kind::Interface, Kind::MacAddress, Kind::IpAddress]);
        }
        device = Self::with_primary(device, primary);
        self.objects.push(device);
        self.objects.extend(network.interfaces.into_iter().map(|(_, interface)| interface));
        self.objects.extend(network.addresses);
    }

    /// Declares the primary addresses: written only when NetBox holds none, so
    /// that one picked by hand survives every run (`set_primary_ip = when-undefined`).
    fn with_primary(mut object: Desired, primary: (Option<Identity>, Option<Identity>)) -> Desired {
        for (field, identity) in [("primary_ip4", primary.0), ("primary_ip6", primary.1)] {
            if let Some(identity) = identity {
                object = object.reference(field, Kind::IpAddress, identity).only_when_empty(field);
            }
        }
        object
    }

    /// The VLAN of a port group, declared for creation at the site: one found
    /// in NetBox is used as it is, its name included. `None` for "no VLAN",
    /// "every VLAN" and what is not a VLAN id.
    ///
    /// A site that shares its VLANs keeps them in its VLAN group: the VLAN is
    /// then the one of the group, and has no site — NetBox refuses a VLAN of
    /// a site on an interface of another one. The group itself is only
    /// referred to: it is a prerequisite, never created here.
    fn vlan(&mut self, vlan_id: u32, name: &str) -> Option<Target> {
        if vlan_id == 0 || vlan_id >= ALL_VLANS {
            return None;
        }
        let settings = self.settings;
        let scope = match &settings.vlan_group {
            Some(group) => VlanScope::Group(group),
            None => VlanScope::Site(&settings.site),
        };
        let identity = Identity::vlan(scope, u64::from(vlan_id));
        let object = self
            .new_object(Kind::Vlan, identity.clone())
            .field("vid", vlan_id)
            .create_only("name", cut(&unquote(name), MAX_NAME))
            .ensure_only();
        let object = match &settings.vlan_group {
            Some(group) => object.reference("group", Kind::VlanGroup, Identity::named(group)),
            None => self.with_site(object),
        };
        self.share(object);
        Some(Target::new(Kind::Vlan, identity))
    }

    /// Adds an interface to the network of its owner; false, with a warning,
    /// when one of that name is there already.
    fn add_interface(&mut self, who: &str, name: &str, interface: Desired, network: &mut Network) -> bool {
        if network.interfaces.iter().any(|(known, _)| known.to_lowercase() == name.to_lowercase()) {
            self.warnings.push(format!("{who}: interface {name} is listed twice; the second one is skipped"));
            return false;
        }
        network.interfaces.push((name.to_owned(), interface));
        true
    }

    /// Declares the MAC address of an interface and makes it its primary one.
    fn mac(&self, interface: Desired, mac: Option<&str>, network: &mut Network) -> Desired {
        let Some(mac) = mac.map(normalized_mac).filter(|mac| !mac.is_empty()) else {
            return interface;
        };
        let target = Target::new(interface.kind, interface.identity.clone());
        let identity = Identity::mac_address(&mac, Some(&target));
        let object = self.new_object(Kind::MacAddress, identity.clone()).field("mac_address", mac.as_str()).reference(
            "assigned_object",
            target.kind,
            target.identity,
        );
        network.addresses.push(object);
        interface.reference("primary_mac_address", Kind::MacAddress, identity)
    }

    /// Declares an address on an interface, when it is one and is permitted;
    /// returns its identity when it was declared.
    fn ip(
        &mut self,
        who: &str,
        interface: &Target,
        found: Option<Address>,
        written: &str,
        network: &mut Network,
    ) -> Option<Identity> {
        let Some(found) = found else {
            self.warnings.push(format!(
                "{who}: {written} on {} is not an IP address with its mask; skipped",
                interface.identity.label()
            ));
            return None;
        };
        if !self.settings.permits(found.ip) {
            return None;
        }
        if network.declared.iter().any(|known| known.ip == found.ip) {
            self.warnings.push(format!(
                "{who}: {} is listed twice; the one on {} is skipped",
                found.ip,
                interface.identity.label()
            ));
            return None;
        }
        let text = found.net.to_string();
        // The source knows no VRF: the address is looked up in every table,
        // and the VRF NetBox has for it is kept.
        let identity = Identity::ip_address(&text, VrfKey::Unknown);
        let mut object = self.new_object(Kind::IpAddress, identity.clone()).field("address", text.as_str()).reference(
            "assigned_object",
            interface.kind,
            interface.identity.clone(),
        );
        // A lookup that gives nothing, or a name NetBox would refuse, writes no name: NetBox keeps the one it has.
        if let Some(dns_name) = self.names.of(found.ip) {
            object = object.field("dns_name", dns_name);
        }
        let object = self.with_tenant(object);
        network.addresses.push(object);
        network.declared.push(found);
        Some(identity)
    }

    /// The standard port groups of a host that team this physical card.
    fn port_groups_of<'h>(host: &'h Host, device: &str) -> Vec<&'h PortGroup> {
        let teams = |group: &&PortGroup| group.active_nics.iter().chain(&group.standby_nics).any(|nic| nic == device);
        host.portgroups.iter().flatten().filter(teams).collect()
    }

    /// A physical card of a host.
    fn physical_nic(&mut self, host: &Host, device_name: &str, pnic: &PhysicalNic, network: &mut Network) {
        let who = format!("host {device_name}");
        let name = cut(&unquote(&pnic.device), MAX_NAME);
        if name.is_empty() {
            self.warnings.push(format!("{who}: a physical card without name is skipped"));
            return;
        }
        if self.settings.filters(&name) {
            return;
        }
        let speed = pnic.speed_mb.or(pnic.spec_speed_mb).or(pnic.valid_speed_mb);
        let duplex = pnic.duplex.or(pnic.spec_duplex).or(pnic.valid_duplex);
        let identity = Identity::interface(device_name, &name);
        let mut interface = self
            .new_object(Kind::Interface, identity)
            .field("name", name.as_str())
            .field("type", interface_type(speed))
            // A link speed is only reported for a link that is up.
            .field("enabled", pnic.speed_mb.is_some())
            .reference("device", Kind::Device, Identity::device(device_name));
        if let Some(speed) = speed.and_then(kilobits) {
            interface = interface.field("speed", speed);
        }
        if let Some(duplex) = duplex {
            interface = interface.field("duplex", if duplex { "full" } else { "half" });
        }
        // An uplink of a distributed switch: what such a switch says was never
        // observed, so its part (MTU, mode, description) stays unreported.
        let distributed = host.proxy_switches.iter().flatten().any(|switch| switch.pnics.contains(&pnic.device));
        if !distributed {
            let mut description = match speed {
                Some(speed) if speed >= 1000 => format!("{}Gb/s ", speed / 1000),
                Some(speed) => format!("{speed}Mb/s "),
                None => String::new(),
            };
            description.push_str(" pNIC");
            for switch in host.vswitches.iter().flatten().filter(|switch| switch.pnics.contains(&pnic.device)) {
                description.push_str(&format!(" ({})", unquote(&switch.name)));
                if let Some(mtu) = switch.mtu {
                    interface = interface.field("mtu", mtu);
                }
            }
            // netbox-sync appended the switch port the card is plugged in, read
            // with `QueryNetworkHint`: this tool tells that port to the cable
            // step instead (`Translation::heard`). The description only fills
            // an interface that has none.
            interface = interface
                .field("description", cut(&unquote(&description), MAX_DESCRIPTION))
                .only_when_empty("description");
            interface = self.physical_nic_vlans(host, pnic, interface);
        }
        if self.add_interface(&who, &name, interface.clone(), network) {
            let interface = self.mac(interface, pnic.mac.as_deref(), network);
            if let Some((_, declared)) = network.interfaces.last_mut() {
                *declared = interface;
            }
        }
    }

    /// The mode and the tagged VLANs of a physical card, from the standard
    /// port groups that team it.
    fn physical_nic_vlans(&mut self, host: &Host, pnic: &PhysicalNic, interface: Desired) -> Desired {
        let groups = Self::port_groups_of(host, &pnic.device);
        let ids: Option<BTreeSet<u32>> = groups.iter().map(|group| group.vlan_id).collect();
        // No port group, or one whose VLAN is unknown: nothing is said.
        let Some(ids) = ids.filter(|ids| !ids.is_empty()) else {
            return interface;
        };
        if ids.len() == 1 && ids.contains(&0) {
            return interface.field("mode", "access");
        }
        if ids.contains(&ALL_VLANS) {
            return interface.field("mode", "tagged-all");
        }
        let mut seen = BTreeSet::new();
        let mut vlans = Vec::new();
        for group in groups {
            let Some(vlan_id) = group.vlan_id.filter(|vlan_id| seen.insert(*vlan_id)) else {
                continue;
            };
            vlans.extend(self.vlan(vlan_id, &group.name));
        }
        let interface = interface.field("mode", "tagged");
        if vlans.is_empty() { interface } else { interface.reference_list("tagged_vlans", vlans) }
    }

    /// A vmkernel interface of a host, with its addresses.
    fn vmkernel_nic(
        &mut self,
        host: &Host,
        device_name: &str,
        vnic: &VirtualNic,
        network: &mut Network,
        primary: &mut (Option<Identity>, Option<Identity>),
    ) {
        let who = format!("host {device_name}");
        let name = cut(&unquote(&vnic.device), MAX_NAME);
        if name.is_empty() {
            self.warnings.push(format!("{who}: a vmkernel interface without name is skipped"));
            return;
        }
        if self.settings.filters(&name) {
            return;
        }
        let identity = Identity::interface(device_name, &name);
        let target = Target::new(Kind::Interface, identity.clone());
        let mut interface = self
            .new_object(Kind::Interface, identity)
            .field("name", name.as_str())
            .field("type", "virtual")
            .field("enabled", true)
            .reference("device", Kind::Device, Identity::device(device_name));
        if let Some(mtu) = vnic.mtu {
            interface = interface.field("mtu", mtu);
        }
        // The standard port group it is on: on a distributed one nothing is said.
        let group = vnic
            .portgroup
            .as_deref()
            .filter(|name| !name.is_empty())
            .and_then(|name| host.portgroups.iter().flatten().find(|group| group.name == name));
        let mut description = String::new();
        if let Some((group, vlan_id)) = group.and_then(|group| Some((group, group.vlan_id?))) {
            if let Some(switch) = &group.vswitch {
                description = format!("{} ({}, vlan ID: {vlan_id})", group.name, unquote(switch));
                interface = interface.field("description", cut(&unquote(&description), MAX_DESCRIPTION));
            }
            interface = interface.field("mode", "access");
            // Named after its site, unless it is the VLAN of several: the one of a VLAN group.
            let vlan_name = match &self.settings.vlan_group {
                Some(_) => format!("ESXi {} (ID: {vlan_id})", group.name),
                None => format!("ESXi {} (ID: {vlan_id}) ({})", group.name, self.settings.site),
            };
            if let Some(vlan) = self.vlan(vlan_id, &vlan_name) {
                interface = interface.reference("untagged_vlan", Kind::Vlan, vlan.identity);
            }
        }
        if !self.add_interface(&who, &name, interface.clone(), network) {
            return;
        }
        let interface = self.mac(interface, vnic.mac.as_deref(), network);
        if let Some((_, declared)) = network.interfaces.last_mut() {
            *declared = interface;
        }
        let lowered = description.to_lowercase();
        let is_primary = vnic.route_spec || MANAGEMENT_MARKS.iter().any(|mark| lowered.contains(mark));
        if let Some((host_address, mask)) = vnic.ipv4.as_ref().filter(|(address, _)| !address.is_empty()) {
            let prefix = mask.parse::<Ipv4Addr>().ok().and_then(|mask| ipnet::ipv4_mask_to_prefix(mask).ok());
            let written = format!("{host_address}/{mask}");
            let declared = self.ip(&who, &target, address(host_address, prefix), &written, network);
            if is_primary && primary.0.is_none() {
                primary.0 = declared;
            }
        }
        for (host_address, prefix) in &vnic.ipv6 {
            let written =
                format!("{host_address}/{}", prefix.map_or_else(|| "?".to_owned(), |prefix| prefix.to_string()));
            let declared = self.ip(&who, &target, address(host_address, *prefix), &written, network);
            if is_primary && primary.1.is_none() {
                primary.1 = declared;
            }
        }
    }

    /// The machines that are synced: among the machines of one name in one
    /// cluster only one is, as NetBox names a machine once per cluster. The
    /// running one, then the oldest one: netbox-sync took the first one
    /// vCenter listed, an order nothing guarantees.
    fn machines(&mut self) -> Result<(), TranslateError> {
        let inventory = self.inventory;
        let mut machines: Vec<(&str, String, &Machine)> = Vec::new();
        for machine in &inventory.machines {
            if self.settings.ignore_templates && machine.template == Some(true) {
                continue;
            }
            let Some(name) = stripped(machine.name.as_deref()) else {
                return unplaced(format!("virtual machine {}", machine.id), "vCenter reports no name for it");
            };
            let Some(cluster) = self.cluster_of(machine) else {
                return unplaced(format!("virtual machine {name} ({})", machine.id), "its host is not reported");
            };
            machines.push((name, cluster, machine));
        }
        machines.sort_by_key(|(name, _, machine)| {
            let stopped = machine.power_state.as_deref() != Some(POWERED_ON);
            (name.to_lowercase(), stopped, object_number(&machine.id), machine.id.as_str())
        });
        let mut kept: BTreeMap<(String, String), &str> = BTreeMap::new();
        for (full_name, cluster, machine) in machines {
            let name = cut(full_name, MAX_NAME);
            let key = (name.to_lowercase(), cluster.to_lowercase());
            if let Some(other) = kept.get(&key) {
                self.warnings.push(format!(
                    "skipping vm {full_name} ({}): name already used by {other} in cluster {cluster}; \
                     machine names must be unique in a cluster",
                    machine.id
                ));
                continue;
            }
            kept.insert(key, machine.id.as_str());
            self.machine(machine, &name, &cluster);
        }
        Ok(())
    }

    /// The NetBox cluster a machine runs in, through its host.
    fn cluster_of(&self, machine: &Machine) -> Option<String> {
        let host = self.host_of(machine)?;
        let cluster = self.inventory.cluster_of(host)?;
        self.clusters.get(cluster.id.as_str()).cloned()
    }

    fn host_of(&self, machine: &Machine) -> Option<&'a Host> {
        let id = machine.host.as_deref()?;
        self.inventory.hosts.iter().find(|host| host.id == id)
    }

    /// The names of the vSphere tags of a machine: its own, those of its
    /// cluster and those of its datacenter (`vm_tag_source`). Each is declared.
    ///
    /// The cluster is the one of the host the machine runs on. netbox-sync
    /// looked for it above the folder of the machine, where only folders and
    /// the datacenter are: the tags of a cluster never reached its machines.
    fn tags(&mut self, machine: &Machine) -> Vec<String> {
        let inventory = self.inventory;
        let mut found = inventory.tags_of("VirtualMachine", &machine.id);
        let cluster = self.host_of(machine).and_then(|host| inventory.cluster_of(host));
        if let Some(cluster) = cluster {
            found.extend(inventory.tags_of(&cluster.kind, &cluster.id));
        }
        let datacenter = cluster.and_then(|cluster| inventory.datacenter_of(cluster.parent.as_ref()?));
        if let Some(datacenter) = datacenter {
            found.extend(inventory.tags_of("Datacenter", &datacenter.id));
        }
        let mut names: Vec<String> = Vec::new();
        for tag in found {
            let name = cut(tag.name.trim(), MAX_LONG_NAME);
            let slug = format_slug(&name, MAX_LONG_NAME);
            if slug.is_empty() {
                self.warnings.push(format!("vSphere tag {:?} cannot be named in NetBox; skipped", tag.name));
                continue;
            }
            if names.iter().any(|known| known.to_lowercase() == name.to_lowercase()) {
                continue;
            }
            let description = match tag.description.trim() {
                "" => TAG_MARKER.to_owned(),
                description => cut(&format!("{TAG_MARKER}: {description}"), MAX_DESCRIPTION),
            };
            // A tag only has to exist. The marker is written to the one this
            // tool creates, never to one NetBox already has: a tag made by hand
            // would then pass for one made from vSphere, and be removed from
            // every machine vSphere does not tag with it.
            let object = self
                .new_object(Kind::Tag, Identity::named(&name))
                .field("name", name.as_str())
                .create_only("slug", slug)
                .create_only("description", description)
                .ensure_only();
            self.share(object);
            names.push(name);
        }
        names
    }

    /// The platform of a machine: the "prettyName" its tools detail, else the
    /// system they report (`guest.guestFullName`), written at every run.
    ///
    /// When the tools told neither, only the system the machine was configured
    /// for is left: it fills a machine that has no platform, and never
    /// replaces the one the tools had reported before they stopped.
    fn platform(&mut self, machine: &Machine, object: Desired) -> Desired {
        let pretty =
            machine.guest_details.as_ref().and_then(|details| stripped(details.get("prettyName").map(String::as_str)));
        let reported = pretty.or(stripped(machine.guest_full_name.as_deref()));
        let Some(name) = reported.or(stripped(machine.config_guest_full_name.as_deref())) else {
            return object;
        };
        // The build of a Windows changes at every update, and each would be a new platform.
        let name = if name.contains("Windows") { name.split(WINDOWS_BUILD).next().unwrap_or(name) } else { name };
        let name = cut(name, MAX_LONG_NAME);
        let platform = self.named(Kind::Platform, &name);
        self.share(platform);
        let object = object.reference("platform", Kind::Platform, Identity::named(&name));
        if reported.is_some() { object } else { object.only_when_empty("platform") }
    }

    /// A machine with its interfaces, their addresses and its disks.
    fn machine(&mut self, machine: &Machine, name: &str, cluster: &str) {
        let settings = self.settings;
        let identity = Identity::virtual_machine(name, cluster);
        let mut object = self.new_object(Kind::VirtualMachine, identity.clone()).field("name", name).reference(
            "cluster",
            Kind::Cluster,
            Identity::named(cluster),
        );
        object = self.with_tenant(self.with_site(object));
        // A state that was not reported says nothing: the status NetBox has is kept.
        if let Some(state) = machine.power_state.as_deref() {
            object = object.field("status", if state == POWERED_ON { "active" } else { "offline" });
        }
        if let Some(device) = machine.host.as_deref().and_then(|host| self.devices.get(host)) {
            object = object.reference("device", Kind::Device, Identity::device(device));
        }
        if let Some(role) = &settings.vm_role {
            let role_object = self.existing(Kind::Role, role);
            self.share(role_object);
            object = object.reference("role", Kind::Role, Identity::named(role));
        }
        let tags = self.tags(machine);
        object = object.tags(tags);
        if machine.instance_uuid.is_none() {
            // An inaccessible machine has no `config`: neither its cards nor
            // its disks are known, and it may not be told from a template.
            self.warnings.push(format!(
                "vm {name} ({}): vCenter reports no configuration for it (inaccessible?); what NetBox holds of it \
                 is kept",
                machine.id
            ));
            let kinds = [Kind::VmInterface, Kind::MacAddress, Kind::IpAddress, Kind::VirtualDisk];
            self.objects.push(object.unknown_dependents(kinds));
            return;
        }
        // Powers of ten, as `vm_disk_and_ram_in_decimal` asked: 4096 MiB is 4000.
        if let Some(memory) = machine.memory_mb.and_then(decimal_megabytes) {
            object = object.field("memory", memory);
        }
        if let Some(cpus) = machine.cpus {
            object = object.field("vcpus", cpus);
        }
        if let Some(uuid) = stripped(machine.instance_uuid.as_deref()) {
            object = object.field("serial", cut(uuid, MAX_SERIAL));
        }
        if let Some(annotation) = stripped(machine.annotation.as_deref()) {
            object = object.field("comments", annotation);
        }
        object = self.platform(machine, object);

        let who = format!("vm {name}");
        let mut network = Network::default();
        let mut unknown: Vec<Kind> = Vec::new();
        let mut targets: Vec<(String, Target)> = Vec::new();
        match &machine.nics {
            Some(nics) => {
                for nic in nics {
                    if let Some((mac, target)) = self.machine_nic(machine, &identity, &who, nic, &mut network) {
                        targets.extend(mac.map(|mac| (mac, target)));
                    }
                }
            }
            None => unknown.extend([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]),
        }
        let tools_run = machine.tools_running_status.as_deref() == Some(TOOLS_RUNNING);
        if let Some(guest_nics) = machine.guest_nics.as_ref().filter(|_| tools_run) {
            // In the order of the cards, then of what the guest lists for each.
            for (mac, target) in &targets {
                for guest in
                    guest_nics.iter().filter(|guest| guest.mac.as_deref().map(normalized_mac).as_ref() == Some(mac))
                {
                    for (host, prefix) in &guest.addresses {
                        let written =
                            format!("{host}/{}", prefix.map_or_else(|| "?".to_owned(), |prefix| prefix.to_string()));
                        self.ip(&who, target, address(host, *prefix), &written, &mut network);
                    }
                }
            }
            object = Self::with_primary(object, Self::machine_primary(machine, &network));
        } else if !unknown.contains(&Kind::IpAddress) {
            // Only running tools tell the addresses of a guest. netbox-sync
            // declared none then: the ones NetBox held lost their source.
            unknown.push(Kind::IpAddress);
        }
        let mut disks = Vec::new();
        match &machine.disks {
            Some(listed) => disks = self.disks(&identity, &who, listed),
            None => unknown.push(Kind::VirtualDisk),
        }
        if !unknown.is_empty() {
            // Unknown is not empty: what NetBox has under this machine is kept.
            object = object.unknown_dependents(unknown);
        }
        self.objects.push(object);
        self.objects.extend(network.interfaces.into_iter().map(|(_, interface)| interface));
        self.objects.extend(network.addresses);
        self.objects.extend(disks);
    }

    /// A virtual network card of a machine; returns its MAC address and the
    /// interface declared for it, to hang the addresses of the guest on.
    fn machine_nic(
        &mut self,
        machine: &Machine,
        vm: &Identity,
        who: &str,
        nic: &MachineNic,
        network: &mut Network,
    ) -> Option<(Option<String>, Target)> {
        let Some(label) = nic.label.as_deref().filter(|label| !label.trim().is_empty()) else {
            self.warnings.push(format!("{who}: a network card without label is skipped"));
            return None;
        };
        let host = self.host_of(machine);
        let inventory = self.inventory;
        // The name of the network the card is on, and its standard port group
        // on the host of the machine. What a distributed port group says of
        // its VLANs was never observed: only its name is used.
        let (network_name, group) = match &nic.backing {
            Some(NicBacking::Network(name)) => {
                let name = stripped(Some(name.as_str()));
                let groups = host.and_then(|host| host.portgroups.as_ref());
                let same = |group: &&PortGroup| Some(group.name.to_lowercase()) == name.map(str::to_lowercase);
                (name, groups.and_then(|groups| groups.iter().rfind(same)))
            }
            Some(NicBacking::Distributed { portgroup_key, .. }) => {
                let known = |group: &&DistributedPortGroup| group.key.as_deref() == Some(portgroup_key);
                let group = inventory.port_groups.iter().find(known);
                (group.and_then(|group| stripped(group.name.as_deref())), None)
            }
            _ => (None, None),
        };
        // `Network adapter 1` is `vNIC 1`.
        let number = label.rsplit(' ').next().unwrap_or(label);
        let full_name = match network_name {
            Some(network_name) => format!("vNIC {number} ({network_name})"),
            None => format!("vNIC {number}"),
        };
        let name = cut(&unquote(&full_name), MAX_NAME);
        if self.settings.filters(&name) {
            return None;
        }
        let identity = Identity::vm_interface(vm, &name);
        let target = Target::new(Kind::VmInterface, identity.clone());
        let mac = nic.mac.as_deref().map(normalized_mac).filter(|mac| !mac.is_empty());
        // What the guest says of the card wins over its configuration.
        let guests = machine.guest_nics.iter().flatten();
        let seen_by_guest = guests
            .filter(|guest| mac.is_some() && guest.mac.as_deref().map(normalized_mac) == mac)
            .filter_map(|guest| guest.connected)
            .next_back();
        let mut interface = self.new_object(Kind::VmInterface, identity).field("name", name.as_str()).reference(
            "virtual_machine",
            Kind::VirtualMachine,
            vm.clone(),
        );
        // Neither says it: nothing is said, and NetBox keeps what it has.
        if let Some(enabled) = seen_by_guest.or(nic.connected) {
            interface = interface.field("enabled", enabled);
        }
        let distributed = matches!(nic.backing, Some(NicBacking::Distributed { .. }));
        if let Some(kind) = nic.kind.as_deref().filter(|_| !distributed) {
            let mut description = format!("{label} ({kind})");
            if let Some(vlan_id) = group.and_then(|group| group.vlan_id) {
                if vlan_id == ALL_VLANS {
                    description.push_str(" (all vlans)");
                } else {
                    description.push_str(&format!(" (vlan ID: {vlan_id})"));
                }
            }
            interface = interface.field("description", cut(&unquote(&description), MAX_DESCRIPTION));
        }
        if let Some(group) = group {
            let switch = host.and_then(|host| {
                let named =
                    |switch: &&VirtualSwitch| Some(unquote(&switch.name)) == group.vswitch.as_deref().map(unquote);
                host.vswitches.iter().flatten().find(named)
            });
            if let Some(mtu) = switch.and_then(|switch| switch.mtu) {
                interface = interface.field("mtu", mtu);
            }
            if let Some(vlan_id) = group.vlan_id {
                interface = interface.field("mode", port_group_mode(vlan_id));
                if let Some(vlan) = self.vlan(vlan_id, network_name.unwrap_or_default()) {
                    interface = interface.reference("untagged_vlan", Kind::Vlan, vlan.identity);
                }
            }
        }
        if !self.add_interface(who, &name, interface.clone(), network) {
            return None;
        }
        let interface = self.mac(interface, mac.as_deref(), network);
        if let Some((_, declared)) = network.interfaces.last_mut() {
            *declared = interface;
        }
        Some((mac, target))
    }

    /// The primary addresses of a machine: the first declared address whose
    /// network holds the default gateway of the guest; in IPv6 the only
    /// address of the machine when it has exactly one.
    fn machine_primary(machine: &Machine, network: &Network) -> (Option<Identity>, Option<Identity>) {
        let mut gateways: (Option<IpAddr>, Option<IpAddr>) = (None, None);
        // The last default route of each family wins.
        for route in machine.routes.iter().flatten().filter(|route| route.prefix_length == Some(0)) {
            let parsed = route
                .network
                .trim()
                .parse::<IpAddr>()
                .ok()
                .zip(route.gateway.as_deref().and_then(|gateway| gateway.trim().parse::<IpAddr>().ok()));
            match parsed {
                Some((IpAddr::V4(_), gateway)) => gateways.0 = Some(gateway),
                Some((IpAddr::V6(_), gateway)) => gateways.1 = Some(gateway),
                None => {}
            }
        }
        let identity = |address: &Address| Identity::ip_address(&address.net.to_string(), VrfKey::Unknown);
        let towards = |gateway: Option<IpAddr>| {
            let gateway = gateway?;
            network.declared.iter().find(|address| address.net.trunc().contains(&gateway)).map(identity)
        };
        let ipv6: Vec<&Address> = network.declared.iter().filter(|address| address.ip.is_ipv6()).collect();
        let only_ipv6 = match ipv6.as_slice() {
            [only] => Some(identity(only)),
            _ => None,
        };
        (towards(gateways.0), only_ipv6.or_else(|| towards(gateways.1)))
    }

    /// The virtual disks of a machine.
    fn disks(&mut self, vm: &Identity, who: &str, disks: &[Disk]) -> Vec<Desired> {
        let mut declared = Vec::new();
        let mut seen = BTreeSet::new();
        for disk in disks {
            let Some(label) = disk.label.as_deref().filter(|label| !label.is_empty()) else {
                self.warnings.push(format!("{who}: a disk without label is skipped"));
                continue;
            };
            let name = cut(label, MAX_NAME);
            if !seen.insert(name.clone()) {
                self.warnings.push(format!("{who}: disk {name} is listed twice; the second one is skipped"));
                continue;
            }
            let mut parts: Vec<String> = Vec::new();
            if let Some(mode) = &disk.disk_mode {
                // Python's `capitalize`: `independent_persistent` is `Independent-persistent`.
                let mut characters = mode.chars();
                let capitalized: String = characters
                    .next()
                    .map(|first| first.to_uppercase().chain(characters.flat_map(char::to_lowercase)).collect())
                    .unwrap_or_default();
                parts.push(capitalized.replace('_', "-"));
            }
            // A disk that does not say how it is provisioned is not called thick.
            if let Some(thin) = disk.thin_provisioned {
                parts.push(if thin { "ThinProvisioned" } else { "ThickProvisioned" }.to_owned());
            }
            parts.extend(disk.root_file_name.clone());
            let mut object = self
                .new_object(Kind::VirtualDisk, Identity::virtual_disk(vm, &name))
                .field("name", name.as_str())
                .field("description", cut(&parts.join(" / "), MAX_DESCRIPTION))
                .reference("virtual_machine", Kind::VirtualMachine, vm.clone());
            // Megabytes in powers of ten, as `vm_disk_and_ram_in_decimal` asked: 40 GiB is 40000.
            if let Some(capacity_kb) = disk.capacity_kb {
                object = object.field("size", capacity_kb / 1024 * 1000 / 1024);
            }
            declared.push(object);
        }
        declared
    }

    /// Says once that the distributed switches of the vCenter are not synced.
    fn distributed_switches(&mut self) {
        let inventory = self.inventory;
        let on_hosts = inventory
            .hosts
            .iter()
            .filter(|host| host.proxy_switches.as_ref().is_some_and(|switches| !switches.is_empty()))
            .count();
        let (switches, groups) = (inventory.switches.len(), inventory.port_groups.len());
        if switches + groups + on_hosts > 0 {
            self.warnings.push(format!(
                "distributed switches are not supported yet ({switches} switch(es), {groups} port group(s), \
                 {on_hosts} host(s) on one): the interfaces on them keep their name, MAC and IP addresses, their \
                 VLANs, mode, MTU and description are left as NetBox has them"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use omnisync_core::inventory::dns::NoReverseDns;
    use serde_json::json;

    use super::*;
    use crate::client::{Tag, Tagged};
    use crate::collect::DistributedSwitch;
    use crate::model::{GuestNic, Node, ProxySwitch, Reference, Route};

    const VC: &str = "vc-a";
    const SITE: &str = "Harbor";
    const HOST: &str = "esx.lab.example";
    const CLUSTER: &str = "prod";
    const UUID: &str = "00000000-0000-4000-8000-00000000000a";

    fn owned(text: &str) -> Option<String> {
        Some(text.to_owned())
    }

    fn reference(kind: &str, id: &str) -> Option<Reference> {
        Some(Reference { kind: kind.to_owned(), id: id.to_owned() })
    }

    fn node(kind: &str, id: &str, name: &str, parent: Option<Reference>) -> Node {
        Node { kind: kind.to_owned(), id: id.to_owned(), name: owned(name), parent, hosts: Vec::new() }
    }

    fn group(name: &str, vlan_id: u32, switch: &str, nics: &[&str]) -> PortGroup {
        PortGroup {
            name: name.to_owned(),
            vlan_id: Some(vlan_id),
            vswitch: owned(switch),
            active_nics: nics.iter().map(|nic| (*nic).to_owned()).collect(),
            standby_nics: Vec::new(),
        }
    }

    /// A host that answers, with one standard switch and nothing on it.
    fn host() -> Host {
        Host {
            id: "host-1".to_owned(),
            name: owned(HOST),
            parent: reference("ClusterComputeResource", "domain-c1"),
            connection_state: owned("connected"),
            vendor: owned("Dell Inc."),
            model: owned("PowerEdge R640"),
            product_name: owned("VMware ESXi"),
            product_version: owned("6.7.0"),
            identifiers: Vec::new(),
            cpu_model: owned("Intel(R) Xeon(R) Gold 5220 CPU @ 2.20GHz"),
            cpu_cores: Some(36),
            memory_bytes: Some(512 * 1024 * 1024 * 1024),
            pnics: Some(Vec::new()),
            vnics: Some(Vec::new()),
            vswitches: Some(vec![VirtualSwitch { name: "vSwitch0".to_owned(), mtu: Some(9000), pnics: Vec::new() }]),
            portgroups: Some(Vec::new()),
            proxy_switches: Some(Vec::new()),
        }
    }

    fn card(label: &str, mac: &str, network: &str) -> MachineNic {
        MachineNic {
            kind: owned("VirtualVmxnet3"),
            key: Some(4000),
            label: owned(label),
            mac: owned(mac),
            connected: Some(true),
            backing: Some(NicBacking::Network(network.to_owned())),
        }
    }

    fn guest(mac: &str, addresses: &[(&str, u8)]) -> GuestNic {
        GuestNic {
            mac: owned(mac),
            connected: Some(true),
            network: None,
            device_config_id: Some(4000),
            addresses: addresses.iter().map(|(address, prefix)| ((*address).to_owned(), Some(*prefix))).collect(),
        }
    }

    /// A running machine whose tools run, without card nor disk.
    fn machine(id: &str, name: &str) -> Machine {
        Machine {
            id: id.to_owned(),
            name: owned(name),
            annotation: None,
            config_guest_full_name: owned("Other Linux (64-bit)"),
            guest_full_name: owned("Debian GNU/Linux 12 (64-bit)"),
            guest_details: Some(BTreeMap::new()),
            memory_mb: Some(4096),
            cpus: Some(2),
            instance_uuid: owned(UUID),
            uuid: None,
            template: Some(false),
            power_state: owned("poweredOn"),
            host: owned("host-1"),
            tools_running_status: owned("guestToolsRunning"),
            guest_host_name: None,
            nics: Some(Vec::new()),
            disks: Some(Vec::new()),
            guest_nics: Some(Vec::new()),
            routes: Some(Vec::new()),
        }
    }

    /// A vCenter with one datacenter, one cluster and one host.
    fn inventory(hosts: Vec<Host>, machines: Vec<Machine>) -> Inventory {
        Inventory {
            server: "VMware vCenter Server 6.7.0 build-1".to_owned(),
            api_version: "6.7.3".to_owned(),
            datacenters: vec![node("Datacenter", "datacenter-2", "DC1", reference("Folder", "group-d1"))],
            folders: vec![node("Folder", "group-h4", "host", reference("Datacenter", "datacenter-2"))],
            clusters: vec![node("ClusterComputeResource", "domain-c1", CLUSTER, reference("Folder", "group-h4"))],
            switches: Vec::new(),
            port_groups: Vec::new(),
            hosts,
            machines,
            tags: Vec::new(),
            hints: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }

    fn settings() -> Settings {
        Settings::new(VC, SITE)
    }

    fn translate(inventory: &Inventory) -> Translation {
        desired(inventory, &settings(), &NoReverseDns).expect("translation")
    }

    fn one(translation: &Translation, kind: Kind, label: &str) -> Desired {
        let found: Vec<&Desired> = translation
            .objects
            .iter()
            .filter(|object| object.kind == kind && object.identity.label() == label)
            .collect();
        assert_eq!(found.len(), 1, "{} object(s) of kind {kind:?} named {label}", found.len());
        found[0].clone()
    }

    fn labels(translation: &Translation, kind: Kind) -> Vec<String> {
        let of_kind = translation.objects.iter().filter(|object| object.kind == kind);
        of_kind.map(|object| object.identity.label().to_owned()).collect()
    }

    fn target(object: &Desired, field: &str) -> String {
        object.references[field].as_ref().expect("a target").identity.label().to_owned()
    }

    // The helpers

    #[test]
    fn a_name_is_unquoted_as_urllib_does() {
        assert_eq!(unquote("pg%2fdmz"), "pg/dmz");
        assert_eq!(unquote("caf%C3%A9"), "café");
        // What is not an escape is kept.
        assert_eq!(unquote("100%"), "100%");
        assert_eq!(unquote("50%zz"), "50%zz");
        assert_eq!(unquote("%2"), "%2");
        assert_eq!(unquote("vSwitch0"), "vSwitch0");
    }

    // vCenter values are read from XML: an absurd one is not written, rather
    // than wrapped to a wrong number in a release build.
    #[test]
    fn a_value_too_large_to_convert_is_not_reported() {
        assert_eq!(kilobits(10_000), Some(10_000_000));
        assert_eq!(kilobits(u64::MAX), None);
        // 4096 MiB is 4000, as `vm_disk_and_ram_in_decimal` asked.
        assert_eq!(decimal_megabytes(4096), Some(4000));
        assert_eq!(decimal_megabytes(u64::MAX), None);
    }

    #[test]
    fn a_mac_address_is_written_in_upper_case_with_colons() {
        assert_eq!(normalized_mac("00:50:56:9a:1b:2c"), "00:50:56:9A:1B:2C");
        assert_eq!(normalized_mac("0050569a1b2c"), "00:50:56:9A:1B:2C");
        assert_eq!(normalized_mac("00-50-56-ab-cd-ef"), "00:50:56:AB:CD:EF");
        // Anything but twelve hexadecimal digits is no MAC address: none is reported.
        for text in ["00:50:56", "not a mac addr", "00:50:56:9a:1b:2g", ""] {
            assert_eq!(normalized_mac(text), "", "{text}");
        }
    }

    #[test]
    fn a_physical_card_is_typed_by_its_speed() {
        assert_eq!(interface_type(Some(1000)), "1000base-t");
        assert_eq!(interface_type(Some(25_000)), "25gbase-x-sfp28");
        assert_eq!(interface_type(Some(400_000)), "400gbase-x-qsfpdd");
        assert_eq!(interface_type(Some(10)), "other");
        assert_eq!(interface_type(None), "other");
    }

    #[test]
    fn the_memory_of_a_host_is_written_in_gb_then_in_tb() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(host_memory(256 * GIB - 100_000_000), "256 GB");
        assert_eq!(host_memory(1023 * GIB), "1023 GB");
        // From 1024 GB on, a float as Python prints it.
        assert_eq!(host_memory(1024 * GIB), "1.0 TB");
        assert_eq!(host_memory(1536 * GIB), "1.5 TB");
        assert_eq!(host_memory(1100 * GIB), "1.07421875 TB");
        // Python rounds a tie to the even number.
        assert_eq!(host_memory(5 * GIB / 2), "2 GB");
        assert_eq!(host_memory(7 * GIB / 2), "4 GB");
    }

    #[test]
    fn link_local_and_loopback_addresses_are_never_permitted() {
        let open = settings();
        let permits = |settings: &Settings, address: &str| settings.permits(address.parse().unwrap());
        assert!(permits(&open, "10.0.0.5"));
        assert!(permits(&open, "2001:db8::5"));
        for address in ["169.254.10.1", "127.0.0.1", "fe80::1", "::1"] {
            assert!(!permits(&open, address), "{address}");
        }
        let narrowed = Settings {
            permitted_subnets: vec!["10.0.0.0/8".parse().unwrap()],
            ignored_subnets: vec!["10.9.0.0/16".parse().unwrap()],
            ..settings()
        };
        assert!(permits(&narrowed, "10.0.0.5"));
        // Ignored wins; with an IPv4 subnet alone no IPv6 address passes.
        assert!(!permits(&narrowed, "10.9.0.5"));
        assert!(!permits(&narrowed, "192.168.0.5"));
        assert!(!permits(&narrowed, "2001:db8::5"));
    }

    // The hosts

    #[test]
    fn the_serial_and_the_asset_tag_of_a_host_come_from_its_identifiers() {
        let identified = |identifiers: &[(&str, &str)]| {
            let identifiers = identifiers.iter().map(|(kind, value)| ((*kind).to_owned(), (*value).to_owned()));
            let host = Host { identifiers: identifiers.collect(), ..host() };
            one(&translate(&inventory(vec![host], Vec::new())), Kind::Device, HOST)
        };
        // `SerialNumberTag` first, whatever the order they are listed in.
        let device =
            identified(&[("EnclosureSerialNumberTag", "ENC1"), ("ServiceTag", "SVC1"), ("SerialNumberTag", "SN1")]);
        assert_eq!(device.fields["serial"], json!("SN1"));
        assert_eq!(
            identified(&[("EnclosureSerialNumberTag", "ENC1"), ("ServiceTag", " SVC1 ")]).fields["serial"],
            json!("SVC1")
        );
        // An empty value is no value; for a kind listed twice the last one wins.
        let device = identified(&[("SerialNumberTag", " "), ("ServiceTag", "SVC1"), ("ServiceTag", "SVC2")]);
        assert_eq!(device.fields["serial"], json!("SVC2"));
        assert!(!identified(&[("OemSpecificString", "X")]).fields.contains_key("serial"));
        assert_eq!(identified(&[("AssetTag", "A-1234")]).fields["asset_tag"], json!("A-1234"));
        // What a firmware answers when nobody set one is not an asset tag.
        for placeholder in ["Default string", "N/A", "to be filled by O.E.M.", "unknown"] {
            assert!(!identified(&[("AssetTag", placeholder)]).fields.contains_key("asset_tag"), "{placeholder}");
        }
    }

    #[test]
    fn a_host_that_tells_no_hardware_is_a_generic_one() {
        let bare = Host { vendor: None, model: owned(" "), ..host() };
        let translation = translate(&inventory(vec![bare], Vec::new()));
        let device = one(&translation, Kind::Device, HOST);
        assert_eq!(target(&device, "device_type"), "Generic Model");
        assert_eq!(target(&one(&translation, Kind::DeviceType, "Generic Model"), "manufacturer"), "Generic Vendor");
    }

    #[test]
    fn what_a_host_did_not_report_is_not_written() {
        // netbox-sync wrote `offline`, a platform `None None` and `36 None` there.
        let silent =
            Host { connection_state: None, product_version: None, cpu_model: None, memory_bytes: None, ..host() };
        let translation = translate(&inventory(vec![silent], Vec::new()));
        let device = one(&translation, Kind::Device, HOST);
        assert!(!device.fields.contains_key("status"));
        assert!(!device.references.contains_key("platform"));
        assert_eq!(labels(&translation, Kind::Platform), Vec::<String>::new());
        assert_eq!(device.custom_fields, Default::default());
        // A host that says it does not answer is offline.
        let lost = Host { connection_state: owned("notResponding"), ..host() };
        let device = one(&translate(&inventory(vec![lost], Vec::new())), Kind::Device, HOST);
        assert_eq!(device.fields["status"], json!("offline"));
    }

    #[test]
    fn a_host_whose_network_was_not_reported_keeps_what_netbox_has() {
        let silent = Host { pnics: None, vnics: None, ..host() };
        let translation = translate(&inventory(vec![silent], Vec::new()));
        let device = one(&translation, Kind::Device, HOST);
        assert_eq!(device.unknown_dependents, BTreeSet::from([Kind::Interface, Kind::MacAddress, Kind::IpAddress]));
        assert_eq!(labels(&translation, Kind::Interface), Vec::<String>::new());
        // A host that reports no card at all has none.
        let device = one(&translate(&inventory(vec![host()], Vec::new())), Kind::Device, HOST);
        assert_eq!(device.unknown_dependents, BTreeSet::new());
    }

    fn pnic(device: &str, speed: Option<u64>) -> PhysicalNic {
        PhysicalNic {
            device: device.to_owned(),
            mac: owned("02:00:00:00:00:01"),
            speed_mb: speed,
            duplex: speed.map(|_| true),
            ..PhysicalNic::default()
        }
    }

    #[test]
    fn the_mode_of_a_physical_card_follows_the_vlans_of_its_port_groups() {
        let with_groups = |groups: Vec<PortGroup>| {
            let host = Host { pnics: Some(vec![pnic("vmnic0", Some(10_000))]), portgroups: Some(groups), ..host() };
            let translation = translate(&inventory(vec![host], Vec::new()));
            (one(&translation, Kind::Interface, "vmnic0"), labels(&translation, Kind::Vlan))
        };
        // In no port group: nothing is said of its mode.
        let (card, vlans) = with_groups(vec![group("other", 12, "vSwitch0", &["vmnic9"])]);
        assert!(!card.fields.contains_key("mode") && !card.reference_lists.contains_key("tagged_vlans"));
        assert_eq!(vlans, Vec::<String>::new());
        // Only port groups without VLAN: access.
        let (card, _) =
            with_groups(vec![group("a", 0, "vSwitch0", &["vmnic0"]), group("b", 0, "vSwitch0", &["vmnic0"])]);
        assert_eq!(card.fields["mode"], json!("access"));
        // One port group that carries every VLAN: tagged-all, and no VLAN is listed.
        let (card, vlans) =
            with_groups(vec![group("a", 12, "vSwitch0", &["vmnic0"]), group("b", 4095, "vSwitch0", &["vmnic0"])]);
        assert_eq!(card.fields["mode"], json!("tagged-all"));
        assert!(!card.reference_lists.contains_key("tagged_vlans"));
        assert_eq!(vlans, Vec::<String>::new());
        // Otherwise tagged, with each VLAN once; 0 is not a VLAN.
        let (card, vlans) = with_groups(vec![
            group("a", 12, "vSwitch0", &["vmnic0"]),
            group("b", 0, "vSwitch0", &["vmnic0"]),
            group("c", 12, "vSwitch0", &["vmnic0"]),
            group("d", 13, "vSwitch0", &["vmnic0"]),
        ]);
        assert_eq!(card.fields["mode"], json!("tagged"));
        let tagged: Vec<&str> = card.reference_lists["tagged_vlans"].iter().map(|vlan| vlan.identity.label()).collect();
        assert_eq!(tagged, ["12", "13"]);
        assert_eq!(vlans, ["12", "13"]);
        // A standby card of a port group is teamed too.
        let standby = PortGroup {
            active_nics: Vec::new(),
            standby_nics: vec!["vmnic0".to_owned()],
            ..group("a", 12, "vSwitch0", &[])
        };
        assert_eq!(with_groups(vec![standby]).0.fields["mode"], json!("tagged"));
    }

    #[test]
    fn a_physical_card_that_is_down_is_disabled_and_typed_by_the_speed_it_is_set_to() {
        let down = PhysicalNic { spec_speed_mb: Some(1000), spec_duplex: Some(false), ..pnic("vmnic1", None) };
        let silent = pnic("vmnic2", None);
        let host = Host { pnics: Some(vec![down, silent]), ..host() };
        let translation = translate(&inventory(vec![host], Vec::new()));
        let card = one(&translation, Kind::Interface, "vmnic1");
        assert_eq!(card.fields["enabled"], json!(false));
        assert_eq!((&card.fields["type"], &card.fields["speed"]), (&json!("1000base-t"), &json!(1_000_000)));
        assert_eq!(card.fields["duplex"], json!("half"));
        assert_eq!(card.fields["description"], json!("1Gb/s  pNIC"));
        // No speed at all: `other`, and neither speed nor duplex is said.
        let card = one(&translation, Kind::Interface, "vmnic2");
        assert_eq!(card.fields["type"], json!("other"));
        assert!(!card.fields.contains_key("speed") && !card.fields.contains_key("duplex"));
        assert_eq!(card.fields["description"], json!(" pNIC"));
    }

    fn vmk(device: &str, portgroup: &str, address: &str, mask: &str) -> VirtualNic {
        VirtualNic {
            device: device.to_owned(),
            mac: owned("02:00:00:00:00:10"),
            mtu: Some(1500),
            portgroup: owned(portgroup),
            ipv4: Some((address.to_owned(), mask.to_owned())),
            ..VirtualNic::default()
        }
    }

    #[test]
    fn the_primary_address_of_a_host_is_on_its_management_interface_or_on_the_one_with_a_route() {
        let primary = |vnics: Vec<VirtualNic>| {
            let groups = vec![group("vMotion", 20, "vSwitch0", &[]), group("ESX-MGMT", 0, "vSwitch0", &[])];
            let host = Host { vnics: Some(vnics), portgroups: Some(groups), ..host() };
            let device = one(&translate(&inventory(vec![host], Vec::new())), Kind::Device, HOST);
            device.references.get("primary_ip4").map(|primary| primary.as_ref().unwrap().identity.label().to_owned())
        };
        let vmotion = || vmk("vmk0", "vMotion", "10.0.20.5", "255.255.255.0");
        let management = || vmk("vmk1", "ESX-MGMT", "10.0.0.5", "255.255.255.128");
        assert_eq!(primary(vec![vmotion()]), None);
        // `mgmt` in the description of the interface, whatever the case.
        assert_eq!(primary(vec![vmotion(), management()]), owned("10.0.0.5/25"));
        // An interface with a route of its own counts as well; the first of them wins.
        let routed = VirtualNic { route_spec: true, ..vmotion() };
        assert_eq!(primary(vec![routed, management()]), owned("10.0.20.5/24"));
    }

    #[test]
    fn a_vmkernel_interface_on_a_port_group_without_vlan_is_an_access_port_without_vlan() {
        let groups = vec![group("ESX-MGMT", 0, "vSwitch0", &[])];
        let host = Host {
            vnics: Some(vec![vmk("vmk0", "ESX-MGMT", "10.0.0.5", "255.255.255.0")]),
            portgroups: Some(groups),
            ..host()
        };
        let translation = translate(&inventory(vec![host], Vec::new()));
        let interface = one(&translation, Kind::Interface, "vmk0");
        assert_eq!(interface.fields["mode"], json!("access"));
        assert_eq!(interface.fields["description"], json!("ESX-MGMT (vSwitch0, vlan ID: 0)"));
        assert!(!interface.references.contains_key("untagged_vlan"));
    }

    #[test]
    fn the_vlan_of_a_vmkernel_interface_is_named_after_its_port_group_and_site() {
        let groups = vec![group("vMotion%2f1", 20, "vSwitch0", &[])];
        let host = Host { vnics: Some(vec![vmk("vmk0", "vMotion%2f1", "", "")]), portgroups: Some(groups), ..host() };
        let translation = translate(&inventory(vec![host], Vec::new()));
        let vlan = one(&translation, Kind::Vlan, "20");
        assert_eq!(vlan.create_only["name"], json!("ESXi vMotion/1 (ID: 20) (Harbor)"));
        // An interface without IPv4 address has none, and says nothing of it.
        assert_eq!(labels(&translation, Kind::IpAddress), Vec::<String>::new());
        assert_eq!(translation.warnings, Vec::<String>::new());
    }

    #[test]
    fn the_vlans_of_a_site_that_is_in_a_vlan_group_are_declared_in_the_group_and_at_no_site() {
        let groups = vec![group("vMotion%2f1", 20, "vSwitch0", &[])];
        let host = Host { vnics: Some(vec![vmk("vmk0", "vMotion%2f1", "", "")]), portgroups: Some(groups), ..host() };
        let grouped = Settings { vlan_group: Some("East".to_owned()), ..settings() };
        let translation = desired(&inventory(vec![host], Vec::new()), &grouped, &NoReverseDns).expect("translation");
        let in_group = |vid: u64| Identity::vlan(VlanScope::Group("East"), vid);
        let vlans: Vec<&Desired> = translation.objects.iter().filter(|object| object.kind == Kind::Vlan).collect();
        assert_eq!(vlans.iter().map(|vlan| vlan.identity.clone()).collect::<Vec<_>>(), [in_group(20)]);
        for vlan in &vlans {
            // In the group, and at no site: NetBox would refuse it on an interface of another site.
            assert_eq!(
                vlan.references.get("group").cloned().flatten(),
                Some(Target::new(Kind::VlanGroup, Identity::named("East")))
            );
            assert!(!vlan.references.contains_key("site"), "{:?}", vlan.references);
            assert!(vlan.ensure_only);
        }
        // The group is a prerequisite: it is referred to, never declared, so never created.
        assert_eq!(labels(&translation, Kind::VlanGroup), Vec::<String>::new());
        let vmk0 = one(&translation, Kind::Interface, "vmk0");
        assert_eq!(vmk0.references["untagged_vlan"].as_ref().map(|vlan| vlan.identity.clone()), Some(in_group(20)));
        // The host stays at its site.
        assert_eq!(
            one(&translation, Kind::Device, HOST).references["site"].as_ref().unwrap().identity,
            Identity::named(SITE)
        );
    }

    #[test]
    fn the_vlan_of_a_vmkernel_interface_in_a_vlan_group_is_not_named_after_a_site() {
        let groups = vec![group("vMotion%2f1", 20, "vSwitch0", &[])];
        let host = Host { vnics: Some(vec![vmk("vmk0", "vMotion%2f1", "", "")]), portgroups: Some(groups), ..host() };
        let grouped = Settings { vlan_group: Some("East".to_owned()), ..settings() };
        let translation = desired(&inventory(vec![host], Vec::new()), &grouped, &NoReverseDns).expect("translation");
        // The VLAN is the one of several sites: the name of one of them would be wrong on the others.
        assert_eq!(one(&translation, Kind::Vlan, "20").create_only["name"], json!("ESXi vMotion/1 (ID: 20)"));
    }

    #[test]
    fn an_address_that_is_not_one_is_left_out_with_a_warning() {
        let host = Host { vnics: Some(vec![vmk("vmk0", "none", "10.0.0.5", "255.0.255.0")]), ..host() };
        let translation = translate(&inventory(vec![host], Vec::new()));
        assert_eq!(labels(&translation, Kind::IpAddress), Vec::<String>::new());
        assert_eq!(
            translation.warnings,
            ["host esx.lab.example: 10.0.0.5/255.0.255.0 on vmk0 is not an IP address with its mask; skipped"]
        );
    }

    #[test]
    fn two_hosts_of_one_name_are_one_device() {
        let twin = Host { id: "host-2".to_owned(), ..host() };
        let translation = translate(&inventory(vec![twin, host()], Vec::new()));
        assert_eq!(labels(&translation, Kind::Device), [HOST]);
        assert_eq!(
            translation.warnings,
            ["skipping host esx.lab.example (host-2): name already used by host-1; host names must be unique"]
        );
    }

    // What cannot be placed

    #[test]
    fn a_host_or_a_cluster_that_cannot_be_placed_stops_the_translation() {
        let error = |inventory: &Inventory| desired(inventory, &settings(), &NoReverseDns).unwrap_err().to_string();
        let lost = Host { parent: reference("ClusterComputeResource", "domain-c9"), ..host() };
        assert_eq!(
            error(&inventory(vec![lost], Vec::new())),
            "host esx.lab.example: its cluster is not reported; nothing is synced from this vCenter"
        );
        let nameless = Host { name: None, ..host() };
        assert_eq!(
            error(&inventory(vec![nameless], Vec::new())),
            "host host-1: vCenter reports no name for it; nothing is synced from this vCenter"
        );
        let mut adrift = inventory(vec![host()], Vec::new());
        adrift.clusters[0].parent = reference("Folder", "group-h9");
        assert_eq!(error(&adrift), "cluster prod: its datacenter is not reported; nothing is synced from this vCenter");
    }

    #[test]
    fn a_machine_that_cannot_be_placed_stops_the_translation() {
        // netbox-sync skipped such a machine: its NetBox object was then an orphan.
        let error = |machine: Machine| {
            desired(&inventory(vec![host()], vec![machine]), &settings(), &NoReverseDns).unwrap_err().to_string()
        };
        assert_eq!(
            error(Machine { host: None, ..machine("vm-1", "web01") }),
            "virtual machine web01 (vm-1): its host is not reported; nothing is synced from this vCenter"
        );
        assert_eq!(
            error(Machine { host: owned("host-9"), ..machine("vm-1", "web01") }),
            "virtual machine web01 (vm-1): its host is not reported; nothing is synced from this vCenter"
        );
        assert_eq!(
            error(Machine { name: owned(" "), ..machine("vm-1", "web01") }),
            "virtual machine vm-1: vCenter reports no name for it; nothing is synced from this vCenter"
        );
        // A template that is left out does not have to be placed.
        let template = Machine { host: None, template: Some(true), ..machine("vm-1", "tpl") };
        assert_eq!(
            labels(&translate(&inventory(vec![host()], vec![template])), Kind::VirtualMachine),
            Vec::<String>::new()
        );
    }

    // The virtual machines

    #[test]
    fn a_machine_without_configuration_is_kept_as_netbox_has_it() {
        // An inaccessible machine has a name, a host and a power state, and no `config` at all: netbox-sync
        // skipped it, and its NetBox object became an orphan.
        let inaccessible = Machine {
            id: "vm-7".to_owned(),
            name: owned("web01"),
            power_state: owned("poweredOff"),
            host: owned("host-1"),
            ..Machine::default()
        };
        let translation = translate(&inventory(vec![host()], vec![inaccessible]));
        let expected = Desired::new(Kind::VirtualMachine, Identity::virtual_machine("web01", CLUSTER), VC)
            .field("name", "web01")
            .field("status", "offline")
            .reference("cluster", Kind::Cluster, Identity::named(CLUSTER))
            .reference("site", Kind::Site, Identity::named(SITE))
            .reference("device", Kind::Device, Identity::device(HOST))
            .tags(Vec::<String>::new())
            .unknown_dependents([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress, Kind::VirtualDisk]);
        assert_eq!(one(&translation, Kind::VirtualMachine, "web01"), expected);
        assert_eq!(
            translation.warnings,
            [
                "vm web01 (vm-7): vCenter reports no configuration for it (inaccessible?); what NetBox holds of it is kept"
            ]
        );
    }

    #[test]
    fn what_a_machine_did_not_report_is_not_written() {
        // netbox-sync wrote `offline`, a memory of 0 and a disabled card there.
        let unplugged = MachineNic { connected: None, ..card("Network adapter 1", "02:00:00:00:00:21", "none") };
        let silent = Machine {
            power_state: None,
            memory_mb: None,
            cpus: None,
            nics: Some(vec![unplugged]),
            ..machine("vm-1", "web01")
        };
        let translation = translate(&inventory(vec![host()], vec![silent]));
        let vm = one(&translation, Kind::VirtualMachine, "web01");
        for field in ["status", "memory", "vcpus"] {
            assert!(!vm.fields.contains_key(field), "{field}");
        }
        assert!(!one(&translation, Kind::VmInterface, "vNIC 1 (none)").fields.contains_key("enabled"));
    }

    #[test]
    fn memory_is_written_in_powers_of_ten() {
        let sized = |memory_mb: u64| {
            let vm = Machine { memory_mb: Some(memory_mb), ..machine("vm-1", "web01") };
            one(&translate(&inventory(vec![host()], vec![vm])), Kind::VirtualMachine, "web01").fields["memory"].clone()
        };
        // `int(memoryMB / 1024 * 1000)`.
        assert_eq!(sized(4096), json!(4000));
        assert_eq!(sized(1000), json!(976));
        assert_eq!(sized(1), json!(0));
    }

    #[test]
    fn the_name_of_a_machine_is_trimmed_and_cut_to_64_characters() {
        let long = format!(" {} ", "x".repeat(70));
        let translation = translate(&inventory(vec![host()], vec![machine("vm-1", &long)]));
        assert_eq!(labels(&translation, Kind::VirtualMachine), ["x".repeat(64)]);
    }

    #[test]
    fn the_platform_of_a_machine_is_what_its_tools_report() {
        let platform = |machine: Machine| {
            let vm = one(&translate(&inventory(vec![host()], vec![machine])), Kind::VirtualMachine, "web01");
            let name = vm.references.get("platform").map(|_| target(&vm, "platform"));
            (name, vm.only_when_empty.contains("platform"))
        };
        let details = |pairs: &[(&str, &str)]| {
            Some(pairs.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect::<BTreeMap<_, _>>())
        };
        // The "prettyName" of the tools, then `guest.guestFullName`: both are written at every run.
        let pretty = Machine {
            guest_details: details(&[("prettyName", "Debian GNU/Linux 12 (bookworm)")]),
            ..machine("vm-1", "web01")
        };
        assert_eq!(platform(pretty), (owned("Debian GNU/Linux 12 (bookworm)"), false));
        assert_eq!(platform(machine("vm-1", "web01")), (owned("Debian GNU/Linux 12 (64-bit)"), false));
        // The build of a Windows changes at every update: it is left out of the name, as the
        // netbox-sync patched in production left it out. Only Windows names are cut.
        let windows = Machine {
            guest_details: details(&[("prettyName", "Windows Server 2022, 64-bit (Build 20348.5870)")]),
            ..machine("vm-1", "web01")
        };
        assert_eq!(platform(windows), (owned("Windows Server 2022, 64-bit"), false));
        let other =
            Machine { guest_details: details(&[("prettyName", "Photon OS (Build 42)")]), ..machine("vm-1", "web01") };
        assert_eq!(platform(other), (owned("Photon OS (Build 42)"), false));
        // An empty "prettyName" is none.
        let empty = Machine { guest_details: details(&[("prettyName", " ")]), ..machine("vm-1", "web01") };
        assert_eq!(platform(empty), (owned("Debian GNU/Linux 12 (64-bit)"), false));
        // The tools told nothing: netbox-sync wrote the system of the configuration over what they had
        // reported before. It only fills a machine that has no platform.
        let silent = Machine { guest_full_name: None, ..machine("vm-1", "web01") };
        assert_eq!(platform(silent), (owned("Other Linux (64-bit)"), true));
        let unknown = Machine { guest_full_name: None, config_guest_full_name: None, ..machine("vm-1", "web01") };
        assert_eq!(platform(unknown), (None, false));
    }

    #[test]
    fn a_machine_whose_tools_do_not_run_keeps_the_addresses_netbox_has() {
        // netbox-sync declared none: with pruning they would be deleted.
        let nics = vec![card("Network adapter 1", "02:00:00:00:00:21", "none")];
        let guests = vec![guest("02:00:00:00:00:21", &[("10.0.0.5", 24)])];
        let stale = Machine {
            tools_running_status: owned("guestToolsNotRunning"),
            nics: Some(nics.clone()),
            guest_nics: Some(guests),
            ..machine("vm-1", "web01")
        };
        let translation = translate(&inventory(vec![host()], vec![stale]));
        let vm = one(&translation, Kind::VirtualMachine, "web01");
        assert_eq!(vm.unknown_dependents, BTreeSet::from([Kind::IpAddress]));
        // What the guest listed before its tools stopped is not trusted either.
        assert_eq!(labels(&translation, Kind::IpAddress), Vec::<String>::new());
        assert_eq!(labels(&translation, Kind::VmInterface), ["vNIC 1 (none)"]);
        // Tools that run and a guest that lists nothing: the machine has no address.
        let bare = Machine { nics: Some(nics.clone()), ..machine("vm-1", "web01") };
        let vm = one(&translate(&inventory(vec![host()], vec![bare])), Kind::VirtualMachine, "web01");
        assert_eq!(vm.unknown_dependents, BTreeSet::new());
        // Tools that run and no `guest.net` at all: unknown.
        let silent = Machine { nics: Some(nics), guest_nics: None, ..machine("vm-1", "web01") };
        let vm = one(&translate(&inventory(vec![host()], vec![silent])), Kind::VirtualMachine, "web01");
        assert_eq!(vm.unknown_dependents, BTreeSet::from([Kind::IpAddress]));
    }

    #[test]
    fn a_machine_whose_devices_were_not_reported_keeps_what_netbox_has() {
        let silent = Machine { nics: None, disks: None, ..machine("vm-1", "web01") };
        let vm = one(&translate(&inventory(vec![host()], vec![silent])), Kind::VirtualMachine, "web01");
        assert_eq!(
            vm.unknown_dependents,
            BTreeSet::from([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress, Kind::VirtualDisk])
        );
        // A machine that reports no disk has none: netbox-sync left the disks NetBox had in place.
        let vm =
            one(&translate(&inventory(vec![host()], vec![machine("vm-1", "web01")])), Kind::VirtualMachine, "web01");
        assert_eq!(vm.unknown_dependents, BTreeSet::new());
    }

    fn disk(label: &str) -> Disk {
        Disk {
            label: owned(label),
            capacity_kb: Some(41_943_040),
            file_name: owned("[store1] web01/web01.vmdk"),
            root_file_name: owned("[store1] web01/web01.vmdk"),
            disk_mode: owned("independent_persistent"),
            thin_provisioned: Some(false),
        }
    }

    #[test]
    fn a_disk_is_described_by_its_mode_its_provisioning_and_its_file() {
        // A disk that does not say how it is provisioned (a raw device mapping): netbox-sync called it thick.
        let raw = Disk { thin_provisioned: None, disk_mode: None, capacity_kb: None, ..disk("Hard disk 2") };
        let nameless = Disk { label: None, ..disk("") };
        let vm = Machine {
            disks: Some(vec![disk("Hard disk 1"), raw, nameless, disk("Hard disk 1")]),
            ..machine("vm-1", "web01")
        };
        let translation = translate(&inventory(vec![host()], vec![vm]));
        let first = one(&translation, Kind::VirtualDisk, "Hard disk 1");
        // 41943040 KB is 40 GiB: 40000.
        assert_eq!(first.fields["size"], json!(40_000));
        assert_eq!(
            first.fields["description"],
            json!("Independent-persistent / ThickProvisioned / [store1] web01/web01.vmdk")
        );
        let second = one(&translation, Kind::VirtualDisk, "Hard disk 2");
        assert_eq!(second.fields["description"], json!("[store1] web01/web01.vmdk"));
        assert!(!second.fields.contains_key("size"));
        assert_eq!(
            translation.warnings,
            [
                "vm web01: a disk without label is skipped",
                "vm web01: disk Hard disk 1 is listed twice; the second one is skipped"
            ]
        );
    }

    #[test]
    fn the_cards_of_a_machine_follow_the_port_group_of_its_host() {
        let groups = vec![
            group("dmz%2ffront", 120, "vSwitch0", &[]),
            group("trunk", 4095, "vSwitch0", &[]),
            group("flat", 0, "vSwitch0", &[]),
        ];
        let host = Host { portgroups: Some(groups), ..host() };
        let nics = vec![
            card("Network adapter 1", "02:00:00:00:00:21", "dmz%2ffront"),
            card("Network adapter 2", "02:00:00:00:00:22", "trunk"),
            card("Network adapter 3", "02:00:00:00:00:23", "flat"),
            card("Network adapter 4", "02:00:00:00:00:24", "elsewhere"),
        ];
        let vm = Machine { nics: Some(nics), ..machine("vm-1", "web01") };
        let translation = translate(&inventory(vec![host], vec![vm]));
        // The name of the network is unquoted, as is the name of the VLAN it gives.
        let front = one(&translation, Kind::VmInterface, "vNIC 1 (dmz/front)");
        assert_eq!(front.fields["description"], json!("Network adapter 1 (VirtualVmxnet3) (vlan ID: 120)"));
        assert_eq!((&front.fields["mode"], &front.fields["mtu"]), (&json!("access"), &json!(9000)));
        assert_eq!(target(&front, "untagged_vlan"), "120");
        assert_eq!(one(&translation, Kind::Vlan, "120").create_only["name"], json!("dmz/front"));
        let trunk = one(&translation, Kind::VmInterface, "vNIC 2 (trunk)");
        assert_eq!(trunk.fields["description"], json!("Network adapter 2 (VirtualVmxnet3) (all vlans)"));
        assert_eq!(trunk.fields["mode"], json!("tagged-all"));
        assert!(!trunk.references.contains_key("untagged_vlan"));
        let flat = one(&translation, Kind::VmInterface, "vNIC 3 (flat)");
        assert_eq!(flat.fields["description"], json!("Network adapter 3 (VirtualVmxnet3) (vlan ID: 0)"));
        assert_eq!(flat.fields["mode"], json!("access"));
        assert!(!flat.references.contains_key("untagged_vlan"));
        // A network the host has no port group for: the card keeps its name, and nothing is said of its VLAN.
        let lost = one(&translation, Kind::VmInterface, "vNIC 4 (elsewhere)");
        assert_eq!(lost.fields["description"], json!("Network adapter 4 (VirtualVmxnet3)"));
        assert!(!lost.fields.contains_key("mode") && !lost.fields.contains_key("mtu"));
        assert_eq!(labels(&translation, Kind::Vlan), ["120"]);
    }

    #[test]
    fn what_the_guest_says_of_a_card_wins_over_its_configuration() {
        let nics = vec![card("Network adapter 1", "02:00:00:00:00:21", "none")];
        let unplugged = GuestNic { connected: Some(false), ..guest("02:00:00:00:00:21", &[]) };
        let vm = Machine { nics: Some(nics), guest_nics: Some(vec![unplugged]), ..machine("vm-1", "web01") };
        let translation = translate(&inventory(vec![host()], vec![vm]));
        assert_eq!(one(&translation, Kind::VmInterface, "vNIC 1 (none)").fields["enabled"], json!(false));
    }

    #[test]
    fn the_addresses_of_a_machine_are_the_ones_its_guest_lists_for_its_cards() {
        let nics = vec![
            card("Network adapter 1", "02:00:00:00:00:21", "front"),
            card("Network adapter 2", "02:00:00:00:00:22", "back"),
        ];
        let guests = vec![
            // A bridge of the guest: no card of the machine has this MAC address.
            guest("02:42:00:00:00:01", &[("172.17.0.1", 16)]),
            guest("02:00:00:00:00:22", &[("10.0.1.5", 24), ("10.0.0.5", 24)]),
            guest("02:00:00:00:00:21", &[("10.0.0.5", 24), ("fe80::1", 64), ("2001:db8::5", 64)]),
        ];
        let routes = vec![
            Route { network: "0.0.0.0".to_owned(), prefix_length: Some(0), gateway: owned("10.0.9.254") },
            Route { network: "10.0.1.0".to_owned(), prefix_length: Some(24), gateway: None },
            // The last default route of a family is the one.
            Route { network: "0.0.0.0".to_owned(), prefix_length: Some(0), gateway: owned("10.0.1.254") },
        ];
        let vm =
            Machine { nics: Some(nics), guest_nics: Some(guests), routes: Some(routes), ..machine("vm-1", "web01") };
        let translation = translate(&inventory(vec![host()], vec![vm]));
        // In the order of the cards; the address listed on both is one object, on the first card.
        let held: Vec<(String, String)> = translation
            .objects
            .iter()
            .filter(|object| object.kind == Kind::IpAddress)
            .map(|address| (target(address, "assigned_object"), address.identity.label().to_owned()))
            .collect();
        let expected =
            [("vNIC 1 (front)", "10.0.0.5/24"), ("vNIC 1 (front)", "2001:db8::5/64"), ("vNIC 2 (back)", "10.0.1.5/24")];
        assert_eq!(held, expected.map(|(interface, address)| (interface.to_owned(), address.to_owned())));
        assert_eq!(translation.warnings, ["vm web01: 10.0.0.5 is listed twice; the one on vNIC 2 (back) is skipped"]);
        let vm = one(&translation, Kind::VirtualMachine, "web01");
        // The address whose network holds the default gateway; in IPv6 the only address of the machine.
        assert_eq!(target(&vm, "primary_ip4"), "10.0.1.5/24");
        assert_eq!(target(&vm, "primary_ip6"), "2001:db8::5/64");
        assert_eq!(vm.only_when_empty, BTreeSet::from(["primary_ip4".to_owned(), "primary_ip6".to_owned()]));
    }

    // The DNS names

    /// A machine with one card and these addresses on it, on the host of the tests.
    fn addressed(addresses: &[(&str, u8)]) -> Inventory {
        let nics = vec![card("Network adapter 1", "02:00:00:00:00:21", "front")];
        let guests = vec![guest("02:00:00:00:00:21", addresses)];
        let vm = Machine { nics: Some(nics), guest_nics: Some(guests), ..machine("vm-1", "web01") };
        inventory(vec![host()], vec![vm])
    }

    fn resolved<const N: usize>(names: [(&str, &str); N]) -> BTreeMap<IpAddr, String> {
        names.into_iter().map(|(address, name)| (address.parse().unwrap(), name.to_owned())).collect()
    }

    #[test]
    fn the_address_of_a_machine_gets_the_name_of_its_reverse_lookup_in_ipv4_and_in_ipv6() {
        let names = resolved([("10.0.0.5", "web01.lab.example."), ("2001:db8::5", "WEB01.v6.Example.")]);
        let inventory = addressed(&[("10.0.0.5", 24), ("2001:db8::5", 64), ("10.0.0.6", 24)]);
        let translation = desired(&inventory, &settings(), &names).unwrap();
        // support.py, reverse_lookup: resolved_name = response.name.lower(); the final dot is not written.
        assert_eq!(one(&translation, Kind::IpAddress, "10.0.0.5/24").fields["dns_name"], json!("web01.lab.example"));
        assert_eq!(one(&translation, Kind::IpAddress, "2001:db8::5/64").fields["dns_name"], json!("web01.v6.example"));
        // inventory.py:440: `if dns_name is not None` — without a record the name NetBox holds is kept.
        assert!(!one(&translation, Kind::IpAddress, "10.0.0.6/24").fields.contains_key("dns_name"));
        assert_eq!(translation.warnings, Vec::<String>::new());
    }

    #[test]
    fn the_address_of_a_vmkernel_interface_gets_the_name_of_its_reverse_lookup() {
        let host = Host {
            vnics: Some(vec![vmk("vmk0", "ESX-MGMT", "10.0.0.5", "255.255.255.0")]),
            portgroups: Some(vec![group("ESX-MGMT", 0, "vSwitch0", &[])]),
            ..host()
        };
        let names = resolved([("10.0.0.5", "esx.lab.example.")]);
        let translation = desired(&inventory(vec![host], Vec::new()), &settings(), &names).unwrap();
        assert_eq!(one(&translation, Kind::IpAddress, "10.0.0.5/24").fields["dns_name"], json!("esx.lab.example"));
    }

    #[test]
    fn only_the_addresses_that_are_synced_are_looked_up_each_once() {
        let narrowed = Settings { ignored_subnets: vec!["10.9.0.0/16".parse().unwrap()], ..settings() };
        let nics = vec![
            card("Network adapter 1", "02:00:00:00:00:21", "front"),
            card("Network adapter 2", "02:00:00:00:00:22", "back"),
        ];
        let guests = vec![
            guest("02:00:00:00:00:21", &[("10.0.0.5", 24), ("fe80::1", 64), ("10.9.0.5", 24), ("169.254.1.1", 16)]),
            // Listed twice: the second one is skipped, and not looked up again.
            guest("02:00:00:00:00:22", &[("10.0.0.5", 24), ("2001:db8::5", 64)]),
        ];
        let vm = Machine { nics: Some(nics), guest_nics: Some(guests), ..machine("vm-1", "web01") };
        let asked = std::sync::Mutex::new(Vec::new());
        let resolver = |address: IpAddr| {
            asked.lock().unwrap().push(address.to_string());
            None
        };
        desired(&inventory(vec![host()], vec![vm]), &narrowed, &resolver).unwrap();
        assert_eq!(*asked.lock().unwrap(), ["10.0.0.5", "2001:db8::5"]);
    }

    #[test]
    fn a_name_netbox_would_refuse_is_not_reported_and_all_of_them_give_one_warning() {
        let names = resolved([
            ("10.0.0.5", "web 01.lab.example."),
            ("10.0.0.6", "web01.lab.example."),
            ("10.0.0.7", "web01..example."),
            ("10.0.0.8", "."),
        ]);
        let inventory = addressed(&[("10.0.0.5", 24), ("10.0.0.6", 24), ("10.0.0.7", 24), ("10.0.0.8", 24)]);
        let translation = desired(&inventory, &settings(), &names).unwrap();
        let name = |address: &str| one(&translation, Kind::IpAddress, address).fields.get("dns_name").cloned();
        assert_eq!(name("10.0.0.5/24"), None);
        assert_eq!(name("10.0.0.6/24"), Some(json!("web01.lab.example")));
        assert_eq!(name("10.0.0.7/24"), None);
        // An empty name is no name: not reported either, and nothing to tell.
        assert_eq!(name("10.0.0.8/24"), None);
        assert_eq!(
            translation.warnings,
            ["reverse DNS: 2 names NetBox would refuse are not written \
              (10.0.0.5: \"web 01.lab.example.\", 10.0.0.7: \"web01..example.\")"]
        );
    }

    #[test]
    fn with_two_ipv6_addresses_the_one_towards_the_default_gateway_is_primary() {
        let nics = vec![card("Network adapter 1", "02:00:00:00:00:21", "front")];
        let guests = vec![guest("02:00:00:00:00:21", &[("2001:db8:1::5", 64), ("2001:db8:2::5", 64)])];
        let routes = vec![Route { network: "::".to_owned(), prefix_length: Some(0), gateway: owned("2001:db8:2::1") }];
        let vm = Machine {
            nics: Some(nics.clone()),
            guest_nics: Some(guests.clone()),
            routes: Some(routes),
            ..machine("vm-1", "web01")
        };
        let translation = translate(&inventory(vec![host()], vec![vm]));
        assert_eq!(target(&one(&translation, Kind::VirtualMachine, "web01"), "primary_ip6"), "2001:db8:2::5/64");
        // Without default route none of the two is.
        let vm = Machine { nics: Some(nics), guest_nics: Some(guests), ..machine("vm-1", "web01") };
        let translation = translate(&inventory(vec![host()], vec![vm]));
        assert!(!one(&translation, Kind::VirtualMachine, "web01").references.contains_key("primary_ip6"));
    }

    #[test]
    fn a_card_is_left_out_by_the_interface_filter_or_for_want_of_a_label() {
        let nics = vec![
            card("Network adapter 1", "02:00:00:00:00:21", "front"),
            card("Network adapter 2", "02:00:00:00:00:22", "backup"),
            MachineNic { label: None, ..card("", "02:00:00:00:00:23", "front") },
        ];
        let guests = vec![guest("02:00:00:00:00:22", &[("10.0.1.5", 24)])];
        let vm = Machine { nics: Some(nics), guest_nics: Some(guests), ..machine("vm-1", "web01") };
        let filtered = Settings { interface_filter: Some(Regex::new(r"\(backup\)$").unwrap()), ..settings() };
        let translation = desired(&inventory(vec![host()], vec![vm]), &filtered, &NoReverseDns).unwrap();
        assert_eq!(labels(&translation, Kind::VmInterface), ["vNIC 1 (front)"]);
        assert_eq!(labels(&translation, Kind::IpAddress), Vec::<String>::new());
        assert_eq!(translation.warnings, ["vm web01: a network card without label is skipped"]);
    }

    // The tags

    fn tag(name: &str, description: &str, kind: &str, id: &str) -> Tag {
        Tag {
            name: name.to_owned(),
            description: description.to_owned(),
            objects: vec![Tagged { kind: kind.to_owned(), id: id.to_owned() }],
        }
    }

    #[test]
    fn a_machine_carries_its_tags_those_of_its_cluster_and_those_of_its_datacenter() {
        let mut inventory = inventory(vec![host()], vec![machine("vm-1", "web01"), machine("vm-2", "web02")]);
        inventory.machines[1].instance_uuid = owned("00000000-0000-4000-8000-00000000000b");
        inventory.tags = vec![
            tag("service-apache", "", "VirtualMachine", "vm-1"),
            // netbox-sync looked for the cluster above the folder of the machine, where no cluster ever is:
            // the tags of a cluster never reached its machines.
            tag("backup-daily", "Backed up every night", "ClusterComputeResource", "domain-c1"),
            tag("dc-paris", "", "Datacenter", "datacenter-2"),
            tag("of-a-host", "", "HostSystem", "host-1"),
            // The same tag again, in another letter case: one NetBox tag.
            tag("Service-Apache", "", "Datacenter", "datacenter-2"),
        ];
        let translation = translate(&inventory);
        let tags = |name: &str| one(&translation, Kind::VirtualMachine, name).tags.expect("tags");
        assert_eq!(tags("web01"), BTreeSet::from(["service-apache", "backup-daily", "dc-paris"].map(str::to_owned)));
        assert_eq!(tags("web02"), BTreeSet::from(["backup-daily", "dc-paris", "Service-Apache"].map(str::to_owned)));
        assert_eq!(labels(&translation, Kind::Tag), ["service-apache", "backup-daily", "dc-paris"]);
        let backup = one(&translation, Kind::Tag, "backup-daily");
        assert_eq!(backup.create_only["description"], json!("netbox-omnisync: Backed up every night"));
        assert_eq!(backup.create_only["slug"], json!("backup-daily"));
    }

    #[test]
    fn a_tag_netbox_already_has_is_never_rewritten() {
        // netbox-sync wrote its marker in the description of any tag of that name, one made by hand
        // included, and then removed that tag from every machine vSphere does not tag with it.
        let mut inventory = inventory(vec![host()], vec![machine("vm-1", "web01")]);
        inventory.tags = vec![tag("check-only-ping", "", "VirtualMachine", "vm-1")];
        let declared = one(&translate(&inventory), Kind::Tag, "check-only-ping");
        assert!(declared.ensure_only);
        assert!(!declared.fields.contains_key("description"));
        assert_eq!(declared.create_only["description"], json!("netbox-omnisync"));
    }

    // Homonyms

    #[test]
    fn two_clusters_of_one_name_are_one_netbox_cluster() {
        let mut inventory = inventory(vec![host()], Vec::new());
        inventory.datacenters.push(node("Datacenter", "datacenter-9", "DC2", reference("Folder", "group-d1")));
        inventory.clusters.push(node(
            "ClusterComputeResource",
            "domain-c2",
            "PROD",
            reference("Datacenter", "datacenter-9"),
        ));
        let translation = translate(&inventory);
        assert_eq!(labels(&translation, Kind::Cluster), [CLUSTER]);
        assert_eq!(labels(&translation, Kind::ClusterGroup), ["DC1", "DC2"]);
        assert_eq!(
            translation.warnings,
            [
                "cluster PROD exists in datacenters DC1 and DC2: NetBox names a cluster once, both are synced as the one of DC1"
            ]
        );
    }

    #[test]
    fn the_order_vcenter_lists_homonyms_in_decides_nothing() {
        let named = |id: &str, power: &str, uuid: &str| Machine {
            power_state: owned(power),
            instance_uuid: owned(uuid),
            ..machine(id, "web01")
        };
        let kept = |machines: Vec<Machine>| {
            let translation = translate(&inventory(vec![host()], machines));
            let vm = one(&translation, Kind::VirtualMachine, "web01");
            (vm.fields["serial"].as_str().unwrap().to_owned(), translation.warnings)
        };
        let (old, new, off) = (
            named("vm-20", "poweredOn", "old"),
            named("vm-100", "poweredOn", "new"),
            named("vm-3", "poweredOff", "off"),
        );
        let warnings = [
            "skipping vm web01 (vm-100): name already used by vm-20 in cluster prod; machine names must be unique in a cluster",
            "skipping vm web01 (vm-3): name already used by vm-20 in cluster prod; machine names must be unique in a cluster",
        ];
        // The running ones first, then the lower number: `vm-20` is before `vm-100`.
        for machines in [vec![new.clone(), off.clone(), old.clone()], vec![off, old, new]] {
            assert_eq!(kept(machines), ("old".to_owned(), warnings.map(str::to_owned).to_vec()));
        }
    }

    // Distributed switches

    #[test]
    fn what_is_on_a_distributed_switch_keeps_its_name_and_addresses_and_nothing_else_is_said() {
        let proxy = ProxySwitch {
            name: owned("dvs-prod"),
            uuid: owned("50 2a"),
            mtu: Some(9000),
            pnics: vec!["vmnic0".to_owned()],
        };
        let distributed_vmk = VirtualNic {
            portgroup: owned(""),
            distributed: Some(("50 2a".to_owned(), "dvportgroup-11".to_owned())),
            ..vmk("vmk0", "", "10.0.0.5", "255.255.255.0")
        };
        let host = Host {
            pnics: Some(vec![pnic("vmnic0", Some(10_000))]),
            vnics: Some(vec![distributed_vmk]),
            proxy_switches: Some(vec![proxy]),
            ..host()
        };
        let backing =
            NicBacking::Distributed { switch_uuid: "50 2a".to_owned(), portgroup_key: "dvportgroup-12".to_owned() };
        let nics = vec![MachineNic { backing: Some(backing), ..card("Network adapter 1", "02:00:00:00:00:21", "") }];
        let guests = vec![guest("02:00:00:00:00:21", &[("10.0.1.5", 24)])];
        let vm = Machine { nics: Some(nics), guest_nics: Some(guests), ..machine("vm-1", "web01") };
        let mut inventory = inventory(vec![host], vec![vm]);
        inventory.switches =
            vec![DistributedSwitch { id: "dvs-10".to_owned(), name: owned("dvs-prod"), uuid: owned("50 2a") }];
        inventory.port_groups = vec![DistributedPortGroup {
            id: "dvportgroup-12".to_owned(),
            name: owned("dv-front"),
            key: owned("dvportgroup-12"),
            switch: reference("VmwareDistributedVirtualSwitch", "dvs-10"),
            default_port_config: None,
        }];
        let translation = translate(&inventory);
        assert_eq!(
            translation.warnings,
            ["distributed switches are not supported yet (1 switch(es), 1 port group(s), 1 host(s) on one): the \
              interfaces on them keep their name, MAC and IP addresses, their VLANs, mode, MTU and description are \
              left as NetBox has them"]
        );
        // The card is named after its port group, as netbox-sync named it: the interface NetBox has is found.
        let card = one(&translation, Kind::VmInterface, "vNIC 1 (dv-front)");
        let said: Vec<&str> = card.fields.keys().map(String::as_str).collect();
        assert_eq!(said, ["enabled", "name"]);
        let referred: Vec<&str> = card.references.keys().map(String::as_str).collect();
        assert_eq!(referred, ["primary_mac_address", "virtual_machine"]);
        // The uplink says what the card itself tells, nothing of the switch.
        let uplink = one(&translation, Kind::Interface, "vmnic0");
        let said: Vec<&str> = uplink.fields.keys().map(String::as_str).collect();
        assert_eq!(said, ["duplex", "enabled", "name", "speed", "type"]);
        assert!(uplink.reference_lists.is_empty());
        let vmk0 = one(&translation, Kind::Interface, "vmk0");
        let said: Vec<&str> = vmk0.fields.keys().map(String::as_str).collect();
        assert_eq!(said, ["enabled", "mtu", "name", "type"]);
        assert!(!vmk0.references.contains_key("untagged_vlan"));
        // Addresses and MAC addresses are synced all the same.
        assert_eq!(labels(&translation, Kind::IpAddress), ["10.0.0.5/24", "10.0.1.5/24"]);
        assert_eq!(labels(&translation, Kind::MacAddress).len(), 3);
        assert_eq!(labels(&translation, Kind::Vlan), Vec::<String>::new());
    }

    #[test]
    fn a_vcenter_without_distributed_switch_says_nothing_of_them() {
        assert_eq!(translate(&inventory(vec![host()], vec![machine("vm-1", "web01")])).warnings, Vec::<String>::new());
    }
}
