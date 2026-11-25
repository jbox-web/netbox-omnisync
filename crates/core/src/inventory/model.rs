//! What a hypervisor source asks for, and what NetBox holds.
//!
//! A source describes an object graph as a flat list of [`Desired`] objects;
//! the loader describes NetBox as a flat list of [`Current`] objects. Both
//! sides name an object by its [`Identity`], never by a NetBox id: a source
//! does not know NetBox, and an object created in this run has no id yet.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use serde_json::Value;

use crate::change::Fields;
use crate::gateway::Row;
use crate::inventory::custom_fields::Definition;

/// Slug (and name) of the tag carried by every object the tool manages.
pub const TOOL_TAG: &str = "netbox-omnisync";

/// How a tag made from a tag of a source (vSphere, Proxmox) is told from one
/// set by hand: its description is this text, followed by `: ` and the
/// description the source gives it when there is one. Such a tag leaves a
/// machine once its source no longer tags it; any other tag is somebody's.
pub const TAG_MARKER: &str = "netbox-omnisync";

/// The marker netbox-sync wrote on the tags it made from vSphere tags: still
/// recognised, never written.
pub const LEGACY_TAG_MARKERS: [&str; 1] = ["NetBox-synced"];

/// Start of the slug of a per-source ownership tag.
pub const SOURCE_TAG_PREFIX: &str = "source-";

/// Slugs of the ownership tags of the tools this one replaces. An object that
/// carries one is adopted: the tag is removed and the tool's own are set.
pub const LEGACY_TAGS: [&str; 6] = [
    "netbox-synced",
    "netbox-synced-orphaned",
    "netbox-ssot",
    "netbox-ssot-orphan",
    "type-proxmox",
    "proxmox-netbox-sync",
];

/// Marks, in the last part of an IP address or prefix identity, a VRF the
/// source does not know: the object is then looked up in every table.
pub const ANY_VRF: &str = "*";

/// The sorts of NetBox objects a hypervisor source may describe.
///
/// The declaration order is the dependency order: an object only refers to
/// objects of an earlier kind, except for the few late references (a primary
/// IP, a primary MAC, a parent interface) that the reconciliation writes in a
/// second step. Creations follow this order, deletions the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Tag,
    Tenant,
    Site,
    Manufacturer,
    DeviceType,
    Platform,
    Role,
    ClusterType,
    ClusterGroup,
    Cluster,
    Vrf,
    VlanGroup,
    Vlan,
    Prefix,
    Device,
    VirtualMachine,
    Interface,
    VmInterface,
    VirtualDisk,
    MacAddress,
    IpAddress,
}

impl Kind {
    /// Every kind, in dependency order.
    pub const ALL: [Kind; 21] = [
        Kind::Tag,
        Kind::Tenant,
        Kind::Site,
        Kind::Manufacturer,
        Kind::DeviceType,
        Kind::Platform,
        Kind::Role,
        Kind::ClusterType,
        Kind::ClusterGroup,
        Kind::Cluster,
        Kind::Vrf,
        Kind::VlanGroup,
        Kind::Vlan,
        Kind::Prefix,
        Kind::Device,
        Kind::VirtualMachine,
        Kind::Interface,
        Kind::VmInterface,
        Kind::VirtualDisk,
        Kind::MacAddress,
        Kind::IpAddress,
    ];

    /// Gateway endpoint, named `app.name`.
    pub fn endpoint(self) -> &'static str {
        match self {
            Kind::Tag => "extras.tags",
            Kind::Tenant => "tenancy.tenants",
            Kind::Site => "dcim.sites",
            Kind::Manufacturer => "dcim.manufacturers",
            Kind::DeviceType => "dcim.device_types",
            Kind::Platform => "dcim.platforms",
            Kind::Role => "dcim.device_roles",
            Kind::ClusterType => "virtualization.cluster_types",
            Kind::ClusterGroup => "virtualization.cluster_groups",
            Kind::Cluster => "virtualization.clusters",
            Kind::Vrf => "ipam.vrfs",
            Kind::VlanGroup => "ipam.vlan_groups",
            Kind::Vlan => "ipam.vlans",
            Kind::Prefix => "ipam.prefixes",
            Kind::Device => "dcim.devices",
            Kind::VirtualMachine => "virtualization.virtual_machines",
            Kind::Interface => "dcim.interfaces",
            Kind::VmInterface => "virtualization.interfaces",
            Kind::VirtualDisk => "virtualization.virtual_disks",
            Kind::MacAddress => "dcim.mac_addresses",
            Kind::IpAddress => "ipam.ip_addresses",
        }
    }

    /// Value of `Change.kind`, shared with the network sources where the object is the same.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Tag => "tag",
            Kind::Tenant => "tenant",
            Kind::Site => "site",
            Kind::Manufacturer => "manufacturer",
            Kind::DeviceType => "device_type",
            Kind::Platform => "platform",
            Kind::Role => "role",
            Kind::ClusterType => "cluster_type",
            Kind::ClusterGroup => "cluster_group",
            Kind::Cluster => "cluster",
            Kind::Vrf => "vrf",
            Kind::VlanGroup => "vlan_group",
            Kind::Vlan => "vlan",
            Kind::Prefix => "prefix",
            Kind::Device => "device",
            Kind::VirtualMachine => "vm",
            Kind::Interface => "interface",
            Kind::VmInterface => "vm_interface",
            Kind::VirtualDisk => "disk",
            Kind::MacAddress => "mac",
            Kind::IpAddress => "ip",
        }
    }

    /// NetBox content type, as written in the `*_type` half of a generic relation.
    pub fn content_type(self) -> &'static str {
        match self {
            Kind::Tag => "extras.tag",
            Kind::Tenant => "tenancy.tenant",
            Kind::Site => "dcim.site",
            Kind::Manufacturer => "dcim.manufacturer",
            Kind::DeviceType => "dcim.devicetype",
            Kind::Platform => "dcim.platform",
            Kind::Role => "dcim.devicerole",
            Kind::ClusterType => "virtualization.clustertype",
            Kind::ClusterGroup => "virtualization.clustergroup",
            Kind::Cluster => "virtualization.cluster",
            Kind::Vrf => "ipam.vrf",
            Kind::VlanGroup => "ipam.vlangroup",
            Kind::Vlan => "ipam.vlan",
            Kind::Prefix => "ipam.prefix",
            Kind::Device => "dcim.device",
            Kind::VirtualMachine => "virtualization.virtualmachine",
            Kind::Interface => "dcim.interface",
            Kind::VmInterface => "virtualization.vminterface",
            Kind::VirtualDisk => "virtualization.virtualdisk",
            Kind::MacAddress => "dcim.macaddress",
            Kind::IpAddress => "ipam.ipaddress",
        }
    }

    /// The kind a content type names, if it is one of ours.
    pub fn from_content_type(content_type: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.content_type() == content_type)
    }

    /// Place in the dependency order: lower is created first and deleted last.
    pub fn rank(self) -> usize {
        self as usize
    }

    /// NetBox has no tags on a tag: ownership cannot be recorded on one.
    pub fn taggable(self) -> bool {
        self != Kind::Tag
    }

    /// The field holding the name by which this kind is identified without
    /// regard to letter case. A difference of case alone on that field is not
    /// a change: the object was found by that very name.
    pub fn caseless_field(self) -> Option<&'static str> {
        match self {
            Kind::Tag
            | Kind::Tenant
            | Kind::Site
            | Kind::Manufacturer
            | Kind::Platform
            | Kind::Role
            | Kind::ClusterType
            | Kind::ClusterGroup
            | Kind::Cluster
            | Kind::Vrf
            | Kind::VlanGroup
            | Kind::Device
            | Kind::VirtualMachine
            | Kind::Interface => Some("name"),
            Kind::DeviceType => Some("model"),
            _ => None,
        }
    }

    /// References NetBox stores as a generic relation: `scope` is read and
    /// written as `scope_type` + `scope_id`.
    pub fn generic_fields(self) -> &'static [&'static str] {
        match self {
            Kind::IpAddress | Kind::MacAddress => &["assigned_object"],
            Kind::Cluster | Kind::Prefix | Kind::VlanGroup => &["scope"],
            _ => &[],
        }
    }

    /// The plain foreign keys of a row of this kind, with the kind they point
    /// to. Used to keep an object that a matched row still points to through a
    /// field the source did not report.
    pub fn reference_fields(self) -> &'static [(&'static str, Kind)] {
        match self {
            Kind::VirtualMachine => &[
                ("platform", Kind::Platform),
                ("role", Kind::Role),
                ("tenant", Kind::Tenant),
                ("site", Kind::Site),
                ("cluster", Kind::Cluster),
                ("device", Kind::Device),
            ],
            Kind::Device => &[
                ("platform", Kind::Platform),
                ("role", Kind::Role),
                ("tenant", Kind::Tenant),
                ("site", Kind::Site),
                ("device_type", Kind::DeviceType),
                ("cluster", Kind::Cluster),
            ],
            Kind::Cluster => &[("type", Kind::ClusterType), ("group", Kind::ClusterGroup), ("tenant", Kind::Tenant)],
            Kind::DeviceType => &[("manufacturer", Kind::Manufacturer)],
            Kind::Platform => &[("manufacturer", Kind::Manufacturer)],
            Kind::Interface | Kind::VmInterface => &[("untagged_vlan", Kind::Vlan), ("vrf", Kind::Vrf)],
            Kind::IpAddress => &[("vrf", Kind::Vrf), ("tenant", Kind::Tenant)],
            Kind::Prefix => &[("vrf", Kind::Vrf), ("vlan", Kind::Vlan), ("tenant", Kind::Tenant)],
            Kind::Vlan => &[("group", Kind::VlanGroup), ("site", Kind::Site), ("tenant", Kind::Tenant)],
            _ => &[],
        }
    }
}

impl Kind {
    /// The many-to-many references of a row of this kind, with the kind they
    /// point to. NetBox takes a deleted object off such a list without a
    /// word: a row that is left as it is keeps what it lists, as it keeps
    /// what it points to through a plain foreign key.
    pub fn reference_list_fields(self) -> &'static [(&'static str, Kind)] {
        match self {
            Kind::Interface | Kind::VmInterface => &[("tagged_vlans", Kind::Vlan)],
            _ => &[],
        }
    }
}

/// Where a VLAN id is unique: NetBox scopes a VLAN to a site or to a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanScope<'a> {
    Site(&'a str),
    Group(&'a str),
    Global,
}

/// The VLAN groups of the configuration: the sites that share their VLANs
/// (one LAN stretched over two rooms) keep them in one NetBox VLAN group
/// instead of once per site. A site belongs to one group at most; a site in
/// none keeps its own VLANs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VlanGroups {
    /// Site name in lower case (NetBox reads a site name caselessly) -> the
    /// name of its group, as the configuration writes it.
    by_site: BTreeMap<String, String>,
}

impl VlanGroups {
    /// Puts `site` in `group`; gives back the group the site was already in,
    /// which it stays in.
    pub fn insert(&mut self, site: &str, group: &str) -> Option<&str> {
        let key = site.to_lowercase();
        if self.by_site.contains_key(&key) {
            return self.by_site.get(&key).map(String::as_str);
        }
        self.by_site.insert(key, group.to_owned());
        None
    }

    pub fn is_empty(&self) -> bool {
        self.by_site.is_empty()
    }

    /// The group the VLANs of `site` are kept in, if any.
    pub fn group_of(&self, site: &str) -> Option<&str> {
        self.by_site.get(&site.to_lowercase()).map(String::as_str)
    }

    /// Where a VLAN of `site` is unique: in the group of the site when it has
    /// one, at the site itself otherwise.
    pub fn scope_of<'a>(&'a self, site: &'a str) -> VlanScope<'a> {
        match self.group_of(site) {
            Some(group) => VlanScope::Group(group),
            None => VlanScope::Site(site),
        }
    }

    /// The sites that have a group (in lower case) with the name of it.
    pub fn sites(&self) -> impl Iterator<Item = (&str, &str)> {
        self.by_site.iter().map(|(site, group)| (site.as_str(), group.as_str()))
    }
}

/// The routing table of an IP address or a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfKey<'a> {
    /// The source cannot tell: the object is looked up in every table, so that
    /// a VRF set by hand in NetBox is kept instead of being duplicated.
    Unknown,
    Global,
    Named(&'a str),
}

/// How an object is found in NetBox.
///
/// `key` is the normalised form that is compared (letter case folded where the
/// rule of the kind says so); `owner` and `label` are the device or virtual
/// machine name and the human name printed in a report, and take no part in
/// the comparison.
#[derive(Debug, Clone)]
pub struct Identity {
    key: Vec<String>,
    owner: String,
    label: String,
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Identity {}

impl PartialOrd for Identity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

/// The host part of an address, in the canonical form of its family, so that
/// `2001:DB8::1/64` and `2001:db8:0::1/128` name the same host.
pub fn ip_host(address: &str) -> String {
    let host = address.split('/').next().unwrap_or(address).trim();
    match host.parse::<IpAddr>() {
        Ok(parsed) => parsed.to_string(),
        Err(_) => host.to_lowercase(),
    }
}

impl Identity {
    pub fn key(&self) -> &[String] {
        &self.key
    }

    /// Device or virtual machine name, for `Change.device`; empty for the rest.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Human name of the object, for `Change.key`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Sets the device or virtual machine the object is shown under.
    pub fn with_owner(mut self, owner: &str) -> Self {
        self.owner = owner.to_owned();
        self
    }

    fn build<const N: usize>(key: [String; N], owner: &str, label: &str) -> Self {
        Identity { key: key.into(), owner: owner.to_owned(), label: label.to_owned() }
    }

    fn vrf_part(vrf: VrfKey<'_>) -> String {
        match vrf {
            VrfKey::Unknown => ANY_VRF.to_owned(),
            VrfKey::Global => String::new(),
            VrfKey::Named(name) => name.to_lowercase(),
        }
    }

    /// Cluster, cluster type, cluster group, site, tenant, role, platform,
    /// manufacturer, tag, VRF, VLAN group: by name, whatever the letter case,
    /// and never by slug — the two reference tools did not build slugs alike.
    pub fn named(name: &str) -> Self {
        Identity::build([name.to_lowercase()], "", name)
    }

    /// A device: by its name, whatever the letter case. NetBox enforces the
    /// uniqueness of a device name on its lower-cased form: `ESX01` reported
    /// where NetBox has `esx01` is that device, and creating it is refused.
    pub fn device(name: &str) -> Self {
        Identity::build([name.to_lowercase()], name, name)
    }

    /// A virtual machine: by its name, whatever the letter case (NetBox
    /// refuses `Web01` next to `web01` in one cluster), and its cluster (a
    /// cluster name, so compared whatever the case as well). Two clusters may
    /// each hold a `web01`. The cluster is empty for a machine that has none.
    pub fn virtual_machine(name: &str, cluster: &str) -> Self {
        Identity::build([name.to_lowercase(), cluster.to_lowercase()], name, name)
    }

    /// A device type: by manufacturer and model, whatever the case. The model
    /// alone is not enough: two vendors may sell a `Generic Model`.
    pub fn device_type(manufacturer: &str, model: &str) -> Self {
        Identity::build([manufacturer.to_lowercase(), model.to_lowercase()], "", model)
    }

    /// A device interface: by device and name; the name whatever the case,
    /// NetBox holding `Port-channel1` where a host says `port-channel1`. The
    /// device part is the key of the device, so that the two always meet.
    pub fn interface(device: &str, name: &str) -> Self {
        Identity::build([device.to_lowercase(), name.to_lowercase()], device, name)
    }

    fn under(virtual_machine: &Identity, name: &str) -> Self {
        let mut key = virtual_machine.key.clone();
        key.push(name.to_owned());
        Identity { key, owner: virtual_machine.owner.clone(), label: name.to_owned() }
    }

    /// A virtual machine interface: by virtual machine and name.
    pub fn vm_interface(virtual_machine: &Identity, name: &str) -> Self {
        Identity::under(virtual_machine, name)
    }

    /// A virtual disk: by virtual machine and name.
    pub fn virtual_disk(virtual_machine: &Identity, name: &str) -> Self {
        Identity::under(virtual_machine, name)
    }

    /// An IP address: by host and VRF. The mask is a field, not part of the
    /// identity: a mask corrected on the host updates the address instead of
    /// creating a second one for the same host.
    pub fn ip_address(address: &str, vrf: VrfKey<'_>) -> Self {
        Identity::build([ip_host(address), Identity::vrf_part(vrf)], "", address)
    }

    /// A MAC address object: by address and the interface it is assigned to
    /// (`None` for an unassigned object). The same address may exist once per
    /// interface: a bridge and its port share one.
    pub fn mac_address(address: &str, assigned: Option<&Target>) -> Self {
        let address = address.to_uppercase();
        let mut key = vec![address.clone()];
        let mut owner = "";
        match assigned {
            Some(target) => {
                key.push(target.kind.content_type().to_owned());
                key.extend(target.identity.key.iter().cloned());
                owner = target.identity.owner();
            }
            None => key.push(String::new()),
        }
        Identity { key, owner: owner.to_owned(), label: address }
    }

    /// A prefix: by prefix and VRF.
    pub fn prefix(prefix: &str, vrf: VrfKey<'_>) -> Self {
        Identity::build([prefix.to_lowercase(), Identity::vrf_part(vrf)], "", prefix)
    }

    /// A VLAN: by site (or group) and VLAN id; its name is free text.
    pub fn vlan(scope: VlanScope<'_>, vid: u64) -> Self {
        let (sort, name) = match scope {
            VlanScope::Site(name) => ("site", name),
            VlanScope::Group(name) => ("group", name),
            VlanScope::Global => ("", ""),
        };
        Identity::build([sort.to_owned(), name.to_lowercase(), vid.to_string()], "", &vid.to_string())
    }
}

/// The object a reference points to: resolved to a NetBox id by the applier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target {
    pub kind: Kind,
    pub identity: Identity,
}

impl Target {
    pub fn new(kind: Kind, identity: Identity) -> Self {
        Target { kind, identity }
    }
}

/// An object as a source wants it in NetBox.
///
/// Absence means "not reported": a field, reference, custom field or the tag
/// set that is missing is left as NetBox has it. An empty value (`""`, `null`,
/// a `None` reference, an empty tag set) is a value and clears.
#[derive(Debug, Clone, PartialEq)]
pub struct Desired {
    pub kind: Kind,
    pub identity: Identity,
    /// Name of the source that reports the object.
    pub source: String,
    /// Fields written at creation and kept equal afterwards.
    pub fields: Fields,
    /// Fields written at creation only (a slug, a colour): someone may have
    /// changed them since, and nothing in the source says they should move.
    pub create_only: Fields,
    /// References to one object, by field; `None` clears the reference.
    pub references: BTreeMap<String, Option<Target>>,
    /// References to a set of objects (`tagged_vlans`), by field.
    pub reference_lists: BTreeMap<String, Vec<Target>>,
    /// Names of the tags the object has in the source itself; `None` when the
    /// source could not read them.
    pub tags: Option<BTreeSet<String>>,
    /// The custom fields the tool manages on this object; the others are kept.
    pub custom_fields: Fields,
    /// Kinds of dependents the source could not read this time (the interfaces
    /// and addresses of a stopped virtual machine): unknown is not absent, so
    /// the ones NetBox has are kept. Empty when everything was read.
    pub unknown_dependents: BTreeSet<Kind>,
    /// The source only needs the object to exist (a site, a tenant, a prefix):
    /// one found in NetBox that no tool owns is used as it is, neither tagged
    /// nor updated, so that it can never become an orphan of the source.
    pub ensure_only: bool,
    /// Names of the fields and references that are written only when NetBox
    /// holds no value there: at creation, or on an object whose field is
    /// empty. A value already set, whoever chose it, is left alone and is not
    /// a difference. This is the reference VMware tool's rule for a primary
    /// IP: one picked by hand must survive every run.
    pub only_when_empty: BTreeSet<String>,
    /// The source does not own the object: it only completes one another
    /// source, or somebody, keeps (a BMC that knows the model and the serial
    /// of a server a hypervisor reports). Such a report never creates the
    /// object, never tags it and is never a reason to delete it; its fields,
    /// references and custom fields are added, one by one, to what the owner
    /// reports (see `reconcile`).
    pub complement: bool,
}

impl Desired {
    pub fn new(kind: Kind, identity: Identity, source: &str) -> Self {
        Desired {
            kind,
            identity,
            source: source.to_owned(),
            fields: Fields::new(),
            create_only: Fields::new(),
            references: BTreeMap::new(),
            reference_lists: BTreeMap::new(),
            tags: None,
            custom_fields: Fields::new(),
            unknown_dependents: BTreeSet::new(),
            ensure_only: false,
            only_when_empty: BTreeSet::new(),
            complement: false,
        }
    }

    pub fn field(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.fields.insert(name.to_owned(), value.into());
        self
    }

    pub fn create_only(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.create_only.insert(name.to_owned(), value.into());
        self
    }

    pub fn reference(mut self, field: &str, kind: Kind, identity: Identity) -> Self {
        self.references.insert(field.to_owned(), Some(Target::new(kind, identity)));
        self
    }

    /// Reports that the object refers to nothing through `field`.
    pub fn no_reference(mut self, field: &str) -> Self {
        self.references.insert(field.to_owned(), None);
        self
    }

    pub fn reference_list(mut self, field: &str, targets: impl IntoIterator<Item = Target>) -> Self {
        self.reference_lists.insert(field.to_owned(), targets.into_iter().collect());
        self
    }

    /// Reports the tags of the object in the source; an empty list is "none".
    pub fn tags<T: Into<String>>(mut self, names: impl IntoIterator<Item = T>) -> Self {
        self.tags = Some(names.into_iter().map(Into::into).collect());
        self
    }

    /// Fills a custom field: one of the definitions the tool can create, so that
    /// no source fills a field NetBox could only be given by hand.
    pub fn custom_field(mut self, definition: &'static Definition, value: impl Into<Value>) -> Self {
        self.custom_fields.insert(definition.name.to_owned(), value.into());
        self
    }

    pub fn unknown_dependents(mut self, kinds: impl IntoIterator<Item = Kind>) -> Self {
        self.unknown_dependents = kinds.into_iter().collect();
        self
    }

    pub fn ensure_only(mut self) -> Self {
        self.ensure_only = true;
        self
    }

    /// Marks the field or reference `name` as written only when NetBox holds
    /// no value for it.
    pub fn only_when_empty(mut self, name: &str) -> Self {
        self.only_when_empty.insert(name.to_owned());
        self
    }

    /// Marks the report as completing an object the source does not own.
    pub fn complement(mut self) -> Self {
        self.complement = true;
        self
    }
}

/// A tag as NetBox nests it in an object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tag {
    pub name: String,
    pub slug: String,
}

/// An object as NetBox holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct Current {
    pub id: u64,
    pub kind: Kind,
    pub identity: Identity,
    /// The object NetBox deletes this one with: the device of an interface,
    /// the virtual machine of an interface or a disk, the interface of an
    /// address.
    pub parent: Option<(Kind, u64)>,
    pub tags: Vec<Tag>,
    /// The row as the API returned it.
    pub row: Row,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(identity: &Identity) -> Vec<&str> {
        identity.key().iter().map(String::as_str).collect()
    }

    #[test]
    fn kinds_are_ranked_in_dependency_order() {
        assert!(Kind::Tag.rank() < Kind::Site.rank());
        assert!(Kind::Manufacturer.rank() < Kind::DeviceType.rank());
        assert!(Kind::ClusterType.rank() < Kind::Cluster.rank());
        assert!(Kind::Cluster.rank() < Kind::Device.rank());
        assert!(Kind::Device.rank() < Kind::VirtualMachine.rank());
        assert!(Kind::Device.rank() < Kind::Interface.rank());
        assert!(Kind::VirtualMachine.rank() < Kind::VmInterface.rank());
        assert!(Kind::VirtualMachine.rank() < Kind::VirtualDisk.rank());
        assert!(Kind::VmInterface.rank() < Kind::MacAddress.rank());
        assert!(Kind::Interface.rank() < Kind::IpAddress.rank());
        assert!(Kind::Vlan.rank() < Kind::Interface.rank());
        assert!(Kind::Prefix.rank() < Kind::IpAddress.rank());
    }

    #[test]
    fn every_kind_is_listed_once_at_its_rank() {
        for (rank, kind) in Kind::ALL.into_iter().enumerate() {
            assert_eq!(kind.rank(), rank);
        }
    }

    #[test]
    fn a_kind_knows_its_endpoint_label_and_content_type() {
        assert_eq!(Kind::VirtualMachine.endpoint(), "virtualization.virtual_machines");
        assert_eq!(Kind::VirtualMachine.label(), "vm");
        assert_eq!(Kind::VmInterface.endpoint(), "virtualization.interfaces");
        assert_eq!(Kind::VmInterface.content_type(), "virtualization.vminterface");
        assert_eq!(Kind::Interface.endpoint(), "dcim.interfaces");
        assert_eq!(Kind::Role.endpoint(), "dcim.device_roles");
        assert_eq!(Kind::IpAddress.label(), "ip");
        assert_eq!(Kind::from_content_type("dcim.interface"), Some(Kind::Interface));
        assert_eq!(Kind::from_content_type("circuits.circuit"), None);
    }

    #[test]
    fn a_named_object_is_identified_whatever_the_case() {
        assert_eq!(Identity::named("Harbor"), Identity::named("HARBOR"));
        assert_eq!(keys(&Identity::named("Harbor")), ["harbor"]);
        assert_eq!(Identity::named("Harbor").label(), "Harbor");
        assert_eq!(Identity::named("Harbor").owner(), "");
    }

    #[test]
    fn a_device_is_identified_by_its_name_whatever_the_case() {
        assert_eq!(Identity::device("esx01"), Identity::device("ESX01"));
        assert_ne!(Identity::device("esx01"), Identity::device("esx02"));
        assert_eq!(keys(&Identity::device("ESX01.Lab")), ["esx01.lab"]);
        // What a report prints is the name as the source wrote it.
        assert_eq!(Identity::device("ESX01.Lab").owner(), "ESX01.Lab");
        assert_eq!(Identity::device("ESX01.Lab").label(), "ESX01.Lab");
    }

    #[test]
    fn a_virtual_machine_is_identified_by_name_and_cluster() {
        let web = Identity::virtual_machine("web01", "PVE-Lab");
        assert_eq!(keys(&web), ["web01", "pve-lab"]);
        assert_eq!(web, Identity::virtual_machine("web01", "pve-lab"));
        assert_ne!(web, Identity::virtual_machine("web01", "pve-prod"));
        assert_eq!(web, Identity::virtual_machine("WEB01", "PVE-Lab"));
        assert_eq!(keys(&Identity::virtual_machine("Web01", "PVE-Lab")), ["web01", "pve-lab"]);
        assert_eq!(web.owner(), "web01");
        assert_eq!(web.label(), "web01");
        assert_eq!(Identity::virtual_machine("Web01", "PVE-Lab").label(), "Web01");
    }

    #[test]
    fn a_device_type_is_identified_by_manufacturer_and_model() {
        let r640 = Identity::device_type("Dell", "PowerEdge R640");
        assert_eq!(keys(&r640), ["dell", "poweredge r640"]);
        assert_ne!(r640, Identity::device_type("HPE", "PowerEdge R640"));
        assert_eq!(r640.label(), "PowerEdge R640");
    }

    #[test]
    fn an_interface_is_identified_by_device_and_caseless_name() {
        let uplink = Identity::interface("esx01", "vmnic0");
        assert_eq!(keys(&uplink), ["esx01", "vmnic0"]);
        assert_eq!(uplink, Identity::interface("esx01", "VMNIC0"));
        assert_ne!(uplink, Identity::interface("esx02", "vmnic0"));
        // The device part is the key of the device, or the interface would not find it.
        assert_eq!(keys(&Identity::interface("ESX01", "vmnic0")), ["esx01", "vmnic0"]);
        assert_eq!(Identity::interface("ESX01", "vmnic0").owner(), "ESX01");
        assert_eq!(uplink.owner(), "esx01");
        assert_eq!(Identity::interface("esx01", "VMNIC0").label(), "VMNIC0");
    }

    #[test]
    fn a_vm_interface_and_a_disk_are_identified_under_their_virtual_machine() {
        let web = Identity::virtual_machine("web01", "PVE-Lab");
        let eth0 = Identity::vm_interface(&web, "eth0");
        assert_eq!(keys(&eth0), ["web01", "pve-lab", "eth0"]);
        assert_ne!(eth0, Identity::vm_interface(&Identity::virtual_machine("web01", "other"), "eth0"));
        assert_eq!(eth0.owner(), "web01");
        assert_eq!(eth0.label(), "eth0");
        assert_eq!(eth0, Identity::vm_interface(&Identity::virtual_machine("WEB01", "pve-lab"), "eth0"));
        let disk = Identity::virtual_disk(&web, "scsi0");
        assert_eq!(keys(&disk), ["web01", "pve-lab", "scsi0"]);
        assert_eq!(disk.owner(), "web01");
    }

    #[test]
    fn an_ip_address_is_identified_by_host_and_vrf() {
        let global = Identity::ip_address("10.0.0.5/24", VrfKey::Global);
        assert_eq!(keys(&global), ["10.0.0.5", ""]);
        assert_eq!(global, Identity::ip_address("10.0.0.5/32", VrfKey::Global));
        assert_ne!(global, Identity::ip_address("10.0.0.5/24", VrfKey::Named("prod")));
        assert_eq!(keys(&Identity::ip_address("10.0.0.5/24", VrfKey::Named("Prod"))), ["10.0.0.5", "prod"]);
        assert_eq!(keys(&Identity::ip_address("10.0.0.5/24", VrfKey::Unknown)), ["10.0.0.5", "*"]);
        assert_eq!(keys(&Identity::ip_address("2001:DB8:0::1/64", VrfKey::Global)), ["2001:db8::1", ""]);
        assert_eq!(global.label(), "10.0.0.5/24");
    }

    #[test]
    fn a_mac_address_is_identified_by_address_and_assigned_interface() {
        let web = Identity::virtual_machine("web01", "pve");
        let eth0 = Target::new(Kind::VmInterface, Identity::vm_interface(&web, "eth0"));
        let mac = Identity::mac_address("bc:24:11:aa:bb:cc", Some(&eth0));
        assert_eq!(keys(&mac), ["BC:24:11:AA:BB:CC", "virtualization.vminterface", "web01", "pve", "eth0"]);
        assert_eq!(mac.owner(), "web01");
        assert_eq!(mac.label(), "BC:24:11:AA:BB:CC");
        assert_eq!(keys(&Identity::mac_address("BC:24:11:AA:BB:CC", None)), ["BC:24:11:AA:BB:CC", ""]);
    }

    #[test]
    fn a_prefix_is_identified_by_prefix_and_vrf() {
        assert_eq!(keys(&Identity::prefix("10.0.0.0/24", VrfKey::Global)), ["10.0.0.0/24", ""]);
        assert_eq!(keys(&Identity::prefix("10.0.0.0/24", VrfKey::Named("Prod"))), ["10.0.0.0/24", "prod"]);
        assert_eq!(keys(&Identity::prefix("10.0.0.0/24", VrfKey::Unknown)), ["10.0.0.0/24", "*"]);
    }

    #[test]
    fn a_vlan_is_identified_by_site_or_group_and_vid() {
        assert_eq!(keys(&Identity::vlan(VlanScope::Site("Harbor"), 120)), ["site", "harbor", "120"]);
        assert_eq!(keys(&Identity::vlan(VlanScope::Group("Lab"), 120)), ["group", "lab", "120"]);
        assert_eq!(keys(&Identity::vlan(VlanScope::Global, 120)), ["", "", "120"]);
        assert_eq!(Identity::vlan(VlanScope::Site("Harbor"), 120).label(), "120");
    }

    #[test]
    fn the_vlans_of_a_site_are_kept_in_its_group_when_it_has_one_and_at_the_site_otherwise() {
        let mut groups = VlanGroups::default();
        assert!(groups.is_empty());
        assert_eq!(groups.insert("east-02", "East"), None);
        assert_eq!(groups.insert("east-01", "East"), None);
        assert_eq!(groups.scope_of("east-02"), VlanScope::Group("East"));
        assert_eq!(groups.scope_of("east-01"), VlanScope::Group("East"));
        // NetBox reads a site name whatever its case.
        assert_eq!(groups.scope_of("EAST-02"), VlanScope::Group("East"));
        // A site of no group keeps its own VLANs.
        assert_eq!(groups.scope_of("Harbor"), VlanScope::Site("Harbor"));
        assert_eq!(VlanGroups::default().scope_of("east-02"), VlanScope::Site("east-02"));
        assert_eq!(groups.sites().collect::<Vec<_>>(), [("east-01", "East"), ("east-02", "East")]);
    }

    #[test]
    fn a_site_stays_in_the_first_group_it_was_put_in() {
        let mut groups = VlanGroups::default();
        groups.insert("east-02", "East");
        assert_eq!(groups.insert("East-02", "Other"), Some("East"));
        assert_eq!(groups.group_of("east-02"), Some("East"));
    }

    #[test]
    fn devices_and_virtual_machines_are_compared_without_regard_to_the_case_of_their_name() {
        assert_eq!(Kind::Device.caseless_field(), Some("name"));
        assert_eq!(Kind::VirtualMachine.caseless_field(), Some("name"));
        // A disk or an address has no such name.
        assert_eq!(Kind::VirtualDisk.caseless_field(), None);
        assert_eq!(Kind::IpAddress.caseless_field(), None);
    }

    #[test]
    fn a_field_is_marked_as_written_only_when_netbox_holds_none() {
        let plain = Desired::new(Kind::VirtualMachine, Identity::virtual_machine("web01", "pve"), "pve1");
        assert!(plain.only_when_empty.is_empty());
        let marked = plain.only_when_empty("primary_ip4").only_when_empty("description");
        let names: Vec<&str> = marked.only_when_empty.iter().map(String::as_str).collect();
        assert_eq!(names, ["description", "primary_ip4"]);
    }

    #[test]
    fn a_report_owns_its_object_unless_it_says_it_only_completes_it() {
        let owned = Desired::new(Kind::Device, Identity::device("pve01.lab01"), "pve");
        assert!(!owned.complement);
        assert!(owned.complement().complement);
    }

    #[test]
    fn an_ip_host_is_written_in_canonical_form() {
        assert_eq!(ip_host("10.0.0.5/24"), "10.0.0.5");
        assert_eq!(ip_host("10.0.0.5"), "10.0.0.5");
        assert_eq!(ip_host("FE80:0:0:0::1/64"), "fe80::1");
    }
}
