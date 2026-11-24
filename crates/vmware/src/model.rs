//! What the source reads of a vCenter, typed: datacenters, clusters, hosts
//! with their network, virtual machines with their devices and what the guest
//! reports.
//!
//! Nothing here decides what goes to NetBox. A value is `None` when vCenter
//! did not report it, which is never the same as an empty one: a host whose
//! `config.network.pnic` is absent has an unknown set of cards, one whose
//! property is empty has none.

use std::collections::BTreeMap;

use crate::soap::ObjectContent;
use crate::xml::Element;

/// What the key of a physical card starts with, before its device name.
const PNIC_KEY_PREFIX: &str = "key-vim.host.PhysicalNic-";

/// A managed object another one points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// `Folder`, `Datacenter`, `ClusterComputeResource`, `HostSystem`.
    pub kind: String,
    pub id: String,
}

/// A datacenter, a folder, a cluster: an object with a name and a parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub kind: String,
    pub id: String,
    pub name: Option<String>,
    pub parent: Option<Reference>,
    /// The hosts of a cluster or of a standalone compute resource.
    pub hosts: Vec<String>,
}

/// The text at a path of an element, when the path is there.
fn text(element: &Element, path: &str) -> Option<String> {
    element.text_at(path).map(str::to_owned)
}

/// The number at a path of an element; None as well when it is not one.
fn number<T: std::str::FromStr>(element: &Element, path: &str) -> Option<T> {
    element.text_at(path).and_then(|text| text.trim().parse().ok())
}

fn boolean(element: &Element, path: &str) -> Option<bool> {
    match element.text_at(path)?.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn reference(element: &Element) -> Option<Reference> {
    Some(Reference { kind: element.reference.clone()?, id: element.text.clone() })
}

/// The text of every child of this name.
fn texts(element: &Element, name: &str) -> Vec<String> {
    element.children_named(name).map(|child| child.text.clone()).collect()
}

/// The device names of the uplinks listed by key under `pnic`.
fn uplinks(element: &Element) -> Vec<String> {
    let device = |key: String| key.strip_prefix(PNIC_KEY_PREFIX).map(str::to_owned).unwrap_or(key);
    texts(element, "pnic").into_iter().map(device).collect()
}

/// The property of an object read as a list: None when the object does not have it.
fn list<T>(object: &ObjectContent, property: &str, item: &str, read: impl Fn(&Element) -> T) -> Option<Vec<T>> {
    object.properties.get(property).map(|value| value.children_named(item).map(read).collect())
}

/// An address with its prefix length, as `ipAddress` and `prefixLength` give them.
fn address(element: &Element) -> Option<(String, Option<u8>)> {
    Some((text(element, "ipAddress")?, number(element, "prefixLength")))
}

impl Node {
    pub fn of(object: &ObjectContent) -> Self {
        Node {
            kind: object.kind.clone(),
            id: object.id.clone(),
            name: object.text("name").map(str::to_owned),
            parent: object.properties.get("parent").and_then(reference),
            hosts: object
                .properties
                .get("host")
                .map(|hosts| texts(hosts, "ManagedObjectReference"))
                .unwrap_or_default(),
        }
    }
}

/// A physical network card of a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhysicalNic {
    /// `vmnic0`.
    pub device: String,
    pub mac: Option<String>,
    /// The speed of the link when it is up, in Mb/s.
    pub speed_mb: Option<u64>,
    pub duplex: Option<bool>,
    /// The speed the card is set to, when it is not negotiated.
    pub spec_speed_mb: Option<u64>,
    pub spec_duplex: Option<bool>,
    /// The first speed the card lists as valid: its best one.
    pub valid_speed_mb: Option<u64>,
    pub valid_duplex: Option<bool>,
}

/// A VMkernel interface of a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VirtualNic {
    /// `vmk0`.
    pub device: String,
    pub mac: Option<String>,
    pub mtu: Option<u64>,
    /// The port group of a standard switch it is on; empty on a distributed one.
    pub portgroup: Option<String>,
    /// The address and its mask, both dotted; absent or empty without IPv4.
    pub ipv4: Option<(String, String)>,
    /// Each IPv6 address with its prefix length.
    pub ipv6: Vec<(String, Option<u8>)>,
    /// The distributed switch and port group it is on: their UUID and key.
    pub distributed: Option<(String, String)>,
    /// Whether the interface carries a route of its own (`spec.ipRouteSpec`).
    pub route_spec: bool,
}

/// A standard switch of a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VirtualSwitch {
    pub name: String,
    pub mtu: Option<u64>,
    /// The device names of its uplinks.
    pub pnics: Vec<String>,
}

/// The part of a distributed switch a host carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxySwitch {
    pub name: Option<String>,
    pub uuid: Option<String>,
    pub mtu: Option<u64>,
    pub pnics: Vec<String>,
}

/// A port group of a standard switch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortGroup {
    pub name: String,
    /// 0 is no VLAN, 4095 every VLAN.
    pub vlan_id: Option<u32>,
    pub vswitch: Option<String>,
    pub active_nics: Vec<String>,
    pub standby_nics: Vec<String>,
}

/// An ESXi host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    pub id: String,
    pub name: Option<String>,
    /// The cluster, or the standalone compute resource, it belongs to.
    pub parent: Option<Reference>,
    /// `connected`, `disconnected`, `notResponding`.
    pub connection_state: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    /// `VMware ESXi`.
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    /// `summary.hardware.otherIdentifyingInfo`, in order: the kind of
    /// identifier (`ServiceTag`, `AssetTag`) and its value, as reported.
    pub identifiers: Vec<(String, String)>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub pnics: Option<Vec<PhysicalNic>>,
    pub vnics: Option<Vec<VirtualNic>>,
    pub vswitches: Option<Vec<VirtualSwitch>>,
    pub portgroups: Option<Vec<PortGroup>>,
    pub proxy_switches: Option<Vec<ProxySwitch>>,
}

impl PhysicalNic {
    fn of(nic: &Element) -> Self {
        let valid = nic.child("validLinkSpecification");
        PhysicalNic {
            device: text(nic, "device").unwrap_or_default(),
            mac: text(nic, "mac"),
            speed_mb: number(nic, "linkSpeed.speedMb"),
            duplex: boolean(nic, "linkSpeed.duplex"),
            spec_speed_mb: number(nic, "spec.linkSpeed.speedMb"),
            spec_duplex: boolean(nic, "spec.linkSpeed.duplex"),
            valid_speed_mb: valid.and_then(|valid| number(valid, "speedMb")),
            valid_duplex: valid.and_then(|valid| boolean(valid, "duplex")),
        }
    }
}

impl VirtualNic {
    fn of(nic: &Element) -> Self {
        let ipv4 = text(nic, "spec.ip.ipAddress")
            .map(|address| (address, text(nic, "spec.ip.subnetMask").unwrap_or_default()));
        let ipv6 = nic
            .at("spec.ip.ipV6Config")
            .map(|config| config.children_named("ipV6Address").filter_map(address).collect());
        let port = nic.at("spec.distributedVirtualPort");
        VirtualNic {
            device: text(nic, "device").unwrap_or_default(),
            mac: text(nic, "spec.mac"),
            mtu: number(nic, "spec.mtu"),
            portgroup: text(nic, "portgroup"),
            ipv4,
            ipv6: ipv6.unwrap_or_default(),
            distributed: port.and_then(|port| Some((text(port, "switchUuid")?, text(port, "portgroupKey")?))),
            route_spec: nic.at("spec.ipRouteSpec").is_some(),
        }
    }
}

impl PortGroup {
    fn of(group: &Element) -> Self {
        let order = group.at("computedPolicy.nicTeaming.nicOrder");
        PortGroup {
            name: text(group, "spec.name").unwrap_or_default(),
            vlan_id: number(group, "spec.vlanId"),
            vswitch: text(group, "spec.vswitchName"),
            active_nics: order.map(|order| texts(order, "activeNic")).unwrap_or_default(),
            standby_nics: order.map(|order| texts(order, "standbyNic")).unwrap_or_default(),
        }
    }
}

impl Host {
    pub fn of(object: &ObjectContent) -> Self {
        let hardware = object.properties.get("summary.hardware");
        let product = object.properties.get("summary.config.product");
        let identifier = |info: &Element| {
            (text(info, "identifierType.key").unwrap_or_default(), text(info, "identifierValue").unwrap_or_default())
        };
        let switch = |switch: &Element| VirtualSwitch {
            name: text(switch, "name").unwrap_or_default(),
            mtu: number(switch, "mtu"),
            pnics: uplinks(switch),
        };
        let proxy = |switch: &Element| ProxySwitch {
            name: text(switch, "dvsName"),
            uuid: text(switch, "dvsUuid"),
            mtu: number(switch, "mtu"),
            pnics: uplinks(switch),
        };
        Host {
            id: object.id.clone(),
            name: object.text("name").map(str::to_owned),
            parent: object.properties.get("parent").and_then(reference),
            connection_state: object.text("summary.runtime.connectionState").map(str::to_owned),
            vendor: hardware.and_then(|hardware| text(hardware, "vendor")),
            model: hardware.and_then(|hardware| text(hardware, "model")),
            product_name: product.and_then(|product| text(product, "name")),
            product_version: product.and_then(|product| text(product, "version")),
            identifiers: hardware
                .map(|hardware| hardware.children_named("otherIdentifyingInfo").map(identifier).collect())
                .unwrap_or_default(),
            cpu_model: hardware.and_then(|hardware| text(hardware, "cpuModel")),
            cpu_cores: hardware.and_then(|hardware| number(hardware, "numCpuCores")),
            memory_bytes: hardware.and_then(|hardware| number(hardware, "memorySize")),
            pnics: list(object, "config.network.pnic", "PhysicalNic", PhysicalNic::of),
            vnics: list(object, "config.network.vnic", "HostVirtualNic", VirtualNic::of),
            vswitches: list(object, "config.network.vswitch", "HostVirtualSwitch", switch),
            portgroups: list(object, "config.network.portgroup", "HostPortGroup", PortGroup::of),
            proxy_switches: list(object, "config.network.proxySwitch", "HostProxySwitch", proxy),
        }
    }
}

/// What a virtual network card is plugged into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NicBacking {
    /// A port group of a standard switch, by name.
    Network(String),
    /// A distributed port group: the UUID of its switch and its key.
    Distributed { switch_uuid: String, portgroup_key: String },
    /// Anything else, by its vSphere type.
    Other(String),
}

/// A virtual network card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineNic {
    /// The vSphere type of the card: `VirtualVmxnet3`, `VirtualE1000`.
    pub kind: Option<String>,
    /// The device key: what a guest card refers to in `device_config_id`.
    pub key: Option<i64>,
    /// `Network adapter 1`.
    pub label: Option<String>,
    pub mac: Option<String>,
    pub connected: Option<bool>,
    pub backing: Option<NicBacking>,
}

/// A virtual disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    /// `Hard disk 1`.
    pub label: Option<String>,
    pub capacity_kb: Option<u64>,
    /// `[datastore] directory/file.vmdk`.
    pub file_name: Option<String>,
    /// The file of the first disk of the chain: the one a snapshot or a
    /// linked clone was taken from, `file_name` itself without any.
    pub root_file_name: Option<String>,
    /// `persistent`, `independent_persistent`.
    pub disk_mode: Option<String>,
    pub thin_provisioned: Option<bool>,
}

/// A network card as the guest reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestNic {
    pub mac: Option<String>,
    pub connected: Option<bool>,
    pub network: Option<String>,
    /// The key of the virtual card this is; -1 when the guest made it up.
    pub device_config_id: Option<i64>,
    /// Each address with its prefix length.
    pub addresses: Vec<(String, Option<u8>)>,
}

/// A route of the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub network: String,
    pub prefix_length: Option<u8>,
    pub gateway: Option<String>,
}

/// A virtual machine, or a template.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Machine {
    pub id: String,
    pub name: Option<String>,
    pub annotation: Option<String>,
    /// The system the machine was configured for.
    pub config_guest_full_name: Option<String>,
    /// The system the guest tools report.
    pub guest_full_name: Option<String>,
    /// What the guest tools detail of the system (`guestOS.detailed.data`),
    /// by key: `prettyName`, `distroName`, `kernelVersion`.
    pub guest_details: Option<BTreeMap<String, String>>,
    pub memory_mb: Option<u64>,
    pub cpus: Option<u64>,
    pub instance_uuid: Option<String>,
    pub uuid: Option<String>,
    pub template: Option<bool>,
    /// `poweredOn`, `poweredOff`, `suspended`.
    pub power_state: Option<String>,
    /// The host it runs on.
    pub host: Option<String>,
    /// `guestToolsRunning`, `guestToolsNotRunning`: only running tools tell
    /// the addresses of the guest.
    pub tools_running_status: Option<String>,
    pub guest_host_name: Option<String>,
    pub nics: Option<Vec<MachineNic>>,
    pub disks: Option<Vec<Disk>>,
    pub guest_nics: Option<Vec<GuestNic>>,
    /// The routes of the first network stack of the guest.
    pub routes: Option<Vec<Route>>,
}

/// The vSphere types of a virtual network card. One of another type is
/// still told by its MAC address, which only a network card has.
const ETHERNET_CARDS: [&str; 8] = [
    "VirtualE1000",
    "VirtualE1000e",
    "VirtualPCNet32",
    "VirtualSriovEthernetCard",
    "VirtualVmxnet",
    "VirtualVmxnet2",
    "VirtualVmxnet3",
    "VirtualVmxnet3Vrdma",
];

/// The option of `config.extraConfig` the guest tools detail the system in.
const GUEST_DETAILS_KEY: &str = "guestOS.detailed.data";

/// The file of the first backing of a chain: each snapshot or linked clone
/// puts a backing in front of the one it was taken from, its `parent`.
fn root_file_name(backing: &Element) -> Option<String> {
    let mut backing = backing;
    while let Some(parent) = backing.child("parent") {
        backing = parent;
    }
    text(backing, "fileName")
}

fn is_ethernet_card(device: &Element) -> bool {
    device.xsi_type.as_deref().is_some_and(|kind| ETHERNET_CARDS.contains(&kind))
        || device.child("macAddress").is_some()
}

impl MachineNic {
    fn of(device: &Element) -> Self {
        let backing = device.child("backing").map(|backing| match backing.xsi_type.as_deref() {
            Some("VirtualEthernetCardNetworkBackingInfo") => {
                NicBacking::Network(text(backing, "deviceName").unwrap_or_default())
            }
            Some("VirtualEthernetCardDistributedVirtualPortBackingInfo") => NicBacking::Distributed {
                switch_uuid: text(backing, "port.switchUuid").unwrap_or_default(),
                portgroup_key: text(backing, "port.portgroupKey").unwrap_or_default(),
            },
            other => NicBacking::Other(other.unwrap_or_default().to_owned()),
        });
        MachineNic {
            kind: device.xsi_type.clone(),
            key: number(device, "key"),
            label: text(device, "deviceInfo.label"),
            mac: text(device, "macAddress"),
            connected: boolean(device, "connectable.connected"),
            backing,
        }
    }
}

impl Machine {
    pub fn of(object: &ObjectContent) -> Self {
        let owned = |property: &str| object.text(property).map(str::to_owned);
        fn parsed_as<T: std::str::FromStr>(object: &ObjectContent, property: &str) -> Option<T> {
            object.text(property).and_then(|text| text.trim().parse().ok())
        }
        let devices = object.properties.get("config.hardware.device");
        let devices = |keep: fn(&Element) -> bool| {
            devices.map(|devices| devices.children.iter().filter(move |device| keep(device)))
        };
        let disk = |device: &Element| Disk {
            label: text(device, "deviceInfo.label"),
            capacity_kb: number(device, "capacityInKB"),
            file_name: text(device, "backing.fileName"),
            root_file_name: device.child("backing").and_then(root_file_name),
            disk_mode: text(device, "backing.diskMode"),
            thin_provisioned: boolean(device, "backing.thinProvisioned"),
        };
        let guest_nic = |nic: &Element| GuestNic {
            mac: text(nic, "macAddress"),
            connected: boolean(nic, "connected"),
            network: text(nic, "network"),
            device_config_id: number(nic, "deviceConfigId"),
            addresses: nic
                .child("ipConfig")
                .map(|config| config.children_named("ipAddress").filter_map(address).collect())
                .unwrap_or_default(),
        };
        let route = |route: &Element| Route {
            network: text(route, "network").unwrap_or_default(),
            prefix_length: number(route, "prefixLength"),
            gateway: text(route, "gateway.ipAddress"),
        };
        let details = object.properties.get("config.extraConfig").map(|options| {
            let option = options.children.iter().find(|option| option.text_at("key") == Some(GUEST_DETAILS_KEY));
            option.and_then(|option| option.text_at("value")).map(guest_details).unwrap_or_default()
        });
        // The routes of the first stack: the one of the guest itself.
        let stack = object.properties.get("guest.ipStack");
        let routes = stack.map(|stacks| {
            let config = stacks.children.first().and_then(|stack| stack.child("ipRouteConfig"));
            config.map(|config| config.children_named("ipRoute").map(route).collect()).unwrap_or_default()
        });
        Machine {
            id: object.id.clone(),
            name: owned("name"),
            annotation: owned("config.annotation"),
            config_guest_full_name: owned("config.guestFullName"),
            guest_full_name: owned("guest.guestFullName"),
            guest_details: details,
            memory_mb: parsed_as(object, "config.hardware.memoryMB"),
            cpus: parsed_as(object, "config.hardware.numCPU"),
            instance_uuid: owned("config.instanceUuid"),
            uuid: owned("config.uuid"),
            template: parsed_as(object, "config.template"),
            power_state: owned("runtime.powerState"),
            host: owned("runtime.host"),
            tools_running_status: owned("guest.toolsRunningStatus"),
            guest_host_name: owned("guest.hostName"),
            nics: devices(is_ethernet_card).map(|cards| cards.map(MachineNic::of).collect()),
            disks: devices(|device| device.xsi_type.as_deref() == Some("VirtualDisk"))
                .map(|disks| disks.map(disk).collect()),
            guest_nics: list(object, "guest.net", "GuestNicInfo", guest_nic),
            routes,
        }
    }
}

/// The `key='value'` pairs of `guestOS.detailed.data`.
pub fn guest_details(text: &str) -> BTreeMap<String, String> {
    let mut details = BTreeMap::new();
    let mut rest = text;
    while let Some((key, after)) = rest.split_once("='") {
        // A value ends at the quote that precedes the next pair, or the end.
        let end = after.find("' ").unwrap_or_else(|| after.strip_suffix('\'').map_or(after.len(), str::len));
        details.insert(key.trim().to_owned(), after[..end].to_owned());
        rest = after.get(end + 1..).unwrap_or_default();
    }
    details
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::page;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../tests/fixtures/6.7/", $name))
        };
    }

    fn objects(answer: &str) -> Vec<ObjectContent> {
        page(answer).expect("page").objects
    }

    fn owned(text: &str) -> Option<String> {
        Some(text.to_owned())
    }

    fn names<const N: usize>(names: [&str; N]) -> Vec<String> {
        names.into_iter().map(str::to_owned).collect()
    }

    fn first_host() -> Host {
        Host::of(&objects(fixture!("RetrievePropertiesEx.HostSystem.0.xml"))[0])
    }

    fn last_machine() -> Machine {
        Machine::of(objects(fixture!("RetrievePropertiesEx.VirtualMachine.1.xml")).last().unwrap())
    }

    #[test]
    fn a_datacenter_a_folder_and_a_cluster_have_a_name_and_a_parent() {
        let datacenter = Node::of(&objects(fixture!("RetrievePropertiesEx.Datacenter.0.xml"))[0]);
        assert_eq!(
            datacenter,
            Node {
                kind: "Datacenter".to_owned(),
                id: "datacenter-2".to_owned(),
                name: owned("DC1"),
                parent: Some(Reference { kind: "Folder".to_owned(), id: "group-d1".to_owned() }),
                hosts: Vec::new(),
            }
        );
        let cluster = Node::of(&objects(fixture!("RetrievePropertiesEx.ClusterComputeResource.0.xml"))[0]);
        assert_eq!((cluster.kind.as_str(), cluster.id.as_str()), ("ClusterComputeResource", "domain-c7"));
        assert_eq!(cluster.parent, Some(Reference { kind: "Folder".to_owned(), id: "group-h4".to_owned() }));
        assert_eq!(cluster.hosts, ["host-353", "host-33564", "host-53898", "host-10", "host-48488", "host-96885"]);
    }

    #[test]
    fn a_host_is_read_with_its_hardware_and_product() {
        let host = first_host();
        assert_eq!(host.id, "host-353");
        assert_eq!(host.name, owned("esx01.lab.example"));
        assert_eq!(
            host.parent,
            Some(Reference { kind: "ClusterComputeResource".to_owned(), id: "domain-c7".to_owned() })
        );
        assert_eq!(host.connection_state, owned("connected"));
        assert_eq!((host.vendor, host.model), (owned("Dell Inc."), owned("PowerEdge R630")));
        assert_eq!((host.product_name, host.product_version), (owned("VMware ESXi"), owned("6.7.0")));
        assert_eq!(host.cpu_model, owned("Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz"));
        assert_eq!((host.cpu_cores, host.memory_bytes), (Some(12), Some(549_657_538_560)));
    }

    #[test]
    fn the_identifiers_of_a_host_are_kept_in_order_empty_ones_included() {
        let identifiers = first_host().identifiers;
        let first: Vec<(&str, &str)> =
            identifiers[..5].iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
        assert_eq!(
            first,
            [
                ("AssetTag", ""),
                ("ServiceTag", "ID00001"),
                ("EnclosureSerialNumberTag", "ID00001"),
                ("SerialNumberTag", "ID00001"),
                ("OemSpecificString", "ID00002")
            ]
        );
    }

    #[test]
    fn the_physical_cards_of_a_host() {
        let nics = first_host().pnics.expect("physical cards");
        assert_eq!(nics.len(), 6);
        assert_eq!(
            nics[0],
            PhysicalNic {
                device: "vmnic0".to_owned(),
                mac: owned("02:00:00:00:00:01"),
                speed_mb: Some(1000),
                duplex: Some(true),
                spec_speed_mb: None,
                spec_duplex: None,
                valid_speed_mb: Some(1000),
                valid_duplex: Some(true),
            }
        );
        // This one is set to its speed rather than negotiating it.
        assert_eq!(
            (nics[5].device.as_str(), nics[5].speed_mb, nics[5].spec_speed_mb),
            ("vmnic5", Some(10000), Some(10000))
        );
    }

    #[test]
    fn the_vmkernel_interfaces_of_a_host() {
        let vnics = first_host().vnics.expect("vmkernel interfaces");
        assert_eq!(vnics.len(), 3);
        assert_eq!(
            vnics[0],
            VirtualNic {
                device: "vmk0".to_owned(),
                mac: owned("02:00:00:00:00:01"),
                mtu: Some(1500),
                portgroup: owned("Management Network"),
                ipv4: Some(("198.18.0.35".to_owned(), "255.255.255.0".to_owned())),
                ipv6: vec![("fe80::1".to_owned(), Some(64))],
                distributed: None,
                route_spec: false,
            }
        );
        // `vmk1` has a `spec.ipRouteSpec` (its own default gateway), `vmk0` and `vmk3` have none.
        let routed: Vec<(&str, bool)> = vnics.iter().map(|vnic| (vnic.device.as_str(), vnic.route_spec)).collect();
        assert_eq!(routed, [("vmk0", false), ("vmk1", true), ("vmk3", false)]);
        let others: Vec<(&str, Option<&str>)> =
            vnics[1..].iter().map(|vnic| (vnic.device.as_str(), vnic.portgroup.as_deref())).collect();
        assert_eq!(others, [("vmk1", Some("pg-11")), ("vmk3", Some("pg-10"))]);
    }

    #[test]
    fn the_switches_and_port_groups_of_a_host() {
        let host = first_host();
        let switches = host.vswitches.expect("switches");
        assert_eq!(switches.len(), 2);
        assert_eq!(
            switches[0],
            VirtualSwitch {
                name: "vSwitch0".to_owned(),
                mtu: Some(1500),
                pnics: names(["vmnic3", "vmnic2", "vmnic1", "vmnic0"])
            }
        );
        let groups = host.portgroups.expect("port groups");
        assert_eq!(groups.len(), 13);
        assert_eq!(
            groups[0],
            PortGroup {
                name: "pg-1".to_owned(),
                vlan_id: Some(3012),
                vswitch: owned("vSwitch0"),
                active_nics: names(["vmnic0", "vmnic1", "vmnic2", "vmnic3"]),
                standby_nics: Vec::new(),
            }
        );
        // The property is there and empty: this host is on no distributed switch.
        assert_eq!(host.proxy_switches, Some(Vec::new()));
    }

    #[test]
    fn what_a_host_did_not_report_is_unknown_not_empty() {
        let bare =
            ObjectContent { kind: "HostSystem".to_owned(), id: "host-1".to_owned(), properties: BTreeMap::new() };
        let host = Host::of(&bare);
        assert_eq!(host, Host { id: "host-1".to_owned(), ..Host::default() });
        assert_eq!((host.pnics, host.vnics, host.portgroups), (None, None, None));
    }

    #[test]
    fn a_machine_is_read_with_its_configuration() {
        let machine = last_machine();
        assert_eq!(machine.id, "vm-12265");
        assert_eq!(machine.name, owned("vm167.lab.example"));
        assert_eq!((machine.memory_mb, machine.cpus, machine.template), (Some(3072), Some(4), Some(false)));
        assert_eq!(machine.power_state, owned("poweredOn"));
        assert_eq!(machine.host, owned("host-353"));
        assert_eq!(machine.tools_running_status, owned("guestToolsRunning"));
        assert_eq!(machine.config_guest_full_name, owned("Debian GNU/Linux 7 (64-bit)"));
        assert_eq!(machine.guest_full_name, owned("Debian GNU/Linux 9 (64-bit)"));
        assert_eq!(machine.guest_host_name, owned("vm167.lab.example"));
        assert_eq!(machine.instance_uuid, owned("00000000-0000-4000-8000-000000000275"));
        assert_eq!(machine.uuid, owned("00000000-0000-4000-8000-000000000276"));
        // No note on this machine, and tools that detail nothing.
        assert_eq!(machine.annotation, None);
        assert_eq!(machine.guest_details, Some(BTreeMap::new()));
    }

    #[test]
    fn the_cards_and_disks_of_a_machine() {
        let machine = last_machine();
        assert_eq!(
            machine.nics,
            Some(vec![MachineNic {
                kind: owned("VirtualVmxnet3"),
                key: Some(4000),
                label: owned("Network adapter 1"),
                mac: owned("02:00:00:00:00:09"),
                connected: Some(true),
                backing: Some(NicBacking::Network("pg-8".to_owned())),
            }])
        );
        assert_eq!(
            machine.disks,
            Some(vec![
                Disk {
                    label: owned("Hard disk 1"),
                    capacity_kb: Some(16_777_216),
                    file_name: owned("[store8] d589/d589.vmdk"),
                    root_file_name: owned("[store8] d589/d589.vmdk"),
                    disk_mode: owned("persistent"),
                    thin_provisioned: Some(true),
                },
                Disk {
                    label: owned("Hard disk 2"),
                    capacity_kb: Some(16_777_216),
                    file_name: owned("[store8] d591/d591.vmdk"),
                    root_file_name: owned("[store8] d591/d591.vmdk"),
                    disk_mode: owned("persistent"),
                    thin_provisioned: Some(true),
                },
            ])
        );
    }

    #[test]
    fn a_disk_with_a_snapshot_knows_the_file_it_started_from() {
        let machines = objects(fixture!("RetrievePropertiesEx.VirtualMachine.0.xml"));
        let machine = Machine::of(machines.iter().find(|machine| machine.id == "vm-6519").expect("vm-6519"));
        let disks = machine.disks.expect("disks");
        // `backing.fileName` is `d260.vmdk`, `backing.parent.fileName` `d262.vmdk`, which has no parent.
        assert_eq!(disks[0].file_name, owned("[store2] d260/d260.vmdk"));
        assert_eq!(disks[0].root_file_name, owned("[store2] d262/d262.vmdk"));
    }

    #[test]
    fn what_the_guest_reports_of_its_network() {
        let machine = last_machine();
        assert_eq!(
            machine.guest_nics,
            Some(vec![GuestNic {
                mac: owned("02:00:00:00:00:09"),
                connected: Some(true),
                network: owned("pg-8"),
                device_config_id: Some(4000),
                addresses: vec![("198.18.2.18".to_owned(), Some(24)), ("fe80::b0".to_owned(), Some(64))],
            }])
        );
        let routes = machine.routes.expect("routes");
        assert_eq!(routes.len(), 4);
        assert_eq!(
            routes[0],
            Route { network: "0.0.0.0".to_owned(), prefix_length: Some(0), gateway: owned("198.18.2.254") }
        );
        assert_eq!(routes[1], Route { network: "198.18.2.0".to_owned(), prefix_length: Some(24), gateway: None });
    }

    #[test]
    fn the_details_of_the_guest_system_are_read_by_key() {
        let machines = objects(fixture!("RetrievePropertiesEx.VirtualMachine.0.xml"));
        let machine = Machine::of(machines.iter().find(|machine| machine.id == "vm-132318").expect("vm-132318"));
        assert_eq!(machine.name, owned("vm002"));
        let details = machine.guest_details.expect("details");
        assert_eq!(details.get("prettyName").map(String::as_str), Some("Debian GNU/Linux 13 (trixie)"));
        assert_eq!(details.get("kernelVersion").map(String::as_str), Some("6.12.111+deb13-amd64"));
        // A note that is there and empty is not an absent one.
        assert_eq!(machine.annotation, owned(""));
    }

    #[test]
    fn guest_details_are_pairs_of_a_key_and_a_quoted_value() {
        let details =
            guest_details("bitness='64' distroName='Debian GNU/Linux' prettyName='Debian GNU/Linux 10 (buster)'");
        let pairs: Vec<(&str, &str)> = details.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
        assert_eq!(
            pairs,
            [("bitness", "64"), ("distroName", "Debian GNU/Linux"), ("prettyName", "Debian GNU/Linux 10 (buster)")]
        );
        assert_eq!(guest_details(""), BTreeMap::new());
    }

    #[test]
    fn what_a_machine_did_not_report_is_unknown_not_empty() {
        let bare =
            ObjectContent { kind: "VirtualMachine".to_owned(), id: "vm-1".to_owned(), properties: BTreeMap::new() };
        let machine = Machine::of(&bare);
        assert_eq!(machine, Machine { id: "vm-1".to_owned(), ..Machine::default() });
        assert_eq!((machine.nics, machine.disks, machine.guest_nics, machine.routes), (None, None, None, None));
    }
}
