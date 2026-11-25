//! The translation of the recorded clusters, and its reconciliation.
//!
//! Every expected value below was read in `tests/fixtures/<version>/api.json`
//! (what was read is quoted above the assertion) or comes from the Go source
//! of netbox-ssot at commit `604930e`; none was copied from what the code
//! returns.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use omnisync_core::change::Action;
use omnisync_core::gateway::Row;
use omnisync_core::inventory::custom_fields;
use omnisync_core::inventory::dns::Asked;
use omnisync_core::inventory::identity::current_objects;
use omnisync_core::inventory::model::{Current, Desired, Identity, Kind, TOOL_TAG, Target, VlanScope, VrfKey};
use omnisync_core::inventory::reconcile::{Link, Phase, Plan, Run, SourceFacts, SourceStatus, Step, reconcile};
use omnisync_proxmox::{NoReverseDns, ProxmoxCluster, Settings, Translation, desired};
use serde_json::{Map, Value, json};

mod common;

use common::{collected, fixture};

/// The settings of production, with made-up names: every relation of
/// netbox-ssot was `.* = value` there, the templates were ignored, every
/// IPv6 subnet was ignored (`::/0`) and the interface filter was this one.
fn production(source: &str) -> Settings {
    Settings {
        tenant: Some("Example Tenant".to_owned()),
        host_role: Some("Hypervisor".to_owned()),
        vm_role: Some("Virtual Machine".to_owned()),
        domain: ".infra.example".to_owned(),
        ignore_templates: true,
        ignored_subnets: Settings::subnets(&["::/0"]).unwrap(),
        interface_filter: Settings::interface_filter("veth|docker|br-|isatap|vEthernet|Loopback").unwrap(),
        ..Settings::new(source, "Paris")
    }
}

async fn translated(version: &str, settings: &Settings) -> (ProxmoxCluster, Translation) {
    let cluster = collected(fixture(version)).await;
    let translation = desired(&cluster, settings, &NoReverseDns);
    (cluster, translation)
}

fn of_kind(objects: &[Desired], kind: Kind) -> Vec<&Desired> {
    objects.iter().filter(|object| object.kind == kind).collect()
}

/// How many objects of each kind, for the kinds that have some.
fn counts(objects: &[Desired]) -> Vec<(Kind, usize)> {
    Kind::ALL.into_iter().map(|kind| (kind, of_kind(objects, kind).len())).filter(|(_, count)| *count > 0).collect()
}

fn one(objects: &[Desired], kind: Kind, identity: &Identity) -> Desired {
    let found: Vec<&Desired> =
        objects.iter().filter(|object| object.kind == kind && &object.identity == identity).collect();
    assert_eq!(found.len(), 1, "{} object(s) of kind {kind:?} with identity {:?}", found.len(), identity.key());
    found[0].clone()
}

fn labels(objects: &[&Desired]) -> Vec<String> {
    objects.iter().map(|object| object.identity.label().to_owned()).collect()
}

fn with_reference<'a>(objects: &[&'a Desired], field: &str) -> Vec<&'a Desired> {
    objects.iter().copied().filter(|object| object.references.get(field).is_some_and(Option::is_some)).collect()
}

fn text(object: &Desired, field: &str) -> String {
    object.fields[field].as_str().unwrap().to_owned()
}

fn nic_identity(vm: &Identity, name: &str) -> Identity {
    Identity::vm_interface(vm, name)
}

fn mac_identity(mac: &str, vm: &Identity, nic: &str) -> Identity {
    Identity::mac_address(mac, Some(&Target::new(Kind::VmInterface, nic_identity(vm, nic))))
}

fn address_identity(address: &str) -> Identity {
    Identity::ip_address(address, VrfKey::Unknown)
}

/// What every virtual machine of `production` refers to, whatever it is.
fn placed(object: Desired, cluster: &str, host: &str) -> Desired {
    object
        .reference("site", Kind::Site, Identity::named("Paris"))
        .reference("cluster", Kind::Cluster, Identity::named(cluster))
        .reference("device", Kind::Device, Identity::device(host))
        .reference("tenant", Kind::Tenant, Identity::named("Example Tenant"))
        .reference("role", Kind::Role, Identity::named("Virtual Machine"))
}

// ---------------------------------------------------------------------------
// The 8.4 cluster
// ---------------------------------------------------------------------------

const PVE_A: &str = "pve-a";
const CLUSTER_A: &str = "pve-cluster-a";

#[tokio::test]
async fn the_8_4_cluster_gives_these_objects() {
    let (_, translation) = translated("8.4", &production(PVE_A)).await;
    let objects = &translation.objects;
    assert_eq!(translation.warnings, Vec::<String>::new());

    assert_eq!(
        counts(objects),
        [
            // 14 distinct tags on the 60 VMs that are not templates: service-apache, service-docker,
            // service-elastic-search, service-haproxy, service-keepalived, service-mariadb, service-nginx,
            // service-oom, service-opensearch, service-rabbit, service-redis, service-seeq-queue,
            // service-veeam-proxy and tag-1.
            (Kind::Tag, 14),
            (Kind::Tenant, 1),
            (Kind::Site, 1),
            (Kind::Manufacturer, 1),
            (Kind::DeviceType, 1),
            // 8 distinct "pretty-name" in the 40 get-osinfo answers that carry one: Debian GNU/Linux 11
            // (bullseye), 12 (bookworm) and 13 (trixie), Ubuntu 24.04.3 LTS, Windows 10 Pro, Windows 8.1 Pro,
            // Windows Server 2016 Standard and Windows Server 2022 Standard.
            // Plus the two an ostype gives to the 20 guests whose agent is silent: "l26" for 15 of them
            // ("Other 2.6.x Linux (64-bit)") and "win11" for 5 ("Microsoft Windows 11 (64-bit)").
            (Kind::Platform, 10),
            // The two roles of the settings; no container, so no Container role.
            (Kind::Role, 2),
            (Kind::ClusterType, 1),
            (Kind::Cluster, 1),
            // The "vlan-id" of the 15 entries of type "vlan" in the three "/nodes/<node>/network": 2701, 2702,
            // 2703, 2713 and 2714 on each node. No configuration of this fixture has a "netN" key.
            (Kind::Vlan, 5),
            // The IPv4 addresses kept below are in 169.254.0.0/16, 198.18.0.0/26, 198.18.0.64/26,
            // 198.18.0.128/26, 198.18.1.0/24 and 198.18.5.0/24.
            (Kind::Prefix, 6),
            // "/nodes" lists pve01, pve02 and pve03.
            (Kind::Device, 3),
            // 65 entries in the three "/nodes/<node>/qemu", 5 of them with "template": 1; no two share a name.
            (Kind::VirtualMachine, 60),
            // "/nodes/pve01/network" has 17 entries, pve02 19, pve03 17; no name matches the filter.
            (Kind::Interface, 53),
            // The 45 agents that answered list 407 interfaces besides "lo"; 358 match the filter (311 "veth…",
            // 20 "br-…", 13 "docker0", 4 "docker_gwbridge", 8 "Loopback Pseudo-Interface 1", 2 "isatap.{…}").
            (Kind::VmInterface, 49),
            // 93 "virtioN", "scsiN", "sataN" or "ideN" keys with a "size=" in the 60 configurations.
            (Kind::VirtualDisk, 93),
            // Each of the 49 interfaces has a "hardware-address".
            (Kind::MacAddress, 49),
            // Those 49 interfaces carry 49 "ipv4" addresses (26 /26, 21 /24, 2 /16) and 39 "ipv6" ones.
            (Kind::IpAddress, 49),
        ]
    );
    assert_eq!(objects.len(), 394 + 5);

    // IPv6 dropped: with "::/0" ignored no address object has a colon.
    let addresses = of_kind(objects, Kind::IpAddress);
    assert!(addresses.iter().all(|address| !text(address, "address").contains(':')));

    let vms = of_kind(objects, Kind::VirtualMachine);
    // "status": "stopped" on 13 of the 60 VMs, "running" on 47.
    assert_eq!(vms.iter().filter(|vm| text(vm, "status") == "offline").count(), 13);
    assert_eq!(vms.iter().filter(|vm| text(vm, "status") == "active").count(), 47);
    // Interfaces unknown: the 13 stopped VMs and the 2 whose agent answered 500 (pve02, 151 and 153).
    assert_eq!(vms.iter().filter(|vm| !vm.unknown_dependents.is_empty()).count(), 15);
    // A platform is written for the 40 VMs whose agent gave a "pretty-name"; for the 20 others the one of
    // their ostype is declared, to be written only when NetBox has none.
    assert_eq!(with_reference(&vms, "platform").len(), 60);
    assert_eq!(vms.iter().filter(|vm| vm.only_when_empty.contains("platform")).count(), 20);
    // Each of the 45 VMs whose agent answered has an IPv4 address on an interface that is kept.
    assert_eq!(with_reference(&vms, "primary_ip4").len(), 45);
    assert_eq!(with_reference(&vms, "primary_ip6").len(), 0);
    // "tags" is set on 33 of the 60 entries.
    assert_eq!(vms.iter().filter(|vm| vm.tags.as_ref().is_some_and(|tags| !tags.is_empty())).count(), 33);
    assert!(vms.iter().all(|vm| vm.tags.is_some()));

    let interfaces = of_kind(objects, Kind::Interface);
    // 9 "bond", 9 "bridge", 15 "vlan" and 20 "eth" in the three network lists.
    let typed =
        |kind: &str| interfaces.iter().filter(|interface| interface.fields.get("type") == Some(&json!(kind))).count();
    assert_eq!([typed("lag"), typed("bridge"), typed("virtual")], [9, 9, 15]);
    assert_eq!(
        interfaces.iter().filter(|interface| interface.create_only.get("type") == Some(&json!("other"))).count(),
        20
    );
    // Each of the 9 bonds has two "slaves".
    assert_eq!(with_reference(&interfaces, "lag").len(), 18);
    // Every entry has "active": 1.
    assert!(interfaces.iter().all(|interface| interface.fields["enabled"] == json!(true)));

    // 4 of the 93 disks are "media=cdrom" drives with a size, all four ISO images ("….iso").
    let disks = of_kind(objects, Kind::VirtualDisk);
    let images = disks.iter().filter(|disk| text(disk, "name").ends_with(".iso")).count();
    assert_eq!(images, 4);
}

#[tokio::test]
async fn the_8_4_cluster_without_the_production_filters() {
    let mut settings = production(PVE_A);
    settings.ignored_subnets = vec![];
    settings.ignore_templates = false;
    let (_, translation) = translated("8.4", &settings).await;
    let objects = &translation.objects;
    // The 5 templates are synced too: the 65 names are all different.
    assert_eq!(of_kind(objects, Kind::VirtualMachine).len(), 65);
    assert_eq!(translation.warnings, Vec::<String>::new());
    // The 39 "ipv6" addresses of the 49 interfaces are synced with the 49 "ipv4" ones; all are fe80::…/64.
    assert_eq!(of_kind(objects, Kind::IpAddress).len(), 88);
    assert_eq!(of_kind(objects, Kind::Prefix).len(), 7);
    let vms = of_kind(objects, Kind::VirtualMachine);
    assert_eq!(with_reference(&vms, "primary_ip4").len(), 45);
}

#[tokio::test]
async fn the_addresses_of_8_4_get_the_names_a_reverse_lookup_gives() {
    let mut settings = production(PVE_A);
    settings.ignored_subnets = vec![];
    let cluster = collected(fixture("8.4")).await;
    // What is asked: of the 49 "ipv4" and 39 "ipv6" addresses synced, never the 2 in 169.254.0.0/16
    // ("ip-address": "169.254.210.12", "ip-address": "169.254.129.166") nor the "ipv6" ones, all fe80::…/64.
    let asked = Asked::default();
    desired(&cluster, &settings, &asked);
    let asked = asked.into_addresses();
    assert!(asked.contains(&"198.18.0.70".parse::<IpAddr>().unwrap()));
    let link_local: Vec<&IpAddr> =
        asked.iter().filter(|address| address.is_ipv6() || address.to_string().starts_with("169.254.")).collect();
    assert_eq!(link_local, Vec::<&IpAddr>::new());

    // { "ip-address": "198.18.0.70", "ip-address-type": "ipv4", "prefix": 26 } of "ens18" of vm042.example.
    let names: BTreeMap<IpAddr, String> =
        BTreeMap::from([("198.18.0.70".parse().unwrap(), "VM042.Infra.Example.".to_owned())]);
    let translation = desired(&cluster, &settings, &names);
    assert_eq!(translation.warnings, Vec::<String>::new());
    let vm = Identity::virtual_machine("vm042.example", CLUSTER_A);
    let address = Desired::new(Kind::IpAddress, address_identity("198.18.0.70"), PVE_A)
        .field("address", "198.18.0.70/26")
        .field("status", "active")
        .field("dns_name", "vm042.infra.example")
        .reference("tenant", Kind::Tenant, Identity::named("Example Tenant"))
        .reference("assigned_object", Kind::VmInterface, nic_identity(&vm, "ens18"))
        .custom_field(&custom_fields::ARP_ENTRY, false)
        .custom_field(&custom_fields::SOURCE, PVE_A);
    assert_eq!(one(&translation.objects, Kind::IpAddress, &address_identity("198.18.0.70")), address);
    // The lookup knows no other name: the 87 other addresses report none, and NetBox keeps what it has.
    let addresses = of_kind(&translation.objects, Kind::IpAddress);
    let unnamed = addresses.iter().filter(|address| !address.fields.contains_key("dns_name")).count();
    assert_eq!((addresses.len(), unnamed), (88, 87));
}

#[tokio::test]
async fn the_hosts_of_8_4() {
    let (_, translation) = translated("8.4", &production(PVE_A)).await;
    let objects = &translation.objects;
    let host = |name: &str, memory: &str| {
        Desired::new(Kind::Device, Identity::device(name), PVE_A)
            .field("name", name)
            .reference("role", Kind::Role, Identity::named("Hypervisor"))
            .reference("site", Kind::Site, Identity::named("Paris"))
            .reference("tenant", Kind::Tenant, Identity::named("Example Tenant"))
            .reference("cluster", Kind::Cluster, Identity::named(CLUSTER_A))
            // "/nodes/<node>/status": "cpuinfo": { "cpus": 32 } on the three nodes.
            .custom_field(&custom_fields::HOST_CPU_CORES, "32")
            .custom_field(&custom_fields::HOST_MEMORY, memory)
            .custom_field(&custom_fields::SOURCE, PVE_A)
            // The generic device type only fills an empty field: one set by hand in NetBox is kept.
            .reference("device_type", Kind::DeviceType, Identity::device_type("Generic Manufacturer", "Generic Model"))
            .only_when_empty("device_type")
    };
    // "/nodes/pve01/status": "memory": { "total": 236538687488 } — 220.29 GiB, an integer division.
    let name = "pve01.infra.example";
    assert_eq!(one(objects, Kind::Device, &Identity::device(name)), host(name, "220 GiB"));
    // "/nodes/pve02/status": "total": 270393266176 — 251.82 GiB.
    let name = "pve02.infra.example";
    assert_eq!(one(objects, Kind::Device, &Identity::device(name)), host(name, "251 GiB"));
    // "/nodes/pve03/status": "total": 270361522176 — 251.79 GiB.
    let name = "pve03.infra.example";
    assert_eq!(one(objects, Kind::Device, &Identity::device(name)), host(name, "251 GiB"));

    // "/nodes/pve02/network": { "iface": "bond2", "slaves": "enp5s0 enp5s0d1", "type": "bond", "active": 1 }
    let device = "pve02.infra.example";
    let interface = |name: &str| {
        Desired::new(Kind::Interface, Identity::interface(device, name), PVE_A)
            .field("name", name)
            .field("enabled", true)
            .reference("device", Kind::Device, Identity::device(device))
            .custom_field(&custom_fields::SOURCE, PVE_A)
    };
    let bond = interface("bond2").field("type", "lag");
    assert_eq!(one(objects, Kind::Interface, &Identity::interface(device, "bond2")), bond);
    let member = interface("enp5s0d1").create_only("type", "other").reference(
        "lag",
        Kind::Interface,
        Identity::interface(device, "bond2"),
    );
    assert_eq!(one(objects, Kind::Interface, &Identity::interface(device, "enp5s0d1")), member);
    // { "iface": "bond2.2702", "type": "vlan", "active": 1, "vlan-id": "2702", "vlan-raw-device": "bond2" }
    let vlan = interface("bond2.2702")
        .field("type", "virtual")
        .field("mode", "access")
        .reference("untagged_vlan", Kind::Vlan, Identity::vlan(VlanScope::Site("Paris"), 2702))
        // An access port carries no tagged VLAN: said, so that NetBox can be told so.
        .reference_list("tagged_vlans", Vec::<Target>::new())
        .reference("parent", Kind::Interface, Identity::interface(device, "bond2"));
    assert_eq!(one(objects, Kind::Interface, &Identity::interface(device, "bond2.2702")), vlan);
    // The VLAN only has to exist at the site: Proxmox does not name it.
    assert_eq!(
        one(objects, Kind::Vlan, &Identity::vlan(VlanScope::Site("Paris"), 2702)),
        Desired::new(Kind::Vlan, Identity::vlan(VlanScope::Site("Paris"), 2702), PVE_A)
            .field("vid", 2702)
            .create_only("name", "VLAN2702")
            .ensure_only()
            .reference("site", Kind::Site, Identity::named("Paris"))
    );
    // { "iface": "eno3", "type": "eth", "active": 1 }: in no bond.
    let nic = interface("eno3").create_only("type", "other");
    assert_eq!(one(objects, Kind::Interface, &Identity::interface(device, "eno3")), nic);
}

#[tokio::test]
async fn a_tagged_docker_host_of_8_4_object_by_object() {
    let (_, translation) = translated("8.4", &production(PVE_A)).await;
    let objects = &translation.objects;
    let identity = Identity::virtual_machine("vm042.example", CLUSTER_A);

    // "/nodes/pve02/qemu": { "cpus": 16, "maxmem": 8589934592, "name": "vm042.example", "status": "running",
    //   "tags": "service-oom", "vmid": 141 }
    // "/nodes/pve02/qemu/141/agent/get-osinfo": "pretty-name": "Debian GNU/Linux 12 (bookworm)"
    let expected = Desired::new(Kind::VirtualMachine, identity.clone(), PVE_A)
        .field("name", "vm042.example")
        .field("status", "active")
        .field("vcpus", 16)
        // 8589934592 / 1048576 = 8192
        .field("memory", 8192)
        .reference("platform", Kind::Platform, Identity::named("Debian GNU/Linux 12 (bookworm)"))
        .reference("primary_ip4", Kind::IpAddress, address_identity("198.18.0.70"))
        .tags(["service-oom"])
        .custom_field(&custom_fields::SOURCE, PVE_A)
        .custom_field(&custom_fields::SOURCE_ID, "141");
    assert_eq!(one(objects, Kind::VirtualMachine, &identity), placed(expected, CLUSTER_A, "pve02.infra.example"));

    // ".../141/agent/network-get-interfaces" lists "lo", "ens18", eight "br-…", "docker0" and 21 "veth…":
    // only "ens18" passes the filter.
    // { "hardware-address": "02:00:00:00:00:a1", "ip-addresses": [
    //   { "ip-address": "198.18.0.70", "ip-address-type": "ipv4", "prefix": 26 },
    //   { "ip-address": "fe80::96", "ip-address-type": "ipv6", "prefix": 64 } ], "name": "ens18" }
    let under: Vec<&Desired> = objects
        .iter()
        .filter(|object| object.identity.key().starts_with(identity.key()) && object.kind == Kind::VmInterface)
        .collect();
    assert_eq!(labels(&under), ["ens18"]);
    let ens18 = nic_identity(&identity, "ens18");
    let mac = mac_identity("02:00:00:00:00:A1", &identity, "ens18");
    let interface = Desired::new(Kind::VmInterface, ens18.clone(), PVE_A)
        .field("name", "ens18")
        .reference("virtual_machine", Kind::VirtualMachine, identity.clone())
        .reference("primary_mac_address", Kind::MacAddress, mac.clone())
        .custom_field(&custom_fields::SOURCE, PVE_A);
    assert_eq!(one(objects, Kind::VmInterface, &ens18), interface);
    let mac_address = Desired::new(Kind::MacAddress, mac.clone(), PVE_A)
        .field("mac_address", "02:00:00:00:00:A1")
        .reference("assigned_object", Kind::VmInterface, ens18.clone());
    assert_eq!(one(objects, Kind::MacAddress, &mac), mac_address);
    let address = Desired::new(Kind::IpAddress, address_identity("198.18.0.70"), PVE_A)
        .field("address", "198.18.0.70/26")
        .field("status", "active")
        .reference("tenant", Kind::Tenant, Identity::named("Example Tenant"))
        .reference("assigned_object", Kind::VmInterface, ens18)
        .custom_field(&custom_fields::ARP_ENTRY, false)
        .custom_field(&custom_fields::SOURCE, PVE_A);
    assert_eq!(one(objects, Kind::IpAddress, &address_identity("198.18.0.70")), address);
    // 198.18.0.70/26 is in 198.18.0.64/26.
    let prefix = Desired::new(Kind::Prefix, Identity::prefix("198.18.0.64/26", VrfKey::Unknown), PVE_A)
        .field("prefix", "198.18.0.64/26")
        .custom_field(&custom_fields::SOURCE, PVE_A)
        .ensure_only();
    assert_eq!(one(objects, Kind::Prefix, &Identity::prefix("198.18.0.64/26", VrfKey::Unknown)), prefix);

    // "/nodes/pve02/qemu/141/config": "ide2": "store1:debian-12.9.0-amd64-netinst.iso,media=cdrom,size=632M",
    //   "scsi0": "store2:vm-disk-1.qcow2,size=70G", "scsi1": "store2:vm-disk-0.qcow2,size=50G"
    let disk = |name: &str, size: u64| {
        Desired::new(Kind::VirtualDisk, Identity::virtual_disk(&identity, name), PVE_A)
            .field("name", name)
            .field("size", size)
            .field("description", name)
            .reference("virtual_machine", Kind::VirtualMachine, identity.clone())
            .custom_field(&custom_fields::SOURCE, PVE_A)
    };
    let disks: Vec<Desired> = of_kind(objects, Kind::VirtualDisk)
        .into_iter()
        .filter(|disk| disk.identity.key().starts_with(identity.key()))
        .cloned()
        .collect();
    // 70G = 71680 MiB, 50G = 51200 MiB; the ISO image is a 632 MiB CD-ROM, which netbox-ssot synced as a disk.
    assert_eq!(
        disks,
        [
            disk("store2:vm-disk-1.qcow2", 71_680),
            disk("store2:vm-disk-0.qcow2", 51_200),
            disk("store1:debian-12.9.0-amd64-netinst.iso", 632),
        ]
    );

    let tag = Desired::new(Kind::Tag, Identity::named("service-oom"), PVE_A)
        .field("name", "service-oom")
        .create_only("slug", "service-oom")
        .create_only("color", "4caf50")
        .create_only("description", "netbox-omnisync")
        .ensure_only();
    assert_eq!(one(objects, Kind::Tag, &Identity::named("service-oom")), tag);
}

#[tokio::test]
async fn a_stopped_windows_vm_of_8_4_object_by_object() {
    let (_, translation) = translated("8.4", &production(PVE_A)).await;
    let objects = &translation.objects;
    let identity = Identity::virtual_machine("vm024.example", CLUSTER_A);

    // "/nodes/pve01/qemu": { "cpus": 4, "maxmem": 17179869184, "name": "vm024.example", "status": "stopped", "vmid":
    //   167 }
    // No ".../qemu/167/agent/..." entry: its interfaces and its system are unknown.
    let expected = Desired::new(Kind::VirtualMachine, identity.clone(), PVE_A)
        .field("name", "vm024.example")
        .field("status", "offline")
        .field("vcpus", 4)
        // 17179869184 / 1048576 = 16384
        .field("memory", 16_384)
        .tags(Vec::<String>::new())
        .custom_field(&custom_fields::SOURCE, PVE_A)
        .custom_field(&custom_fields::SOURCE_ID, "167")
        // ".../qemu/167/config": "ostype": "win11" — proxmoxOSTypePlatformNames: "Microsoft Windows 11 (64-bit)",
        // written only when NetBox has no platform for this VM.
        .reference("platform", Kind::Platform, Identity::named("Microsoft Windows 11 (64-bit)"))
        .only_when_empty("platform")
        .unknown_dependents([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]);
    assert_eq!(one(objects, Kind::VirtualMachine, &identity), placed(expected, CLUSTER_A, "pve01.infra.example"));

    // Nothing but its two disks hangs under it.
    let under: Vec<(Kind, String)> = objects
        .iter()
        .filter(|object| object.kind != Kind::VirtualMachine && object.identity.key().starts_with(identity.key()))
        .map(|object| (object.kind, object.identity.label().to_owned()))
        .collect();
    // "/nodes/pve01/qemu/167/config": "ide0": "store1:vm-disk-1.qcow2,size=100G",
    //   "ide2": "store1:Win11_French_x64.iso,media=cdrom,size=5384344K"
    assert_eq!(
        under,
        [
            (Kind::VirtualDisk, "store1:vm-disk-1.qcow2".to_owned()),
            (Kind::VirtualDisk, "store1:Win11_French_x64.iso".to_owned())
        ]
    );
    let iso = one(objects, Kind::VirtualDisk, &Identity::virtual_disk(&identity, "store1:Win11_French_x64.iso"));
    // 5384344K / 1024 = 5258.14 MiB, rounded down.
    assert_eq!(iso.fields["size"], json!(5258));
}

// ---------------------------------------------------------------------------
// The 9.2 cluster
// ---------------------------------------------------------------------------

const PVE_B: &str = "pve-b";
const CLUSTER_B: &str = "pve-cluster-b";

#[tokio::test]
async fn the_9_2_cluster_gives_these_objects() {
    let (_, translation) = translated("9.2", &production(PVE_B)).await;
    let objects = &translation.objects;
    assert_eq!(translation.warnings, Vec::<String>::new());

    assert_eq!(
        counts(objects),
        [
            // 11 distinct tags on the 13 VMs that are not templates: service-apache, service-docker, service-etcd,
            // service-keepalived, service-patroni-haproxy, service-pgbouncer, service-php-fpm, service-postgres,
            // service-restic, tag-1 and tag-2.
            (Kind::Tag, 11),
            (Kind::Tenant, 1),
            (Kind::Site, 1),
            (Kind::Manufacturer, 1),
            (Kind::DeviceType, 1),
            // The 9 get-osinfo answers that carry a "pretty-name" say Debian GNU/Linux 12 (bookworm) or 13 (trixie).
            // Plus "Other 2.6.x Linux (64-bit)", the ostype "l26" of the 4 guests whose agent is silent.
            (Kind::Platform, 3),
            (Kind::Role, 2),
            (Kind::ClusterType, 1),
            (Kind::Cluster, 1),
            // "tag=10" and "tag=11" on the "netN" keys of the configurations; "vlan-id": "19", "20" and "25" on
            // the 6 entries of type "vlan" of the two "/nodes/<node>/network".
            (Kind::Vlan, 5),
            // The 20 IPv4 addresses are in 198.18.0.0/24 or 198.18.1.0/24.
            (Kind::Prefix, 2),
            (Kind::Device, 2),
            // 18 entries in the two "/nodes/<node>/qemu", 5 of them with "template": 1.
            (Kind::VirtualMachine, 13),
            // "/nodes/pve01/network" has 18 entries, pve02 17.
            (Kind::Interface, 35),
            // The 13 agents list 25 interfaces besides "lo"; 5 match the filter (3 "veth…", "docker0", one "br-…").
            (Kind::VmInterface, 20),
            // 27 disk keys with a "size=" in the 13 configurations, 7 of them cloud-init CD-ROM drives of 4M.
            (Kind::VirtualDisk, 27),
            (Kind::MacAddress, 20),
            // 20 "ipv4" addresses, all /24, and 20 "ipv6" ones, on those 20 interfaces.
            (Kind::IpAddress, 20),
        ]
    );
    assert_eq!(objects.len(), 161 + 5);

    // Each of the 20 interfaces kept ("eth0" or "eth1") has the address of a "netN" key of its VM, all with a
    // "tag": 20 access ports. Of the 13 running VMs, 8 have "net0" with "tag=10" (102, 103, 104, 105, 106, 113, 116
    // and 117) and 5 with "tag=11" (107, 108, 109, 110 and 112); the 7 that have a "net1" have it with "tag=11".
    let ports = of_kind(objects, Kind::VmInterface);
    assert!(ports.iter().all(|port| text(port, "mode") == "access"));
    let vlan_of =
        |port: &&Desired| port.references["untagged_vlan"].as_ref().map(|vlan| vlan.identity.label().to_owned());
    assert_eq!(ports.iter().filter(|port| vlan_of(port).as_deref() == Some("10")).count(), 8);
    assert_eq!(ports.iter().filter(|port| vlan_of(port).as_deref() == Some("11")).count(), 12);

    let addresses = of_kind(objects, Kind::IpAddress);
    assert!(addresses.iter().all(|address| !text(address, "address").contains(':')));

    let vms = of_kind(objects, Kind::VirtualMachine);
    // The 13 VMs are "running" and their 13 agents list their interfaces.
    assert!(vms.iter().all(|vm| text(vm, "status") == "active" && vm.unknown_dependents.is_empty()));
    // 4 of the 13 get-osinfo answers are {"error": {"class": "CommandNotFound"}}: 9 platforms are known,
    // and the 4 others get the one of their ostype, written only when NetBox has none.
    assert_eq!(with_reference(&vms, "platform").len(), 13);
    assert_eq!(vms.iter().filter(|vm| vm.only_when_empty.contains("platform")).count(), 4);
    assert_eq!(with_reference(&vms, "primary_ip4").len(), 13);
    // "tags" is set on each of the 13 entries.
    assert_eq!(vms.iter().filter(|vm| vm.tags.as_ref().is_some_and(|tags| !tags.is_empty())).count(), 13);

    let interfaces = of_kind(objects, Kind::Interface);
    // 6 "bond", 6 "bridge", 6 "vlan" and 17 "eth" in the two network lists.
    let typed =
        |kind: &str| interfaces.iter().filter(|interface| interface.fields.get("type") == Some(&json!(kind))).count();
    assert_eq!([typed("lag"), typed("bridge"), typed("virtual")], [6, 6, 6]);
    assert_eq!(
        interfaces.iter().filter(|interface| interface.create_only.get("type") == Some(&json!("other"))).count(),
        17
    );
    assert_eq!(with_reference(&interfaces, "lag").len(), 12);
    // "/nodes/pve01/network": { "iface": "idrac", "type": "eth" } has no "active": it is down. The 34 others are up.
    let down: Vec<&Desired> =
        interfaces.iter().copied().filter(|interface| interface.fields["enabled"] == json!(false)).collect();
    assert_eq!(down.len(), 1);
    assert_eq!(down[0].identity, Identity::interface("pve01.infra.example", "idrac"));

    // The 7 cloud-init drives that have a size are virtual disks.
    let disks = of_kind(objects, Kind::VirtualDisk);
    assert_eq!(disks.iter().filter(|disk| text(disk, "name").contains("cloudinit")).count(), 7);
    assert!(
        disks
            .iter()
            .filter(|disk| text(disk, "name").contains("cloudinit"))
            .all(|disk| disk.fields["size"] == json!(4))
    );
}

#[tokio::test]
async fn the_9_2_cluster_without_the_production_filters() {
    let mut settings = production(PVE_B);
    settings.ignored_subnets = vec![];
    settings.ignore_templates = false;
    settings.interface_filter = None;
    let (_, translation) = translated("9.2", &settings).await;
    let objects = &translation.objects;
    assert_eq!(translation.warnings, Vec::<String>::new());
    assert_eq!(of_kind(objects, Kind::VirtualMachine).len(), 18);
    // Without the filter the 25 interfaces besides "lo" are synced.
    assert_eq!(of_kind(objects, Kind::VmInterface).len(), 25);
    let vms = of_kind(objects, Kind::VirtualMachine);
    // Each of the 13 running VMs has an fe80::…/64 address on its first interface, and no
    // other IPv6 one: a link-local address is never primary.
    assert_eq!(with_reference(&vms, "primary_ip6").len(), 0);
}

#[tokio::test]
async fn the_hosts_of_9_2() {
    let (_, translation) = translated("9.2", &production(PVE_B)).await;
    let objects = &translation.objects;
    // "/nodes/pve02/status": "cpuinfo": { "cpus": 56 }, "memory": { "total": 540888895488 } — 503.74 GiB.
    let name = "pve02.infra.example";
    let expected = Desired::new(Kind::Device, Identity::device(name), PVE_B)
        .field("name", name)
        .reference("role", Kind::Role, Identity::named("Hypervisor"))
        .reference("site", Kind::Site, Identity::named("Paris"))
        .reference("tenant", Kind::Tenant, Identity::named("Example Tenant"))
        .reference("cluster", Kind::Cluster, Identity::named(CLUSTER_B))
        .custom_field(&custom_fields::HOST_CPU_CORES, "56")
        .custom_field(&custom_fields::HOST_MEMORY, "503 GiB")
        .custom_field(&custom_fields::SOURCE, PVE_B)
        .reference("device_type", Kind::DeviceType, Identity::device_type("Generic Manufacturer", "Generic Model"))
        .only_when_empty("device_type");
    assert_eq!(one(objects, Kind::Device, &Identity::device(name)), expected);
    // "/nodes/pve01/status": "cpus": 32, "total": 270357209088 — 251.79 GiB.
    let other = one(objects, Kind::Device, &Identity::device("pve01.infra.example"));
    assert_eq!(other.custom_fields["host_cpu_cores"], json!("32"));
    assert_eq!(other.custom_fields["host_memory"], json!("251 GiB"));

    // "/nodes/pve01/network": { "iface": "bond0", "slaves": "enp129s0 enp130s0", "type": "bond" }
    let device = "pve01.infra.example";
    let lag = |name: &str| {
        let interface = one(objects, Kind::Interface, &Identity::interface(device, name));
        interface.references.get("lag").cloned().flatten().map(|target| target.identity)
    };
    assert_eq!(lag("enp129s0"), Some(Identity::interface(device, "bond0")));
    assert_eq!(lag("enp130s0"), Some(Identity::interface(device, "bond0")));
    // { "iface": "bond2", "slaves": "enp129s0d1 enp130s0d1", "type": "bond" }
    assert_eq!(lag("enp129s0d1"), Some(Identity::interface(device, "bond2")));
    // { "iface": "eno3", "type": "eth" } and { "iface": "idrac", "type": "eth" } are in no bond.
    assert_eq!(lag("eno3"), None);
    assert_eq!(lag("idrac"), None);
}

#[tokio::test]
async fn a_vm_of_9_2_with_two_interfaces_and_an_old_agent_object_by_object() {
    let (_, translation) = translated("9.2", &production(PVE_B)).await;
    let objects = &translation.objects;
    let identity = Identity::virtual_machine("vm002.example", CLUSTER_B);

    // "/nodes/pve01/qemu": { "cpus": 8, "maxmem": 17179869184, "name": "vm002.example", "status": "running",
    //   "tags": "tag-1;service-apache;tag-2", "vmid": 105 }
    // "/nodes/pve01/qemu/105/agent/get-osinfo": "result": {"error": {"class": "CommandNotFound", …}}:
    // the agent says nothing of the system, the platform NetBox has is kept.
    let expected = Desired::new(Kind::VirtualMachine, identity.clone(), PVE_B)
        .field("name", "vm002.example")
        .field("status", "active")
        .field("vcpus", 8)
        .field("memory", 16_384)
        // The first "ipv4" address in the order of the agent: the one of "eth0".
        .reference("primary_ip4", Kind::IpAddress, address_identity("198.18.0.177"))
        .tags(["tag-1", "service-apache", "tag-2"])
        .custom_field(&custom_fields::SOURCE, PVE_B)
        .custom_field(&custom_fields::SOURCE_ID, "105")
        // ".../qemu/105/config": "ostype": "l26" — proxmoxOSTypePlatformNames: "Other 2.6.x Linux (64-bit)",
        // written only when NetBox has no platform for this VM.
        .reference("platform", Kind::Platform, Identity::named("Other 2.6.x Linux (64-bit)"))
        .only_when_empty("platform");
    assert_eq!(one(objects, Kind::VirtualMachine, &identity), placed(expected, CLUSTER_B, "pve01.infra.example"));

    // ".../105/agent/network-get-interfaces": "lo",
    //   { "hardware-address": "02:00:00:00:00:08", "ip-addresses": [ 198.18.0.177/24 "ipv4", fe80::7/64 "ipv6" ],
    //   "name": "eth0" },
    //   { "hardware-address": "02:00:00:00:00:09", "ip-addresses": [ 198.18.1.177/24 "ipv4", fe80::8/64 "ipv6" ],
    //   "name": "eth1" }
    let under = |kind: Kind| -> Vec<String> {
        objects
            .iter()
            .filter(|object| object.kind == kind)
            .filter(|object| {
                let holder =
                    object.references.get("assigned_object").and_then(Option::as_ref).map(|target| &target.identity);
                holder.unwrap_or(&object.identity).key().starts_with(identity.key())
            })
            .map(|object| object.identity.label().to_owned())
            .collect()
    };
    assert_eq!(under(Kind::VmInterface), ["eth0", "eth1"]);
    assert_eq!(under(Kind::MacAddress), ["02:00:00:00:00:08", "02:00:00:00:00:09"]);
    assert_eq!(under(Kind::IpAddress), ["198.18.0.177/24", "198.18.1.177/24"]);
    let second = one(objects, Kind::IpAddress, &address_identity("198.18.1.177"));
    assert_eq!(second.references["assigned_object"].as_ref().unwrap().identity, nic_identity(&identity, "eth1"));

    // "/nodes/pve01/qemu/105/config": "ide1": "store1:vm-105-cloudinit.raw,media=cdrom,size=4M",
    //   "scsi0": "store1:vm-disk-0.qcow2,size=15G" — 15360 MiB, and the cloud-init drive of 4 MiB.
    let size =
        |name: &str| one(objects, Kind::VirtualDisk, &Identity::virtual_disk(&identity, name)).fields["size"].clone();
    assert_eq!(under(Kind::VirtualDisk), ["store1:vm-disk-0.qcow2", "store1:vm-105-cloudinit.raw"]);
    assert_eq!(size("store1:vm-disk-0.qcow2"), json!(15_360));
    assert_eq!(size("store1:vm-105-cloudinit.raw"), json!(4));
}

#[tokio::test]
async fn a_vm_of_9_2_whose_agent_tells_its_system_object_by_object() {
    let (_, translation) = translated("9.2", &production(PVE_B)).await;
    let objects = &translation.objects;
    let identity = Identity::virtual_machine("vm001.example", CLUSTER_B);

    // "/nodes/pve01/qemu": { "cpus": 2, "maxmem": 2147483648, "name": "vm001.example", "status": "running",
    //   "tags": "service-etcd", "vmid": 109 }
    // ".../109/agent/get-osinfo": "pretty-name": "Debian GNU/Linux 12 (bookworm)"
    // ".../109/agent/network-get-interfaces": "lo" and { "hardware-address": "02:00:00:00:00:0b", "ip-addresses": [
    //   198.18.1.10/24 "ipv4", fe80::a/64 "ipv6" ], "name": "eth0" }
    let expected = Desired::new(Kind::VirtualMachine, identity.clone(), PVE_B)
        .field("name", "vm001.example")
        .field("status", "active")
        .field("vcpus", 2)
        .field("memory", 2048)
        .reference("platform", Kind::Platform, Identity::named("Debian GNU/Linux 12 (bookworm)"))
        .reference("primary_ip4", Kind::IpAddress, address_identity("198.18.1.10"))
        .tags(["service-etcd"])
        .custom_field(&custom_fields::SOURCE, PVE_B)
        .custom_field(&custom_fields::SOURCE_ID, "109");
    assert_eq!(one(objects, Kind::VirtualMachine, &identity), placed(expected, CLUSTER_B, "pve01.infra.example"));

    let platform = Desired::new(Kind::Platform, Identity::named("Debian GNU/Linux 12 (bookworm)"), PVE_B)
        .field("name", "Debian GNU/Linux 12 (bookworm)")
        .create_only("slug", "debian-gnulinux-12-bookworm");
    assert_eq!(one(objects, Kind::Platform, &Identity::named("Debian GNU/Linux 12 (bookworm)")), platform);

    // The MAC address is written in upper case.
    let mac = mac_identity("02:00:00:00:00:0B", &identity, "eth0");
    assert_eq!(one(objects, Kind::MacAddress, &mac).fields["mac_address"], json!("02:00:00:00:00:0B"));

    // "/nodes/pve01/qemu/109/config": "ide1": "store1:vm-109-cloudinit.raw,media=cdrom" has no size: no disk.
    //   "scsi0": "store1:vm-disk-0.qcow2,size=25G" — 25600 MiB.
    let disks: Vec<&Desired> = of_kind(objects, Kind::VirtualDisk)
        .into_iter()
        .filter(|disk| disk.identity.key().starts_with(identity.key()))
        .collect();
    assert_eq!(labels(&disks), ["store1:vm-disk-0.qcow2"]);
    assert_eq!(disks[0].fields["size"], json!(25_600));
}

// ---------------------------------------------------------------------------
// Reconciliation: created once, then nothing left to write
// ---------------------------------------------------------------------------

/// A NetBox reduced to what a plan writes and to what the loader reads back.
///
/// It stores the steps of a plan as NetBox 4.5 to 4.7 would render them (a reference
/// as a nested `{id, name}`, a generic one with its `_type` and `_id`, a
/// choice as `{value, label}`, tags as `{name, slug}`) and hands the rows to
/// `current_objects`, the code the real loader uses to identify them. It
/// validates nothing: a payload NetBox would refuse is accepted here.
#[derive(Default)]
struct FakeNetbox {
    rows: BTreeMap<Kind, Vec<Row>>,
    ids: BTreeMap<(Kind, Vec<String>), u64>,
    last_id: u64,
}

impl FakeNetbox {
    fn id_of(&self, link: &Link) -> u64 {
        link.id.unwrap_or_else(|| {
            *self.ids.get(&(link.kind, link.identity.key().to_vec())).expect("a reference to an object that exists")
        })
    }

    /// The slug of a tag: the one it was created with, its name for an
    /// ownership tag, which the tool names by its slug.
    fn tag(&self, name: &str) -> Value {
        let created = self.rows.get(&Kind::Tag).into_iter().flatten().find(|row| row["name"] == json!(name));
        let slug = created.map_or_else(|| json!(name), |row| row["slug"].clone());
        json!({"name": name, "slug": slug})
    }

    fn render(&self, step: &Step, row: &mut Row) {
        for (field, value) in &step.change.fields {
            if let Some(link) = step.references.get(field) {
                let nested = link.as_ref().map(|link| json!({"id": self.id_of(link), "name": link.identity.label()}));
                if step.kind.generic_fields().contains(&field.as_str()) {
                    let content_type = link.as_ref().map(|link| link.kind.content_type());
                    row.insert(format!("{field}_type"), json!(content_type));
                    row.insert(format!("{field}_id"), json!(link.as_ref().map(|link| self.id_of(link))));
                }
                row.insert(field.clone(), json!(nested));
            } else if field == "tags" {
                let names = value.as_array().expect("a list of tag names");
                let tags: Vec<Value> = names.iter().map(|name| self.tag(name.as_str().expect("a tag name"))).collect();
                row.insert(field.clone(), Value::Array(tags));
            } else if field == "custom_fields" {
                let held = row.entry(field.clone()).or_insert_with(|| Value::Object(Map::new()));
                let held = held.as_object_mut().expect("custom fields");
                held.extend(value.as_object().expect("custom fields").clone());
            } else if matches!(field.as_str(), "status" | "type") && value.is_string() {
                row.insert(field.clone(), json!({"value": value, "label": value}));
            } else {
                row.insert(field.clone(), value.clone());
            }
        }
    }

    fn apply(&mut self, plan: &Plan) {
        for step in &plan.steps {
            assert!(step.reference_lists.is_empty(), "the Proxmox source declares no reference list");
            let key = (step.kind, step.identity.key().to_vec());
            match step.change.action {
                Action::Create => {
                    self.last_id += 1;
                    let mut row = Row::new();
                    row.insert("id".to_owned(), json!(self.last_id));
                    self.render(step, &mut row);
                    // Two objects of one identity would make the references of this model ambiguous.
                    assert_eq!(self.ids.insert(key, self.last_id), None, "{:?} created twice", step.identity.key());
                    self.rows.entry(step.kind).or_default().push(row);
                }
                Action::Update => {
                    let id = step.change.id.unwrap_or_else(|| self.ids[&key]);
                    let rows = self.rows.get(&step.kind).expect("rows of that kind");
                    let at = rows.iter().position(|row| row["id"] == json!(id)).expect("the updated row");
                    let mut row = rows[at].clone();
                    self.render(step, &mut row);
                    self.rows.get_mut(&step.kind).expect("rows of that kind")[at] = row;
                }
                Action::Delete => panic!("{:?} deleted", step.identity.key()),
            }
        }
    }

    fn current(&self) -> Vec<Current> {
        let (current, warnings) = current_objects(&self.rows);
        assert_eq!(warnings, Vec::<String>::new());
        current
    }
}

fn run(source: &str) -> Run {
    Run {
        sources: vec![SourceFacts {
            name: source.to_owned(),
            tag: format!("source-{source}"),
            status: SourceStatus::Succeeded,
            prune: true,
            create_devices: true,
        }],
        priority: vec![source.to_owned()],
        unique_ip_vrfs: BTreeSet::new(),
        source_tag_markers: vec![],
    }
}

/// How a reported object is told from the others: an address is one per interface.
fn object_key(kind: Kind, identity: &Identity) -> (Kind, Vec<String>) {
    (kind, identity.key().to_vec())
}

/// Translates a fixture, reconciles it with an empty NetBox, then with the
/// NetBox the first plan gives. `links` is the number of references written
/// in the second step of the first plan.
async fn created_once_then_nothing(version: &str, source: &str, links: usize) {
    let (_, translation) = translated(version, &production(source)).await;
    let facts = run(source);

    let first = reconcile(&translation.objects, &[], &facts);
    assert_eq!(first.warnings, Vec::<String>::new());
    assert_eq!(first.orphans_kept, Vec::<String>::new());
    let created: Vec<&Step> = first.steps.iter().filter(|step| step.change.action == Action::Create).collect();
    let created_keys: BTreeSet<(Kind, Vec<String>)> =
        created.iter().map(|step| object_key(step.kind, &step.identity)).collect();
    let wanted_keys: BTreeSet<(Kind, Vec<String>)> =
        translation.objects.iter().map(|object| object_key(object.kind, &object.identity)).collect();
    // Every object is created, none twice, and nothing else is.
    assert_eq!(created.len(), translation.objects.len());
    assert_eq!(created_keys.len(), created.len());
    assert_eq!(created_keys, wanted_keys);
    assert!(created.iter().all(|step| step.phase == Phase::Write && step.change.id.is_none()));
    // Each creation carries the two ownership tags, except a tag, which has none.
    for step in &created {
        let tags = step.change.fields.get("tags");
        if step.kind == Kind::Tag {
            assert_eq!(tags, None);
        } else {
            let names: Vec<&str> =
                tags.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
            assert!(names.contains(&TOOL_TAG) && names.contains(&facts.sources[0].tag.as_str()), "{names:?}");
        }
    }
    // What is left are the references to objects created later: a primary address, a primary MAC, a LAG,
    // the interface a VLAN sub-interface is carried on.
    let linked: Vec<&Step> = first.steps.iter().filter(|step| step.change.action != Action::Create).collect();
    assert!(linked.iter().all(|step| step.phase == Phase::Link && step.change.action == Action::Update));
    let late: BTreeSet<&str> = linked.iter().flat_map(|step| step.change.fields.keys().map(String::as_str)).collect();
    assert_eq!(late, BTreeSet::from(["lag", "parent", "primary_ip4", "primary_mac_address"]));
    assert_eq!(linked.len(), links);

    let mut netbox = FakeNetbox::default();
    netbox.apply(&first);
    let current = netbox.current();
    assert_eq!(current.len(), translation.objects.len());

    let second = reconcile(&translation.objects, &current, &facts);
    assert_eq!(second.changes(), []);
    assert_eq!(second.warnings, Vec::<String>::new());
    assert_eq!(second.orphans_kept, Vec::<String>::new());
}

#[tokio::test]
async fn the_8_4_cluster_is_created_once_and_a_second_run_writes_nothing() {
    // 45 VMs with a primary IPv4, 49 interfaces with a primary MAC, 18 members of a bond, 15 VLAN sub-interfaces.
    created_once_then_nothing("8.4", PVE_A, 45 + 49 + 18 + 15).await;
}

#[tokio::test]
async fn the_9_2_cluster_is_created_once_and_a_second_run_writes_nothing() {
    // 13 VMs with a primary IPv4, 20 interfaces with a primary MAC, 12 members of a bond, 6 VLAN sub-interfaces.
    created_once_then_nothing("9.2", PVE_B, 13 + 20 + 12 + 6).await;
}
