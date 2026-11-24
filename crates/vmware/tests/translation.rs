//! The translation of the recorded vCenter, and its reconciliation.
//!
//! Every expected value below was read in `tests/fixtures/6.7/` (what was read
//! is quoted above the assertion) or comes from the Python source of
//! netbox-sync v1.8.0 as inventoried in `docs/vmware-reference.md`; none was
//! copied from what the code returns.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use omnisync_core::change::Action;
use omnisync_core::inventory::dns::{Asked, NoReverseDns, ReverseDns};
use omnisync_core::inventory::model::{Desired, Identity, Kind, LEGACY_TAG_MARKERS, Target, VlanScope, VrfKey};
use omnisync_core::inventory::reconcile::{Plan, Run, SourceFacts, SourceStatus, ownership_tags, reconcile};
use omnisync_core::network::hosts::Heard;
use omnisync_netbox::inventory_apply::apply;
use omnisync_netbox::inventory_state::load;
use omnisync_netbox::testing::FakeGateway;
use omnisync_vmware::collect::{Inventory, Wanted, collect, collect_with};
use omnisync_vmware::translate::{Settings, TAG_MARKER, Translation, desired};
use serde_json::{Value, json};

mod common;

use common::{client, vcenter};

const VC: &str = "vc-a";
const SITE: &str = "Harbor";
const TENANT: &str = "Example Tenant";
const HOST_ROLE: &str = "Hypervisor ESX";
const VM_ROLE: &str = "Virtual Machine ESX";
const CLUSTER: &str = "cluster2";

fn subnets<const N: usize>(written: [&str; N]) -> Vec<ipnet::IpNet> {
    written.iter().map(|subnet| subnet.parse().unwrap()).collect()
}

/// The settings of production, with made-up names: every relation of
/// netbox-sync was `.* = value` there, the templates were skipped and only
/// one IPv4 range was permitted. The fixtures were anonymised into
/// `198.18.0.0/15`, which stands for that range here.
fn production() -> Settings {
    Settings {
        tenant: Some(TENANT.to_owned()),
        host_role: Some(HOST_ROLE.to_owned()),
        vm_role: Some(VM_ROLE.to_owned()),
        permitted_subnets: subnets(["198.18.0.0/15"]),
        ..Settings::new(VC, SITE)
    }
}

async fn inventory() -> Inventory {
    let server = vcenter("6.7").await;
    collect(&client(&server)).await.expect("inventory")
}

async fn translated(settings: &Settings) -> Translation {
    desired(&inventory().await, settings, &NoReverseDns).expect("translation")
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

fn with_reference<'a>(objects: &[&'a Desired], field: &str) -> Vec<&'a Desired> {
    objects.iter().copied().filter(|object| object.references.get(field).is_some_and(Option::is_some)).collect()
}

fn text(object: &Desired, field: &str) -> String {
    object.fields[field].as_str().unwrap_or_else(|| panic!("{field} of {:?}", object.identity.key())).to_owned()
}

fn names(objects: &[&Desired]) -> BTreeSet<String> {
    objects.iter().map(|object| object.identity.label().to_owned()).collect()
}

fn vm(name: &str) -> Identity {
    Identity::virtual_machine(name, CLUSTER)
}

fn nic(owner: &Identity, name: &str) -> Identity {
    Identity::vm_interface(owner, name)
}

fn port(host: &str, name: &str) -> Identity {
    Identity::interface(host, name)
}

fn vlan(vid: u64) -> Identity {
    Identity::vlan(VlanScope::Site(SITE), vid)
}

fn vlan_target(vid: u64) -> Target {
    Target::new(Kind::Vlan, vlan(vid))
}

fn address(written: &str) -> Identity {
    Identity::ip_address(written, VrfKey::Unknown)
}

fn new(kind: Kind, identity: Identity) -> Desired {
    Desired::new(kind, identity, VC)
}

/// What every host of `production` refers to, whatever it is.
fn host_placed(object: Desired) -> Desired {
    object
        .reference("site", Kind::Site, Identity::named(SITE))
        .reference("cluster", Kind::Cluster, Identity::named(CLUSTER))
        .reference("tenant", Kind::Tenant, Identity::named(TENANT))
        .reference("role", Kind::Role, Identity::named(HOST_ROLE))
        .reference("platform", Kind::Platform, Identity::named("VMware ESXi 6.7.0"))
}

/// What every virtual machine of `production` refers to, whatever it is.
fn vm_placed(object: Desired, host: &str) -> Desired {
    object
        .reference("site", Kind::Site, Identity::named(SITE))
        .reference("cluster", Kind::Cluster, Identity::named(CLUSTER))
        .reference("device", Kind::Device, Identity::device(host))
        .reference("tenant", Kind::Tenant, Identity::named(TENANT))
        .reference("role", Kind::Role, Identity::named(VM_ROLE))
}

// ---------------------------------------------------------------------------
// The whole vCenter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_6_7_vcenter_gives_these_objects() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    // `vm041.lab.example` is the name of vm-5366 and vm-4513, both powered on; `vm068.lab.example` the name
    // of vm-5365, powered on, and vm-4339, powered off.
    assert_eq!(
        translation.warnings,
        [
            "skipping vm vm041.lab.example (vm-5366): name already used by vm-4513 in cluster cluster2; \
             machine names must be unique in a cluster",
            "skipping vm vm068.lab.example (vm-4339): name already used by vm-5365 in cluster cluster2; \
             machine names must be unique in a cluster",
        ]
    );

    assert_eq!(
        counts(objects),
        [
            // 28 tags in `rest.tag.list.json`; `service-veeam` (rest.tag.25) is attached to nothing.
            (Kind::Tag, 27),
            (Kind::Tenant, 1),
            (Kind::Site, 1),
            // `summary.hardware.vendor` is "Dell Inc." on the six hosts.
            (Kind::Manufacturer, 1),
            // `summary.hardware.model`: PowerEdge R630, R640 (three times), FC430 and R650.
            (Kind::DeviceType, 4),
            // "VMware ESXi 6.7.0" for the hosts, and 22 distinct systems for the machines that are synced:
            // 9 "prettyName" of the tools, 8 `guest.guestFullName` and, for 3 powered-off machines whose
            // tools never told anything, their `config.guestFullName`, two of which no other machine has.
            // Six systems of Windows that differ by their build alone are three platforms.
            (Kind::Platform, 20),
            (Kind::Role, 2),
            (Kind::ClusterType, 1),
            // One datacenter, `DC1`, and one cluster, `cluster2` (domain-c7), listed as a compute resource too.
            (Kind::ClusterGroup, 1),
            (Kind::Cluster, 1),
            // The `spec.vlanId` of the port groups of the six hosts: 26, 2500, 2701, 2702, 2703, 2712, 2715,
            // 2716, 2717, 2800, 2901 and 3012.
            (Kind::Vlan, 12),
            (Kind::Device, 6),
            // 166 machines, 8 of them with `config.template` true, and 2 homonyms left out.
            (Kind::VirtualMachine, 156),
            // `config.network.pnic` lists 6, 4, 4, 3, 4 and 4 cards; each host has 3 `config.network.vnic`.
            (Kind::Interface, 43),
            // 169 devices with a `macAddress` on the 166 machines; 8 on the templates, 2 on vm-5366 and 1 on
            // vm-4339.
            (Kind::VmInterface, 158),
            // 294 `VirtualDisk` devices; 8 on the templates, 2 on vm-5366 and 2 on vm-4339.
            (Kind::VirtualDisk, 282),
            // One per interface: every card and every vmkernel interface has a MAC address.
            (Kind::MacAddress, 201),
            // 18 `spec.ip.ipAddress` on the vmkernel interfaces, and 164 addresses that are not `fe80::…`
            // on the `guest.net` cards of the machines whose tools run.
            (Kind::IpAddress, 182),
        ]
    );
    assert_eq!(objects.len(), 1099);

    // No IPv6: the only ones are link-local.
    let addresses = of_kind(objects, Kind::IpAddress);
    assert!(addresses.iter().all(|address| !text(address, "address").contains(':')));
    // No DNS name is resolved, no status and no VRF is chosen for an address.
    for field in ["dns_name", "status"] {
        assert!(addresses.iter().all(|address| !address.fields.contains_key(field)), "{field}");
    }
    assert!(addresses.iter().all(|address| !address.references.contains_key("vrf")));
    assert!(addresses.iter().all(|address| address.identity.key()[1] == "*"));

    let vms = of_kind(objects, Kind::VirtualMachine);
    // `runtime.powerState` is poweredOff on 20 machines: the 8 templates, vm-4339 and 11 others.
    assert_eq!(vms.iter().filter(|vm| text(vm, "status") == "offline").count(), 11);
    assert_eq!(vms.iter().filter(|vm| text(vm, "status") == "active").count(), 145);
    // `guest.toolsRunningStatus` is guestToolsNotRunning on those 11: their addresses are unknown.
    let unknown: Vec<&&Desired> = vms.iter().filter(|vm| !vm.unknown_dependents.is_empty()).collect();
    assert_eq!(unknown.len(), 11);
    assert!(unknown.iter().all(|vm| vm.unknown_dependents == BTreeSet::from([Kind::IpAddress])));
    assert!(unknown.iter().all(|vm| text(vm, "status") == "offline"));
    // Every machine has a system; the 3 that only have the one of their configuration (vm-5242, vm-37699
    // and vm-176, powered off, without `guest.guestFullName` nor "prettyName") only fill an empty platform.
    assert_eq!(with_reference(&vms, "platform").len(), 156);
    let configured: BTreeSet<String> =
        vms.iter().filter(|vm| vm.only_when_empty.contains("platform")).map(|vm| text(vm, "name")).collect();
    assert_eq!(configured, BTreeSet::from(["vm015.lab.example", "vm141", "vm160.lab.example"].map(str::to_owned)));
    // 123 of the 145 running machines have an address in the network of their default gateway.
    assert_eq!(with_reference(&vms, "primary_ip4").len(), 123);
    assert!(
        vms.iter().all(|vm| !vm.references.contains_key("primary_ip4") || vm.only_when_empty.contains("primary_ip4"))
    );
    assert_eq!(with_reference(&vms, "primary_ip6").len(), 0);
    // 122 of the 156 machines carry a tag; every machine says which ones, none included.
    assert_eq!(vms.iter().filter(|vm| vm.tags.as_ref().is_some_and(|tags| !tags.is_empty())).count(), 122);
    assert!(vms.iter().all(|vm| vm.tags.is_some()));
    // `config.annotation` holds a text on 5 machines.
    assert_eq!(vms.iter().filter(|vm| vm.fields.contains_key("comments")).count(), 5);

    let nics = of_kind(objects, Kind::VmInterface);
    // `connectable.connected` is false on the cards of the 11 powered-off machines, true on the 147 others.
    assert_eq!(nics.iter().filter(|nic| nic.fields["enabled"] == json!(false)).count(), 11);
    // Every card is on a standard port group of its host with a VLAN id: `access`, and that VLAN untagged.
    assert!(nics.iter().all(|nic| nic.fields["mode"] == json!("access")));
    assert_eq!(with_reference(&nics, "untagged_vlan").len(), 158);
    assert!(nics.iter().all(|nic| nic.fields["mtu"] == json!(1500)));

    // The devices say nothing of their tags: no host tag source is set.
    assert!(of_kind(objects, Kind::Device).iter().all(|device| device.tags.is_none()));
}

#[tokio::test]
async fn the_shared_objects_of_6_7() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;

    // A site, a tenant and a role only have to exist: one made by hand is used as it is.
    for (kind, name, slug) in [
        (Kind::Site, SITE, "harbor"),
        (Kind::Tenant, TENANT, "example-tenant"),
        (Kind::Role, HOST_ROLE, "hypervisor-esx"),
        (Kind::Role, VM_ROLE, "virtual-machine-esx"),
    ] {
        let expected = new(kind, Identity::named(name)).field("name", name).create_only("slug", slug).ensure_only();
        assert_eq!(one(objects, kind, &Identity::named(name)), expected);
    }
    assert_eq!(
        one(objects, Kind::ClusterType, &Identity::named("VMware ESXi")),
        new(Kind::ClusterType, Identity::named("VMware ESXi"))
            .field("name", "VMware ESXi")
            .create_only("slug", "vmware-esxi")
    );
    // `RetrievePropertiesEx.Datacenter.0.xml`: name `DC1`.
    assert_eq!(
        one(objects, Kind::ClusterGroup, &Identity::named("DC1")),
        new(Kind::ClusterGroup, Identity::named("DC1")).field("name", "DC1").create_only("slug", "dc1")
    );
    assert_eq!(
        one(objects, Kind::Cluster, &Identity::named(CLUSTER)),
        new(Kind::Cluster, Identity::named(CLUSTER))
            .field("name", CLUSTER)
            .reference("type", Kind::ClusterType, Identity::named("VMware ESXi"))
            .reference("group", Kind::ClusterGroup, Identity::named("DC1"))
            .reference("scope", Kind::Site, Identity::named(SITE))
            .reference("tenant", Kind::Tenant, Identity::named(TENANT))
    );
    // "Dell Inc." is the `Dell` of netbox-sync's mapping (`.*Dell.*`).
    assert_eq!(
        one(objects, Kind::Manufacturer, &Identity::named("Dell")),
        new(Kind::Manufacturer, Identity::named("Dell")).field("name", "Dell").create_only("slug", "dell")
    );
    let r640 = Identity::device_type("Dell", "PowerEdge R640");
    assert_eq!(
        one(objects, Kind::DeviceType, &r640),
        new(Kind::DeviceType, r640.clone())
            .field("model", "PowerEdge R640")
            .create_only("slug", "poweredge-r640")
            .reference("manufacturer", Kind::Manufacturer, Identity::named("Dell"))
    );
    // `summary.config.product`: name "VMware ESXi", version "6.7.0"; dots become hyphens in a slug.
    assert_eq!(
        one(objects, Kind::Platform, &Identity::named("VMware ESXi 6.7.0")),
        new(Kind::Platform, Identity::named("VMware ESXi 6.7.0"))
            .field("name", "VMware ESXi 6.7.0")
            .create_only("slug", "vmware-esxi-6-7-0")
    );
    // A system of the tools with a comma, its build left out (vm-6519, "prettyName" `Windows 11 Pro,
    // 64-bit (Build 26300.9974)`).
    let windows = "Windows 11 Pro, 64-bit";
    assert_eq!(
        one(objects, Kind::Platform, &Identity::named(windows)),
        new(Kind::Platform, Identity::named(windows))
            .field("name", windows)
            .create_only("slug", "windows-11-pro--64-bit")
    );
}

#[tokio::test]
async fn the_vlans_of_6_7() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    let vlans = of_kind(objects, Kind::Vlan);
    // Each VLAN only has to exist at the site, whatever its name there; the name is the one of the first
    // port group that has it, hosts taken by name: on esx01 (host-353) the port groups are, in order, pg-1
    // (3012), pg-2 (2712), pg-3 (2800), pg-4 (2500), pg-5 (2717), pg-6 (2715), pg-7 (2716), pg-8 (26),
    // Management Network (2800 again), pg-9 (2701), pg-10 (2702), pg-11 (2703) and pg-12 (2901), and every one
    // teams a physical card.
    let named: BTreeMap<u64, String> = vlans
        .iter()
        .map(|vlan| (vlan.fields["vid"].as_u64().unwrap(), vlan.create_only["name"].as_str().unwrap().to_owned()))
        .collect();
    let expected = [
        (26, "pg-8"),
        (2500, "pg-4"),
        (2701, "pg-9"),
        (2702, "pg-10"),
        (2703, "pg-11"),
        (2712, "pg-2"),
        (2715, "pg-6"),
        (2716, "pg-7"),
        (2717, "pg-5"),
        (2800, "pg-3"),
        (2901, "pg-12"),
        (3012, "pg-1"),
    ];
    assert_eq!(named, expected.into_iter().map(|(vid, name)| (vid, name.to_owned())).collect());
    assert_eq!(
        one(objects, Kind::Vlan, &vlan(26)),
        new(Kind::Vlan, vlan(26))
            .field("vid", 26)
            .create_only("name", "pg-8")
            .reference("site", Kind::Site, Identity::named(SITE))
            .ensure_only()
    );
}

// ---------------------------------------------------------------------------
// The hosts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_hosts_of_6_7() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    let devices = of_kind(objects, Kind::Device);
    // name, model, `SerialNumberTag`, cores and CPU model, memory in bytes rounded to GB, vmk0 address.
    let expected = [
        (
            "esx01.lab.example",
            "PowerEdge R630",
            "ID00001",
            "12 Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz",
            "198.18.0.35/24",
        ),
        (
            "esx02.lab.example",
            "PowerEdge R640",
            "ID00009",
            "36 Intel(R) Xeon(R) Gold 5220 CPU @ 2.20GHz",
            "198.18.0.38/24",
        ),
        (
            "esx03.lab.example",
            "PowerEdge R640",
            "ID00013",
            "36 Intel(R) Xeon(R) Gold 5220 CPU @ 2.20GHz",
            "198.18.0.59/24",
        ),
        (
            "esx04.lab.example",
            "PowerEdge FC430",
            "ID00016",
            "28 Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
            "198.18.0.36/24",
        ),
        (
            "esx05.lab.example",
            "PowerEdge R640",
            "ID00020",
            "36 Intel(R) Xeon(R) Gold 5220 CPU @ 2.20GHz",
            "198.18.0.39/24",
        ),
        (
            "esx06.lab.example",
            "PowerEdge R650",
            "ID00023",
            "36 Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
            "198.18.0.62/24",
        ),
    ];
    assert_eq!(devices.len(), expected.len());
    for (name, model, serial, cores, management) in expected {
        // `memorySize`, in bytes then in GiB: 549657538560 on esx01 (511.91), 274779635712 on esx04 (255.91),
        // 549217386496 on esx02, esx03 and esx05 (511.498) and 549180678144 on esx06 (511.46). Rounded to
        // the nearest: the last four are below the half.
        let memory = match name {
            "esx01.lab.example" => "512 GB",
            "esx04.lab.example" => "256 GB",
            _ => "511 GB",
        };
        let device = new(Kind::Device, Identity::device(name))
            .field("name", name)
            // `summary.runtime.connectionState` is `connected` on the six hosts.
            .field("status", "active")
            // The `AssetTag` identifier is empty on the six hosts: no asset tag.
            .field("serial", serial)
            .reference("device_type", Kind::DeviceType, Identity::device_type("Dell", model))
            .custom_field("host_cpu_cores", cores)
            .custom_field("host_memory", memory)
            // vmk0 is on the port group `Management Network` on every host.
            .reference("primary_ip4", Kind::IpAddress, address(management))
            .only_when_empty("primary_ip4");
        assert_eq!(one(objects, Kind::Device, &Identity::device(name)), host_placed(device), "{name}");
    }
}

#[tokio::test]
async fn a_host_of_6_7_object_by_object() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    // host-10, `esx04.lab.example`: vmnic0, vmnic1, vusb0, then vmk0, vmk1, vmk2.
    let host = "esx04.lab.example";
    let interfaces: Vec<&Desired> =
        of_kind(objects, Kind::Interface).into_iter().filter(|interface| interface.identity.owner() == host).collect();
    let listed: Vec<&str> = interfaces.iter().map(|interface| interface.identity.label()).collect();
    assert_eq!(listed, ["vmnic0", "vmnic1", "vusb0", "vmk0", "vmk1", "vmk2"]);

    let mac_of = |interface: &str, mac: &str| {
        Identity::mac_address(mac, Some(&Target::new(Kind::Interface, port(host, interface))))
    };
    // vmnic0: `mac` 02:00:00:00:00:64, `linkSpeed` 10000 Mb/s full duplex, uplink of vSwitch0 (`mtu` 1500).
    // The 13 port groups of the host team it (`Management Network` as its active card); their VLANs, in the
    // order of the port groups: 3012, 2716, 2715, 2701, 2712, 2800, 2500, 2717, 26, 2703, 2702, 2800 again, 2901.
    let vmnic0 = new(Kind::Interface, port(host, "vmnic0"))
        .field("name", "vmnic0")
        .field("type", "10gbase-x-sfpp")
        .field("enabled", true)
        .field("speed", 10_000_000)
        .field("duplex", "full")
        .field("mtu", 1500)
        .field("mode", "tagged")
        // Two spaces, as netbox-sync wrote it; the switch port it appended is not known here, so the
        // description only fills an interface that has none.
        .field("description", "10Gb/s  pNIC (vSwitch0)")
        .only_when_empty("description")
        .reference("device", Kind::Device, Identity::device(host))
        .reference_list(
            "tagged_vlans",
            [3012, 2716, 2715, 2701, 2712, 2800, 2500, 2717, 26, 2703, 2702, 2901].map(vlan_target),
        )
        .reference("primary_mac_address", Kind::MacAddress, mac_of("vmnic0", "02:00:00:00:00:64"));
    assert_eq!(one(objects, Kind::Interface, &port(host, "vmnic0")), vmnic0);

    // vusb0: `mac` 02:00:00:00:00:66, 100 Mb/s full duplex, on no switch and in no port group.
    let vusb0 = new(Kind::Interface, port(host, "vusb0"))
        .field("name", "vusb0")
        .field("type", "100base-tx")
        .field("enabled", true)
        .field("speed", 100_000)
        .field("duplex", "full")
        .field("description", "100Mb/s  pNIC")
        .only_when_empty("description")
        .reference("device", Kind::Device, Identity::device(host))
        .reference("primary_mac_address", Kind::MacAddress, mac_of("vusb0", "02:00:00:00:00:66"));
    assert_eq!(one(objects, Kind::Interface, &port(host, "vusb0")), vusb0);

    // vmk0: `spec.mac` 02:00:00:00:00:64 (the one of vmnic0), `spec.mtu` 1500, port group `Management
    // Network` of vSwitch0, VLAN 2800.
    let vmk0 = new(Kind::Interface, port(host, "vmk0"))
        .field("name", "vmk0")
        .field("type", "virtual")
        .field("enabled", true)
        .field("mtu", 1500)
        .field("mode", "access")
        .field("description", "Management Network (vSwitch0, vlan ID: 2800)")
        .reference("device", Kind::Device, Identity::device(host))
        .reference("untagged_vlan", Kind::Vlan, vlan(2800))
        .reference("primary_mac_address", Kind::MacAddress, mac_of("vmk0", "02:00:00:00:00:64"));
    assert_eq!(one(objects, Kind::Interface, &port(host, "vmk0")), vmk0);

    // The same MAC address on two interfaces is two objects.
    for interface in ["vmnic0", "vmk0"] {
        let identity = mac_of(interface, "02:00:00:00:00:64");
        assert_eq!(
            one(objects, Kind::MacAddress, &identity),
            new(Kind::MacAddress, identity.clone()).field("mac_address", "02:00:00:00:00:64").reference(
                "assigned_object",
                Kind::Interface,
                port(host, interface)
            )
        );
    }

    // vmk0 198.18.0.36 mask 255.255.255.0; vmk1 (pg-10) 198.18.1.36 and vmk2 (pg-11) 198.18.1.68, mask
    // 255.255.255.224. No vmkernel interface of this host has an IPv6 address.
    let held: Vec<(String, String)> = of_kind(objects, Kind::IpAddress)
        .into_iter()
        .filter(|address| address.references["assigned_object"].as_ref().unwrap().identity.owner() == host)
        .map(|address| {
            let interface = address.references["assigned_object"].as_ref().unwrap().identity.label().to_owned();
            (interface, text(address, "address"))
        })
        .collect();
    let expected = [("vmk0", "198.18.0.36/24"), ("vmk1", "198.18.1.36/27"), ("vmk2", "198.18.1.68/27")];
    assert_eq!(held, expected.map(|(interface, address)| (interface.to_owned(), address.to_owned())));
    assert_eq!(
        one(objects, Kind::IpAddress, &address("198.18.0.36/24")),
        new(Kind::IpAddress, address("198.18.0.36/24"))
            .field("address", "198.18.0.36/24")
            .reference("assigned_object", Kind::Interface, port(host, "vmk0"))
            .reference("tenant", Kind::Tenant, Identity::named(TENANT))
    );
}

#[tokio::test]
async fn a_host_with_a_route_of_its_own_on_another_interface_keeps_its_management_address_as_primary() {
    let translation = translated(&production()).await;
    // esx01 (host-353): vmk0 (`Management Network`) has no `spec.ipRouteSpec`, vmk1 (pg-11) has one; vmk0
    // comes first and is a management interface by its port group.
    let device = one(&translation.objects, Kind::Device, &Identity::device("esx01.lab.example"));
    assert_eq!(device.references["primary_ip4"], Some(Target::new(Kind::IpAddress, address("198.18.0.35/24"))));
}

// ---------------------------------------------------------------------------
// The virtual machines
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_vm_of_6_7_with_two_cards_object_by_object() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    // vm-82525, `vm133.lab.example`, on host-33564 (`esx02.lab.example`): poweredOn, tools running,
    // `memoryMB` 4096, `numCPU` 4, `instanceUuid` …01ef, an empty note, "prettyName" Debian 12, and the tag
    // `service-haproxy` (rest.tag.12).
    let identity = vm("vm133.lab.example");
    let machine = new(Kind::VirtualMachine, identity.clone())
        .field("name", "vm133.lab.example")
        .field("status", "active")
        .field("memory", 4000)
        .field("vcpus", 4)
        .field("serial", "00000000-0000-4000-8000-0000000001ef")
        .reference("platform", Kind::Platform, Identity::named("Debian GNU/Linux 12 (bookworm)"))
        .tags(["service-haproxy"])
        // Its default route goes through 198.18.2.254: the address of the first card is in that network.
        .reference("primary_ip4", Kind::IpAddress, address("198.18.2.146/24"))
        .only_when_empty("primary_ip4");
    assert_eq!(one(objects, Kind::VirtualMachine, &identity), vm_placed(machine, "esx02.lab.example"));

    // `Network adapter 1`, VirtualVmxnet3, 02:00:00:00:00:33, on pg-8: VLAN 26 of vSwitch0 (`mtu` 1500) on
    // esx02. `Network adapter 2`, 02:00:00:00:00:e1, on pg-12: VLAN 2901 of vSwitch0.
    let cards = [
        (
            "vNIC 1 (pg-8)",
            "Network adapter 1 (VirtualVmxnet3) (vlan ID: 26)",
            26,
            "02:00:00:00:00:33",
            "198.18.2.146/24",
        ),
        (
            "vNIC 2 (pg-12)",
            "Network adapter 2 (VirtualVmxnet3) (vlan ID: 2901)",
            2901,
            "02:00:00:00:00:E1",
            "198.18.12.31/26",
        ),
    ];
    for (name, description, vid, mac, ip) in cards {
        let interface = nic(&identity, name);
        let mac_identity = Identity::mac_address(mac, Some(&Target::new(Kind::VmInterface, interface.clone())));
        let expected = new(Kind::VmInterface, interface.clone())
            .field("name", name)
            .field("enabled", true)
            .field("mtu", 1500)
            .field("mode", "access")
            .field("description", description)
            .reference("virtual_machine", Kind::VirtualMachine, identity.clone())
            .reference("untagged_vlan", Kind::Vlan, vlan(vid))
            .reference("primary_mac_address", Kind::MacAddress, mac_identity.clone());
        assert_eq!(one(objects, Kind::VmInterface, &interface), expected);
        assert_eq!(
            one(objects, Kind::MacAddress, &mac_identity),
            new(Kind::MacAddress, mac_identity.clone()).field("mac_address", mac.to_uppercase()).reference(
                "assigned_object",
                Kind::VmInterface,
                interface.clone()
            )
        );
        // The `fe80::…` address the guest lists next to it is link-local: never synced.
        let held: Vec<&Desired> = of_kind(objects, Kind::IpAddress)
            .into_iter()
            .filter(|address| address.references["assigned_object"].as_ref().unwrap().identity == interface)
            .collect();
        let expected = new(Kind::IpAddress, address(ip))
            .field("address", ip)
            .reference("assigned_object", Kind::VmInterface, interface.clone())
            .reference("tenant", Kind::Tenant, Identity::named(TENANT));
        assert_eq!(held, [&expected]);
    }

    // `Hard disk 1`: `capacityInKB` 26214400 (25 GiB), persistent, thin, `[store1] d466/d466.vmdk`.
    let disk = Identity::virtual_disk(&identity, "Hard disk 1");
    assert_eq!(
        one(objects, Kind::VirtualDisk, &disk),
        new(Kind::VirtualDisk, disk.clone())
            .field("name", "Hard disk 1")
            .field("size", 25000)
            .field("description", "Persistent / ThinProvisioned / [store1] d466/d466.vmdk")
            .reference("virtual_machine", Kind::VirtualMachine, identity.clone())
    );
}

#[tokio::test]
async fn a_stopped_vm_of_6_7_keeps_what_netbox_knows_of_its_addresses() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    // vm-76823, `vm123.lab.example`, on host-33564: poweredOff, guestToolsNotRunning, `memoryMB` 12288,
    // `numCPU` 2, the note "note 4", no `guest.guestFullName` but a "prettyName" left by its tools, no tag.
    let identity = vm("vm123.lab.example");
    let machine = new(Kind::VirtualMachine, identity.clone())
        .field("name", "vm123.lab.example")
        .field("status", "offline")
        .field("memory", 12000)
        .field("vcpus", 2)
        .field("serial", "00000000-0000-4000-8000-0000000001ca")
        .field("comments", "note 4")
        .reference("platform", Kind::Platform, Identity::named("Windows Server 2022, 64-bit"))
        .tags(Vec::<String>::new())
        // Its tools do not run: the addresses NetBox holds for it are unknown, not gone.
        .unknown_dependents([Kind::IpAddress]);
    assert_eq!(one(objects, Kind::VirtualMachine, &identity), vm_placed(machine, "esx02.lab.example"));

    // Its card is known all the same: `Network adapter 1`, VirtualE1000e, 02:00:00:00:00:35, not connected.
    let interface = nic(&identity, "vNIC 1 (pg-8)");
    let card = one(objects, Kind::VmInterface, &interface);
    assert_eq!(card.fields["enabled"], json!(false));
    assert_eq!(card.fields["description"], json!("Network adapter 1 (VirtualE1000e) (vlan ID: 26)"));
    // `Hard disk 1`: `capacityInKB` 104857600 (100 GiB).
    let disk = one(objects, Kind::VirtualDisk, &Identity::virtual_disk(&identity, "Hard disk 1"));
    assert_eq!(disk.fields["size"], json!(100_000));
    let none: Vec<&Desired> = of_kind(objects, Kind::IpAddress)
        .into_iter()
        .filter(|address| {
            address.references["assigned_object"].as_ref().unwrap().identity.owner() == "vm123.lab.example"
        })
        .collect();
    assert_eq!(none, Vec::<&Desired>::new());
}

#[tokio::test]
async fn a_vm_without_default_route_has_no_primary_address() {
    let translation = translated(&production()).await;
    // vm-342, `vm076.lab.example`: its `guest.ipStack` has an empty `ipRouteConfig`.
    let machine = one(&translation.objects, Kind::VirtualMachine, &vm("vm076.lab.example"));
    assert!(!machine.references.contains_key("primary_ip4"));
    // `guest.guestFullName` (Debian 8) wins over `config.guestFullName` (Debian 7); no "prettyName".
    assert_eq!(
        machine.references["platform"],
        Some(Target::new(Kind::Platform, Identity::named("Debian GNU/Linux 8 (64-bit)")))
    );
    assert!(!machine.only_when_empty.contains("platform"));
}

#[tokio::test]
async fn a_disk_with_a_snapshot_is_described_by_the_file_it_started_from() {
    let translation = translated(&production()).await;
    // vm-6519, `vm074.lab.example`: `backing.fileName` is d260.vmdk, `backing.parent.fileName` d262.vmdk;
    // `capacityInKB` 283115520 (270 GiB): 276480 MiB, 270000 in powers of ten.
    let disk =
        one(&translation.objects, Kind::VirtualDisk, &Identity::virtual_disk(&vm("vm074.lab.example"), "Hard disk 1"));
    assert_eq!(disk.fields["description"], json!("Persistent / ThinProvisioned / [store2] d262/d262.vmdk"));
    assert_eq!(disk.fields["size"], json!(270_000));
}

#[tokio::test]
async fn among_homonyms_the_running_then_the_oldest_machine_is_synced() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    // `vm068.lab.example`: vm-5365 is poweredOn (`instanceUuid` …0107), vm-4339 poweredOff.
    let running = one(objects, Kind::VirtualMachine, &vm("vm068.lab.example"));
    assert_eq!(running.fields["serial"], json!("00000000-0000-4000-8000-000000000107"));
    // `vm041.lab.example`: vm-5366 (…0098) and vm-4513 (…0205) are both poweredOn; vCenter lists vm-5366
    // first, which decides nothing: the lower number, the older machine, is the one.
    let oldest = one(objects, Kind::VirtualMachine, &vm("vm041.lab.example"));
    assert_eq!(oldest.fields["serial"], json!("00000000-0000-4000-8000-000000000205"));
    // vm-4513 has one card where vm-5366 has two.
    let cards: Vec<&Desired> = of_kind(objects, Kind::VmInterface)
        .into_iter()
        .filter(|card| card.identity.owner() == "vm041.lab.example")
        .collect();
    assert_eq!(names(&cards), BTreeSet::from(["vNIC 1 (pg-8)".to_owned()]));
}

#[tokio::test]
async fn the_tags_of_6_7() {
    let translation = translated(&production()).await;
    let objects = &translation.objects;
    // `rest.tag.0.json`: `service-rabbit`, empty description, attached to vm-342 (`vm076.lab.example`) alone.
    let machine = one(objects, Kind::VirtualMachine, &vm("vm076.lab.example"));
    assert_eq!(machine.tags, Some(BTreeSet::from(["service-rabbit".to_owned()])));
    // The marker the reconciliation knows a tag made from a source by, in lower case; it is only written
    // to a tag that does not exist yet.
    assert_eq!(
        one(objects, Kind::Tag, &Identity::named("service-rabbit")),
        new(Kind::Tag, Identity::named("service-rabbit"))
            .field("name", "service-rabbit")
            .create_only("slug", "service-rabbit")
            .create_only("description", "netbox-omnisync")
            .ensure_only()
    );
    assert_eq!(TAG_MARKER, "netbox-omnisync");
    // The tags downstream tooling reads are all there.
    let tags = names(&of_kind(objects, Kind::Tag));
    for name in ["check-by-snmp", "check-only-ping", "service-apache", "service-postgres"] {
        assert!(tags.contains(name), "{name}");
    }
    // `service-veeam` (rest.tag.25) is attached to nothing: not a tag of any machine, not declared.
    assert!(!tags.contains("service-veeam"));
}

// ---------------------------------------------------------------------------
// The settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn templates_are_synced_when_asked() {
    let settings = Settings { ignore_templates: false, ..production() };
    let translation = translated(&settings).await;
    // The 8 templates have 8 names nothing else has.
    assert_eq!(of_kind(&translation.objects, Kind::VirtualMachine).len(), 164);
    // vm-132318, `vm002`: `config.template` true, poweredOff.
    let template = one(&translation.objects, Kind::VirtualMachine, &vm("vm002"));
    assert_eq!(template.fields["status"], json!("offline"));
}

#[tokio::test]
async fn only_the_addresses_of_the_permitted_subnets_are_synced() {
    let settings = Settings { permitted_subnets: subnets(["198.18.2.0/24"]), ..production() };
    let translation = translated(&settings).await;
    let objects = &translation.objects;
    // 131 of the 164 addresses of the machines are in 198.18.2.0/24; the hosts are in 198.18.0.0/24 and
    // 198.18.1.0/24.
    assert_eq!(of_kind(objects, Kind::IpAddress).len(), 131);
    // A host whose management address is not synced has no primary address to set.
    assert!(of_kind(objects, Kind::Device).iter().all(|device| !device.references.contains_key("primary_ip4")));
}

#[tokio::test]
async fn the_addresses_of_the_ignored_subnets_are_left_out() {
    let settings = Settings { ignored_subnets: subnets(["198.18.2.0/24"]), ..production() };
    let translation = translated(&settings).await;
    // 164 - 131 addresses of machines, and the 18 of the hosts.
    assert_eq!(of_kind(&translation.objects, Kind::IpAddress).len(), 51);
}

#[tokio::test]
async fn without_permitted_subnets_every_address_but_the_link_local_ones_is_synced() {
    let settings = Settings { permitted_subnets: Vec::new(), ..production() };
    let translation = translated(&settings).await;
    assert_eq!(of_kind(&translation.objects, Kind::IpAddress).len(), 182);
}

#[tokio::test]
async fn the_interface_filter_leaves_interfaces_and_what_they_carry_out() {
    let filter = regex::Regex::new("^(vusb|vmk[12])").unwrap();
    let settings = Settings { interface_filter: Some(filter), ..production() };
    let translation = translated(&settings).await;
    let objects = &translation.objects;
    // vusb0 exists on esx04 alone; vmk1 on the six hosts, vmk2 on five (esx01 has a vmk3 instead).
    assert_eq!(of_kind(objects, Kind::Interface).len(), 43 - 1 - 6 - 5);
    assert_eq!(of_kind(objects, Kind::MacAddress).len(), 201 - 1 - 6 - 5);
    // Each filtered vmkernel interface carried one address.
    assert_eq!(of_kind(objects, Kind::IpAddress).len(), 182 - 6 - 5);
}

#[tokio::test]
async fn without_tenant_and_roles_nothing_is_said_of_them() {
    let translation = translated(&Settings::new(VC, SITE)).await;
    let objects = &translation.objects;
    assert_eq!(of_kind(objects, Kind::Tenant).len(), 0);
    for kind in [Kind::Cluster, Kind::Device, Kind::VirtualMachine, Kind::IpAddress] {
        assert!(of_kind(objects, kind).iter().all(|object| !object.references.contains_key("tenant")), "{kind:?}");
    }
    // A device needs a role: the `Server` of netbox-sync. A machine does not: the one it has is kept.
    let roles = names(&of_kind(objects, Kind::Role));
    assert_eq!(roles, BTreeSet::from(["Server".to_owned()]));
    let device = one(objects, Kind::Device, &Identity::device("esx01.lab.example"));
    assert_eq!(device.references["role"], Some(Target::new(Kind::Role, Identity::named("Server"))));
    assert!(of_kind(objects, Kind::VirtualMachine).iter().all(|vm| !vm.references.contains_key("role")));
}

// ---------------------------------------------------------------------------
// The whole chain against a NetBox
// ---------------------------------------------------------------------------

fn run() -> Run {
    Run {
        sources: vec![SourceFacts {
            name: VC.to_owned(),
            tag: format!("source-{VC}"),
            status: SourceStatus::Succeeded,
            prune: true,
            create_devices: true,
        }],
        priority: vec![VC.to_owned()],
        unique_ip_vrfs: BTreeSet::new(),
        // As the production run: the marker of the tool and the one of netbox-sync.
        source_tag_markers: std::iter::once(TAG_MARKER).chain(LEGACY_TAG_MARKERS).map(str::to_owned).collect(),
    }
}

/// Loads NetBox, compares it with what the vCenter asks for, and writes.
async fn synced(netbox: &FakeGateway, translation: &Translation) -> Plan {
    let kinds: BTreeSet<Kind> = Kind::ALL.into();
    let loaded = load(netbox, &kinds).await.expect("NetBox state");
    assert_eq!(loaded.warnings, Vec::<String>::new());
    let facts = Run { unique_ip_vrfs: loaded.unique_ip_vrfs.clone(), ..run() };
    let mut objects = translation.objects.clone();
    objects.extend(ownership_tags(&facts, &loaded.current));
    let plan = reconcile(&objects, &loaded.current, &facts);
    let applied = apply(netbox, &plan, || ()).await.expect("applied");
    assert_eq!(applied.written, plan.steps.len());
    plan
}

#[tokio::test]
async fn the_6_7_vcenter_is_created_once_and_a_second_run_writes_nothing() {
    let translation = translated(&production()).await;
    let netbox = FakeGateway::new();
    // The custom fields of the hosts are netbox-sync's: they exist in a NetBox it ran on.
    let first = synced(&netbox, &translation).await;
    assert_eq!(first.warnings, Vec::<String>::new());
    let created = first.steps.iter().filter(|step| step.change.action == Action::Create).count();
    // Every object, and the two ownership tags.
    assert_eq!(created, 1099 + 2);
    let second = synced(&netbox, &translation).await;
    assert_eq!(second.changes(), []);
    assert_eq!(second.warnings, Vec::<String>::new());
    assert_eq!(second.orphans_kept, Vec::<String>::new());
}

/// A NetBox as netbox-sync left it for one host and one machine of the
/// fixtures, written by hand from `docs/vmware-reference.md`: every object
/// carries `NetBox-synced` and `Source: vc-a`, as section 3.4 says, except the
/// roles (never tagged) and what was made by hand.
struct Legacy {
    netbox: FakeGateway,
    /// The objects netbox-sync tagged, by a name for the messages.
    owned: Vec<(&'static str, &'static str, u64)>,
    /// The objects it did not tag.
    foreign: Vec<(&'static str, &'static str, u64)>,
    synced_tag: u64,
    source_tag: u64,
    rabbit_tag: u64,
}

fn legacy_netbox() -> Legacy {
    let netbox = FakeGateway::new();
    let synced_tag = netbox.add(
        "extras.tags",
        json!({"name": "NetBox-synced", "slug": "netbox-synced", "description": "Created and used by NetBox Sync \
            Script to keep track of created items. DO NOT change this tag, otherwise syncing can't keep track of \
            deleted objects."}),
    );
    let source_tag = netbox.add(
        "extras.tags",
        json!({"name": "Source: vc-a", "slug": "source-vc-a", "description": "Marks objects synced from vCenter \
            'vc-a' (vcenter.lab.example) to this NetBox Instance."}),
    );
    // A tag netbox-sync made from a vSphere tag, in another letter case than vSphere has it today.
    let rabbit_tag = netbox.add(
        "extras.tags",
        json!({"name": "Service-Rabbit", "slug": "service-rabbit", "description": "NetBox-synced"}),
    );
    let mut owned = Vec::new();
    let mut foreign = Vec::new();
    let tags = json!([synced_tag, source_tag]);
    let mut add = |endpoint: &'static str, what: &'static str, mut fields: Value| {
        fields["tags"] = tags.clone();
        let id = netbox.add(endpoint, fields);
        owned.push((endpoint, what, id));
        id
    };
    let site = add("dcim.sites", "site", json!({"name": SITE, "slug": "harbor"}));
    let tenant = add("tenancy.tenants", "tenant", json!({"name": TENANT, "slug": "example-tenant"}));
    let cluster_type =
        add("virtualization.cluster_types", "cluster type", json!({"name": "VMware ESXi", "slug": "vmware-esxi"}));
    let group = add("virtualization.cluster_groups", "cluster group", json!({"name": "DC1", "slug": "dc1"}));
    let cluster = add(
        "virtualization.clusters",
        "cluster",
        json!({"name": CLUSTER, "type": cluster_type, "group": group, "tenant": tenant,
            "scope_type": "dcim.site", "scope_id": site}),
    );
    let dell = add("dcim.manufacturers", "manufacturer", json!({"name": "Dell", "slug": "dell"}));
    let fc430 = add(
        "dcim.device_types",
        "device type",
        json!({"model": "PowerEdge FC430", "slug": "poweredge-fc430", "manufacturer": dell}),
    );
    let esxi =
        add("dcim.platforms", "host platform", json!({"name": "VMware ESXi 6.7.0", "slug": "vmware-esxi-6-7-0"}));
    let debian = add(
        "dcim.platforms",
        "vm platform",
        json!({"name": "Debian GNU/Linux 8 (64-bit)", "slug": "debian-gnulinux-8-64-bit"}),
    );
    // The VLANs of the port groups of esx04, at the site. VLAN 26 was made by hand, with another name, and
    // only referenced: netbox-sync tagged it all the same (section 3.4).
    let mut vlans = BTreeMap::new();
    for (vid, name) in [
        (3012, "pg-1"),
        (2716, "pg-7"),
        (2715, "pg-6"),
        (2701, "pg-9"),
        (2712, "pg-2"),
        (2800, "ESXi Management Network (ID: 2800) (Harbor)"),
        (2500, "pg-4"),
        (2717, "pg-5"),
        (26, "prod-front"),
        (2703, "pg-11"),
        (2702, "pg-10"),
        (2901, "pg-12"),
    ] {
        vlans.insert(vid, add("ipam.vlans", "vlan", json!({"vid": vid, "name": name, "site": site})));
    }
    let vrf = netbox.add("ipam.vrfs", json!({"name": "prod", "enforce_unique": true}));
    foreign.push(("ipam.vrfs", "vrf", vrf));
    // The roles: created by netbox-sync with a name and a slug, never tagged.
    let host_role = netbox.add("dcim.device_roles", json!({"name": HOST_ROLE, "slug": "hypervisor-esx"}));
    let vm_role = netbox.add("dcim.device_roles", json!({"name": VM_ROLE, "slug": "virtual-machine-esx"}));
    foreign.extend([("dcim.device_roles", "host role", host_role), ("dcim.device_roles", "vm role", vm_role)]);

    // esx04 (host-10), as `a_host_of_6_7_object_by_object` reads it in the fixtures.
    let device = add(
        "dcim.devices",
        "device",
        json!({"name": "esx04.lab.example", "device_type": fc430, "role": host_role, "site": site,
            "cluster": cluster, "tenant": tenant, "platform": esxi, "status": "active", "serial": "ID00016",
            "custom_fields": {"host_cpu_cores": "28 Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
                "host_memory": "256 GB", "rack_note": "set by hand"}}),
    );
    let tagged: Vec<u64> =
        [3012, 2716, 2715, 2701, 2712, 2800, 2500, 2717, 26, 2703, 2702, 2901].iter().map(|vid| vlans[vid]).collect();
    // The description carries the switch port netbox-sync read with `QueryNetworkHint`.
    let vmnic0 = add(
        "dcim.interfaces",
        "vmnic0",
        json!({"device": device, "name": "vmnic0", "type": "10gbase-x-sfpp", "enabled": true, "speed": 10_000_000,
            "duplex": "full", "mtu": 1500, "mode": "tagged", "tagged_vlans": tagged,
            "description": "10Gb/s  pNIC (vSwitch0) (conn: sw01.lab.example - Ethernet1/7)"}),
    );
    let vusb0 = add(
        "dcim.interfaces",
        "vusb0",
        json!({"device": device, "name": "vusb0", "type": "100base-tx", "enabled": true, "speed": 100_000,
            "duplex": "full", "description": "100Mb/s  pNIC"}),
    );
    let vmk0 = add(
        "dcim.interfaces",
        "vmk0",
        json!({"device": device, "name": "vmk0", "type": "virtual", "enabled": true, "mtu": 1500, "mode": "access",
            "untagged_vlan": vlans[&2800], "description": "Management Network (vSwitch0, vlan ID: 2800)"}),
    );
    for (interface, what, mac) in [
        (vmnic0, "mac of vmnic0", "02:00:00:00:00:64"),
        (vusb0, "mac of vusb0", "02:00:00:00:00:66"),
        (vmk0, "mac of vmk0", "02:00:00:00:00:64"),
    ] {
        let mac = add(
            "dcim.mac_addresses",
            what,
            json!({"mac_address": mac, "assigned_object_type": "dcim.interface", "assigned_object_id": interface}),
        );
        netbox.set("dcim.interfaces", interface, "primary_mac_address", json!(mac));
    }
    // The address of vmk0: in the VRF of its prefix, with the name of a reverse lookup.
    let management = add(
        "ipam.ip_addresses",
        "ip of vmk0",
        json!({"address": "198.18.0.36/24", "assigned_object_type": "dcim.interface", "assigned_object_id": vmk0,
            "tenant": tenant, "vrf": vrf, "status": "active", "dns_name": "esx04.lab.example"}),
    );
    netbox.set("dcim.devices", device, "primary_ip4", json!(management));

    // vm076 (vm-342, on esx04): poweredOn, 2048 MB, 2 CPU, `instanceUuid` …0121, `guest.guestFullName`
    // Debian 8, the tag `service-rabbit`; `Network adapter 1` (VirtualVmxnet3, 02:00:00:00:00:72) on pg-8
    // with 198.18.2.160/24; `Hard disk 1` of 33554432 KB (32 GiB), `[store2] d270/d270.vmdk`.
    let machine = add(
        "virtualization.virtual_machines",
        "vm",
        json!({"name": "vm076.lab.example", "cluster": cluster, "site": site, "device": device, "tenant": tenant,
            "role": vm_role, "platform": debian, "status": "active", "memory": 2000, "vcpus": "2.00",
            "serial": "00000000-0000-4000-8000-000000000121", "comments": "kept by hand"}),
    );
    netbox.set("virtualization.virtual_machines", machine, "tags", json!([synced_tag, source_tag, rabbit_tag]));
    let card = add(
        "virtualization.interfaces",
        "vNIC 1",
        json!({"virtual_machine": machine, "name": "vNIC 1 (pg-8)", "enabled": true, "mtu": 1500, "mode": "access",
            "untagged_vlan": vlans[&26], "description": "Network adapter 1 (VirtualVmxnet3) (vlan ID: 26)"}),
    );
    let mac = add(
        "dcim.mac_addresses",
        "mac of vNIC 1",
        json!({"mac_address": "02:00:00:00:00:72", "assigned_object_type": "virtualization.vminterface",
            "assigned_object_id": card}),
    );
    netbox.set("virtualization.interfaces", card, "primary_mac_address", json!(mac));
    add(
        "ipam.ip_addresses",
        "ip of vNIC 1",
        json!({"address": "198.18.2.160/24", "assigned_object_type": "virtualization.vminterface",
            "assigned_object_id": card, "tenant": tenant, "status": "active"}),
    );
    add(
        "virtualization.virtual_disks",
        "disk",
        json!({"virtual_machine": machine, "name": "Hard disk 1", "size": 32000,
            "description": "Persistent / ThinProvisioned / [store2] d270/d270.vmdk"}),
    );
    Legacy { netbox, owned, foreign, synced_tag, source_tag, rabbit_tag }
}

#[tokio::test]
async fn the_first_run_on_what_netbox_sync_left_changes_nothing_but_ownership_tags() {
    let translation = translated(&production()).await;
    let legacy = legacy_netbox();
    let plan = synced(&legacy.netbox, &translation).await;
    let tool_tag = legacy.netbox.find("extras.tags", "name", &json!("netbox-omnisync")).expect("the tag of the tool");

    let touching = |endpoint: &str, id: u64| {
        let touched = |step: &&omnisync_core::inventory::reconcile::Step| {
            step.kind.endpoint() == endpoint && step.change.id == Some(id)
        };
        plan.steps.iter().filter(touched).collect::<Vec<_>>()
    };
    // Each object netbox-sync tagged changes once, and only its tags: `NetBox-synced` goes, the tag of the
    // tool comes, the tag of the source stays under the name it has.
    for (endpoint, what, id) in &legacy.owned {
        let steps = touching(endpoint, *id);
        assert_eq!(steps.len(), 1, "{what}: {:?}", steps.iter().map(|step| &step.change).collect::<Vec<_>>());
        let change = &steps[0].change;
        assert_eq!(change.action, Action::Update, "{what}");
        let fields: Vec<&str> = change.fields.keys().map(String::as_str).collect();
        assert_eq!(fields, ["tags"], "{what}: {:?} -> {:?}", change.before, change.fields);
        let held = legacy.netbox.row(endpoint, *id).unwrap()["tags"].clone();
        let expected = if *what == "vm" {
            json!([tool_tag, legacy.source_tag, legacy.rabbit_tag])
        } else {
            json!([tool_tag, legacy.source_tag])
        };
        let sorted = |tags: &Value| {
            let mut ids: Vec<u64> = tags.as_array().unwrap().iter().map(|tag| tag.as_u64().unwrap()).collect();
            ids.sort_unstable();
            ids
        };
        assert_eq!(sorted(&held), sorted(&expected), "{what}");
    }
    // What it did not tag is not touched at all: the roles, the VRF, and the three tags.
    for (endpoint, what, id) in &legacy.foreign {
        assert_eq!(touching(endpoint, *id).len(), 0, "{what}");
    }
    for tag in [legacy.synced_tag, legacy.source_tag, legacy.rabbit_tag] {
        assert_eq!(touching("extras.tags", tag).len(), 0);
    }
    // Nothing is deleted, and nothing that was there is created again.
    assert!(plan.steps.iter().all(|step| step.change.action != Action::Delete));
    let created = |kind: Kind, label: &str| {
        plan.steps
            .iter()
            .any(|step| step.kind == kind && step.change.action == Action::Create && step.change.key == label)
    };
    assert!(!created(Kind::Device, "esx04.lab.example"));
    assert!(!created(Kind::VirtualMachine, "vm076.lab.example"));
    assert!(!created(Kind::Tag, "service-rabbit"));
    assert!(!created(Kind::Vlan, "26"));
    // The rest of the vCenter, which this NetBox did not hold, is.
    assert!(created(Kind::Device, "esx01.lab.example"));
}

/// What a reverse lookup gave, by address.
fn resolved<const N: usize>(names: [(&str, &str); N]) -> BTreeMap<IpAddr, String> {
    names.into_iter().map(|(address, name)| (address.parse().unwrap(), name.to_owned())).collect()
}

async fn named(resolver: &dyn ReverseDns) -> Translation {
    desired(&inventory().await, &production(), resolver).expect("translation")
}

#[tokio::test]
async fn the_addresses_of_6_7_get_the_names_a_reverse_lookup_gives() {
    // What is asked: the addresses that are synced, all within the permitted 198.18.0.0/15, and never the
    // `fe80::…` ones of the `guest.net` cards.
    let asked = Asked::default();
    named(&asked).await;
    let asked = asked.into_addresses();
    let permitted: ipnet::IpNet = "198.18.0.0/15".parse().unwrap();
    assert!(asked.contains(&"198.18.0.36".parse::<IpAddr>().unwrap()));
    assert_eq!(asked.iter().filter(|address| !permitted.contains(*address)).count(), 0);

    // vmk0 of host-10: `spec.ip.ipAddress` 198.18.0.36, mask 255.255.255.0.
    let translation = named(&resolved([("198.18.0.36", "ESX04.Lab.Example.")])).await;
    // The two warnings of the fixture are about homonyms; none is about a name.
    assert_eq!(translation.warnings.iter().filter(|warning| warning.contains("DNS")).count(), 0);
    assert_eq!(
        one(&translation.objects, Kind::IpAddress, &address("198.18.0.36/24")),
        new(Kind::IpAddress, address("198.18.0.36/24"))
            .field("address", "198.18.0.36/24")
            .field("dns_name", "esx04.lab.example")
            .reference("assigned_object", Kind::Interface, port("esx04.lab.example", "vmk0"))
            .reference("tenant", Kind::Tenant, Identity::named(TENANT))
    );
    // The lookup knows no other name: the 181 other addresses report none.
    let addresses = of_kind(&translation.objects, Kind::IpAddress);
    let unnamed = addresses.iter().filter(|address| !address.fields.contains_key("dns_name")).count();
    assert_eq!((addresses.len(), unnamed), (182, 181));
}

#[tokio::test]
async fn a_lookup_that_gives_no_name_never_clears_the_one_netbox_holds() {
    // The NetBox netbox-sync left holds "dns_name": "esx04.lab.example" for 198.18.0.36/24.
    let legacy = legacy_netbox();
    let id = legacy.netbox.find("ipam.ip_addresses", "address", &json!("198.18.0.36/24")).expect("the address");
    let held = || legacy.netbox.row("ipam.ip_addresses", id).unwrap()["dns_name"].clone();
    let touching_the_name =
        |plan: &Plan| plan.steps.iter().filter(|step| step.change.fields.contains_key("dns_name")).count();
    // No record, a failed lookup or a timeout (all of them a `None`), an empty name, a name NetBox would refuse.
    for unknown in [resolved([]), resolved([("198.18.0.36", ".")]), resolved([("198.18.0.36", "esx 04.lab.example.")])]
    {
        let plan = synced(&legacy.netbox, &named(&unknown).await).await;
        assert_eq!(touching_the_name(&plan), 0, "{unknown:?}");
        assert_eq!(held(), json!("esx04.lab.example"), "{unknown:?}");
    }
    // Only an answer writes.
    let renamed = resolved([("198.18.0.36", "esx04.infra.example.")]);
    let plan = synced(&legacy.netbox, &named(&renamed).await).await;
    assert_eq!(touching_the_name(&plan), 1);
    assert_eq!(held(), json!("esx04.infra.example"));
    // And the record lost afterwards leaves the name where it is.
    synced(&legacy.netbox, &named(&resolved([])).await).await;
    assert_eq!(held(), json!("esx04.infra.example"));
}

#[tokio::test]
async fn a_second_run_with_the_same_names_writes_nothing() {
    let names = resolved([("198.18.0.36", "ESX04.Lab.Example."), ("198.18.2.160", "vm076.lab.example.")]);
    let translation = named(&names).await;
    let netbox = FakeGateway::new();
    synced(&netbox, &translation).await;
    let id = netbox.find("ipam.ip_addresses", "address", &json!("198.18.2.160/24")).expect("the address of vm076");
    assert_eq!(netbox.row("ipam.ip_addresses", id).unwrap()["dns_name"], json!("vm076.lab.example"));
    let second = synced(&netbox, &named(&names).await).await;
    assert_eq!(second.changes(), []);
}

#[tokio::test]
async fn the_switch_port_of_each_card_is_reported_under_the_name_of_its_host() {
    let server = vcenter("6.7").await;
    let inventory = collect_with(&client(&server), &Wanted { hints: true }).await.expect("inventory");
    let translation = desired(&inventory, &production(), &NoReverseDns).expect("translation");
    let heard = |host: &str, card: &str, switch: &str, port: &str| Heard {
        host: host.to_owned(),
        card: card.to_owned(),
        switch: switch.to_owned(),
        port: port.to_owned(),
    };
    // host-10 is esx04.lab.example; QueryNetworkHint.networkSystem-10.xml: vmnic0 and vusb0 hear
    // nothing, <device>vmnic1</device> hears <devId>nexus04.lab.example(FOC0000A0A4)</devId>
    // <portId>Ethernet1/40</portId>.
    let of_esx04: Vec<&Heard> = translation.heard.iter().filter(|heard| heard.host == "esx04.lab.example").collect();
    assert_eq!(of_esx04, [&heard("esx04.lab.example", "vmnic1", "nexus04.lab.example(FOC0000A0A4)", "Ethernet1/40")]);
    // host-353 is esx01.lab.example; QueryNetworkHint.networkSystem-353.xml: six cards, each heard.
    let of_esx01: Vec<&Heard> = translation.heard.iter().filter(|heard| heard.host == "esx01.lab.example").collect();
    assert_eq!(
        of_esx01,
        [
            &heard("esx01.lab.example", "vmnic0", "stack01.lab.switch.example.com", "GigabitEthernet1/0/14"),
            &heard("esx01.lab.example", "vmnic1", "stack01.lab.switch.example.com", "GigabitEthernet2/0/14"),
            &heard("esx01.lab.example", "vmnic2", "stack01.lab.switch.example.com", "GigabitEthernet1/0/13"),
            &heard("esx01.lab.example", "vmnic3", "stack01.lab.switch.example.com", "GigabitEthernet2/0/13"),
            &heard("esx01.lab.example", "vmnic4", "nexus01.lab.example(FOC0000A0A1)", "Ethernet1/3"),
            &heard("esx01.lab.example", "vmnic5", "nexus02.lab.example(FOC0000A0A2)", "Ethernet1/3"),
        ]
    );
    // Six hosts: 1 + 6 + 4 + 4 + 4 + 4 cards that hear a switch.
    assert_eq!(translation.heard.len(), 23);
    // Without the hints, nothing is heard.
    assert!(translated(&production()).await.heard.is_empty());
}
