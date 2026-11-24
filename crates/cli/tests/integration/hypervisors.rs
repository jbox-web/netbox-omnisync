//! The hypervisor chain against a real NetBox: a scripted Proxmox cluster goes
//! through the real translation, the reconciliation and the real client.
//!
//! The expected values are those of the scenario, written by hand.

use std::collections::BTreeSet;

use omnisync_cli::config::{Bmc, Credentials, Hypervisor, HypervisorType};
use omnisync_cli::dns::ReverseLookups;
use omnisync_cli::hypervisors::{Reader, Reading, read_redfish_at, read_vmware_at, run};
use omnisync_core::inventory::model::{Desired, Identity, Kind, Target};
use omnisync_core::network::inventory::{Secret, Wanted};
use omnisync_core::progress::NullProgress;
use omnisync_core::{Action, Change, Gateway, Outcome};
use omnisync_netbox::inventory_apply::DryRun;
use omnisync_proxmox::{
    Container, ContainerInterface, Disk, DiskBus, GuestAddress, GuestInterface, GuestNic, GuestNics, GuestOsInfo,
    NoReverseDns, Node, NodeNetwork, NodeVlan, ProxmoxCluster, ProxmoxVersion, Settings, Vm, desired,
};
use serde_json::{Value, json};

use crate::support::{Netbox, tag_slugs, text};
use crate::{fake_bmc, fake_vcenter};

const SITE: &str = "Paris";
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

fn hypervisor(name: &str) -> Hypervisor {
    Hypervisor {
        name: name.to_owned(),
        r#type: HypervisorType::Proxmox,
        host: "192.0.2.10".to_owned(),
        port: None,
        validate_certs: true,
        ca_file: None,
        site: Some(SITE.to_owned()),
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
            password: Secret::new("unused"),
        }),
        neighbors: false,
        ssh: None,
    }
}

/// A source that answers with a cluster built by the test, translated as the
/// real reader translates what it collected.
struct Script(ProxmoxCluster);

impl Reader for Script {
    async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
        let translation = desired(&self.0, &Settings::new(&source.name, SITE), &NoReverseDns);
        Ok(Reading { objects: translation.objects, warnings: translation.warnings, ..Reading::default() })
    }
}

fn network(name: &str, kind: &str, active: bool, bond_members: &[&str]) -> NodeNetwork {
    NodeNetwork {
        name: name.to_owned(),
        kind: kind.to_owned(),
        active,
        bond_members: bond_members.iter().map(|member| (*member).to_owned()).collect(),
        vlan: None,
    }
}

/// `web01`: a running VM whose agent answers.
fn web01(addresses: &[(&str, &str, u8)]) -> Vm {
    Vm {
        vmid: 101,
        name: "web01".to_owned(),
        status: "running".to_owned(),
        template: false,
        cpus: 2,
        max_memory_bytes: 2 * GIB,
        tags: Vec::new(),
        os_type: Some("l26".to_owned()),
        disks: vec![Disk {
            bus: DiskBus::Scsi,
            index: 0,
            name: "local-lvm:vm-101-disk-0".to_owned(),
            size_mib: 10240,
            cdrom: false,
        }],
        nics: GuestNics::default(),
        interfaces: Some(vec![GuestInterface {
            name: "eth0".to_owned(),
            mac: Some("bc:24:11:aa:bb:01".to_owned()),
            addresses: addresses
                .iter()
                .map(|(address, family, prefix)| GuestAddress {
                    address: (*address).to_owned(),
                    family: (*family).to_owned(),
                    prefix: *prefix,
                })
                .collect(),
        }]),
        os_info: Some(GuestOsInfo {
            pretty_name: Some("Debian GNU/Linux 12 (bookworm)".to_owned()),
            ..GuestOsInfo::default()
        }),
    }
}

/// `db01`: a stopped VM, whose interfaces and system are unknown.
fn db01() -> Vm {
    Vm {
        vmid: 102,
        name: "db01".to_owned(),
        status: "stopped".to_owned(),
        template: false,
        cpus: 4,
        max_memory_bytes: 8 * GIB,
        tags: Vec::new(),
        os_type: Some("win11".to_owned()),
        disks: vec![Disk {
            bus: DiskBus::Virtio,
            index: 0,
            name: "local-lvm:vm-102-disk-0".to_owned(),
            size_mib: 51200,
            cdrom: false,
        }],
        nics: GuestNics::default(),
        interfaces: None,
        os_info: None,
    }
}

/// `dns01`: a running container.
fn dns01() -> Container {
    Container {
        vmid: 200,
        name: "dns01".to_owned(),
        status: "running".to_owned(),
        cpus: 1,
        max_memory_bytes: 512 * MIB,
        max_disk_bytes: 8 * GIB,
        tags: Vec::new(),
        interfaces: Some(vec![ContainerInterface {
            name: "eth0".to_owned(),
            mac: Some("BC:24:11:AA:BB:53".to_owned()),
            inet: Some("192.0.2.53/24".to_owned()),
            inet6: None,
        }]),
        nics: Some(GuestNics::default()),
    }
}

fn cluster(networks: Vec<NodeNetwork>, vms: Vec<Vm>, containers: Vec<Container>) -> ProxmoxCluster {
    ProxmoxCluster {
        version: ProxmoxVersion { version: "8.4.21".to_owned(), release: "8.4".to_owned() },
        name: "lab".to_owned(),
        nodes: vec![Node {
            name: "pve01".to_owned(),
            cpus: 16,
            memory_total_bytes: 64 * GIB,
            networks,
            vms,
            containers,
        }],
        offline: Vec::new(),
    }
}

/// Each source answers with its own cluster, translated as the real reader
/// translates what it collected: at the site of the source, its VLANs in the
/// VLAN group of that site when it has one.
struct Scripts(Vec<(&'static str, ProxmoxCluster)>);

impl Reader for Scripts {
    async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
        let (_, cluster) = self.0.iter().find(|(name, _)| *name == source.name).expect("a scripted source");
        let site = source.site.as_deref().expect("a site");
        let settings = Settings { vlan_group: source.vlan_group.clone(), ..Settings::new(&source.name, site) };
        let translation = desired(cluster, &settings, &NoReverseDns);
        Ok(Reading { objects: translation.objects, warnings: translation.warnings, ..Reading::default() })
    }
}

/// A cluster of one node, with a bond that carries the VLAN 25 on a
/// sub-interface, and one running VM whose two cards are an access port of
/// the VLAN 10 (`tag=10`) and a trunk of the VLANs 20 and 21 (`trunks=20;21`).
fn room(cluster_name: &str, node: &str, vm: &str, mac: u8) -> ProxmoxCluster {
    let card = |key: &str, last: u8, tag: Option<u16>, trunks: &[(u16, u16)]| GuestNic {
        key: key.to_owned(),
        mac: format!("BC:24:11:00:{mac:02X}:{last:02X}"),
        bridge: Some("vmbr0".to_owned()),
        tag,
        trunks: trunks.to_vec(),
    };
    let interface = |name: &str, last: u8| GuestInterface {
        name: name.to_owned(),
        mac: Some(format!("bc:24:11:00:{mac:02x}:{last:02x}")),
        addresses: Vec::new(),
    };
    let guest = Vm {
        name: vm.to_owned(),
        nics: GuestNics {
            read: vec![card("net0", 1, Some(10), &[]), card("net1", 2, None, &[(20, 21)])],
            unread: Vec::new(),
        },
        interfaces: Some(vec![interface("eth0", 1), interface("eth1", 2)]),
        ..web01(&[])
    };
    let storage = NodeNetwork {
        vlan: Some(NodeVlan { id: 25, raw_device: Some("bond0".to_owned()) }),
        ..network("bond0.25", "vlan", true, &[])
    };
    ProxmoxCluster {
        version: ProxmoxVersion { version: "9.2.11".to_owned(), release: "9.2".to_owned() },
        name: cluster_name.to_owned(),
        nodes: vec![Node {
            name: node.to_owned(),
            cpus: 16,
            memory_total_bytes: 64 * GIB,
            networks: vec![network("bond0", "bond", true, &[]), storage],
            vms: vec![guest],
            containers: Vec::new(),
        }],
        offline: Vec::new(),
    }
}

/// (number, name of the site, name of the group) of every VLAN, sorted.
async fn vlans(netbox: &Netbox) -> Vec<(u64, String, String)> {
    let mut vlans: Vec<(u64, String, String)> = netbox
        .list("ipam.vlans", [])
        .await
        .iter()
        .map(|vlan| {
            let name = |field: &str| vlan[field]["name"].as_str().unwrap_or_default().to_owned();
            (vlan["vid"].as_u64().expect("a vid"), name("site"), name("group"))
        })
        .collect();
    vlans.sort();
    vlans
}

/// Two rooms of one LAN: two sites, each with its Proxmox cluster, that carry
/// the same VLANs. Each first keeps its own; once the configuration puts both
/// in the VLAN group `East`, the interfaces of both sites are on the VLANs of
/// the group, which NetBox takes on a device and on a virtual machine of
/// either site because they have no site, and the VLANs of the sites, which
/// the sources owned, are deleted. A second run has nothing to write.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn two_sites_that_share_a_vlan_group_keep_their_vlans_in_it() {
    let netbox = Netbox::empty().await;
    let reader = Scripts(vec![
        ("pve-ul", room("ul", "pve-ul01", "web-ul", 0x0A)),
        ("pve-bs", room("bs", "pve-bs01", "web-bs", 0x0B)),
    ]);
    let at = |name: &str, site: &str, group: Option<&str>| Hypervisor {
        site: Some(site.to_owned()),
        vlan_group: group.map(str::to_owned),
        ..hypervisor(name)
    };
    let alone = [at("pve-ul", "Ulis", None), at("pve-bs", "Bessieres", None)];
    let selected: Vec<&Hypervisor> = alone.iter().collect();
    let first = run(&alone, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    clean(&first);
    let per_site = |site: &str| [10, 20, 21, 25].map(|vid| (vid, site.to_owned(), String::new()));
    let mut expected: Vec<(u64, String, String)> = per_site("Bessieres").into_iter().chain(per_site("Ulis")).collect();
    expected.sort();
    assert_eq!(vlans(&netbox).await, expected);

    // The group is a prerequisite: created by hand, as its two sites join it.
    netbox.create("ipam.vlan_groups", json!({"name": "East", "slug": "east"})).await;
    let grouped = [at("pve-ul", "Ulis", Some("East")), at("pve-bs", "Bessieres", Some("East"))];
    let selected: Vec<&Hypervisor> = grouped.iter().collect();
    let second = run(&grouped, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    clean(&second);
    // One VLAN of each number, in the group and at no site; the eight VLANs of the sites are gone.
    let in_group = [10, 20, 21, 25].map(|vid| (vid, String::new(), "East".to_owned()));
    assert_eq!(vlans(&netbox).await, in_group);
    assert_eq!(
        changed(&second, Action::Delete),
        ["10", "10", "20", "20", "21", "21", "25", "25"].map(|vid| ("vlan", vid))
    );
    let mut ids = Vec::new();
    for vid in ["10", "20", "21", "25"] {
        ids.push(netbox.one("ipam.vlans", [("vid", vid)]).await["id"].as_u64().expect("an id"));
    }
    let (access, storage) = (ids[0], ids[3]);
    let trunked = BTreeSet::from([ids[1], ids[2]]);
    for (vm, node) in [("web-ul", "pve-ul01"), ("web-bs", "pve-bs01")] {
        // An interface of a virtual machine of each site: untagged, then tagged.
        let machine = netbox.one("virtualization.virtual_machines", [("name", vm)]).await;
        let machine_id = machine["id"].as_u64().expect("an id").to_string();
        let port = |name: &'static str| {
            netbox.one("virtualization.interfaces", [("virtual_machine_id", &machine_id), ("name", name)])
        };
        let eth0 = port("eth0").await;
        assert_eq!(
            (text(&eth0, "/mode/value"), eth0["untagged_vlan"]["id"].as_u64()),
            ("access", Some(access)),
            "{vm}"
        );
        let eth1 = port("eth1").await;
        let tagged: BTreeSet<u64> = eth1["tagged_vlans"]
            .as_array()
            .expect("tagged VLANs")
            .iter()
            .filter_map(|vlan| vlan["id"].as_u64())
            .collect();
        assert_eq!((text(&eth1, "/mode/value"), &tagged), ("tagged", &trunked), "{vm}");
        // An interface of a device of each site, under the bond that carries it.
        let device = netbox.one("dcim.devices", [("name", node)]).await;
        let device_id = device["id"].as_u64().expect("an id").to_string();
        let sub = netbox.one("dcim.interfaces", [("device_id", &device_id), ("name", "bond0.25")]).await;
        assert_eq!(
            (sub["untagged_vlan"]["id"].as_u64(), text(&sub, "/parent/name")),
            (Some(storage), "bond0"),
            "{node}"
        );
    }

    let third = run(&grouped, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    unchanged(&third);
}

/// The recorded vCenter at a site that keeps its VLANs in a VLAN group: the
/// VLANs of its port groups are created in the group, at no site, once.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_recorded_vcenter_whose_site_is_in_a_vlan_group_keeps_its_vlans_in_it() {
    let netbox = Netbox::empty().await;
    netbox.create("ipam.vlan_groups", json!({"name": "East", "slug": "east"})).await;
    let server = fake_vcenter::vcenter("6.7").await;
    let source = Hypervisor {
        r#type: HypervisorType::Vmware,
        host: "127.0.0.1".to_owned(),
        port: Some(server.address().port()),
        validate_certs: false,
        site: Some("Harbor".to_owned()),
        vlan_group: Some("East".to_owned()),
        permitted_subnets: vec!["198.18.0.0/15".parse().expect("a network")],
        ..hypervisor("vc01.lab01")
    };
    let reader = OverHttp { vcenter: server.uri(), bmcs: Vec::new(), lookups: ReverseLookups::system() };
    let sources = [source];
    let selected: Vec<&Hypervisor> = sources.iter().collect();
    let first = run(&sources, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    assert_eq!(first.errors, Vec::<String>::new());
    assert_eq!(first.applied, first.changes.len());
    let held = vlans(&netbox).await;
    assert!(!held.is_empty(), "the port groups of the recorded vCenter carry VLANs");
    assert!(held.iter().all(|(_, site, group)| site.is_empty() && group == "East"), "{held:?}");
    let second = run(&sources, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    assert_eq!((second.errors, second.changes), (Vec::<String>::new(), Vec::<Change>::new()));
}

/// The cluster `lab`: one node with a bond under a bridge, two VMs (one
/// tagged, with an interface, a MAC, two addresses and a disk; one stopped)
/// and a container.
fn lab(with_container: bool) -> ProxmoxCluster {
    let networks = vec![
        network("bond0", "bond", true, &["eno1", "eno2"]),
        network("eno1", "eth", true, &[]),
        network("eno2", "eth", false, &[]),
        network("vmbr0", "bridge", true, &[]),
    ];
    let mut web01 = web01(&[("192.0.2.10", "ipv4", 24), ("2001:db8::10", "ipv6", 64)]);
    web01.tags = vec!["prod".to_owned(), "web".to_owned()];
    let containers = if with_container { vec![dns01()] } else { Vec::new() };
    cluster(networks, vec![web01, db01()], containers)
}

async fn sync<G: Gateway + DryRun>(source: &str, gateway: &G, cluster: ProxmoxCluster) -> Outcome {
    sync_reading(source, gateway, &Script(cluster)).await
}

async fn sync_reading<G: Gateway + DryRun, R: Reader>(source: &str, gateway: &G, reader: &R) -> Outcome {
    let sources = [hypervisor(source)];
    let selected: Vec<&Hypervisor> = sources.iter().collect();
    run(&sources, &selected, &[], gateway, reader, &NullProgress).await
}

/// The outcome of a run that wrote everything it planned, without a remark.
fn clean(outcome: &Outcome) {
    assert_eq!(outcome.errors, Vec::<String>::new());
    assert_eq!(outcome.warnings, Vec::<String>::new());
    assert_eq!(outcome.applied, outcome.changes.len());
}

/// The outcome of a run that found nothing to do.
fn unchanged(outcome: &Outcome) {
    assert_eq!(outcome.changes, Vec::<Change>::new());
    assert_eq!((outcome.errors.as_slice(), outcome.applied), ([].as_slice(), 0));
}

/// Kind and key of the changes of one action, sorted.
fn changed(outcome: &Outcome, action: Action) -> Vec<(&str, &str)> {
    let of_action = outcome.changes.iter().filter(|change| change.action == action);
    let mut changed: Vec<(&str, &str)> = of_action.map(|change| (change.kind.as_str(), change.key.as_str())).collect();
    changed.sort_unstable();
    changed
}

const OWNED_BY_PVE_LAB: [&str; 2] = ["netbox-omnisync", "source-pve-lab"];

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_first_run_creates_the_objects_of_the_source() {
    let netbox = Netbox::empty().await;
    let first = sync("pve-lab", &netbox.client, lab(true)).await;
    clean(&first);
    assert_eq!(changed(&first, Action::Delete), []);

    let site = netbox.one("dcim.sites", [("name", SITE)]).await;
    assert_eq!(text(&site, "/slug"), "paris");
    let cluster_type = netbox.one("virtualization.cluster_types", [("name", "Proxmox")]).await;
    assert_eq!(
        (text(&cluster_type, "/slug"), tag_slugs(&cluster_type)),
        ("proxmox", OWNED_BY_PVE_LAB.map(String::from).to_vec())
    );
    let cluster = netbox.one("virtualization.clusters", [("name", "lab")]).await;
    assert_eq!(
        (text(&cluster, "/type/name"), text(&cluster, "/scope_type"), text(&cluster, "/scope/name")),
        ("Proxmox", "dcim.site", SITE)
    );
    assert_eq!(text(&cluster, "/custom_fields/source"), "pve-lab");
    assert_eq!(tag_slugs(&cluster), OWNED_BY_PVE_LAB);

    // The host, on the generic hardware Proxmox cannot tell.
    let host = netbox.one("dcim.devices", [("name", "pve01")]).await;
    assert_eq!(
        (
            text(&host, "/role/name"),
            text(&host, "/device_type/model"),
            text(&host, "/device_type/manufacturer/name"),
            text(&host, "/site/name"),
            text(&host, "/cluster/name"),
        ),
        ("Server", "Generic Model", "Generic Manufacturer", SITE, "lab")
    );
    assert_eq!(
        host["custom_fields"],
        json!({"source": "pve-lab", "source_id": null, "host_cpu_cores": "16", "host_memory": "64 GiB"})
    );
    assert_eq!(tag_slugs(&host), OWNED_BY_PVE_LAB);
    let host_id = host["id"].to_string();
    assert_eq!(netbox.names("dcim.interfaces", [("device_id", &host_id)]).await, ["bond0", "eno1", "eno2", "vmbr0"]);
    let port = |name: &'static str| netbox.one("dcim.interfaces", [("device_id", &host_id), ("name", name)]);
    let (bond, eno1, eno2, bridge) = (port("bond0").await, port("eno1").await, port("eno2").await, port("vmbr0").await);
    assert_eq!((text(&bond, "/type/value"), text(&bridge, "/type/value")), ("lag", "bridge"));
    assert_eq!(
        (text(&eno1, "/type/value"), text(&eno1, "/lag/name"), &eno1["enabled"]),
        ("other", "bond0", &json!(true))
    );
    assert_eq!((text(&eno2, "/lag/name"), &eno2["enabled"]), ("bond0", &json!(false)));

    // The running VM: what Proxmox configures, and what its agent reports.
    let web = netbox.one("virtualization.virtual_machines", [("name", "web01")]).await;
    assert_eq!(
        (
            text(&web, "/status/value"),
            web["vcpus"].as_f64(),
            web["memory"].as_u64(),
            text(&web, "/cluster/name"),
            text(&web, "/device/name"),
            text(&web, "/site/name"),
            text(&web, "/role/name"),
            text(&web, "/platform/name"),
        ),
        ("active", Some(2.0), Some(2048), "lab", "pve01", SITE, "VM", "Debian GNU/Linux 12 (bookworm)")
    );
    assert_eq!(web["custom_fields"], json!({"source": "pve-lab", "source_id": "101"}));
    assert_eq!(tag_slugs(&web), ["netbox-omnisync", "prod", "source-pve-lab", "web"]);
    assert_eq!(
        (text(&web, "/primary_ip4/address"), text(&web, "/primary_ip6/address")),
        ("192.0.2.10/24", "2001:db8::10/64")
    );
    let web_id = web["id"].to_string();
    let eth0 = netbox.one("virtualization.interfaces", [("virtual_machine_id", &web_id)]).await;
    assert_eq!((text(&eth0, "/name"), text(&eth0, "/primary_mac_address/mac_address")), ("eth0", "BC:24:11:AA:BB:01"));
    let mac = netbox.one("dcim.mac_addresses", [("mac_address", "BC:24:11:AA:BB:01")]).await;
    assert_eq!(
        (text(&mac, "/assigned_object_type"), mac["assigned_object_id"].as_u64()),
        ("virtualization.vminterface", eth0["id"].as_u64())
    );
    let ip = netbox.one("ipam.ip_addresses", [("address", "192.0.2.10")]).await;
    assert_eq!(
        (text(&ip, "/address"), text(&ip, "/status/value"), ip["assigned_object_id"].as_u64()),
        ("192.0.2.10/24", "active", eth0["id"].as_u64())
    );
    assert_eq!(ip["custom_fields"], json!({"source": "pve-lab", "source_id": null, "arp_entry": false}));
    let disk = netbox.one("virtualization.virtual_disks", [("virtual_machine_id", &web_id)]).await;
    assert_eq!(
        (text(&disk, "/name"), disk["size"].as_u64(), text(&disk, "/description")),
        ("local-lvm:vm-101-disk-0", Some(10240), "local-lvm:vm-101-disk-0")
    );
    // The networks of its addresses exist, and its tags in the colour of a guest tag.
    assert_eq!(netbox.names("ipam.vrfs", []).await, Vec::<String>::new());
    let mut prefixes: Vec<Value> = netbox.list("ipam.prefixes", []).await;
    prefixes.sort_by_key(|prefix| text(prefix, "/prefix").to_owned());
    let prefixes: Vec<&str> = prefixes.iter().map(|prefix| text(prefix, "/prefix")).collect();
    assert_eq!(prefixes, ["192.0.2.0/24", "2001:db8::/64"]);
    let tag = netbox.one("extras.tags", [("slug", "web")]).await;
    assert_eq!((text(&tag, "/name"), text(&tag, "/color")), ("web", "4caf50"));

    // The stopped VM: its `ostype` names its platform, its interfaces are unknown.
    let db = netbox.one("virtualization.virtual_machines", [("name", "db01")]).await;
    assert_eq!(
        (text(&db, "/status/value"), db["vcpus"].as_f64(), db["memory"].as_u64(), text(&db, "/platform/name")),
        ("offline", Some(4.0), Some(8192), "Microsoft Windows 11 (64-bit)")
    );
    let db_id = db["id"].to_string();
    assert_eq!(netbox.names("virtualization.interfaces", [("virtual_machine_id", &db_id)]).await, Vec::<String>::new());
    assert_eq!(
        netbox.names("virtualization.virtual_disks", [("virtual_machine_id", &db_id)]).await,
        ["local-lvm:vm-102-disk-0"]
    );

    // The container: a virtual machine of the Container role, with its root disk.
    let dns = netbox.one("virtualization.virtual_machines", [("name", "dns01")]).await;
    assert_eq!(
        (text(&dns, "/role/name"), dns["vcpus"].as_f64(), dns["memory"].as_u64(), dns["disk"].as_u64()),
        ("Container", Some(1.0), Some(512), Some(8192))
    );
    assert_eq!((text(&dns, "/custom_fields/source_id"), text(&dns, "/primary_ip4/address")), ("200", "192.0.2.53/24"));
    let dns_id = dns["id"].to_string();
    let eth0 = netbox.one("virtualization.interfaces", [("virtual_machine_id", &dns_id)]).await;
    assert_eq!(text(&eth0, "/primary_mac_address/mac_address"), "BC:24:11:AA:BB:53");
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_second_identical_run_changes_nothing() {
    let netbox = Netbox::empty().await;
    clean(&sync("pve-lab", &netbox.client, lab(true)).await);
    let second = sync("pve-lab", &netbox.client, lab(true)).await;
    unchanged(&second);
    assert_eq!(second.warnings, Vec::<String>::new());
}

/// A selection custom field the tool does not manage keeps its value when the
/// tool writes the custom fields it manages. From NetBox 4.7 such a field is
/// read as `{"value", "label"}`, a form NetBox refuses on write: a tool that
/// sent back the custom fields it read had every PATCH of the object refused
/// (netbox-ssot, bl4ko/netbox-ssot#920).
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_selection_custom_field_of_someone_else_survives_a_write_of_the_managed_ones() {
    let netbox = Netbox::empty().await;
    clean(&sync("pve-lab", &netbox.client, lab(true)).await);
    let choices = json!({"name": "environments", "extra_choices": [["prod", "Production"], ["test", "Test"]]});
    let choice_set = netbox.create("extras.custom_field_choice_sets", choices).await;
    let field = json!({"name": "environment", "label": "Environment", "type": "select", "choice_set": choice_set,
                       "object_types": ["virtualization.virtualmachine"]});
    netbox.create("extras.custom_fields", field).await;
    let web = netbox.one("virtualization.virtual_machines", [("name", "web01")]).await;
    let id = web["id"].as_u64().expect("the id of web01");
    // The selection of the operator, and a managed field edited by hand: the
    // next run writes the managed one back.
    netbox
        .update(
            "virtualization.virtual_machines",
            id,
            json!({"custom_fields": {"environment": "prod", "source_id": "999"}}),
        )
        .await;

    let second = sync("pve-lab", &netbox.client, lab(true)).await;
    clean(&second);
    assert_eq!(changed(&second, Action::Update), [("vm", "web01")]);
    let web = netbox.one("virtualization.virtual_machines", [("name", "web01")]).await;
    assert_eq!(text(&web, "/custom_fields/source_id"), "101");
    // A plain value up to NetBox 4.6, `{"value", "label"}` from 4.7.
    let environment = &web["custom_fields"]["environment"];
    assert_eq!(environment.get("value").unwrap_or(environment), "prod", "{environment}");
    unchanged(&sync("pve-lab", &netbox.client, lab(true)).await);
}

/// On a NetBox netbox-ssot never ran on, the custom fields the translation
/// fills (`source`, `source_id`, `host_cpu_cores`, `host_memory`, `arp_entry`)
/// are not defined, and NetBox 4.5 to 4.7 refuse a write that carries one
/// (`extras/api/customfields.py`). Whatever the tool does about it, it must not
/// stop half way through its plan nor report a clean run that never converges:
/// either it refuses before writing anything, naming the custom fields, or the
/// next run finds nothing to do.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_netbox_without_the_custom_fields_is_refused_or_converges() {
    let netbox = Netbox::without_custom_fields().await;
    let first = sync("pve-lab", &netbox.client, lab(true)).await;
    if !first.errors.is_empty() {
        assert!(first.errors.iter().all(|error| error.contains("custom field")), "{:?}", first.errors);
        assert_eq!(first.applied, 0);
        return;
    }
    unchanged(&sync("pve-lab", &netbox.client, lab(true)).await);
}

/// The cluster `lab` as netbox-ssot, run with a source named `pve1`, left it
/// in NetBox: a host and `web01` with one address, every object under the
/// tags of the old tools. Returns the endpoint and the id of each tagged object.
async fn seed_old_tools(netbox: &Netbox) -> Vec<(&'static str, u64)> {
    for (name, slug) in
        [("netbox-ssot", "netbox-ssot"), ("NetBox-synced", "netbox-synced"), ("Source: pve1", "source-pve1")]
    {
        netbox.create("extras.tags", json!({"name": name, "slug": slug})).await;
    }
    let old = json!([{"slug": "netbox-ssot"}, {"slug": "source-pve1"}]);
    let source = json!({"source": "pve1"});
    // The site is the operator's: no tool owns it.
    let site = netbox.create("dcim.sites", json!({"name": SITE, "slug": "paris"})).await;
    let cluster_type =
        netbox.create("virtualization.cluster_types", json!({"name": "Proxmox", "slug": "proxmox", "tags": old})).await;
    let cluster = netbox
        .create(
            "virtualization.clusters",
            json!({"name": "lab", "type": cluster_type, "scope_type": "dcim.site", "scope_id": site,
                   "custom_fields": source, "tags": old}),
        )
        .await;
    let maker = netbox
        .create(
            "dcim.manufacturers",
            json!({"name": "Generic Manufacturer", "slug": "generic-manufacturer",
                   "description": "Generic Manufacturer created by netbox-ssot", "tags": old}),
        )
        .await;
    let model = netbox
        .create(
            "dcim.device_types",
            json!({"manufacturer": maker, "model": "Generic Model", "slug": "generic-manufacturergeneric-model",
                   "description": "Generic Device Type created by netbox-ssot", "tags": old}),
        )
        .await;
    let server = netbox
        .create(
            "dcim.device_roles",
            json!({"name": "Server", "slug": "server", "color": "00add8",
                   "description": "Device role for marking server.", "tags": old}),
        )
        .await;
    let vm_role = netbox
        .create(
            "dcim.device_roles",
            json!({"name": "VM", "slug": "vm", "color": "81eaea", "description": "Role for representing VMs.",
                   "tags": old}),
        )
        .await;
    let platform = netbox
        .create(
            "dcim.platforms",
            json!({"name": "Debian GNU/Linux 12 (bookworm)", "slug": "debian-gnulinux-12-bookworm", "tags": old}),
        )
        .await;
    let host = netbox
        .create(
            "dcim.devices",
            json!({"name": "pve01", "device_type": model, "role": server, "site": site, "cluster": cluster,
                   "custom_fields": {"source": "pve1", "host_cpu_cores": "16", "host_memory": "64 GiB"},
                   "tags": old}),
        )
        .await;
    let vm = netbox
        .create(
            "virtualization.virtual_machines",
            json!({"name": "web01", "status": "active", "vcpus": 2, "memory": 2048, "cluster": cluster,
                   "device": host, "site": site, "role": vm_role, "platform": platform,
                   "custom_fields": {"source": "pve1", "source_id": "101"},
                   "tags": [{"slug": "netbox-ssot"}, {"slug": "source-pve1"}, {"slug": "netbox-synced"}]}),
        )
        .await;
    let eth0 = netbox
        .create(
            "virtualization.interfaces",
            json!({"virtual_machine": vm, "name": "eth0", "custom_fields": source, "tags": old}),
        )
        .await;
    let mac = netbox
        .create(
            "dcim.mac_addresses",
            json!({"mac_address": "BC:24:11:AA:BB:01", "assigned_object_type": "virtualization.vminterface",
                   "assigned_object_id": eth0, "tags": old}),
        )
        .await;
    netbox.update("virtualization.interfaces", eth0, json!({"primary_mac_address": mac})).await;
    let prefix =
        netbox.create("ipam.prefixes", json!({"prefix": "192.0.2.0/24", "custom_fields": source, "tags": old})).await;
    let ip = netbox
        .create(
            "ipam.ip_addresses",
            json!({"address": "192.0.2.10/24", "status": "active",
                   "assigned_object_type": "virtualization.vminterface", "assigned_object_id": eth0,
                   "custom_fields": {"source": "pve1", "arp_entry": false}, "tags": old}),
        )
        .await;
    netbox.update("virtualization.virtual_machines", vm, json!({"primary_ip4": ip})).await;
    let disk = netbox
        .create(
            "virtualization.virtual_disks",
            json!({"virtual_machine": vm, "name": "local-lvm:vm-101-disk-0", "size": 10240,
                   "description": "local-lvm:vm-101-disk-0", "custom_fields": source, "tags": old}),
        )
        .await;
    vec![
        ("virtualization.cluster_types", cluster_type),
        ("virtualization.clusters", cluster),
        ("dcim.manufacturers", maker),
        ("dcim.device_types", model),
        ("dcim.device_roles", server),
        ("dcim.device_roles", vm_role),
        ("dcim.platforms", platform),
        ("dcim.devices", host),
        ("virtualization.virtual_machines", vm),
        ("virtualization.interfaces", eth0),
        ("dcim.mac_addresses", mac),
        ("ipam.prefixes", prefix),
        ("ipam.ip_addresses", ip),
        ("virtualization.virtual_disks", disk),
    ]
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn objects_of_the_old_tools_are_adopted_by_their_tags_alone() {
    let netbox = Netbox::empty().await;
    let seeded = seed_old_tools(&netbox).await;
    let reported = cluster(Vec::new(), vec![web01(&[("192.0.2.10", "ipv4", 24)])], Vec::new());

    let adoption = sync("pve1", &netbox.client, reported.clone()).await;
    clean(&adoption);
    // The tag of the tool is new; the tag of the source is the one the old tool made.
    assert_eq!(changed(&adoption, Action::Create), [("tag", "netbox-omnisync")]);
    assert_eq!(changed(&adoption, Action::Delete), []);
    assert_eq!(
        changed(&adoption, Action::Update),
        [
            ("cluster", "lab"),
            ("cluster_type", "Proxmox"),
            ("device", "pve01"),
            ("device_type", "Generic Model"),
            ("disk", "local-lvm:vm-101-disk-0"),
            ("ip", "192.0.2.10/24"),
            ("mac", "BC:24:11:AA:BB:01"),
            ("manufacturer", "Generic Manufacturer"),
            ("platform", "Debian GNU/Linux 12 (bookworm)"),
            ("prefix", "192.0.2.0/24"),
            ("role", "Server"),
            ("role", "VM"),
            ("vm", "web01"),
            ("vm_interface", "eth0"),
        ]
    );
    let new_tags: BTreeSet<&str> = ["Source: pve1", "netbox-omnisync"].into();
    for change in adoption.changes.iter().filter(|change| change.action == Action::Update) {
        let fields: Vec<&str> = change.fields.keys().map(String::as_str).collect();
        assert_eq!(fields, ["tags"], "{} {} changes more than its tags: {:?}", change.kind, change.key, change.fields);
        let tags: BTreeSet<&str> =
            change.fields["tags"].as_array().expect("tag names").iter().filter_map(Value::as_str).collect();
        assert_eq!(tags, new_tags, "{} {}", change.kind, change.key);
    }

    for (endpoint, id) in seeded {
        let object = netbox.one(endpoint, [("id", &id.to_string())]).await;
        assert_eq!(tag_slugs(&object), ["netbox-omnisync", "source-pve1"], "{endpoint} {id}");
    }
    // No second tag under the slug of the source: the old one was kept, with its name.
    let mut tags: Vec<(String, String)> = Vec::new();
    for tag in netbox.list("extras.tags", []).await {
        tags.push((text(&tag, "/slug").to_owned(), text(&tag, "/name").to_owned()));
    }
    tags.sort();
    let expected = [
        ("netbox-omnisync", "netbox-omnisync"),
        ("netbox-ssot", "netbox-ssot"),
        ("netbox-synced", "NetBox-synced"),
        ("source-pve1", "Source: pve1"),
    ];
    assert_eq!(tags, expected.map(|(slug, name)| (slug.to_owned(), name.to_owned())));

    unchanged(&sync("pve1", &netbox.client, reported).await);
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn what_the_source_stops_reporting_is_deleted_unless_the_run_is_dry() {
    let netbox = Netbox::empty().await;
    clean(&sync("pve-lab", &netbox.client, lab(true)).await);
    // The container is gone from the cluster, and with it the only use of its role.
    let gone = [
        ("ip", "192.0.2.53/24"),
        ("mac", "BC:24:11:AA:BB:53"),
        ("role", "Container"),
        ("vm", "dns01"),
        ("vm_interface", "eth0"),
    ];

    let dry = sync("pve-lab", &netbox.dry_run(), lab(false)).await;
    assert_eq!(changed(&dry, Action::Delete), gone);
    assert_eq!((changed(&dry, Action::Create), changed(&dry, Action::Update)), (vec![], vec![]));
    assert_eq!((dry.errors.as_slice(), dry.applied), ([].as_slice(), 0));
    // Nothing was written: the container is still there, with its address and its role.
    assert_eq!(netbox.names("virtualization.virtual_machines", []).await, ["db01", "dns01", "web01"]);
    assert_eq!(netbox.list("ipam.ip_addresses", [("address", "192.0.2.53")]).await.len(), 1);
    assert_eq!(netbox.names("dcim.device_roles", []).await, ["Container", "Server", "VM"]);

    let pruned = sync("pve-lab", &netbox.client, lab(false)).await;
    clean(&pruned);
    assert_eq!(pruned.changes, dry.changes);
    assert_eq!(netbox.names("virtualization.virtual_machines", []).await, ["db01", "web01"]);
    assert_eq!(netbox.list("ipam.ip_addresses", [("address", "192.0.2.53")]).await, Vec::<Value>::new());
    assert_eq!(netbox.list("dcim.mac_addresses", [("mac_address", "BC:24:11:AA:BB:53")]).await, Vec::<Value>::new());
    assert_eq!(netbox.names("dcim.device_roles", []).await, ["Server", "VM"]);
    // What is still reported is untouched: the network of the deleted address is also web01's.
    let web = netbox.one("virtualization.virtual_machines", [("name", "web01")]).await;
    assert_eq!(text(&web, "/primary_ip4/address"), "192.0.2.10/24");
    assert_eq!(netbox.list("ipam.prefixes", [("prefix", "192.0.2.0/24")]).await.len(), 1);

    unchanged(&sync("pve-lab", &netbox.client, lab(false)).await);
}

/// The one change of a run that renames an object in place.
fn renaming(kind: &str, id: &Value, from: &str, to: &str) -> Vec<Change> {
    let id = id.as_u64().expect("an id");
    vec![Change::new(kind, Action::Update, to, to).fields([("name", json!(to))]).before([("name", json!(from))]).id(id)]
}

/// The ids of the objects of `endpoint` that match `query`, sorted.
async fn ids<const N: usize>(netbox: &Netbox, endpoint: &str, query: [(&str, &str); N]) -> Vec<u64> {
    let mut ids: Vec<u64> = netbox.list(endpoint, query).await.iter().filter_map(|row| row["id"].as_u64()).collect();
    ids.sort_unstable();
    ids
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_virtual_machine_renamed_in_the_source_is_renamed_in_place() {
    let netbox = Netbox::empty().await;
    clean(&sync("pve-lab", &netbox.client, lab(true)).await);
    let web = netbox.one("virtualization.virtual_machines", [("name", "web01")]).await;
    let web_id = web["id"].to_string();
    let interfaces = ids(&netbox, "virtualization.interfaces", [("virtual_machine_id", &web_id)]).await;
    let macs = ids(&netbox, "dcim.mac_addresses", [("virtual_machine_id", &web_id)]).await;
    let addresses = ids(&netbox, "ipam.ip_addresses", [("virtual_machine_id", &web_id)]).await;
    let disks = ids(&netbox, "virtualization.virtual_disks", [("virtual_machine_id", &web_id)]).await;
    // One interface with its MAC address, an IPv4 and an IPv6 address, one disk.
    assert_eq!((interfaces.len(), macs.len(), addresses.len(), disks.len()), (1, 1, 2, 1));

    // Proxmox now calls the machine `www01`; nothing else changed.
    let mut renamed = lab(true);
    renamed.nodes[0].vms[0].name = "www01".to_owned();
    let second = sync("pve-lab", &netbox.client, renamed.clone()).await;
    clean(&second);
    assert_eq!(second.changes, renaming("vm", &web["id"], "web01", "www01"));

    // The same object under its new name, and the same objects under it.
    assert_eq!(netbox.names("virtualization.virtual_machines", []).await, ["db01", "dns01", "www01"]);
    let www = netbox.one("virtualization.virtual_machines", [("name", "www01")]).await;
    assert_eq!(www["id"], web["id"]);
    assert_eq!(
        (text(&www, "/primary_ip4/address"), text(&www, "/primary_ip6/address")),
        ("192.0.2.10/24", "2001:db8::10/64")
    );
    assert_eq!(tag_slugs(&www), ["netbox-omnisync", "prod", "source-pve-lab", "web"]);
    assert_eq!(ids(&netbox, "virtualization.interfaces", [("virtual_machine_id", &web_id)]).await, interfaces);
    assert_eq!(ids(&netbox, "dcim.mac_addresses", [("virtual_machine_id", &web_id)]).await, macs);
    assert_eq!(ids(&netbox, "ipam.ip_addresses", [("virtual_machine_id", &web_id)]).await, addresses);
    assert_eq!(ids(&netbox, "virtualization.virtual_disks", [("virtual_machine_id", &web_id)]).await, disks);
    assert_eq!(netbox.list("dcim.mac_addresses", [("mac_address", "BC:24:11:AA:BB:01")]).await.len(), 1);

    unchanged(&sync("pve-lab", &netbox.client, renamed).await);
}

/// The scripted cluster, and the MAC address of `eno1` of its node. Proxmox
/// reports no address for the interfaces of a node (a vCenter does for those
/// of a host): the object is added to what the translation gives.
struct WithHostMac(ProxmoxCluster);

impl Reader for WithHostMac {
    async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
        let mut reading = Script(self.0.clone()).read(source).await?;
        let eno1 = Identity::interface(&self.0.nodes[0].name, "eno1");
        let address = "D4:AE:52:AA:BB:01";
        let identity = Identity::mac_address(address, Some(&Target::new(Kind::Interface, eno1.clone())));
        reading.objects.push(
            Desired::new(Kind::MacAddress, identity, &source.name).field("mac_address", address).reference(
                "assigned_object",
                Kind::Interface,
                eno1,
            ),
        );
        Ok(reading)
    }
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_host_renamed_in_the_source_is_renamed_in_place() {
    let netbox = Netbox::empty().await;
    clean(&sync_reading("pve-lab", &netbox.client, &WithHostMac(lab(true))).await);
    let host = netbox.one("dcim.devices", [("name", "pve01")]).await;
    let host_id = host["id"].to_string();
    let interfaces = ids(&netbox, "dcim.interfaces", [("device_id", &host_id)]).await;
    let macs = ids(&netbox, "dcim.mac_addresses", [("device_id", &host_id)]).await;
    let machines = ids(&netbox, "virtualization.virtual_machines", [("device_id", &host_id)]).await;
    // bond0, eno1, eno2 and vmbr0; the MAC address of eno1; web01, db01 and dns01.
    assert_eq!((interfaces.len(), macs.len(), machines.len()), (4, 1, 3));

    // The node is now `pve02`.
    let mut renamed = lab(true);
    renamed.nodes[0].name = "pve02".to_owned();
    let second = sync_reading("pve-lab", &netbox.client, &WithHostMac(renamed.clone())).await;
    clean(&second);
    assert_eq!(second.changes, renaming("device", &host["id"], "pve01", "pve02"));

    assert_eq!(netbox.names("dcim.devices", []).await, ["pve02"]);
    let pve02 = netbox.one("dcim.devices", [("name", "pve02")]).await;
    assert_eq!(pve02["id"], host["id"]);
    assert_eq!(tag_slugs(&pve02), OWNED_BY_PVE_LAB);
    assert_eq!(ids(&netbox, "dcim.interfaces", [("device_id", &host_id)]).await, interfaces);
    assert_eq!(ids(&netbox, "dcim.mac_addresses", [("device_id", &host_id)]).await, macs);
    // The machines it runs are still on it.
    assert_eq!(ids(&netbox, "virtualization.virtual_machines", [("device_id", &host_id)]).await, machines);

    unchanged(&sync_reading("pve-lab", &netbox.client, &WithHostMac(renamed)).await);
}

/// Reads a vCenter or BMCs as the tool does, at the URL of a fake one.
struct OverHttp {
    vcenter: String,
    bmcs: Vec<(String, String)>,
    lookups: ReverseLookups,
}

impl Reader for OverHttp {
    async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
        let bmc = |host: &str| {
            let url = self.bmcs.iter().find(|(name, _)| name == host).map(|(_, url)| url.clone());
            url.unwrap_or_else(|| panic!("no fake BMC for {host}"))
        };
        match source.r#type {
            HypervisorType::Vmware => read_vmware_at(source, &self.vcenter, &self.lookups).await,
            HypervisorType::Redfish => read_redfish_at(source, &bmc).await,
            HypervisorType::Proxmox => panic!("a Proxmox is scripted, not read over HTTP"),
        }
    }
}

/// The recorded vCenter 6.7 (6 hosts, 166 machines, 28 tags, port groups and
/// physical NICs with their speed) goes through the real collection, the real
/// translation and the real client: NetBox takes every field written, and a
/// second run finds nothing to change.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_recorded_vcenter_is_written_once() {
    let netbox = Netbox::empty().await;
    let server = fake_vcenter::vcenter("6.7").await;
    let source = Hypervisor {
        r#type: HypervisorType::Vmware,
        host: "127.0.0.1".to_owned(),
        port: Some(server.address().port()),
        validate_certs: false,
        site: Some("Harbor".to_owned()),
        tenant: Some("Example Tenant".to_owned()),
        host_role: Some("Hypervisor ESX".to_owned()),
        vm_role: Some("Virtual Machine ESX".to_owned()),
        permitted_subnets: vec!["198.18.0.0/15".parse().expect("a network")],
        ..hypervisor("vc01.lab01")
    };
    let reader = OverHttp { vcenter: server.uri(), bmcs: Vec::new(), lookups: ReverseLookups::system() };
    let sources = [source];
    let selected: Vec<&Hypervisor> = sources.iter().collect();

    let first = run(&sources, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    assert_eq!(first.errors, Vec::<String>::new());
    assert_eq!(first.applied, first.changes.len());
    let second = run(&sources, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    assert_eq!((second.errors, second.changes), (Vec::<String>::new(), Vec::<Change>::new()));

    // host-10: `esx04.lab.example`, a PowerEdge FC430 whose `SerialNumberTag` is ID00016,
    // its vmk0 on 198.18.0.36/24.
    let device = netbox.one("dcim.devices", [("name", "esx04.lab.example")]).await;
    assert_eq!((text(&device, "/serial"), text(&device, "/device_type/model")), ("ID00016", "PowerEdge FC430"));
    assert_eq!(text(&device, "/primary_ip4/address"), "198.18.0.36/24");
    // vm-342: `vm076.lab.example` carries the vSphere tag `service-rabbit`.
    let machine = netbox.one("virtualization.virtual_machines", [("name", "vm076.lab.example")]).await;
    assert!(tag_slugs(&machine).contains(&"service-rabbit".to_owned()), "{machine}");
}

/// A host documented in NetBox with one of the cards its iDRAC 8 reports
/// (idrac8-2.86.86.86: "Model": "PowerEdge R630", "SKU": "878X8Z3", a card
/// "02:00:00:00:00:0E"): the BMC source creates the device type and writes it
/// with the serial, and a second run finds nothing to change.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_bmc_completes_the_host_it_proves_once() {
    let netbox = Netbox::empty().await;
    let site = netbox.create("dcim.sites", json!({"name": SITE, "slug": "paris", "status": "active"})).await;
    let maker = netbox.create("dcim.manufacturers", json!({"name": "Generic", "slug": "generic"})).await;
    let model = json!({"manufacturer": maker, "model": "Generic Model", "slug": "generic-model"});
    let model = netbox.create("dcim.device_types", model).await;
    let role = netbox.create("dcim.device_roles", json!({"name": "Server", "slug": "server"})).await;
    let host = json!({"name": "pve01.lab01", "device_type": model, "role": role, "site": site, "status": "active"});
    let host = netbox.create("dcim.devices", host).await;
    let card = netbox.create("dcim.interfaces", json!({"device": host, "name": "eno1", "type": "1000base-t"})).await;
    let mac = json!({"mac_address": "02:00:00:00:00:0E", "assigned_object_type": "dcim.interface",
                     "assigned_object_id": card});
    let mac = netbox.create("dcim.mac_addresses", mac).await;
    netbox.update("dcim.interfaces", card, json!({"primary_mac_address": mac})).await;

    let server = fake_bmc::bmc("idrac8-2.86.86.86").await;
    let source = Hypervisor {
        r#type: HypervisorType::Redfish,
        host: String::new(),
        validate_certs: false,
        site: None,
        create_devices: false,
        prune: false,
        vlan_group: None,
        bmcs: vec![Bmc { device: "pve01.lab01".to_owned(), host: "drac-pve01.lab01".to_owned(), fingerprint: None }],
        // The account the fake BMC takes, and no other.
        credentials: Wanted::Held(Credentials::Password {
            username: fake_bmc::USER.to_owned(),
            password: Secret::new(fake_bmc::PASSWORD),
        }),
        ..hypervisor("bmc.lab01")
    };
    let bmcs = vec![("drac-pve01.lab01".to_owned(), server.uri())];
    let reader = OverHttp { vcenter: String::new(), bmcs, lookups: ReverseLookups::system() };
    let sources = [source];
    let selected: Vec<&Hypervisor> = sources.iter().collect();

    let first = run(&sources, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    assert_eq!(first.errors, Vec::<String>::new());
    assert_eq!(first.applied, first.changes.len());
    let second = run(&sources, &selected, &[], &netbox.client, &reader, &NullProgress).await;
    assert_eq!((second.errors, second.changes), (Vec::<String>::new(), Vec::<Change>::new()));

    let device = netbox.one("dcim.devices", [("name", "pve01.lab01")]).await;
    assert_eq!((text(&device, "/device_type/model"), text(&device, "/serial")), ("PowerEdge R630", "878X8Z3"));
}
