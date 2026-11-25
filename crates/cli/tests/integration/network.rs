//! The network chain against a real NetBox: the three integration tests of
//! netbox-switch-sync, with the same seeds and the same recorded outputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use omnisync_cisco::collect::collect as collect_cisco;
use omnisync_cisco::commands::Platform;
use omnisync_cisco::runner::CommandRunner;
use omnisync_cli::network::{Collector, CommandLog, Options, ReportingRunner, run};
use omnisync_core::gateway::filters;
use omnisync_core::inventory::model::VlanGroups;
use omnisync_core::network::collect::CollectionError;
use omnisync_core::network::inventory::{Inventory, Kind, Secret, Source, Wanted};
use omnisync_core::network::model::DeviceState;
use omnisync_core::progress::NullProgress;
use omnisync_core::{Change, Gateway, GatewayError, Outcome};
use omnisync_fortios::collect::{Fetcher, collect as collect_fortios};
use serde_json::{Value, json};

use crate::support::{Netbox, text, url};

/// The recorded outputs of nexus01 (NX-OS I2), in the Cisco crate.
fn nxos_i2() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../cisco/tests/fixtures/nxos_i2")
}

/// The recorded answers of the FortiGate cluster (FortiOS v7.4.13), in the FortiOS crate.
fn fortios() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fortios/tests/fixtures/7.4.13")
}

/// The recorded output of `command`, named like the probe files.
fn recorded(directory: &Path, command: &str) -> Result<String, CollectionError> {
    let name: String = command.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let path = directory.join(format!("{name}.txt"));
    fs::read_to_string(&path).map_err(|error| CollectionError(format!("{}: {error}", path.display())))
}

/// The recorded outputs of a Catalyst 2960-X stack (IOS), in the Cisco crate.
fn ios() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../cisco/tests/fixtures/ios")
}

/// Command runner that answers from the recorded outputs of a switch.
struct FixtureRunner(PathBuf);

impl CommandRunner for FixtureRunner {
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        recorded(&self.0, command)
    }
}

/// Fetcher that answers from the recorded firewall answers.
struct FixtureFetcher<'a> {
    commands: &'a CommandLog<'a>,
}

impl Fetcher for FixtureFetcher<'_> {
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        self.commands.starting(command);
        let answer = recorded(&fortios(), command)?;
        self.commands.finished();
        Ok(answer)
    }
}

/// The devices of the tests, read from the recorded outputs: no SSH, no API.
struct Fixtures;

impl Collector for Fixtures {
    async fn collect(&self, source: &Source, commands: &CommandLog<'_>) -> Result<DeviceState, CollectionError> {
        let directory = |platform| if platform == Platform::Ios { ios() } else { nxos_i2() };
        match Platform::from_type(&source.r#type) {
            Some(platform) => {
                let runner = FixtureRunner(directory(platform));
                collect_cisco(platform, &mut ReportingRunner::new(runner, commands)).await
            }
            None => collect_fortios(&mut FixtureFetcher { commands }, source).await,
        }
    }
}

fn inventory(source: Source, domains: &[&str]) -> Inventory {
    Inventory {
        sources: vec![source],
        domains: domains.iter().map(|domain| (*domain).to_owned()).collect(),
        netbox_url: url().to_owned(),
        netbox_token: Wanted::Held(Secret::new("unused")),
        aliases: BTreeMap::new(),
    }
}

async fn sync(inventory: &Inventory, netbox: &Netbox, apply: bool) -> Outcome {
    let options = Options { apply, prune: true, only: BTreeSet::new(), ..Options::default() };
    run(inventory, &netbox.client, &Fixtures, &options, &NullProgress).await
}

fn nexus01() -> Source {
    Source {
        username: "user".to_owned(),
        password: Some(Wanted::Held(Secret::new("secret"))),
        ..Source::new("nexus01.lab01", Kind::Switch, "nxos", "192.0.2.239")
    }
}

/// nexus01 as documented by hand: its address on a fictitious `admin` port.
async fn seed(netbox: &Netbox) -> (u64, u64) {
    let site = netbox.create("dcim.sites", json!({"name": "Falcon", "slug": "falcon", "status": "active"})).await;
    let maker = netbox.create("dcim.manufacturers", json!({"name": "Cisco", "slug": "cisco"})).await;
    let model = netbox
        .create(
            "dcim.device_types",
            json!({"manufacturer": maker, "model": "N3K-C3064PQ-10GX", "slug": "n3k-c3064pq-10gx"}),
        )
        .await;
    let role = netbox.create("dcim.device_roles", json!({"name": "Network switch", "slug": "network-switch"})).await;
    let device = netbox
        .create(
            "dcim.devices",
            json!({"name": "nexus01.lab01", "device_type": model, "role": role, "site": site, "status": "active"}),
        )
        .await;
    for vrf in ["management", "mgmt-sw"] {
        netbox.create("ipam.vrfs", json!({"name": vrf})).await;
    }
    let admin = netbox.create("dcim.interfaces", json!({"device": device, "name": "admin", "type": "virtual"})).await;
    let ip = netbox
        .create(
            "ipam.ip_addresses",
            json!({
                "address": "192.0.2.239/24",
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": admin,
                "status": "active",
            }),
        )
        .await;
    netbox.update("dcim.devices", device, json!({"primary_ip4": ip})).await;
    (device, ip)
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn sync_is_idempotent_on_netbox_44() {
    let netbox = Netbox::empty().await;
    let (device_id, ip_id) = seed(&netbox).await;
    let device_id = device_id.to_string();
    let inventory = inventory(nexus01(), &["switch.example.com"]);

    let first = sync(&inventory, &netbox, true).await;
    assert_eq!(first.errors, Vec::<String>::new());

    let second = sync(&inventory, &netbox, false).await;
    assert_eq!(second.errors, Vec::<String>::new());
    assert_eq!(second.changes, Vec::<Change>::new());

    let ip = netbox.one("ipam.ip_addresses", [("address", "192.0.2.239")]).await;
    assert_eq!(
        (ip["id"].as_u64(), text(&ip, "/assigned_object/name"), text(&ip, "/vrf/name")),
        (Some(ip_id), "Vlan2800", "mgmt-sw")
    );
    let device = netbox.one("dcim.devices", [("name", "nexus01.lab01")]).await;
    assert_eq!(device["primary_ip4"]["id"].as_u64(), Some(ip_id));
    assert_eq!(text(&device, "/serial"), "FOC9792A4K9");
    let eth = netbox.one("dcim.interfaces", [("device_id", &device_id), ("name", "Ethernet1/1")]).await;
    assert_eq!(text(&eth, "/primary_mac_address/mac_address"), "02:08:D1:90:97:2D");
    assert_eq!(
        netbox.list("dcim.interfaces", [("device_id", &device_id), ("name", "admin")]).await,
        Vec::<Value>::new()
    );
}

/// A device of the site of nexus01, with the ports `names`: a neighbour
/// NetBox documents but the run does not read.
async fn neighbour(netbox: &Netbox, name: &str, names: &[&str]) -> u64 {
    let nexus01 = netbox.one("dcim.devices", [("name", "nexus01.lab01")]).await;
    let device = json!({"name": name, "device_type": nexus01["device_type"]["id"], "role": nexus01["role"]["id"],
                        "site": nexus01["site"]["id"], "status": "active"});
    let device = netbox.create("dcim.devices", device).await;
    for port in names {
        netbox.create("dcim.interfaces", json!({"device": device, "name": port, "type": "10gbase-x-sfpp"})).await;
    }
    device
}

/// The far end of the cable of a port of nexus01: (device, port).
async fn far_end(netbox: &Netbox, device_id: &str, port: &str) -> (String, String) {
    let interface = netbox.one("dcim.interfaces", [("device_id", device_id), ("name", port)]).await;
    let peer = &interface["link_peers"][0];
    (text(peer, "/device/name").to_owned(), text(peer, "/name").to_owned())
}

/// nexus01 announces nexus02 on three ports over CDP and LLDP
/// (`show cdp neighbors detail | json`: Ethernet1/48 -> Ethernet1/48,
/// Ethernet1/51 -> Ethernet1/52, Ethernet1/52 -> Ethernet1/51). nexus02 is in
/// NetBox and not read by the run: the three cables are written, and a second
/// run finds nothing to change.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn the_cables_to_a_neighbour_netbox_documents_are_written_once() {
    let netbox = Netbox::empty().await;
    let (device_id, _) = seed(&netbox).await;
    let device_id = device_id.to_string();
    neighbour(&netbox, "nexus02.lab01", &["Ethernet1/48", "Ethernet1/51", "Ethernet1/52"]).await;
    let inventory = inventory(nexus01(), &["switch.example.com"]);

    let first = sync(&inventory, &netbox, true).await;
    assert_eq!(first.errors, Vec::<String>::new());
    let second = sync(&inventory, &netbox, false).await;
    assert_eq!((second.errors, second.changes), (Vec::<String>::new(), Vec::<Change>::new()));

    let nexus02 = |port: &str| ("nexus02.lab01".to_owned(), port.to_owned());
    assert_eq!(far_end(&netbox, &device_id, "Ethernet1/48").await, nexus02("Ethernet1/48"));
    assert_eq!(far_end(&netbox, &device_id, "Ethernet1/51").await, nexus02("Ethernet1/52"));
    assert_eq!(far_end(&netbox, &device_id, "Ethernet1/52").await, nexus02("Ethernet1/51"));
}

/// The 2960-X stack of the recorded outputs, one member (`show switch`:
/// `*1 Master`), synced through its NetBox virtual chassis: the member gets
/// the serial of the chassis (`show inventory`: `NAME: "1" … SN: FCW8657Y7S5`)
/// and its ports, the address of `Vlan2800` (`show ip interface brief`:
/// `192.0.2.251`) is its primary one, and a second run finds nothing to change.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn an_ios_stack_is_synced_through_its_virtual_chassis_once() {
    let netbox = Netbox::empty().await;
    let site = netbox.create("dcim.sites", json!({"name": "Kestrel", "slug": "kestrel", "status": "active"})).await;
    let maker = netbox.create("dcim.manufacturers", json!({"name": "Cisco", "slug": "cisco"})).await;
    let model = json!({"manufacturer": maker, "model": "WS-C2960X-24TD-L", "slug": "ws-c2960x-24td-l"});
    let model = netbox.create("dcim.device_types", model).await;
    let role = netbox.create("dcim.device_roles", json!({"name": "Access switch", "slug": "access-switch"})).await;
    let chassis = netbox.create("dcim.virtual_chassis", json!({"name": "2960-stack"})).await;
    let member = json!({"name": "2960-stack01.lab01", "device_type": model, "role": role, "site": site,
                        "status": "active", "virtual_chassis": chassis, "vc_position": 1});
    let member = netbox.create("dcim.devices", member).await;
    netbox.update("dcim.virtual_chassis", chassis, json!({"master": member})).await;
    let stack = Source {
        virtual_chassis: Some("2960-stack".to_owned()),
        username: "user".to_owned(),
        password: Some(Wanted::Held(Secret::new("secret"))),
        ..Source::new("2960-stack.lab01", Kind::Switch, "ios", "192.0.2.251")
    };
    let inventory = inventory(stack, &["switch.example.com"]);

    let first = sync(&inventory, &netbox, true).await;
    assert_eq!(first.errors, Vec::<String>::new());
    let second = sync(&inventory, &netbox, false).await;
    assert_eq!((second.errors, second.changes), (Vec::<String>::new(), Vec::<Change>::new()));

    let device = netbox.one("dcim.devices", [("name", "2960-stack01.lab01")]).await;
    assert_eq!(text(&device, "/serial"), "FCW8657Y7S5");
    assert_eq!(text(&device, "/primary_ip4/address"), "192.0.2.251/24");
    let member = member.to_string();
    let port = netbox.one("dcim.interfaces", [("device_id", &member), ("name", "TenGigabitEthernet1/0/1")]).await;
    assert_eq!(text(&port, "/name"), "TenGigabitEthernet1/0/1");
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn unknown_filter_is_refused() {
    let netbox = Netbox::empty().await;
    let refused = netbox.client.list("dcim.mac_addresses", &filters([("bogusfilter", 1)])).await;
    assert_eq!(
        refused,
        Err(GatewayError::UnknownFilter {
            endpoint: "dcim.mac_addresses".to_owned(),
            filter: "bogusfilter".to_owned()
        })
    );
}

fn firewall() -> Source {
    Source {
        username: "readonly".to_owned(),
        password: Some(Wanted::Held(Secret::new("secret"))),
        tls_fingerprint: Some("ab".repeat(32)),
        ha_peers: vec![
            ("LABLU-FWL01".to_owned(), "lablu-fwl01.dc1".to_owned()),
            ("LABBS-FWL01".to_owned(), "labbs-fwl01.dc1".to_owned()),
        ],
        ignore_interfaces: vec!["dmz".to_owned()],
        ..Source::new("lablu-fwl01.dc1", Kind::Firewall, "fortios", "10.0.13.1")
    }
}

/// A cluster documented by hand: the API address on a fictitious port.
async fn seed_firewalls(netbox: &Netbox) -> (u64, u64, u64) {
    let site = netbox.create("dcim.sites", json!({"name": "Harbour", "slug": "harbour", "status": "active"})).await;
    let maker = netbox.create("dcim.manufacturers", json!({"name": "Fortinet", "slug": "fortinet"})).await;
    let model = netbox
        .create(
            "dcim.device_types",
            json!({"manufacturer": maker, "model": "FortiGate 101F", "slug": "fortigate-101f"}),
        )
        .await;
    let role = netbox.create("dcim.device_roles", json!({"name": "Firewall", "slug": "firewall"})).await;
    let mut devices = Vec::new();
    for name in ["lablu-fwl01.dc1", "labbs-fwl01.dc1"] {
        let device = json!({"name": name, "device_type": model, "role": role, "site": site, "status": "active"});
        devices.push(netbox.create("dcim.devices", device).await);
    }
    let (entry, peer) = (devices[0], devices[1]);
    let eth0 = netbox.create("dcim.interfaces", json!({"device": entry, "name": "eth0", "type": "other"})).await;
    netbox.create("dcim.interfaces", json!({"device": peer, "name": "eth0", "type": "other"})).await;
    let ip = netbox
        .create(
            "ipam.ip_addresses",
            json!({
                "address": "10.0.13.1/24",
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": eth0,
                "status": "active",
            }),
        )
        .await;
    netbox.update("dcim.devices", entry, json!({"primary_ip4": ip})).await;
    (entry, peer, ip)
}

/// (id, has a site, name of its group) of every VLAN NetBox holds.
async fn vlans(netbox: &Netbox) -> Vec<(u64, bool, String)> {
    let rows = netbox.list("ipam.vlans", []).await;
    let vlan = |row: &Value| {
        let group = row["group"]["name"].as_str().unwrap_or_default().to_owned();
        (row["id"].as_u64().expect("an id"), !row["site"].is_null(), group)
    };
    rows.iter().map(vlan).collect()
}

/// The ids of the VLANs the interfaces of a device point to, untagged or tagged.
async fn pointed(netbox: &Netbox, device_id: &str) -> BTreeSet<u64> {
    let mut pointed = BTreeSet::new();
    for interface in netbox.list("dcim.interfaces", [("device_id", device_id)]).await {
        let tagged = interface["tagged_vlans"].as_array().cloned().unwrap_or_default();
        pointed.extend(tagged.iter().chain([&interface["untagged_vlan"]]).filter_map(|vlan| vlan["id"].as_u64()));
    }
    pointed
}

/// A firewall cluster whose site joins a VLAN group: its VLANs are created in
/// the group, at no site, its ports are moved to them (untagged and tagged,
/// which NetBox takes on a device of that site), and the VLANs of the site
/// are left where they are. A second run has nothing to write.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn a_firewall_whose_site_joins_a_vlan_group_gets_its_ports_on_the_vlans_of_the_group() {
    let netbox = Netbox::empty().await;
    let (entry_id, _, _) = seed_firewalls(&netbox).await;
    let entry_id = entry_id.to_string();
    let inventory = inventory(firewall(), &[]);
    let before = sync(&inventory, &netbox, true).await;
    assert_eq!(before.errors, Vec::<String>::new());
    let of_the_site = vlans(&netbox).await;
    assert!(of_the_site.iter().all(|(_, at_site, group)| *at_site && group.is_empty()), "{of_the_site:?}");
    let site_ids: BTreeSet<u64> = of_the_site.iter().map(|vlan| vlan.0).collect();
    let on_site = pointed(&netbox, &entry_id).await;
    assert!(!on_site.is_empty() && on_site.is_subset(&site_ids), "{on_site:?}");

    // The group is a prerequisite: created by hand, as the site (seeded as `Harbour`) joins it.
    netbox.create("ipam.vlan_groups", json!({"name": "East", "slug": "east"})).await;
    let mut vlan_groups = VlanGroups::default();
    vlan_groups.insert("Harbour", "East");
    let grouped = |apply| Options { apply, prune: true, vlan_groups: vlan_groups.clone(), ..Options::default() };
    let moved = run(&inventory, &netbox.client, &Fixtures, &grouped(true), &NullProgress).await;
    assert_eq!(moved.errors, Vec::<String>::new());
    let held = vlans(&netbox).await;
    let group_ids: BTreeSet<u64> =
        held.iter().filter(|(_, at_site, group)| !at_site && group == "East").map(|vlan| vlan.0).collect();
    // As many VLANs in the group as the site has, and those of the site still there.
    assert_eq!(group_ids.len(), site_ids.len());
    assert_eq!(held.len(), 2 * site_ids.len());
    let on_group = pointed(&netbox, &entry_id).await;
    assert_eq!(on_group.len(), on_site.len());
    assert!(on_group.is_subset(&group_ids), "{on_group:?}");

    let again = run(&inventory, &netbox.client, &Fixtures, &grouped(false), &NullProgress).await;
    assert_eq!((again.errors, again.changes), (Vec::<String>::new(), Vec::<Change>::new()));
}

#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn firewall_cluster_sync_is_idempotent_on_netbox_44() {
    let netbox = Netbox::empty().await;
    let (entry_id, peer_id, ip_id) = seed_firewalls(&netbox).await;
    let (entry_id, peer_id) = (entry_id.to_string(), peer_id.to_string());
    let inventory = inventory(firewall(), &[]);

    let first = sync(&inventory, &netbox, true).await;
    assert_eq!(first.errors, Vec::<String>::new());

    let second = sync(&inventory, &netbox, false).await;
    assert_eq!(second.errors, Vec::<String>::new());
    assert_eq!(second.changes, Vec::<Change>::new());

    let entry = netbox.one("dcim.devices", [("name", "lablu-fwl01.dc1")]).await;
    let peer = netbox.one("dcim.devices", [("name", "labbs-fwl01.dc1")]).await;
    assert_eq!((text(&entry, "/serial"), text(&peer, "/serial")), ("FG101FTK22000001", "FG101FTK22000002"));
    // The API address left the fictitious port, which the prune then removed.
    let ip = netbox.one("ipam.ip_addresses", [("address", "10.0.13.1")]).await;
    assert_eq!((ip["id"].as_u64(), text(&ip, "/assigned_object/name")), (Some(ip_id), "HOUSING"));
    assert_eq!(entry["primary_ip4"]["id"].as_u64(), Some(ip_id));
    assert_eq!(netbox.list("dcim.interfaces", [("device_id", &entry_id), ("name", "eth0")]).await, Vec::<Value>::new());
    // A tunnel over a VLAN over an aggregate, each a child of the next.
    let interface = |name: &'static str| netbox.one("dcim.interfaces", [("device_id", &entry_id), ("name", name)]);
    let tunnel = interface("VPN_DC2").await;
    let vlan = interface("INTERNET").await;
    assert_eq!((text(&tunnel, "/type/value"), text(&tunnel, "/parent/name")), ("virtual", "INTERNET"));
    assert_eq!(
        (text(&vlan, "/parent/name"), text(&vlan, "/mode/value"), vlan["untagged_vlan"]["vid"].as_u64()),
        ("PO1", "access", Some(954))
    );
    let aggregate = interface("PO2").await;
    assert_eq!((text(&aggregate, "/type/value"), text(&aggregate, "/mode/value")), ("lag", "tagged"));
    // The alias of the interface is its label.
    assert_eq!(text(&aggregate, "/label"), "Port-Channel 2");
    let mut tagged: Vec<u64> =
        aggregate["tagged_vlans"].as_array().expect("tagged VLANs").iter().filter_map(|v| v["vid"].as_u64()).collect();
    tagged.sort_unstable();
    assert_eq!(tagged, [4, 10, 11, 12, 15, 17, 18, 24, 25, 27]);
    let member = interface("x1").await;
    assert_eq!(text(&member, "/lag/name"), "PO2");
    let bridge = interface("lan").await;
    assert_eq!(text(&bridge, "/type/value"), "bridge");
    // The other member keeps what NetBox had.
    assert_eq!(netbox.names("dcim.interfaces", [("device_id", &peer_id)]).await, ["eth0"]);
}
