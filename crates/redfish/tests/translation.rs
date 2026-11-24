//! The translation of the recorded BMCs, and its reconciliation with a NetBox
//! that holds the server.
//!
//! Every expected value below was read in `tests/fixtures/<family>/api.json`
//! (what was read is quoted above the assertion) or comes from the rule the
//! source follows; none was copied from what the code returns.

use std::collections::BTreeSet;

use omnisync_core::change::Action;
use omnisync_core::inventory::guard::admit;
use omnisync_core::inventory::model::Kind;
use omnisync_core::inventory::reconcile::{Plan, Run, SourceFacts, SourceStatus, ownership_tags, reconcile};
use omnisync_netbox::inventory_apply::apply;
use omnisync_netbox::inventory_state::load;
use omnisync_netbox::testing::FakeGateway;
use omnisync_redfish::translate::{Translation, desired};
use serde_json::json;

mod common;

use common::collected;

const SOURCE: &str = "bmc-a";

/// The facts of a run of the source alone: it never creates a device and never prunes.
fn run() -> Run {
    Run {
        sources: vec![SourceFacts {
            name: SOURCE.to_owned(),
            tag: format!("source-{SOURCE}"),
            status: SourceStatus::Succeeded,
            prune: false,
            create_devices: false,
        }],
        priority: Vec::new(),
        unique_ip_vrfs: BTreeSet::new(),
        source_tag_markers: Vec::new(),
    }
}

/// A server as NetBox holds it before its BMC is read: a generic device type,
/// the serial given, and one interface carrying the MAC address `mac`.
fn server(netbox: &FakeGateway, name: &str, serial: &str, mac: &str) -> u64 {
    let site = netbox.add("dcim.sites", json!({"name": "Paris", "slug": "paris"}));
    let manufacturer = netbox.add("dcim.manufacturers", json!({"name": "Generic Manufacturer", "slug": "generic"}));
    let generic = netbox
        .add("dcim.device_types", json!({"model": "Generic Model", "slug": "generic", "manufacturer": manufacturer}));
    let device =
        netbox.add("dcim.devices", json!({"name": name, "site": site, "device_type": generic, "serial": serial}));
    let interface = netbox.add("dcim.interfaces", json!({"device": device, "name": "eno1", "type": "other"}));
    let assigned =
        json!({"mac_address": mac, "assigned_object_type": "dcim.interface", "assigned_object_id": interface});
    netbox.add("dcim.mac_addresses", assigned);
    device
}

/// The fixture `family`, collected and translated for the device `device`.
async fn translated(family: &str, device: &str) -> Translation {
    desired(SOURCE, device, &format!("drac-{device}"), &collected(family).await)
}

/// Reconciles what a BMC says with NetBox and writes the plan; the warnings of the guard come with it.
async fn synced(netbox: &FakeGateway, translation: &Translation) -> (Plan, Vec<String>) {
    let kinds: BTreeSet<Kind> = Kind::ALL.into();
    let loaded = load(netbox, &kinds).await.expect("NetBox state");
    assert_eq!(loaded.warnings, Vec::<String>::new());
    let (mut objects, refusals) = admit(vec![translation.report.clone()], &loaded.current);
    let facts = run();
    if !objects.is_empty() {
        objects.extend(ownership_tags(&facts, &loaded.current));
    }
    let plan = reconcile(&objects, &loaded.current, &facts);
    let applied = apply(netbox, &plan, || ()).await.expect("applied");
    assert_eq!(applied.written, plan.steps.len());
    (plan, refusals)
}

/// What NetBox holds for a device: the name of its manufacturer, the model of its device type, its serial.
fn hardware(netbox: &FakeGateway, device: u64) -> (String, String, String) {
    let row = netbox.row("dcim.devices", device).unwrap();
    let device_type = netbox.row("dcim.device_types", row["device_type"].as_u64().unwrap()).unwrap();
    let manufacturer = netbox.row("dcim.manufacturers", device_type["manufacturer"].as_u64().unwrap()).unwrap();
    let text = |value: &serde_json::Value| value.as_str().unwrap().to_owned();
    (text(&manufacturer["name"]), text(&device_type["model"]), text(&row["serial"]))
}

/// The actions of a plan, by kind of object.
fn written(plan: &Plan) -> Vec<(&str, Action)> {
    plan.steps.iter().map(|step| (step.change.kind.as_str(), step.change.action)).collect()
}

/// The server of `family` is completed by its BMC, once: the device type is
/// created under its manufacturer, the device gets it and its serial, and the
/// same answer read again writes nothing.
async fn completed_once_then_nothing(family: &str, mac: &str, expected: (&str, &str, &str)) {
    let netbox = FakeGateway::new();
    let device = server(&netbox, "srv01.lab01", "", mac);
    let translation = translated(family, "srv01.lab01").await;
    let (first, refusals) = synced(&netbox, &translation).await;
    assert_eq!(refusals, Vec::<String>::new(), "{family}");
    assert_eq!(first.warnings, Vec::<String>::new(), "{family}");
    // The two ownership tags, the manufacturer, the device type, then the device: never created, updated.
    assert_eq!(
        written(&first),
        [
            ("tag", Action::Create),
            ("tag", Action::Create),
            ("manufacturer", Action::Create),
            ("device_type", Action::Create),
            ("device", Action::Update)
        ],
        "{family}"
    );
    let (manufacturer, model, serial) = hardware(&netbox, device);
    assert_eq!((manufacturer.as_str(), model.as_str(), serial.as_str()), expected, "{family}");
    // The device was completed and nothing else: neither renamed nor tagged.
    let device_step = first.steps.last().unwrap();
    assert_eq!(device_step.change.fields.keys().collect::<Vec<_>>(), ["device_type", "serial"], "{family}");
    let (second, refusals) = synced(&netbox, &translation).await;
    assert_eq!((second.steps.len(), second.warnings.len(), refusals.len()), (0, 0, 0), "{family}");
}

#[tokio::test]
async fn an_idrac_7_completes_its_server_once_and_a_second_run_writes_nothing() {
    // The system: "Manufacturer": "Dell Inc.", "Model": "PowerEdge R620", "SKU": "X8D6622"; the card
    // NIC.Integrated.1-1-1: "MACAddress": "02:00:00:00:00:04". `Dell Inc.` is `Dell` in NetBox.
    completed_once_then_nothing("idrac7-2.65.65.65", "02:00:00:00:00:04", ("Dell", "PowerEdge R620", "X8D6622")).await;
}

#[tokio::test]
async fn an_idrac_8_completes_its_server_once_and_a_second_run_writes_nothing() {
    // The system: "Model": "PowerEdge R630", "SKU": "878X8Z3"; NIC.Slot.1-2-1: "MACAddress": "02:00:00:00:00:13".
    completed_once_then_nothing("idrac8-2.86.86.86", "02:00:00:00:00:13", ("Dell", "PowerEdge R630", "878X8Z3")).await;
    // A blade: "Model": "PowerEdge FC430", "SKU": "8RQZLZ7"; NIC.Embedded.2-1-1: "MACAddress": "02:00:00:00:00:0B".
    completed_once_then_nothing("idrac8-2.83.83.83", "02:00:00:00:00:0B", ("Dell", "PowerEdge FC430", "8RQZLZ7")).await;
}

#[tokio::test]
async fn an_idrac_9_completes_its_server_once_and_a_second_run_writes_nothing() {
    // The system: "Model": "PowerEdge R640", "SKU": "JW1QC50"; NIC.Integrated.1-3-1: "MACAddress": "02:00:00:00:00:17".
    completed_once_then_nothing("idrac9-7.00.00.174", "02:00:00:00:00:17", ("Dell", "PowerEdge R640", "JW1QC50")).await;
    // The system: "Model": "PowerEdge R650", "SKU": "UCUB250"; NIC.Embedded.2-1-1: "MACAddress": "02:00:00:00:00:1D".
    completed_once_then_nothing("idrac9-7.10.90.00", "02:00:00:00:00:1D", ("Dell", "PowerEdge R650", "UCUB250")).await;
}

#[tokio::test]
async fn an_ilo_4_completes_its_server_once_and_a_second_run_writes_nothing() {
    // "/redfish/v1/Systems/1/": "Manufacturer": "HPE", "Model": "ProLiant DL360 Gen9", "SerialNumber": "CBQ260112M";
    // "HostMACAddress": […, "02:00:00:00:00:20", …], which NetBox holds in upper case.
    completed_once_then_nothing("ilo4-2.82", "02:00:00:00:00:20", ("HPE", "ProLiant DL360 Gen9", "CBQ260112M")).await;
}

#[tokio::test]
async fn the_serial_written_for_a_dell_is_never_its_serial_number() {
    // idrac9-7.00.00.174: "SKU": "JW1QC50", "SerialNumber": "KFCAG113SR44CL"
    let translation = translated("idrac9-7.00.00.174", "srv01.lab01").await;
    let device = translation.report.objects.last().unwrap();
    assert_eq!(device.fields["serial"], json!("JW1QC50"));
    let printed = format!("{:?}", translation.report.objects);
    assert!(!printed.contains("KFCAG113SR44CL"), "{printed}");
}

#[tokio::test]
async fn the_serial_written_for_an_hpe_is_never_its_product_reference() {
    // ilo4-2.82: "SKU": "939544-P69", "SerialNumber": "CBQ260112M"
    let translation = translated("ilo4-2.82", "srv01.lab01").await;
    let device = translation.report.objects.last().unwrap();
    assert_eq!(device.fields["serial"], json!("CBQ260112M"));
    let printed = format!("{:?}", translation.report.objects);
    assert!(!printed.contains("939544-P69"), "{printed}");
}

#[tokio::test]
async fn a_serial_made_of_spaces_never_clears_the_one_netbox_has() {
    // ilo4-2.82-blank-serial: "SerialNumber": "                ", "Model": "ProLiant DL360 Gen9",
    // "HostMACAddress": ["02:00:00:00:00:22", …]
    let netbox = FakeGateway::new();
    let device = server(&netbox, "srv01.lab01", "TYPED-BY-HAND", "02:00:00:00:00:22");
    let translation = translated("ilo4-2.82-blank-serial", "srv01.lab01").await;
    let (plan, refusals) = synced(&netbox, &translation).await;
    assert_eq!(refusals, Vec::<String>::new());
    // The device type is known and written; the serial is not, and is left alone.
    let device_step = plan.steps.last().unwrap();
    assert_eq!(device_step.change.fields.keys().collect::<Vec<_>>(), ["device_type"]);
    assert_eq!(
        hardware(&netbox, device),
        ("HPE".to_owned(), "ProLiant DL360 Gen9".to_owned(), "TYPED-BY-HAND".to_owned())
    );
    let (second, _) = synced(&netbox, &translation).await;
    assert_eq!(second.steps.len(), 0);
}

#[tokio::test]
async fn a_permanent_address_netbox_holds_does_not_prove_the_server() {
    // idrac8-2.83.83.83, NIC.Embedded.1-1-1: "MACAddress": "02:00:00:00:00:09",
    // "PermanentMACAddress": "02:00:00:00:00:0A". NetBox holds the permanent one only: the address
    // in use, which is the one a hypervisor reports, is not there.
    let netbox = FakeGateway::new();
    let device = server(&netbox, "srv01.lab01", "", "02:00:00:00:00:0A");
    let translation = translated("idrac8-2.83.83.83", "srv01.lab01").await;
    let (plan, refusals) = synced(&netbox, &translation).await;
    assert_eq!(
        refusals,
        ["device srv01.lab01: none of the 2 MAC address(es) BMC drac-srv01.lab01 reports is on its 1 NetBox \
          interface address(es): wrong BMC for this device?; nothing is written for it"]
    );
    assert_eq!(plan.steps.len(), 0);
    assert_eq!(netbox.writes(), []);
    assert_eq!(hardware(&netbox, device).1, "Generic Model");
}

#[tokio::test]
async fn a_host_name_the_bmc_was_told_short_is_no_mismatch() {
    // idrac7-2.65.65.65: "HostName": "sitea-esx01", for a device NetBox names in full.
    let translation = translated("idrac7-2.65.65.65", "sitea-esx01.example.net").await;
    assert_eq!(translation.warnings, Vec::<String>::new());
    // ilo4-2.82: "HostName": "corp-siteb-pve02", for a device NetBox names siteb-pve02.example.net.
    let translation = desired(SOURCE, "siteb-pve02.example.net", "ilo-siteb-pve02", &collected("ilo4-2.82").await);
    assert_eq!(
        translation.warnings,
        ["device siteb-pve02.example.net: BMC ilo-siteb-pve02 says its server is named corp-siteb-pve02"]
    );
    // The report is whole all the same: "SerialNumber": "CBQ260112M"
    assert_eq!(translation.report.objects.last().unwrap().fields["serial"], json!("CBQ260112M"));
}
