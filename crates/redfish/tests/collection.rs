//! The collection of the recorded BMCs.
//!
//! Every expected value below was read in `tests/fixtures/<family>/api.json`
//! (what was read is quoted above the assertion); none was copied from what
//! the code returns.

use omnisync_redfish::{Bmc, CollectError, collect};
use serde_json::json;

mod common;

use common::{bmc, client, collected, fixture, gets, serve};

const SYSTEM: &str = "/redfish/v1/Systems/System.Embedded.1";
const CARDS: &str = "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces";

fn text(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("(not reported)")
}

fn manager(bmc: &Bmc) -> (&str, &str) {
    let manager = bmc.manager.as_ref().expect("a manager");
    (text(&manager.model), text(&manager.firmware_version))
}

#[tokio::test]
async fn an_idrac_7_is_collected_whole() {
    let bmc = collected("idrac7-2.65.65.65").await;
    // "/redfish/v1/": "RedfishVersion": "1.4.0"
    assert_eq!(text(&bmc.redfish_version), "1.4.0");
    // The system: "Manufacturer": "Dell Inc.", "Model": "PowerEdge R620", "SKU": "X8D6622",
    // "SerialNumber": "BV060139W50268", "HostName": "sitea-esx01"
    assert_eq!(text(&bmc.system.manufacturer), "Dell Inc.");
    assert_eq!(text(&bmc.system.model), "PowerEdge R620");
    assert_eq!(text(&bmc.system.sku), "X8D6622");
    assert_eq!(text(&bmc.system.serial_number), "BV060139W50268");
    assert_eq!(text(&bmc.system.host_name), "sitea-esx01");
    // "/redfish/v1/Managers/iDRAC.Embedded.1": "Model": "12G Monolithic", "FirmwareVersion": "2.65.65.65"
    assert_eq!(manager(&bmc), ("12G Monolithic", "2.65.65.65"));
    // The six members of the Ethernet interfaces, in the order of the collection:
    // NIC.Integrated.1-3-1 "MACAddress": "02:00:00:00:00:02", NIC.Integrated.1-4-1 …:03,
    // NIC.Integrated.1-1-1 …:04, NIC.Integrated.1-2-1 …:05, NIC.Slot.2-1-1 …:06, NIC.Slot.2-2-1 …:07
    assert_eq!(
        bmc.system.mac_addresses,
        [
            "02:00:00:00:00:02",
            "02:00:00:00:00:03",
            "02:00:00:00:00:04",
            "02:00:00:00:00:05",
            "02:00:00:00:00:06",
            "02:00:00:00:00:07"
        ]
    );
}

#[tokio::test]
async fn an_idrac_8_is_collected_whole() {
    let bmc = collected("idrac8-2.86.86.86").await;
    // "/redfish/v1/": "RedfishVersion": "1.4.0"
    assert_eq!(text(&bmc.redfish_version), "1.4.0");
    // The system: "Manufacturer": "Dell Inc.", "Model": "PowerEdge R630", "SKU": "878X8Z3",
    // "SerialNumber": "FWFNU8514L6547", "HostName": "pve01.lab01"
    assert_eq!(text(&bmc.system.manufacturer), "Dell Inc.");
    assert_eq!(text(&bmc.system.model), "PowerEdge R630");
    assert_eq!(text(&bmc.system.sku), "878X8Z3");
    assert_eq!(text(&bmc.system.serial_number), "FWFNU8514L6547");
    assert_eq!(text(&bmc.system.host_name), "pve01.lab01");
    // "/redfish/v1/Managers/iDRAC.Embedded.1": "Model": "13G Monolithic", "FirmwareVersion": "2.86.86.86"
    assert_eq!(manager(&bmc), ("13G Monolithic", "2.86.86.86"));
    // NIC.Integrated.1-1-1 "MACAddress": "02:00:00:00:00:0E", then 1-2-1 …:0F, 1-3-1 …:10, 1-4-1 …:11,
    // NIC.Slot.1-1-1 …:12, NIC.Slot.1-2-1 …:13
    assert_eq!(
        bmc.system.mac_addresses,
        [
            "02:00:00:00:00:0E",
            "02:00:00:00:00:0F",
            "02:00:00:00:00:10",
            "02:00:00:00:00:11",
            "02:00:00:00:00:12",
            "02:00:00:00:00:13"
        ]
    );
}

#[tokio::test]
async fn the_address_in_use_is_read_never_the_permanent_one() {
    // A blade (iDRAC 8, "Model": "13G Modular") whose two cards each have another address than the
    // one they were made with.
    let bmc = collected("idrac8-2.83.83.83").await;
    // The system: "Model": "PowerEdge FC430", "SKU": "8RQZLZ7", "SerialNumber": "EB7659403Z0381",
    // "HostName": "esx02.lab01"
    assert_eq!(text(&bmc.system.model), "PowerEdge FC430");
    assert_eq!(text(&bmc.system.sku), "8RQZLZ7");
    assert_eq!(text(&bmc.system.serial_number), "EB7659403Z0381");
    assert_eq!(text(&bmc.system.host_name), "esx02.lab01");
    assert_eq!(manager(&bmc), ("13G Modular", "2.83.83.83"));
    // NIC.Embedded.1-1-1: "MACAddress": "02:00:00:00:00:09", "PermanentMACAddress": "02:00:00:00:00:0A"
    // NIC.Embedded.2-1-1: "MACAddress": "02:00:00:00:00:0B", "PermanentMACAddress": "02:00:00:00:00:0C"
    assert_eq!(bmc.system.mac_addresses, ["02:00:00:00:00:09", "02:00:00:00:00:0B"]);
}

#[tokio::test]
async fn an_idrac_9_is_collected_whole() {
    let bmc = collected("idrac9-7.00.00.174").await;
    // "/redfish/v1/": "RedfishVersion": "1.17.0"
    assert_eq!(text(&bmc.redfish_version), "1.17.0");
    // The system: "Manufacturer": "Dell Inc.", "Model": "PowerEdge R640", "SKU": "JW1QC50",
    // "SerialNumber": "KFCAG113SR44CL", "HostName": "esx03.lab01"
    assert_eq!(text(&bmc.system.manufacturer), "Dell Inc.");
    assert_eq!(text(&bmc.system.model), "PowerEdge R640");
    assert_eq!(text(&bmc.system.sku), "JW1QC50");
    assert_eq!(text(&bmc.system.serial_number), "KFCAG113SR44CL");
    assert_eq!(text(&bmc.system.host_name), "esx03.lab01");
    // "/redfish/v1/Managers/iDRAC.Embedded.1": "Model": "14G Monolithic", "FirmwareVersion": "7.00.00.174"
    assert_eq!(manager(&bmc), ("14G Monolithic", "7.00.00.174"));
    // In the order of the collection: NIC.Integrated.1-2-1 "MACAddress": "02:00:00:00:00:15",
    // NIC.Integrated.1-1-1 …:16, NIC.Integrated.1-3-1 …:17, NIC.Integrated.1-4-1 …:18
    assert_eq!(
        bmc.system.mac_addresses,
        ["02:00:00:00:00:15", "02:00:00:00:00:16", "02:00:00:00:00:17", "02:00:00:00:00:18"]
    );

    // A later generation and firmware of the same family.
    let bmc = collected("idrac9-7.10.90.00").await;
    // "/redfish/v1/": "RedfishVersion": "1.20.1"
    assert_eq!(text(&bmc.redfish_version), "1.20.1");
    // The system: "Model": "PowerEdge R650", "SKU": "UCUB250", "SerialNumber": "CKEUT0237416TB",
    // "HostName": "esx04.lab01"
    assert_eq!(text(&bmc.system.model), "PowerEdge R650");
    assert_eq!(text(&bmc.system.sku), "UCUB250");
    assert_eq!(text(&bmc.system.serial_number), "CKEUT0237416TB");
    assert_eq!(text(&bmc.system.host_name), "esx04.lab01");
    // "Model": "15G Monolithic", "FirmwareVersion": "7.10.90.00"
    assert_eq!(manager(&bmc), ("15G Monolithic", "7.10.90.00"));
    // NIC.Slot.2-1-1 "MACAddress": "02:00:00:00:00:1A", NIC.Slot.2-2-1 …:1B, NIC.Embedded.1-1-1 …:1C,
    // NIC.Embedded.2-1-1 …:1D
    assert_eq!(
        bmc.system.mac_addresses,
        ["02:00:00:00:00:1A", "02:00:00:00:00:1B", "02:00:00:00:00:1C", "02:00:00:00:00:1D"]
    );
}

#[tokio::test]
async fn an_ilo_4_is_collected_whole() {
    let bmc = collected("ilo4-2.82").await;
    // "/redfish/v1/": "RedfishVersion": "1.0.0"
    assert_eq!(text(&bmc.redfish_version), "1.0.0");
    // "/redfish/v1/Systems/1/": "Manufacturer": "HPE", "Model": "ProLiant DL360 Gen9", "SKU": "939544-P69",
    // "SerialNumber": "CBQ260112M", "HostName": "corp-siteb-pve02"
    assert_eq!(text(&bmc.system.manufacturer), "HPE");
    assert_eq!(text(&bmc.system.model), "ProLiant DL360 Gen9");
    assert_eq!(text(&bmc.system.sku), "939544-P69");
    assert_eq!(text(&bmc.system.serial_number), "CBQ260112M");
    assert_eq!(text(&bmc.system.host_name), "corp-siteb-pve02");
    // "/redfish/v1/Managers/1/", found through "links": {"ManagedBy": [{"href": "/redfish/v1/Managers/1/"}]}:
    // no "Model", "FirmwareVersion": "iLO 4 v2.82"
    assert_eq!(manager(&bmc), ("(not reported)", "iLO 4 v2.82"));
    // "HostCorrelation": {"HostMACAddress": ["02:00:00:00:00:1e", "02:00:00:00:00:1f", "02:00:00:00:00:20",
    // "02:00:00:00:00:21"], …}
    assert_eq!(
        bmc.system.mac_addresses,
        ["02:00:00:00:00:1e", "02:00:00:00:00:1f", "02:00:00:00:00:20", "02:00:00:00:00:21"]
    );
}

#[tokio::test]
async fn a_serial_made_of_spaces_is_not_reported() {
    let bmc = collected("ilo4-2.82-blank-serial").await;
    // "/redfish/v1/Systems/1/": "SKU": "                ", "SerialNumber": "                " (sixteen
    // spaces each), "HostName": ""
    assert_eq!(bmc.system.sku, None);
    assert_eq!(bmc.system.serial_number, None);
    assert_eq!(bmc.system.host_name, None);
    // What the system does say is read all the same: "Manufacturer": "HPE", "Model": "ProLiant DL360 Gen9"
    assert_eq!(text(&bmc.system.manufacturer), "HPE");
    assert_eq!(text(&bmc.system.model), "ProLiant DL360 Gen9");
    // "HostMACAddress": ["02:00:00:00:00:22", "02:00:00:00:00:23", "02:00:00:00:00:24", "02:00:00:00:00:25"]
    assert_eq!(
        bmc.system.mac_addresses,
        ["02:00:00:00:00:22", "02:00:00:00:00:23", "02:00:00:00:00:24", "02:00:00:00:00:25"]
    );
}

#[tokio::test]
async fn the_collection_only_ever_reads_and_asks_each_recorded_answer_once() {
    // The number of requests is the number of answers of the fixture: the root, the systems, the
    // system, its manager, its Ethernet interfaces and each card. Every one is a GET (`gets`).
    //   idrac7-2.65.65.65: 5 + 6 cards; idrac8-2.83.83.83: 5 + 2; idrac8-2.86.86.86: 5 + 6;
    //   idrac9-7.00.00.174: 5 + 4; idrac9-7.10.90.00: 5 + 4.
    // An iLO 4 gives the addresses in its system and is not asked for its cards: the root, the
    // systems twice (the 308, then the path with its final `/`), the system and its manager.
    let families = [
        ("idrac7-2.65.65.65", 11),
        ("idrac8-2.83.83.83", 7),
        ("idrac8-2.86.86.86", 11),
        ("idrac9-7.00.00.174", 9),
        ("idrac9-7.10.90.00", 9),
        ("ilo4-2.82", 5),
        ("ilo4-2.82-blank-serial", 5),
    ];
    for (family, expected) in families {
        let answers = fixture(family);
        let server = bmc(family).await;
        collect(&client(&server)).await.unwrap();
        let mut asked = gets(&server).await;
        assert_eq!(asked.len(), expected, "{family}: {asked:?}");
        // Nothing outside the fixture, and nothing twice.
        asked.sort();
        let mut recorded: Vec<String> = answers.into_keys().collect();
        recorded.sort();
        assert_eq!(asked, recorded, "{family}");
    }
}

#[tokio::test]
async fn the_calls_of_an_idrac_are_made_in_order_one_after_the_other() {
    let server = bmc("idrac8-2.83.83.83").await;
    collect(&client(&server)).await.unwrap();
    assert_eq!(
        gets(&server).await,
        [
            "/redfish/v1/",
            "/redfish/v1/Systems",
            SYSTEM,
            "/redfish/v1/Managers/iDRAC.Embedded.1",
            CARDS,
            "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Embedded.1-1-1",
            "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Embedded.2-1-1",
        ]
    );
}

#[tokio::test]
async fn the_308_of_an_ilo_4_is_asked_again_with_its_final_slash() {
    // "/redfish/v1/Systems": {"status": 308, "body": ""}
    let server = bmc("ilo4-2.82").await;
    collect(&client(&server)).await.unwrap();
    assert_eq!(
        gets(&server).await,
        [
            "/redfish/v1/",
            "/redfish/v1/Systems",
            "/redfish/v1/Systems/",
            "/redfish/v1/Systems/1/",
            "/redfish/v1/Managers/1/"
        ]
    );
}

#[tokio::test]
async fn a_bmc_that_refuses_the_account_fails_the_collection_without_showing_it() {
    let server = bmc("idrac9-7.00.00.174").await;
    let stranger = omnisync_redfish::Credentials::new(common::USER, "another password");
    let client = omnisync_redfish::RedfishClient::new(&server.uri(), stranger).unwrap();
    let error = collect(&client).await.unwrap_err();
    // The root is given to anybody; the systems are not.
    assert_eq!(error.to_string(), "GET /redfish/v1/Systems answered 401: Unauthorized");
    assert!(!format!("{error:?}").contains("0perator"), "{error:?}");
}

#[tokio::test]
async fn a_bmc_without_system_is_an_error_never_an_empty_server() {
    let mut answers = fixture("idrac8-2.86.86.86");
    answers.insert("/redfish/v1/Systems".to_owned(), (200, json!({"Members": [], "Members@odata.count": 0})));
    let server = serve(answers).await;
    let error = collect(&client(&server)).await.unwrap_err();
    assert_eq!(error.to_string(), "GET /redfish/v1/Systems: no system in the answer");
    assert!(matches!(error, CollectError::Unexpected { .. }));
}

#[tokio::test]
async fn a_card_that_cannot_be_read_fails_the_whole_bmc() {
    let mut answers = fixture("idrac8-2.83.83.83");
    answers.insert(format!("{CARDS}/NIC.Embedded.2-1-1"), (500, json!({"error": {"message": "internal"}})));
    let server = serve(answers).await;
    let error = collect(&client(&server)).await.unwrap_err();
    let expected = format!("GET {CARDS}/NIC.Embedded.2-1-1 answered 500: ");
    assert!(error.to_string().starts_with(&expected), "{error}");
}

#[tokio::test]
async fn a_path_of_a_bmc_that_is_not_one_of_the_closed_list_is_never_asked() {
    // A system that names something else than a manager as its manager.
    let mut answers = fixture("idrac8-2.83.83.83");
    let (status, mut system) = answers[SYSTEM].clone();
    system["Links"]["ManagedBy"] = json!([{"@odata.id": "/redfish/v1/AccountService/Accounts/2"}]);
    answers.insert(SYSTEM.to_owned(), (status, system));
    let server = serve(answers).await;
    let error = collect(&client(&server)).await.unwrap_err();
    assert_eq!(error.to_string(), "Redfish client: a manager is not at a path of the closed list");
    assert_eq!(gets(&server).await, ["/redfish/v1/", "/redfish/v1/Systems", SYSTEM]);
}

#[tokio::test]
async fn a_system_that_links_to_no_manager_is_read_without_one() {
    let mut answers = fixture("idrac8-2.83.83.83");
    let (status, mut system) = answers[SYSTEM].clone();
    system["Links"].as_object_mut().unwrap().remove("ManagedBy");
    answers.insert(SYSTEM.to_owned(), (status, system));
    let server = serve(answers).await;
    let bmc = collect(&client(&server)).await.unwrap();
    assert_eq!(bmc.manager, None);
    // "SKU": "8RQZLZ7"
    assert_eq!(text(&bmc.system.sku), "8RQZLZ7");
}

// "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces" of iDRAC 9
// gives its 4 members with `"Members@odata.count": 4`. A BMC that pages a
// collection gives some, the count of all, and `Members@odata.nextLink`: read
// as a whole, it would be a server with fewer cards, and its MAC proof wrong.
#[tokio::test]
async fn a_collection_given_in_pages_is_never_read_as_a_whole() {
    let mut answers = fixture("idrac9-7.10.90.00");
    let interfaces = "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces";
    let (_, body) = answers.get_mut(interfaces).unwrap();
    body["Members"].as_array_mut().unwrap().pop();
    body["Members@odata.nextLink"] = serde_json::json!(format!("{interfaces}?$skip=3"));
    let server = serve(answers).await;
    let error = collect(&client(&server)).await.expect_err("a collection in pages");
    assert_eq!(
        error.to_string(),
        format!("GET {interfaces}: 3 of 4 members given, the rest in pages that are never asked")
    );
}

#[tokio::test]
async fn a_collection_that_counts_more_members_than_it_gives_is_never_read_as_a_whole() {
    // Fewer members than the count, and no link to the rest: still not the whole.
    let mut answers = fixture("idrac9-7.10.90.00");
    let (_, body) = answers.get_mut(CARDS).unwrap();
    body["Members"].as_array_mut().unwrap().pop();
    let server = serve(answers).await;
    let error = collect(&client(&server)).await.expect_err("a collection cut short");
    assert_eq!(error.to_string(), format!("GET {CARDS}: 3 of 4 members given, the rest in pages that are never asked"));
}

#[tokio::test]
async fn a_collection_in_pages_that_gives_no_count_is_never_read_as_a_whole() {
    // The count is optional in Redfish: the link to a next page alone says there is more.
    let mut answers = fixture("idrac9-7.10.90.00");
    let (_, body) = answers.get_mut(CARDS).unwrap();
    body.as_object_mut().unwrap().remove("Members@odata.count");
    body["Members@odata.nextLink"] = json!(format!("{CARDS}?$skip=4"));
    let server = serve(answers).await;
    let error = collect(&client(&server)).await.expect_err("a collection in pages");
    assert_eq!(error.to_string(), format!("GET {CARDS}: 4 members given, the rest in pages that are never asked"));
}

#[tokio::test]
async fn an_answer_of_another_shape_is_an_error_that_does_not_quote_it() {
    let mut answers = fixture("idrac9-7.10.90.00");
    answers.insert("/redfish/v1/Systems".to_owned(), (200, json!({"Members": "s3cret-in-the-answer"})));
    let server = serve(answers).await;
    let error = collect(&client(&server)).await.expect_err("another shape");
    assert_eq!(error.to_string(), "GET /redfish/v1/Systems: the answer does not have the expected shape");
    assert!(!format!("{error:?}").contains("s3cret"), "{error:?}");
}

#[tokio::test]
async fn a_system_that_lists_no_card_is_read_without_address() {
    // No address is no proof: the translation then leaves the device alone.
    let mut answers = fixture("idrac9-7.10.90.00");
    let (status, mut system) = answers[SYSTEM].clone();
    system.as_object_mut().unwrap().remove("EthernetInterfaces");
    answers.insert(SYSTEM.to_owned(), (status, system));
    let server = serve(answers).await;
    let bmc = collect(&client(&server)).await.unwrap();
    assert_eq!(bmc.system.mac_addresses, Vec::<String>::new());
    assert!(!gets(&server).await.iter().any(|path| path.starts_with(CARDS)));
}

#[tokio::test]
async fn a_collection_without_count_nor_next_page_is_the_whole() {
    // The count is optional: without it and without a link to a next page,
    // what is given is all there is, and the BMC is read as usual.
    let whole = collected("idrac9-7.10.90.00").await;
    let mut answers = fixture("idrac9-7.10.90.00");
    let (_, body) = answers.get_mut(CARDS).unwrap();
    body.as_object_mut().unwrap().remove("Members@odata.count");
    let server = serve(answers).await;
    let bmc = collect(&client(&server)).await.expect("a whole collection");
    assert_eq!(bmc.system.mac_addresses.len(), 4);
    assert_eq!(bmc.system.mac_addresses, whole.system.mac_addresses);
}
