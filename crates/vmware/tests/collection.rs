//! The collection of a whole vCenter, on the recorded answers of a real one.

mod common;

use common::{calls, client, fixture, mount_inventory, mount_soap, mount_tags, vcenter, xml};
use omnisync_vmware::client::ClientError;
use omnisync_vmware::collect::{CollectError, Wanted, collect, collect_with};
use omnisync_vmware::model::Reference;
use omnisync_vmware::soap::{CardHint, SwitchPort};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VERSION: &str = "6.7";

#[tokio::test]
async fn a_vcenter_is_read_whole() {
    let server = vcenter(VERSION).await;
    let inventory = collect(&client(&server)).await.expect("inventory");
    assert_eq!(inventory.server, "VMware vCenter Server 6.7.0 build-22509751");
    assert_eq!(inventory.datacenters.len(), 1);
    assert_eq!(inventory.folders.len(), 60);
    assert_eq!(inventory.hosts.len(), 6);
    // 100 on the first page, 66 on the second.
    assert_eq!(inventory.machines.len(), 166);
    assert_eq!(inventory.tags.len(), 28);
    // This vCenter has no distributed switch.
    assert_eq!((inventory.switches.len(), inventory.port_groups.len()), (0, 0));
}

#[tokio::test]
async fn a_cluster_seen_as_a_compute_resource_too_is_one_cluster() {
    let server = vcenter(VERSION).await;
    let inventory = collect(&client(&server)).await.expect("inventory");
    // `domain-c7` is in both answers: a cluster is a compute resource.
    let clusters: Vec<(&str, &str, Option<&str>)> = inventory
        .clusters
        .iter()
        .map(|cluster| (cluster.kind.as_str(), cluster.id.as_str(), cluster.name.as_deref()))
        .collect();
    assert_eq!(clusters, [("ClusterComputeResource", "domain-c7", Some("cluster2"))]);
}

#[tokio::test]
async fn a_host_finds_its_cluster_and_its_datacenter() {
    let server = vcenter(VERSION).await;
    let inventory = collect(&client(&server)).await.expect("inventory");
    let host = inventory.hosts.iter().find(|host| host.id == "host-353").expect("host-353");
    let cluster = inventory.cluster_of(host).expect("cluster");
    assert_eq!(cluster.name.as_deref(), Some("cluster2"));
    // The cluster is in the folder `host` of the datacenter.
    let datacenter = inventory.datacenter_of(cluster.parent.as_ref().expect("parent")).expect("datacenter");
    assert_eq!(datacenter.name.as_deref(), Some("DC1"));
    let nowhere = Reference { kind: "Folder".to_owned(), id: "group-unknown".to_owned() };
    assert_eq!(inventory.datacenter_of(&nowhere), None);
}

#[tokio::test]
async fn the_tags_of_an_object_are_found_by_its_kind_and_id() {
    let server = vcenter(VERSION).await;
    let inventory = collect(&client(&server)).await.expect("inventory");
    let names: Vec<&str> = inventory.tags_of("VirtualMachine", "vm-342").iter().map(|tag| tag.name.as_str()).collect();
    assert!(names.contains(&"service-rabbit"), "{names:?}");
    assert_eq!(inventory.tags_of("HostSystem", "vm-342").len(), 0);
}

#[tokio::test]
async fn a_collection_ends_its_session() {
    let server = vcenter(VERSION).await;
    collect(&client(&server)).await.expect("inventory");
    let calls = calls(&server).await;
    let soap: Vec<&str> = calls.iter().map(String::as_str).filter(|call| !call.contains("/rest/")).collect();
    // The session is checked once everything is read, then ended.
    assert_eq!(soap[soap.len() - 2..], ["RetrievePropertiesEx", "Logout"]);
    assert_eq!(soap.iter().filter(|call| **call == "CreateContainerView").count(), 8);
    assert_eq!(soap.iter().filter(|call| **call == "DestroyView").count(), 8);
}

#[tokio::test]
async fn a_session_lost_on_the_way_fails_the_collection() {
    let server = MockServer::start().await;
    // Without a session a vCenter answers reads with empty results: every
    // kind would look empty, and the session manager shows no session.
    let gone = xml(200, &common::fixture(VERSION, "RetrievePropertiesEx.SessionManager.unauthenticated.xml"));
    mount_soap(&server, "<vim25:pathSet>currentSession", gone, 1).await;
    mount_inventory(&server, VERSION).await;
    mount_tags(&server, VERSION).await;
    let error = collect(&client(&server)).await.expect_err("lost");
    assert_eq!(error, CollectError::Client(ClientError::SessionLost));
    assert_eq!(error.to_string(), "the session ended before the collection did: what was read cannot be trusted");
    // The logout is attempted all the same.
    assert_eq!(calls(&server).await.iter().filter(|call| *call == "Logout").count(), 1);
}

#[tokio::test]
async fn a_vcenter_without_datacenter_is_never_an_inventory() {
    let server = MockServer::start().await;
    let empty = xml(200, &common::fixture(VERSION, "RetrievePropertiesEx.unauthenticated.xml"));
    mount_soap(&server, "<vim25:propSet><vim25:type>Datacenter</vim25:type>", empty, 1).await;
    mount_inventory(&server, VERSION).await;
    mount_tags(&server, VERSION).await;
    let error = collect(&client(&server)).await.expect_err("empty");
    assert_eq!(error, CollectError::Empty);
    assert_eq!(error.to_string(), "the vCenter reports no datacenter: an empty inventory is never synced");
}

#[tokio::test]
async fn tags_that_cannot_be_read_fail_the_collection() {
    let server = MockServer::start().await;
    mount_inventory(&server, VERSION).await;
    let refused = ResponseTemplate::new(401).set_body_string(common::fixture(VERSION, "rest.unauthenticated.json"));
    Mock::given(method("POST")).and(path("/rest/com/vmware/cis/session")).respond_with(refused).mount(&server).await;
    let error = collect(&client(&server)).await.expect_err("no tags");
    assert_eq!(
        error.to_string(),
        "POST /rest/com/vmware/cis/session answered 401: This method requires authentication."
    );
    assert_eq!(calls(&server).await.iter().filter(|call| *call == "Logout").count(), 1);
}

#[tokio::test]
async fn a_kind_that_cannot_be_read_fails_the_collection() {
    let server = MockServer::start().await;
    let fault = xml(500, &common::fixture(VERSION, "CreateContainerView.unauthenticated.xml"));
    mount_soap(&server, "<vim25:type>HostSystem</vim25:type><vim25:recursive>", fault, 1).await;
    mount_inventory(&server, VERSION).await;
    mount_tags(&server, VERSION).await;
    let error = collect(&client(&server)).await.expect_err("fault");
    assert_eq!(error.to_string(), "CreateContainerView: NotAuthenticated: The session is not authenticated.");
    // The REST session of the tags is closed all the same: one left open per
    // failed run would pile up against the session limit of the account.
    let made = calls(&server).await;
    assert!(made.iter().any(|call| call == "POST /rest/com/vmware/cis/session"), "{made:?}");
    assert!(made.iter().any(|call| call == "DELETE /rest/com/vmware/cis/session"), "{made:?}");
}

/// One answer of `RetrievePropertiesEx`, around its `objects`.
fn properties(objects: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n\
         <soapenv:Body>\n<RetrievePropertiesExResponse xmlns=\"urn:vim25\"><returnval>{objects}</returnval>\
         </RetrievePropertiesExResponse>\n</soapenv:Body>\n</soapenv:Envelope>\n"
    )
}

#[tokio::test]
async fn distributed_switches_and_their_port_groups_are_read() {
    // The recorded vCenter has none: these two answers are written by hand,
    // in the shape the vSphere API documents, with the properties the
    // collection asks for.
    let switches = properties(
        "<objects><obj type=\"VmwareDistributedVirtualSwitch\">dvs-21</obj>\
         <propSet><name>name</name><val xsi:type=\"xsd:string\">DSwitch-Prod</val></propSet>\
         <propSet><name>uuid</name><val xsi:type=\"xsd:string\">50 2a 6f 0c 11 22 33 44-55 66 77 88 99 aa bb cc</val>\
         </propSet></objects>",
    );
    let port_groups = properties(
        "<objects><obj type=\"DistributedVirtualPortgroup\">dvportgroup-31</obj>\
         <propSet><name>config.defaultPortConfig</name><val xsi:type=\"VMwareDVSPortSetting\">\
         <vlan xsi:type=\"VmwareDistributedVirtualSwitchVlanIdSpec\"><inherited>false</inherited><vlanId>120</vlanId>\
         </vlan></val></propSet>\
         <propSet><name>config.distributedVirtualSwitch</name>\
         <val type=\"VmwareDistributedVirtualSwitch\" xsi:type=\"ManagedObjectReference\">dvs-21</val></propSet>\
         <propSet><name>key</name><val xsi:type=\"xsd:string\">dvportgroup-31</val></propSet>\
         <propSet><name>name</name><val xsi:type=\"xsd:string\">DPG-Prod-120</val></propSet></objects>\
         <objects><obj type=\"DistributedVirtualPortgroup\">dvportgroup-32</obj>\
         <propSet><name>name</name><val xsi:type=\"xsd:string\">DPG-Orphan</val></propSet></objects>",
    );
    let server = MockServer::start().await;
    let of = |kind: &str| format!("<vim25:propSet><vim25:type>{kind}</vim25:type>");
    mount_soap(&server, &of("DistributedVirtualSwitch"), xml(200, &switches), 1).await;
    mount_soap(&server, &of("DistributedVirtualPortgroup"), xml(200, &port_groups), 1).await;
    mount_inventory(&server, VERSION).await;
    mount_tags(&server, VERSION).await;
    let inventory = collect(&client(&server)).await.expect("inventory");

    let switches: Vec<(&str, Option<&str>, Option<&str>)> = inventory
        .switches
        .iter()
        .map(|switch| (switch.id.as_str(), switch.name.as_deref(), switch.uuid.as_deref()))
        .collect();
    assert_eq!(switches, [("dvs-21", Some("DSwitch-Prod"), Some("50 2a 6f 0c 11 22 33 44-55 66 77 88 99 aa bb cc"))]);

    assert_eq!(inventory.port_groups.len(), 2);
    let group = &inventory.port_groups[0];
    assert_eq!(
        (group.id.as_str(), group.name.as_deref(), group.key.as_deref()),
        ("dvportgroup-31", Some("DPG-Prod-120"), Some("dvportgroup-31"))
    );
    // The switch of a port group is a reference: its kind and its id.
    let switch = Reference { kind: "VmwareDistributedVirtualSwitch".to_owned(), id: "dvs-21".to_owned() };
    assert_eq!(group.switch, Some(switch));
    assert!(group.default_port_config.is_some());
    // A port group that says nothing of its switch is kept, without one.
    let orphan = &inventory.port_groups[1];
    assert_eq!((orphan.name.as_deref(), orphan.key.as_deref()), (Some("DPG-Orphan"), None));
    assert_eq!((&orphan.switch, &orphan.default_port_config), (&None, &None));
}

const HINTS: Wanted = Wanted { hints: true };

#[tokio::test]
async fn the_hints_are_only_asked_when_the_collection_wants_them() {
    let server = vcenter(VERSION).await;
    let inventory = collect(&client(&server)).await.expect("inventory");
    assert!(inventory.hints.is_empty());
    let sent = calls(&server).await;
    assert!(!sent.iter().any(|call| call == "QueryNetworkHint"), "{sent:?}");

    let server = vcenter(VERSION).await;
    let inventory = collect_with(&client(&server), &HINTS).await.expect("inventory");
    let sent = calls(&server).await;
    // One per host, the six of them connected:
    // <name>summary.runtime.connectionState</name><val ...>connected</val>
    assert_eq!(sent.iter().filter(|call| *call == "QueryNetworkHint").count(), 6);
    // The hosts, asked a second time for their network system alone.
    assert_eq!(sent.iter().filter(|call| *call == "CreateContainerView").count(), 9);
    assert_eq!(sent.iter().filter(|call| *call == "DestroyView").count(), 9);
    // RetrievePropertiesEx.HostSystem.networkSystem.xml: <obj type="HostSystem">host-10</obj> ...
    // networkSystem-10; QueryNetworkHint.networkSystem-10.xml: <device>vmnic1</device> ...
    // <devId>nexus04.lab.example(FOC0000A0A4)</devId> ... <portId>Ethernet1/40</portId>
    let heard =
        SwitchPort { device_id: "nexus04.lab.example(FOC0000A0A4)".to_owned(), port_id: "Ethernet1/40".to_owned() };
    assert_eq!(inventory.hints["host-10"][1], CardHint { device: "vmnic1".to_owned(), switch_port: Some(heard) });
    assert_eq!(inventory.hints.len(), 6);
    assert!(inventory.warnings.is_empty(), "{:?}", inventory.warnings);
    // The session is still proven alive after everything, the hints included.
    let soap: Vec<&str> = sent.iter().map(String::as_str).filter(|call| !call.contains("/rest/")).collect();
    assert_eq!(soap[soap.len() - 2..], ["RetrievePropertiesEx", "Logout"]);
}

#[tokio::test]
async fn a_host_whose_hint_fails_is_a_warning_and_the_others_are_read() {
    let server = MockServer::start().await;
    let refused = "<vim25:_this type=\"HostNetworkSystem\">networkSystem-10</vim25:_this>";
    mount_soap(&server, refused, xml(500, &fixture(VERSION, "fault.ContinueRetrievePropertiesEx.xml")), 1).await;
    mount_inventory(&server, VERSION).await;
    common::mount_hints(&server, VERSION).await;
    mount_tags(&server, VERSION).await;
    let inventory = collect_with(&client(&server), &HINTS).await.expect("the other hosts are read");
    assert_eq!(inventory.hints.len(), 5);
    assert!(!inventory.hints.contains_key("host-10"));
    // host-10 is <name>name</name><val xsi:type="xsd:string">esx04.lab.example</val>
    assert_eq!(inventory.warnings.len(), 1, "{:?}", inventory.warnings);
    let warning = &inventory.warnings[0];
    assert!(warning.starts_with("esx04.lab.example: the switch ports its cards hear cannot be read: "), "{warning}");
    assert!(warning.contains("InvalidArgument"), "{warning}");
}

#[tokio::test]
async fn a_collection_that_wants_the_hints_only_sends_reads_and_session_operations() {
    let server = vcenter(VERSION).await;
    collect_with(&client(&server), &HINTS).await.expect("inventory");
    let allowed = [
        "GET /sdk/vimServiceVersions.xml",
        "RetrieveServiceContent",
        "Login",
        "CreateContainerView",
        "RetrievePropertiesEx",
        "ContinueRetrievePropertiesEx",
        "QueryNetworkHint",
        "DestroyView",
        "Logout",
    ];
    for call in calls(&server).await.iter().filter(|call| !call.contains("/rest/")) {
        assert!(allowed.contains(&call.as_str()), "{call}");
    }
}

#[tokio::test]
async fn a_network_system_read_that_fails_is_a_warning_and_the_vcenter_is_read() {
    let server = MockServer::start().await;
    let systems = "<vim25:pathSet>configManager.networkSystem</vim25:pathSet>";
    mount_soap(&server, systems, xml(500, &fixture(VERSION, "fault.ContinueRetrievePropertiesEx.xml")), 1).await;
    mount_inventory(&server, VERSION).await;
    common::mount_hints(&server, VERSION).await;
    mount_tags(&server, VERSION).await;
    let inventory = collect_with(&client(&server), &HINTS).await.expect("the inventory is read");
    assert_eq!(inventory.hosts.len(), 6);
    assert!(inventory.hints.is_empty());
    assert_eq!(inventory.warnings.len(), 1, "{:?}", inventory.warnings);
    assert!(
        inventory.warnings[0].starts_with("the switch ports the cards of the hosts hear cannot be read: "),
        "{}",
        inventory.warnings[0]
    );
}
