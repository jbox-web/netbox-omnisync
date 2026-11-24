//! A vCenter served from the recorded answers of a real one, shared by the
//! test files of this crate.

// Each test file uses its own part of these helpers.
#![allow(dead_code)]

use omnisync_vmware::client::{Credentials, VsphereClient};
use serde_json::Value;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The kinds of objects a collection reads.
pub const KINDS: [&str; 8] = [
    "Datacenter",
    "Folder",
    "ClusterComputeResource",
    "ComputeResource",
    "DistributedVirtualSwitch",
    "DistributedVirtualPortgroup",
    "HostSystem",
    "VirtualMachine",
];

pub const COOKIE: &str = "vmware_soap_session=\"52000000-0000-0000-0000-000000000001\"";

/// The fixtures, from the directory of whichever crate of the workspace
/// includes this module: the command line tests read them too.
pub fn fixture(version: &str, name: &str) -> String {
    let file = format!("{}/../vmware/tests/fixtures/{version}/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&file).unwrap_or_else(|error| panic!("{file}: {error}"))
}

pub fn xml(status: u16, body: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_owned(), "text/xml; charset=utf-8")
}

/// One SOAP operation, told by a piece of its body. A mock mounted with a
/// lower `priority` number is preferred: 5 is the default of the recorded answers.
pub async fn mount_soap(server: &MockServer, piece: &str, answer: ResponseTemplate, priority: u8) {
    Mock::given(method("POST"))
        .and(path("/sdk"))
        .and(body_string_contains(piece))
        .respond_with(answer)
        .with_priority(priority)
        .mount(server)
        .await;
}

/// The SOAP side: the session, the eight kinds, the pages, the end.
pub async fn mount_inventory(server: &MockServer, version: &str) {
    let versions = ResponseTemplate::new(200).set_body_raw(fixture(version, "vimServiceVersions.xml"), "text/xml");
    Mock::given(method("GET")).and(path("/sdk/vimServiceVersions.xml")).respond_with(versions).mount(server).await;
    mount_soap(server, "<vim25:RetrieveServiceContent>", xml(200, &fixture(version, "RetrieveServiceContent.xml")), 5)
        .await;
    let login = xml(200, &fixture(version, "Login.xml"))
        .insert_header("Set-Cookie", format!("{COOKIE}; Path=/; HttpOnly; Secure; "));
    mount_soap(server, "<vim25:Login>", login, 5).await;
    for kind in KINDS {
        let view = format!("<vim25:type>{kind}</vim25:type><vim25:recursive>");
        mount_soap(server, &view, xml(200, &fixture(version, &format!("CreateContainerView.{kind}.xml"))), 5).await;
        let properties = format!("<vim25:propSet><vim25:type>{kind}</vim25:type>");
        let page = fixture(version, &format!("RetrievePropertiesEx.{kind}.0.xml"));
        mount_soap(server, &properties, xml(200, &page), 5).await;
    }
    // The only kind in several pages.
    let next = fixture(version, "RetrievePropertiesEx.VirtualMachine.1.xml");
    mount_soap(server, "<vim25:ContinueRetrievePropertiesEx>", xml(200, &next), 5).await;
    mount_soap(server, "<vim25:DestroyView>", xml(200, &fixture(version, "DestroyView.Datacenter.xml")), 5).await;
    let session = fixture(version, "RetrievePropertiesEx.SessionManager.0.xml");
    mount_soap(server, "<vim25:pathSet>currentSession", xml(200, &session), 5).await;
    mount_soap(server, "<vim25:Logout>", xml(200, &fixture(version, "Logout.xml")), 5).await;
}

/// The network systems of the six hosts, by their host.
pub const NETWORK_SYSTEMS: [&str; 6] = [
    "networkSystem-353",
    "networkSystem-33564",
    "networkSystem-53898",
    "networkSystem-10",
    "networkSystem-48488",
    "networkSystem-96885",
];

/// The network system of each host, and the switch port each card of a host
/// hears: asked only by a collection that wants them.
pub async fn mount_hints(server: &MockServer, version: &str) {
    // Preferred to the other properties of the hosts, whose piece it also holds.
    let systems = fixture(version, "RetrievePropertiesEx.HostSystem.networkSystem.xml");
    mount_soap(server, "<vim25:pathSet>configManager.networkSystem</vim25:pathSet>", xml(200, &systems), 4).await;
    for system in NETWORK_SYSTEMS {
        let this = format!("<vim25:_this type=\"HostNetworkSystem\">{system}</vim25:_this>");
        let hint = fixture(version, &format!("QueryNetworkHint.{system}.xml"));
        mount_soap(server, &this, xml(200, &hint), 5).await;
    }
}

/// The REST side: the session and every tag with its objects.
pub async fn mount_tags(server: &MockServer, version: &str) {
    let session = "/rest/com/vmware/cis/session";
    let opened = ResponseTemplate::new(200).set_body_string(fixture(version, "rest.session.json"));
    Mock::given(method("POST")).and(path(session)).respond_with(opened).mount(server).await;
    Mock::given(method("DELETE")).and(path(session)).respond_with(ResponseTemplate::new(200)).mount(server).await;
    let list: Value = serde_json::from_str(&fixture(version, "rest.tag.list.json")).unwrap();
    Mock::given(method("GET"))
        .and(path("/rest/com/vmware/cis/tagging/tag"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&list))
        .mount(server)
        .await;
    for (index, id) in list["value"].as_array().unwrap().iter().enumerate() {
        let id = id.as_str().unwrap();
        let details = ResponseTemplate::new(200).set_body_string(fixture(version, &format!("rest.tag.{index}.json")));
        Mock::given(method("GET"))
            .and(path(format!("/rest/com/vmware/cis/tagging/tag/id:{id}")))
            .respond_with(details)
            .mount(server)
            .await;
        let objects = ResponseTemplate::new(200)
            .set_body_string(fixture(version, &format!("rest.tag.{index}.attached-objects.json")));
        Mock::given(method("POST"))
            .and(path(format!("/rest/com/vmware/cis/tagging/tag-association/id:{id}")))
            .respond_with(objects)
            .mount(server)
            .await;
    }
}

/// A vCenter answering what the one of the fixtures answered.
pub async fn vcenter(version: &str) -> MockServer {
    let server = MockServer::start().await;
    mount_inventory(&server, version).await;
    mount_hints(&server, version).await;
    mount_tags(&server, version).await;
    server
}

pub fn client(server: &MockServer) -> VsphereClient {
    VsphereClient::new(&server.uri(), Credentials::new("sync@vsphere.local", "pw")).unwrap()
}

/// The SOAP method of each request received, or its HTTP method and path.
pub async fn calls(server: &MockServer) -> Vec<String> {
    let requests = server.received_requests().await.unwrap();
    requests.iter().map(call).collect()
}

pub fn call(request: &Request) -> String {
    let body = String::from_utf8_lossy(&request.body);
    match body.split_once("<soapenv:Body><vim25:") {
        Some((_, rest)) => rest.split('>').next().unwrap().to_owned(),
        None => format!("{} {}", request.method, request.url.path()),
    }
}
