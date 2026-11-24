//! The SOAP side of the vSphere API (`urn:vim25`): the requests this source
//! may send, and what it reads in the answers.
//!
//! The list of operations is closed: [`Operation`] has a variant per request,
//! every one a read or a session operation, and nothing else can be turned
//! into an envelope.

use std::collections::BTreeMap;

use roxmltree::{Document, Node};

use crate::xml::{Element, escape};

/// The dialects of the API this source was written and tested against, the
/// preferred one first. A vCenter is spoken to in the first one it lists:
/// a newer server answers an older dialect as an older server would.
pub const DIALECTS: [&str; 1] = ["6.7"];

/// The namespace of the API, also the start of the `SOAPAction` header.
pub const NAMESPACE: &str = "urn:vim25";

/// A request this source may send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation<'a> {
    /// What the server is, and the managed objects to talk to. Needs no session.
    RetrieveServiceContent,
    Login {
        session_manager: &'a str,
        username: &'a str,
        password: &'a str,
    },
    /// A view of every object of `kind` under `root`, sub-folders included.
    CreateContainerView {
        view_manager: &'a str,
        root: &'a str,
        kind: &'a str,
    },
    /// The first page of `properties` of the objects of a view.
    RetrieveProperties {
        collector: &'a str,
        view: &'a str,
        kind: &'a str,
        properties: &'a [&'a str],
        page_size: u32,
    },
    /// The session this request is made in, as the session manager sees it.
    RetrieveCurrentSession {
        collector: &'a str,
        session_manager: &'a str,
    },
    /// The next page, by the token of the previous one.
    ContinueRetrieveProperties {
        collector: &'a str,
        token: &'a str,
    },
    DestroyView {
        view: &'a str,
    },
    /// The switch port each physical card of a host hears (CDP), as the
    /// network system of the host knows it. A read.
    QueryNetworkHint {
        network_system: &'a str,
    },
    Logout {
        session_manager: &'a str,
    },
}

/// What every envelope starts and ends with.
const ENVELOPE_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope \
    xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vim25=\"urn:vim25\"><soapenv:Body>";
const ENVELOPE_TAIL: &str = "</soapenv:Body></soapenv:Envelope>";

/// `<vim25:_this type="…">…</vim25:_this>`: the managed object a request is sent to.
fn this(kind: &str, id: &str) -> String {
    format!("<vim25:_this type=\"{kind}\">{}</vim25:_this>", escape(id))
}

impl Operation<'_> {
    /// The name of the SOAP method.
    pub fn name(&self) -> &'static str {
        match self {
            Operation::RetrieveServiceContent => "RetrieveServiceContent",
            Operation::Login { .. } => "Login",
            Operation::CreateContainerView { .. } => "CreateContainerView",
            Operation::RetrieveProperties { .. } | Operation::RetrieveCurrentSession { .. } => "RetrievePropertiesEx",
            Operation::ContinueRetrieveProperties { .. } => "ContinueRetrievePropertiesEx",
            Operation::DestroyView { .. } => "DestroyView",
            Operation::QueryNetworkHint { .. } => "QueryNetworkHint",
            Operation::Logout { .. } => "Logout",
        }
    }

    /// What the method carries.
    fn arguments(&self) -> String {
        match self {
            Operation::RetrieveServiceContent => this("ServiceInstance", "ServiceInstance"),
            Operation::Login { session_manager, username, password } => format!(
                "{}<vim25:userName>{}</vim25:userName><vim25:password>{}</vim25:password>",
                this("SessionManager", session_manager),
                escape(username),
                escape(password)
            ),
            Operation::CreateContainerView { view_manager, root, kind } => format!(
                "{}<vim25:container type=\"Folder\">{}</vim25:container><vim25:type>{}</vim25:type>\
                 <vim25:recursive>true</vim25:recursive>",
                this("ViewManager", view_manager),
                escape(root),
                escape(kind)
            ),
            Operation::RetrieveProperties { collector, view, kind, properties, page_size } => {
                let paths: String =
                    properties.iter().map(|path| format!("<vim25:pathSet>{}</vim25:pathSet>", escape(path))).collect();
                // The view itself is skipped; its `view` property leads to the objects.
                format!(
                    "{}<vim25:specSet><vim25:propSet><vim25:type>{}</vim25:type>{paths}</vim25:propSet>\
                     <vim25:objectSet><vim25:obj type=\"ContainerView\">{}</vim25:obj><vim25:skip>true</vim25:skip>\
                     <vim25:selectSet xsi:type=\"vim25:TraversalSpec\"><vim25:name>view</vim25:name>\
                     <vim25:type>ContainerView</vim25:type><vim25:path>view</vim25:path>\
                     <vim25:skip>false</vim25:skip></vim25:selectSet></vim25:objectSet></vim25:specSet>\
                     <vim25:options><vim25:maxObjects>{page_size}</vim25:maxObjects></vim25:options>",
                    this("PropertyCollector", collector),
                    escape(kind),
                    escape(view)
                )
            }
            Operation::RetrieveCurrentSession { collector, session_manager } => format!(
                "{}<vim25:specSet><vim25:propSet><vim25:type>SessionManager</vim25:type>\
                 <vim25:pathSet>currentSession</vim25:pathSet></vim25:propSet><vim25:objectSet>\
                 <vim25:obj type=\"SessionManager\">{}</vim25:obj></vim25:objectSet></vim25:specSet><vim25:options/>",
                this("PropertyCollector", collector),
                escape(session_manager)
            ),
            Operation::ContinueRetrieveProperties { collector, token } => {
                format!("{}<vim25:token>{}</vim25:token>", this("PropertyCollector", collector), escape(token))
            }
            Operation::DestroyView { view } => this("ContainerView", view),
            // No device named: every card of the host.
            Operation::QueryNetworkHint { network_system } => this("HostNetworkSystem", network_system),
            Operation::Logout { session_manager } => this("SessionManager", session_manager),
        }
    }

    /// The whole request body.
    pub fn envelope(&self) -> String {
        let name = self.name();
        format!("{ENVELOPE_HEAD}<vim25:{name}>{}</vim25:{name}>{ENVELOPE_TAIL}", self.arguments())
    }
}

/// The first element child of this name, whatever its namespace.
fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|child| child.is_element() && child.tag_name().name() == name)
}

/// The text of the first element child of this name; empty when it has none.
fn child_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name).map(|child| Element::of(child).text)
}

/// Deeper than any answer of vSphere: the answers are read recursively, and
/// roxmltree bounds the depth of entities, not of elements.
const MAX_DEPTH: usize = 64;

/// The document of an answer, refused when deeper than [`MAX_DEPTH`]: a few
/// thousand nested elements would overflow the stack of the task reading it,
/// and end the whole run.
fn parse(text: &str) -> Result<Document<'_>, String> {
    let document = Document::parse(text).map_err(|error| format!("not XML: {error}"))?;
    // Each element is at most MAX_DEPTH + 1 nodes below the root once the check passes
    // for every element, so the count of ancestors is bounded as well.
    let deeper = document.descendants().any(|node| node.is_element() && node.ancestors().nth(MAX_DEPTH + 1).is_some());
    if deeper {
        return Err(format!("an answer nested deeper than {MAX_DEPTH} elements"));
    }
    Ok(document)
}

/// The answer as a document, and the content of its SOAP body through `read`.
fn in_body<T>(answer: &str, read: impl FnOnce(Node<'_, '_>) -> Result<T, String>) -> Result<T, String> {
    let document = parse(answer)?;
    let envelope = document.root_element();
    if envelope.tag_name().name() != "Envelope" {
        return Err("not a SOAP envelope".to_owned());
    }
    read(child(envelope, "Body").ok_or("a SOAP envelope without body")?)
}

/// A fault the server answered instead of a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// The vSphere type of the fault: `NotAuthenticated`, `InvalidLogin`.
    pub kind: String,
    pub message: String,
}

/// The fault of an answer, None when the answer is a result.
pub fn fault(answer: &str) -> Result<Option<Fault>, String> {
    in_body(answer, |body| {
        let Some(fault) = child(body, "Fault") else {
            return Ok(None);
        };
        let detail = child(fault, "detail").and_then(|detail| detail.children().find(Node::is_element));
        // `<NotAuthenticatedFault xsi:type="NotAuthenticated">`: the type, or the name without its suffix.
        let kind = detail
            .map(Element::of)
            .map(|detail| detail.xsi_type.unwrap_or_else(|| detail.name.trim_end_matches("Fault").to_owned()));
        Ok(Some(Fault {
            kind: kind.unwrap_or_else(|| "Fault".to_owned()),
            message: child_text(fault, "faultstring").unwrap_or_default(),
        }))
    })
}

/// What `RetrieveServiceContent` tells: the server, and whom to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContent {
    pub root_folder: String,
    pub property_collector: String,
    pub view_manager: String,
    pub session_manager: String,
    /// `VMware vCenter Server 6.7.0 build-22509751`.
    pub full_name: String,
    pub api_version: String,
}

pub fn service_content(answer: &str) -> Result<ServiceContent, String> {
    in_body(answer, |body| {
        let content = child(body, "RetrieveServiceContentResponse")
            .and_then(|response| child(response, "returnval"))
            .ok_or("no RetrieveServiceContentResponse in the answer")?;
        let named = |node: Node<'_, '_>, name: &str| {
            child_text(node, name).filter(|text| !text.is_empty()).ok_or(format!("no {name} in the service content"))
        };
        let about = child(content, "about").ok_or("no about in the service content")?;
        Ok(ServiceContent {
            root_folder: named(content, "rootFolder")?,
            property_collector: named(content, "propertyCollector")?,
            view_manager: named(content, "viewManager")?,
            session_manager: named(content, "sessionManager")?,
            full_name: named(about, "fullName")?,
            api_version: named(about, "apiVersion")?,
        })
    })
}

/// The versions of the API a server lists in `vimServiceVersions.xml`, the
/// current one first.
pub fn versions(document: &str) -> Result<Vec<String>, String> {
    let document = parse(document)?;
    let namespaces = document.root_element().children().filter(|node| node.tag_name().name() == "namespace");
    let ours = namespaces
        .into_iter()
        .find(|namespace| child_text(*namespace, "name").as_deref() == Some(NAMESPACE))
        .ok_or(format!("no {NAMESPACE} among the namespaces of the server"))?;
    let current = child_text(ours, "version").ok_or("no version of the API")?;
    let prior = child(ours, "priorVersions").into_iter().flat_map(|prior| {
        prior.children().filter(|node| node.tag_name().name() == "version").map(|version| Element::of(version).text)
    });
    Ok(std::iter::once(current).chain(prior).collect())
}

/// The dialect to speak to a server that lists these versions.
pub fn dialect(versions: &[String]) -> Result<&'static str, String> {
    DIALECTS.into_iter().find(|dialect| versions.iter().any(|version| version == dialect)).ok_or_else(|| {
        format!("the server speaks vSphere API {} and this build speaks {}", versions.join(", "), DIALECTS.join(", "))
    })
}

/// The view a `CreateContainerView` answer names.
pub fn view(answer: &str) -> Result<String, String> {
    in_body(answer, |body| {
        child(body, "CreateContainerViewResponse")
            .and_then(|response| child_text(response, "returnval"))
            .filter(|view| !view.is_empty())
            .ok_or("no view in the answer".to_owned())
    })
}

/// A managed object and the properties that were asked for and that it has.
/// A property the object does not have is absent, never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectContent {
    pub kind: String,
    pub id: String,
    /// The `val` element of each property, by property path.
    pub properties: BTreeMap<String, Element>,
}

impl ObjectContent {
    /// The text of a property with a simple value.
    pub fn text(&self, property: &str) -> Option<&str> {
        self.properties.get(property).map(|value| value.text.as_str())
    }

    fn of(node: Node<'_, '_>) -> Result<Self, String> {
        let reference = child(node, "obj").map(Element::of).ok_or("an object without reference")?;
        let kind = reference.reference.ok_or("an object reference without type")?;
        let mut properties = BTreeMap::new();
        for property in node.children().filter(|child| child.tag_name().name() == "propSet") {
            let name = child_text(property, "name").ok_or("a property without name")?;
            let value = child(property, "val").ok_or(format!("property {name} without value"))?;
            properties.insert(name, Element::of(value));
        }
        Ok(ObjectContent { kind, id: reference.text, properties })
    }
}

/// One page of a property retrieval.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub objects: Vec<ObjectContent>,
    /// Set when more pages follow.
    pub token: Option<String>,
}

/// The page of a `RetrievePropertiesEx` or `ContinueRetrievePropertiesEx` answer.
pub fn page(answer: &str) -> Result<Page, String> {
    in_body(answer, |body| {
        let response = child(body, "RetrievePropertiesExResponse")
            .or_else(|| child(body, "ContinueRetrievePropertiesExResponse"))
            .ok_or("no property retrieval in the answer")?;
        // Nothing to return: the response has no `returnval` at all.
        let Some(result) = child(response, "returnval") else {
            return Ok(Page::default());
        };
        let objects = result.children().filter(|child| child.tag_name().name() == "objects");
        Ok(Page {
            objects: objects.map(ObjectContent::of).collect::<Result<_, _>>()?,
            token: child_text(result, "token").filter(|token| !token.is_empty()),
        })
    })
}

/// Whether a `RetrieveCurrentSession` answer shows a session: without one the
/// server answers the same object, without the property.
pub fn session_is_alive(answer: &str) -> Result<bool, String> {
    let page = page(answer)?;
    let sessions = page.objects.iter().filter_map(|object| object.properties.get("currentSession"));
    Ok(sessions.into_iter().any(|session| session.text_at("key").is_some_and(|key| !key.is_empty())))
}

/// The switch port a physical card hears, as the switch announces it by CDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchPort {
    /// `devId`: the name of the switch, as it gives it (with a domain, or the
    /// serial of a Nexus between parentheses).
    pub device_id: String,
    /// `portId`: the port of the switch, as it names it.
    pub port_id: String,
}

/// What `QueryNetworkHint` tells of one physical card of a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardHint {
    /// The card, as the host names it (`vmnic0`).
    pub device: String,
    /// None when the card hears no switch: unknown, never "no cable".
    pub switch_port: Option<SwitchPort>,
}

/// The cards of a `QueryNetworkHint` answer, in the order of the host.
pub fn network_hints(answer: &str) -> Result<Vec<CardHint>, String> {
    in_body(answer, |body| {
        let response = child(body, "QueryNetworkHintResponse").ok_or("no QueryNetworkHintResponse in the answer")?;
        let cards = response.children().filter(|child| child.tag_name().name() == "returnval");
        cards
            .map(|card| {
                let device =
                    child_text(card, "device").filter(|device| !device.is_empty()).ok_or("a card without name")?;
                // A port told without the switch, or the reverse, says nothing of the cable.
                let switch_port = child(card, "connectedSwitchPort").and_then(|port| {
                    let device_id = child_text(port, "devId").filter(|id| !id.trim().is_empty())?;
                    let port_id = child_text(port, "portId").filter(|id| !id.trim().is_empty())?;
                    Some(SwitchPort { device_id, port_id })
                });
                Ok(CardHint { device, switch_port })
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../tests/fixtures/6.7/", $name))
        };
    }

    const HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope \
        xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
        xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vim25=\"urn:vim25\"><soapenv:Body>";
    const TAIL: &str = "</soapenv:Body></soapenv:Envelope>";

    fn every_operation() -> Vec<Operation<'static>> {
        vec![
            Operation::RetrieveServiceContent,
            Operation::Login { session_manager: "SessionManager", username: "sync", password: "pw" },
            Operation::CreateContainerView { view_manager: "ViewManager", root: "group-d1", kind: "Datacenter" },
            Operation::RetrieveProperties {
                collector: "propertyCollector",
                view: "session[a]b",
                kind: "Datacenter",
                properties: &["name", "parent"],
                page_size: 100,
            },
            Operation::RetrieveCurrentSession { collector: "propertyCollector", session_manager: "SessionManager" },
            Operation::ContinueRetrieveProperties { collector: "propertyCollector", token: "0" },
            Operation::DestroyView { view: "session[a]b" },
            Operation::QueryNetworkHint { network_system: "networkSystem-10" },
            Operation::Logout { session_manager: "SessionManager" },
        ]
    }

    // Requests

    // roxmltree bounds the depth of entities, not of elements, and an answer is
    // read recursively: 4 000 nested elements overflow the 2 MiB stack of a
    // tokio worker and end the whole run. A vSphere answer is never that deep.
    #[test]
    fn an_answer_nested_deeper_than_any_vsphere_answer_is_refused() {
        let nested = format!("{}{}", "<a>".repeat(10_000), "</a>".repeat(10_000));
        let answer = format!(
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>\
             <soapenv:Fault><faultstring>x</faultstring><detail>{nested}</detail></soapenv:Fault>\
             </soapenv:Body></soapenv:Envelope>"
        );
        let refused = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || fault(&answer))
            .unwrap()
            .join()
            .expect("no stack overflow");
        assert_eq!(refused, Err("an answer nested deeper than 64 elements".to_owned()));
        let document = format!("<namespaces>{nested}</namespaces>");
        assert_eq!(versions(&document), Err("an answer nested deeper than 64 elements".to_owned()));
    }

    #[test]
    fn only_reads_and_session_operations_can_be_sent() {
        let names: BTreeSet<&str> = every_operation().iter().map(Operation::name).collect();
        let allowed = [
            "ContinueRetrievePropertiesEx",
            "CreateContainerView",
            "DestroyView",
            "Login",
            "Logout",
            "QueryNetworkHint",
            "RetrievePropertiesEx",
            "RetrieveServiceContent",
        ];
        assert_eq!(names, BTreeSet::from(allowed));
    }

    #[test]
    fn the_method_of_an_envelope_is_the_one_of_its_operation() {
        for operation in every_operation() {
            let opening = format!("<soapenv:Body><vim25:{}>", operation.name());
            assert!(operation.envelope().contains(&opening), "{operation:?}");
        }
    }

    #[test]
    fn the_service_content_request_is_the_one_a_vcenter_was_seen_answering() {
        let body = "<vim25:RetrieveServiceContent><vim25:_this type=\"ServiceInstance\">ServiceInstance</vim25:_this>\
                    </vim25:RetrieveServiceContent>";
        assert_eq!(Operation::RetrieveServiceContent.envelope(), format!("{HEAD}{body}{TAIL}"));
    }

    #[test]
    fn a_login_escapes_the_account_and_the_password() {
        let login = Operation::Login { session_manager: "SessionManager", username: "a&b", password: "p<w>\"'" };
        let body = "<vim25:Login><vim25:_this type=\"SessionManager\">SessionManager</vim25:_this>\
                    <vim25:userName>a&amp;b</vim25:userName><vim25:password>p&lt;w&gt;&quot;&apos;</vim25:password>\
                    </vim25:Login>";
        assert_eq!(login.envelope(), format!("{HEAD}{body}{TAIL}"));
    }

    #[test]
    fn a_view_covers_a_kind_under_the_root_folder_and_below() {
        let view = Operation::CreateContainerView { view_manager: "ViewManager", root: "group-d1", kind: "HostSystem" };
        let body = "<vim25:CreateContainerView><vim25:_this type=\"ViewManager\">ViewManager</vim25:_this>\
                    <vim25:container type=\"Folder\">group-d1</vim25:container><vim25:type>HostSystem</vim25:type>\
                    <vim25:recursive>true</vim25:recursive></vim25:CreateContainerView>";
        assert_eq!(view.envelope(), format!("{HEAD}{body}{TAIL}"));
    }

    #[test]
    fn properties_are_asked_for_the_objects_of_a_view_page_by_page() {
        let retrieval = Operation::RetrieveProperties {
            collector: "propertyCollector",
            view: "session[a]b",
            kind: "Datacenter",
            properties: &["name", "parent"],
            page_size: 100,
        };
        // The view itself is skipped; its `view` property leads to the objects.
        let body = "<vim25:RetrievePropertiesEx><vim25:_this type=\"PropertyCollector\">propertyCollector</vim25:_this>\
                    <vim25:specSet><vim25:propSet><vim25:type>Datacenter</vim25:type><vim25:pathSet>name</vim25:pathSet>\
                    <vim25:pathSet>parent</vim25:pathSet></vim25:propSet><vim25:objectSet>\
                    <vim25:obj type=\"ContainerView\">session[a]b</vim25:obj><vim25:skip>true</vim25:skip>\
                    <vim25:selectSet xsi:type=\"vim25:TraversalSpec\"><vim25:name>view</vim25:name>\
                    <vim25:type>ContainerView</vim25:type><vim25:path>view</vim25:path><vim25:skip>false</vim25:skip>\
                    </vim25:selectSet></vim25:objectSet></vim25:specSet><vim25:options>\
                    <vim25:maxObjects>100</vim25:maxObjects></vim25:options></vim25:RetrievePropertiesEx>";
        assert_eq!(retrieval.envelope(), format!("{HEAD}{body}{TAIL}"));
    }

    #[test]
    fn the_current_session_is_a_property_of_the_session_manager() {
        let current =
            Operation::RetrieveCurrentSession { collector: "propertyCollector", session_manager: "SessionManager" };
        let body = "<vim25:RetrievePropertiesEx><vim25:_this type=\"PropertyCollector\">propertyCollector</vim25:_this>\
                    <vim25:specSet><vim25:propSet><vim25:type>SessionManager</vim25:type>\
                    <vim25:pathSet>currentSession</vim25:pathSet></vim25:propSet><vim25:objectSet>\
                    <vim25:obj type=\"SessionManager\">SessionManager</vim25:obj></vim25:objectSet></vim25:specSet>\
                    <vim25:options/></vim25:RetrievePropertiesEx>";
        assert_eq!(current.envelope(), format!("{HEAD}{body}{TAIL}"));
    }

    #[test]
    fn the_next_page_the_end_of_a_view_and_the_logout() {
        let next = Operation::ContinueRetrieveProperties { collector: "propertyCollector", token: "0" };
        let body = "<vim25:ContinueRetrievePropertiesEx><vim25:_this type=\"PropertyCollector\">propertyCollector\
                    </vim25:_this><vim25:token>0</vim25:token></vim25:ContinueRetrievePropertiesEx>";
        assert_eq!(next.envelope(), format!("{HEAD}{body}{TAIL}"));
        let destroy = Operation::DestroyView { view: "session[a]b" };
        let body =
            "<vim25:DestroyView><vim25:_this type=\"ContainerView\">session[a]b</vim25:_this></vim25:DestroyView>";
        assert_eq!(destroy.envelope(), format!("{HEAD}{body}{TAIL}"));
        let logout = Operation::Logout { session_manager: "SessionManager" };
        let body = "<vim25:Logout><vim25:_this type=\"SessionManager\">SessionManager</vim25:_this></vim25:Logout>";
        assert_eq!(logout.envelope(), format!("{HEAD}{body}{TAIL}"));
    }

    #[test]
    fn the_network_hint_is_asked_of_the_network_system_of_a_host_for_every_card() {
        let hint = Operation::QueryNetworkHint { network_system: "networkSystem-10" };
        // What govc sent to the vCenter of the fixtures, in the prefixes of this client.
        let body = "<vim25:QueryNetworkHint><vim25:_this type=\"HostNetworkSystem\">networkSystem-10</vim25:_this>\
                    </vim25:QueryNetworkHint>";
        assert_eq!(hint.envelope(), format!("{HEAD}{body}{TAIL}"));
    }

    // Answers

    #[test]
    fn the_service_content_names_the_server_and_whom_to_ask() {
        assert_eq!(
            service_content(fixture!("RetrieveServiceContent.xml")),
            Ok(ServiceContent {
                root_folder: "group-d1".to_owned(),
                property_collector: "propertyCollector".to_owned(),
                view_manager: "ViewManager".to_owned(),
                session_manager: "SessionManager".to_owned(),
                full_name: "VMware vCenter Server 6.7.0 build-22509751".to_owned(),
                api_version: "6.7.3".to_owned(),
            })
        );
    }

    #[test]
    fn an_answer_that_is_not_a_service_content_is_refused() {
        assert_eq!(
            service_content(fixture!("Logout.xml")),
            Err("no RetrieveServiceContentResponse in the answer".to_owned())
        );
        assert!(service_content("<html>login</html>").is_err());
        assert!(service_content("not xml").is_err());
    }

    #[test]
    fn the_versions_of_a_server_are_listed_current_first() {
        let listed = versions(fixture!("vimServiceVersions.xml")).expect("versions");
        assert_eq!(listed, ["6.7.3", "6.7.2", "6.7.1", "6.7", "6.5", "6.0", "5.5", "5.1", "5.0", "4.1", "4.0"]);
    }

    #[test]
    fn a_server_is_spoken_to_in_a_dialect_it_lists() {
        let owned = |versions: &[&str]| versions.iter().map(|version| (*version).to_owned()).collect::<Vec<_>>();
        assert_eq!(dialect(&owned(&["6.7.3", "6.7", "6.5"])), Ok("6.7"));
        // A newer server still lists the older dialects.
        assert_eq!(dialect(&owned(&["8.0.3.0", "8.0.2.0", "7.0", "6.7", "6.5"])), Ok("6.7"));
        assert_eq!(
            dialect(&owned(&["6.5", "6.0"])),
            Err("the server speaks vSphere API 6.5, 6.0 and this build speaks 6.7".to_owned())
        );
    }

    #[test]
    fn the_view_of_an_answer() {
        assert_eq!(
            view(fixture!("CreateContainerView.Datacenter.xml")),
            Ok("session[00000000-0000-4000-8000-000000000001]00000000-0000-4000-8000-000000000002".to_owned())
        );
        assert_eq!(view(fixture!("Logout.xml")), Err("no view in the answer".to_owned()));
    }

    #[test]
    fn a_page_holds_each_object_with_its_properties() {
        let datacenters = page(fixture!("RetrievePropertiesEx.Datacenter.0.xml")).expect("page");
        assert_eq!(datacenters.token, None);
        assert_eq!(datacenters.objects.len(), 1);
        let datacenter = &datacenters.objects[0];
        assert_eq!((datacenter.kind.as_str(), datacenter.id.as_str()), ("Datacenter", "datacenter-2"));
        assert_eq!(datacenter.text("name"), Some("DC1"));
        let parent = &datacenter.properties["parent"];
        assert_eq!((parent.reference.as_deref(), parent.text.as_str()), (Some("Folder"), "group-d1"));
        assert_eq!(datacenter.properties.keys().collect::<Vec<_>>(), ["name", "parent"]);
    }

    #[test]
    fn structured_properties_keep_their_structure() {
        let hosts = page(fixture!("RetrievePropertiesEx.HostSystem.0.xml")).expect("page");
        let ids: Vec<&str> = hosts.objects.iter().map(|host| host.id.as_str()).collect();
        assert_eq!(ids, ["host-353", "host-33564", "host-53898", "host-10", "host-48488", "host-96885"]);
        let first = &hosts.objects[0];
        assert_eq!(first.text("name"), Some("esx01.lab.example"));
        let nics = &first.properties["config.network.pnic"];
        assert_eq!(nics.xsi_type.as_deref(), Some("ArrayOfPhysicalNic"));
        let nic = nics.child("PhysicalNic").expect("a physical nic");
        assert_eq!((nic.text_at("device"), nic.text_at("linkSpeed.speedMb")), (Some("vmnic0"), Some("1000")));
        assert_eq!(first.properties["hardware.systemInfo"].text_at("model"), Some("PowerEdge R630"));
        // No proxy switch on this host: the property is there, and empty.
        assert_eq!(first.properties["config.network.proxySwitch"].children.len(), 0);
        let identifier = first.properties["hardware.systemInfo"].child("otherIdentifyingInfo").expect("identifier");
        assert_eq!(
            (identifier.text_at("identifierType.key"), identifier.text_at("identifierValue")),
            (Some("AssetTag"), Some(""))
        );
    }

    #[test]
    fn a_page_followed_by_another_carries_a_token() {
        let first = page(fixture!("RetrievePropertiesEx.VirtualMachine.0.xml")).expect("page");
        assert_eq!((first.objects.len(), first.token.as_deref()), (100, Some("0")));
        let last = page(fixture!("RetrievePropertiesEx.VirtualMachine.1.xml")).expect("page");
        assert_eq!((last.objects.len(), last.token.as_deref()), (66, None));
        let machine = last.objects.last().expect("a machine");
        assert_eq!(machine.id, "vm-12265");
        assert_eq!(machine.text("config.hardware.memoryMB"), Some("3072"));
        assert_eq!(machine.text("config.template"), Some("false"));
        assert_eq!(machine.text("guest.hostName"), Some("vm167.lab.example"));
        let host = &machine.properties["runtime.host"];
        assert_eq!((host.reference.as_deref(), host.text.as_str()), (Some("HostSystem"), "host-353"));
        // This machine has no note: the property is absent, not empty.
        assert_eq!(machine.text("config.annotation"), None);
    }

    #[test]
    fn an_answer_without_object_is_an_empty_page() {
        assert_eq!(page(fixture!("RetrievePropertiesEx.DistributedVirtualSwitch.0.xml")), Ok(Page::default()));
        // What a vCenter answers without a session: the same.
        assert_eq!(page(fixture!("RetrievePropertiesEx.unauthenticated.xml")), Ok(Page::default()));
    }

    #[test]
    fn an_answer_that_is_not_a_page_is_refused() {
        assert_eq!(page(fixture!("Logout.xml")), Err("no property retrieval in the answer".to_owned()));
        assert!(page("<html>login</html>").is_err());
    }

    #[test]
    fn a_fault_is_told_by_its_kind_and_message() {
        assert_eq!(
            fault(fixture!("CreateContainerView.unauthenticated.xml")),
            Ok(Some(Fault {
                kind: "NotAuthenticated".to_owned(),
                message: "The session is not authenticated.".to_owned()
            }))
        );
        assert_eq!(
            fault(fixture!("fault.ContinueRetrievePropertiesEx.xml")),
            Ok(Some(Fault {
                kind: "InvalidArgument".to_owned(),
                message: "A specified parameter was not correct: token".to_owned()
            }))
        );
    }

    #[test]
    fn a_result_is_not_a_fault() {
        assert_eq!(fault(fixture!("RetrievePropertiesEx.Datacenter.0.xml")), Ok(None));
        assert_eq!(fault(fixture!("Logout.xml")), Ok(None));
        assert!(fault("<html>proxy error").is_err());
    }

    #[test]
    fn a_session_shows_in_the_session_manager_and_its_absence_too() {
        assert_eq!(session_is_alive(fixture!("RetrievePropertiesEx.SessionManager.0.xml")), Ok(true));
        assert_eq!(session_is_alive(fixture!("RetrievePropertiesEx.SessionManager.unauthenticated.xml")), Ok(false));
        // An empty answer is not a session either.
        assert_eq!(session_is_alive(fixture!("RetrievePropertiesEx.unauthenticated.xml")), Ok(false));
    }
    #[test]
    fn a_card_that_hears_cdp_gives_its_switch_and_port() {
        let hints = network_hints(fixture!("QueryNetworkHint.networkSystem-10.xml")).expect("hints");
        // <device>vmnic1</device> ... <devId>nexus04.lab.example(FOC0000A0A4)</devId>
        // <address>198.18.12.241</address><portId>Ethernet1/40</portId>
        let heard =
            SwitchPort { device_id: "nexus04.lab.example(FOC0000A0A4)".to_owned(), port_id: "Ethernet1/40".to_owned() };
        assert_eq!(hints[1], CardHint { device: "vmnic1".to_owned(), switch_port: Some(heard) });
        let provider = network_hints(fixture!("QueryNetworkHint.provider.xml")).expect("hints");
        // <device>vmnic4</device> ... <devId>PROVIDER-SW001.provider.example</devId>
        // ... <portId>TenGigabitEthernet2/1/1</portId>
        let heard = SwitchPort {
            device_id: "PROVIDER-SW001.provider.example".to_owned(),
            port_id: "TenGigabitEthernet2/1/1".to_owned(),
        };
        assert_eq!(provider[4], CardHint { device: "vmnic4".to_owned(), switch_port: Some(heard) });
        let stack = network_hints(fixture!("QueryNetworkHint.networkSystem-353.xml")).expect("hints");
        // <device>vmnic0</device> ... <devId>stack01.lab.switch.example.com</devId> ...
        // <portId>GigabitEthernet1/0/14</portId>
        let heard = SwitchPort {
            device_id: "stack01.lab.switch.example.com".to_owned(),
            port_id: "GigabitEthernet1/0/14".to_owned(),
        };
        assert_eq!(stack[0], CardHint { device: "vmnic0".to_owned(), switch_port: Some(heard) });
    }

    #[test]
    fn a_card_that_hears_nothing_gives_no_neighbour() {
        let hints = network_hints(fixture!("QueryNetworkHint.networkSystem-10.xml")).expect("hints");
        // <returnval><device>vmnic0</device><subnet>... without connectedSwitchPort,
        // and <returnval><device>vusb0</device></returnval>.
        let devices: Vec<&str> = hints.iter().map(|hint| hint.device.as_str()).collect();
        assert_eq!(devices, ["vmnic0", "vmnic1", "vusb0"]);
        assert_eq!(hints[0], CardHint { device: "vmnic0".to_owned(), switch_port: None });
        assert_eq!(hints[2], CardHint { device: "vusb0".to_owned(), switch_port: None });
    }

    #[test]
    fn an_answer_that_is_not_a_network_hint_is_refused() {
        assert_eq!(network_hints(fixture!("Logout.xml")), Err("no QueryNetworkHintResponse in the answer".to_owned()));
        assert!(network_hints("<html>login</html>").is_err());
    }
}
