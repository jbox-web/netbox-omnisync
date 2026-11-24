//! XML as the vSphere API speaks it: an owned tree of what an answer holds,
//! and the escaping of what a request carries.

use roxmltree::Node;

const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// One element of an answer, kept after the text of the answer is gone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    /// The name, without its namespace.
    pub name: String,
    /// `xsi:type`: the vSphere type of a value (`ArrayOfPhysicalNic`, `xsd:int`).
    pub xsi_type: Option<String>,
    /// `type`: the kind of managed object a reference points at (`HostSystem`).
    pub reference: Option<String>,
    /// The text of an element without children; empty otherwise.
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn of(node: Node<'_, '_>) -> Element {
        let children: Vec<Element> = node.children().filter(Node::is_element).map(Element::of).collect();
        let text = if children.is_empty() {
            node.children().filter(Node::is_text).filter_map(|text| text.text()).collect()
        } else {
            String::new()
        };
        Element {
            name: node.tag_name().name().to_owned(),
            xsi_type: node.attribute((XSI, "type")).map(str::to_owned),
            reference: node.attribute("type").map(str::to_owned),
            text,
            children,
        }
    }

    /// The first child of this name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }

    /// Every child of this name, in the order of the answer.
    pub fn children_named<'e>(&'e self, name: &'e str) -> impl Iterator<Item = &'e Element> {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// The element at a dotted path of first children: `linkSpeed.speedMb`.
    pub fn at(&self, path: &str) -> Option<&Element> {
        path.split('.').try_fold(self, |element, name| element.child(name))
    }

    /// The text at a dotted path; None when the path leads nowhere.
    pub fn text_at(&self, path: &str) -> Option<&str> {
        self.at(path).map(|element| element.text.as_str())
    }
}

/// Text as the body of a request carries it.
pub fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use roxmltree::Document;

    use super::*;

    fn element(text: &str) -> Element {
        Element::of(Document::parse(text).expect("xml").root_element())
    }

    #[test]
    fn an_element_keeps_its_name_types_text_and_children() {
        let nic = element(
            r#"<val xmlns="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ArrayOfPhysicalNic"><PhysicalNic xsi:type="PhysicalNic"><device>vmnic0</device><linkSpeed><speedMb>1000</speedMb><duplex>true</duplex></linkSpeed></PhysicalNic><PhysicalNic><device>vmnic1</device></PhysicalNic></val>"#,
        );
        assert_eq!(
            (nic.name.as_str(), nic.xsi_type.as_deref(), nic.text.as_str()),
            ("val", Some("ArrayOfPhysicalNic"), "")
        );
        let devices: Vec<&str> = nic.children_named("PhysicalNic").filter_map(|nic| nic.text_at("device")).collect();
        assert_eq!(devices, ["vmnic0", "vmnic1"]);
        let first = nic.child("PhysicalNic").expect("first nic");
        assert_eq!(first.xsi_type.as_deref(), Some("PhysicalNic"));
        assert_eq!(first.text_at("linkSpeed.speedMb"), Some("1000"));
        assert_eq!(first.text_at("linkSpeed.mtu"), None);
        assert_eq!(first.at("linkSpeed").map(|speed| speed.children.len()), Some(2));
    }

    #[test]
    fn a_reference_keeps_the_kind_of_object_it_points_at() {
        let host = element(
            r#"<val xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" type="HostSystem" xsi:type="ManagedObjectReference">host-353</val>"#,
        );
        assert_eq!((host.reference.as_deref(), host.text.as_str()), (Some("HostSystem"), "host-353"));
    }

    #[test]
    fn entities_of_an_answer_are_decoded() {
        assert_eq!(element("<v>a &amp; b &apos;c&apos; &lt;d&gt;</v>").text, "a & b 'c' <d>");
    }

    #[test]
    fn an_empty_element_has_an_empty_text() {
        let value = element("<identifierValue></identifierValue>");
        assert_eq!((value.name.as_str(), value.text.as_str(), value.children.len()), ("identifierValue", "", 0));
    }

    #[test]
    fn what_a_request_carries_is_escaped() {
        assert_eq!(escape(r#"p<w>&"q'"#), "p&lt;w&gt;&amp;&quot;q&apos;");
        assert_eq!(escape("plain"), "plain");
    }
}
