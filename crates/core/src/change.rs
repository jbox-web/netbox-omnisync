//! A single write to perform on NetBox, as produced by the diff functions.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a change does to its object. Serialised as its NetBox verb, as the
/// journal of the runs records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Create,
    Update,
    Delete,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Update => "update",
            Action::Delete => "delete",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Field values of a change, sorted by field name so that a report is stable.
pub type Fields = BTreeMap<String, Value>;

/// Serialised without its NetBox id, as the journal of the runs records it:
/// the fields named here are its schema, and a rename changes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    /// Sort of object: `interface`, `ip`, `vlan`, `cable`, `vm`…
    pub kind: String,
    pub action: Action,
    /// NetBox device (or virtual machine) name; empty for site-level changes.
    pub device: String,
    /// Human identity of the object: interface name, address, VID, cable ends.
    pub key: String,
    /// New values, keyed by field.
    pub fields: Fields,
    /// Previous values of the updated fields, for the report only.
    pub before: Fields,
    /// NetBox id of the object to update or delete.
    #[serde(skip)]
    pub id: Option<u64>,
}

impl Change {
    pub fn new(kind: &str, action: Action, device: &str, key: &str) -> Self {
        Change {
            kind: kind.to_owned(),
            action,
            device: device.to_owned(),
            key: key.to_owned(),
            fields: Fields::new(),
            before: Fields::new(),
            id: None,
        }
    }

    pub fn fields<K: Into<String>, V: Into<Value>>(mut self, fields: impl IntoIterator<Item = (K, V)>) -> Self {
        self.fields = fields.into_iter().map(|(key, value)| (key.into(), value.into())).collect();
        self
    }

    pub fn before<K: Into<String>, V: Into<Value>>(mut self, before: impl IntoIterator<Item = (K, V)>) -> Self {
        self.before = before.into_iter().map(|(key, value)| (key.into(), value.into())).collect();
        self
    }

    pub fn id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_new_change_carries_no_field_and_no_id() {
        let change = Change::new("interface", Action::Delete, "nexus01.lab01", "Ethernet1/1");
        assert_eq!(change.kind, "interface");
        assert_eq!(change.action, Action::Delete);
        assert_eq!(change.device, "nexus01.lab01");
        assert_eq!(change.key, "Ethernet1/1");
        assert!(change.fields.is_empty());
        assert!(change.before.is_empty());
        assert_eq!(change.id, None);
    }

    #[test]
    fn fields_are_kept_sorted_by_name() {
        let change = Change::new("interface", Action::Update, "sw", "Ethernet1/1")
            .fields([("mtu", json!(9216)), ("description", json!("uplink"))])
            .before([("mtu", json!(1500)), ("description", json!(""))])
            .id(42);
        let names: Vec<&str> = change.fields.keys().map(String::as_str).collect();
        assert_eq!(names, ["description", "mtu"]);
        assert_eq!(change.before["mtu"], json!(1500));
        assert_eq!(change.id, Some(42));
    }

    // The journal of the runs records a change as this object: the id is
    // NetBox's business, and is not part of it.
    #[test]
    fn a_change_is_recorded_without_its_netbox_id() {
        let change = Change::new("interface", Action::Update, "nexus01.lab01", "Ethernet1/7")
            .fields([("mtu", json!(9216))])
            .before([("mtu", json!(1500))])
            .id(42);
        let recorded = serde_json::to_string(&change).unwrap();
        assert_eq!(
            recorded,
            r#"{"kind":"interface","action":"update","device":"nexus01.lab01","key":"Ethernet1/7","fields":{"mtu":9216},"before":{"mtu":1500}}"#
        );
        let read: Change = serde_json::from_str(&recorded).unwrap();
        assert_eq!(read, Change { id: None, ..change });
        let actions: Vec<String> =
            [Action::Create, Action::Delete].iter().map(|action| serde_json::to_string(action).unwrap()).collect();
        assert_eq!(actions, ["\"create\"", "\"delete\""]);
    }

    #[test]
    fn an_action_prints_as_its_netbox_verb() {
        assert_eq!(Action::Create.to_string(), "create");
        assert_eq!(Action::Update.to_string(), "update");
        assert_eq!(Action::Delete.to_string(), "delete");
    }
}
