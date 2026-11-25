//! The custom fields the hypervisor sources fill, and what NetBox has to
//! define before a plan that carries them is written.
//!
//! NetBox refuses a write that carries a custom field it does not define for
//! the type of the object (`extras/api/customfields.py`, 4.5 to 4.7). The
//! definitions are shared by every source that fills a field (a Proxmox and a
//! vCenter both tell the memory of a host): two sources must define it alike.
//!
//! The names, labels and descriptions are those of netbox-ssot, which defined
//! them on the NetBox this tool takes over. One thing differs: no field is
//! created with a default value. NetBox writes a default on every existing
//! object of the types of the field, whoever owns them, and from 4.7 takes
//! the field offline while a job does it on a large table: the writes of the
//! plan that follow would be refused.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::change::{Action, Change};
use crate::gateway::Row;

use super::model::Kind;
use super::reconcile::Step;

/// The endpoint of the custom field definitions.
pub const ENDPOINT: &str = "extras.custom_fields";

/// Value of `Change.kind` for a definition.
pub const LABEL: &str = "custom_field";

/// The types of the custom fields the tool fills, as NetBox names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Boolean,
}

impl FieldType {
    pub fn as_str(self) -> &'static str {
        match self {
            FieldType::Text => "text",
            FieldType::Boolean => "boolean",
        }
    }
}

/// A custom field as the tool creates it when NetBox does not define it.
#[derive(Debug, PartialEq, Eq)]
pub struct Definition {
    pub name: &'static str,
    pub field_type: FieldType,
    pub label: &'static str,
    pub description: &'static str,
}

/// The source an object was collected from.
pub static SOURCE: Definition = Definition {
    name: "source",
    field_type: FieldType::Text,
    label: "Source",
    description: "Name of the source from which the object was collected",
};

/// The id of a virtual machine in its source (the VMID of Proxmox).
pub static SOURCE_ID: Definition = Definition {
    name: "source_id",
    field_type: FieldType::Text,
    label: "Source ID",
    description: "ID of the object on the source API",
};

pub static HOST_CPU_CORES: Definition = Definition {
    name: "host_cpu_cores",
    field_type: FieldType::Text,
    label: "Host CPU cores",
    description: "Number of CPU cores on the host",
};

pub static HOST_MEMORY: Definition = Definition {
    name: "host_memory",
    field_type: FieldType::Text,
    label: "Host memory",
    description: "Amount of memory on the host",
};

pub static ARP_ENTRY: Definition = Definition {
    name: "arp_entry",
    field_type: FieldType::Boolean,
    label: "Arp Entry",
    description: "Was this IP collected from ARP table",
};

/// Every custom field the tool knows how to create.
pub static DEFINITIONS: [&Definition; 5] = [&SOURCE, &SOURCE_ID, &HOST_CPU_CORES, &HOST_MEMORY, &ARP_ENTRY];

/// For each custom field, the kinds of object it is written on.
pub type Used = BTreeMap<String, BTreeSet<Kind>>;

/// The custom fields the writes of a plan send, and on which kinds: only
/// those, so that a field nothing writes is neither created nor given a type.
pub fn used(steps: &[Step]) -> Used {
    let mut used = Used::new();
    for step in steps {
        if step.change.action == Action::Delete {
            continue;
        }
        let Some(sent) = step.change.fields.get("custom_fields").and_then(Value::as_object) else {
            continue;
        };
        for name in sent.keys() {
            used.entry(name.clone()).or_default().insert(step.kind);
        }
    }
    used
}

/// A choice NetBox reads as `{"value", "label"}` and takes as its value.
fn choice(value: Option<&Value>) -> Option<&str> {
    let value = value?;
    value.get("value").unwrap_or(value).as_str()
}

/// What to write to the definitions NetBox `held` so that every field of
/// `used` can be written on its kinds, as changes of kind `custom_field`
/// whose fields are the payload: a creation, or an update of `object_types`
/// alone (the ones NetBox has, in their order, then the missing ones).
///
/// Nothing else of an existing definition is ever written, and no object
/// type is ever taken off: NetBox would erase the values of the field on it.
///
/// An error for a field NetBox defines with another type, one it is updating
/// the stored data of (`status`, from 4.7), one whose type, id or object
/// types cannot be read, and one the tool has no definition for: nothing is
/// then to be written.
pub fn plan(used: &Used, held: &[Row]) -> Result<Vec<Change>, Vec<String>> {
    let mut changes = Vec::new();
    let mut errors = Vec::new();
    for (name, kinds) in used {
        let Some(definition) = DEFINITIONS.iter().find(|definition| definition.name == name) else {
            errors.push(format!("custom field {name} is written by the plan and the tool has no definition for it"));
            continue;
        };
        let wanted: BTreeSet<&str> = kinds.iter().map(|kind| kind.content_type()).collect();
        let existing = held.iter().find(|row| row.get("name").and_then(Value::as_str) == Some(name));
        let Some(row) = existing else {
            let types: Vec<&str> = wanted.into_iter().collect();
            changes.push(Change::new(LABEL, Action::Create, "", name).fields([
                ("name", json!(name)),
                ("type", json!(definition.field_type.as_str())),
                ("label", json!(definition.label)),
                ("description", json!(definition.description)),
                ("object_types", json!(types)),
            ]));
            continue;
        };
        let expected = definition.field_type.as_str();
        match choice(row.get("type")) {
            Some(found) if found == expected => {}
            Some(found) => {
                errors.push(format!("custom field {name} is of type {found} in NetBox, the tool writes {expected}"));
                continue;
            }
            None => {
                errors.push(format!("custom field {name}: NetBox gives no type for it"));
                continue;
            }
        }
        // Absent before 4.7, where a field is always live.
        if let Some(status) = choice(row.get("status"))
            && status != "active"
        {
            errors.push(format!("custom field {name} is {status} in NetBox: its stored data is being updated"));
            continue;
        }
        // A list that cannot be read is not an empty one: sent back with the
        // missing types alone, it would take off every type NetBox has.
        let Some(held_types) = row.get("object_types").and_then(Value::as_array) else {
            errors.push(format!("custom field {name}: NetBox gives no object types for it"));
            continue;
        };
        let held_types: Vec<&str> = held_types.iter().filter_map(Value::as_str).collect();
        let missing: Vec<&str> = wanted.into_iter().filter(|wanted| !held_types.contains(wanted)).collect();
        if missing.is_empty() {
            continue;
        }
        let Some(id) = row.get("id").and_then(Value::as_u64) else {
            errors.push(format!("custom field {name}: NetBox gives no id for it"));
            continue;
        };
        let types: Vec<&str> = held_types.iter().copied().chain(missing).collect();
        changes.push(
            Change::new(LABEL, Action::Update, "", name)
                .fields([("object_types", json!(types))])
                .before([("object_types", json!(held_types))])
                .id(id),
        );
    }
    if errors.is_empty() { Ok(changes) } else { Err(errors) }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::inventory::model::Identity;
    use crate::inventory::reconcile::Phase;

    fn row(value: Value) -> Row {
        value.as_object().cloned().expect("a JSON object")
    }

    fn uses<const N: usize>(pairs: [(&str, &[Kind]); N]) -> Used {
        pairs.into_iter().map(|(name, kinds)| (name.to_owned(), kinds.iter().copied().collect())).collect()
    }

    /// A definition as NetBox 4.5 to 4.7 read it: the type is a choice.
    fn held(id: u64, name: &str, field_type: &str, types: &[&str]) -> Row {
        row(json!({
            "id": id, "name": name, "label": "Kept", "description": "kept",
            "type": {"value": field_type, "label": "Whatever"}, "object_types": types, "default": null,
        }))
    }

    fn step(kind: Kind, action: Action, fields: Value) -> Step {
        let identity = Identity::named("lab");
        let mut change = Change::new(kind.label(), action, "", "lab");
        change.fields = fields.as_object().cloned().expect("a JSON object").into_iter().collect();
        Step {
            phase: Phase::Write,
            kind,
            identity,
            change,
            references: BTreeMap::new(),
            reference_lists: BTreeMap::new(),
        }
    }

    #[test]
    fn a_field_netbox_does_not_define_is_created_on_the_kinds_that_fill_it() {
        // Kind::Device is `dcim.device`, Kind::IpAddress `ipam.ipaddress`,
        // Kind::Cluster `virtualization.cluster`: sorted as texts.
        let used = uses([("source", &[Kind::IpAddress, Kind::Cluster, Kind::Device])]);
        assert_eq!(
            plan(&used, &[]),
            Ok(vec![Change::new("custom_field", Action::Create, "", "source").fields([
                ("name", json!("source")),
                ("type", json!("text")),
                ("label", json!("Source")),
                ("description", json!("Name of the source from which the object was collected")),
                ("object_types", json!(["dcim.device", "ipam.ipaddress", "virtualization.cluster"])),
            ])])
        );
    }

    // netbox-ssot gave `arp_entry` the default `false`: NetBox would write it
    // on every address there is, and from 4.7 take the field offline to do so.
    #[test]
    fn a_created_field_has_no_default() {
        let created = plan(&uses([("arp_entry", &[Kind::IpAddress])]), &[]).unwrap();
        let fields: Vec<&str> = created[0].fields.keys().map(String::as_str).collect();
        assert_eq!(fields, ["description", "label", "name", "object_types", "type"]);
        assert_eq!(created[0].fields["type"], json!("boolean"));
    }

    #[test]
    fn a_field_that_lacks_an_object_type_gets_it_and_keeps_those_it_has() {
        // `wireless.wirelesslan` is nothing the tool fills: it stays, first.
        let netbox = [held(7, "source", "text", &["wireless.wirelesslan", "dcim.device"])];
        let used = uses([("source", &[Kind::Device, Kind::Prefix, Kind::Cluster])]);
        assert_eq!(
            plan(&used, &netbox),
            Ok(vec![
                Change::new("custom_field", Action::Update, "", "source")
                    .fields([(
                        "object_types",
                        json!(["wireless.wirelesslan", "dcim.device", "ipam.prefix", "virtualization.cluster"])
                    )])
                    .before([("object_types", json!(["wireless.wirelesslan", "dcim.device"]))])
                    .id(7)
            ])
        );
    }

    #[test]
    fn a_field_netbox_defines_in_full_is_left_alone() {
        let netbox = [held(7, "host_memory", "text", &["dcim.device", "dcim.site"])];
        assert_eq!(plan(&uses([("host_memory", &[Kind::Device])]), &netbox), Ok(Vec::new()));
    }

    #[test]
    fn a_field_of_another_type_is_an_error_naming_both_types() {
        let netbox = [held(7, "source_id", "integer", &["virtualization.virtualmachine"])];
        assert_eq!(
            plan(&uses([("source_id", &[Kind::VirtualMachine])]), &netbox),
            Err(vec!["custom field source_id is of type integer in NetBox, the tool writes text".to_owned()])
        );
    }

    #[test]
    fn a_field_netbox_is_still_provisioning_is_an_error() {
        let mut provisioning = held(7, "arp_entry", "boolean", &["ipam.ipaddress"]);
        provisioning.insert("status".to_owned(), json!({"value": "provisioning", "label": "Provisioning"}));
        assert_eq!(
            plan(&uses([("arp_entry", &[Kind::IpAddress])]), &[provisioning]),
            Err(vec!["custom field arp_entry is provisioning in NetBox: its stored data is being updated".to_owned()])
        );
        // From 4.7 a live field says so; before, it says nothing.
        let mut active = held(7, "arp_entry", "boolean", &["ipam.ipaddress"]);
        active.insert("status".to_owned(), json!({"value": "active", "label": "Active"}));
        assert_eq!(plan(&uses([("arp_entry", &[Kind::IpAddress])]), &[active]), Ok(Vec::new()));
    }

    // netbox-sync named the memory of a host `Memory`: the label is whoever's
    // defined the field, and so is everything but the object types.
    #[test]
    fn a_definition_is_never_given_a_label_a_description_or_a_type_it_does_not_have() {
        let netbox = [held(7, "host_memory", "text", &["dcim.site"])];
        let changes = plan(&uses([("host_memory", &[Kind::Device])]), &netbox).unwrap();
        let fields: Vec<Vec<&str>> =
            changes.iter().map(|change| change.fields.keys().map(String::as_str).collect()).collect();
        assert_eq!(fields, [["object_types"]]);
    }

    #[test]
    fn the_type_of_a_field_is_read_from_its_value() {
        // As NetBox reads it, and as it takes it.
        let read = held(7, "host_memory", "text", &["dcim.device"]);
        let mut taken = read.clone();
        taken.insert("type".to_owned(), json!("text"));
        for netbox in [read, taken] {
            assert_eq!(plan(&uses([("host_memory", &[Kind::Device])]), &[netbox]), Ok(Vec::new()));
        }
    }

    #[test]
    fn a_field_without_a_readable_type_is_an_error() {
        let mut netbox = held(7, "host_memory", "text", &["dcim.device"]);
        netbox.remove("type");
        assert_eq!(
            plan(&uses([("host_memory", &[Kind::Device])]), &[netbox]),
            Err(vec!["custom field host_memory: NetBox gives no type for it".to_owned()])
        );
    }

    // Sent back as they are read, the object types NetBox has would be lost.
    #[test]
    fn a_field_whose_object_types_or_id_cannot_be_read_is_an_error() {
        let mut without_types = held(7, "host_memory", "text", &[]);
        without_types.remove("object_types");
        assert_eq!(
            plan(&uses([("host_memory", &[Kind::Device])]), &[without_types]),
            Err(vec!["custom field host_memory: NetBox gives no object types for it".to_owned()])
        );
        let mut without_id = held(7, "host_memory", "text", &["dcim.site"]);
        without_id.remove("id");
        assert_eq!(
            plan(&uses([("host_memory", &[Kind::Device])]), &[without_id]),
            Err(vec!["custom field host_memory: NetBox gives no id for it".to_owned()])
        );
    }

    #[test]
    fn a_field_the_plan_writes_that_the_catalogue_does_not_have_is_an_error() {
        // Even when NetBox defines it: the tool could not create it elsewhere.
        let netbox = [held(7, "uuid", "text", &["dcim.device"])];
        assert_eq!(
            plan(&uses([("uuid", &[Kind::Device])]), &netbox),
            Err(vec!["custom field uuid is written by the plan and the tool has no definition for it".to_owned()])
        );
    }

    #[test]
    fn every_error_is_told_and_nothing_is_then_to_be_written() {
        let netbox = [held(7, "source_id", "integer", &["virtualization.virtualmachine"])];
        let used =
            uses([("source", &[Kind::Device]), ("source_id", &[Kind::VirtualMachine]), ("uuid", &[Kind::Device])]);
        assert_eq!(
            plan(&used, &netbox),
            Err(vec![
                "custom field source_id is of type integer in NetBox, the tool writes text".to_owned(),
                "custom field uuid is written by the plan and the tool has no definition for it".to_owned(),
            ])
        );
    }

    #[test]
    fn only_the_fields_a_write_of_the_plan_sends_are_asked_for() {
        let steps = [
            step(
                Kind::Device,
                Action::Create,
                json!({"name": "pve01", "custom_fields": {"source": "pve", "host_memory": "64 GiB"}}),
            ),
            step(Kind::Cluster, Action::Update, json!({"custom_fields": {"source": "pve"}})),
            // Neither a write without custom field nor a deletion asks for one.
            step(Kind::VirtualMachine, Action::Update, json!({"vcpus": 2})),
            step(Kind::IpAddress, Action::Delete, json!({"custom_fields": {"arp_entry": false}})),
        ];
        assert_eq!(used(&steps), uses([("host_memory", &[Kind::Device]), ("source", &[Kind::Device, Kind::Cluster])]));
    }

    #[test]
    fn the_definitions_have_the_names_netbox_takes_and_no_two_share_one() {
        // NetBox: `^[a-z0-9_]+$`, without a double underscore, unique.
        let names: BTreeSet<&str> = DEFINITIONS.iter().map(|definition| definition.name).collect();
        assert_eq!(names.len(), DEFINITIONS.len());
        for name in names {
            assert!(name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
            assert!(!name.contains("__"), "{name}");
        }
    }
}
