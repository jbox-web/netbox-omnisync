//! The identity of a NetBox row, computed from the shapes NetBox 4.5 to 4.7 return.
//!
//! A source builds an [`Identity`] from what the hypervisor says; this module
//! builds the same identity from what NetBox says, so that the two meet. The
//! rows are read in dependency order: a virtual machine interface or a MAC
//! address is identified through its parent, which NetBox only nests as
//! `{id, name}`, hence the [`Index`] of the identities already computed.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::gateway::Row;

use super::model::{Current, Identity, Kind, Tag, Target, VlanScope, VrfKey};

/// The identities already computed, by kind and NetBox id.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Index {
    by_id: BTreeMap<(Kind, u64), Identity>,
}

impl Index {
    pub fn new() -> Self {
        Index::default()
    }

    pub fn insert(&mut self, kind: Kind, id: u64, identity: Identity) {
        self.by_id.insert((kind, id), identity);
    }

    pub fn get(&self, kind: Kind, id: u64) -> Option<&Identity> {
        self.by_id.get(&(kind, id))
    }
}

/// Why a row cannot be identified. Such a row is left out of the current
/// state: the tool then neither updates nor deletes it.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum IdentityError {
    #[error("{kind} row without {field}")]
    MissingField { kind: &'static str, field: &'static str },
    #[error("{kind} {id}: its {parent} {parent_id} was not read")]
    UnknownParent { kind: &'static str, id: u64, parent: &'static str, parent_id: u64 },
}

fn text<'r>(kind: Kind, row: &'r Row, field: &'static str) -> Result<&'r str, IdentityError> {
    row.get(field).and_then(Value::as_str).ok_or(IdentityError::MissingField { kind: kind.label(), field })
}

/// A value of the object nested under `field`, `None` when the field is null.
fn nested<'r>(row: &'r Row, field: &str, key: &str) -> Option<&'r Value> {
    row.get(field).and_then(Value::as_object).and_then(|object| object.get(key))
}

fn nested_text<'r>(row: &'r Row, field: &str, key: &str) -> Option<&'r str> {
    nested(row, field, key).and_then(Value::as_str)
}

fn row_id(kind: Kind, row: &Row) -> Result<u64, IdentityError> {
    row.get("id").and_then(Value::as_u64).ok_or(IdentityError::MissingField { kind: kind.label(), field: "id" })
}

fn vrf(row: &Row) -> VrfKey<'_> {
    match nested_text(row, "vrf", "name") {
        Some(name) => VrfKey::Named(name),
        None => VrfKey::Global,
    }
}

/// The interface an address row is assigned to.
fn assigned(row: &Row) -> Option<(Kind, u64)> {
    let kind = row.get("assigned_object_type").and_then(Value::as_str).and_then(Kind::from_content_type)?;
    let id = row.get("assigned_object_id").and_then(Value::as_u64)?;
    matches!(kind, Kind::Interface | Kind::VmInterface).then_some((kind, id))
}

/// The identity of the virtual machine a row hangs under, from the index: the
/// nested object has the name but not the cluster.
fn virtual_machine<'i>(kind: Kind, row: &Row, index: &'i Index) -> Result<&'i Identity, IdentityError> {
    let missing = IdentityError::MissingField { kind: kind.label(), field: "virtual_machine" };
    let parent_id = nested(row, "virtual_machine", "id").and_then(Value::as_u64).ok_or(missing)?;
    index.get(Kind::VirtualMachine, parent_id).ok_or(IdentityError::UnknownParent {
        kind: kind.label(),
        id: row.get("id").and_then(Value::as_u64).unwrap_or_default(),
        parent: Kind::VirtualMachine.label(),
        parent_id,
    })
}

/// The identity of a row of `kind`.
pub fn identify(kind: Kind, row: &Row, index: &Index) -> Result<Identity, IdentityError> {
    let missing = |field: &'static str| IdentityError::MissingField { kind: kind.label(), field };
    match kind {
        Kind::Tag
        | Kind::Tenant
        | Kind::Site
        | Kind::Manufacturer
        | Kind::Platform
        | Kind::Role
        | Kind::ClusterType
        | Kind::ClusterGroup
        | Kind::Cluster
        | Kind::Vrf
        | Kind::VlanGroup => Ok(Identity::named(text(kind, row, "name")?)),
        Kind::DeviceType => {
            let manufacturer = nested_text(row, "manufacturer", "name").ok_or(missing("manufacturer"))?;
            Ok(Identity::device_type(manufacturer, text(kind, row, "model")?))
        }
        Kind::Vlan => {
            let vid = row.get("vid").and_then(Value::as_u64).ok_or(missing("vid"))?;
            // A VLAN that has both is unique in its site first.
            let scope = match (nested_text(row, "site", "name"), nested_text(row, "group", "name")) {
                (Some(site), _) => VlanScope::Site(site),
                (None, Some(group)) => VlanScope::Group(group),
                (None, None) => VlanScope::Global,
            };
            Ok(Identity::vlan(scope, vid))
        }
        Kind::Prefix => Ok(Identity::prefix(text(kind, row, "prefix")?, vrf(row))),
        Kind::Device => Ok(Identity::device(text(kind, row, "name")?)),
        Kind::VirtualMachine => {
            let cluster = nested_text(row, "cluster", "name").unwrap_or_default();
            Ok(Identity::virtual_machine(text(kind, row, "name")?, cluster))
        }
        Kind::Interface => {
            let device = nested_text(row, "device", "name").ok_or(missing("device"))?;
            Ok(Identity::interface(device, text(kind, row, "name")?))
        }
        Kind::VmInterface => Ok(Identity::vm_interface(virtual_machine(kind, row, index)?, text(kind, row, "name")?)),
        Kind::VirtualDisk => Ok(Identity::virtual_disk(virtual_machine(kind, row, index)?, text(kind, row, "name")?)),
        Kind::MacAddress => {
            let address = text(kind, row, "mac_address")?;
            let Some((parent, parent_id)) = assigned(row) else {
                return Ok(Identity::mac_address(address, None));
            };
            let interface = index.get(parent, parent_id).ok_or(IdentityError::UnknownParent {
                kind: kind.label(),
                id: row_id(kind, row)?,
                parent: parent.label(),
                parent_id,
            })?;
            Ok(Identity::mac_address(address, Some(&Target::new(parent, interface.clone()))))
        }
        Kind::IpAddress => {
            // The holder is only shown, never compared: the nested object is enough.
            let holder = ["device", "virtual_machine"].into_iter().find_map(|field| {
                nested(row, "assigned_object", field).and_then(|holder| holder.get("name")).and_then(Value::as_str)
            });
            Ok(Identity::ip_address(text(kind, row, "address")?, vrf(row)).with_owner(holder.unwrap_or_default()))
        }
    }
}

/// The object NetBox deletes this row with, read from the row itself.
pub fn parent(kind: Kind, row: &Row) -> Option<(Kind, u64)> {
    let through = |field: &str, parent: Kind| Some((parent, nested(row, field, "id")?.as_u64()?));
    match kind {
        Kind::Interface => through("device", Kind::Device),
        Kind::VmInterface | Kind::VirtualDisk => through("virtual_machine", Kind::VirtualMachine),
        Kind::MacAddress | Kind::IpAddress => assigned(row),
        _ => None,
    }
}

/// The tags nested in a row.
pub fn tags(row: &Row) -> Vec<Tag> {
    let nested = row.get("tags").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    nested
        .iter()
        .filter_map(|tag| {
            let name = tag.get("name").and_then(Value::as_str)?;
            let slug = tag.get("slug").and_then(Value::as_str).unwrap_or(name);
            Some(Tag { name: name.to_owned(), slug: slug.to_owned() })
        })
        .collect()
}

/// Turns the rows read from NetBox into the current state, kind by kind in
/// dependency order. A row that cannot be identified is left out and reported.
pub fn current_objects(rows: &BTreeMap<Kind, Vec<Row>>) -> (Vec<Current>, Vec<String>) {
    let mut index = Index::new();
    let mut current = Vec::new();
    let mut warnings = Vec::new();
    // A BTreeMap of kinds iterates in dependency order: parents are indexed first.
    for (&kind, kind_rows) in rows {
        for row in kind_rows {
            let identified = row_id(kind, row).and_then(|id| Ok((id, identify(kind, row, &index)?)));
            match identified {
                Ok((id, identity)) => {
                    index.insert(kind, id, identity.clone());
                    current.push(Current {
                        id,
                        kind,
                        identity,
                        parent: parent(kind, row),
                        tags: tags(row),
                        row: row.clone(),
                    });
                }
                Err(error) => {
                    let id = row.get("id").and_then(Value::as_u64).map(|id| id.to_string());
                    warnings.push(format!("{} {} ignored: {error}", kind.endpoint(), id.as_deref().unwrap_or("?")));
                }
            }
        }
    }
    (current, warnings)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn row(value: Value) -> Row {
        value.as_object().cloned().expect("a JSON object")
    }

    fn keys(identity: &Identity) -> Vec<&str> {
        identity.key().iter().map(String::as_str).collect()
    }

    fn key_of(kind: Kind, value: Value) -> Vec<String> {
        identify(kind, &row(value), &Index::new()).expect("an identity").key().to_vec()
    }

    fn web01() -> Identity {
        Identity::virtual_machine("web01", "PVE-Lab")
    }

    #[test]
    fn a_tag_is_identified_by_its_name_not_its_slug() {
        let value = json!({"id": 4, "name": "Service-Apache", "slug": "svc-apache-1", "color": "9e9e9e"});
        assert_eq!(key_of(Kind::Tag, value), ["service-apache"]);
    }

    #[test]
    fn a_tenant_is_identified_by_its_name() {
        assert_eq!(key_of(Kind::Tenant, json!({"id": 1, "name": "Example FR", "slug": "exfr"})), ["example fr"]);
    }

    #[test]
    fn a_site_is_identified_by_its_name() {
        let value = json!({"id": 1, "name": "Harbor", "slug": "jag", "status": {"value": "active", "label": "Active"}});
        assert_eq!(key_of(Kind::Site, value), ["harbor"]);
    }

    #[test]
    fn a_manufacturer_is_identified_by_its_name() {
        assert_eq!(key_of(Kind::Manufacturer, json!({"id": 1, "name": "Dell", "slug": "dell-inc"})), ["dell"]);
    }

    #[test]
    fn a_device_type_is_identified_by_manufacturer_and_model() {
        let value = json!({
            "id": 7, "model": "PowerEdge R640", "slug": "poweredge-r640",
            "manufacturer": {"id": 1, "name": "Dell", "slug": "dell"}
        });
        assert_eq!(key_of(Kind::DeviceType, value), ["dell", "poweredge r640"]);
    }

    #[test]
    fn a_platform_is_identified_by_its_name() {
        let value = json!({"id": 3, "name": "VMware ESXi 6.7.0", "slug": "vmware-esxi-6-7-0"});
        assert_eq!(key_of(Kind::Platform, value), ["vmware esxi 6.7.0"]);
    }

    #[test]
    fn a_role_is_identified_by_its_name() {
        assert_eq!(key_of(Kind::Role, json!({"id": 2, "name": "Hypervisor ESX", "slug": "hv"})), ["hypervisor esx"]);
    }

    #[test]
    fn a_cluster_type_is_identified_by_its_name() {
        assert_eq!(key_of(Kind::ClusterType, json!({"id": 2, "name": "Proxmox", "slug": "pve"})), ["proxmox"]);
    }

    #[test]
    fn a_cluster_group_is_identified_by_its_name() {
        assert_eq!(key_of(Kind::ClusterGroup, json!({"id": 2, "name": "DC-Paris", "slug": "dc"})), ["dc-paris"]);
    }

    #[test]
    fn a_cluster_is_identified_by_its_name() {
        let value = json!({
            "id": 3, "name": "PVE-Lab", "type": {"id": 2, "name": "Proxmox"},
            "scope_type": "dcim.site", "scope_id": 1, "scope": {"id": 1, "name": "Harbor"}
        });
        assert_eq!(key_of(Kind::Cluster, value), ["pve-lab"]);
    }

    #[test]
    fn a_vrf_is_identified_by_its_name() {
        assert_eq!(key_of(Kind::Vrf, json!({"id": 5, "name": "Prod", "rd": "65000:1"})), ["prod"]);
    }

    #[test]
    fn a_vlan_group_is_identified_by_its_name() {
        assert_eq!(key_of(Kind::VlanGroup, json!({"id": 5, "name": "Lab", "slug": "lab"})), ["lab"]);
    }

    #[test]
    fn a_vlan_is_identified_by_site_then_group_and_vid() {
        let on_site = json!({"id": 9, "vid": 120, "name": "users", "site": {"id": 1, "name": "Harbor"}, "group": null});
        assert_eq!(key_of(Kind::Vlan, on_site), ["site", "harbor", "120"]);
        let in_group = json!({"id": 9, "vid": 120, "name": "users", "site": null, "group": {"id": 5, "name": "Lab"}});
        assert_eq!(key_of(Kind::Vlan, in_group), ["group", "lab", "120"]);
        let global = json!({"id": 9, "vid": 120, "name": "users", "site": null, "group": null});
        assert_eq!(key_of(Kind::Vlan, global), ["", "", "120"]);
    }

    #[test]
    fn a_prefix_is_identified_by_prefix_and_vrf() {
        let global = json!({"id": 9, "prefix": "10.0.0.0/24", "vrf": null});
        assert_eq!(key_of(Kind::Prefix, global), ["10.0.0.0/24", ""]);
        let in_vrf = json!({"id": 9, "prefix": "10.0.0.0/24", "vrf": {"id": 5, "name": "Prod"}});
        assert_eq!(key_of(Kind::Prefix, in_vrf), ["10.0.0.0/24", "prod"]);
    }

    #[test]
    fn a_device_is_identified_by_its_name() {
        let value = json!({"id": 12, "name": "esx01.lab", "site": {"id": 1, "name": "Harbor"}});
        let identity = identify(Kind::Device, &row(value), &Index::new()).expect("an identity");
        assert_eq!(keys(&identity), ["esx01.lab"]);
        assert_eq!(identity.owner(), "esx01.lab");
    }

    #[test]
    fn a_device_and_its_interfaces_are_identified_whatever_the_case_of_its_name() {
        let device = json!({"id": 12, "name": "ESX01.Lab", "site": {"id": 1, "name": "Harbor"}});
        assert_eq!(key_of(Kind::Device, device), ["esx01.lab"]);
        let interface = json!({"id": 30, "name": "vmnic0", "device": {"id": 12, "name": "ESX01.Lab"}});
        assert_eq!(key_of(Kind::Interface, interface), ["esx01.lab", "vmnic0"]);
    }

    #[test]
    fn a_virtual_machine_is_identified_whatever_the_case_of_its_name() {
        let value = json!({"id": 10, "name": "Web01", "cluster": {"id": 3, "name": "PVE-Lab"}});
        let identity = identify(Kind::VirtualMachine, &row(value), &Index::new()).expect("an identity");
        assert_eq!(keys(&identity), ["web01", "pve-lab"]);
        assert_eq!(identity.label(), "Web01");
    }

    #[test]
    fn a_device_without_a_name_cannot_be_identified() {
        let unnamed = row(json!({"id": 12, "name": null}));
        assert_eq!(
            identify(Kind::Device, &unnamed, &Index::new()),
            Err(IdentityError::MissingField { kind: "device", field: "name" })
        );
    }

    #[test]
    fn a_virtual_machine_is_identified_by_name_and_cluster() {
        let value = json!({"id": 10, "name": "web01", "cluster": {"id": 3, "name": "PVE-Lab"}});
        assert_eq!(key_of(Kind::VirtualMachine, value), ["web01", "pve-lab"]);
        let without_cluster = json!({"id": 10, "name": "web01", "cluster": null, "site": {"id": 1, "name": "Harbor"}});
        assert_eq!(key_of(Kind::VirtualMachine, without_cluster), ["web01", ""]);
    }

    #[test]
    fn an_interface_is_identified_by_device_and_caseless_name() {
        let value = json!({
            "id": 30, "name": "Port-Channel1", "device": {"id": 12, "name": "esx01.lab"},
            "type": {"value": "lag", "label": "Link Aggregation Group (LAG)"}
        });
        let identity = identify(Kind::Interface, &row(value.clone()), &Index::new()).expect("an identity");
        assert_eq!(keys(&identity), ["esx01.lab", "port-channel1"]);
        assert_eq!(identity.owner(), "esx01.lab");
        assert_eq!(identity.label(), "Port-Channel1");
        assert_eq!(parent(Kind::Interface, &row(value)), Some((Kind::Device, 12)));
    }

    #[test]
    fn a_vm_interface_is_identified_through_its_virtual_machine() {
        let mut index = Index::new();
        index.insert(Kind::VirtualMachine, 10, web01());
        let value = json!({"id": 40, "name": "eth0", "virtual_machine": {"id": 10, "name": "web01"}});
        let identity = identify(Kind::VmInterface, &row(value.clone()), &index).expect("an identity");
        assert_eq!(keys(&identity), ["web01", "pve-lab", "eth0"]);
        assert_eq!(identity.owner(), "web01");
        assert_eq!(parent(Kind::VmInterface, &row(value.clone())), Some((Kind::VirtualMachine, 10)));
        assert_eq!(
            identify(Kind::VmInterface, &row(value), &Index::new()),
            Err(IdentityError::UnknownParent { kind: "vm_interface", id: 40, parent: "vm", parent_id: 10 })
        );
    }

    #[test]
    fn a_virtual_disk_is_identified_through_its_virtual_machine() {
        let mut index = Index::new();
        index.insert(Kind::VirtualMachine, 10, web01());
        let value = json!({"id": 50, "name": "scsi0", "size": 32000, "virtual_machine": {"id": 10, "name": "web01"}});
        let identity = identify(Kind::VirtualDisk, &row(value.clone()), &index).expect("an identity");
        assert_eq!(keys(&identity), ["web01", "pve-lab", "scsi0"]);
        assert_eq!(parent(Kind::VirtualDisk, &row(value)), Some((Kind::VirtualMachine, 10)));
    }

    #[test]
    fn a_mac_address_is_identified_by_address_and_assigned_interface() {
        let mut index = Index::new();
        index.insert(Kind::VmInterface, 40, Identity::vm_interface(&web01(), "eth0"));
        let value = json!({
            "id": 60, "mac_address": "bc:24:11:aa:bb:cc",
            "assigned_object_type": "virtualization.vminterface", "assigned_object_id": 40,
            "assigned_object": {"id": 40, "name": "eth0", "virtual_machine": {"id": 10, "name": "web01"}}
        });
        let identity = identify(Kind::MacAddress, &row(value.clone()), &index).expect("an identity");
        assert_eq!(keys(&identity), ["BC:24:11:AA:BB:CC", "virtualization.vminterface", "web01", "pve-lab", "eth0"]);
        assert_eq!(identity.owner(), "web01");
        assert_eq!(parent(Kind::MacAddress, &row(value)), Some((Kind::VmInterface, 40)));
        let loose = json!({
            "id": 61, "mac_address": "BC:24:11:AA:BB:CC",
            "assigned_object_type": null, "assigned_object_id": null, "assigned_object": null
        });
        assert_eq!(key_of(Kind::MacAddress, loose.clone()), ["BC:24:11:AA:BB:CC", ""]);
        assert_eq!(parent(Kind::MacAddress, &row(loose)), None);
    }

    #[test]
    fn an_ip_address_is_identified_by_host_and_vrf() {
        let value = json!({
            "id": 70, "address": "10.0.0.5/24", "vrf": {"id": 5, "name": "Prod"},
            "assigned_object_type": "dcim.interface", "assigned_object_id": 30,
            "assigned_object": {"id": 30, "name": "vmk0", "device": {"id": 12, "name": "esx01.lab"}}
        });
        let identity = identify(Kind::IpAddress, &row(value.clone()), &Index::new()).expect("an identity");
        assert_eq!(keys(&identity), ["10.0.0.5", "prod"]);
        assert_eq!(identity.owner(), "esx01.lab");
        assert_eq!(identity.label(), "10.0.0.5/24");
        assert_eq!(parent(Kind::IpAddress, &row(value)), Some((Kind::Interface, 30)));
        let loose = json!({"id": 71, "address": "2001:DB8::1/64", "vrf": null, "assigned_object_id": null});
        let identity = identify(Kind::IpAddress, &row(loose.clone()), &Index::new()).expect("an identity");
        assert_eq!(keys(&identity), ["2001:db8::1", ""]);
        assert_eq!(identity.owner(), "");
        assert_eq!(parent(Kind::IpAddress, &row(loose)), None);
    }

    #[test]
    fn an_ip_address_on_a_vm_interface_is_shown_under_its_virtual_machine() {
        let value = json!({
            "id": 70, "address": "10.0.0.5/24", "vrf": null,
            "assigned_object_type": "virtualization.vminterface", "assigned_object_id": 40,
            "assigned_object": {"id": 40, "name": "eth0", "virtual_machine": {"id": 10, "name": "web01"}}
        });
        let identity = identify(Kind::IpAddress, &row(value), &Index::new()).expect("an identity");
        assert_eq!(identity.owner(), "web01");
    }

    #[test]
    fn tags_are_read_with_name_and_slug() {
        let value = json!({"id": 1, "tags": [
            {"id": 2, "name": "NetBox-synced", "slug": "netbox-synced", "color": "9e9e9e"},
            {"id": 3, "name": "Source: vc1", "slug": "source-vc1"}
        ]});
        assert_eq!(
            tags(&row(value)),
            [
                Tag { name: "NetBox-synced".to_owned(), slug: "netbox-synced".to_owned() },
                Tag { name: "Source: vc1".to_owned(), slug: "source-vc1".to_owned() }
            ]
        );
        assert_eq!(tags(&row(json!({"id": 1}))), []);
    }

    #[test]
    fn rows_are_identified_in_dependency_order_whatever_the_order_given() {
        let rows = BTreeMap::from([
            (Kind::IpAddress, vec![row(json!({"id": 70, "address": "10.0.0.5/24", "vrf": null}))]),
            (
                Kind::VmInterface,
                vec![row(json!({"id": 40, "name": "eth0", "virtual_machine": {"id": 10, "name": "web01"}}))],
            ),
            (
                Kind::VirtualMachine,
                vec![row(json!({
                    "id": 10, "name": "web01", "cluster": {"id": 3, "name": "PVE-Lab"},
                    "tags": [{"id": 1, "name": "netbox-ssot", "slug": "netbox-ssot"}]
                }))],
            ),
        ]);
        let (current, warnings) = current_objects(&rows);
        assert_eq!(warnings, Vec::<String>::new());
        let seen: Vec<(Kind, u64, Vec<&str>)> =
            current.iter().map(|object| (object.kind, object.id, keys(&object.identity))).collect();
        assert_eq!(
            seen,
            [
                (Kind::VirtualMachine, 10, vec!["web01", "pve-lab"]),
                (Kind::VmInterface, 40, vec!["web01", "pve-lab", "eth0"]),
                (Kind::IpAddress, 70, vec!["10.0.0.5", ""]),
            ]
        );
        assert_eq!(current[0].tags, [Tag { name: "netbox-ssot".to_owned(), slug: "netbox-ssot".to_owned() }]);
        assert_eq!(current[1].parent, Some((Kind::VirtualMachine, 10)));
        assert_eq!(current[0].row["name"], json!("web01"));
    }

    #[test]
    fn a_row_that_cannot_be_identified_is_left_out_with_a_warning() {
        let rows = BTreeMap::from([(
            Kind::Device,
            vec![row(json!({"id": 12, "name": null})), row(json!({"id": 13, "name": "esx02"}))],
        )]);
        let (current, warnings) = current_objects(&rows);
        assert_eq!(current.iter().map(|object| object.id).collect::<Vec<_>>(), [13]);
        assert_eq!(warnings, ["dcim.devices 12 ignored: device row without name"]);
    }
}
