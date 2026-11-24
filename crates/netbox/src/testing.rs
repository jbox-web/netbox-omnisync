//! In-memory stand-in for NetBox, rendering records in the REST API shape.
//!
//! Test support: exported so that the tests of the other crates can run their
//! logic against the same fake.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use omnisync_core::{Filters, Gateway, GatewayError, Row};
use serde_json::Value;

use crate::inventory_apply::DryRun;
use crate::version::NetboxVersion;

/// A write the fake accepted: its kind (`create`, `update` or `delete`), the
/// endpoint and the id of the object.
pub type Write = (&'static str, String, u64);

#[derive(Debug)]
struct Inner {
    tables: BTreeMap<String, BTreeMap<u64, Row>>,
    writes: Vec<Write>,
    // Fail the write that would make the number of writes exceed this number.
    fail_after: Option<usize>,
    // NetBox default of ENFORCE_GLOBAL_UNIQUE; a VRF enforces uniqueness unless
    // its record says `enforce_unique: false`, as in NetBox.
    enforce_global_unique: bool,
    // In dry run every write is refused; the attempts are kept, as (HTTP method, endpoint).
    refuse_writes: bool,
    refused: Vec<(&'static str, String)>,
    next_id: u64,
    // What `/api/status/` gives as `netbox-version`: the fake behaves as 4.5 to 4.7.
    version: String,
}

#[derive(Debug)]
pub struct FakeGateway {
    inner: Mutex<Inner>,
}

impl Default for FakeGateway {
    fn default() -> Self {
        FakeGateway::new()
    }
}

fn failure(message: impl Into<String>) -> GatewayError {
    GatewayError::Request(message.into())
}

/// A value as a query filter writes it: `12`, `nexus01.lab01`.
fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The reference held by a field: an id, or nothing when the field is absent or null.
fn reference(record: &Row, field: &str) -> Option<u64> {
    record.get(field).and_then(Value::as_u64)
}

fn host(address: &str) -> &str {
    address.split('/').next().unwrap_or(address)
}

fn object(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(key, value)| (key.to_owned(), value)).collect())
}

/// The terminations of one side of a cable, as (object type, object id).
fn terminations(cable: &Row, side: &str) -> Vec<(String, u64)> {
    let ends = cable.get(side).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    ends.iter()
        .filter_map(|end| {
            let object_type = end.get("object_type")?.as_str()?;
            Some((object_type.to_owned(), end.get("object_id")?.as_u64()?))
        })
        .collect()
}

const SIDES: [&str; 2] = ["a_terminations", "b_terminations"];

/// A nested foreign key: (field, endpoint of the target, attribute shown).
type Nested = (&'static str, &'static str, &'static str);

/// The plain foreign keys the fake nests as `{"id": …, <attribute>: …}`, by
/// endpoint: (field, endpoint of the target, attribute shown). A field the
/// record does not have is rendered `null`, as NetBox does.
const NESTED: [(&str, &[Nested]); 7] = [
    ("dcim.device_types", &[("manufacturer", "dcim.manufacturers", "name")]),
    ("dcim.platforms", &[("manufacturer", "dcim.manufacturers", "name")]),
    (
        "dcim.devices",
        &[
            ("device_type", "dcim.device_types", "model"),
            ("role", "dcim.device_roles", "name"),
            ("platform", "dcim.platforms", "name"),
            ("tenant", "tenancy.tenants", "name"),
            ("cluster", "virtualization.clusters", "name"),
            ("primary_ip6", "ipam.ip_addresses", "address"),
            // Read-only in NetBox, where a device bay sets it: a test sets it directly.
            ("parent_device", "dcim.devices", "name"),
        ],
    ),
    (
        "virtualization.clusters",
        &[
            ("type", "virtualization.cluster_types", "name"),
            ("group", "virtualization.cluster_groups", "name"),
            ("tenant", "tenancy.tenants", "name"),
        ],
    ),
    (
        "virtualization.virtual_machines",
        &[
            ("cluster", "virtualization.clusters", "name"),
            ("device", "dcim.devices", "name"),
            ("platform", "dcim.platforms", "name"),
            ("role", "dcim.device_roles", "name"),
            ("tenant", "tenancy.tenants", "name"),
            ("site", "dcim.sites", "name"),
            ("primary_ip4", "ipam.ip_addresses", "address"),
            ("primary_ip6", "ipam.ip_addresses", "address"),
        ],
    ),
    (
        "virtualization.interfaces",
        &[
            ("virtual_machine", "virtualization.virtual_machines", "name"),
            ("parent", "virtualization.interfaces", "name"),
            ("untagged_vlan", "ipam.vlans", "vid"),
            ("vrf", "ipam.vrfs", "name"),
            ("primary_mac_address", "dcim.mac_addresses", "mac_address"),
        ],
    ),
    ("virtualization.virtual_disks", &[("virtual_machine", "virtualization.virtual_machines", "name")]),
];

/// The choice fields rendered as `{"value": …, "label": …}` when the record
/// has them, by endpoint.
const CHOICES: [(&str, &[&str]); 6] = [
    ("dcim.devices", &["status"]),
    ("dcim.interfaces", &["type", "mode"]),
    ("ipam.ip_addresses", &["status"]),
    ("virtualization.clusters", &["status"]),
    ("virtualization.interfaces", &["mode"]),
    ("virtualization.virtual_machines", &["status"]),
];

/// The entries of a per-endpoint table.
fn of<T: Copy>(table: &[(&str, &'static [T])], endpoint: &str) -> &'static [T] {
    table.iter().find(|(name, _)| *name == endpoint).map(|(_, entries)| *entries).unwrap_or_default()
}

/// A choice as NetBox renders it. The label is the value with a capital: the
/// real one is a display text nothing compares.
fn choice(value: &Value) -> Value {
    let label = match value.as_str() {
        Some(text) => {
            let mut letters = text.chars();
            let first: String = letters.next().map(|letter| letter.to_uppercase().collect()).unwrap_or_default();
            Value::from(format!("{first}{}", letters.as_str()))
        }
        None => value.clone(),
    };
    object([("value", value.clone()), ("label", label)])
}

/// The content type of the interfaces of an endpoint, and what holds them:
/// (content type, field of the holder, endpoint of the holder, what NetBox
/// calls the holder in an error).
const INTERFACES: [(&str, &str, &str, &str, &str); 2] = [
    ("dcim.interfaces", "dcim.interface", "device", "dcim.devices", "device"),
    (
        "virtualization.interfaces",
        "virtualization.vminterface",
        "virtual_machine",
        "virtualization.virtual_machines",
        "VM",
    ),
];

impl Inner {
    fn add(&mut self, endpoint: &str, mut fields: Row) -> u64 {
        self.next_id += 1;
        fields.insert("id".to_owned(), Value::from(self.next_id));
        self.tables.entry(endpoint.to_owned()).or_default().insert(self.next_id, fields);
        self.next_id
    }

    fn record(&self, endpoint: &str, id: u64) -> Option<&Row> {
        self.tables.get(endpoint)?.get(&id)
    }

    fn existing(&self, endpoint: &str, id: u64) -> Result<&Row, GatewayError> {
        self.record(endpoint, id).ok_or_else(|| failure(format!("fake: no {endpoint} object with id {id}")))
    }

    fn records(&self, endpoint: &str) -> impl Iterator<Item = &Row> {
        self.tables.get(endpoint).into_iter().flat_map(BTreeMap::values)
    }

    fn check_failure(&self) -> Result<(), GatewayError> {
        match self.fail_after {
            Some(limit) if self.writes.len() >= limit => Err(failure("injected failure")),
            _ => Ok(()),
        }
    }

    // As the client in dry run: the write is refused before anything else.
    fn check_dry_run(&mut self, method: &'static str, endpoint: &str) -> Result<(), GatewayError> {
        if !self.refuse_writes {
            return Ok(());
        }
        self.refused.push((method, endpoint.to_owned()));
        Err(GatewayError::DryRun { method: method.to_owned(), endpoint: endpoint.to_owned() })
    }

    /// The payload as the fake stores it. As NetBox: `tags` names each tag by
    /// its id or by exact attributes (`{"name": …}`, `{"slug": …}`) and a tag
    /// that does not exist is refused; the custom fields given on an update
    /// are merged into the ones the object has.
    fn accepted(&self, payload: &Row, existing: Option<&Row>) -> Result<Row, GatewayError> {
        let mut accepted = payload.clone();
        if let Some(tags) = payload.get("tags").and_then(Value::as_array) {
            let ids: Result<Vec<Value>, GatewayError> = tags.iter().map(|tag| self.tag_id(tag)).collect();
            accepted.insert("tags".to_owned(), Value::Array(ids?));
        }
        let held = existing.and_then(|record| record.get("custom_fields")).and_then(Value::as_object);
        if let (Some(held), Some(given)) = (held, payload.get("custom_fields").and_then(Value::as_object)) {
            let mut merged = held.clone();
            merged.extend(given.clone());
            accepted.insert("custom_fields".to_owned(), Value::Object(merged));
        }
        Ok(accepted)
    }

    fn tag_id(&self, tag: &Value) -> Result<Value, GatewayError> {
        let matches = |record: &&Row| match tag {
            Value::Object(attributes) => attributes.iter().all(|(key, value)| record.get(key) == Some(value)),
            id => record.get("id") == Some(id),
        };
        self.records("extras.tags")
            .find(matches)
            .and_then(|record| record.get("id").cloned())
            .ok_or_else(|| failure(format!("Related object not found using the provided attributes: {tag}")))
    }

    // As NetBox: the primary MAC of an interface is one of its own MAC addresses.
    fn check_primary_mac(&self, endpoint: &str, id: Option<u64>, payload: &Row) -> Result<(), GatewayError> {
        let Some(&(_, content_type, ..)) = INTERFACES.iter().find(|(name, ..)| *name == endpoint) else {
            return Ok(());
        };
        let Some(mac_id) = reference(payload, "primary_mac_address") else {
            return Ok(());
        };
        let mac = self.existing("dcim.mac_addresses", mac_id)?;
        let assigned = mac.get("assigned_object_type").and_then(Value::as_str) == Some(content_type)
            && id.is_some()
            && reference(mac, "assigned_object_id") == id;
        if assigned {
            return Ok(());
        }
        let address = mac.get("mac_address").map(text).unwrap_or_default();
        Err(failure(format!("MAC address {address} is not assigned to this interface")))
    }

    // As NetBox: the primary IP of a device or a virtual machine is assigned
    // to one of its interfaces.
    fn check_primary_ip(&self, endpoint: &str, id: Option<u64>, payload: &Row) -> Result<(), GatewayError> {
        let Some(&(interfaces, content_type, holder, _, called)) =
            INTERFACES.iter().find(|(_, _, _, holders, _)| *holders == endpoint)
        else {
            return Ok(());
        };
        for field in ["primary_ip4", "primary_ip6"] {
            let Some(ip_id) = reference(payload, field) else {
                continue;
            };
            let ip = self.existing("ipam.ip_addresses", ip_id)?;
            let interface = reference(ip, "assigned_object_id")
                .filter(|_| ip.get("assigned_object_type").and_then(Value::as_str) == Some(content_type))
                .and_then(|interface| self.record(interfaces, interface));
            if id.is_none() || interface.and_then(|interface| reference(interface, holder)) != id {
                let address = ip.get("address").map(text).unwrap_or_default();
                return Err(failure(format!("The specified IP address ({address}) is not assigned to this {called}.")));
            }
        }
        Ok(())
    }

    /// The interface an address or a MAC is assigned to, as NetBox nests it.
    fn assigned_object(&self, record: &Row) -> Result<Value, GatewayError> {
        let field = |key: &str| record.get(key).cloned().unwrap_or(Value::Null);
        let id = reference(record, "assigned_object_id");
        if record.get("assigned_object_type").and_then(Value::as_str) == Some("virtualization.vminterface") {
            let Some(interface) = id.and_then(|id| self.record("virtualization.interfaces", id)) else {
                // No such interface is stored: the record names it itself.
                let machine = object([("id", Value::from(1)), ("name", field("vm"))]);
                return Ok(object([
                    ("id", field("assigned_object_id")),
                    ("name", field("vm_interface")),
                    ("virtual_machine", machine),
                ]));
            };
            let machine =
                self.nested("virtualization.virtual_machines", reference(interface, "virtual_machine"), "name")?;
            return Ok(object([
                ("id", field("assigned_object_id")),
                ("name", interface.get("name").cloned().unwrap_or(Value::Null)),
                ("virtual_machine", machine),
            ]));
        }
        match self.interface(id) {
            None => Ok(Value::Null),
            Some(interface) => Ok(object([
                ("id", interface.get("id").cloned().unwrap_or(Value::Null)),
                ("name", interface.get("name").cloned().unwrap_or(Value::Null)),
                ("device", self.device_ref(interface)?),
            ])),
        }
    }

    // As NetBox: a parent exists, and only a virtual interface has one.
    fn check_parent(&self, record: &Row) -> Result<(), GatewayError> {
        let Some(parent) = reference(record, "parent") else {
            return Ok(());
        };
        if self.record("dcim.interfaces", parent).is_none() {
            return Err(failure(format!("Related object not found: interface {parent}")));
        }
        if record.get("type").and_then(Value::as_str) != Some("virtual") {
            return Err(failure("Only virtual interfaces may be assigned to a parent interface."));
        }
        Ok(())
    }

    fn check_unique_ip(&self, id: Option<u64>, record: &Row) -> Result<(), GatewayError> {
        let vrf = reference(record, "vrf");
        let unique = match vrf {
            None => self.enforce_global_unique,
            Some(vrf) => {
                self.existing("ipam.vrfs", vrf)?.get("enforce_unique").and_then(Value::as_bool).unwrap_or(true)
            }
        };
        if !unique {
            return Ok(());
        }
        let address = |record: &Row| record.get("address").and_then(Value::as_str).unwrap_or_default().to_owned();
        let wanted = address(record);
        for other in self.records("ipam.ip_addresses") {
            let taken = address(other);
            if reference(other, "id") != id && reference(other, "vrf") == vrf && host(&taken) == host(&wanted) {
                return Err(failure(format!("Duplicate IP address found: {taken}")));
            }
        }
        Ok(())
    }

    fn termination(&self, object_type: &str, id: u64) -> Result<&Row, GatewayError> {
        let table = if object_type == "dcim.interface" { "dcim.interfaces" } else { "dcim.front_ports" };
        self.existing(table, id)
    }

    fn interface(&self, id: Option<u64>) -> Option<&Row> {
        self.record("dcim.interfaces", id?)
    }

    /// The device of the interface an address or a MAC is assigned to.
    fn assigned_device(&self, record: &Row) -> Option<String> {
        self.interface(reference(record, "assigned_object_id"))?.get("device").map(text)
    }

    fn matches(&self, endpoint: &str, record: &Row, filters: &Filters) -> bool {
        // As NetBox: an empty value is dropped, so the filter selects nothing out.
        filters.iter().filter(|(_, value)| !value.is_empty()).all(|(key, value)| match (endpoint, key.as_str()) {
            // `DeviceFilterSet.name` is `iexact` in NetBox 4.5 to 4.7.
            ("dcim.devices", "name") => {
                record.get("name").and_then(Value::as_str).is_some_and(|name| name.eq_ignore_ascii_case(value))
            }
            ("ipam.ip_addresses" | "dcim.mac_addresses", "device_id") => {
                self.assigned_device(record).as_ref() == Some(value)
            }
            ("ipam.ip_addresses", "address") => {
                record.get("address").and_then(Value::as_str).is_some_and(|address| host(address) == host(value))
            }
            ("dcim.mac_addresses", "interface_id") => {
                record.get("assigned_object_id").map(text).as_ref() == Some(value)
            }
            ("dcim.cables", "device_id") => {
                SIDES.iter().flat_map(|side| terminations(record, side)).any(|(kind, id)| {
                    self.termination(&kind, id).ok().and_then(|end| end.get("device")).map(text).as_ref() == Some(value)
                })
            }
            _ => {
                let field = key.strip_suffix("_id").unwrap_or(key);
                record.get(field).map(text).as_ref() == Some(value)
            }
        })
    }

    /// `{"id": …, attribute: …}` of the object a field refers to, or null.
    fn nested(&self, endpoint: &str, id: Option<u64>, attribute: &'static str) -> Result<Value, GatewayError> {
        let Some(id) = id else {
            return Ok(Value::Null);
        };
        let value = self.existing(endpoint, id)?.get(attribute).cloned().unwrap_or(Value::Null);
        Ok(object([("id", Value::from(id)), (attribute, value)]))
    }

    fn cable_of(&self, object_type: &str, object_id: u64) -> Option<u64> {
        self.records("dcim.cables")
            .find(|cable| {
                SIDES
                    .iter()
                    .flat_map(|side| terminations(cable, side))
                    .any(|(kind, id)| (kind.as_str(), id) == (object_type, object_id))
            })
            .and_then(|cable| reference(cable, "id"))
    }

    fn device_ref(&self, record: &Row) -> Result<Value, GatewayError> {
        let id = reference(record, "device").ok_or_else(|| failure("fake: a record without its device"))?;
        self.nested("dcim.devices", Some(id), "name")
    }

    fn render(&self, endpoint: &str, record: &Row) -> Result<Row, GatewayError> {
        let mut out = record.clone();
        let mut set = |key: &str, value: Value| {
            out.insert(key.to_owned(), value);
        };
        match endpoint {
            "dcim.interfaces" => {
                if !record.contains_key("type") {
                    return Err(failure("fake: an interface without its type"));
                }
                set("device", self.device_ref(record)?);
                if !record.contains_key("mode") {
                    set("mode", Value::Null);
                }
                set("lag", self.nested("dcim.interfaces", reference(record, "lag"), "name")?);
                set("parent", self.nested("dcim.interfaces", reference(record, "parent"), "name")?);
                set("untagged_vlan", self.nested("ipam.vlans", reference(record, "untagged_vlan"), "vid")?);
                let tagged =
                    record.get("tagged_vlans").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
                let tagged: Result<Vec<Value>, GatewayError> =
                    tagged.iter().map(|vlan| self.nested("ipam.vlans", vlan.as_u64(), "vid")).collect();
                set("tagged_vlans", Value::Array(tagged?));
                set(
                    "primary_mac_address",
                    self.nested("dcim.mac_addresses", reference(record, "primary_mac_address"), "mac_address")?,
                );
                for (key, default) in [
                    ("description", Value::from("")),
                    ("label", Value::from("")),
                    ("mtu", Value::Null),
                    ("enabled", Value::Bool(true)),
                ] {
                    if !record.contains_key(key) {
                        set(key, default);
                    }
                }
                let cable = reference(record, "id").and_then(|id| self.cable_of("dcim.interface", id));
                set("cable", cable.map_or(Value::Null, |id| object([("id", Value::from(id))])));
            }
            "ipam.ip_addresses" => {
                set("vrf", self.nested("ipam.vrfs", reference(record, "vrf"), "name")?);
                set("assigned_object", self.assigned_object(record)?);
                // A record without tenant is rendered without the key: the network tests compare whole rows.
                if let Some(tenant) = reference(record, "tenant") {
                    set("tenant", self.nested("tenancy.tenants", Some(tenant), "name")?);
                }
            }
            "ipam.vlans" => {
                // As for a device: the network tests name a site by a bare id that no record backs.
                let stored = reference(record, "site").filter(|id| self.record("dcim.sites", *id).is_some());
                if let Some(site) = stored {
                    set("site", self.nested("dcim.sites", Some(site), "name")?);
                }
                // A VLAN group is always a record: nested as NetBox nests it.
                if let Some(group) = reference(record, "group") {
                    set("group", self.nested("ipam.vlan_groups", Some(group), "name")?);
                }
            }
            "dcim.mac_addresses" => {
                for half in ["assigned_object_type", "assigned_object_id"] {
                    if !record.contains_key(half) {
                        set(half, Value::Null);
                    }
                }
                set("assigned_object", self.assigned_object(record)?);
            }
            "virtualization.clusters" => {
                for half in ["scope_type", "scope_id"] {
                    if !record.contains_key(half) {
                        set(half, Value::Null);
                    }
                }
                let site = reference(record, "scope_id")
                    .filter(|_| record.get("scope_type").and_then(Value::as_str) == Some("dcim.site"));
                set("scope", self.nested("dcim.sites", site, "name")?);
            }
            "dcim.devices" => {
                let site = record.get("site").cloned().ok_or_else(|| failure("fake: a device without its site"))?;
                // The network tests name a site by a bare id that no record backs.
                let stored = site.as_u64().filter(|id| self.record("dcim.sites", *id).is_some());
                match stored {
                    Some(id) => set("site", self.nested("dcim.sites", Some(id), "name")?),
                    None => set("site", object([("id", site)])),
                }
                set("primary_ip4", self.nested("ipam.ip_addresses", reference(record, "primary_ip4"), "address")?);
                let chassis = reference(record, "virtual_chassis");
                set("virtual_chassis", chassis.map_or(Value::Null, |id| object([("id", Value::from(id))])));
                if !record.contains_key("serial") {
                    set("serial", Value::from(""));
                }
            }
            "dcim.virtual_chassis" => {
                set("master", self.nested("dcim.devices", reference(record, "master"), "name")?);
            }
            "dcim.cables" => {
                for side in SIDES {
                    let mut ends = Vec::new();
                    for (object_type, id) in terminations(record, side) {
                        let target = self.termination(&object_type, id)?;
                        let end = object([
                            ("id", Value::from(id)),
                            ("name", target.get("name").cloned().unwrap_or(Value::Null)),
                            ("device", self.device_ref(target)?),
                        ]);
                        ends.push(object([
                            ("object_type", Value::from(object_type)),
                            ("object_id", Value::from(id)),
                            ("object", end),
                        ]));
                    }
                    set(side, Value::Array(ends));
                }
            }
            _ => {}
        }
        for (field, target, attribute) in of(&NESTED, endpoint) {
            set(field, self.nested(target, reference(record, field), attribute)?);
        }
        for field in of(&CHOICES, endpoint) {
            if let Some(value) = record.get(*field).filter(|value| !value.is_null()) {
                set(field, choice(value));
            }
        }
        // Stored as ids, rendered as NetBox nests a tag. A record without the
        // key is rendered without it: the network tests compare whole rows.
        if let Some(tags) = record.get("tags").and_then(Value::as_array) {
            let nested: Result<Vec<Value>, GatewayError> = tags
                .iter()
                .map(|tag| {
                    let stored = self.existing("extras.tags", tag.as_u64().unwrap_or_default())?;
                    let attribute = |key: &'static str| (key, stored.get(key).cloned().unwrap_or(Value::Null));
                    Ok(object([attribute("id"), attribute("name"), attribute("slug")]))
                })
                .collect();
            set("tags", Value::Array(nested?));
        }
        Ok(out)
    }
}

impl FakeGateway {
    pub fn new() -> Self {
        FakeGateway {
            inner: Mutex::new(Inner {
                tables: BTreeMap::new(),
                writes: Vec::new(),
                fail_after: None,
                enforce_global_unique: true,
                refuse_writes: false,
                refused: Vec::new(),
                next_id: 1000,
                version: "4.7.5".to_owned(),
            }),
        }
    }

    // A test that panicked while holding the lock has already failed: the
    // records are still good for the others.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores a record as the fake keeps it (references are bare ids) and
    /// returns its id. `fields` must be a JSON object.
    pub fn add(&self, endpoint: &str, fields: Value) -> u64 {
        let Value::Object(fields) = fields else {
            panic!("a record is a JSON object, got {fields}");
        };
        self.lock().add(endpoint, fields)
    }

    /// Sets one field of a stored record.
    pub fn set(&self, endpoint: &str, id: u64, field: &str, value: Value) {
        let mut inner = self.lock();
        let Some(record) = inner.tables.get_mut(endpoint).and_then(|table| table.get_mut(&id)) else {
            panic!("no {endpoint} object with id {id}");
        };
        record.insert(field.to_owned(), value);
    }

    /// The record as stored, not as rendered.
    pub fn row(&self, endpoint: &str, id: u64) -> Option<Row> {
        self.lock().record(endpoint, id).cloned()
    }

    /// Id of the first stored record whose `field` equals `value`.
    pub fn find(&self, endpoint: &str, field: &str, value: &Value) -> Option<u64> {
        self.lock()
            .records(endpoint)
            .find(|record| record.get(field) == Some(value))
            .and_then(|record| reference(record, "id"))
    }

    /// The writes accepted so far, in order.
    pub fn writes(&self) -> Vec<Write> {
        self.lock().writes.clone()
    }

    /// Fail the write that would make the number of writes exceed `limit`.
    pub fn fail_after(&self, limit: Option<usize>) {
        self.lock().fail_after = limit;
    }

    /// NetBox default of ENFORCE_GLOBAL_UNIQUE is on; a VRF enforces uniqueness
    /// unless its record says `enforce_unique: false`, as in NetBox.
    pub fn enforce_global_unique(&self, enforce: bool) {
        self.lock().enforce_global_unique = enforce;
    }

    /// Puts the fake in dry run, as `NetboxClientBuilder::dry_run` does the
    /// client: every write is refused with `GatewayError::DryRun`.
    pub fn refuse_writes(&self, refuse: bool) {
        self.lock().refuse_writes = refuse;
    }

    /// The writes refused in dry run so far, as (HTTP method, endpoint): a
    /// write that was attempted, even though nothing was stored.
    pub fn refused(&self) -> Vec<(&'static str, String)> {
        self.lock().refused.clone()
    }

    /// Says another release in `/api/status/`; only what it says changes.
    pub fn set_version(&self, version: &str) {
        self.lock().version = version.to_owned();
    }
}

impl NetboxVersion for FakeGateway {
    async fn netbox_version(&self) -> Result<String, GatewayError> {
        Ok(self.lock().version.clone())
    }

    // The fake takes every field it is written: there is no schema to read.
    async fn load_schema(&self) -> Result<(), GatewayError> {
        Ok(())
    }
}

impl DryRun for FakeGateway {
    fn dry_run(&self) -> bool {
        self.lock().refuse_writes
    }
}

impl Gateway for FakeGateway {
    async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
        let inner = self.lock();
        inner
            .records(endpoint)
            .filter(|record| inner.matches(endpoint, record, filters))
            .map(|record| inner.render(endpoint, record))
            .collect()
    }

    async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
        let mut inner = self.lock();
        inner.check_dry_run("POST", endpoint)?;
        inner.check_failure()?;
        let payload = &inner.accepted(payload, None)?;
        inner.check_primary_mac(endpoint, None, payload)?;
        inner.check_primary_ip(endpoint, None, payload)?;
        match endpoint {
            "dcim.cables" => {
                for (object_type, id) in SIDES.iter().flat_map(|side| terminations(payload, side)) {
                    if inner.cable_of(&object_type, id).is_some() {
                        return Err(failure("Duplicate termination found"));
                    }
                }
            }
            "ipam.ip_addresses" => inner.check_unique_ip(None, payload)?,
            "dcim.interfaces" => inner.check_parent(payload)?,
            _ => {}
        }
        let id = inner.add(endpoint, payload.clone());
        inner.writes.push(("create", endpoint.to_owned(), id));
        inner.render(endpoint, inner.existing(endpoint, id)?)
    }

    async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
        let mut inner = self.lock();
        inner.check_dry_run("PATCH", endpoint)?;
        inner.check_failure()?;
        let mut updated = inner.existing(endpoint, id)?.clone();
        let payload = inner.accepted(payload, Some(&updated))?;
        inner.check_primary_mac(endpoint, Some(id), &payload)?;
        inner.check_primary_ip(endpoint, Some(id), &payload)?;
        updated.extend(payload);
        match endpoint {
            "ipam.ip_addresses" => inner.check_unique_ip(Some(id), &updated)?,
            "dcim.interfaces" => inner.check_parent(&updated)?,
            _ => {}
        }
        inner.tables.entry(endpoint.to_owned()).or_default().insert(id, updated);
        inner.writes.push(("update", endpoint.to_owned(), id));
        Ok(())
    }

    async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
        let mut inner = self.lock();
        inner.check_dry_run("DELETE", endpoint)?;
        inner.check_failure()?;
        // NetBox protects a parent interface (RESTRICT): its children go first.
        if endpoint == "dcim.interfaces" && inner.records(endpoint).any(|other| reference(other, "parent") == Some(id))
        {
            return Err(failure("Unable to delete interface: it has child interfaces"));
        }
        inner.existing(endpoint, id)?;
        inner.tables.entry(endpoint.to_owned()).or_default().remove(&id);
        inner.writes.push(("delete", endpoint.to_owned(), id));
        Ok(())
    }

    // The fake keeps every field it is given, as NetBox answers every write:
    // what NetBox would drop is the schema's to say (`NetboxClient`).
    async fn check_write(&self, _: omnisync_core::Write, _: &str, _: &[String]) -> Result<(), GatewayError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use omnisync_core::gateway::filters;
    use serde_json::json;

    use super::*;

    fn row(value: Value) -> Row {
        value.as_object().expect("a JSON object").clone()
    }

    fn request(message: &str) -> GatewayError {
        GatewayError::Request(message.to_owned())
    }

    #[tokio::test]
    async fn a_vlan_and_an_address_nest_what_they_refer_to_when_it_is_stored() {
        let netbox = FakeGateway::new();
        let site = netbox.add("dcim.sites", json!({"name": "Harbor", "slug": "harbor"}));
        let tenant = netbox.add("tenancy.tenants", json!({"name": "Example Tenant", "slug": "example-tenant"}));
        let at_site = netbox.add("ipam.vlans", json!({"site": site, "vid": 26, "name": "pg-8"}));
        // The network tests name a site by a bare id that no record backs.
        let bare = netbox.add("ipam.vlans", json!({"site": 12, "vid": 27, "name": "pg-9"}));
        let address = netbox.add("ipam.ip_addresses", json!({"address": "198.18.2.160/24", "tenant": tenant}));
        let vlans = netbox.list("ipam.vlans", &Vec::new()).await.unwrap();
        assert_eq!(
            vlans,
            [
                row(json!({"id": at_site, "site": {"id": site, "name": "Harbor"}, "vid": 26, "name": "pg-8"})),
                row(json!({"id": bare, "site": 12, "vid": 27, "name": "pg-9"})),
            ]
        );
        let addresses = netbox.list("ipam.ip_addresses", &Vec::new()).await.unwrap();
        assert_eq!(addresses[0]["id"], json!(address));
        assert_eq!(addresses[0]["tenant"], json!({"id": tenant, "name": "Example Tenant"}));
        // An address without tenant is rendered without the key, as before.
        let plain = netbox.add("ipam.ip_addresses", json!({"address": "198.18.2.161/24"}));
        let addresses = netbox.list("ipam.ip_addresses", &Vec::new()).await.unwrap();
        let plain = addresses.iter().find(|row| row["id"] == json!(plain)).unwrap();
        assert!(!plain.contains_key("tenant"));
    }

    #[tokio::test]
    async fn an_interface_is_rendered_in_the_api_shape() {
        let netbox = FakeGateway::new();
        let vlan = netbox.add("ipam.vlans", json!({"site": 12, "vid": 26, "name": "VLAN2600-PPE"}));
        let device = netbox.add("dcim.devices", json!({"name": "nexus01.lab01", "site": 12}));
        let lag = netbox.add("dcim.interfaces", json!({"device": device, "name": "Port-channel10", "type": "lag"}));
        let eth = netbox.add(
            "dcim.interfaces",
            json!({
                "device": device, "name": "Ethernet1/51", "type": "other", "lag": lag, "mode": "tagged",
                "untagged_vlan": vlan, "tagged_vlans": [vlan],
            }),
        );
        let rows = netbox.list("dcim.interfaces", &filters([("name", "Ethernet1/51")])).await.unwrap();
        assert_eq!(
            rows,
            [row(json!({
                "id": eth,
                "device": {"id": device, "name": "nexus01.lab01"},
                "name": "Ethernet1/51",
                "type": {"value": "other", "label": "Other"},
                "mode": {"value": "tagged", "label": "Tagged"},
                "lag": {"id": lag, "name": "Port-channel10"},
                "parent": null,
                "untagged_vlan": {"id": vlan, "vid": 26},
                "tagged_vlans": [{"id": vlan, "vid": 26}],
                "primary_mac_address": null,
                "description": "",
                "label": "",
                "mtu": null,
                "enabled": true,
                "cable": null,
            }))]
        );
    }

    #[tokio::test]
    async fn ids_start_after_1000_and_filters_ending_in_id_match_the_reference() {
        let netbox = FakeGateway::new();
        let first = netbox.add("dcim.devices", json!({"name": "a", "site": 12}));
        let second = netbox.add("dcim.devices", json!({"name": "b", "site": 13}));
        assert_eq!((first, second), (1001, 1002));
        let rows = netbox.list("dcim.devices", &filters([("site_id", 13)])).await.unwrap();
        assert_eq!(rows.iter().map(|row| row["name"].clone()).collect::<Vec<_>>(), [json!("b")]);
    }

    // NetBox drops an empty filter value (`multivalue_field_factory.to_python`
    // keeps non-empty values only) and then returns the whole table.
    #[tokio::test]
    async fn an_empty_filter_value_filters_nothing_as_in_netbox() {
        let netbox = FakeGateway::new();
        netbox.add("ipam.vrfs", json!({"name": "mgmt"}));
        netbox.add("ipam.vrfs", json!({"name": "prod"}));
        let rows = netbox.list("ipam.vrfs", &filters([("name", "")])).await.unwrap();
        assert_eq!(rows.iter().map(|row| row["name"].clone()).collect::<Vec<_>>(), [json!("mgmt"), json!("prod")]);
    }

    // `DeviceFilterSet.name` is `iexact` in NetBox 4.5.10 and 4.7.5 (dcim/filtersets.py:1310, :1529),
    // and two sites may each hold a device of the same name.
    #[tokio::test]
    async fn a_device_name_is_matched_whatever_its_case_on_every_site() {
        let netbox = FakeGateway::new();
        netbox.add("dcim.devices", json!({"name": "SW01", "site": 12}));
        netbox.add("dcim.devices", json!({"name": "sw01", "site": 13}));
        netbox.add("dcim.devices", json!({"name": "sw02", "site": 12}));
        let rows = netbox.list("dcim.devices", &filters([("name", "sw01")])).await.unwrap();
        assert_eq!(rows.iter().map(|row| row["site"]["id"].clone()).collect::<Vec<_>>(), [json!(12), json!(13)]);
    }

    #[tokio::test]
    async fn writes_are_recorded_and_applied() {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "a", "site": 12}));
        let created = netbox
            .create("dcim.interfaces", &row(json!({"device": device, "name": "Ethernet1/1", "type": "other"})))
            .await
            .unwrap();
        let id = created["id"].as_u64().unwrap();
        assert_eq!(created["device"], json!({"id": device, "name": "a"}));
        netbox.update("dcim.interfaces", id, &row(json!({"description": "uplink"}))).await.unwrap();
        assert_eq!(netbox.row("dcim.interfaces", id).unwrap()["description"], json!("uplink"));
        netbox.delete("dcim.interfaces", id).await.unwrap();
        assert_eq!(netbox.row("dcim.interfaces", id), None);
        assert_eq!(
            netbox.writes(),
            [
                ("create", "dcim.interfaces".to_owned(), id),
                ("update", "dcim.interfaces".to_owned(), id),
                ("delete", "dcim.interfaces".to_owned(), id),
            ]
        );
    }

    #[tokio::test]
    async fn the_write_past_the_limit_fails() {
        let netbox = FakeGateway::new();
        netbox.fail_after(Some(1));
        netbox.create("ipam.vrfs", &row(json!({"name": "a"}))).await.unwrap();
        let error = netbox.create("ipam.vrfs", &row(json!({"name": "b"}))).await.unwrap_err();
        assert_eq!(error, request("injected failure"));
        assert_eq!(netbox.writes().len(), 1);
    }

    #[tokio::test]
    async fn a_duplicate_address_is_refused_where_uniqueness_is_enforced() {
        let netbox = FakeGateway::new();
        let loose = netbox.add("ipam.vrfs", json!({"name": "loose", "enforce_unique": false}));
        netbox.add("ipam.ip_addresses", json!({"address": "192.0.2.1/24", "vrf": null}));
        netbox.add("ipam.ip_addresses", json!({"address": "192.0.2.1/24", "vrf": loose}));
        let global = netbox.create("ipam.ip_addresses", &row(json!({"address": "192.0.2.1/32", "vrf": null}))).await;
        assert_eq!(global, Err(request("Duplicate IP address found: 192.0.2.1/24")));
        let in_vrf = netbox.create("ipam.ip_addresses", &row(json!({"address": "192.0.2.1/32", "vrf": loose}))).await;
        assert!(in_vrf.is_ok());
        netbox.enforce_global_unique(false);
        let global = netbox.create("ipam.ip_addresses", &row(json!({"address": "192.0.2.1/32", "vrf": null}))).await;
        assert!(global.is_ok());
    }

    #[tokio::test]
    async fn a_parent_interface_is_checked_and_protected() {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "fw01.dc1", "site": 12}));
        let lag = netbox.add("dcim.interfaces", json!({"device": device, "name": "PO2", "type": "lag"}));
        let physical = netbox
            .create("dcim.interfaces", &row(json!({"device": device, "name": "x", "type": "other", "parent": lag})))
            .await;
        assert_eq!(physical, Err(request("Only virtual interfaces may be assigned to a parent interface.")));
        let orphan = netbox
            .create("dcim.interfaces", &row(json!({"device": device, "name": "y", "type": "virtual", "parent": 5})))
            .await;
        assert_eq!(orphan, Err(request("Related object not found: interface 5")));
        netbox.add("dcim.interfaces", json!({"device": device, "name": "HOUSING", "type": "virtual", "parent": lag}));
        assert_eq!(
            netbox.delete("dcim.interfaces", lag).await,
            Err(request("Unable to delete interface: it has child interfaces"))
        );
    }

    #[tokio::test]
    async fn writes_are_refused_and_remembered_in_dry_run() {
        let netbox = FakeGateway::new();
        let vrf = netbox.add("ipam.vrfs", json!({"name": "a"}));
        assert!(!netbox.dry_run());
        netbox.refuse_writes(true);
        assert!(netbox.dry_run());
        let dry = |method: &str| GatewayError::DryRun { method: method.to_owned(), endpoint: "ipam.vrfs".to_owned() };
        assert_eq!(netbox.create("ipam.vrfs", &row(json!({"name": "b"}))).await, Err(dry("POST")));
        assert_eq!(netbox.update("ipam.vrfs", vrf, &row(json!({"name": "c"}))).await, Err(dry("PATCH")));
        assert_eq!(netbox.delete("ipam.vrfs", vrf).await, Err(dry("DELETE")));
        assert_eq!(
            netbox.refused(),
            [("POST", "ipam.vrfs".to_owned()), ("PATCH", "ipam.vrfs".to_owned()), ("DELETE", "ipam.vrfs".to_owned())]
        );
        assert_eq!(netbox.writes(), []);
        assert_eq!(netbox.row("ipam.vrfs", vrf).unwrap()["name"], json!("a"));
        // Reads still go through.
        assert_eq!(netbox.list("ipam.vrfs", &filters::<&str, &str>([])).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tags_are_written_by_name_slug_or_id_and_rendered_nested() {
        let netbox = FakeGateway::new();
        let tool = netbox.add("extras.tags", json!({"name": "netbox-omnisync", "slug": "netbox-omnisync"}));
        let gold = netbox.add("extras.tags", json!({"name": "Backup Gold", "slug": "backup-gold"}));
        let old = netbox.add("extras.tags", json!({"name": "NetBox-synced", "slug": "netbox-synced"}));
        let created = netbox
            .create("dcim.platforms", &row(json!({"name": "Debian 12", "tags": [{"name": "netbox-omnisync"}, old]})))
            .await
            .unwrap();
        let id = created["id"].as_u64().unwrap();
        assert_eq!(netbox.row("dcim.platforms", id).unwrap()["tags"], json!([tool, old]));
        assert_eq!(
            created["tags"],
            json!([
                {"id": tool, "name": "netbox-omnisync", "slug": "netbox-omnisync"},
                {"id": old, "name": "NetBox-synced", "slug": "netbox-synced"}
            ])
        );
        // A PATCH replaces the whole set.
        netbox.update("dcim.platforms", id, &row(json!({"tags": [{"slug": "backup-gold"}]}))).await.unwrap();
        assert_eq!(netbox.row("dcim.platforms", id).unwrap()["tags"], json!([gold]));
        // As NetBox: a tag is matched on the exact attributes given, and must exist.
        let unknown = netbox.update("dcim.platforms", id, &row(json!({"tags": [{"name": "backup gold"}]}))).await;
        assert_eq!(
            unknown,
            Err(request("Related object not found using the provided attributes: {\"name\":\"backup gold\"}"))
        );
        let missing = netbox.create("dcim.platforms", &row(json!({"name": "x", "tags": [4242]}))).await;
        assert_eq!(missing, Err(request("Related object not found using the provided attributes: 4242")));
        // A record without tags is rendered without the key, as before.
        let bare = netbox.create("dcim.platforms", &row(json!({"name": "Debian 13"}))).await.unwrap();
        assert_eq!(bare.get("tags"), None);
    }

    #[tokio::test]
    async fn custom_fields_are_merged_on_update() {
        let netbox = FakeGateway::new();
        let vm = netbox
            .add("virtualization.virtual_machines", json!({"name": "web01", "custom_fields": {"owner_team": "web"}}));
        let patch = row(json!({"custom_fields": {"uuid": "42d0"}}));
        netbox.update("virtualization.virtual_machines", vm, &patch).await.unwrap();
        assert_eq!(
            netbox.row("virtualization.virtual_machines", vm).unwrap()["custom_fields"],
            json!({"owner_team": "web", "uuid": "42d0"})
        );
    }

    #[tokio::test]
    async fn a_virtual_machine_and_what_hangs_under_it_are_rendered_in_the_api_shape() {
        let netbox = FakeGateway::new();
        let cluster = netbox.add("virtualization.clusters", json!({"name": "pve-lab"}));
        let vm = netbox.add(
            "virtualization.virtual_machines",
            json!({"name": "web01", "cluster": cluster, "status": "active", "vcpus": 2}),
        );
        let eth0 =
            netbox.add("virtualization.interfaces", json!({"name": "eth0", "virtual_machine": vm, "mode": "access"}));
        let mac = netbox.add(
            "dcim.mac_addresses",
            json!({"mac_address": "BC:24:11:AA:BB:CC", "assigned_object_type": "virtualization.vminterface",
                   "assigned_object_id": eth0}),
        );
        netbox.set("virtualization.interfaces", eth0, "primary_mac_address", json!(mac));
        let ip = netbox.add(
            "ipam.ip_addresses",
            json!({"address": "192.0.2.21/24", "status": "active", "assigned_object_type": "virtualization.vminterface",
                   "assigned_object_id": eth0}),
        );
        netbox.set("virtualization.virtual_machines", vm, "primary_ip4", json!(ip));
        let disk =
            netbox.add("virtualization.virtual_disks", json!({"name": "scsi0", "size": 32000, "virtual_machine": vm}));
        let all = filters::<&str, &str>([]);
        let nested_vm = json!({"id": vm, "name": "web01"});
        assert_eq!(
            netbox.list("virtualization.virtual_machines", &all).await.unwrap(),
            [row(json!({
                "id": vm, "name": "web01", "vcpus": 2,
                "cluster": {"id": cluster, "name": "pve-lab"},
                "status": {"value": "active", "label": "Active"},
                "primary_ip4": {"id": ip, "address": "192.0.2.21/24"}, "primary_ip6": null,
                "device": null, "platform": null, "role": null, "tenant": null, "site": null,
            }))]
        );
        assert_eq!(
            netbox.list("virtualization.interfaces", &all).await.unwrap(),
            [row(json!({
                "id": eth0, "name": "eth0", "virtual_machine": nested_vm,
                "mode": {"value": "access", "label": "Access"},
                "primary_mac_address": {"id": mac, "mac_address": "BC:24:11:AA:BB:CC"},
                "parent": null, "untagged_vlan": null, "vrf": null,
            }))]
        );
        assert_eq!(
            netbox.list("virtualization.virtual_disks", &all).await.unwrap(),
            [row(json!({"id": disk, "name": "scsi0", "size": 32000, "virtual_machine": nested_vm}))]
        );
        let assigned = json!({"id": eth0, "name": "eth0", "virtual_machine": nested_vm});
        assert_eq!(
            netbox.list("dcim.mac_addresses", &all).await.unwrap(),
            [row(json!({
                "id": mac, "mac_address": "BC:24:11:AA:BB:CC",
                "assigned_object_type": "virtualization.vminterface", "assigned_object_id": eth0,
                "assigned_object": assigned,
            }))]
        );
        assert_eq!(
            netbox.list("ipam.ip_addresses", &all).await.unwrap(),
            [row(json!({
                "id": ip, "address": "192.0.2.21/24", "status": {"value": "active", "label": "Active"}, "vrf": null,
                "assigned_object_type": "virtualization.vminterface", "assigned_object_id": eth0,
                "assigned_object": assigned,
            }))]
        );
    }

    #[tokio::test]
    async fn a_cluster_a_device_and_a_device_type_are_rendered_with_their_nested_objects() {
        let netbox = FakeGateway::new();
        let site = netbox.add("dcim.sites", json!({"name": "Lab"}));
        let kind = netbox.add("virtualization.cluster_types", json!({"name": "Proxmox"}));
        let cluster = netbox.add(
            "virtualization.clusters",
            json!({"name": "pve-lab", "type": kind, "status": "active", "scope_type": "dcim.site", "scope_id": site}),
        );
        let dell = netbox.add("dcim.manufacturers", json!({"name": "Dell"}));
        let r640 = netbox.add("dcim.device_types", json!({"model": "PowerEdge R640", "manufacturer": dell}));
        let role = netbox.add("dcim.device_roles", json!({"name": "Hypervisor"}));
        let host = netbox.add(
            "dcim.devices",
            json!({"name": "pve01", "site": site, "device_type": r640, "role": role, "cluster": cluster,
                   "status": "active"}),
        );
        let all = filters::<&str, &str>([]);
        assert_eq!(
            netbox.list("virtualization.clusters", &all).await.unwrap(),
            [row(json!({
                "id": cluster, "name": "pve-lab", "type": {"id": kind, "name": "Proxmox"},
                "status": {"value": "active", "label": "Active"}, "group": null, "tenant": null,
                "scope_type": "dcim.site", "scope_id": site, "scope": {"id": site, "name": "Lab"},
            }))]
        );
        assert_eq!(
            netbox.list("dcim.device_types", &all).await.unwrap(),
            [row(json!({"id": r640, "model": "PowerEdge R640", "manufacturer": {"id": dell, "name": "Dell"}}))]
        );
        assert_eq!(
            netbox.list("dcim.devices", &all).await.unwrap(),
            [row(json!({
                "id": host, "name": "pve01", "serial": "", "status": {"value": "active", "label": "Active"},
                "site": {"id": site, "name": "Lab"},
                "device_type": {"id": r640, "model": "PowerEdge R640"},
                "role": {"id": role, "name": "Hypervisor"},
                "cluster": {"id": cluster, "name": "pve-lab"},
                "platform": null, "tenant": null, "primary_ip4": null, "primary_ip6": null, "virtual_chassis": null,
                "parent_device": null,
            }))]
        );
        // A cluster without scope: both halves of the relation are null.
        let bare = netbox.add("virtualization.clusters", json!({"name": "other"}));
        let rows = netbox.list("virtualization.clusters", &filters([("name", "other")])).await.unwrap();
        assert_eq!(
            rows,
            [row(json!({
                "id": bare, "name": "other", "type": null, "group": null, "tenant": null,
                "scope_type": null, "scope_id": null, "scope": null,
            }))]
        );
    }

    #[tokio::test]
    async fn a_primary_mac_must_be_assigned_to_the_interface() {
        let netbox = FakeGateway::new();
        let vm = netbox.add("virtualization.virtual_machines", json!({"name": "web01"}));
        let eth0 = netbox.add("virtualization.interfaces", json!({"name": "eth0", "virtual_machine": vm}));
        let eth1 = netbox.add("virtualization.interfaces", json!({"name": "eth1", "virtual_machine": vm}));
        let mac = netbox.add(
            "dcim.mac_addresses",
            json!({"mac_address": "BC:24:11:AA:BB:CC", "assigned_object_type": "virtualization.vminterface",
                   "assigned_object_id": eth0}),
        );
        let primary = row(json!({"primary_mac_address": mac}));
        assert_eq!(
            netbox.update("virtualization.interfaces", eth1, &primary).await,
            Err(request("MAC address BC:24:11:AA:BB:CC is not assigned to this interface"))
        );
        assert_eq!(netbox.update("virtualization.interfaces", eth0, &primary).await, Ok(()));
        // The same id on a device interface is another interface.
        let device = netbox.add("dcim.devices", json!({"name": "pve01", "site": 12}));
        let eno1 = netbox.add("dcim.interfaces", json!({"device": device, "name": "eno1", "type": "other"}));
        assert_eq!(
            netbox.update("dcim.interfaces", eno1, &primary).await,
            Err(request("MAC address BC:24:11:AA:BB:CC is not assigned to this interface"))
        );
    }

    #[tokio::test]
    async fn a_primary_ip_must_be_assigned_to_an_interface_of_the_object() {
        let netbox = FakeGateway::new();
        let web = netbox.add("virtualization.virtual_machines", json!({"name": "web01"}));
        let db = netbox.add("virtualization.virtual_machines", json!({"name": "db01"}));
        let eth0 = netbox.add("virtualization.interfaces", json!({"name": "eth0", "virtual_machine": web}));
        let ip = netbox.add(
            "ipam.ip_addresses",
            json!({"address": "192.0.2.21/24", "assigned_object_type": "virtualization.vminterface",
                   "assigned_object_id": eth0}),
        );
        let primary = row(json!({"primary_ip4": ip}));
        assert_eq!(
            netbox.update("virtualization.virtual_machines", db, &primary).await,
            Err(request("The specified IP address (192.0.2.21/24) is not assigned to this VM."))
        );
        assert_eq!(netbox.update("virtualization.virtual_machines", web, &primary).await, Ok(()));
        let device = netbox.add("dcim.devices", json!({"name": "pve01", "site": 12}));
        assert_eq!(
            netbox.update("dcim.devices", device, &primary).await,
            Err(request("The specified IP address (192.0.2.21/24) is not assigned to this device."))
        );
        // Clearing it is always possible.
        assert_eq!(
            netbox.update("virtualization.virtual_machines", web, &row(json!({"primary_ip4": null}))).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn a_second_cable_on_a_termination_is_refused() {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "a", "site": 12}));
        let ports: Vec<u64> = ["e1", "e2", "e3"]
            .iter()
            .map(|name| netbox.add("dcim.interfaces", json!({"device": device, "name": name, "type": "other"})))
            .collect();
        let cable = |a: u64, b: u64| {
            row(json!({
                "a_terminations": [{"object_type": "dcim.interface", "object_id": a}],
                "b_terminations": [{"object_type": "dcim.interface", "object_id": b}],
            }))
        };
        netbox.create("dcim.cables", &cable(ports[0], ports[1])).await.unwrap();
        assert_eq!(
            netbox.create("dcim.cables", &cable(ports[2], ports[1])).await,
            Err(request("Duplicate termination found"))
        );
    }
}
