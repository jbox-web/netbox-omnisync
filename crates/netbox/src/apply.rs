//! Write changes to NetBox in dependency order, stopping at the first error.

use std::collections::{BTreeMap, BTreeSet};

use omnisync_core::change::{Action, Change};
use omnisync_core::gateway::{Gateway, GatewayError, Row, Write, filters};
use omnisync_core::network::cables::InterfacesOf;
use omnisync_core::network::names::interface_key;
use omnisync_core::network::state::NbDevice;
use omnisync_core::network::vlans::VlanHome;
use serde_json::{Value, json};

/// A write failed: the message names the change, `applied` counts the changes
/// written before it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ApplyError {
    pub message: String,
    pub applied: usize,
}

/// The id of the one row found; otherwise the ids of the rows found (none, or several).
fn only_id(rows: &[Row]) -> Result<u64, Vec<String>> {
    match rows {
        [one] => row_id(one).ok_or_else(Vec::new),
        _ => Err(rows.iter().filter_map(row_id).map(|id| id.to_string()).collect()),
    }
}

/// A write the changes make, as a dry run checks it: what it is, its
/// endpoint, and the names of the fields it sends, sorted.
pub type PlannedWrite = (Write, &'static str, Vec<String>);

/// The writes `Applier` makes for `changes`, without the ids it looks up:
/// a dry run checks their fields against NetBox and sends none. A deletion
/// sends no field and is left out.
pub fn planned_writes(changes: &[Change]) -> Vec<PlannedWrite> {
    let names = |fields: &[&str]| {
        let mut names: Vec<String> = fields.iter().map(|field| (*field).to_owned()).collect();
        names.sort();
        names
    };
    let mut writes = Vec::new();
    for change in changes.iter().filter(|change| change.action != Action::Delete) {
        let write = if change.action == Action::Create { Write::Create } else { Write::Update };
        let fields: Vec<&str> = change.fields.keys().map(String::as_str).collect();
        match change.kind.as_str() {
            // `apply_vlans`: the fields as they are, a creation active.
            "vlan" => {
                let mut sent = fields;
                if write == Write::Create {
                    sent.push("status");
                }
                writes.push((write, "ipam.vlans", names(&sent)));
            }
            // `apply_device`: the MAC is an object of its own, set as primary.
            "interface" => {
                let mut sent: Vec<&str> = fields.iter().copied().filter(|field| *field != "mac").collect();
                if write == Write::Create {
                    sent.push("device");
                }
                if !sent.is_empty() {
                    writes.push((write, "dcim.interfaces", names(&sent)));
                }
                if change.fields.get("mac").is_some_and(Value::is_string) {
                    let mac = ["mac_address", "assigned_object_type", "assigned_object_id"];
                    writes.push((Write::Create, "dcim.mac_addresses", names(&mac)));
                    writes.push((Write::Update, "dcim.interfaces", names(&["primary_mac_address"])));
                }
            }
            // `apply_ip`: the interface as the object the address is assigned to.
            "ip" => {
                let mut sent: Vec<&str> =
                    ["address", "vrf"].into_iter().filter(|field| fields.contains(field)).collect();
                if fields.contains(&"interface") {
                    sent.extend(["assigned_object_type", "assigned_object_id"]);
                }
                if write == Write::Create {
                    sent.push("status");
                }
                writes.push((write, "ipam.ip_addresses", names(&sent)));
            }
            "primary_ip" => writes.push((Write::Update, "dcim.devices", names(&["primary_ip4"]))),
            "serial" => writes.push((Write::Update, "dcim.devices", names(&["serial"]))),
            "cable" if write == Write::Create => {
                writes.push((Write::Create, "dcim.cables", names(&["a_terminations", "b_terminations", "status"])));
            }
            _ => {}
        }
    }
    writes
}

pub struct Applier<'g, G> {
    gateway: &'g G,
    vlan_ids: BTreeMap<(VlanHome, u64), u64>,
    /// Where the VLANs of a site are kept when it is not at the site itself, by site id.
    vlan_homes: BTreeMap<u64, VlanHome>,
    vrf_ids: BTreeMap<String, u64>,
    /// Number of changes written so far.
    pub applied: usize,
    on_applied: Option<Box<dyn Fn() + Send + Sync + 'g>>,
}

/// The name of the interface a change is about: its new name, or its key.
fn interface_name(change: &Change) -> &str {
    change.fields.get("name").and_then(Value::as_str).unwrap_or(&change.key)
}

fn row<const N: usize>(pairs: [(&str, Value); N]) -> Row {
    pairs.into_iter().map(|(key, value)| (key.to_owned(), value)).collect()
}

fn row_id(row: &Row) -> Option<u64> {
    row.get("id").and_then(Value::as_u64)
}

impl<'g, G: Gateway> Applier<'g, G> {
    pub fn new(gateway: &'g G) -> Self {
        Applier {
            gateway,
            vlan_ids: BTreeMap::new(),
            vlan_homes: BTreeMap::new(),
            vrf_ids: BTreeMap::new(),
            applied: 0,
            on_applied: None,
        }
    }

    /// Tells where the VLANs of each site are kept, by site id: a site that
    /// is not listed keeps its own. The VLAN an interface is given by its
    /// number is then looked up in the VLAN group of the site of its device.
    pub fn set_vlan_homes(&mut self, homes: BTreeMap<u64, VlanHome>) {
        self.vlan_homes = homes;
    }

    /// Called once per applied change: the progress counts writes as they land.
    pub fn on_applied(mut self, callback: impl Fn() + Send + Sync + 'g) -> Self {
        self.on_applied = Some(Box::new(callback));
        self
    }

    fn done(&mut self) {
        self.applied += 1;
        if let Some(callback) = &self.on_applied {
            callback();
        }
    }

    fn fail(&self, change: &Change, message: impl std::fmt::Display) -> ApplyError {
        ApplyError {
            message: format!("{} {} {} {}: {message}", change.action, change.kind, change.device, change.key),
            applied: self.applied,
        }
    }

    /// The result of a NetBox call, its failure named after the change.
    fn run<T>(&self, change: &Change, result: Result<T, GatewayError>) -> Result<T, ApplyError> {
        result.map_err(|error| self.fail(change, error))
    }

    fn reference(&self, change: &Change) -> Result<u64, ApplyError> {
        change.id.ok_or_else(|| self.fail(change, "no NetBox id"))
    }

    async fn vlan_id(&mut self, change: &Change, site_id: u64, vid: u64) -> Result<u64, ApplyError> {
        let home = self.vlan_homes.get(&site_id).cloned().unwrap_or(VlanHome::Site(site_id));
        let key = (home, vid);
        if let Some(id) = self.vlan_ids.get(&key) {
            return Ok(*id);
        }
        let home = &key.0;
        let scope = match home {
            VlanHome::Site(id) => ("site_id", *id),
            VlanHome::Group { id, .. } => ("group_id", *id),
        };
        let found = self.gateway.list("ipam.vlans", &filters([scope, ("vid", vid)])).await;
        let rows = self.run(change, found)?;
        // Without a VLAN group, NetBox lets two VLANs of a site share a number:
        // the first would be an arbitrary one.
        let id = match only_id(&rows) {
            Ok(id) => id,
            Err(ids) if ids.is_empty() => {
                let place = match home {
                    VlanHome::Site(_) => format!("on {home}"),
                    VlanHome::Group { .. } => format!("in {home}"),
                };
                return Err(self.fail(change, format!("VLAN {vid} missing {place}")));
            }
            Err(ids) => {
                return Err(self.fail(
                    change,
                    format!("{} VLANs of {home} have the number {vid} (ids {})", ids.len(), ids.join(", ")),
                ));
            }
        };
        self.vlan_ids.insert(key, id);
        Ok(id)
    }

    async fn vrf_id(&mut self, change: &Change, name: &str) -> Result<u64, ApplyError> {
        if let Some(id) = self.vrf_ids.get(name) {
            return Ok(*id);
        }
        let found = self.gateway.list("ipam.vrfs", &filters([("name", name)])).await;
        let rows = self.run(change, found)?;
        // A VRF name is not unique in NetBox, only its route distinguisher is.
        let id = match only_id(&rows) {
            Ok(id) => id,
            Err(ids) if ids.is_empty() => return Err(self.fail(change, format!("VRF {name} missing in Netbox"))),
            Err(ids) => {
                return Err(self
                    .fail(change, format!("{} VRFs in Netbox are named {name} (ids {})", ids.len(), ids.join(", "))));
            }
        };
        self.vrf_ids.insert(name.to_owned(), id);
        Ok(id)
    }

    pub async fn apply_vlans(&mut self, changes: &[Change]) -> Result<(), ApplyError> {
        for change in changes {
            let mut payload: Row = change.fields.clone().into_iter().collect();
            if change.action == Action::Create {
                payload.insert("status".to_owned(), json!("active"));
                let created = self.gateway.create("ipam.vlans", &payload).await;
                self.run(change, created)?;
            } else {
                let id = self.reference(change)?;
                let updated = self.gateway.update("ipam.vlans", id, &payload).await;
                self.run(change, updated)?;
            }
            self.done();
        }
        Ok(())
    }

    /// The interface a `lag` or `parent` field names: on this device, or among
    /// the port-channels of the other members of the stack.
    fn target(
        &self,
        change: &Change,
        what: &str,
        value: &Value,
        ids: &BTreeMap<String, u64>,
        lag_ids: &BTreeMap<String, u64>,
    ) -> Result<Value, ApplyError> {
        let Some(name) = value.as_str() else {
            return Ok(Value::Null);
        };
        let key = interface_key(name);
        ids.get(&key)
            .or_else(|| lag_ids.get(&key))
            .map(|id| json!(id))
            .ok_or_else(|| self.fail(change, format!("{what} {name} not found")))
    }

    async fn interface_payload(
        &mut self,
        change: &Change,
        ids: &BTreeMap<String, u64>,
        site_id: u64,
        lag_ids: &BTreeMap<String, u64>,
    ) -> Result<Row, ApplyError> {
        let mut payload = Row::new();
        for (key, value) in &change.fields {
            let written = match key.as_str() {
                "mac" => continue,
                "lag" => self.target(change, "LAG", value, ids, lag_ids)?,
                "parent" => self.target(change, "parent", value, ids, lag_ids)?,
                "untagged_vlan" => match value.as_u64() {
                    Some(vid) => json!(self.vlan_id(change, site_id, vid).await?),
                    None => Value::Null,
                },
                "tagged_vlans" => {
                    let mut vlans = Vec::new();
                    for vid in value.as_array().into_iter().flatten().filter_map(Value::as_u64) {
                        vlans.push(self.vlan_id(change, site_id, vid).await?);
                    }
                    json!(vlans)
                }
                _ => value.clone(),
            };
            payload.insert(key.clone(), written);
        }
        Ok(payload)
    }

    async fn set_mac(&self, interface_id: u64, mac: &str) -> Result<(), GatewayError> {
        let existing = self.gateway.list("dcim.mac_addresses", &filters([("interface_id", interface_id)])).await?;
        let known = existing.iter().find(|found| {
            found.get("mac_address").and_then(Value::as_str).is_some_and(|address| address.to_uppercase() == mac)
        });
        let mac_id = match known.and_then(row_id) {
            Some(id) => id,
            None => {
                let created = self
                    .gateway
                    .create(
                        "dcim.mac_addresses",
                        &row([
                            ("mac_address", json!(mac)),
                            ("assigned_object_type", json!("dcim.interface")),
                            ("assigned_object_id", json!(interface_id)),
                        ]),
                    )
                    .await?;
                row_id(&created).ok_or_else(|| GatewayError::Request("created MAC address has no id".to_owned()))?
            }
        };
        self.gateway.update("dcim.interfaces", interface_id, &row([("primary_mac_address", json!(mac_id))])).await
    }

    /// Apply a device's changes; `lag_ids` holds the port-channels of the other
    /// members of a stack (key: interface_key), where a member's LAG parent may live.
    pub async fn apply_device(
        &mut self,
        device: &NbDevice,
        changes: &[Change],
        lag_ids: &BTreeMap<String, u64>,
    ) -> Result<(), ApplyError> {
        let mut ids: BTreeMap<String, u64> =
            device.interfaces.iter().map(|(key, interface)| (key.clone(), interface.id)).collect();
        let mut interface_changes: Vec<&Change> =
            changes.iter().filter(|change| change.kind == "interface" && change.action != Action::Delete).collect();
        // A LAG must exist before its members point at it, a parent before its
        // children: an interface is written after everything it points at.
        let by_key: BTreeMap<String, &Change> =
            interface_changes.iter().map(|change| (interface_key(interface_name(change)), *change)).collect();
        interface_changes.sort_by_key(|change| {
            let aggregate = change.fields.get("type").and_then(Value::as_str) == Some("lag")
                || interface_key(&change.key).starts_with("port-channel");
            (rank(change, &by_key, &BTreeSet::new()), usize::from(!aggregate))
        });
        for change in interface_changes {
            let payload = self.interface_payload(change, &ids, device.site_id, lag_ids).await?;
            let interface_id = if change.action == Action::Create {
                let mut created = row([("device", json!(device.id))]);
                created.extend(payload);
                let answer = self.gateway.create("dcim.interfaces", &created).await;
                let answer = self.run(change, answer)?;
                row_id(&answer).ok_or_else(|| self.fail(change, "created interface has no id"))?
            } else {
                let id = self.reference(change)?;
                if !payload.is_empty() {
                    let updated = self.gateway.update("dcim.interfaces", id, &payload).await;
                    self.run(change, updated)?;
                }
                id
            };
            ids.insert(interface_key(interface_name(change)), interface_id);
            if let Some(mac) = change.fields.get("mac").and_then(Value::as_str) {
                let set = self.set_mac(interface_id, mac).await;
                self.run(change, set)?;
            }
            self.done();
        }
        // The primary MAC was moved above: the stale objects are no longer referenced.
        for change in changes.iter().filter(|change| change.kind == "mac" && change.action == Action::Delete) {
            let deleted = self.gateway.delete("dcim.mac_addresses", self.reference(change)?).await;
            self.run(change, deleted)?;
            self.done();
        }
        for change in changes.iter().filter(|change| change.kind == "ip" && change.action != Action::Delete) {
            self.apply_ip(change, &ids).await?;
        }
        for change in changes {
            if change.kind == "primary_ip" {
                self.apply_primary(change, device).await?;
            } else if change.kind == "serial" {
                let serial = change.fields.get("serial").cloned().unwrap_or(Value::Null);
                let updated = self.gateway.update("dcim.devices", device.id, &row([("serial", serial)])).await;
                self.run(change, updated)?;
                self.done();
            }
        }
        for change in changes.iter().filter(|change| change.kind == "ip" && change.action == Action::Delete) {
            let deleted = self.gateway.delete("ipam.ip_addresses", self.reference(change)?).await;
            self.run(change, deleted)?;
            self.done();
        }
        Ok(())
    }

    async fn apply_ip(&mut self, change: &Change, ids: &BTreeMap<String, u64>) -> Result<(), ApplyError> {
        let mut payload = Row::new();
        if let Some(address) = change.fields.get("address") {
            payload.insert("address".to_owned(), address.clone());
        }
        if let Some(vrf) = change.fields.get("vrf") {
            let id = match vrf.as_str() {
                Some(name) => json!(self.vrf_id(change, name).await?),
                None => Value::Null,
            };
            payload.insert("vrf".to_owned(), id);
        }
        if let Some(name) = change.fields.get("interface").and_then(Value::as_str) {
            let id = ids
                .get(&interface_key(name))
                .ok_or_else(|| self.fail(change, format!("interface {name} not found")))?;
            payload.insert("assigned_object_type".to_owned(), json!("dcim.interface"));
            payload.insert("assigned_object_id".to_owned(), json!(id));
        }
        if change.action == Action::Create {
            payload.insert("status".to_owned(), json!("active"));
            let created = self.gateway.create("ipam.ip_addresses", &payload).await;
            self.run(change, created)?;
        } else {
            let updated = self.gateway.update("ipam.ip_addresses", self.reference(change)?, &payload).await;
            self.run(change, updated)?;
        }
        self.done();
        Ok(())
    }

    async fn apply_primary(&mut self, change: &Change, device: &NbDevice) -> Result<(), ApplyError> {
        let address = change.fields.get("address").and_then(Value::as_str).unwrap_or_default();
        let vrf = change.fields.get("vrf").and_then(Value::as_str);
        let host = address.split('/').next().unwrap_or(address);
        let found = self
            .gateway
            .list("ipam.ip_addresses", &filters([("device_id", device.id.to_string()), ("address", host.to_owned())]))
            .await;
        let rows = self.run(change, found)?;
        let held = rows
            .iter()
            .find(|found| found.get("vrf").and_then(|vrf| vrf.get("name")).and_then(Value::as_str) == vrf)
            .and_then(row_id)
            .ok_or_else(|| self.fail(change, format!("{address} not assigned to {}", device.name)))?;
        let updated = self.gateway.update("dcim.devices", device.id, &row([("primary_ip4", json!(held))])).await;
        self.run(change, updated)?;
        self.done();
        Ok(())
    }

    pub async fn apply_cables(
        &mut self,
        changes: &[Change],
        interfaces_of: &InterfacesOf<'_>,
    ) -> Result<(), ApplyError> {
        for change in changes.iter().filter(|change| change.action == Action::Delete) {
            let deleted = self.gateway.delete("dcim.cables", self.reference(change)?).await;
            self.run(change, deleted)?;
            self.done();
        }
        for change in changes.iter().filter(|change| change.action == Action::Create) {
            let mut ends = Vec::new();
            for side in ["a", "b"] {
                let field = |suffix: &str| {
                    change.fields.get(&format!("{side}_{suffix}")).and_then(Value::as_str).unwrap_or_default()
                };
                let (device, name) = (field("device"), field("interface"));
                let interface = interfaces_of(device)
                    .and_then(|interfaces| interfaces.get(&interface_key(name)))
                    .ok_or_else(|| self.fail(change, format!("{device} {name} not found")))?;
                ends.push(json!([{"object_type": "dcim.interface", "object_id": interface.id}]));
            }
            let b = ends.pop().unwrap_or(Value::Null);
            let a = ends.pop().unwrap_or(Value::Null);
            let payload = row([("a_terminations", a), ("b_terminations", b), ("status", json!("connected"))]);
            let created = self.gateway.create("dcim.cables", &payload).await;
            self.run(change, created)?;
            self.done();
        }
        Ok(())
    }

    pub async fn apply_interface_deletions(&mut self, changes: &[Change]) -> Result<(), ApplyError> {
        for change in changes {
            let deleted = self.gateway.delete("dcim.interfaces", self.reference(change)?).await;
            self.run(change, deleted)?;
            self.done();
        }
        Ok(())
    }
}

/// How many interfaces of this run must be written before this one: the LAG
/// and the parent it points at, and what those point at in turn.
fn rank(change: &Change, by_key: &BTreeMap<String, &Change>, above: &BTreeSet<String>) -> usize {
    let key = interface_key(interface_name(change));
    let mut below = above.clone();
    below.insert(key.clone());
    ["lag", "parent"]
        .iter()
        .filter_map(|field| change.fields.get(*field).and_then(Value::as_str))
        .map(interface_key)
        .filter(|target| *target != key && !above.contains(target))
        .filter_map(|target| by_key.get(&target))
        .map(|target| 1 + rank(target, by_key, &below))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use omnisync_core::gateway::Filters;

    use super::*;
    use crate::state::read_device;
    use crate::testing::FakeGateway;

    const DEVICE: &str = "nexus01.lab01";

    fn netbox() -> FakeGateway {
        let netbox = FakeGateway::new();
        netbox.add("ipam.vlans", json!({"site": 12, "vid": 26, "name": "PPE"}));
        netbox.add("ipam.vlans", json!({"site": 12, "vid": 2800, "name": "Admin"}));
        netbox.add("ipam.vrfs", json!({"name": "mgmt-sw"}));
        netbox.add("dcim.devices", json!({"name": DEVICE, "site": 12, "serial": ""}));
        netbox
    }

    fn device_id(netbox: &FakeGateway) -> u64 {
        netbox.find("dcim.devices", "name", &json!(DEVICE)).expect("the device exists")
    }

    fn create<const N: usize>(name: &str, fields: [(&str, Value); N]) -> Change {
        let mut all: BTreeMap<&str, Value> = BTreeMap::from([
            ("name", json!(name)),
            ("enabled", json!(true)),
            ("description", json!("")),
            ("lag", json!(null)),
            ("type", json!("other")),
        ]);
        all.extend(fields);
        Change::new("interface", Action::Create, DEVICE, name).fields(all)
    }

    async fn device(netbox: &FakeGateway, name: &str) -> NbDevice {
        read_device(netbox, name).await.expect("the device is read")
    }

    fn no_lags() -> BTreeMap<String, u64> {
        BTreeMap::new()
    }

    #[tokio::test]
    async fn lag_created_before_its_member() {
        let netbox = netbox();
        let mut applier = Applier::new(&netbox);
        let changes = [
            create("Ethernet1/51", [("type", json!("10gbase-x-sfpp")), ("lag", json!("port-channel10"))]),
            create("port-channel10", [("type", json!("lag"))]),
        ];
        applier.apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags()).await.expect("applied");
        let after = device(&netbox, DEVICE).await;
        assert_eq!(after.interfaces["ethernet1/51"].lag.as_deref(), Some("port-channel10"));
        assert_eq!(applier.applied, 2);
    }

    // The order of netbox-switch-sync (apply.py): among interfaces that do not
    // point at one another, the port-channels first, by their type or by their
    // name, then the others, each group in the order of the changes.
    #[tokio::test]
    async fn port_channels_are_written_before_the_interfaces_that_do_not_depend_on_them() {
        let netbox = netbox();
        let changes = [
            create("Ethernet1/1", []),
            create("Po1", [("type", json!("lag"))]),
            create("Ethernet1/2", []),
            create("port-channel5", []),
        ];
        let applied = Applier::new(&netbox).apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags()).await;
        assert_eq!(applied, Ok(()));
        let id = |name: &str| netbox.find("dcim.interfaces", "name", &json!(name)).expect("created");
        let created: Vec<u64> = netbox.writes().into_iter().map(|(_, _, id)| id).collect();
        assert_eq!(created, [id("Po1"), id("port-channel5"), id("Ethernet1/1"), id("Ethernet1/2")]);
    }

    #[tokio::test]
    async fn dot1q_and_mac() {
        let netbox = netbox();
        let changes = [create(
            "Ethernet1/1",
            [
                ("type", json!("10gbase-x-sfpp")),
                ("mode", json!("tagged")),
                ("untagged_vlan", json!(26)),
                ("tagged_vlans", json!([2800])),
                ("mac", json!("02:08:D1:90:97:2D")),
            ],
        )];
        Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect("applied");
        let eth = device(&netbox, DEVICE).await.interfaces["ethernet1/1"].clone();
        assert_eq!(eth.mode.as_deref(), Some("tagged"));
        assert_eq!(eth.untagged_vlan, Some(26));
        assert_eq!(eth.tagged_vlans, [2800]);
        assert_eq!(eth.mac.as_deref(), Some("02:08:D1:90:97:2D"));
    }

    #[tokio::test]
    async fn ip_reattached_keeps_object_and_primary() {
        let netbox = netbox();
        let id = device_id(&netbox);
        let admin = netbox.add("dcim.interfaces", json!({"device": id, "name": "admin", "type": "virtual"}));
        netbox.add("dcim.interfaces", json!({"device": id, "name": "Vlan2800", "type": "virtual"}));
        let ip = netbox.add(
            "ipam.ip_addresses",
            json!({"address": "192.0.2.239/24", "vrf": null, "assigned_object_type": "dcim.interface",
                   "assigned_object_id": admin, "status": "active"}),
        );
        netbox.set("dcim.devices", id, "primary_ip4", json!(ip));
        let changes = [Change::new("ip", Action::Update, DEVICE, "192.0.2.239/24")
            .fields([("interface", json!("Vlan2800")), ("vrf", json!("mgmt-sw"))])
            .id(ip)];
        Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect("applied");
        let after = device(&netbox, DEVICE).await;
        let ips: Vec<(u64, Option<&str>, Option<&str>)> =
            after.ips.iter().map(|ip| (ip.id, ip.interface.as_deref(), ip.vrf.as_deref())).collect();
        assert_eq!(ips, [(ip, Some("Vlan2800"), Some("mgmt-sw"))]);
        assert_eq!(after.primary_ip4.as_deref(), Some("192.0.2.239/24"));
    }

    #[tokio::test]
    async fn primary_ip_and_serial() {
        let netbox = netbox();
        let id = device_id(&netbox);
        let svi = netbox.add("dcim.interfaces", json!({"device": id, "name": "Vlan2800", "type": "virtual"}));
        netbox.add(
            "ipam.ip_addresses",
            json!({"address": "192.0.2.239/24", "vrf": null, "assigned_object_type": "dcim.interface",
                   "assigned_object_id": svi, "status": "active"}),
        );
        let changes = [
            Change::new("primary_ip", Action::Update, DEVICE, "192.0.2.239/24")
                .fields([("address", json!("192.0.2.239/24")), ("vrf", json!(null))])
                .id(id),
            Change::new("serial", Action::Update, DEVICE, DEVICE).fields([("serial", json!("FOC9792A4K9"))]).id(id),
        ];
        Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect("applied");
        let after = device(&netbox, DEVICE).await;
        assert_eq!(after.primary_ip4.as_deref(), Some("192.0.2.239/24"));
        assert_eq!(after.serial, "FOC9792A4K9");
    }

    #[tokio::test]
    async fn stops_at_first_error() {
        let netbox = netbox();
        netbox.fail_after(Some(1));
        let mut applier = Applier::new(&netbox);
        let changes = [create("Ethernet1/1", []), create("Ethernet1/2", [])];
        let error = applier
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("the second write fails");
        assert_eq!(error.applied, 1);
        assert!(error.message.starts_with("create interface nexus01.lab01 Ethernet1/2: "), "{error}");
        let after = device(&netbox, DEVICE).await;
        assert_eq!(after.interfaces.keys().collect::<Vec<_>>(), ["ethernet1/1"]);
    }

    #[tokio::test]
    async fn missing_vlan_is_an_error() {
        let netbox = netbox();
        let changes = [create(
            "Ethernet1/1",
            [("mode", json!("access")), ("untagged_vlan", json!(999)), ("tagged_vlans", json!([]))],
        )];
        let error = Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("the VLAN is missing");
        assert_eq!(error.message, "create interface nexus01.lab01 Ethernet1/1: VLAN 999 missing on site 12");
        assert_eq!(error.applied, 0);
    }

    // A VRF name is not unique in NetBox (only `rd` is): an address written to
    // the first of two would land in an arbitrary table.
    #[tokio::test]
    async fn a_vrf_name_two_vrfs_hold_is_an_error_naming_both() {
        let netbox = netbox();
        let first = netbox.find("ipam.vrfs", "name", &json!("mgmt-sw")).unwrap();
        let second = netbox.add("ipam.vrfs", json!({"name": "mgmt-sw"}));
        let changes = [Change::new("ip", Action::Create, DEVICE, "192.0.2.250/24")
            .fields([("address", json!("192.0.2.250/24")), ("vrf", json!("mgmt-sw"))])];
        let error = Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("two VRFs have the name");
        assert_eq!(
            error.message,
            format!(
                "create ip nexus01.lab01 192.0.2.250/24: 2 VRFs in Netbox are named mgmt-sw (ids {first}, {second})"
            )
        );
        assert_eq!(error.applied, 0);
    }

    // Without a VLAN group, NetBox lets two VLANs of one site share a number.
    #[tokio::test]
    async fn a_vlan_number_two_vlans_of_the_site_hold_is_an_error_naming_both() {
        let netbox = netbox();
        let first = netbox.find("ipam.vlans", "name", &json!("PPE")).unwrap();
        let second = netbox.add("ipam.vlans", json!({"site": 12, "vid": 26, "name": "PPE-bis"}));
        let changes = [create(
            "Ethernet1/1",
            [("mode", json!("access")), ("untagged_vlan", json!(26)), ("tagged_vlans", json!([]))],
        )];
        let error = Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("two VLANs have the number");
        assert_eq!(
            error.message,
            format!(
                "create interface nexus01.lab01 Ethernet1/1: 2 VLANs of site 12 have the number 26 (ids {first}, {second})"
            )
        );
    }

    // The site of the device keeps its VLANs in a group: NetBox holds the VLAN
    // 26 twice, at the site (from before) and in the group, and only the one
    // of the group is the port's.
    #[tokio::test]
    async fn the_vlan_of_a_device_whose_site_is_in_a_group_is_the_one_of_the_group() {
        let netbox = netbox();
        let group = netbox.add("ipam.vlan_groups", json!({"name": "East", "slug": "east"}));
        let shared = netbox.add("ipam.vlans", json!({"group": group, "vid": 26, "name": "PPE"}));
        let trunked = netbox.add("ipam.vlans", json!({"group": group, "vid": 27, "name": "DMZ"}));
        let changes = [create(
            "Ethernet1/1",
            [("mode", json!("tagged")), ("untagged_vlan", json!(26)), ("tagged_vlans", json!([27]))],
        )];
        let mut applier = Applier::new(&netbox);
        applier.set_vlan_homes(BTreeMap::from([(12, VlanHome::Group { id: group, name: "East".to_owned() })]));
        applier.apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags()).await.expect("applied");
        let port = netbox.find("dcim.interfaces", "name", &json!("Ethernet1/1")).expect("the port");
        let port = netbox.row("dcim.interfaces", port).expect("its row");
        assert_eq!(port["untagged_vlan"], json!(shared));
        assert_eq!(port["tagged_vlans"], json!([trunked]));
    }

    #[tokio::test]
    async fn a_vlan_the_group_does_not_hold_is_an_error_naming_the_group() {
        let netbox = netbox();
        let group = netbox.add("ipam.vlan_groups", json!({"name": "East", "slug": "east"}));
        // The site holds the VLAN 26: it is not the one of the group.
        let changes = [create(
            "Ethernet1/1",
            [("mode", json!("access")), ("untagged_vlan", json!(26)), ("tagged_vlans", json!([]))],
        )];
        let mut applier = Applier::new(&netbox);
        applier.set_vlan_homes(BTreeMap::from([(12, VlanHome::Group { id: group, name: "East".to_owned() })]));
        let error = applier
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("the group has no such VLAN");
        assert_eq!(error.message, "create interface nexus01.lab01 Ethernet1/1: VLAN 26 missing in VLAN group East");
        let first = netbox.add("ipam.vlans", json!({"group": group, "vid": 26, "name": "PPE"}));
        let second = netbox.add("ipam.vlans", json!({"group": group, "vid": 26, "name": "PPE-bis"}));
        let error = applier
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("two VLANs have the number");
        assert_eq!(
            error.message,
            format!(
                "create interface nexus01.lab01 Ethernet1/1: 2 VLANs of VLAN group East have the number 26 \
                 (ids {first}, {second})"
            )
        );
    }

    #[tokio::test]
    async fn vlans_cables_and_deletions() {
        let netbox = netbox();
        let mut applier = Applier::new(&netbox);
        let vlan = Change::new("vlan", Action::Create, "", "3012").fields([
            ("site", json!(12)),
            ("vid", json!(3012)),
            ("name", json!("Monitoring")),
        ]);
        applier.apply_vlans(&[vlan]).await.expect("applied");
        assert!(netbox.find("ipam.vlans", "vid", &json!(3012)).is_some());

        let id = device_id(&netbox);
        let other = netbox.add("dcim.devices", json!({"name": "nexus02.lab01", "site": 12}));
        let a = netbox.add("dcim.interfaces", json!({"device": id, "name": "Ethernet1/48", "type": "other"}));
        let b = netbox.add("dcim.interfaces", json!({"device": other, "name": "Ethernet1/48", "type": "other"}));
        let cable = Change::new("cable", Action::Create, "", "x").fields([
            ("a_device", DEVICE),
            ("a_interface", "Ethernet1/48"),
            ("b_device", "nexus02.lab01"),
            ("b_interface", "Ethernet1/48"),
        ]);
        let known: BTreeMap<String, _> = BTreeMap::from([
            (DEVICE.to_owned(), device(&netbox, DEVICE).await.interfaces),
            ("nexus02.lab01".to_owned(), device(&netbox, "nexus02.lab01").await.interfaces),
        ]);
        applier.apply_cables(&[cable], &|name| known.get(name)).await.expect("applied");
        assert!(device(&netbox, DEVICE).await.interfaces["ethernet1/48"].cable_id.is_some());

        let deletion = Change::new("interface", Action::Delete, DEVICE, "Ethernet1/48").id(a);
        applier.apply_interface_deletions(&[deletion]).await.expect("applied");
        assert!(!device(&netbox, DEVICE).await.interfaces.contains_key("ethernet1/48"));
        assert!(netbox.row("dcim.interfaces", b).is_some());
    }

    /// Records the writes the applier sends, as a dry run plans them.
    struct Recorder {
        netbox: FakeGateway,
        writes: std::sync::Mutex<Vec<PlannedWrite>>,
    }

    impl Recorder {
        fn record(&self, write: Write, endpoint: &str, payload: &Row) {
            let mut fields: Vec<String> = payload.keys().cloned().collect();
            fields.sort();
            let endpoint = planned_endpoint(endpoint);
            self.writes.lock().expect("the writes").push((write, endpoint, fields));
        }
    }

    /// The endpoints the network family writes to.
    fn planned_endpoint(endpoint: &str) -> &'static str {
        ["ipam.vlans", "dcim.interfaces", "dcim.mac_addresses", "ipam.ip_addresses", "dcim.devices", "dcim.cables"]
            .into_iter()
            .find(|known| *known == endpoint)
            .unwrap_or_else(|| panic!("a write to {endpoint}"))
    }

    impl Gateway for Recorder {
        async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
            self.netbox.list(endpoint, filters).await
        }

        async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
            self.record(Write::Create, endpoint, payload);
            self.netbox.create(endpoint, payload).await
        }

        async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
            self.record(Write::Update, endpoint, payload);
            self.netbox.update(endpoint, id, payload).await
        }

        async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
            self.netbox.delete(endpoint, id).await
        }

        async fn check_write(&self, write: Write, endpoint: &str, fields: &[String]) -> Result<(), GatewayError> {
            self.netbox.check_write(write, endpoint, fields).await
        }
    }

    // What a dry run checks must be what the real run sends: every kind of
    // change applied for real, its writes recorded, and compared with the
    // writes `planned_writes` gives for the same changes.
    #[tokio::test]
    async fn the_writes_a_dry_run_checks_are_those_the_applier_sends() {
        let netbox = netbox();
        let id = device_id(&netbox);
        let other = netbox.add("dcim.devices", json!({"name": "nexus02.lab01", "site": 12}));
        let svi = netbox.add("dcim.interfaces", json!({"device": id, "name": "Vlan2800", "type": "virtual"}));
        netbox.add("dcim.interfaces", json!({"device": other, "name": "Ethernet1/48", "type": "other"}));
        let ip = netbox.add(
            "ipam.ip_addresses",
            json!({"address": "192.0.2.239/24", "vrf": null, "assigned_object_type": "dcim.interface",
                   "assigned_object_id": svi, "status": "active"}),
        );
        let admin_vlan = netbox.find("ipam.vlans", "vid", &json!(2800)).expect("VLAN 2800");
        let vlans = [
            Change::new("vlan", Action::Create, "", "3012").fields([
                ("site", json!(12)),
                ("vid", json!(3012)),
                ("name", json!("Monitoring")),
            ]),
            Change::new("vlan", Action::Update, "", "2800").fields([("name", json!("Admin LAN"))]).id(admin_vlan),
        ];
        let device_changes = [
            create("port-channel10", [("type", json!("lag"))]),
            create(
                "Ethernet1/48",
                [
                    ("lag", json!("port-channel10")),
                    ("mode", json!("tagged")),
                    ("untagged_vlan", json!(26)),
                    ("tagged_vlans", json!([2800])),
                    ("mac", json!("02:08:D1:90:97:2D")),
                ],
            ),
            Change::new("interface", Action::Update, DEVICE, "Vlan2800")
                .fields([("description", json!("admin"))])
                .id(svi),
            Change::new("ip", Action::Create, DEVICE, "192.0.2.240/24").fields([
                ("address", json!("192.0.2.240/24")),
                ("vrf", json!("mgmt-sw")),
                ("interface", json!("Vlan2800")),
            ]),
            Change::new("ip", Action::Update, DEVICE, "192.0.2.239/24")
                .fields([("interface", json!("Vlan2800"))])
                .id(ip),
            Change::new("primary_ip", Action::Update, DEVICE, "192.0.2.239/24")
                .fields([("address", json!("192.0.2.239/24")), ("vrf", json!(null))])
                .id(id),
            Change::new("serial", Action::Update, DEVICE, DEVICE).fields([("serial", json!("FOC9792A4K9"))]).id(id),
        ];
        let cable = Change::new("cable", Action::Create, "", "x").fields([
            ("a_device", DEVICE),
            ("a_interface", "Ethernet1/48"),
            ("b_device", "nexus02.lab01"),
            ("b_interface", "Ethernet1/48"),
        ]);
        let recorder = Recorder { netbox, writes: std::sync::Mutex::default() };
        let mut applier = Applier::new(&recorder);
        applier.apply_vlans(&vlans).await.expect("applied");
        applier
            .apply_device(&device(&recorder.netbox, DEVICE).await, &device_changes, &no_lags())
            .await
            .expect("applied");
        let known: BTreeMap<String, _> = BTreeMap::from([
            (DEVICE.to_owned(), device(&recorder.netbox, DEVICE).await.interfaces),
            ("nexus02.lab01".to_owned(), device(&recorder.netbox, "nexus02.lab01").await.interfaces),
        ]);
        applier.apply_cables(std::slice::from_ref(&cable), &|name| known.get(name)).await.expect("applied");

        let mut sent = recorder.writes.lock().unwrap().clone();
        let all: Vec<Change> = vlans.iter().chain(&device_changes).chain([&cable]).cloned().collect();
        let mut planned = planned_writes(&all);
        sent.sort();
        planned.sort();
        assert_eq!(planned, sent);
    }

    #[tokio::test]
    async fn lag_on_another_stack_member() {
        // Port-channel1 sits on the master; a member of stack member 2 points at it.
        let netbox = netbox();
        let master = device_id(&netbox);
        let lag = netbox.add("dcim.interfaces", json!({"device": master, "name": "Port-channel1", "type": "lag"}));
        netbox.add("dcim.devices", json!({"name": "2960-stack02.lab01", "site": 12, "serial": ""}));
        let member = device(&netbox, "2960-stack02.lab01").await;
        let mut change = create("TenGigabitEthernet2/0/2", [("lag", json!("Port-channel1"))]);
        change.device = "2960-stack02.lab01".to_owned();
        Applier::new(&netbox)
            .apply_device(&member, &[change], &BTreeMap::from([("port-channel1".to_owned(), lag)]))
            .await
            .expect("applied");
        let after = device(&netbox, "2960-stack02.lab01").await;
        assert_eq!(after.interfaces["tengigabitethernet2/0/2"].lag.as_deref(), Some("Port-channel1"));
    }

    #[tokio::test]
    async fn each_applied_change_is_reported() {
        let netbox = netbox();
        let reported = AtomicUsize::new(0);
        let mut applier = Applier::new(&netbox).on_applied(|| {
            reported.fetch_add(1, Ordering::SeqCst);
        });
        let changes = [create("Ethernet1/1", []), create("Ethernet1/2", [])];
        applier.apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags()).await.expect("applied");
        assert_eq!(applier.applied, 2);
        drop(applier);
        assert_eq!(reported.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn parents_are_created_before_their_children_whatever_the_depth() {
        let netbox = netbox();
        let changes = [
            create("VPN_SITE", [("type", json!("virtual")), ("parent", json!("INTERNET"))]),
            create("INTERNET", [("type", json!("virtual")), ("parent", json!("PO1"))]),
            create("wan2", [("lag", json!("PO1"))]),
            create("PO1", [("type", json!("lag"))]),
        ];
        Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect("applied");
        let after = device(&netbox, DEVICE).await.interfaces;
        assert_eq!(after["vpn_site"].parent.as_deref(), Some("INTERNET"));
        assert_eq!(after["internet"].parent.as_deref(), Some("PO1"));
        assert_eq!(after["wan2"].lag.as_deref(), Some("PO1"));
    }

    #[tokio::test]
    async fn parent_is_updated_and_cleared() {
        let netbox = netbox();
        let id = device_id(&netbox);
        let lag = netbox.add("dcim.interfaces", json!({"device": id, "name": "PO1", "type": "lag"}));
        netbox.add("dcim.interfaces", json!({"device": id, "name": "PO2", "type": "lag"}));
        let moved = netbox.add("dcim.interfaces", json!({"device": id, "name": "A", "type": "virtual", "parent": lag}));
        let freed = netbox.add("dcim.interfaces", json!({"device": id, "name": "B", "type": "virtual", "parent": lag}));
        let changes = [
            Change::new("interface", Action::Update, DEVICE, "A").fields([("parent", json!("po2"))]).id(moved),
            Change::new("interface", Action::Update, DEVICE, "B").fields([("parent", json!(null))]).id(freed),
        ];
        Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect("applied");
        let after = device(&netbox, DEVICE).await.interfaces;
        assert_eq!(after["a"].parent.as_deref(), Some("PO2"));
        assert_eq!(after["b"].parent, None);
    }

    #[tokio::test]
    async fn unknown_parent_stops_the_device() {
        let netbox = netbox();
        let changes = [create("HOUSING", [("type", json!("virtual")), ("parent", json!("PO9"))])];
        let error = Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("the parent is unknown");
        assert_eq!(error.message, "create interface nexus01.lab01 HOUSING: parent PO9 not found");
    }

    #[tokio::test]
    async fn label_is_written() {
        let netbox = netbox();
        let changes = [create("a", [("label", json!("HA"))])];
        Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect("applied");
        assert_eq!(device(&netbox, DEVICE).await.interfaces["a"].label, "HA");
    }

    #[tokio::test]
    async fn a_cable_end_that_is_not_known_is_an_error() {
        let netbox = netbox();
        let cable = Change::new("cable", Action::Create, "", "x").fields([
            ("a_device", DEVICE),
            ("a_interface", "Ethernet1/48"),
            ("b_device", "nexus02.lab01"),
            ("b_interface", "Ethernet1/48"),
        ]);
        let error = Applier::new(&netbox).apply_cables(&[cable], &|_| None).await.expect_err("no end is known");
        assert_eq!(error.message, "create cable  x: nexus01.lab01 Ethernet1/48 not found");
    }

    #[tokio::test]
    async fn a_vrf_that_netbox_does_not_have_is_an_error_saying_it_is_missing() {
        let netbox = netbox();
        let changes = [Change::new("ip", Action::Create, DEVICE, "192.0.2.250/24")
            .fields([("address", json!("192.0.2.250/24")), ("vrf", json!("backbone"))])];
        let error = Applier::new(&netbox)
            .apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags())
            .await
            .expect_err("the VRF is missing");
        assert_eq!(error.message, "create ip nexus01.lab01 192.0.2.250/24: VRF backbone missing in Netbox");
        assert_eq!(error.applied, 0);
    }

    // NetBox keeps a MAC address as an object of its own, which the interface
    // names as its primary one: the interface has no `mac` field to write.
    #[tokio::test]
    async fn a_mac_address_is_written_as_its_own_object_and_never_as_a_field_of_the_interface() {
        let netbox = netbox();
        let id = device_id(&netbox);
        let eth = netbox.add("dcim.interfaces", json!({"device": id, "name": "Ethernet1/1", "type": "other"}));
        let changes = [Change::new("interface", Action::Update, DEVICE, "Ethernet1/1")
            .fields([("mac", json!("02:08:D1:90:97:2D"))])
            .id(eth)];
        let applied = Applier::new(&netbox).apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags()).await;
        assert_eq!(applied, Ok(()));
        let mac = netbox.find("dcim.mac_addresses", "mac_address", &json!("02:08:D1:90:97:2D")).expect("the MAC");
        assert_eq!(
            netbox.writes(),
            [("create", "dcim.mac_addresses".to_owned(), mac), ("update", "dcim.interfaces".to_owned(), eth)]
        );
        let stored = netbox.row("dcim.interfaces", eth).expect("the interface");
        assert_eq!(stored.get("mac"), None);
        assert_eq!(stored.get("primary_mac_address"), Some(&json!(mac)));
    }

    #[tokio::test]
    async fn the_mac_address_object_an_interface_already_holds_becomes_its_primary_one_without_a_second_object() {
        let netbox = netbox();
        let id = device_id(&netbox);
        let eth = netbox.add("dcim.interfaces", json!({"device": id, "name": "Ethernet1/1", "type": "other"}));
        let held = |address: &str| {
            netbox.add(
                "dcim.mac_addresses",
                json!({"mac_address": address, "assigned_object_type": "dcim.interface", "assigned_object_id": eth}),
            )
        };
        // The address of another time comes first: the one to pick is not the first found.
        let stale = held("00:11:22:33:44:55");
        let wanted = held("02:08:D1:90:97:2D");
        netbox.set("dcim.interfaces", eth, "primary_mac_address", json!(stale));
        let changes = [Change::new("interface", Action::Update, DEVICE, "Ethernet1/1")
            .fields([("mac", json!("02:08:D1:90:97:2D"))])
            .id(eth)];
        let applied = Applier::new(&netbox).apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags()).await;
        assert_eq!(applied, Ok(()));
        assert_eq!(netbox.writes(), [("update", "dcim.interfaces".to_owned(), eth)]);
        let stored = netbox.row("dcim.interfaces", eth).expect("the interface");
        assert_eq!(stored.get("primary_mac_address"), Some(&json!(wanted)));
    }

    // Each deletion goes to the endpoint of its kind: the id of an address is
    // not the id of a MAC address object.
    #[tokio::test]
    async fn a_stale_mac_address_and_a_stale_address_are_each_deleted_from_their_own_endpoint() {
        let netbox = netbox();
        let id = device_id(&netbox);
        let eth = netbox.add("dcim.interfaces", json!({"device": id, "name": "Ethernet1/1", "type": "other"}));
        let mac = netbox.add(
            "dcim.mac_addresses",
            json!({"mac_address": "00:11:22:33:44:55", "assigned_object_type": "dcim.interface",
                   "assigned_object_id": eth}),
        );
        let ip = netbox.add(
            "ipam.ip_addresses",
            json!({"address": "192.0.2.239/24", "vrf": null, "assigned_object_type": "dcim.interface",
                   "assigned_object_id": eth, "status": "active"}),
        );
        let changes = [
            Change::new("ip", Action::Delete, DEVICE, "192.0.2.239/24").id(ip),
            Change::new("mac", Action::Delete, DEVICE, "Ethernet1/1 00:11:22:33:44:55").id(mac),
        ];
        let mut applier = Applier::new(&netbox);
        let applied = applier.apply_device(&device(&netbox, DEVICE).await, &changes, &no_lags()).await;
        assert_eq!(applied, Ok(()));
        assert_eq!(applier.applied, 2);
        assert_eq!(netbox.row("dcim.mac_addresses", mac), None);
        assert_eq!(netbox.row("ipam.ip_addresses", ip), None);
        assert!(netbox.row("dcim.interfaces", eth).is_some());
    }

    // What must be written before an interface is what it points at: itself
    // is not one more interface to wait for.
    #[test]
    fn an_interface_that_names_itself_as_its_lag_has_nothing_to_be_written_before_it() {
        let own = create("PO1", [("type", json!("lag")), ("lag", json!("PO1"))]);
        let by_key = BTreeMap::from([("po1".to_owned(), &own)]);
        assert_eq!(rank(&own, &by_key, &BTreeSet::new()), 0);
    }
}
