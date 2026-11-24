//! Read the current NetBox state into plain data.

use std::collections::{BTreeMap, BTreeSet};

use omnisync_core::gateway::filters;
use omnisync_core::network::names::interface_key;
use omnisync_core::network::state::{End, NbCable, NbDevice, NbInterface, NbIp, NotFound};
use omnisync_core::{Gateway, GatewayError, Row};
use serde_json::Value;

/// Why a reader could not build the NetBox state.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum StateError {
    #[error(transparent)]
    NotFound(#[from] NotFound),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
    /// NetBox returned an object without a field the reader needs, or with a
    /// value of another type: the state cannot be trusted, so nothing is built.
    #[error("{0}")]
    Malformed(String),
    /// Several NetBox objects answer to the name asked: none is taken, as
    /// writing to the first would be writing to an arbitrary one.
    #[error("{0}")]
    Ambiguous(String),
}

fn malformed(what: &str, value: &Value) -> StateError {
    StateError::Malformed(format!("unexpected NetBox object, {what}: {value}"))
}

/// The field, which the API always sends: its absence is an error.
fn field<'a>(row: &'a Row, key: &str) -> Result<&'a Value, StateError> {
    row.get(key).ok_or_else(|| {
        StateError::Malformed(format!("unexpected NetBox object, no field {key}: {}", Value::Object(row.clone())))
    })
}

fn number<T: TryFrom<u64>>(value: &Value, what: &str) -> Result<T, StateError> {
    value.as_u64().and_then(|number| T::try_from(number).ok()).ok_or_else(|| malformed(what, value))
}

fn string(value: &Value, what: &str) -> Result<String, StateError> {
    value.as_str().map(str::to_owned).ok_or_else(|| malformed(what, value))
}

fn id(row: &Row) -> Result<u64, StateError> {
    number(field(row, "id")?, "id")
}

/// A text field NetBox may send as null: empty then.
fn text_or_empty(row: &Row, key: &str) -> Result<String, StateError> {
    match field(row, key)? {
        Value::Null => Ok(String::new()),
        value => string(value, key),
    }
}

/// `inner` of the nested object under `key`, when there is one: `key` itself
/// is always sent, null when the object has no such relation.
fn nested<'a>(row: &'a Row, key: &str, inner: &str) -> Result<Option<&'a Value>, StateError> {
    match field(row, key)? {
        Value::Null => Ok(None),
        Value::Object(object) => Ok(object.get(inner).filter(|value| !value.is_null())),
        other => Err(malformed(key, other)),
    }
}

fn nested_string(row: &Row, key: &str, inner: &str) -> Result<Option<String>, StateError> {
    nested(row, key, inner)?.map(|value| string(value, key)).transpose()
}

fn nested_number<T: TryFrom<u64>>(row: &Row, key: &str, inner: &str) -> Result<Option<T>, StateError> {
    nested(row, key, inner)?.map(|value| number(value, key)).transpose()
}

fn interface(row: &Row) -> Result<NbInterface, StateError> {
    let tagged = field(row, "tagged_vlans")?;
    let mut tagged_vlans = tagged
        .as_array()
        .ok_or_else(|| malformed("tagged_vlans", tagged))?
        .iter()
        .map(|vlan| number(vlan.get("vid").unwrap_or(&Value::Null), "tagged_vlans"))
        .collect::<Result<Vec<u16>, StateError>>()?;
    tagged_vlans.sort_unstable();
    // The NetBox id of each of those VLANs: the same number may be a VLAN of
    // the site and one of a VLAN group, untagged and tagged on one port.
    let mut tagged_vlan_ids = Vec::new();
    for vlan in tagged.as_array().into_iter().flatten() {
        if let (Some(vid), Some(vlan_id)) = (vlan.get("vid"), vlan.get("id")) {
            tagged_vlan_ids.push((number(vid, "tagged_vlans")?, number(vlan_id, "tagged_vlans")?));
        }
    }
    // Sorted, as the numbers are: NetBox gives them in an order of its own.
    tagged_vlan_ids.sort_unstable();
    let untagged_vlan_id = nested_number(row, "untagged_vlan", "id")?;
    let mtu = match field(row, "mtu")? {
        Value::Null => None,
        value => Some(number(value, "mtu")?),
    };
    Ok(NbInterface {
        id: id(row)?,
        name: string(field(row, "name")?, "name")?,
        enabled: truthy(field(row, "enabled")?),
        description: text_or_empty(row, "description")?,
        mtu,
        r#type: nested_string(row, "type", "value")?,
        mac: nested_string(row, "primary_mac_address", "mac_address")?,
        lag: nested_string(row, "lag", "name")?,
        mode: nested_string(row, "mode", "value")?,
        untagged_vlan: nested_number(row, "untagged_vlan", "vid")?,
        tagged_vlans,
        untagged_vlan_id,
        tagged_vlan_ids,
        cable_id: nested_number(row, "cable", "id")?,
        macs: Vec::new(),
        // Always present in the API; absent only from records that predate the field.
        mgmt_only: row.get("mgmt_only").is_some_and(truthy),
        parent: nested_string(row, "parent", "name")?,
        label: text_or_empty(row, "label")?,
    })
}

fn truthy(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

fn ip(row: &Row) -> Result<NbIp, StateError> {
    let unassigned = |row: &Row| -> Result<NbIp, StateError> {
        Ok(NbIp {
            id: id(row)?,
            address: string(field(row, "address")?, "address")?,
            vrf: nested_string(row, "vrf", "name")?,
            device: None,
            interface: None,
        })
    };
    let assigned = match field(row, "assigned_object")? {
        Value::Null => return unassigned(row),
        Value::Object(assigned) => assigned,
        other => return Err(malformed("assigned_object", other)),
    };
    // A VM interface or an FHRP group owns the IP too: it must never look unassigned,
    // or the diff would adopt it and take it from its owner.
    let owner =
        ["device", "virtual_machine"].iter().filter_map(|key| assigned.get(*key)).find(|owner| !owner.is_null());
    let owner_name = match owner {
        Some(owner) => string(owner.get("name").unwrap_or(&Value::Null), "assigned_object")?,
        None => {
            let kind = string(field(row, "assigned_object_type")?, "assigned_object_type")?;
            format!("{kind} {}", id(assigned)?)
        }
    };
    let interface =
        assigned.get("name").filter(|name| !name.is_null()).map(|name| string(name, "assigned_object")).transpose()?;
    Ok(NbIp { device: Some(owner_name), interface, ..unassigned(row)? })
}

/// The one row NetBox has under a name. NetBox makes a device name unique per
/// site only (and reads it caselessly), a virtual chassis name not at all:
/// several rows are refused rather than the first taken, which would be an
/// arbitrary one, written to and pruned.
fn only_row(rows: Vec<Row>, what: &str, many: &str, name: &str) -> Result<Row, StateError> {
    match rows.as_slice() {
        [] => Err(NotFound(format!("{what} {name} not found in Netbox")).into()),
        [_] => Ok(rows.into_iter().next().expect("one row")),
        _ => {
            let ids: Vec<String> = rows.iter().map(|row| id(row).map(|id| id.to_string())).collect::<Result<_, _>>()?;
            Err(StateError::Ambiguous(format!(
                "{what} {name}: {} {many} in Netbox have this name (ids {}), none is written",
                rows.len(),
                ids.join(", ")
            )))
        }
    }
}

async fn device_row<G: Gateway>(gateway: &G, name: &str) -> Result<Row, StateError> {
    let rows = gateway.list("dcim.devices", &filters([("name", name)])).await?;
    only_row(rows, "device", "devices", name)
}

async fn interfaces<G: Gateway>(gateway: &G, device_id: u64) -> Result<BTreeMap<String, NbInterface>, StateError> {
    let mut interfaces = BTreeMap::new();
    for row in gateway.list("dcim.interfaces", &filters([("device_id", device_id)])).await? {
        let interface = interface(&row)?;
        interfaces.insert(interface_key(&interface.name), interface);
    }
    Ok(interfaces)
}

/// The interfaces of a device only, keyed by `interface_key(name)`.
pub async fn read_interfaces<G: Gateway>(gateway: &G, name: &str) -> Result<BTreeMap<String, NbInterface>, StateError> {
    let device = device_row(gateway, name).await?;
    interfaces(gateway, id(&device)?).await
}

async fn with_macs<G: Gateway>(
    gateway: &G,
    device_id: u64,
    mut interfaces: BTreeMap<String, NbInterface>,
) -> Result<BTreeMap<String, NbInterface>, StateError> {
    let mut macs: BTreeMap<u64, Vec<(u64, String)>> = BTreeMap::new();
    for row in gateway.list("dcim.mac_addresses", &filters([("device_id", device_id)])).await? {
        if field(&row, "assigned_object_type")?.as_str() == Some("dcim.interface") {
            let interface_id = number(field(&row, "assigned_object_id")?, "assigned_object_id")?;
            let address = string(field(&row, "mac_address")?, "mac_address")?.to_uppercase();
            macs.entry(interface_id).or_default().push((id(&row)?, address));
        }
    }
    for interface in interfaces.values_mut() {
        interface.macs = macs.remove(&interface.id).unwrap_or_default();
        interface.macs.sort();
    }
    Ok(interfaces)
}

/// The device a device is installed in (`parent_device`: a blade in its
/// chassis), by name; None when it is in none.
pub async fn read_parent_device<G: Gateway>(gateway: &G, name: &str) -> Result<Option<String>, StateError> {
    let device = device_row(gateway, name).await?;
    nested_string(&device, "parent_device", "name")
}

pub async fn read_device<G: Gateway>(gateway: &G, name: &str) -> Result<NbDevice, StateError> {
    let device = device_row(gateway, name).await?;
    let device_id = id(&device)?;
    let interfaces = with_macs(gateway, device_id, interfaces(gateway, device_id).await?).await?;
    let ips = gateway.list("ipam.ip_addresses", &filters([("device_id", device_id)])).await?;
    Ok(NbDevice {
        id: device_id,
        name: string(field(&device, "name")?, "name")?,
        site_id: nested_number(&device, "site", "id")?
            .ok_or_else(|| malformed("site", &Value::Object(device.clone())))?,
        site: nested_string(&device, "site", "name")?.unwrap_or_default(),
        serial: text_or_empty(&device, "serial")?,
        primary_ip4: nested_string(&device, "primary_ip4", "address")?,
        interfaces,
        ips: ips.iter().map(ip).collect::<Result<_, _>>()?,
    })
}

pub async fn read_ips_by_host<G, I, S>(gateway: &G, hosts: I) -> Result<BTreeMap<String, Vec<NbIp>>, StateError>
where
    G: Gateway,
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let hosts: Vec<String> = hosts.into_iter().map(Into::into).collect();
    let mut found = BTreeMap::new();
    for host in hosts {
        let rows = gateway.list("ipam.ip_addresses", &filters([("address", &host)])).await?;
        found.insert(host, rows.iter().map(ip).collect::<Result<_, _>>()?);
    }
    Ok(found)
}

/// The VLANs of a site: (id, name) by VLAN number.
pub async fn read_site_vlans<G: Gateway>(
    gateway: &G,
    site_id: u64,
) -> Result<BTreeMap<u16, (u64, String)>, StateError> {
    let rows = gateway.list("ipam.vlans", &filters([("site_id", site_id)])).await?;
    rows.iter()
        .map(|row| Ok((number(field(row, "vid")?, "vid")?, (id(row)?, string(field(row, "name")?, "name")?))))
        .collect()
}

/// The VLANs of a VLAN group: (id, name) by VLAN number, and the name of
/// the site of those that also have one, by VLAN number.
pub async fn read_group_vlans<G: Gateway>(gateway: &G, group_id: u64) -> Result<GroupVlans, StateError> {
    let rows = gateway.list("ipam.vlans", &filters([("group_id", group_id)])).await?;
    let mut read = GroupVlans::default();
    for row in &rows {
        let vid: u16 = number(field(row, "vid")?, "vid")?;
        read.vlans.insert(vid, (id(row)?, string(field(row, "name")?, "name")?));
        // A site absent from the answer is no site: the field is always sent.
        if let Some(site) = row.get("site").filter(|site| !site.is_null()) {
            let name = site.get("name").and_then(Value::as_str).map_or_else(|| site.to_string(), str::to_owned);
            read.sited.insert(vid, name);
        }
    }
    Ok(read)
}

/// What `read_group_vlans` gives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupVlans {
    /// (id, name) by VLAN number.
    pub vlans: BTreeMap<u16, (u64, String)>,
    /// The site of the VLANs that also have one, by VLAN number: NetBox
    /// refuses such a VLAN on an interface of another site of the group.
    pub sited: BTreeMap<u16, String>,
}

/// The id of the VLAN group named `name`, whatever the case: a prerequisite,
/// never created. A name NetBox does not hold, or holds twice, is an error.
///
/// Every group is read and compared here: the `name` filter of NetBox is
/// exact, while the hypervisor run and the configuration compare a group
/// name without case. There are a few groups, not thousands.
pub async fn read_vlan_group<G: Gateway>(gateway: &G, name: &str) -> Result<u64, StateError> {
    let wanted = name.to_lowercase();
    let rows: Vec<Row> = gateway
        .list("ipam.vlan_groups", &Vec::new())
        .await?
        .into_iter()
        .filter(|row| row.get("name").and_then(Value::as_str).is_some_and(|held| held.to_lowercase() == wanted))
        .collect();
    id(&only_row(rows, "VLAN group", "VLAN groups", name)?)
}

async fn virtual_chassis<G: Gateway>(gateway: &G, vc_name: &str) -> Result<Row, StateError> {
    let chassis = gateway.list("dcim.virtual_chassis", &filters([("name", vc_name)])).await?;
    only_row(chassis, "virtual chassis", "virtual chassis", vc_name)
}

/// The members of a virtual chassis: device name by position.
pub async fn read_vc_members<G: Gateway>(gateway: &G, vc_name: &str) -> Result<BTreeMap<u32, String>, StateError> {
    let chassis = virtual_chassis(gateway, vc_name).await?;
    let rows = gateway.list("dcim.devices", &filters([("virtual_chassis_id", id(&chassis)?)])).await?;
    // A member without position (NetBox allows it) is at no position of the stack.
    rows.iter()
        .filter(|row| row.get("vc_position").is_some_and(|position| !position.is_null()))
        .map(|row| Ok((number(field(row, "vc_position")?, "vc_position")?, string(field(row, "name")?, "name")?)))
        .collect()
}

pub async fn read_vc_master<G: Gateway>(gateway: &G, vc_name: &str) -> Result<Option<String>, StateError> {
    let chassis = virtual_chassis(gateway, vc_name).await?;
    match chassis.get("master") {
        None | Some(Value::Null) => Ok(None),
        Some(master) => Ok(Some(string(master.get("name").unwrap_or(&Value::Null), "master")?)),
    }
}

/// The tables among `vrfs` (None: global) where NetBox refuses a duplicate address.
///
/// The global table follows ENFORCE_GLOBAL_UNIQUE, which the API does not expose:
/// it is taken as unique, its NetBox default.
pub async fn unique_ip_tables<G, I>(gateway: &G, vrfs: I) -> Result<BTreeSet<Option<String>>, StateError>
where
    G: Gateway,
    I: IntoIterator<Item = Option<String>>,
{
    let vrfs: BTreeSet<Option<String>> = vrfs.into_iter().collect();
    let mut unique = BTreeSet::new();
    for vrf in vrfs {
        let Some(name) = &vrf else {
            unique.insert(None);
            continue;
        };
        let rows = gateway.list("ipam.vrfs", &filters([("name", name)])).await?;
        if rows.first().is_some_and(|row| row.get("enforce_unique").is_none_or(truthy)) {
            unique.insert(vrf);
        }
    }
    Ok(unique)
}

pub async fn missing_vrfs<G, I, S>(gateway: &G, names: I) -> Result<BTreeSet<String>, StateError>
where
    G: Gateway,
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let names: BTreeSet<String> = names.into_iter().map(Into::into).collect();
    let mut missing = BTreeSet::new();
    for name in names {
        if gateway.list("ipam.vrfs", &filters([("name", &name)])).await?.is_empty() {
            missing.insert(name);
        }
    }
    Ok(missing)
}

fn end(row: &Row, side: &str) -> Result<Option<End>, StateError> {
    let terminations = field(row, side)?;
    let [termination] = terminations.as_array().ok_or_else(|| malformed(side, terminations))?.as_slice() else {
        return Ok(None);
    };
    if termination.get("object_type").and_then(Value::as_str) != Some("dcim.interface") {
        return Ok(None);
    }
    let name = |value: Option<&Value>| string(value.and_then(|named| named.get("name")).unwrap_or(&Value::Null), side);
    let target = termination.get("object");
    Ok(Some(End { device: name(target.and_then(|target| target.get("device")))?, interface: name(target)? }))
}

pub async fn read_device_cables<G: Gateway>(gateway: &G, device_id: u64) -> Result<Vec<NbCable>, StateError> {
    let mut cables = Vec::new();
    for row in gateway.list("dcim.cables", &filters([("device_id", device_id)])).await? {
        // Multi-termination cables are left alone: the tool only writes 1:1 cables.
        if let (Some(a), Some(b)) = (end(&row, "a_terminations")?, end(&row, "b_terminations")?) {
            cables.push(NbCable { id: id(&row)?, a, b });
        }
    }
    Ok(cables)
}

/// The cables of several devices, once each (a cable has two ends), by id.
pub fn combine_cables<I>(per_device: I) -> Vec<NbCable>
where
    I: IntoIterator<Item = Vec<NbCable>>,
{
    let cables: BTreeMap<u64, NbCable> = per_device.into_iter().flatten().map(|cable| (cable.id, cable)).collect();
    cables.into_values().collect()
}

pub async fn read_cables<G, I>(gateway: &G, device_ids: I) -> Result<Vec<NbCable>, StateError>
where
    G: Gateway,
    I: IntoIterator<Item = u64>,
{
    let device_ids: Vec<u64> = device_ids.into_iter().collect();
    let mut per_device = Vec::new();
    for device_id in device_ids {
        per_device.push(read_device_cables(gateway, device_id).await?);
    }
    Ok(combine_cables(per_device))
}

#[cfg(test)]
mod tests {
    use omnisync_core::Filters;
    use omnisync_core::Write;
    use serde_json::json;

    use super::*;
    use crate::testing::FakeGateway;

    struct Seed {
        netbox: FakeGateway,
        device: u64,
        eth: u64,
        mac: u64,
        ip: u64,
    }

    fn seed() -> Seed {
        let netbox = FakeGateway::new();
        let vlan26 = netbox.add("ipam.vlans", json!({"site": 12, "vid": 26, "name": "VLAN2600-PPE"}));
        let vlan2800 = netbox.add("ipam.vlans", json!({"site": 12, "vid": 2800, "name": "VLAN2800-Admin"}));
        let vrf = netbox.add("ipam.vrfs", json!({"name": "mgmt-sw"}));
        let device = netbox.add("dcim.devices", json!({"name": "nexus01.lab01", "site": 12, "serial": "FOC9792A4K9"}));
        let lag = netbox.add(
            "dcim.interfaces",
            json!({
                "device": device, "name": "Port-channel10", "type": "lag", "enabled": true, "description": "",
                "mtu": 9216,
            }),
        );
        let eth = netbox.add(
            "dcim.interfaces",
            json!({
                "device": device, "name": "Ethernet1/51", "type": "10gbase-x-sfpp", "enabled": true,
                "description": "peer", "mtu": 1500, "lag": lag, "mode": "tagged", "untagged_vlan": vlan26,
                "tagged_vlans": [vlan2800, vlan26],
            }),
        );
        let mac = netbox.add(
            "dcim.mac_addresses",
            json!({
                "mac_address": "02:08:D1:90:97:2D", "assigned_object_type": "dcim.interface",
                "assigned_object_id": eth,
            }),
        );
        netbox.set("dcim.interfaces", eth, "primary_mac_address", json!(mac));
        let admin = netbox.add(
            "dcim.interfaces",
            json!({
                "device": device, "name": "admin", "type": "virtual", "enabled": true, "description": "", "mtu": null,
            }),
        );
        let ip = netbox.add(
            "ipam.ip_addresses",
            json!({
                "address": "192.0.2.239/24", "vrf": null, "assigned_object_type": "dcim.interface",
                "assigned_object_id": admin, "status": "active",
            }),
        );
        netbox.set("dcim.devices", device, "primary_ip4", json!(ip));
        netbox.add("ipam.ip_addresses", json!({"address": "192.0.2.250/24", "vrf": vrf, "status": "active"}));
        Seed { netbox, device, eth, mac, ip }
    }

    fn cable(netbox: &FakeGateway, a: u64, b: u64) -> u64 {
        netbox.add(
            "dcim.cables",
            json!({
                "a_terminations": [{"object_type": "dcim.interface", "object_id": a}],
                "b_terminations": [{"object_type": "dcim.interface", "object_id": b}],
                "status": "connected",
            }),
        )
    }

    fn not_found(message: &str) -> StateError {
        StateError::NotFound(NotFound(message.to_owned()))
    }

    // The `name` filter of `ipam/vlan-groups` is exact (VLANGroupFilterSet,
    // ipam/filtersets.py:965 in NetBox 4.5.10, :980 in 4.7.5), and the names are compared without case everywhere
    // else: the configuration may write a group in another case.
    #[tokio::test]
    async fn a_vlan_group_is_found_whatever_the_case_of_its_name() {
        let netbox = FakeGateway::new();
        let east = netbox.add("ipam.vlan_groups", json!({"name": "East", "slug": "east"}));
        netbox.add("ipam.vlan_groups", json!({"name": "Paris", "slug": "paris"}));
        assert_eq!(read_vlan_group(&netbox, "east").await, Ok(east));
        assert_eq!(read_vlan_group(&netbox, "EAST").await, Ok(east));
        assert_eq!(read_vlan_group(&netbox, "Lyon").await, Err(not_found("VLAN group Lyon not found in Netbox")));
        // Two groups whose names differ by case only: none is taken.
        let other = netbox.add("ipam.vlan_groups", json!({"name": "EAST", "slug": "east-2"}));
        assert_eq!(
            read_vlan_group(&netbox, "east").await,
            Err(StateError::Ambiguous(format!(
                "VLAN group east: 2 VLAN groups in Netbox have this name (ids {east}, {other}), none is written"
            )))
        );
    }

    #[tokio::test]
    async fn read_device_builds_the_device_with_its_interfaces_and_addresses() {
        let seed = seed();
        let device = read_device(&seed.netbox, "nexus01.lab01").await.unwrap();
        assert_eq!(
            (device.id, device.name.as_str(), device.site_id, device.serial.as_str(), device.primary_ip4.as_deref()),
            (seed.device, "nexus01.lab01", 12, "FOC9792A4K9", Some("192.0.2.239/24"))
        );
        assert_eq!(
            device.interfaces["ethernet1/51"],
            NbInterface {
                id: seed.eth,
                name: "Ethernet1/51".to_owned(),
                enabled: true,
                description: "peer".to_owned(),
                mtu: Some(1500),
                r#type: Some("10gbase-x-sfpp".to_owned()),
                mac: Some("02:08:D1:90:97:2D".to_owned()),
                lag: Some("Port-channel10".to_owned()),
                mode: Some("tagged".to_owned()),
                untagged_vlan: Some(26),
                tagged_vlans: vec![26, 2800],
                // The two VLANs the seed adds at the site.
                untagged_vlan_id: seed.netbox.find("ipam.vlans", "vid", &json!(26)),
                tagged_vlan_ids: vec![
                    (26, seed.netbox.find("ipam.vlans", "vid", &json!(26)).unwrap()),
                    (2800, seed.netbox.find("ipam.vlans", "vid", &json!(2800)).unwrap()),
                ],
                cable_id: None,
                macs: vec![(seed.mac, "02:08:D1:90:97:2D".to_owned())],
                mgmt_only: false,
                parent: None,
                label: String::new(),
            }
        );
        assert!(device.interfaces.contains_key("port-channel10"));
        assert_eq!(
            device.ips,
            [NbIp {
                id: seed.ip,
                address: "192.0.2.239/24".to_owned(),
                vrf: None,
                device: Some("nexus01.lab01".to_owned()),
                interface: Some("admin".to_owned()),
            }]
        );
    }

    // NetBox makes a device name unique per site only, and reads it caselessly:
    // writing to the first of two would be writing to the wrong one.
    #[tokio::test]
    async fn a_device_name_two_sites_hold_is_refused_naming_both() {
        let seed = seed();
        let other = seed.netbox.add("dcim.devices", json!({"name": "NEXUS01.lab01", "site": 13, "serial": ""}));
        let expected = format!(
            "device nexus01.lab01: 2 devices in Netbox have this name (ids {}, {other}), none is written",
            seed.device
        );
        assert_eq!(read_device(&seed.netbox, "nexus01.lab01").await, Err(StateError::Ambiguous(expected.clone())));
        assert_eq!(read_interfaces(&seed.netbox, "nexus01.lab01").await, Err(StateError::Ambiguous(expected)));
    }

    // A virtual chassis name is not unique in NetBox either.
    #[tokio::test]
    async fn a_virtual_chassis_name_two_chassis_hold_is_refused_naming_both() {
        let netbox = FakeGateway::new();
        let first = netbox.add("dcim.virtual_chassis", json!({"name": "stack01"}));
        let second = netbox.add("dcim.virtual_chassis", json!({"name": "stack01"}));
        let expected = format!(
            "virtual chassis stack01: 2 virtual chassis in Netbox have this name (ids {first}, {second}), none is written"
        );
        assert_eq!(read_vc_members(&netbox, "stack01").await, Err(StateError::Ambiguous(expected)));
    }

    #[tokio::test]
    async fn read_device_not_found() {
        let seed = seed();
        assert_eq!(
            read_device(&seed.netbox, "nexus09.lab01").await,
            Err(not_found("device nexus09.lab01 not found in Netbox"))
        );
    }

    #[tokio::test]
    async fn the_macs_of_an_interface_are_upper_cased_and_sorted_by_id() {
        let seed = seed();
        let second = seed.netbox.add(
            "dcim.mac_addresses",
            json!({
                "mac_address": "02:08:d1:90:97:2e", "assigned_object_type": "dcim.interface",
                "assigned_object_id": seed.eth,
            }),
        );
        // A MAC assigned to something else than an interface is not one of the interface.
        seed.netbox.add(
            "dcim.mac_addresses",
            json!({
                "mac_address": "02:08:D1:90:97:2F", "assigned_object_type": "virtualization.vminterface",
                "assigned_object_id": seed.eth,
            }),
        );
        let device = read_device(&seed.netbox, "nexus01.lab01").await.unwrap();
        assert_eq!(
            device.interfaces["ethernet1/51"].macs,
            [(seed.mac, "02:08:D1:90:97:2D".to_owned()), (second, "02:08:D1:90:97:2E".to_owned())]
        );
        assert_eq!(device.interfaces["admin"].macs, []);
    }

    #[tokio::test]
    async fn read_ips_by_host_finds_the_addresses_of_each_host() {
        let seed = seed();
        let found = read_ips_by_host(&seed.netbox, ["192.0.2.250", "192.0.2.1"]).await.unwrap();
        let summary: Vec<_> = found["192.0.2.250"]
            .iter()
            .map(|ip| (ip.address.as_str(), ip.vrf.as_deref(), ip.device.as_deref()))
            .collect();
        assert_eq!(summary, [("192.0.2.250/24", Some("mgmt-sw"), None)]);
        assert_eq!(found["192.0.2.1"], []);
    }

    #[tokio::test]
    async fn read_site_vlans_gives_id_and_name_by_number() {
        let seed = seed();
        let vlans = read_site_vlans(&seed.netbox, 12).await.unwrap();
        let names: BTreeMap<u16, &str> = vlans.iter().map(|(vid, (_, name))| (*vid, name.as_str())).collect();
        assert_eq!(names, BTreeMap::from([(26, "VLAN2600-PPE"), (2800, "VLAN2800-Admin")]));
        let vlan26 = seed.netbox.find("ipam.vlans", "vid", &json!(26)).unwrap();
        assert_eq!(vlans[&26].0, vlan26);
    }

    #[tokio::test]
    async fn read_vc_members_gives_the_names_by_position() {
        let netbox = FakeGateway::new();
        let chassis = netbox.add("dcim.virtual_chassis", json!({"name": "2960-stack"}));
        for (name, position) in [("2960-stack01.lab01", 1), ("2960-stack02.lab01", 2)] {
            netbox.add(
                "dcim.devices",
                json!({"name": name, "site": 12, "virtual_chassis": chassis, "vc_position": position}),
            );
        }
        assert_eq!(
            read_vc_members(&netbox, "2960-stack").await,
            Ok(BTreeMap::from([(1, "2960-stack01.lab01".to_owned()), (2, "2960-stack02.lab01".to_owned())]))
        );
        assert_eq!(
            read_vc_members(&netbox, "missing-vc").await,
            Err(not_found("virtual chassis missing-vc not found in Netbox"))
        );
    }

    // NetBox lets a member of a virtual chassis have no position: it is at no
    // position of the stack, and the members that have one are still read.
    #[tokio::test]
    async fn a_member_without_position_is_at_no_position_of_the_stack() {
        let netbox = FakeGateway::new();
        let chassis = netbox.add("dcim.virtual_chassis", json!({"name": "2960-stack"}));
        netbox.add(
            "dcim.devices",
            json!({"name": "2960-stack01.lab01", "site": 12, "virtual_chassis": chassis, "vc_position": 1}),
        );
        netbox.add(
            "dcim.devices",
            json!({"name": "2960-spare.lab01", "site": 12, "virtual_chassis": chassis, "vc_position": null}),
        );
        assert_eq!(
            read_vc_members(&netbox, "2960-stack").await,
            Ok(BTreeMap::from([(1, "2960-stack01.lab01".to_owned())]))
        );
    }

    #[tokio::test]
    async fn read_vc_master_names_the_master_when_there_is_one() {
        let netbox = FakeGateway::new();
        let chassis = netbox.add("dcim.virtual_chassis", json!({"name": "2960-stack"}));
        let first = netbox.add(
            "dcim.devices",
            json!({"name": "2960-stack01.lab01", "site": 12, "virtual_chassis": chassis, "vc_position": 1}),
        );
        assert_eq!(read_vc_master(&netbox, "2960-stack").await, Ok(None));
        netbox.set("dcim.virtual_chassis", chassis, "master", json!(first));
        assert_eq!(read_vc_master(&netbox, "2960-stack").await, Ok(Some("2960-stack01.lab01".to_owned())));
        assert_eq!(
            read_vc_master(&netbox, "missing-vc").await,
            Err(not_found("virtual chassis missing-vc not found in Netbox"))
        );
    }

    #[tokio::test]
    async fn missing_vrfs_names_those_netbox_does_not_have() {
        let seed = seed();
        assert_eq!(
            missing_vrfs(&seed.netbox, ["mgmt-sw", "management", "management"]).await,
            Ok(BTreeSet::from(["management".to_owned()]))
        );
    }

    #[tokio::test]
    async fn unique_ip_tables_keeps_the_global_table_and_the_enforcing_vrfs() {
        let seed = seed();
        seed.netbox.add("ipam.vrfs", json!({"name": "loose", "enforce_unique": false}));
        seed.netbox.add("ipam.vrfs", json!({"name": "strict", "enforce_unique": true}));
        let vrfs = [None, Some("mgmt-sw"), Some("loose"), Some("strict"), Some("absent"), None];
        assert_eq!(
            unique_ip_tables(&seed.netbox, vrfs.map(|vrf| vrf.map(str::to_owned))).await,
            Ok(BTreeSet::from([None, Some("mgmt-sw".to_owned()), Some("strict".to_owned())]))
        );
        assert_eq!(unique_ip_tables(&seed.netbox, [Some("loose".to_owned())]).await, Ok(BTreeSet::new()));
    }

    #[tokio::test]
    async fn read_cables_gives_the_cables_of_the_devices() {
        let seed = seed();
        let other = seed.netbox.add("dcim.devices", json!({"name": "nexus02.lab01", "site": 12}));
        let peer = seed
            .netbox
            .add("dcim.interfaces", json!({"device": other, "name": "Ethernet1/52", "type": "10gbase-x-sfpp"}));
        let cable = cable(&seed.netbox, seed.eth, peer);
        assert_eq!(
            read_cables(&seed.netbox, [seed.device, other]).await,
            Ok(vec![NbCable {
                id: cable,
                a: End::new("nexus01.lab01", "Ethernet1/51"),
                b: End::new("nexus02.lab01", "Ethernet1/52"),
            }])
        );
    }

    #[tokio::test]
    async fn cables_read_per_device_are_combined_once_each_by_id() {
        let seed = seed();
        let netbox = &seed.netbox;
        let other = netbox.add("dcim.devices", json!({"name": "nexus02.lab01", "site": 12}));
        let port = |number: u8| {
            netbox.add(
                "dcim.interfaces",
                json!({"device": other, "name": format!("Ethernet1/{number}"), "type": "other"}),
            )
        };
        let (port52, port53, port54) = (port(52), port(53), port(54));
        let first_cable = cable(netbox, seed.eth, port52);
        // Between two ports of nexus02 only.
        let second_cable = cable(netbox, port53, port54);
        let shared = NbCable {
            id: first_cable,
            a: End::new("nexus01.lab01", "Ethernet1/51"),
            b: End::new("nexus02.lab01", "Ethernet1/52"),
        };
        let internal = NbCable {
            id: second_cable,
            a: End::new("nexus02.lab01", "Ethernet1/53"),
            b: End::new("nexus02.lab01", "Ethernet1/54"),
        };
        assert_eq!(read_device_cables(netbox, seed.device).await, Ok(vec![shared.clone()]));
        let per_device =
            [read_device_cables(netbox, other).await.unwrap(), read_device_cables(netbox, seed.device).await.unwrap()];
        // The cable seen from both devices comes once; the list is ordered by id.
        assert_eq!(combine_cables(per_device), [shared, internal]);
    }

    #[tokio::test]
    async fn a_cable_with_several_terminations_or_another_kind_of_end_is_left_out() {
        let seed = seed();
        let netbox = &seed.netbox;
        let port =
            |name: &str| netbox.add("dcim.interfaces", json!({"device": seed.device, "name": name, "type": "other"}));
        let (first, second, third) = (port("Ethernet1/1"), port("Ethernet1/2"), port("Ethernet1/3"));
        let front = netbox.add("dcim.front_ports", json!({"device": seed.device, "name": "FP1"}));
        // Multi-termination cables are left alone: the tool only writes 1:1 cables.
        netbox.add(
            "dcim.cables",
            json!({
                "a_terminations": [
                    {"object_type": "dcim.interface", "object_id": first},
                    {"object_type": "dcim.interface", "object_id": second},
                ],
                "b_terminations": [{"object_type": "dcim.interface", "object_id": seed.eth}],
            }),
        );
        netbox.add(
            "dcim.cables",
            json!({
                "a_terminations": [{"object_type": "dcim.interface", "object_id": third}],
                "b_terminations": [{"object_type": "dcim.frontport", "object_id": front}],
            }),
        );
        assert_eq!(read_device_cables(netbox, seed.device).await, Ok(vec![]));
    }

    #[tokio::test]
    async fn ip_owned_by_a_virtual_machine_has_an_owner() {
        // Treated as "unassigned" it would be adopted, i.e. taken from the VM.
        let netbox = FakeGateway::new();
        netbox.add(
            "ipam.ip_addresses",
            json!({
                "address": "192.0.2.10/24", "vrf": null, "assigned_object_type": "virtualization.vminterface",
                "assigned_object_id": 7, "vm": "vm01", "vm_interface": "eth0", "status": "active",
            }),
        );
        let found = read_ips_by_host(&netbox, ["192.0.2.10"]).await.unwrap();
        let owners: Vec<_> =
            found["192.0.2.10"].iter().map(|ip| (ip.device.as_deref(), ip.interface.as_deref())).collect();
        assert_eq!(owners, [(Some("vm01"), Some("eth0"))]);
    }

    /// Answers every list with the same rows, or with the same error.
    struct Canned(Result<Vec<Row>, GatewayError>);

    impl Gateway for Canned {
        async fn list(&self, _endpoint: &str, _filters: &Filters) -> Result<Vec<Row>, GatewayError> {
            self.0.clone()
        }

        async fn create(&self, _endpoint: &str, _payload: &Row) -> Result<Row, GatewayError> {
            unreachable!("the readers never write")
        }

        async fn update(&self, _endpoint: &str, _id: u64, _payload: &Row) -> Result<(), GatewayError> {
            unreachable!("the readers never write")
        }

        async fn delete(&self, _endpoint: &str, _id: u64) -> Result<(), GatewayError> {
            unreachable!("the readers never write")
        }
        async fn check_write(&self, _: Write, _: &str, _: &[String]) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    fn canned(rows: Value) -> Canned {
        Canned(Ok(rows.as_array().unwrap().iter().map(|row| row.as_object().unwrap().clone()).collect()))
    }

    #[tokio::test]
    async fn ip_owned_by_an_object_without_device_is_named_after_that_object() {
        // An FHRP group owns the IP too: it must never look unassigned.
        let netbox = canned(json!([{
            "id": 5, "address": "192.0.2.1/24", "vrf": null, "assigned_object_type": "ipam.fhrpgroup",
            "assigned_object": {"id": 3, "group_id": 10},
        }]));
        assert_eq!(
            read_ips_by_host(&netbox, ["192.0.2.1"]).await.unwrap()["192.0.2.1"],
            [NbIp {
                id: 5,
                address: "192.0.2.1/24".to_owned(),
                vrf: None,
                device: Some("ipam.fhrpgroup 3".to_owned()),
                interface: None,
            }]
        );
    }

    #[tokio::test]
    async fn management_only_flag() {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "lab1-pve01.prod", "site": 13, "serial": ""}));
        netbox.add(
            "dcim.interfaces",
            json!({"device": device, "name": "iDrac8", "type": "1000base-t", "mgmt_only": true}),
        );
        netbox
            .add("dcim.interfaces", json!({"device": device, "name": "eno1", "type": "10gbase-t", "mgmt_only": false}));
        // Always present in the API; absent only from records that predate the field.
        netbox.add("dcim.interfaces", json!({"device": device, "name": "eno2", "type": "10gbase-t"}));
        let interfaces = read_interfaces(&netbox, "lab1-pve01.prod").await.unwrap();
        assert!(interfaces["idrac8"].mgmt_only);
        assert!(!interfaces["eno1"].mgmt_only);
        assert!(!interfaces["eno2"].mgmt_only);
    }

    #[tokio::test]
    async fn parent_interface_is_read_by_name() {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "fw01.dc1", "site": 12}));
        let lag = netbox.add("dcim.interfaces", json!({"device": device, "name": "PO2", "type": "lag"}));
        netbox.add("dcim.interfaces", json!({"device": device, "name": "HOUSING", "type": "virtual", "parent": lag}));
        let interfaces = read_interfaces(&netbox, "fw01.dc1").await.unwrap();
        assert_eq!(interfaces["housing"].parent.as_deref(), Some("PO2"));
        assert_eq!(interfaces["po2"].parent, None);
    }

    #[tokio::test]
    async fn label_is_read() {
        let netbox = FakeGateway::new();
        let device = netbox.add("dcim.devices", json!({"name": "fw01.dc1", "site": 12}));
        netbox.add("dcim.interfaces", json!({"device": device, "name": "a", "type": "other", "label": "HA"}));
        netbox.add("dcim.interfaces", json!({"device": device, "name": "b", "type": "other"}));
        let interfaces = read_interfaces(&netbox, "fw01.dc1").await.unwrap();
        assert_eq!((interfaces["a"].label.as_str(), interfaces["b"].label.as_str()), ("HA", ""));
    }

    #[tokio::test]
    async fn the_device_a_device_is_installed_in_is_read_by_its_name() {
        let netbox = FakeGateway::new();
        let chassis = netbox.add("dcim.devices", json!({"name": "fx01.dc1", "site": 12}));
        netbox.add("dcim.devices", json!({"name": "esx04.dc1", "site": 12, "parent_device": chassis}));
        netbox.add("dcim.devices", json!({"name": "esx08.dc1", "site": 12}));
        assert_eq!(read_parent_device(&netbox, "esx04.dc1").await, Ok(Some("fx01.dc1".to_owned())));
        assert_eq!(read_parent_device(&netbox, "esx08.dc1").await, Ok(None));
        assert_eq!(
            read_parent_device(&netbox, "esx09.dc1").await,
            Err(not_found("device esx09.dc1 not found in Netbox"))
        );
    }

    #[tokio::test]
    async fn read_interfaces_of_a_missing_device_is_not_found() {
        let netbox = FakeGateway::new();
        assert_eq!(read_interfaces(&netbox, "fw09.dc1").await, Err(not_found("device fw09.dc1 not found in Netbox")));
    }

    #[tokio::test]
    async fn a_gateway_error_is_handed_back() {
        let netbox = Canned(Err(GatewayError::Request("GET /api/ipam/vlans/ answered 502".to_owned())));
        assert_eq!(
            read_site_vlans(&netbox, 12).await,
            Err(StateError::Gateway(GatewayError::Request("GET /api/ipam/vlans/ answered 502".to_owned())))
        );
    }

    #[tokio::test]
    async fn an_object_without_a_needed_field_is_an_error_not_a_panic() {
        let missing = canned(json!([{"id": 1, "name": "VLAN2600-PPE"}]));
        assert!(matches!(read_site_vlans(&missing, 12).await, Err(StateError::Malformed(_))));
        // A number sent as text is not trusted either.
        let mistyped = canned(json!([{"id": 1, "vid": "26", "name": "VLAN2600-PPE"}]));
        assert!(matches!(read_site_vlans(&mistyped, 12).await, Err(StateError::Malformed(_))));
    }

    #[test]
    fn a_state_error_prints_what_it_carries() {
        assert_eq!(not_found("device sw1 not found in Netbox").to_string(), "device sw1 not found in Netbox");
        let refused = GatewayError::UnknownFilter { endpoint: "dcim.devices".to_owned(), filter: "nmae".to_owned() };
        assert_eq!(StateError::from(refused).to_string(), "unknown filter nmae on dcim.devices");
    }
}
