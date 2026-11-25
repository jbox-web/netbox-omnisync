//! Per-device diff between what the switch reports and what NetBox holds.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::change::{Action, Change, Fields};

use super::model::Interface;
use super::names::interface_key;
use super::stack::DesiredDevice;
use super::state::{NbDevice, NbInterface, NbIp};

fn wanted_fields(interface: &Interface) -> Fields {
    let mut fields =
        Fields::from([("name".to_owned(), json!(interface.name)), ("enabled".to_owned(), json!(interface.enabled))]);
    let mut set = |key: &str, value: Value| {
        fields.insert(key.to_owned(), value);
    };
    if let Some(description) = &interface.description {
        set("description", json!(description));
    }
    if interface.lag_managed {
        set("lag", json!(interface.lag));
    }
    if let Some(parent) = &interface.parent {
        set("parent", json!(parent));
    }
    if let Some(label) = &interface.label {
        set("label", json!(label));
    }
    // A value the switch does not report is not a value: the field stays unmanaged.
    if let Some(mtu) = interface.mtu {
        set("mtu", json!(mtu));
    }
    if let Some(r#type) = &interface.r#type {
        set("type", json!(r#type));
    }
    if let Some(mac) = &interface.mac {
        set("mac", json!(mac));
    }
    if interface.dot1q_managed {
        let dot1q = interface.dot1q.as_ref();
        set("mode", json!(dot1q.map(|dot1q| dot1q.mode.as_str())));
        // A source may tell the mode of a port and not its VLANs (a trunk of a
        // configuration report): those NetBox has are not compared.
        if interface.untagged_vlan_managed {
            set("untagged_vlan", json!(dot1q.and_then(|dot1q| dot1q.untagged_vlan)));
        }
        if interface.tagged_vlans_managed {
            set("tagged_vlans", json!(dot1q.map(|dot1q| dot1q.tagged_vlans.as_slice()).unwrap_or_default()));
        }
    }
    fields
}

fn current_fields(interface: &NbInterface) -> Fields {
    Fields::from([
        ("name".to_owned(), json!(interface.name)),
        ("enabled".to_owned(), json!(interface.enabled)),
        ("description".to_owned(), json!(interface.description)),
        ("lag".to_owned(), json!(interface.lag)),
        ("parent".to_owned(), json!(interface.parent)),
        ("label".to_owned(), json!(interface.label)),
        ("mtu".to_owned(), json!(interface.mtu)),
        ("type".to_owned(), json!(interface.r#type)),
        ("mac".to_owned(), json!(interface.mac)),
        ("mode".to_owned(), json!(interface.mode)),
        ("untagged_vlan".to_owned(), json!(interface.untagged_vlan)),
        ("tagged_vlans".to_owned(), json!(interface.tagged_vlans)),
    ])
}

/// The VIDs of a `tagged_vlans` value, in ascending order.
fn sorted_vids(value: &Value) -> Vec<u64> {
    let mut vids: Vec<u64> = value.as_array().into_iter().flatten().filter_map(Value::as_u64).collect();
    vids.sort_unstable();
    vids
}

fn same(key: &str, wanted: &Value, current: &Value) -> bool {
    match key {
        // NetBox holds `Port-channel10` where NX-OS says `port-channel10`.
        "lag" | "parent" => match (wanted.as_str(), current.as_str()) {
            (Some(wanted), Some(current)) => interface_key(wanted) == interface_key(current),
            _ => wanted.is_null() && current.is_null(),
        },
        "tagged_vlans" => sorted_vids(wanted) == sorted_vids(current),
        _ => wanted == current,
    }
}

/// The fields of `wanted` that `differs` from what NetBox has, and their NetBox values.
fn changed(wanted: Fields, have: &Fields, differs: impl Fn(&str, &Value, &Value) -> bool) -> (Fields, Fields) {
    let mut diff = Fields::new();
    let mut before = Fields::new();
    for (key, value) in wanted {
        let held = have.get(&key).cloned().unwrap_or(Value::Null);
        if differs(&key, &value, &held) {
            before.insert(key.clone(), held);
            diff.insert(key, value);
        }
    }
    (diff, before)
}

/// How many parents an interface has above it.
fn depth(interface: &NbInterface, interfaces: &BTreeMap<String, NbInterface>) -> usize {
    let mut depth = 0;
    let mut seen = BTreeSet::from([interface_key(&interface.name)]);
    let mut current = interface;
    while let Some(parent) = current.parent.as_deref().map(interface_key)
        && !seen.contains(&parent)
    {
        let Some(above) = interfaces.get(&parent) else {
            break;
        };
        seen.insert(interface_key(&above.name));
        depth += 1;
        current = above;
    }
    depth
}

fn is_interface_deletion(change: &Change) -> bool {
    change.kind == "interface" && change.action == Action::Delete
}

fn interface_changes(desired: &DesiredDevice, current: &NbDevice, prune: bool) -> Vec<Change> {
    let mut changes = Vec::new();
    for (name, interface) in &desired.interfaces {
        let mut wanted = wanted_fields(interface);
        let Some(existing) = current.interfaces.get(&interface_key(name)) else {
            // NetBox requires a type on creation; `other` until the hardware is known.
            wanted.entry("type".to_owned()).or_insert_with(|| json!("other"));
            changes.push(Change::new("interface", Action::Create, &desired.name, name).fields(wanted));
            continue;
        };
        let have = current_fields(existing);
        let (diff, before) = changed(wanted, &have, |key, value, held| !same(key, value, held));
        if !diff.is_empty() {
            changes.push(
                Change::new("interface", Action::Update, &desired.name, name)
                    .fields(diff)
                    .before(before)
                    .id(existing.id),
            );
        }
        // A MAC object the switch no longer reports on a managed MAC: deleted with prune,
        // after the apply has moved the primary MAC to the right object.
        if prune && let Some(mac) = &interface.mac {
            for (mac_id, address) in &existing.macs {
                if address != mac {
                    let key = format!("{name} {address}");
                    changes.push(Change::new("mac", Action::Delete, &desired.name, &key).id(*mac_id));
                }
            }
        }
    }
    if prune {
        let wanted_keys: BTreeSet<String> = desired.interfaces.keys().map(|name| interface_key(name)).collect();
        // NetBox refuses to delete a parent before its children: the deepest go first.
        let mut deepest_first: Vec<(&String, &NbInterface)> = current.interfaces.iter().collect();
        deepest_first.sort_by_key(|(key, existing)| (std::cmp::Reverse(depth(existing, &current.interfaces)), *key));
        for (key, existing) in deepest_first {
            if !wanted_keys.contains(key) && !desired.unmanaged_interfaces.contains(key) {
                changes.push(Change::new("interface", Action::Delete, &desired.name, &existing.name).id(existing.id));
            }
        }
    }
    changes
}

fn host(address: &str) -> &str {
    address.split('/').next().unwrap_or(address)
}

/// Pair each collected IP (by index) with a NetBox IP of the device.
///
/// Same host and VRF first; then, for the rest, same host in any VRF, which is
/// re-attached and moved to the switch's VRF. The two passes keep a host held in
/// two VRFs as two objects.
fn match_own_ips<'c>(desired: &DesiredDevice, current: &'c NbDevice) -> BTreeMap<usize, &'c NbIp> {
    let mut matched = BTreeMap::new();
    let mut free: Vec<&NbIp> = current.ips.iter().collect();
    for same_vrf in [true, false] {
        for (index, ip) in desired.ips.iter().enumerate() {
            if matched.contains_key(&index) {
                continue;
            }
            let found = free
                .iter()
                .position(|nb_ip| host(&nb_ip.address) == host(&ip.address) && (nb_ip.vrf == ip.vrf || !same_vrf));
            if let Some(position) = found {
                matched.insert(index, free.remove(position));
            }
        }
    }
    matched
}

fn ip_fields(address: &str, interface: Option<&str>, vrf: Option<&str>) -> Fields {
    Fields::from([
        ("address".to_owned(), json!(address)),
        ("interface".to_owned(), json!(interface)),
        ("vrf".to_owned(), json!(vrf)),
    ])
}

fn ip_changes(
    desired: &DesiredDevice,
    current: &NbDevice,
    ips_by_host: &BTreeMap<String, Vec<NbIp>>,
    prune: bool,
    unique_tables: &BTreeSet<Option<String>>,
) -> (Vec<Change>, Vec<String>) {
    let mut changes = Vec::new();
    let mut warnings = Vec::new();
    let matched = match_own_ips(desired, current);
    for (index, ip) in desired.ips.iter().enumerate() {
        let wanted = ip_fields(&ip.address, Some(&ip.interface), ip.vrf.as_deref());
        if let Some(existing) = matched.get(&index) {
            let have = ip_fields(&existing.address, existing.interface.as_deref(), existing.vrf.as_deref());
            let (diff, before) = changed(wanted, &have, |key, value, held| {
                if key == "interface" {
                    interface_key(value.as_str().unwrap_or_default())
                        != interface_key(held.as_str().unwrap_or_default())
                } else {
                    value != held
                }
            });
            if !diff.is_empty() {
                changes.push(
                    Change::new("ip", Action::Update, &desired.name, &ip.address)
                        .fields(diff)
                        .before(before)
                        .id(existing.id),
                );
            }
            continue;
        }
        let others = ips_by_host.get(host(&ip.address)).map(Vec::as_slice).unwrap_or_default();
        // An unassigned IP is adopted in its own table only: the same host in
        // another VRF is another object, left where it is.
        if let Some(loose) = others.iter().find(|other| other.device.is_none() && other.vrf == ip.vrf) {
            let have = ip_fields(&loose.address, None, loose.vrf.as_deref());
            let (diff, before) = changed(wanted, &have, |_, value, held| value != held);
            changes.push(
                Change::new("ip", Action::Update, &desired.name, &ip.address).fields(diff).before(before).id(loose.id),
            );
            continue;
        }
        // Never move an IP owned by another device: both may legitimately hold it.
        let mut held_elsewhere = false;
        for other in others {
            let Some(holder) = other.device.as_deref().filter(|_| other.vrf == ip.vrf) else {
                continue;
            };
            held_elsewhere = true;
            let mut warning = format!(
                "{}: {} (VRF {}) also assigned to {}",
                desired.name,
                ip.address,
                ip.vrf.as_deref().filter(|vrf| !vrf.is_empty()).unwrap_or("global"),
                holder,
            );
            if let Some(interface) = other.interface.as_deref() {
                warning.push(' ');
                warning.push_str(interface);
            }
            if unique_tables.contains(&ip.vrf) {
                warning.push_str("; not created: ");
                match &ip.vrf {
                    None => {
                        warning.push_str("the global table enforces unique addresses (ENFORCE_GLOBAL_UNIQUE)");
                    }
                    Some(vrf) => warning.push_str(&format!(
                        "VRF {vrf} enforces unique addresses (uncheck its \
                         'enforce unique space' to hold it on both devices)"
                    )),
                }
            }
            warnings.push(warning);
        }
        // NetBox refuses the duplicate, and the refusal would stop the device's writes.
        if held_elsewhere && unique_tables.contains(&ip.vrf) {
            continue;
        }
        changes.push(Change::new("ip", Action::Create, &desired.name, &ip.address).fields(wanted));
    }
    if prune {
        let claimed: BTreeSet<u64> = matched.values().map(|existing| existing.id).collect();
        let mut by_address: Vec<&NbIp> = current.ips.iter().collect();
        by_address.sort_by_key(|nb_ip| (nb_ip.address.as_str(), nb_ip.id));
        for existing in by_address {
            // The current primary IP is never pruned: losing it cuts the device's
            // management entry in NetBox, whatever the collection missed. IPv6 is not
            // collected: an IPv6 address is unmanaged, not absent from the switch.
            if !claimed.contains(&existing.id)
                && current.primary_ip4.as_deref() != Some(existing.address.as_str())
                && !host(&existing.address).contains(':')
                && !desired
                    .unmanaged_interfaces
                    .contains(&interface_key(existing.interface.as_deref().unwrap_or_default()))
            {
                changes.push(Change::new("ip", Action::Delete, &desired.name, &existing.address).id(existing.id));
            }
        }
    }
    (changes, warnings)
}

/// Drop the deletion of the interface carrying the current primary IP.
///
/// NetBox deletes an interface's IPs with it, so pruning that interface would
/// delete the primary IP too — unless this run re-attaches the IP elsewhere first.
fn keep_primary_interface(
    desired: &DesiredDevice,
    current: &NbDevice,
    changes: &mut Vec<Change>,
    warnings: &mut Vec<String>,
) {
    // NetBox names the primary IP by its address: when the device holds that
    // address more than once (in two VRFs), each of them may be the primary one.
    let primaries = current.ips.iter().filter(|ip| current.primary_ip4.as_deref() == Some(ip.address.as_str()));
    for primary in primaries {
        let Some(interface) = primary.interface.as_deref() else {
            continue;
        };
        let moved = changes.iter().any(|change| {
            change.kind == "ip" && change.id == Some(primary.id) && change.fields.contains_key("interface")
        });
        if moved {
            continue;
        }
        changes.retain(|change| {
            let kept = is_interface_deletion(change) && interface_key(&change.key) == interface_key(interface);
            if kept {
                warnings.push(format!("{}: {interface} carries the primary IP; interface left in place", desired.name));
            }
            !kept
        });
    }
}

/// Drop the deletion of an interface carrying an IPv6 address.
///
/// IPv6 is not collected, so an IPv6 address is unmanaged, not absent from the
/// switch; NetBox deletes an interface's IPs with it.
fn keep_interfaces_with_ipv6(desired: &DesiredDevice, current: &NbDevice, changes: &mut Vec<Change>) -> Vec<String> {
    let with_ipv6: BTreeSet<String> = current
        .ips
        .iter()
        .filter(|ip| host(&ip.address).contains(':'))
        .filter_map(|ip| ip.interface.as_deref())
        .map(interface_key)
        .collect();
    let mut warnings = Vec::new();
    changes.retain(|change| {
        let kept = is_interface_deletion(change) && with_ipv6.contains(&interface_key(&change.key));
        if kept {
            warnings.push(format!("{}: {} carries an IPv6 address; interface left in place", desired.name, change.key));
        }
        !kept
    });
    warnings
}

/// The source tells no IP: NetBox keeps its IPs, and the interfaces carrying
/// them, since deleting an interface deletes its IPs.
fn keep_interfaces_with_ips(desired: &DesiredDevice, current: &NbDevice, changes: &mut Vec<Change>) -> Vec<String> {
    let with_ips: BTreeSet<String> = current
        .ips
        .iter()
        .filter_map(|ip| ip.interface.as_deref())
        .filter(|interface| !interface.is_empty())
        .map(interface_key)
        .collect();
    let mut warnings = Vec::new();
    changes.retain(|change| {
        let kept = is_interface_deletion(change) && with_ips.contains(&interface_key(&change.key));
        if kept {
            warnings.push(format!("{}: {} carries IP addresses; interface left in place", desired.name, change.key));
        }
        !kept
    });
    warnings
}

/// Drop the deletion of a parent whose child stays: NetBox would refuse it and
/// stop the deletions there.
fn keep_parents(desired: &DesiredDevice, current: &NbDevice, changes: &mut Vec<Change>) -> Vec<String> {
    let mut deletions: BTreeSet<String> = changes
        .iter()
        .filter(|change| is_interface_deletion(change))
        .map(|change| interface_key(&change.key))
        .collect();
    let wanted: BTreeMap<String, &Interface> =
        desired.interfaces.iter().map(|(name, interface)| (interface_key(name), interface)).collect();
    let mut kept = BTreeSet::new();
    let mut warnings = Vec::new();
    for (key, interface) in &current.interfaces {
        // A child whose parent this run sets no longer hangs on the NetBox one.
        if deletions.contains(key) || wanted.get(key).is_some_and(|interface| interface.parent.is_some()) {
            continue;
        }
        let mut child = interface;
        while let Some(parent_key) = child.parent.as_deref().map(interface_key)
            && deletions.contains(&parent_key)
        {
            let Some(parent) = current.interfaces.get(&parent_key) else {
                break;
            };
            deletions.remove(&parent_key);
            kept.insert(parent_key);
            warnings.push(format!(
                "{}: {} is the parent of {}, which stays; interface left in place",
                desired.name, parent.name, child.name
            ));
            child = parent;
        }
    }
    changes.retain(|change| !(is_interface_deletion(change) && kept.contains(&interface_key(&change.key))));
    warnings
}

/// Add the IP and primary IP changes to `changes`; return the warnings.
fn managed_ip_changes(
    desired: &DesiredDevice,
    current: &NbDevice,
    ips_by_host: &BTreeMap<String, Vec<NbIp>>,
    prune: bool,
    unique_tables: &BTreeSet<Option<String>>,
    changes: &mut Vec<Change>,
) -> Vec<String> {
    let (ip_changes, mut warnings) = ip_changes(desired, current, ips_by_host, prune, unique_tables);
    changes.extend(ip_changes);
    keep_primary_interface(desired, current, changes, &mut warnings);
    let Some(primary) = desired.primary_ip4.as_deref() else {
        if current.primary_ip4.is_some() {
            warnings
                .push(format!("{}: no collected IP matches the inventory host; primary IP left as is", desired.name));
        }
        return warnings;
    };
    if current.primary_ip4.as_deref() != Some(primary) {
        // NetBox only takes as primary an address the device holds: one it has
        // already, or one this run creates or moves onto it. Otherwise the
        // write is refused, and the refusal stops the device's later writes.
        let held = current.ips.iter().any(|ip| ip.address == primary)
            || changes
                .iter()
                .any(|change| change.kind == "ip" && change.key == primary && change.action != Action::Delete);
        if !held {
            warnings.push(format!("{}: primary IP {primary} not set: the device does not hold it", desired.name));
            return warnings;
        }
        let vrf = desired.ips.iter().find(|ip| ip.address == primary).and_then(|ip| ip.vrf.as_deref());
        changes.push(
            Change::new("primary_ip", Action::Update, &desired.name, primary)
                .fields([("address", json!(primary)), ("vrf", json!(vrf))])
                .before([("address", json!(current.primary_ip4))])
                .id(current.id),
        );
    }
    warnings
}

/// `unique_tables` holds the VRF names (None: the global table) where NetBox
/// refuses a duplicate address.
///
/// `ips_by_host` maps a host address (no mask) to every NetBox IP that has it,
/// whatever holds it. Returns the changes and the warnings.
pub fn diff_device(
    desired: &DesiredDevice,
    current: &NbDevice,
    ips_by_host: &BTreeMap<String, Vec<NbIp>>,
    prune: bool,
    unique_tables: &BTreeSet<Option<String>>,
) -> (Vec<Change>, Vec<String>) {
    let mut changes = Vec::new();
    let mut warnings = Vec::new();
    // Nothing is known of an unmanaged device's interfaces: none is compared nor pruned.
    if desired.interfaces_managed {
        changes = interface_changes(desired, current, prune);
        warnings = if desired.ips_managed {
            let mut warnings = managed_ip_changes(desired, current, ips_by_host, prune, unique_tables, &mut changes);
            warnings.extend(keep_interfaces_with_ipv6(desired, current, &mut changes));
            warnings
        } else {
            keep_interfaces_with_ips(desired, current, &mut changes)
        };
        warnings.extend(keep_parents(desired, current, &mut changes));
    }
    if let Some(serial) = desired.serial.as_deref()
        && serial != current.serial
    {
        changes.push(
            Change::new("serial", Action::Update, &desired.name, &desired.name)
                .fields([("serial", json!(serial))])
                .before([("serial", json!(current.serial))])
                .id(current.id),
        );
    }
    (changes, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::model::{Dot1q, IpAddress, Mode};

    const DEVICE: &str = "nexus01.lab01";

    fn nb_iface(id: u64, name: &str) -> NbInterface {
        nb_typed(id, name, "10gbase-x-sfpp")
    }

    fn nb_typed(id: u64, name: &str, kind: &str) -> NbInterface {
        NbInterface { mtu: Some(1500), r#type: Some(kind.to_owned()), ..NbInterface::new(id, name) }
    }

    fn nb_child(id: u64, name: &str, parent: &str) -> NbInterface {
        NbInterface { parent: Some(parent.to_owned()), ..nb_typed(id, name, "virtual") }
    }

    fn nb_ip(id: u64, address: &str, vrf: Option<&str>, device: Option<&str>, interface: Option<&str>) -> NbIp {
        NbIp {
            id,
            address: address.to_owned(),
            vrf: vrf.map(str::to_owned),
            device: device.map(str::to_owned),
            interface: interface.map(str::to_owned),
        }
    }

    fn device<const N: usize>(interfaces: [NbInterface; N]) -> NbDevice {
        NbDevice {
            id: 65,
            name: DEVICE.to_owned(),
            site_id: 12,
            site: "Harbor".to_owned(),
            serial: "S1".to_owned(),
            primary_ip4: None,
            interfaces: interfaces.into_iter().map(|interface| (interface.name.to_lowercase(), interface)).collect(),
            ips: Vec::new(),
        }
    }

    fn device_with_ips<const N: usize, const M: usize>(
        interfaces: [NbInterface; N],
        ips: [NbIp; M],
        primary: Option<&str>,
    ) -> NbDevice {
        NbDevice { ips: ips.to_vec(), primary_ip4: primary.map(str::to_owned), ..device(interfaces) }
    }

    fn iface(name: &str, kind: Option<&str>) -> Interface {
        Interface {
            description: Some(String::new()),
            mtu: Some(1500),
            r#type: kind.map(str::to_owned),
            ..Interface::new(name, true)
        }
    }

    fn eth() -> Interface {
        iface("Ethernet1/1", Some("10gbase-x-sfpp"))
    }

    fn svi(name: &str) -> Interface {
        iface(name, Some("virtual"))
    }

    /// An SVI as a configuration report gives it: no description, no MTU, no 802.1Q.
    fn report_svi() -> Interface {
        Interface { r#type: Some("virtual".to_owned()), dot1q_managed: false, ..Interface::new("Vlan952", true) }
    }

    fn ip(address: &str, interface: &str, vrf: Option<&str>) -> IpAddress {
        IpAddress { address: address.to_owned(), interface: interface.to_owned(), vrf: vrf.map(str::to_owned) }
    }

    fn want<const N: usize>(interfaces: [Interface; N]) -> DesiredDevice {
        let mut desired = DesiredDevice::new(DEVICE, Some("S1".to_owned()));
        desired.interfaces = interfaces.into_iter().map(|interface| (interface.name.clone(), interface)).collect();
        desired
    }

    fn want_ips<const N: usize, const M: usize>(
        interfaces: [Interface; N],
        ips: [IpAddress; M],
        primary: Option<&str>,
    ) -> DesiredDevice {
        DesiredDevice { ips: ips.to_vec(), primary_ip4: primary.map(str::to_owned), ..want(interfaces) }
    }

    fn vlan() -> Interface {
        Interface { parent: Some("PO2".to_owned()), ..svi("HOUSING") }
    }

    fn aggregate() -> Interface {
        iface("PO2", Some("lag"))
    }

    fn peer(serial: Option<&str>) -> DesiredDevice {
        DesiredDevice { interfaces_managed: false, ..DesiredDevice::new(DEVICE, serial.map(str::to_owned)) }
    }

    fn by_host<const N: usize>(host: &str, ips: [NbIp; N]) -> BTreeMap<String, Vec<NbIp>> {
        BTreeMap::from([(host.to_owned(), ips.to_vec())])
    }

    fn tables<const N: usize>(names: [Option<&str>; N]) -> BTreeSet<Option<String>> {
        names.into_iter().map(|name| name.map(str::to_owned)).collect()
    }

    /// The diff with no IP known elsewhere in NetBox and no table enforcing uniqueness.
    fn diff(desired: &DesiredDevice, current: &NbDevice, prune: bool) -> (Vec<Change>, Vec<String>) {
        diff_device(desired, current, &BTreeMap::new(), prune, &BTreeSet::new())
    }

    fn nothing() -> (Vec<Change>, Vec<String>) {
        (Vec::new(), Vec::new())
    }

    fn change(kind: &str, action: Action, key: &str) -> Change {
        Change::new(kind, action, "nexus01.lab01", key)
    }

    fn actions_and_keys(changes: &[Change]) -> Vec<(Action, &str)> {
        changes.iter().map(|change| (change.action, change.key.as_str())).collect()
    }

    fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Fields {
        pairs.into_iter().map(|(key, value)| (key.to_owned(), value)).collect()
    }

    #[test]
    fn in_sync_gives_nothing() {
        assert_eq!(diff(&want([eth()]), &device([nb_iface(1, "Ethernet1/1")]), true), nothing());
    }

    #[test]
    fn new_interface_with_unknown_type_is_created_as_other() {
        let new = iface("GigabitEthernet1/0/25", None);
        let (changes, _) = diff(&want([new]), &device([]), false);
        assert_eq!(
            changes,
            [change("interface", Action::Create, "GigabitEthernet1/0/25").fields([
                ("name", json!("GigabitEthernet1/0/25")),
                ("enabled", json!(true)),
                ("description", json!("")),
                ("lag", json!(null)),
                ("mtu", json!(1500)),
                ("type", json!("other")),
                ("mode", json!(null)),
                ("untagged_vlan", json!(null)),
                ("tagged_vlans", json!([])),
            ])]
        );
    }

    #[test]
    fn switch_wins_even_with_empty_description() {
        let current = device([NbInterface { description: "Uplink".to_owned(), ..nb_iface(1, "Ethernet1/1") }]);
        let (changes, _) = diff(&want([eth()]), &current, false);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "Ethernet1/1")
                .fields([("description", json!(""))])
                .before([("description", json!("Uplink"))])
                .id(1)]
        );
    }

    #[test]
    fn unmanaged_type_is_not_compared() {
        let unknown = iface("Ethernet1/1", None);
        assert_eq!(diff(&want([unknown]), &device([nb_typed(1, "Ethernet1/1", "other")]), false), nothing());
    }

    #[test]
    fn case_only_difference_is_a_rename() {
        let lag = iface("port-channel10", Some("lag"));
        let (changes, _) = diff(&want([lag]), &device([nb_typed(9, "Port-channel10", "lag")]), true);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "port-channel10")
                .fields([("name", json!("port-channel10"))])
                .before([("name", json!("Port-channel10"))])
                .id(9)]
        );
    }

    #[test]
    fn lag_parent_compared_case_insensitively() {
        let member =
            Interface { lag: Some("port-channel10".to_owned()), ..iface("Ethernet1/51", Some("10gbase-x-sfpp")) };
        let current = device([NbInterface { lag: Some("Port-channel10".to_owned()), ..nb_iface(1, "Ethernet1/51") }]);
        assert_eq!(diff(&want([member]), &current, false), nothing());
    }

    #[test]
    fn dot1q_update() {
        let trunk = Interface {
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: Some(26), tagged_vlans: vec![2600, 2712] }),
            ..eth()
        };
        let current = device([NbInterface { mode: Some("access".to_owned()), ..nb_iface(1, "Ethernet1/1") }]);
        let (changes, _) = diff(&want([trunk]), &current, false);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "Ethernet1/1")
                .fields([
                    ("mode", json!("tagged")),
                    ("untagged_vlan", json!(26)),
                    ("tagged_vlans", json!([2600, 2712]))
                ])
                .before([("mode", json!("access")), ("untagged_vlan", json!(null)), ("tagged_vlans", json!([]))])
                .id(1)]
        );
    }

    #[test]
    fn dot1q_unmanaged_is_not_compared() {
        let port = Interface { dot1q_managed: false, ..eth() };
        let current = device([NbInterface {
            mode: Some("tagged".to_owned()),
            untagged_vlan: Some(5),
            ..nb_iface(1, "Ethernet1/1")
        }]);
        assert_eq!(diff(&want([port]), &current, false), nothing());
    }

    // A trunk of a configuration report: the report gives its mode, neither its
    // native VLAN nor the VLANs it allows.
    #[test]
    fn a_mode_told_without_its_vlans_leaves_the_vlans_netbox_has() {
        let trunk = Interface {
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: Vec::new() }),
            untagged_vlan_managed: false,
            tagged_vlans_managed: false,
            ..eth()
        };
        let current = device([NbInterface {
            mode: Some("access".to_owned()),
            untagged_vlan: Some(3),
            tagged_vlans: vec![10, 11],
            ..nb_iface(1, "Ethernet1/1")
        }]);
        let (changes, _) = diff(&want([trunk]), &current, false);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "Ethernet1/1")
                .fields([("mode", json!("tagged"))])
                .before([("mode", json!("access"))])
                .id(1)]
        );
    }

    // The same trunk once its description lists its VLANs: the list is written,
    // the native VLAN still is not known.
    #[test]
    fn the_tagged_vlans_are_written_while_the_untagged_one_is_left_as_netbox_has_it() {
        let trunk = Interface {
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: vec![10, 12] }),
            untagged_vlan_managed: false,
            ..eth()
        };
        let current = device([NbInterface {
            mode: Some("tagged".to_owned()),
            untagged_vlan: Some(3),
            tagged_vlans: vec![10, 11],
            ..nb_iface(1, "Ethernet1/1")
        }]);
        let (changes, _) = diff(&want([trunk]), &current, false);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "Ethernet1/1")
                .fields([("tagged_vlans", json!([10, 12]))])
                .before([("tagged_vlans", json!([10, 11]))])
                .id(1)]
        );
    }

    // A source that tells the native VLAN of its trunks already keeps it out of the tagged ones.
    #[test]
    fn a_native_vlan_the_source_tells_is_compared_as_it_is_told() {
        let trunk = Interface {
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: Some(1), tagged_vlans: vec![19, 24] }),
            ..eth()
        };
        let current = device([NbInterface {
            mode: Some("tagged".to_owned()),
            untagged_vlan: Some(24),
            tagged_vlans: vec![19],
            ..nb_iface(1, "Ethernet1/1")
        }]);
        let (changes, _) = diff(&want([trunk]), &current, false);
        assert_eq!(changes[0].fields, fields([("untagged_vlan", json!(1)), ("tagged_vlans", json!([19, 24]))]));
    }

    #[test]
    fn routed_interface_clears_mode() {
        let current = device([NbInterface {
            mode: Some("access".to_owned()),
            untagged_vlan: Some(1),
            ..nb_iface(1, "Ethernet1/1")
        }]);
        let (changes, _) = diff(&want([eth()]), &current, false);
        assert_eq!(changes[0].fields, fields([("mode", json!(null)), ("untagged_vlan", json!(null))]));
    }

    #[test]
    fn mac_managed_only_when_reported() {
        let with_mac = Interface { mac: Some("02:08:D1:90:97:2D".to_owned()), ..eth() };
        let (changes, _) = diff(&want([with_mac]), &device([nb_iface(1, "Ethernet1/1")]), false);
        assert_eq!(changes[0].fields, fields([("mac", json!("02:08:D1:90:97:2D"))]));
        let current = device([NbInterface { mac: Some("00:00:00:00:00:01".to_owned()), ..nb_iface(1, "Ethernet1/1") }]);
        assert_eq!(diff(&want([eth()]), &current, false), nothing());
    }

    #[test]
    fn stale_mac_objects_deleted_only_with_prune() {
        let port = Interface { mac: Some("02:08:D1:90:97:2D".to_owned()), ..eth() };
        let current = device([NbInterface {
            mac: Some("02:08:D1:90:97:2D".to_owned()),
            macs: vec![(5, "00:11:22:33:44:55".to_owned()), (6, "02:08:D1:90:97:2D".to_owned())],
            ..nb_iface(1, "Ethernet1/1")
        }]);
        assert_eq!(diff(&want([port.clone()]), &current, false), nothing());
        let (changes, _) = diff(&want([port]), &current, true);
        assert_eq!(changes, [change("mac", Action::Delete, "Ethernet1/1 00:11:22:33:44:55").id(5)]);
    }

    #[test]
    fn mac_objects_untouched_when_the_mac_is_unmanaged() {
        // The switch reports no MAC for this interface: its MAC objects are not ours to judge.
        let current =
            device([NbInterface { macs: vec![(5, "00:11:22:33:44:55".to_owned())], ..nb_iface(1, "Ethernet1/1") }]);
        assert_eq!(diff(&want([eth()]), &current, true), nothing());
    }

    #[test]
    fn unknown_interface_deleted_only_with_prune() {
        let current = device([nb_iface(1, "Ethernet1/1"), nb_typed(2, "admin", "virtual")]);
        assert_eq!(diff(&want([eth()]), &current, false), nothing());
        let (changes, _) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, [change("interface", Action::Delete, "admin").id(2)]);
    }

    #[test]
    fn ip_reattached_to_real_interface() {
        let current = device_with_ips(
            [nb_typed(1, "Vlan2800", "virtual"), nb_typed(2, "admin", "virtual")],
            [nb_ip(1116, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("admin"))],
            Some("192.0.2.239/24"),
        );
        let desired =
            want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", Some("mgmt-sw"))], Some("192.0.2.239/24"));
        let (changes, _) = diff(&desired, &current, true);
        let reattached = change("ip", Action::Update, "192.0.2.239/24")
            .fields([("interface", json!("Vlan2800")), ("vrf", json!("mgmt-sw"))])
            .before([("interface", json!("admin")), ("vrf", json!(null))])
            .id(1116);
        assert!(changes.contains(&reattached), "{changes:?}");
        assert!(!changes.iter().any(|c| c.kind == "ip" && c.action != Action::Update), "{changes:?}");
        assert!(!changes.iter().any(|c| c.kind == "primary_ip"), "{changes:?}");
    }

    #[test]
    fn ip_created_when_unknown() {
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", None)], None);
        let (changes, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "Vlan2800", "virtual")]),
            &by_host("192.0.2.239", []),
            false,
            &BTreeSet::new(),
        );
        assert_eq!(
            changes,
            [change("ip", Action::Create, "192.0.2.239/24").fields([
                ("address", json!("192.0.2.239/24")),
                ("vrf", json!(null)),
                ("interface", json!("Vlan2800")),
            ])]
        );
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn unassigned_ip_is_adopted() {
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", None)], None);
        let loose = nb_ip(77, "192.0.2.239/24", None, None, None);
        let (changes, _) = diff_device(
            &desired,
            &device([nb_typed(1, "Vlan2800", "virtual")]),
            &by_host("192.0.2.239", [loose]),
            false,
            &BTreeSet::new(),
        );
        assert_eq!(
            changes,
            [change("ip", Action::Update, "192.0.2.239/24")
                .fields([("interface", json!("Vlan2800"))])
                .before([("interface", json!(null))])
                .id(77)]
        );
    }

    #[test]
    fn ip_on_other_device_is_duplicated_with_warning() {
        let desired =
            want_ips([iface("mgmt0", Some("1000base-t"))], [ip("192.168.1.1/24", "mgmt0", Some("management"))], None);
        let other = nb_ip(80, "192.168.1.1/24", Some("management"), Some("nexus03.lab01"), Some("mgmt0"));
        let (changes, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "mgmt0", "1000base-t")]),
            &by_host("192.168.1.1", [other]),
            false,
            &BTreeSet::new(),
        );
        let actions: Vec<Action> = changes.iter().map(|c| c.action).collect();
        assert_eq!(actions, [Action::Create]);
        assert_eq!(warnings, ["nexus01.lab01: 192.168.1.1/24 (VRF management) also assigned to nexus03.lab01 mgmt0"]);
    }

    #[test]
    fn ip_on_other_device_in_a_unique_vrf_is_not_created() {
        // NetBox would refuse the duplicate and stop the rest of the device's writes.
        let desired =
            want_ips([iface("mgmt0", Some("1000base-t"))], [ip("192.168.1.1/24", "mgmt0", Some("management"))], None);
        let other = nb_ip(80, "192.168.1.1/24", Some("management"), Some("nexus03.lab01"), Some("mgmt0"));
        let (changes, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "mgmt0", "1000base-t")]),
            &by_host("192.168.1.1", [other]),
            false,
            &tables([None, Some("management")]),
        );
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            ["nexus01.lab01: 192.168.1.1/24 (VRF management) also assigned to nexus03.lab01 mgmt0; \
              not created: VRF management enforces unique addresses (uncheck its \
              'enforce unique space' to hold it on both devices)"]
        );
    }

    #[test]
    fn ip_on_other_device_in_the_unique_global_table_is_not_created() {
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", None)], None);
        let other = nb_ip(81, "192.0.2.239/24", None, Some("nexus03.lab01"), Some("Vlan2800"));
        let (changes, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "Vlan2800", "virtual")]),
            &by_host("192.0.2.239", [other]),
            false,
            &tables([None]),
        );
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            ["nexus01.lab01: 192.0.2.239/24 (VRF global) also assigned to nexus03.lab01 Vlan2800; \
              not created: the global table enforces unique addresses (ENFORCE_GLOBAL_UNIQUE)"]
        );
    }

    // The management address is not created (another device holds it in a
    // unique table): setting it as primary would be refused by NetBox, and the
    // refusal stop every later write of the device, at every run.
    #[test]
    fn a_primary_ip_that_is_not_created_is_not_set_as_primary() {
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", None)], Some("192.0.2.239/24"));
        let other = nb_ip(81, "192.0.2.239/24", None, Some("nexus03.lab01"), Some("Vlan2800"));
        let (changes, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "Vlan2800", "virtual")]),
            &by_host("192.0.2.239", [other]),
            false,
            &tables([None]),
        );
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            [
                "nexus01.lab01: 192.0.2.239/24 (VRF global) also assigned to nexus03.lab01 Vlan2800; \
                 not created: the global table enforces unique addresses (ENFORCE_GLOBAL_UNIQUE)",
                "nexus01.lab01: primary IP 192.0.2.239/24 not set: the device does not hold it",
            ]
        );
    }

    #[test]
    fn ip_deleted_only_with_prune() {
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1")],
            [nb_ip(5, "10.9.9.9/24", None, Some("nexus01.lab01"), Some("Ethernet1/1"))],
            None,
        );
        assert_eq!(diff(&want([eth()]), &current, false), nothing());
        let (changes, _) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, [change("ip", Action::Delete, "10.9.9.9/24").id(5)]);
    }

    #[test]
    fn same_host_in_two_vrfs_is_two_ips() {
        let in_a = nb_ip(10, "192.168.1.1/24", Some("a"), Some("nexus01.lab01"), Some("Vlan1"));
        let desired = want_ips(
            [svi("Vlan1")],
            [ip("192.168.1.1/24", "Vlan1", Some("b")), ip("192.168.1.1/24", "Vlan1", Some("a"))],
            None,
        );
        let current = device_with_ips([nb_typed(1, "Vlan1", "virtual")], [in_a.clone()], None);
        let (changes, warnings) =
            diff_device(&desired, &current, &by_host("192.168.1.1", [in_a.clone()]), true, &BTreeSet::new());
        assert_eq!(
            changes,
            [change("ip", Action::Create, "192.168.1.1/24").fields([
                ("address", json!("192.168.1.1/24")),
                ("vrf", json!("b")),
                ("interface", json!("Vlan1")),
            ])]
        );
        assert_eq!(warnings, Vec::<String>::new());
        let in_b = nb_ip(11, "192.168.1.1/24", Some("b"), Some("nexus01.lab01"), Some("Vlan1"));
        let both = device_with_ips([nb_typed(1, "Vlan1", "virtual")], [in_a.clone(), in_b.clone()], None);
        assert_eq!(
            diff_device(&desired, &both, &by_host("192.168.1.1", [in_a, in_b]), true, &BTreeSet::new()),
            nothing()
        );
    }

    #[test]
    fn ipv6_is_never_pruned() {
        // Only IPv4 is collected: an IPv6 address in NetBox is unmanaged, not absent.
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1")],
            [nb_ip(6, "2001:db8::1/64", None, Some("nexus01.lab01"), Some("Ethernet1/1"))],
            None,
        );
        assert_eq!(diff(&want([eth()]), &current, true), nothing());
    }

    #[test]
    fn primary_ip_update() {
        let current = device_with_ips(
            [nb_typed(1, "Vlan2800", "virtual")],
            [nb_ip(9, "192.0.2.239/24", Some("mgmt-sw"), Some("nexus01.lab01"), Some("Vlan2800"))],
            None,
        );
        let desired =
            want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", Some("mgmt-sw"))], Some("192.0.2.239/24"));
        let (changes, _) = diff(&desired, &current, false);
        assert_eq!(
            changes,
            [change("primary_ip", Action::Update, "192.0.2.239/24")
                .fields([("address", json!("192.0.2.239/24")), ("vrf", json!("mgmt-sw"))])
                .before([("address", json!(null))])
                .id(65)]
        );
    }

    #[test]
    fn serial() {
        let desired = DesiredDevice { serial: Some("FOC9792A4K9".to_owned()), ..want([eth()]) };
        let current = NbDevice { serial: String::new(), ..device([nb_iface(1, "Ethernet1/1")]) };
        let (changes, _) = diff(&desired, &current, false);
        assert_eq!(
            changes,
            [change("serial", Action::Update, "nexus01.lab01")
                .fields([("serial", json!("FOC9792A4K9"))])
                .before([("serial", json!(""))])
                .id(65)]
        );
        let unreported = DesiredDevice { serial: None, ..want([eth()]) };
        assert_eq!(diff(&unreported, &device([nb_iface(1, "Ethernet1/1")]), false), nothing());
    }

    #[test]
    fn rename_when_the_switch_has_the_capital_letter() {
        // IOS reports `Port-channel1`; a NetBox interface typed as `port-channel1` is the same one.
        let lag = iface("Port-channel1", Some("lag"));
        let (changes, _) = diff(&want([lag]), &device([nb_typed(7, "port-channel1", "lag")]), true);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "Port-channel1")
                .fields([("name", json!("Port-channel1"))])
                .before([("name", json!("port-channel1"))])
                .id(7)]
        );
    }

    #[test]
    fn current_primary_ip_is_never_pruned() {
        // The inventory host is a DNS name or a NATed address: no collected IP matches it.
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1")],
            [nb_ip(5, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("Ethernet1/1"))],
            Some("192.0.2.239/24"),
        );
        let (changes, warnings) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, []);
        assert_eq!(warnings, ["nexus01.lab01: no collected IP matches the inventory host; primary IP left as is"]);
    }

    #[test]
    fn interface_holding_the_primary_ip_is_never_pruned() {
        // Deleting the interface would cascade to its IPs in NetBox, primary IP included.
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "admin", "virtual")],
            [nb_ip(5, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("admin"))],
            Some("192.0.2.239/24"),
        );
        let (changes, warnings) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, []);
        assert!(
            warnings.contains(&"nexus01.lab01: admin carries the primary IP; interface left in place".to_owned()),
            "{warnings:?}"
        );
    }

    #[test]
    fn unmanaged_lag_is_left_as_is() {
        // A configuration report gives no channel-group: the member's LAG stays as it is.
        let port = Interface { lag_managed: false, ..eth() };
        let current = device([NbInterface { lag: Some("Port-channel40".to_owned()), ..nb_iface(1, "Ethernet1/1") }]);
        assert_eq!(diff(&want([port]), &current, true), nothing());
    }

    #[test]
    fn unmanaged_ips_are_neither_pruned_nor_warned_about() {
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "Vlan952", "virtual")],
            [
                nb_ip(7, "192.0.2.3/26", None, Some("nexus01.lab01"), Some("Vlan952")),
                nb_ip(8, "192.0.2.9/24", None, Some("nexus01.lab01"), Some("Vlan952")),
            ],
            Some("192.0.2.9/24"),
        );
        let desired = DesiredDevice { ips_managed: false, ..want([eth(), report_svi()]) };
        assert_eq!(diff(&desired, &current, true), nothing());
    }

    #[test]
    fn unmanaged_ips_keep_the_interfaces_carrying_them() {
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "Vlan952", "virtual"), nb_typed(3, "Vlan4", "virtual")],
            [nb_ip(7, "192.0.2.3/26", None, Some("nexus01.lab01"), Some("Vlan952"))],
            None,
        );
        let desired = DesiredDevice { ips_managed: false, ..want([eth()]) };
        let (changes, warnings) = diff(&desired, &current, true);
        let summary: Vec<(&str, Action, &str)> =
            changes.iter().map(|c| (c.kind.as_str(), c.action, c.key.as_str())).collect();
        assert_eq!(summary, [("interface", Action::Delete, "Vlan4")]);
        assert_eq!(warnings, ["nexus01.lab01: Vlan952 carries IP addresses; interface left in place"]);
    }

    #[test]
    fn unmanaged_description_is_not_compared() {
        let current =
            device([NbInterface { description: "Interco RT-FW".to_owned(), ..nb_typed(1, "Vlan952", "virtual") }]);
        assert_eq!(diff(&want([report_svi()]), &current, false), nothing());
    }

    #[test]
    fn unmanaged_description_is_left_out_of_a_creation() {
        let (changes, _) = diff(&want([report_svi()]), &device([]), false);
        let created: Vec<_> = changes.iter().map(|c| c.fields.clone()).collect();
        assert_eq!(
            created,
            [fields([
                ("name", json!("Vlan952")),
                ("enabled", json!(true)),
                ("lag", json!(null)),
                ("type", json!("virtual")),
            ])]
        );
    }

    #[test]
    fn unmanaged_ips_still_update_the_serial() {
        let desired = DesiredDevice { serial: Some("S2".to_owned()), ips_managed: false, ..want([eth()]) };
        let (changes, _) = diff(&desired, &device([nb_iface(1, "Ethernet1/1")]), false);
        assert_eq!(
            changes,
            [change("serial", Action::Update, "nexus01.lab01")
                .fields([("serial", json!("S2"))])
                .before([("serial", json!("S1"))])
                .id(65)]
        );
    }

    #[test]
    fn parent_is_set_on_an_existing_interface() {
        let current = device([nb_typed(1, "PO2", "lag"), nb_typed(2, "HOUSING", "virtual")]);
        let (changes, _) = diff(&want([aggregate(), vlan()]), &current, false);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "HOUSING")
                .fields([("parent", json!("PO2"))])
                .before([("parent", json!(null))])
                .id(2)]
        );
    }

    #[test]
    fn parent_is_compared_without_case() {
        let current = device([nb_typed(1, "po2", "lag"), nb_child(2, "HOUSING", "po2")]);
        let lower = Interface { name: "po2".to_owned(), ..aggregate() };
        assert_eq!(diff(&want([lower, vlan()]), &current, false), nothing());
    }

    #[test]
    fn parent_not_reported_is_left_as_netbox_has_it() {
        let current = device([nb_iface(1, "Ethernet1/1"), nb_child(2, "Ethernet1/1.100", "Ethernet1/1")]);
        assert_eq!(diff(&want([eth(), svi("Ethernet1/1.100")]), &current, false), nothing());
    }

    #[test]
    fn new_interface_carries_its_parent() {
        let (changes, _) = diff(&want([aggregate(), vlan()]), &device([nb_typed(1, "PO2", "lag")]), false);
        assert_eq!(changes.len(), 1, "{changes:?}");
        let create = &changes[0];
        assert_eq!(
            (create.action, create.key.as_str(), create.fields.get("parent")),
            (Action::Create, "HOUSING", Some(&json!("PO2")))
        );
    }

    #[test]
    fn pruned_children_are_deleted_before_their_parents() {
        let current = device([
            nb_typed(1, "AAA", "lag"),
            nb_child(2, "MMM", "AAA"),
            nb_child(3, "ZZZ", "MMM"),
            nb_iface(4, "Ethernet1/1"),
        ]);
        let (changes, _) = diff(&want([eth()]), &current, true);
        assert_eq!(
            actions_and_keys(&changes),
            [(Action::Delete, "ZZZ"), (Action::Delete, "MMM"), (Action::Delete, "AAA")]
        );
    }

    #[test]
    fn unmanaged_device_only_gets_its_serial_even_with_prune() {
        let current = NbDevice {
            serial: "OLD".to_owned(),
            ..device_with_ips(
                [nb_iface(1, "eth0")],
                [nb_ip(7, "192.0.2.2/24", None, Some("nexus01.lab01"), Some("eth0"))],
                Some("192.0.2.2/24"),
            )
        };
        assert_eq!(
            diff(&peer(Some("NEW")), &current, true),
            (
                vec![
                    change("serial", Action::Update, "nexus01.lab01")
                        .fields([("serial", json!("NEW"))])
                        .before([("serial", json!("OLD"))])
                        .id(65)
                ],
                vec![]
            )
        );
    }

    #[test]
    fn unmanaged_device_in_sync_gives_nothing() {
        let current = device_with_ips([nb_iface(1, "eth0")], [], Some("192.0.2.2/24"));
        assert_eq!(diff(&peer(Some("S1")), &current, true), nothing());
        assert_eq!(diff(&peer(None), &current, true), nothing());
    }

    #[test]
    fn ignored_interface_is_never_pruned_nor_its_addresses() {
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_iface(2, "modem")],
            [nb_ip(7, "192.0.2.9/24", None, Some("nexus01.lab01"), Some("modem"))],
            None,
        );
        let desired = DesiredDevice { unmanaged_interfaces: BTreeSet::from(["modem".to_owned()]), ..want([eth()]) };
        assert_eq!(diff(&desired, &current, true), nothing());
    }

    #[test]
    fn parent_of_a_kept_interface_is_kept_too() {
        // `Vlan9` carries the primary IP and is gone from the switch, like its parent.
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "OLD-LAG", "lag"), nb_child(3, "Vlan9", "OLD-LAG")],
            [nb_ip(7, "192.0.2.9/24", None, Some("nexus01.lab01"), Some("Vlan9"))],
            Some("192.0.2.9/24"),
        );
        let (changes, warnings) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            [
                "nexus01.lab01: Vlan9 carries the primary IP; interface left in place",
                "nexus01.lab01: no collected IP matches the inventory host; primary IP left as is",
                "nexus01.lab01: OLD-LAG is the parent of Vlan9, which stays; interface left in place",
            ]
        );
    }

    #[test]
    fn every_ancestor_of_a_kept_interface_is_kept() {
        let current = device_with_ips(
            [
                nb_iface(1, "Ethernet1/1"),
                nb_typed(2, "OLD-LAG", "lag"),
                nb_child(3, "OLD-VLAN", "OLD-LAG"),
                nb_child(4, "Tunnel9", "OLD-VLAN"),
            ],
            [nb_ip(7, "192.0.2.9/24", None, Some("nexus01.lab01"), Some("Tunnel9"))],
            Some("192.0.2.9/24"),
        );
        let (changes, warnings) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, []);
        assert_eq!(
            warnings[2..],
            [
                "nexus01.lab01: OLD-VLAN is the parent of Tunnel9, which stays; interface left in place",
                "nexus01.lab01: OLD-LAG is the parent of OLD-VLAN, which stays; interface left in place",
            ]
        );
    }

    #[test]
    fn parent_of_a_synced_child_that_reports_none_is_kept() {
        // The switch still has the sub-interface and tells no parent: NetBox keeps its own.
        let current = device([
            nb_iface(1, "Ethernet1/1"),
            nb_typed(2, "OLD-LAG", "lag"),
            nb_child(3, "Ethernet1/1.100", "OLD-LAG"),
        ]);
        assert_eq!(
            diff(&want([eth(), svi("Ethernet1/1.100")]), &current, true),
            (
                vec![],
                vec![
                    "nexus01.lab01: OLD-LAG is the parent of Ethernet1/1.100, which stays; \
                     interface left in place"
                        .to_owned()
                ]
            )
        );
    }

    #[test]
    fn old_parent_of_a_child_moved_by_the_run_is_pruned() {
        let current =
            device([nb_typed(1, "PO2", "lag"), nb_typed(2, "OLD-LAG", "lag"), nb_child(3, "HOUSING", "OLD-LAG")]);
        let (changes, warnings) = diff(&want([aggregate(), vlan()]), &current, true);
        assert_eq!(actions_and_keys(&changes), [(Action::Update, "HOUSING"), (Action::Delete, "OLD-LAG")]);
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn label_follows_the_device_when_it_reports_one() {
        let port = Interface { label: Some("HA".to_owned()), ..iface("a", Some("10gbase-x-sfpp")) };
        let (changes, _) = diff(&want([port.clone()]), &device([nb_iface(1, "a")]), false);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "a")
                .fields([("label", json!("HA"))])
                .before([("label", json!(""))])
                .id(1)]
        );
        let cleared = Interface { label: Some(String::new()), ..port };
        let current = device([NbInterface { label: "HA".to_owned(), ..nb_iface(1, "a") }]);
        let (changes, _) = diff(&want([cleared]), &current, false);
        let updated: Vec<_> = changes.iter().map(|c| c.fields.clone()).collect();
        assert_eq!(updated, [fields([("label", json!(""))])]);
    }

    #[test]
    fn label_not_reported_is_left_as_netbox_has_it() {
        let current = device([NbInterface { label: "rack 12".to_owned(), ..nb_iface(1, "Ethernet1/1") }]);
        assert_eq!(diff(&want([eth()]), &current, false), nothing());
    }

    // The tests below are not in the Python tests: each is written from `diff.py`,
    // to give a protection of the deletion path a test of its own.

    // `_wanted_fields`: an MTU the device does not report stays out of the wanted
    // fields, whatever NetBox holds.
    #[test]
    fn unreported_mtu_is_not_compared() {
        let port = Interface { mtu: None, ..eth() };
        let current = device([NbInterface { mtu: Some(9216), ..nb_iface(1, "Ethernet1/1") }]);
        assert_eq!(diff(&want([port]), &current, true), nothing());
    }

    // `_wanted_fields`: `lag` is wanted as soon as `lag_managed` is true, None
    // included, so a port the switch reports out of any LAG leaves its NetBox one.
    #[test]
    fn managed_lag_reported_empty_clears_the_netbox_one() {
        let current = device([NbInterface { lag: Some("Port-channel40".to_owned()), ..nb_iface(1, "Ethernet1/1") }]);
        let (changes, _) = diff(&want([eth()]), &current, false);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "Ethernet1/1")
                .fields([("lag", json!(null))])
                .before([("lag", json!("Port-channel40"))])
                .id(1)]
        );
    }

    // `_interface_changes`: the prune pass looks NetBox interfaces up by
    // `interface_key`, so an interface that only differs by case is neither
    // deleted nor created.
    #[test]
    fn case_only_difference_is_neither_a_delete_nor_a_create() {
        let lag = iface("port-channel10", Some("lag"));
        let (changes, _) = diff(&want([lag]), &device([nb_typed(9, "Port-channel10", "lag")]), true);
        let actions: Vec<Action> = changes.iter().map(|c| c.action).collect();
        assert_eq!(actions, [Action::Update]);
        assert_eq!(changes[0].id, Some(9));
    }

    // `_ip_changes`: the prune pass skips the address NetBox has as primary, even
    // when the run sets another primary IP.
    #[test]
    fn current_primary_ip_is_never_pruned_when_the_primary_moves() {
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1")],
            [
                nb_ip(5, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("Ethernet1/1")),
                nb_ip(6, "10.9.9.9/24", None, Some("nexus01.lab01"), Some("Ethernet1/1")),
            ],
            Some("192.0.2.239/24"),
        );
        let desired = want_ips([eth()], [ip("10.9.9.9/24", "Ethernet1/1", None)], Some("10.9.9.9/24"));
        let (changes, warnings) = diff(&desired, &current, true);
        assert_eq!(
            changes,
            [change("primary_ip", Action::Update, "10.9.9.9/24")
                .fields([("address", json!("10.9.9.9/24")), ("vrf", json!(null))])
                .before([("address", json!("192.0.2.239/24"))])
                .id(65)]
        );
        assert_eq!(warnings, Vec::<String>::new());
    }

    // `_keep_primary_interface`: the interface is only let go when this run
    // re-attaches the primary IP to another interface first.
    #[test]
    fn interface_the_primary_ip_leaves_in_this_run_is_pruned() {
        let current = device_with_ips(
            [nb_typed(1, "Vlan2800", "virtual"), nb_typed(2, "admin", "virtual")],
            [nb_ip(1116, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("admin"))],
            Some("192.0.2.239/24"),
        );
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", None)], Some("192.0.2.239/24"));
        let (changes, warnings) = diff(&desired, &current, true);
        assert_eq!(
            changes,
            [
                change("interface", Action::Delete, "admin").id(2),
                change("ip", Action::Update, "192.0.2.239/24")
                    .fields([("interface", json!("Vlan2800"))])
                    .before([("interface", json!("admin"))])
                    .id(1116),
            ]
        );
        assert_eq!(warnings, Vec::<String>::new());
    }

    // `_ip_changes`: an address held by another device or virtual machine is
    // never the object of an update, in the same VRF or in another one; the
    // device gets an IP object of its own.
    #[test]
    fn ip_held_by_another_device_or_vm_is_never_taken() {
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", None)], None);
        let on_device = nb_ip(81, "192.0.2.239/24", None, Some("nexus03.lab01"), Some("Vlan2800"));
        let on_vm = nb_ip(82, "192.0.2.239/24", Some("tenant"), Some("vm-web01"), Some("eth0"));
        let (changes, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "Vlan2800", "virtual")]),
            &by_host("192.0.2.239", [on_device, on_vm]),
            true,
            &BTreeSet::new(),
        );
        assert_eq!(
            changes,
            [change("ip", Action::Create, "192.0.2.239/24").fields([
                ("address", json!("192.0.2.239/24")),
                ("vrf", json!(null)),
                ("interface", json!("Vlan2800")),
            ])]
        );
        assert_eq!(warnings, ["nexus01.lab01: 192.0.2.239/24 (VRF global) also assigned to nexus03.lab01 Vlan2800"]);
    }

    // `_match_own_ips`: an address the device already holds in the wanted VRF is
    // the one paired, whatever its place in the NetBox list.
    #[test]
    fn own_ip_is_paired_in_its_vrf_before_any_other() {
        let in_a = nb_ip(10, "192.168.1.1/24", Some("a"), Some("nexus01.lab01"), Some("Vlan1"));
        let in_b = nb_ip(11, "192.168.1.1/24", Some("b"), Some("nexus01.lab01"), Some("Vlan1"));
        let desired = want_ips([svi("Vlan1")], [ip("192.168.1.1/24", "Vlan1", Some("b"))], None);
        let current = device_with_ips([nb_typed(1, "Vlan1", "virtual")], [in_a, in_b], None);
        let (changes, _) = diff(&desired, &current, true);
        assert_eq!(changes, [change("ip", Action::Delete, "192.168.1.1/24").id(10)]);
    }

    // `_keep_interfaces_with_ips`: with a source that tells no IP, any address
    // keeps its interface, an IPv6 one or one that is not the primary included.
    #[test]
    fn report_source_keeps_an_interface_carrying_any_ip() {
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "Loopback0", "virtual")],
            [nb_ip(7, "2001:db8::1/64", None, Some("nexus01.lab01"), Some("loopback0"))],
            None,
        );
        let desired = DesiredDevice { ips_managed: false, ..want([eth()]) };
        assert_eq!(
            diff(&desired, &current, true),
            (vec![], vec!["nexus01.lab01: Loopback0 carries IP addresses; interface left in place".to_owned()])
        );
    }
    // The four tests below pin fixes of defects found in the Python reference
    // while porting it; they have no counterpart in its test file.
    #[test]
    fn interface_carrying_an_ipv6_is_never_pruned() {
        // IPv6 is not collected: deleting the interface would cascade to an address
        // the switch was never asked about.
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "admin6", "virtual")],
            [nb_ip(6, "2001:db8::1/64", None, Some("nexus01.lab01"), Some("admin6"))],
            None,
        );
        let (changes, warnings) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, []);
        assert!(
            warnings.contains(&"nexus01.lab01: admin6 carries an IPv6 address; interface left in place".to_owned()),
            "{warnings:?}"
        );
    }

    #[test]
    fn every_interface_that_may_carry_the_primary_ip_is_kept() {
        // NetBox names the primary IP by its address: held in two VRFs on two
        // interfaces, either may be the primary one.
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "admin", "virtual"), nb_typed(3, "admin2", "virtual")],
            [
                nb_ip(5, "192.0.2.239/24", Some("management"), Some("nexus01.lab01"), Some("admin")),
                nb_ip(6, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("admin2")),
            ],
            Some("192.0.2.239/24"),
        );
        let (changes, warnings) = diff(&want([eth()]), &current, true);
        assert_eq!(changes, []);
        for interface in ["admin", "admin2"] {
            let warning = format!("nexus01.lab01: {interface} carries the primary IP; interface left in place");
            assert!(warnings.contains(&warning), "{interface} in {warnings:?}");
        }
    }

    #[test]
    fn unassigned_ip_of_another_vrf_is_not_adopted() {
        // The same host in another table is another object: it is left where it is.
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", Some("management"))], None);
        let loose = nb_ip(77, "192.0.2.239/24", None, None, None);
        let (changes, _) = diff_device(
            &desired,
            &device([nb_typed(1, "Vlan2800", "virtual")]),
            &by_host("192.0.2.239", [loose]),
            false,
            &BTreeSet::new(),
        );
        assert_eq!(
            changes,
            [change("ip", Action::Create, "192.0.2.239/24").fields([
                ("address", json!("192.0.2.239/24")),
                ("interface", json!("Vlan2800")),
                ("vrf", json!("management")),
            ])]
        );
    }

    #[test]
    fn ip_held_elsewhere_without_an_interface_names_its_holder_only() {
        let desired =
            want_ips([iface("mgmt0", Some("1000base-t"))], [ip("192.168.1.1/24", "mgmt0", Some("management"))], None);
        let other = nb_ip(80, "192.168.1.1/24", Some("management"), Some("nexus03.lab01"), None);
        let (_, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "mgmt0", "1000base-t")]),
            &by_host("192.168.1.1", [other]),
            false,
            &BTreeSet::new(),
        );
        assert_eq!(warnings, ["nexus01.lab01: 192.168.1.1/24 (VRF management) also assigned to nexus03.lab01"]);
    }

    // The tests below pin behaviours that mutation testing found unprotected.

    #[test]
    fn tagged_vlans_are_the_same_whatever_their_order() {
        // The tagged VLANs of an interface are a set: NetBox may list them in another order.
        let trunk = Interface {
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: Some(26), tagged_vlans: vec![2600, 2712] }),
            ..eth()
        };
        let current = device([NbInterface {
            mode: Some("tagged".to_owned()),
            untagged_vlan: Some(26),
            tagged_vlans: vec![2712, 2600],
            ..nb_iface(1, "Ethernet1/1")
        }]);
        assert_eq!(diff(&want([trunk]), &current, false), nothing());
    }

    #[test]
    fn update_of_the_interface_carrying_the_primary_ip_is_not_dropped() {
        // Only the deletion of that interface is held back: its other changes go through.
        let current = device_with_ips(
            [NbInterface { description: "Uplink".to_owned(), ..nb_iface(1, "Ethernet1/1") }],
            [nb_ip(5, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("Ethernet1/1"))],
            Some("192.0.2.239/24"),
        );
        let desired = want_ips([eth()], [ip("192.0.2.239/24", "Ethernet1/1", None)], Some("192.0.2.239/24"));
        let (changes, warnings) = diff(&desired, &current, true);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "Ethernet1/1")
                .fields([("description", json!(""))])
                .before([("description", json!("Uplink"))])
                .id(1)]
        );
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn ip_is_not_moved_when_its_interface_only_differs_by_case() {
        // NetBox holds `Port-channel10` where NX-OS says `port-channel10`: the
        // interface is renamed, and its address is already on it.
        let current = device_with_ips(
            [nb_typed(9, "Port-channel10", "lag")],
            [nb_ip(5, "10.9.9.9/24", None, Some("nexus01.lab01"), Some("Port-channel10"))],
            None,
        );
        let desired =
            want_ips([iface("port-channel10", Some("lag"))], [ip("10.9.9.9/24", "port-channel10", None)], None);
        let (changes, warnings) = diff(&desired, &current, true);
        assert_eq!(
            changes,
            [change("interface", Action::Update, "port-channel10")
                .fields([("name", json!("port-channel10"))])
                .before([("name", json!("Port-channel10"))])
                .id(9)]
        );
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn interface_of_the_primary_ip_is_kept_when_the_run_moves_another_ip_off_it() {
        // Only the move of the primary IP itself frees its interface: `admin` still
        // carries it once `10.9.9.9/24` has left for `Ethernet1/1`.
        let current = device_with_ips(
            [nb_iface(1, "Ethernet1/1"), nb_typed(2, "admin", "virtual")],
            [
                nb_ip(5, "192.0.2.239/24", None, Some("nexus01.lab01"), Some("admin")),
                nb_ip(6, "10.9.9.9/24", None, Some("nexus01.lab01"), Some("admin")),
            ],
            Some("192.0.2.239/24"),
        );
        let desired = want_ips([eth()], [ip("10.9.9.9/24", "Ethernet1/1", None)], None);
        let (changes, warnings) = diff(&desired, &current, true);
        assert_eq!(
            changes,
            [change("ip", Action::Update, "10.9.9.9/24")
                .fields([("interface", json!("Ethernet1/1"))])
                .before([("interface", json!("admin"))])
                .id(6)]
        );
        assert_eq!(
            warnings,
            [
                "nexus01.lab01: admin carries the primary IP; interface left in place",
                "nexus01.lab01: no collected IP matches the inventory host; primary IP left as is",
            ]
        );
    }

    #[test]
    fn primary_ip_created_by_the_run_is_set_as_primary() {
        // NetBox takes as primary an address the device holds, one this run creates included.
        let desired = want_ips([svi("Vlan2800")], [ip("192.0.2.239/24", "Vlan2800", None)], Some("192.0.2.239/24"));
        let (changes, warnings) = diff(&desired, &device([nb_typed(1, "Vlan2800", "virtual")]), false);
        assert_eq!(
            changes,
            [
                change("ip", Action::Create, "192.0.2.239/24").fields([
                    ("address", json!("192.0.2.239/24")),
                    ("interface", json!("Vlan2800")),
                    ("vrf", json!(null)),
                ]),
                change("primary_ip", Action::Update, "192.0.2.239/24")
                    .fields([("address", json!("192.0.2.239/24")), ("vrf", json!(null))])
                    .before([("address", json!(null))])
                    .id(65),
            ]
        );
        assert_eq!(warnings, Vec::<String>::new());
    }

    #[test]
    fn primary_ip_that_is_not_created_is_not_set_when_the_run_creates_another_ip() {
        // Another address created by the run does not make the device hold the
        // management one, which a unique table refuses.
        let desired = want_ips(
            [svi("Vlan2800")],
            [ip("192.0.2.239/24", "Vlan2800", None), ip("10.9.9.9/24", "Vlan2800", None)],
            Some("192.0.2.239/24"),
        );
        let other = nb_ip(81, "192.0.2.239/24", None, Some("nexus03.lab01"), Some("Vlan2800"));
        let (changes, warnings) = diff_device(
            &desired,
            &device([nb_typed(1, "Vlan2800", "virtual")]),
            &by_host("192.0.2.239", [other]),
            false,
            &tables([None]),
        );
        assert_eq!(
            changes,
            [change("ip", Action::Create, "10.9.9.9/24").fields([
                ("address", json!("10.9.9.9/24")),
                ("interface", json!("Vlan2800")),
                ("vrf", json!(null)),
            ])]
        );
        assert_eq!(
            warnings,
            [
                "nexus01.lab01: 192.0.2.239/24 (VRF global) also assigned to nexus03.lab01 Vlan2800; \
                 not created: the global table enforces unique addresses (ENFORCE_GLOBAL_UNIQUE)",
                "nexus01.lab01: primary IP 192.0.2.239/24 not set: the device does not hold it",
            ]
        );
    }
}
