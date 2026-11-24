//! Turn one collected target into the NetBox device(s) it describes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use super::inventory::{REPORT_TYPES, Source};
use super::model::{DeviceState, Interface, IpAddress, Neighbor};
use super::names::interface_key;

// `TenGigabitEthernet2/0/2` belongs to stack member 2.
static MEMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z-]+(\d+)/\d+/\d+$").expect("valid pattern"));

/// The stack seen on the switch does not match the virtual chassis in NetBox.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StackError {
    #[error("stack member(s) {0:?} have no vc_position in Netbox")]
    MembersWithoutPosition(Vec<u32>),
    #[error("the virtual chassis has no master in Netbox")]
    NoMaster,
    #[error("the Netbox master {0} has no vc_position")]
    MasterWithoutPosition(String),
    #[error("stack master not found among the members")]
    MasterNotFound,
    #[error("stack master is member {member} ({device}) on the switch but {netbox_master} in Netbox")]
    MasterMismatch { member: u32, device: String, netbox_master: String },
    #[error("{interface} belongs to unknown stack member {member}")]
    UnknownMember { interface: String, member: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredDevice {
    pub name: String,
    pub serial: Option<String>,
    /// Keyed by interface name.
    pub interfaces: BTreeMap<String, Interface>,
    pub ips: Vec<IpAddress>,
    pub neighbors: Vec<Neighbor>,
    pub primary_ip4: Option<String>,
    pub ips_managed: bool,
    /// False: the other member of a firewall cluster, which holds the same
    /// configuration as the entry: only its serial is synced, nothing is pruned.
    pub interfaces_managed: bool,
    /// interface_key of the interfaces left out of the sync: unknown, not absent,
    /// so neither they nor their addresses are pruned.
    pub unmanaged_interfaces: BTreeSet<String>,
}

impl DesiredDevice {
    /// A device with nothing collected yet and everything managed.
    pub fn new(name: &str, serial: Option<String>) -> Self {
        DesiredDevice {
            name: name.to_owned(),
            serial,
            interfaces: BTreeMap::new(),
            ips: Vec::new(),
            neighbors: Vec::new(),
            primary_ip4: None,
            ips_managed: true,
            interfaces_managed: true,
            unmanaged_interfaces: BTreeSet::new(),
        }
    }
}

/// The stack member number an interface name carries, None if it carries none.
pub fn member_position(interface: &str) -> Option<u32> {
    MEMBER.captures(interface)?.get(1)?.as_str().parse().ok()
}

/// Split the collected state into NetBox devices, the stack master first.
///
/// `members` maps each `vc_position` of the NetBox virtual chassis to its device
/// name, None for a source that is not a stack. `netbox_master` is the master
/// device of the NetBox virtual chassis: it must be the member the switch reports
/// as master, or the interfaces that carry no member number (SVIs, port-channels,
/// management IP) would move between devices.
pub fn desired_devices(
    source: &Source,
    state: &DeviceState,
    members: Option<&BTreeMap<u32, String>>,
    netbox_master: Option<&str>,
) -> Result<Vec<DesiredDevice>, StackError> {
    let primary = state
        .ips
        .iter()
        .find(|ip| ip.address.split('/').next() == Some(source.host.as_str()))
        .map(|ip| ip.address.clone());
    let Some(members) = members else {
        return Ok(single_device(source, state, primary));
    };
    // A configuration report gives no serials: the members are the stack numbers
    // its port names carry, and the master can only be taken from Netbox.
    let from_report = REPORT_TYPES.contains(&source.r#type.as_str()) && state.member_serials.is_empty();
    let mut serials: BTreeMap<u32, Option<String>> = if from_report {
        state.interfaces.keys().filter_map(|name| member_position(name)).map(|number| (number, None)).collect()
    } else {
        state.member_serials.iter().map(|(number, serial)| (*number, Some(serial.clone()))).collect()
    };
    let unknown: Vec<u32> = serials.keys().copied().filter(|number| !members.contains_key(number)).collect();
    if !unknown.is_empty() {
        return Err(StackError::MembersWithoutPosition(unknown));
    }
    let netbox_master = netbox_master.ok_or(StackError::NoMaster)?;
    let master = if from_report {
        let found = members.iter().find(|(_, name)| name.as_str() == netbox_master).map(|(number, _)| *number);
        let master = found.ok_or_else(|| StackError::MasterWithoutPosition(netbox_master.to_owned()))?;
        serials.entry(master).or_insert(None);
        master
    } else {
        let found = serials.iter().find(|(_, serial)| **serial == state.serial).map(|(number, _)| *number);
        let master = found.ok_or(StackError::MasterNotFound)?;
        let device = members.get(&master).map(String::as_str).unwrap_or_default();
        if device != netbox_master {
            return Err(StackError::MasterMismatch {
                member: master,
                device: device.to_owned(),
                netbox_master: netbox_master.to_owned(),
            });
        }
        master
    };
    let mut devices: BTreeMap<u32, DesiredDevice> = BTreeMap::new();
    for (number, serial) in serials {
        let name = members.get(&number).map(String::as_str).unwrap_or_default();
        let mut device = DesiredDevice::new(name, serial);
        device.primary_ip4 = if number == master { primary.clone() } else { None };
        device.ips_managed = state.ips_managed;
        devices.insert(number, device);
    }
    for (name, interface) in &state.interfaces {
        owner(&mut devices, master, name)?.interfaces.insert(name.clone(), interface.clone());
    }
    for ip in &state.ips {
        owner(&mut devices, master, &ip.interface)?.ips.push(ip.clone());
    }
    for neighbor in &state.neighbors {
        owner(&mut devices, master, &neighbor.local_interface)?.neighbors.push(neighbor.clone());
    }
    // The master goes first: its port-channels must exist before the other
    // members' interfaces point at them.
    let first = devices.remove(&master);
    Ok(first.into_iter().chain(devices.into_values()).collect())
}

/// The device of the stack an interface belongs to: the member its name carries,
/// the master when it carries none.
fn owner<'d>(
    devices: &'d mut BTreeMap<u32, DesiredDevice>,
    master: u32,
    interface: &str,
) -> Result<&'d mut DesiredDevice, StackError> {
    let member = member_position(interface).unwrap_or(master);
    devices.get_mut(&member).ok_or_else(|| StackError::UnknownMember { interface: interface.to_owned(), member })
}

/// A source that is not a stack: one device, plus the other members of a
/// firewall cluster.
fn single_device(source: &Source, state: &DeviceState, primary: Option<String>) -> Vec<DesiredDevice> {
    let mut serial = state.serial.clone();
    let mut peers = Vec::new();
    if !source.ha_peers.is_empty() {
        // The unit that answers changes with a failover: each serial goes to the
        // device its host name is mapped to, never to the one that answered.
        // A member the cluster does not list keeps the serial Netbox has.
        // Host names are matched without case, as the identity check does.
        let reported: BTreeMap<String, &String> =
            state.peer_serials.iter().map(|(host, value)| (host.to_lowercase(), value)).collect();
        let mut by_device: Vec<(&str, Option<String>)> = Vec::new();
        for (host, device) in &source.ha_peers {
            let peer_serial = reported.get(&host.to_lowercase()).map(|value| (*value).clone());
            match by_device.iter_mut().find(|(known, _)| *known == device.as_str()) {
                Some(entry) => entry.1 = peer_serial,
                None => by_device.push((device, peer_serial)),
            }
        }
        serial = None;
        for (device, peer_serial) in by_device {
            if device == source.name {
                serial = peer_serial;
            } else {
                peers.push(DesiredDevice { interfaces_managed: false, ..DesiredDevice::new(device, peer_serial) });
            }
        }
    }
    let synced: BTreeSet<String> = state.interfaces.keys().map(|name| interface_key(name)).collect();
    let entry = DesiredDevice {
        interfaces: state.interfaces.clone(),
        ips: state.ips.clone(),
        neighbors: state.neighbors.clone(),
        primary_ip4: primary,
        ips_managed: state.ips_managed,
        // An ignored name that collides with a synced interface (`dmz` beside
        // `DMZ`) shares its key: that key stays managed.
        unmanaged_interfaces: source
            .ignore_interfaces
            .iter()
            .map(|name| interface_key(name))
            .filter(|key| !synced.contains(key))
            .collect(),
        ..DesiredDevice::new(&source.name, serial)
    };
    let mut devices = vec![entry];
    devices.extend(peers);
    devices
}

#[cfg(test)]
mod tests {
    use super::super::inventory::{Kind, Secret, Wanted};
    use super::*;

    fn iface(name: &str) -> Interface {
        Interface {
            description: Some(String::new()),
            mtu: Some(1500),
            r#type: Some("1000base-t".to_owned()),
            ..Interface::new(name, true)
        }
    }

    fn interfaces<const N: usize>(names: [&str; N]) -> BTreeMap<String, Interface> {
        names.into_iter().map(|name| (name.to_owned(), iface(name))).collect()
    }

    fn switch(name: &str, host: &str, chassis: Option<&str>) -> Source {
        Source {
            virtual_chassis: chassis.map(str::to_owned),
            username: "user".to_owned(),
            password: Some(Wanted::Held(Secret::new("secret"))),
            ..Source::new(name, Kind::Switch, "ios", host)
        }
    }

    fn nipper() -> Source {
        Source {
            virtual_chassis: Some("fplab1-sw001".to_owned()),
            ..Source::new("fplab1-sw001", Kind::Switch, "nipper", "")
        }
    }

    fn firewall() -> Source {
        Source {
            username: "readonly".to_owned(),
            password: Some(Wanted::Held(Secret::new("secret"))),
            ..Source::new("fw01.dc1", Kind::Firewall, "fortios", "192.0.2.1")
        }
    }

    fn ip(address: &str, interface: &str) -> IpAddress {
        IpAddress { address: address.to_owned(), interface: interface.to_owned(), vrf: None }
    }

    fn neighbor(local: &str, device: &str, remote: &str, protocol: &str) -> Neighbor {
        Neighbor {
            local_interface: local.to_owned(),
            remote_device: device.to_owned(),
            remote_interface: Some(remote.to_owned()),
            protocol: protocol.to_owned(),
        }
    }

    fn serials(members: &[(u32, &str)]) -> BTreeMap<u32, String> {
        members.iter().map(|(number, value)| (*number, (*value).to_owned())).collect()
    }

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values.iter().map(|(first, second)| ((*first).to_owned(), (*second).to_owned())).collect()
    }

    fn keys(device: &DesiredDevice) -> Vec<&str> {
        device.interfaces.keys().map(String::as_str).collect()
    }

    fn two(devices: Vec<DesiredDevice>) -> (DesiredDevice, DesiredDevice) {
        let [first, second]: [DesiredDevice; 2] = devices.try_into().unwrap();
        (first, second)
    }

    fn one(devices: Vec<DesiredDevice>) -> DesiredDevice {
        let [only]: [DesiredDevice; 1] = devices.try_into().unwrap();
        only
    }

    #[test]
    fn member_position_reads_the_stack_member_of_a_port() {
        assert_eq!(member_position("TenGigabitEthernet2/0/2"), Some(2));
        assert_eq!(member_position("GigabitEthernet1/0/1"), Some(1));
        assert_eq!(member_position("Vlan2800"), None);
        assert_eq!(member_position("Ethernet1/1"), None);
    }

    #[test]
    fn single_device() {
        let state = DeviceState {
            serial: Some("FCW8657Y7S5".to_owned()),
            interfaces: interfaces(["Vlan2800"]),
            vlans: BTreeMap::from([(2800, "Admin".to_owned())]),
            ips: vec![ip("192.0.2.251/24", "Vlan2800")],
            member_serials: serials(&[(1, "FCW8657Y7S5")]),
            ..DeviceState::default()
        };
        let device =
            one(desired_devices(&switch("2960-admin.lab01", "192.0.2.251", None), &state, None, None).unwrap());
        assert_eq!(device.name, "2960-admin.lab01");
        assert_eq!(device.serial.as_deref(), Some("FCW8657Y7S5"));
        assert_eq!(device.primary_ip4.as_deref(), Some("192.0.2.251/24"));
        assert_eq!(keys(&device), ["Vlan2800"]);
        assert!(device.interfaces_managed);
        assert!(device.ips_managed);
        assert_eq!(device.unmanaged_interfaces, BTreeSet::new());
    }

    #[test]
    fn stack_split_by_member() {
        let state = DeviceState {
            serial: Some("SERIAL-1".to_owned()),
            interfaces: interfaces(["GigabitEthernet1/0/1", "TenGigabitEthernet2/0/2", "Vlan2800", "Port-channel1"]),
            ips: vec![ip("192.0.2.252/24", "Vlan2800")],
            neighbors: vec![neighbor("TenGigabitEthernet2/0/2", "nexus01.lab01", "Ethernet1/30", "cdp")],
            member_serials: serials(&[(1, "SERIAL-1"), (2, "SERIAL-2")]),
            ..DeviceState::default()
        };
        let members = serials(&[(1, "2960-stack01.lab01"), (2, "2960-stack02.lab01")]);
        let (first, second) = two(desired_devices(
            &switch("2960-stack.lab01", "192.0.2.252", Some("2960-stack")),
            &state,
            Some(&members),
            Some("2960-stack01.lab01"),
        )
        .unwrap());
        assert_eq!(
            (first.name.as_str(), first.serial.as_deref(), first.primary_ip4.as_deref()),
            ("2960-stack01.lab01", Some("SERIAL-1"), Some("192.0.2.252/24"))
        );
        assert_eq!(keys(&first), ["GigabitEthernet1/0/1", "Port-channel1", "Vlan2800"]);
        assert_eq!(first.ips, [ip("192.0.2.252/24", "Vlan2800")]);
        assert_eq!(
            (second.name.as_str(), second.serial.as_deref(), second.primary_ip4.as_deref()),
            ("2960-stack02.lab01", Some("SERIAL-2"), None)
        );
        assert_eq!(keys(&second), ["TenGigabitEthernet2/0/2"]);
        assert_eq!(second.neighbors.len(), 1);
    }

    #[test]
    fn stack_member_without_vc_position() {
        let state = DeviceState {
            serial: Some("SERIAL-1".to_owned()),
            member_serials: serials(&[(1, "SERIAL-1"), (3, "SERIAL-3")]),
            ..DeviceState::default()
        };
        let members = serials(&[(1, "2960-stack01.lab01"), (2, "2960-stack02.lab01")]);
        let failure = desired_devices(
            &switch("2960-stack.lab01", "192.0.2.252", Some("2960-stack")),
            &state,
            Some(&members),
            None,
        )
        .unwrap_err();
        assert_eq!(failure.to_string(), "stack member(s) [3] have no vc_position in Netbox");
    }

    fn two_member_state(master_serial: &str) -> DeviceState {
        DeviceState {
            serial: Some(master_serial.to_owned()),
            interfaces: interfaces(["Vlan2800", "Port-channel1"]),
            ips: vec![ip("192.0.2.252/24", "Vlan2800")],
            member_serials: serials(&[(1, "SERIAL-1"), (2, "SERIAL-2")]),
            ..DeviceState::default()
        }
    }

    fn members() -> BTreeMap<u32, String> {
        serials(&[(1, "2960-stack01.lab01"), (2, "2960-stack02.lab01")])
    }

    fn stack() -> Source {
        switch("2960-stack.lab01", "192.0.2.252", Some("2960-stack"))
    }

    // Member 2 became master on the switch, NetBox still says member 1: moving the
    // SVIs, port-channels and management IP to member 2 would lose them on member 1.
    #[test]
    fn master_failover_fails_instead_of_moving_interfaces() {
        let failure =
            desired_devices(&stack(), &two_member_state("SERIAL-2"), Some(&members()), Some("2960-stack01.lab01"))
                .unwrap_err();
        assert_eq!(
            failure.to_string(),
            "stack master is member 2 (2960-stack02.lab01) on the switch but 2960-stack01.lab01 in Netbox"
        );
    }

    #[test]
    fn virtual_chassis_without_master_fails() {
        let failure = desired_devices(&stack(), &two_member_state("SERIAL-1"), Some(&members()), None).unwrap_err();
        assert_eq!(failure.to_string(), "the virtual chassis has no master in Netbox");
    }

    #[test]
    fn master_comes_first() {
        let devices =
            desired_devices(&stack(), &two_member_state("SERIAL-2"), Some(&members()), Some("2960-stack02.lab01"))
                .unwrap();
        let names: Vec<&str> = devices.iter().map(|device| device.name.as_str()).collect();
        assert_eq!(names, ["2960-stack02.lab01", "2960-stack01.lab01"]);
        assert_eq!(keys(&devices[0]), ["Port-channel1", "Vlan2800"]);
    }

    /// A stack read from a report: no serials, members told by the port names only.
    fn report_state<const N: usize>(names: [&str; N]) -> DeviceState {
        DeviceState {
            interfaces: interfaces(names),
            neighbors: vec![neighbor("TenGigabitEthernet2/0/40", "lab1-pve01.prod", "enp130s0", "description")],
            ..DeviceState::default()
        }
    }

    fn report_members() -> BTreeMap<u32, String> {
        serials(&[(1, "fplab1-sw001-1"), (2, "fplab1-sw001-2")])
    }

    #[test]
    fn stack_without_serials_trusts_the_netbox_master() {
        let state = report_state([
            "GigabitEthernet0/0",
            "Port-channel40",
            "TenGigabitEthernet1/0/40",
            "TenGigabitEthernet2/0/40",
        ]);
        let (master, other) =
            two(desired_devices(&nipper(), &state, Some(&report_members()), Some("fplab1-sw001-1")).unwrap());
        assert_eq!((master.name.as_str(), master.serial.as_deref()), ("fplab1-sw001-1", None));
        assert_eq!(keys(&master), ["GigabitEthernet0/0", "Port-channel40", "TenGigabitEthernet1/0/40"]);
        assert_eq!((other.name.as_str(), other.serial.as_deref()), ("fplab1-sw001-2", None));
        assert_eq!(keys(&other), ["TenGigabitEthernet2/0/40"]);
        let locals: Vec<&str> = other.neighbors.iter().map(|neighbor| neighbor.local_interface.as_str()).collect();
        assert_eq!(locals, ["TenGigabitEthernet2/0/40"]);
    }

    #[test]
    fn stack_without_serials_needs_every_member_in_netbox() {
        let state = report_state(["TenGigabitEthernet1/0/40", "TenGigabitEthernet3/0/40"]);
        let failure = desired_devices(&nipper(), &state, Some(&report_members()), Some("fplab1-sw001-1")).unwrap_err();
        assert_eq!(failure.to_string(), "stack member(s) [3] have no vc_position in Netbox");
    }

    #[test]
    fn stack_without_serials_needs_a_positioned_master() {
        let state = report_state(["TenGigabitEthernet1/0/40"]);
        let members = serials(&[(1, "fplab1-sw001-1")]);
        let failure = desired_devices(&nipper(), &state, Some(&members), Some("fplab1-sw001-9")).unwrap_err();
        assert_eq!(failure.to_string(), "the Netbox master fplab1-sw001-9 has no vc_position");
    }

    // Not in the Python tests: read from `stack.py`, the master of a report stack is
    // a member even when no port name carries its number.
    #[test]
    fn stack_without_serials_keeps_a_master_no_port_names() {
        let state =
            DeviceState { interfaces: interfaces(["TenGigabitEthernet2/0/40", "Vlan18"]), ..DeviceState::default() };
        let (master, other) =
            two(desired_devices(&nipper(), &state, Some(&report_members()), Some("fplab1-sw001-1")).unwrap());
        assert_eq!((master.name.as_str(), keys(&master)), ("fplab1-sw001-1", vec!["Vlan18"]));
        assert_eq!((other.name.as_str(), keys(&other)), ("fplab1-sw001-2", vec!["TenGigabitEthernet2/0/40"]));
    }

    // Over SSH a stack reports its member serials: none means a broken collection,
    // not a report to split by port names.
    #[test]
    fn ssh_stack_without_serials_still_fails() {
        let state = report_state(["TenGigabitEthernet1/0/40", "TenGigabitEthernet2/0/40"]);
        let failure = desired_devices(&stack(), &state, Some(&members()), Some("2960-stack01.lab01")).unwrap_err();
        assert_eq!(failure.to_string(), "stack master not found among the members");
    }

    // Not in the Python tests: read from `stack.py`, a port of a member the switch
    // does not list stops the run.
    #[test]
    fn port_of_a_member_the_switch_does_not_list_fails() {
        let state = DeviceState { interfaces: interfaces(["GigabitEthernet3/0/1"]), ..two_member_state("SERIAL-1") };
        let failure = desired_devices(&stack(), &state, Some(&members()), Some("2960-stack01.lab01")).unwrap_err();
        assert_eq!(failure.to_string(), "GigabitEthernet3/0/1 belongs to unknown stack member 3");
    }

    fn cluster_state(answering_serial: &str) -> DeviceState {
        DeviceState {
            serial: Some(answering_serial.to_owned()),
            interfaces: interfaces(["HOUSING"]),
            vlans: BTreeMap::from([(12, "HOUSING".to_owned())]),
            ips: vec![ip("192.0.2.1/24", "HOUSING")],
            peer_serials: pairs(&[("FW-A", "SERIAL-A"), ("FW-B", "SERIAL-B")]).into_iter().collect(),
            ..DeviceState::default()
        }
    }

    fn cluster() -> Source {
        Source { ha_peers: pairs(&[("FW-A", "fw01.dc1"), ("FW-B", "fw02.dc1")]), ..firewall() }
    }

    #[test]
    fn cluster_keeps_everything_on_the_entry_whichever_unit_answers() {
        for answering_serial in ["SERIAL-A", "SERIAL-B"] {
            let (entry, peer) = two(desired_devices(&cluster(), &cluster_state(answering_serial), None, None).unwrap());
            assert_eq!(
                (entry.name.as_str(), entry.serial.as_deref(), entry.interfaces_managed),
                ("fw01.dc1", Some("SERIAL-A"), true),
                "{answering_serial}"
            );
            assert_eq!(keys(&entry), ["HOUSING"]);
            assert_eq!(entry.ips, [ip("192.0.2.1/24", "HOUSING")]);
            assert_eq!(entry.primary_ip4.as_deref(), Some("192.0.2.1/24"));
            assert_eq!(
                (peer.name.as_str(), peer.serial.as_deref(), peer.interfaces_managed),
                ("fw02.dc1", Some("SERIAL-B"), false),
                "{answering_serial}"
            );
            assert_eq!((peer.interfaces, peer.ips, peer.primary_ip4), (BTreeMap::new(), vec![], None));
        }
    }

    #[test]
    fn cluster_member_that_does_not_answer_keeps_its_serial() {
        let mut state = cluster_state("SERIAL-A");
        state.peer_serials = BTreeMap::from([("FW-A".to_owned(), "SERIAL-A".to_owned())]);
        let (_, peer) = two(desired_devices(&cluster(), &state, None, None).unwrap());
        assert_eq!((peer.name.as_str(), peer.serial.as_deref()), ("fw02.dc1", None));
    }

    #[test]
    fn standalone_firewall_takes_the_serial_of_the_unit() {
        let device = one(desired_devices(&firewall(), &cluster_state("SERIAL-A"), None, None).unwrap());
        assert_eq!((device.name.as_str(), device.serial.as_deref()), ("fw01.dc1", Some("SERIAL-A")));
    }

    #[test]
    fn cluster_host_names_are_matched_without_case() {
        let lower = Source { ha_peers: pairs(&[("fw-a", "fw01.dc1"), ("fw-b", "fw02.dc1")]), ..firewall() };
        let (entry, peer) = two(desired_devices(&lower, &cluster_state("SERIAL-A"), None, None).unwrap());
        assert_eq!((entry.serial.as_deref(), peer.serial.as_deref()), (Some("SERIAL-A"), Some("SERIAL-B")));
    }

    // Not in the Python tests: read from `stack.py`, the entry comes first and the
    // other members follow in the order `ha_peers` lists them.
    #[test]
    fn cluster_entry_comes_first_then_the_peers_in_file_order() {
        let source = Source {
            ha_peers: pairs(&[("FW-C", "fw03.dc1"), ("FW-B", "fw02.dc1"), ("FW-A", "fw01.dc1")]),
            ..firewall()
        };
        let devices = desired_devices(&source, &cluster_state("SERIAL-B"), None, None).unwrap();
        let found: Vec<(&str, Option<&str>)> =
            devices.iter().map(|device| (device.name.as_str(), device.serial.as_deref())).collect();
        assert_eq!(found, [("fw01.dc1", Some("SERIAL-A")), ("fw03.dc1", None), ("fw02.dc1", Some("SERIAL-B"))]);
    }

    #[test]
    fn ignored_interfaces_are_carried_to_the_diff() {
        let ignoring = Source { ignore_interfaces: vec!["Modem".to_owned()], ..firewall() };
        let device = one(desired_devices(&ignoring, &cluster_state("SERIAL-A"), None, None).unwrap());
        assert_eq!(device.unmanaged_interfaces, BTreeSet::from(["modem".to_owned()]));
    }

    // `housing` is ignored because it collides with `HOUSING`, which is still synced.
    #[test]
    fn ignored_name_does_not_shield_the_synced_interface_of_the_same_key() {
        let ignoring = Source { ignore_interfaces: vec!["housing".to_owned(), "modem".to_owned()], ..firewall() };
        let device = one(desired_devices(&ignoring, &cluster_state("SERIAL-A"), None, None).unwrap());
        assert_eq!(device.unmanaged_interfaces, BTreeSet::from(["modem".to_owned()]));
    }
}
