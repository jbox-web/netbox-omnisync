//! Neighbours told by port descriptions, for switches without LLDP or CDP data.
//!
//! A provider-managed switch is only known through its configuration report: the
//! port descriptions written by its operator are the one source of what is plugged
//! in. They are free text, so the host part is matched by a pattern of the
//! inventory (named groups `host` and optional `port`); a port the description does
//! not name stays unresolved and gives no cable.
//!
//! The same pattern may read the VLANs of a port, in an optional group `vlans`:
//! a report does not list the VLANs a trunk allows.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

use regex::{Captures, Regex};

use super::dot1q::{ALL_VLANS, VlanListError, expand_vlan_list, vlan_list};
use super::model::{Interface, Mode, Neighbor};
use super::names::interface_key;

/// Remote port of a link to a server's out-of-band management (iLO, iDRAC): the
/// cable resolver picks the device's only management interface, whatever its name.
pub const MANAGEMENT_PORT: &str = "<management>";
pub const PROTOCOL: &str = "description";

// Anchored: the port word must start with the management word.
static MANAGEMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(?:i?drac|ilo)\b").expect("valid pattern"));
// Without a port, a management word glued to the host names its iLO or iDRAC
// (`DRAC-lab1-esx01`, `IDRAC ESX06`); elsewhere it is unrelated text (a VLAN name).
static MANAGEMENT_BEFORE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:i?drac|ilo)[\s_-]*$").expect("valid pattern"));
// After the host, a domain the pattern left out may come first (`lab1-pve01.prod-ILO`).
static MANAGEMENT_AFTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:\.[a-z0-9-]+)*[\s_-]*(?:i?drac|ilo)\b").expect("valid pattern"));
// Interfaces no cable can end on, by lower-cased name prefix.
const LOGICAL: [&str; 7] = ["port-channel", "vlan", "loopback", "tunnel", "nve", "null", "bdi"];

fn is_logical(name: &str) -> bool {
    let key = interface_key(name);
    LOGICAL.iter().any(|prefix| key.starts_with(prefix))
}

fn remote_port(captures: &Captures<'_>, description: &str) -> Option<String> {
    // The `port` group is optional in the pattern itself.
    if let Some(port) = captures.name("port").map(|group| group.as_str()).filter(|port| !port.is_empty()) {
        return Some(if MANAGEMENT.is_match(port) { MANAGEMENT_PORT.to_owned() } else { port.to_lowercase() });
    }
    let host = captures.name("host")?;
    let whole = captures.get(0)?;
    let (before, after) = (&description[..host.start()], &description[whole.end()..]);
    (MANAGEMENT_BEFORE.is_match(before) || MANAGEMENT_AFTER.is_match(after)).then(|| MANAGEMENT_PORT.to_owned())
}

/// One neighbour per enabled physical port whose description names a host.
///
/// Logical interfaces are left out: a cable only ends on a physical port, and a
/// port-channel's description names the members' links, which the physical ports
/// already carry. On a switch also read over LLDP and CDP, the description only
/// completes them: ports in `announced` (a protocol neighbour already) are left
/// out, and so are ports whose link is down, whose description is most often a
/// leftover of a former server. A match whose `host` group is absent or empty
/// names no host and gives no neighbour.
pub fn neighbors_from_descriptions(
    interfaces: &BTreeMap<String, Interface>,
    pattern: &Regex,
    suffix: &str,
    announced: &BTreeSet<String>,
) -> Vec<Neighbor> {
    let silent: BTreeSet<String> = announced.iter().map(|name| interface_key(name)).collect();
    let mut neighbors = Vec::new();
    for (name, interface) in interfaces {
        let Some(description) = interface.description.as_deref() else {
            continue;
        };
        if !interface.enabled || is_logical(name) {
            continue;
        }
        if silent.contains(&interface_key(name)) || interface.link_up == Some(false) {
            continue;
        }
        let Some(captures) = pattern.captures(description) else {
            continue;
        };
        let Some(host) = captures.name("host").map(|group| group.as_str()).filter(|host| !host.is_empty()) else {
            continue;
        };
        neighbors.push(Neighbor {
            local_interface: name.clone(),
            remote_device: format!("{}{suffix}", host.to_lowercase()),
            remote_interface: remote_port(&captures, description),
            protocol: PROTOCOL.to_owned(),
        });
    }
    neighbors
}

/// The VLANs a description gives a port.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Described {
    /// `all`, as `switchport trunk allowed vlan all`.
    All,
    Listed(BTreeSet<u16>),
}

impl fmt::Display for Described {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Described::All => formatter.write_str("all"),
            Described::Listed(vids) => formatter.write_str(&vlan_list(vids)),
        }
    }
}

/// The VLANs the description of `interface` gives, in the `vlans` group of the
/// pattern and the syntax of a switch (`10-12,25`, or `all`); None when it
/// gives none: no description, no match, a pattern without the group, an
/// empty group.
fn described_vlans(interface: &Interface, pattern: &Regex) -> Option<Result<Described, VlanListError>> {
    let captures = pattern.captures(interface.description.as_deref()?)?;
    let list = captures.name("vlans").map(|group| group.as_str()).filter(|list| !list.is_empty())?;
    if list.eq_ignore_ascii_case("all") {
        return Some(Ok(Described::All));
    }
    Some(match expand_vlan_list(list) {
        // Every VLAN, as a switch whose trunk allows them all lists them.
        Ok(vids) if ALL_VLANS.into_iter().all(|vid| vids.contains(&vid)) => Ok(Described::All),
        // No VLAN at all, without the `none` of a switch: commas alone, a mistake.
        Ok(vids) if vids.is_empty() && !list.eq_ignore_ascii_case("none") => Err(VlanListError(list.to_owned())),
        read => read.map(Described::Listed),
    })
}

fn unreadable(name: &str, error: &VlanListError, kept: &str) -> String {
    format!("{name}: the VLANs of its description cannot be read ({error}); {kept}")
}

/// Completes the 802.1Q of the ports of a switch known by a configuration
/// report with the VLANs their descriptions give; gives the warnings, each
/// starting with its port.
///
/// A report gives the mode of a port and its access VLAN, never the VLANs a
/// trunk allows: the description of the trunk is their one source, read as
/// the list of `switchport trunk allowed vlan`. The native VLAN is not known,
/// so the whole list is tagged, and `all` is a trunk that carries every VLAN.
/// A trunk whose description gives nothing, or something that is not a list,
/// keeps the tagged VLANs NetBox has. On an access port the report is
/// believed, and a description that says otherwise is told.
///
/// Every interface the report gives a mode is read, a port-channel as well,
/// and whatever keeps its description from telling a cable (a port that is
/// disabled, without link, or whose neighbour is announced).
pub fn vlans_from_descriptions(interfaces: &mut BTreeMap<String, Interface>, pattern: &Regex) -> Vec<String> {
    let mut warnings = Vec::new();
    for (name, interface) in interfaces.iter_mut().filter(|(_, interface)| interface.dot1q_managed) {
        let Some(read) = described_vlans(interface, pattern) else {
            continue;
        };
        let Some(dot1q) = interface.dot1q.as_mut() else {
            continue;
        };
        match (dot1q.mode, read) {
            (Mode::Access, Err(error)) => warnings.push(unreadable(name, &error, "the VLAN of the report is kept")),
            (_, Err(error)) => {
                warnings.push(unreadable(name, &error, "the tagged VLANs NetBox has are left as they are"));
            }
            (Mode::Access, Ok(described)) => {
                let differs = |vlan: &u16| described != Described::Listed(BTreeSet::from([*vlan]));
                if let Some(vlan) = dot1q.untagged_vlan.filter(differs) {
                    warnings.push(format!(
                        "{name}: its description says VLAN {described}, the report says it is an access port of VLAN \
                         {vlan}; the report is believed"
                    ));
                }
            }
            (_, Ok(described)) => {
                (dot1q.mode, dot1q.tagged_vlans) = match described {
                    Described::All => (Mode::TaggedAll, Vec::new()),
                    Described::Listed(vids) => (Mode::Tagged, vids.into_iter().collect()),
                };
                interface.tagged_vlans_managed = true;
            }
        }
    }
    warnings
}

/// The warnings of the ports whose description gives other VLANs than their
/// configuration, on a switch whose configuration was read: it is believed,
/// and nothing is changed.
///
/// The list of a trunk is compared with its tagged VLANs, with or without
/// its native one (the allowed list of a switch may hold it). A trunk that
/// carries every VLAN carries those of its description. Only the VLANs the
/// switch defines (`defined`) are compared: the collection keeps no other, so
/// a description that copies an allowed list naming a VLAN that is not
/// created says nothing else than the configuration.
pub fn vlans_against_descriptions(
    interfaces: &BTreeMap<String, Interface>,
    pattern: &Regex,
    defined: &BTreeSet<u16>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for (name, interface) in interfaces {
        let (Some(dot1q), Some(read)) = (interface.dot1q.as_ref(), described_vlans(interface, pattern)) else {
            continue;
        };
        if dot1q.mode == Mode::TaggedAll {
            continue;
        }
        let described = match read {
            // The collection kept the VLANs the switch defines, of its access VLAN
            // as of the list of a trunk: the description is compared on those.
            Ok(Described::Listed(vids)) => Described::Listed(vids.intersection(defined).copied().collect()),
            Ok(described) => described,
            Err(error) => {
                warnings.push(unreadable(name, &error, "the configuration is believed"));
                continue;
            }
        };
        let configured: BTreeSet<u16> = match dot1q.mode {
            Mode::Access => dot1q.untagged_vlan.into_iter().collect(),
            _ => dot1q.tagged_vlans.iter().copied().collect(),
        };
        let with_native: BTreeSet<u16> = configured.iter().copied().chain(dot1q.untagged_vlan).collect();
        let same = described == Described::Listed(configured.clone())
            || (dot1q.mode == Mode::Tagged && described == Described::Listed(with_native));
        if !same {
            warnings.push(format!(
                "{name}: its description says VLAN {described}, its configuration says {}; the configuration is \
                 believed",
                vlan_list(&configured)
            ));
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::super::model::Dot1q;
    use super::*;

    fn pattern() -> Regex {
        Regex::new(concat!(
            r"(?i)\b(?P<host>lab[12]-(?:pve|esx|db|pre)\d+|lab[12]-c190-\d+)",
            r"(?:\.prod)?(?:[\s_-]+(?P<port>[a-z0-9]+))?",
        ))
        .unwrap()
    }

    fn port(name: &str, description: &str) -> Interface {
        Interface { description: Some(description.to_owned()), dot1q_managed: false, ..Interface::new(name, true) }
    }

    fn linked(name: &str, description: &str, link_up: bool) -> Interface {
        Interface { description: Some(description.to_owned()), link_up: Some(link_up), ..Interface::new(name, true) }
    }

    fn by_name<const N: usize>(interfaces: [Interface; N]) -> BTreeMap<String, Interface> {
        interfaces.into_iter().map(|interface| (interface.name.clone(), interface)).collect()
    }

    fn neighbors<const N: usize>(interfaces: [Interface; N]) -> Vec<Neighbor> {
        neighbors_from_descriptions(&by_name(interfaces), &pattern(), ".prod", &BTreeSet::new())
    }

    fn neighbor(local: &str, device: &str, remote: Option<&str>) -> Neighbor {
        Neighbor {
            local_interface: local.to_owned(),
            remote_device: device.to_owned(),
            remote_interface: remote.map(str::to_owned),
            protocol: "description".to_owned(),
        }
    }

    #[test]
    fn the_management_port_and_the_protocol_keep_their_values() {
        assert_eq!(MANAGEMENT_PORT, "<management>");
        assert_eq!(PROTOCOL, "description");
    }

    #[test]
    fn host_and_port() {
        assert_eq!(
            neighbors([port("Te1/0/40", "N:lab1-pve01 enp129s0 10G Vlan 10-11-12")]),
            [neighbor("Te1/0/40", "lab1-pve01.prod", Some("enp129s0"))]
        );
    }

    #[test]
    fn port_glued_with_a_dash() {
        assert_eq!(
            neighbors([port("Gi1/0/18", "VMWARE-lab2-esx03-vmnic2")]),
            [neighbor("Gi1/0/18", "lab2-esx03.prod", Some("vmnic2"))]
        );
    }

    #[test]
    fn upper_case_description() {
        assert_eq!(
            neighbors([port("Gi1/0/17", "LAB1-DB05-ENO1")]),
            [neighbor("Gi1/0/17", "lab1-db05.prod", Some("eno1"))]
        );
    }

    #[test]
    fn management_port_from_the_port_word() {
        assert_eq!(
            neighbors([port("Gi1/0/27", "N:lab1-pve01.prod-ILO Vlan 18"), port("Gi2/0/36", "LAB1-DB05 - DRAC")]),
            [
                neighbor("Gi1/0/27", "lab1-pve01.prod", Some("<management>")),
                neighbor("Gi2/0/36", "lab1-db05.prod", Some("<management>")),
            ]
        );
    }

    #[test]
    fn management_port_named_before_the_host() {
        assert_eq!(
            neighbors([port("Gi1/0/34", "[No Monitor] DRAC-LAB1-ESX01")]),
            [neighbor("Gi1/0/34", "lab1-esx01.prod", Some("<management>"))]
        );
    }

    #[test]
    fn host_without_port() {
        assert_eq!(neighbors([port("Te1/0/39", "N:LAB2-DB06")]), [neighbor("Te1/0/39", "lab2-db06.prod", None)]);
    }

    #[test]
    fn ignored_ports() {
        let disabled = Interface { enabled: false, ..port("Gi1/0/16", "LAB1-DB06") };
        assert_eq!(
            neighbors([
                disabled,
                port("Port-channel40", "N:lab1-pve01 enp129s0 + enp130s0 10G Vlan 10-11-12"),
                port("Gi1/0/6", "SEELU-FWL01 INTERFACE WAN1(OUTSIDE)"),
                port("Gi1/0/10", ""),
            ]),
            []
        );
    }

    #[test]
    fn ports_with_a_protocol_neighbour_or_a_down_link_are_left_out() {
        let up = linked("Eth1/7", "drac-lab1-pve02", true);
        let down = linked("Eth1/8", "drac-lab1-pve03", false);
        let announced = linked("Eth1/9", "lab1-pve01 eno1", true);
        let interfaces = by_name([up, down, announced]);
        assert_eq!(
            neighbors_from_descriptions(&interfaces, &pattern(), ".prod", &BTreeSet::from(["Eth1/9".to_owned()])),
            [neighbor("Eth1/7", "lab1-pve02.prod", Some("<management>"))]
        );
    }

    #[test]
    fn pattern_without_port_group() {
        let pattern = Regex::new(r"(?i)\b(?P<host>lab1-pve\d+)").unwrap();
        let interfaces = by_name([port("Te1/0/40", "N:lab1-pve01 enp129s0")]);
        assert_eq!(
            neighbors_from_descriptions(&interfaces, &pattern, ".prod", &BTreeSet::new()),
            [neighbor("Te1/0/40", "lab1-pve01.prod", None)]
        );
    }

    #[test]
    fn management_word_elsewhere_in_the_description_is_not_a_management_link() {
        assert_eq!(
            neighbors([
                port("Gi1/0/26", "N:lab1-pve01 eno1 1G Vlan ADMIN/ILO"),
                port("Te1/0/39", "N:lab2-db06 (ADMIN/ILO/HOUSING)"),
            ]),
            [neighbor("Gi1/0/26", "lab1-pve01.prod", Some("eno1")), neighbor("Te1/0/39", "lab2-db06.prod", None)]
        );
    }

    #[test]
    fn unmanaged_description_gives_no_neighbour() {
        let svi =
            Interface { r#type: Some("virtual".to_owned()), dot1q_managed: false, ..Interface::new("Vlan952", true) };
        assert_eq!(neighbors([svi]), []);
    }

    // A cable only ends on a physical port, whatever the description of an SVI says.
    #[test]
    fn logical_interfaces_give_no_neighbour() {
        assert_eq!(
            neighbors([
                port("Vlan18", "lab1-esx01 ILO"),
                port("Loopback0", "lab1-pve01 eno1"),
                port("Tunnel1", "lab1-pve01 eno1"),
                port("nve1", "lab1-pve01 eno1"),
                port("port-channel40", "lab1-pve01 eno1"),
            ]),
            []
        );
    }

    #[test]
    fn host_group_left_out_of_the_match_gives_no_neighbour() {
        let optional = Regex::new(r"(?i)(?P<host>lab1-esx\d+)?[-_ ]ilo").unwrap();
        let interfaces = by_name([port("Gi1/0/1", "spare ILO")]);
        assert_eq!(neighbors_from_descriptions(&interfaces, &optional, ".prod", &BTreeSet::new()), []);
    }

    #[test]
    fn empty_host_gives_no_neighbour() {
        let loose = Regex::new(r"(?P<host>[a-z0-9-]*)").unwrap();
        let interfaces = by_name([port("Gi1/0/2", "!!")]);
        assert_eq!(neighbors_from_descriptions(&interfaces, &loose, ".prod", &BTreeSet::new()), []);
    }

    #[test]
    fn announced_ports_compared_case_insensitively() {
        let interfaces = by_name([port("Ethernet1/9", "lab1-pve01 eno1")]);
        let found =
            neighbors_from_descriptions(&interfaces, &pattern(), ".prod", &BTreeSet::from(["ethernet1/9".to_owned()]));
        assert_eq!(found, []);
    }

    // The VLANs of a port.

    /// Reads the host as the other tests do, and the VLANs of a `V:` pair,
    /// with or without a host before it.
    fn vlan_pattern() -> Regex {
        Regex::new(
            r"(?i)(?:\b(?P<host>lab[12]-(?:pve|esx|pre)\d+)\S*.*?)?\bV:(?P<vlans>\S+)|\b(?P<host2>lab[12]-pve\d+)",
        )
        .unwrap()
    }

    /// A trunk as a configuration report gives it: its mode, neither its native
    /// VLAN nor the VLANs it allows.
    fn report_trunk(name: &str, description: &str) -> Interface {
        Interface {
            description: Some(description.to_owned()),
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: Vec::new() }),
            untagged_vlan_managed: false,
            tagged_vlans_managed: false,
            ..Interface::new(name, true)
        }
    }

    /// An access port as a configuration report gives it.
    fn report_access(name: &str, description: &str, vlan: u16) -> Interface {
        Interface {
            description: Some(description.to_owned()),
            dot1q: Some(Dot1q { mode: Mode::Access, untagged_vlan: Some(vlan), tagged_vlans: Vec::new() }),
            ..Interface::new(name, true)
        }
    }

    fn completed<const N: usize>(interfaces: [Interface; N]) -> (BTreeMap<String, Interface>, Vec<String>) {
        let mut interfaces = by_name(interfaces);
        let warnings = vlans_from_descriptions(&mut interfaces, &vlan_pattern());
        (interfaces, warnings)
    }

    fn tagged(interface: &Interface) -> Option<&[u16]> {
        interface.tagged_vlans_managed.then(|| interface.dot1q.as_ref().expect("a mode").tagged_vlans.as_slice())
    }

    #[test]
    fn the_vlans_of_a_trunk_come_from_its_description() {
        // `TenGigabitEthernet1/1/8 | Yes | description CTA/CTB/LE-143095 V:4-6,10-12,14-19,952 | 2 | Trunk`
        // in fplab1-sw001.html: no host, and the list of `switchport trunk allowed vlan`.
        let (interfaces, warnings) =
            completed([report_trunk("TenGigabitEthernet1/1/8", "description CTA/CTB/LE-143095 V:4-6,10-12,14-19,952")]);
        let port = &interfaces["TenGigabitEthernet1/1/8"];
        assert_eq!(tagged(port), Some(&[4, 5, 6, 10, 11, 12, 14, 15, 16, 17, 18, 19, 952][..]));
        // The native VLAN of a trunk is in no column of a report: it stays unknown.
        assert!(!port.untagged_vlan_managed);
        assert_eq!(port.dot1q.as_ref().map(|dot1q| (dot1q.mode, dot1q.untagged_vlan)), Some((Mode::Tagged, None)));
        assert_eq!(warnings, [] as [&str; 0]);
    }

    #[test]
    fn a_vlan_list_in_the_former_form_is_not_a_list() {
        // `TenGigabitEthernet1/0/40 | Yes | N:lab1-pve01 enp129s0 10G Vlan 10-11-12 | 2 | Trunk`: the dashes
        // separate three VLANs, which is not the syntax of a list. The pattern that only knows `V:` reads none.
        let description = "N:lab1-pve01 enp129s0 10G Vlan 10-11-12";
        let (interfaces, warnings) = completed([report_trunk("TenGigabitEthernet1/0/40", description)]);
        assert_eq!(tagged(&interfaces["TenGigabitEthernet1/0/40"]), None);
        assert_eq!(warnings, [] as [&str; 0]);
        // A pattern that takes it for one does not get VLANs 10 to 12 out of it.
        let loose = Regex::new(r"(?i)\b(?P<host>lab1-pve\d+).*\bVlan (?P<vlans>\S+)").unwrap();
        let mut interfaces = by_name([report_trunk("TenGigabitEthernet1/0/40", description)]);
        let warnings = vlans_from_descriptions(&mut interfaces, &loose);
        assert_eq!(tagged(&interfaces["TenGigabitEthernet1/0/40"]), None);
        assert_eq!(
            warnings,
            ["TenGigabitEthernet1/0/40: the VLANs of its description cannot be read (invalid VLAN list item \
              '10-11-12'); the tagged VLANs NetBox has are left as they are"]
        );
    }

    #[test]
    fn an_unreadable_vlan_list_is_a_warning_and_the_port_keeps_its_vlans() {
        let (interfaces, warnings) = completed([
            report_trunk("Te1/0/1", "lab1-esx01.prod/vmnic0 V:10-x"),
            report_access("Gi1/0/2", "lab1-pre01.prod/eth0 V:1O", 12),
        ]);
        assert_eq!(tagged(&interfaces["Te1/0/1"]), None);
        // The report gave the VLAN of the access port: it is still written.
        assert_eq!(interfaces["Gi1/0/2"], report_access("Gi1/0/2", "lab1-pre01.prod/eth0 V:1O", 12));
        assert_eq!(
            warnings,
            [
                "Gi1/0/2: the VLANs of its description cannot be read (invalid VLAN list item '1O'); the VLAN of \
                 the report is kept",
                "Te1/0/1: the VLANs of its description cannot be read (invalid VLAN list item '10-x'); the tagged \
                 VLANs NetBox has are left as they are",
            ]
        );
    }

    #[test]
    fn a_trunk_without_vlans_in_its_description_keeps_the_tagged_vlans_netbox_has() {
        // `GigabitEthernet1/0/18 | Yes | N:lab1-esx03 vmnic2 1G | 2 | Trunk`, and a trunk without description.
        let described = report_trunk("GigabitEthernet1/0/18", "N:lab1-esx03 vmnic2 1G");
        let blank = report_trunk("GigabitEthernet1/0/19", "");
        let (interfaces, warnings) = completed([described.clone(), blank.clone()]);
        assert_eq!(interfaces, by_name([described, blank]));
        assert_eq!(warnings, [] as [&str; 0]);
    }

    #[test]
    fn the_vlans_of_a_port_channel_come_from_its_description() {
        let (interfaces, _) = completed([report_trunk("Port-channel40", "lab1-pve01.prod/bond0 V:10-12")]);
        assert_eq!(tagged(&interfaces["Port-channel40"]), Some(&[10, 11, 12][..]));
    }

    // The rules that keep a description from telling a cable do not keep it
    // from telling the VLANs of the port.
    #[test]
    fn a_disabled_port_or_one_without_link_keeps_its_vlans() {
        let disabled = Interface { enabled: false, ..report_trunk("Te1/0/1", "lab1-esx01.prod/vmnic0 V:10,12") };
        let down = Interface { link_up: Some(false), ..report_trunk("Te1/0/2", "lab1-esx02.prod/vmnic0 V:11") };
        let (interfaces, _) = completed([disabled, down]);
        assert_eq!(tagged(&interfaces["Te1/0/1"]), Some(&[10, 12][..]));
        assert_eq!(tagged(&interfaces["Te1/0/2"]), Some(&[11][..]));
    }

    #[test]
    fn the_access_vlan_of_the_report_wins_over_the_description_and_the_difference_is_warned() {
        // `GigabitEthernet1/0/24 | Yes | LAB1-PRE01-ETH0 T:HOU V:12 I:192.0.2.10/192.0.2.11 | 12 | Access`:
        // the two agree. The second port is the same one, had its description said another VLAN.
        let agreeing = report_access("GigabitEthernet1/0/24", "LAB1-PRE01-ETH0 T:HOU V:12 I:192.0.2.10/192.0.2.11", 12);
        let differing = report_access("GigabitEthernet1/0/25", "LAB1-PRE01-ETH1 T:HOU V:11,13", 12);
        let (interfaces, warnings) = completed([agreeing.clone(), differing.clone()]);
        assert_eq!(interfaces, by_name([agreeing, differing]));
        assert_eq!(
            warnings,
            ["GigabitEthernet1/0/25: its description says VLAN 11,13, the report says it is an access port of \
              VLAN 12; the report is believed"]
        );
    }

    // `all` is what `switchport trunk allowed vlan` takes for every VLAN.
    #[test]
    fn a_trunk_whose_description_says_all_carries_every_vlan() {
        let (interfaces, warnings) = completed([
            report_trunk("Port-channel18", "[No Monitor] lab1-c190-01.prod/a0a/10G V:all"),
            report_trunk("Port-channel19", "[No Monitor] lab1-c190-02.prod/a0a/10G V:ALL"),
        ]);
        for name in ["Port-channel18", "Port-channel19"] {
            let port = &interfaces[name];
            assert_eq!(
                port.dot1q,
                Some(Dot1q { mode: Mode::TaggedAll, untagged_vlan: None, tagged_vlans: Vec::new() })
            );
            assert!(port.tagged_vlans_managed);
            assert!(!port.untagged_vlan_managed);
        }
        assert_eq!(warnings, [] as [&str; 0]);
    }

    #[test]
    fn a_list_of_every_vlan_is_a_trunk_that_carries_them_all() {
        let (interfaces, warnings) = completed([report_trunk("Port-channel18", "lab1-c190-01.prod/a0a V:1-4094")]);
        let port = &interfaces["Port-channel18"];
        assert_eq!(port.dot1q, Some(Dot1q { mode: Mode::TaggedAll, untagged_vlan: None, tagged_vlans: Vec::new() }));
        assert!(port.tagged_vlans_managed);
        assert_eq!(warnings, [] as [&str; 0]);
    }

    // A list that holds no VLAN without saying `none` is a typing mistake: it clears nothing.
    #[test]
    fn a_reversed_range_or_a_list_without_any_vlan_is_not_a_list() {
        let (interfaces, warnings) = completed([
            report_trunk("Te1/0/1", "lab1-esx01.prod/vmnic0 V:20-10"),
            report_trunk("Te1/0/2", "lab1-esx02.prod/vmnic0 V:,"),
            report_trunk("Te1/0/3", "lab1-esx03.prod/vmnic0 V:none"),
        ]);
        assert_eq!(tagged(&interfaces["Te1/0/1"]), None);
        assert_eq!(tagged(&interfaces["Te1/0/2"]), None);
        // `none` is what a switch says of a trunk that allows no VLAN.
        assert_eq!(tagged(&interfaces["Te1/0/3"]), Some(&[][..]));
        assert_eq!(
            warnings,
            [
                "Te1/0/1: the VLANs of its description cannot be read (invalid VLAN list item '20-10'); the tagged \
                 VLANs NetBox has are left as they are",
                "Te1/0/2: the VLANs of its description cannot be read (invalid VLAN list item ','); the tagged \
                 VLANs NetBox has are left as they are",
            ]
        );
    }

    #[test]
    fn an_access_port_whose_description_says_all_is_warned_about() {
        let port = report_access("Gi1/0/2", "lab1-pre01.prod/eth0 V:all", 12);
        let (interfaces, warnings) = completed([port.clone()]);
        assert_eq!(interfaces, by_name([port]));
        assert_eq!(
            warnings,
            ["Gi1/0/2: its description says VLAN all, the report says it is an access port of VLAN 12; the report \
              is believed"]
        );
    }

    #[test]
    fn a_port_whose_mode_the_report_does_not_tell_takes_no_vlan_from_its_description() {
        let unmanaged = Interface {
            description: Some("V:10-12".to_owned()),
            dot1q_managed: false,
            ..Interface::new("Vlan952", true)
        };
        let (interfaces, warnings) = completed([unmanaged.clone()]);
        assert_eq!(interfaces, by_name([unmanaged]));
        assert_eq!(warnings, [] as [&str; 0]);
    }

    #[test]
    fn a_pattern_without_the_vlans_group_reads_none() {
        let trunk = report_trunk("Te1/0/1", "lab1-pve01 eno1 V:10-12");
        let mut interfaces = by_name([trunk.clone()]);
        assert_eq!(vlans_from_descriptions(&mut interfaces, &pattern()), [] as [&str; 0]);
        assert_eq!(interfaces, by_name([trunk]));
    }

    // A switch whose configuration was read: it is believed, the description is compared.

    fn configured(name: &str, description: &str, mode: Mode, untagged: Option<u16>, tagged_vlans: &[u16]) -> Interface {
        Interface {
            description: Some(description.to_owned()),
            dot1q: Some(Dot1q { mode, untagged_vlan: untagged, tagged_vlans: tagged_vlans.to_vec() }),
            ..Interface::new(name, true)
        }
    }

    #[test]
    fn vlans_in_a_description_that_differ_from_the_configuration_are_warned_about() {
        let interfaces = by_name([
            configured("Eth1/1", "lab1-esx01.prod/vmnic0 V:10-12", Mode::Tagged, Some(1), &[10, 11]),
            configured("Eth1/2", "lab1-esx02.prod/vmnic0 V:11", Mode::Access, Some(12), &[]),
            configured("Eth1/3", "lab1-esx03.prod/vmnic0 V:1x", Mode::Tagged, Some(1), &[10]),
            configured("Eth1/4", "lab1-esx04.prod/vmnic0 V:all", Mode::Tagged, Some(1), &[10]),
        ]);
        let before = interfaces.clone();
        assert_eq!(
            vlans_against_descriptions(&interfaces, &vlan_pattern(), &BTreeSet::from([1, 10, 11, 12])),
            [
                "Eth1/1: its description says VLAN 10-12, its configuration says 10-11; the configuration is believed",
                "Eth1/2: its description says VLAN 11, its configuration says 12; the configuration is believed",
                "Eth1/3: the VLANs of its description cannot be read (invalid VLAN list item '1x'); the \
                 configuration is believed",
                "Eth1/4: its description says VLAN all, its configuration says 10; the configuration is believed",
            ]
        );
        assert_eq!(interfaces, before);
    }

    // What is compared is what the collection kept of the configuration: the VLANs the switch
    // defines. `switchport trunk allowed vlan 10-12` where VLAN 12 is not created, and an access
    // port of a VLAN that is not, are read without them.
    #[test]
    fn a_vlan_the_switch_does_not_define_is_not_a_difference() {
        let interfaces = by_name([
            configured("Eth1/1", "lab1-esx01.prod/vmnic0 V:10-12", Mode::Tagged, Some(1), &[10, 11]),
            configured("Eth1/2", "lab1-esx02.prod/vmnic0 V:30", Mode::Access, None, &[]),
        ]);
        assert_eq!(
            vlans_against_descriptions(&interfaces, &vlan_pattern(), &BTreeSet::from([1, 10, 11])),
            [] as [&str; 0]
        );
    }

    #[test]
    fn a_description_that_lists_the_vlans_of_the_configuration_is_not_warned_about() {
        let interfaces = by_name([
            // The allowed list of a trunk may hold its native VLAN, or not.
            configured("Eth1/1", "lab1-esx01.prod/vmnic0 V:10-11", Mode::Tagged, Some(1), &[10, 11]),
            configured("Eth1/2", "lab1-esx02.prod/vmnic0 V:1,10-11", Mode::Tagged, Some(1), &[10, 11]),
            configured("Eth1/3", "lab1-esx03.prod/vmnic0 V:12", Mode::Access, Some(12), &[]),
            // A trunk that carries every VLAN carries those of its description.
            configured("Eth1/4", "lab1-esx04.prod/vmnic0 V:10-12", Mode::TaggedAll, Some(1), &[]),
            configured("Eth1/7", "lab1-esx07.prod/vmnic0 V:all", Mode::TaggedAll, Some(1), &[]),
            // No list, no mode: nothing to compare.
            configured("Eth1/5", "lab1-esx05.prod/vmnic0", Mode::Tagged, Some(1), &[10]),
            Interface { description: Some("lab1-esx06.prod/vmnic0 V:10".to_owned()), ..Interface::new("Eth1/6", true) },
        ]);
        assert_eq!(
            vlans_against_descriptions(&interfaces, &vlan_pattern(), &BTreeSet::from([1, 10, 11, 12])),
            [] as [&str; 0]
        );
    }
}
