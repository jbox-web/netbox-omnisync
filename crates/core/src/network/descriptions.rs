//! Neighbours told by port descriptions, for switches without LLDP or CDP data.
//!
//! A provider-managed switch is only known through its configuration report: the
//! port descriptions written by its operator are the one source of what is plugged
//! in. They are free text, so the host part is matched by a pattern of the
//! inventory (named groups `host` and optional `port`); a port the description does
//! not name stays unresolved and gives no cable.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::{Captures, Regex};

use super::model::{Interface, Neighbor};
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

#[cfg(test)]
mod tests {
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
}
