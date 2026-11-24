//! What the physical cards of a node hear of their switches, as `lldpd`
//! tells it: the output of `lldpcli -f json show neighbors`, read over SSH.
//!
//! The Proxmox VE API has no such call; `lldpd` hears LLDP, and CDP when it
//! is started with `-c`.

use std::collections::BTreeMap;
use std::future::Future;

use serde_json::{Map, Value};

use crate::model::ProxmoxCluster;

/// The one command run on a node, exactly: nothing else is ever sent.
pub const COMMAND: &str = "lldpcli -f json show neighbors";

/// A card of a node and the switch port it hears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardNeighbor {
    /// The card, as the node names it (`eno1`).
    pub card: String,
    /// The name the switch announces (`chassis`).
    pub switch: String,
    /// The port of the switch, as it names it.
    pub port: String,
}

/// Why an answer is not what `lldpcli` prints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not the JSON of lldpcli: {0}")]
pub struct NeighborsError(pub String);

/// The closed list of what is ever run on a node: [`COMMAND`], exactly, and
/// nothing else, whatever is added to it.
pub fn check(command: &str) -> Result<(), String> {
    if command == COMMAND { Ok(()) } else { Err(format!("{command}: not the one command run on a node")) }
}

/// What runs a command on a node and gives its standard output, or why it
/// could not: the command was refused, it failed, the node was not reached.
pub trait Shell: Sync {
    fn run(&self, node: &str, command: &str) -> impl Future<Output = Result<String, String>> + Send;
}

/// What the cards of the nodes of a cluster hear.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeNeighbors {
    /// By node, the physical cards (`eth`) that hear a switch.
    pub by_node: BTreeMap<String, Vec<CardNeighbor>>,
    /// A node whose neighbours could not be read: the others are.
    pub warnings: Vec<String>,
}

/// Asks each node of `cluster` that is online what its physical cards hear,
/// with [`COMMAND`] and nothing else. A card that is not physical (a bridge,
/// a bond, the interface of a guest firewall) is left out.
pub async fn read_neighbors<S: Shell>(cluster: &ProxmoxCluster, shell: &S) -> NodeNeighbors {
    let answers = futures::future::join_all(cluster.nodes.iter().map(|node| shell.run(&node.name, COMMAND))).await;
    let mut read = NodeNeighbors::default();
    for (node, answer) in cluster.nodes.iter().zip(answers) {
        let heard = answer.and_then(|text| neighbors(&text).map_err(|error| error.to_string()));
        match heard {
            Ok(heard) => {
                let physical = |card: &CardNeighbor| {
                    node.networks.iter().any(|network| network.name == card.card && network.kind == "eth")
                };
                read.by_node.insert(node.name.clone(), heard.into_iter().filter(physical).collect());
            }
            Err(error) => {
                read.warnings.push(format!("node {}: what its cards hear cannot be read: {error}", node.name))
            }
        }
    }
    read
}

/// The neighbours an answer of [`COMMAND`] gives, card by card.
///
/// `lldpcli` writes a list of one element as the element alone (`capability`
/// is an object for a switch that has one), so a lone interface may come as
/// an object as well as a list of objects. A neighbour whose port is not a
/// name (a MAC address: a bridge that hears the node itself) names no port and
/// is left out.
pub fn neighbors(answer: &str) -> Result<Vec<CardNeighbor>, NeighborsError> {
    let failed = |why: &str| NeighborsError(why.to_owned());
    let document: Value = serde_json::from_str(answer).map_err(|error| NeighborsError(error.to_string()))?;
    let lldp = document.get("lldp").and_then(Value::as_object).ok_or_else(|| failed("no lldp object"))?;
    let interfaces: Vec<&Map<String, Value>> = match lldp.get("interface") {
        // No neighbour at all: `{"lldp": {}}`.
        None => Vec::new(),
        Some(Value::Array(list)) => list
            .iter()
            .map(|item| item.as_object().ok_or_else(|| failed("an interface that is not an object")))
            .collect::<Result<_, _>>()?,
        Some(Value::Object(one)) => vec![one],
        Some(_) => return Err(failed("interface is neither a list nor an object")),
    };
    let mut found = Vec::new();
    for interface in interfaces {
        for (card, neighbor) in interface {
            if let Some(heard) = neighbor_of(card, neighbor) {
                found.push(heard);
            }
        }
    }
    Ok(found)
}

/// The switch and the port one card hears, when the neighbour names both.
fn neighbor_of(card: &str, neighbor: &Value) -> Option<CardNeighbor> {
    let chassis = neighbor.get("chassis")?.as_object()?;
    // One chassis, under the name it announces: an object holding its `id`.
    // Without a name, the fields of the chassis are the keys, and none names it.
    let (switch, fields) = chassis.iter().next()?;
    fields.as_object()?.get("id")?;
    let switch = switch.trim();
    let id = neighbor.get("port")?.get("id")?;
    let port = match id.get("type")?.as_str()? {
        "ifname" | "local" => id.get("value")?.as_str()?.trim(),
        _ => return None,
    };
    if switch.is_empty() || port.is_empty() {
        return None;
    }
    Some(CardNeighbor { card: card.to_owned(), switch: switch.to_owned(), port: port.to_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../tests/fixtures/lldpd/", $name))
        };
    }

    fn heard(card: &str, switch: &str, port: &str) -> CardNeighbor {
        CardNeighbor { card: card.to_owned(), switch: switch.to_owned(), port: port.to_owned() }
    }

    #[test]
    fn a_card_that_hears_lldp_gives_the_name_and_the_port_of_its_switch() {
        let found = neighbors(fixture!("pve01.json")).expect("neighbours");
        // "eno1": {"via": "LLDP", ... "chassis": {"nexus04.lab.example": ...},
        // "port": {"id": {"type": "ifname", "value": "Ethernet1/27"}, "descr": "pve01.lab.example/eno1/10G"
        assert_eq!(found[0], heard("eno1", "nexus04.lab.example", "Ethernet1/27"));
        // Six cards, each hearing one Nexus.
        assert_eq!(found.len(), 6);
        assert_eq!(found[5], heard("enp130s0f1", "nexus04.lab.example", "Ethernet1/25"));
    }

    #[test]
    fn a_card_that_hears_cdp_gives_the_name_and_the_port_of_its_switch() {
        let found = neighbors(fixture!("cdp.json")).expect("neighbours");
        // "eth0": {"via": "CDPv2", ... "chassis": {"PROVIDER-SW001.provider.example": ...},
        // "port": {"id": {"type": "ifname", "value": "GigabitEthernet1/0/24"}, ...
        assert_eq!(
            found,
            [
                heard("eth0", "PROVIDER-SW001.provider.example", "GigabitEthernet1/0/24"),
                heard("eth1", "PROVIDER-SW001.provider.example", "GigabitEthernet2/0/24"),
            ]
        );
    }

    #[test]
    fn a_neighbour_whose_port_is_an_address_names_no_port_and_is_left_out() {
        let found = neighbors(fixture!("pve02.json")).expect("neighbours");
        // The bridges of the firewalls hear the node itself, its port a MAC address:
        // "fwpr141p0": {... "port": {"id": {"type": "mac", ...
        assert!(found.iter().all(|neighbor| !neighbor.card.starts_with("fw")), "{found:?}");
        assert_eq!(found.len(), 6);
    }

    #[test]
    fn an_answer_without_neighbour_is_no_neighbour_and_not_a_failure() {
        // {"lldp": {}}
        assert_eq!(neighbors(fixture!("empty.json")), Ok(Vec::new()));
    }

    #[test]
    fn an_answer_that_is_not_the_json_of_lldpcli_is_a_failure() {
        assert!(neighbors("lldpd: no neighbor.").is_err());
        assert!(neighbors("{}").is_err());
        assert!(neighbors("{\"lldp\": {\"interface\": 3}}").is_err());
    }
    #[test]
    fn a_switch_that_announces_no_name_names_no_switch() {
        // lldpcli keys `chassis` by the system name; without one, the fields of
        // the chassis (`id`, `descr`…) are its keys. Built from pve01.json by
        // taking the level of the name out of every chassis.
        let mut document: Value = serde_json::from_str(fixture!("pve01.json")).unwrap();
        for interface in document["lldp"]["interface"].as_array_mut().unwrap() {
            for neighbor in interface.as_object_mut().unwrap().values_mut() {
                let chassis = neighbor["chassis"].as_object().unwrap().values().next().unwrap().clone();
                neighbor["chassis"] = chassis;
            }
        }
        assert_eq!(neighbors(&document.to_string()), Ok(Vec::new()));
    }
}
