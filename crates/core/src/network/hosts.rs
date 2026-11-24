//! What the cards of a host hear of the switches they are plugged in (CDP,
//! LLDP), as a hypervisor tells it, and how it enters the cable step: as a
//! neighbour of the port of the switch.

use std::collections::{BTreeMap, BTreeSet};

use super::cables::{Aliases, Stacks, name_family};
use super::descriptions::PROTOCOL as DESCRIPTION;
use super::model::Neighbor;
use super::names::{interface_key, long_interface_name, strip_serial_suffix};
use super::stack::member_position;

/// One physical card of a host, and the switch port it hears.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Heard {
    /// The host, under the name NetBox has for it (the one its translation gives).
    pub host: String,
    /// The card, as the host names it and as its NetBox interface is named.
    pub card: String,
    /// The switch, as it announces itself: with a domain, or followed by a serial.
    pub switch: String,
    /// The port of the switch, as it names it.
    pub port: String,
}

/// The protocol of a neighbour a host heard, as the warnings name it.
pub const PROTOCOL: &str = "host";

/// What the merge knows of the run, besides the neighbours and what was heard.
pub struct HeardContext<'a> {
    /// The stacks, whose ports live on the member devices.
    pub stacks: &'a Stacks,
    /// The domains a switch may append to its name.
    pub domains: &'a [&'a str],
    /// Names a switch announces -> NetBox device names.
    pub aliases: &'a Aliases,
    /// The hosts installed in another device (`parent_device`: a blade in its chassis).
    pub blades: &'a BTreeSet<String>,
    /// Whether NetBox has the interface of a host by this name: (host, card).
    pub in_netbox: &'a dyn Fn(&str, &str) -> bool,
}

/// Adds what the hosts hear to the neighbours of the synced switches, and
/// gives the warnings.
///
/// On a port of a synced switch, the neighbour the switch announces itself
/// (LLDP, CDP) is believed first, what a host hears next, the description of
/// the port last. A switch no source of the run reads is not given anything;
/// a blade (a host installed in another device) gives nothing, its chassis
/// repeating what the switch announces; a card NetBox does not have leaves the
/// port as it is.
pub fn merge_heard(
    neighbors: &mut BTreeMap<String, Vec<Neighbor>>,
    heard: &[Heard],
    context: &HeardContext<'_>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let unique: BTreeSet<&Heard> = heard.iter().collect();
    for heard in unique {
        // A blade hears what the switches of its chassis repeat: never the cable of its card.
        if context.blades.iter().any(|blade| blade.eq_ignore_ascii_case(&heard.host)) {
            continue;
        }
        let port = long_interface_name(&heard.port, None);
        let switch = match switch_device(&heard.switch, &port, neighbors, context) {
            Ok(Some(switch)) => switch,
            Ok(None) => continue,
            Err(several) => {
                warnings.push(format!(
                    "{} {} hears {}, which names several switches of the run ({}): left out",
                    heard.host,
                    heard.card,
                    heard.switch,
                    several.join(", ")
                ));
                continue;
            }
        };
        let key = interface_key(&port);
        // A card NetBox does not have would leave the port without any cable.
        if !(context.in_netbox)(&heard.host, &heard.card) {
            warnings.push(format!(
                "{switch} {port}: {} {} hears this port, but NetBox has no such interface",
                heard.host, heard.card
            ));
            continue;
        }
        let Some(found) = neighbors.get_mut(&switch) else {
            continue;
        };
        let names_host = |neighbor: &Neighbor| {
            neighbor.announced_name().is_some_and(|name| {
                name_family(name, context.domains, context.aliases)
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&heard.host))
            })
        };
        let on_port = |neighbor: &Neighbor| interface_key(&long_interface_name(&neighbor.local_interface, None)) == key;
        let announced: Vec<&Neighbor> = found
            .iter()
            .filter(|neighbor| on_port(neighbor))
            .filter(|neighbor| neighbor.protocol != DESCRIPTION && neighbor.protocol != PROTOCOL)
            .filter(|neighbor| !neighbor.anonymous())
            .collect();
        if !announced.is_empty() {
            if !announced.iter().any(|neighbor| names_host(neighbor)) {
                let said: Vec<String> = announced
                    .iter()
                    .map(|neighbor| format!("{} ({})", neighbor.remote_device.trim(), neighbor.protocol))
                    .collect();
                warnings.push(format!(
                    "{switch} {port}: the switch announces {}, {} {} hears this port: the switch is believed",
                    said.join(", "),
                    heard.host,
                    heard.card
                ));
            }
            continue;
        }
        // What the description, or a neighbour that says nothing, told of the port goes.
        let described: Vec<Neighbor> = found
            .iter()
            .filter(|neighbor| on_port(neighbor) && neighbor.protocol == DESCRIPTION && !names_host(neighbor))
            .cloned()
            .collect();
        for told in described {
            warnings.push(format!(
                "{switch} {port}: the description names {}, {} {} hears this port: the host is believed",
                told.remote_device.trim(),
                heard.host,
                heard.card
            ));
        }
        found.retain(|neighbor| !(on_port(neighbor) && (neighbor.protocol == DESCRIPTION || neighbor.anonymous())));
        found.push(Neighbor {
            local_interface: port,
            remote_device: heard.host.clone(),
            remote_interface: Some(heard.card.clone()),
            protocol: PROTOCOL.to_owned(),
        });
    }
    warnings
}

/// The name a switch announces, without the serial a Nexus adds, and without
/// anything after its first dot: a report is known by that short name.
fn short_name(name: &str) -> String {
    let name = strip_serial_suffix(name);
    name.split('.').next().unwrap_or_default().trim().to_lowercase()
}

/// The synced device that holds `port` of the switch a host hears, as the run
/// names it: none when the switch is no source of the run, and every one it
/// may name when it is not one only.
///
/// The name itself, without a domain of the file, or an alias, is looked for
/// first; then the name without anything after its first dot, as the name of
/// a report is compared: two switches of the run holding it are neither.
fn switch_device(
    switch: &str,
    port: &str,
    neighbors: &BTreeMap<String, Vec<Neighbor>>,
    context: &HeardContext<'_>,
) -> Result<Option<String>, Vec<String>> {
    let name = strip_serial_suffix(switch);
    let mut wanted: BTreeSet<String> =
        name_family(&name, context.domains, context.aliases).iter().map(|name| name.to_lowercase()).collect();
    let short = short_name(&name);
    // The short name may itself be an alias.
    wanted.extend(
        context.aliases.iter().filter(|(alias, _)| short_name(alias) == short).map(|(_, to)| to.to_lowercase()),
    );
    // A stack announces one name; its ports live on the member devices.
    let device_of = |run_name: &str| -> Option<String> {
        match context.stacks.iter().find(|(stack, _)| stack.eq_ignore_ascii_case(run_name)) {
            Some((_, members)) => {
                let member = members.get(&member_position(port).unwrap_or(0))?;
                neighbors.keys().find(|device| device.eq_ignore_ascii_case(member)).cloned()
            }
            None => neighbors.keys().find(|device| device.eq_ignore_ascii_case(run_name)).cloned(),
        }
    };
    let run_names: BTreeSet<&str> =
        context.stacks.keys().map(String::as_str).chain(neighbors.keys().map(String::as_str)).collect();
    if let Some(exact) = run_names.iter().find(|run_name| wanted.contains(&run_name.to_lowercase())) {
        return Ok(device_of(exact));
    }
    let mut by_short: Vec<&str> = run_names.into_iter().filter(|run_name| short_name(run_name) == short).collect();
    // The members of a stack are the stack itself.
    by_short.retain(|run_name| {
        !context.stacks.values().any(|members| members.values().any(|member| member.eq_ignore_ascii_case(run_name)))
    });
    match by_short.as_slice() {
        [] => Ok(None),
        [one] => Ok(device_of(one)),
        several => Err(several.iter().map(|name| (*name).to_owned()).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAINS: [&str; 1] = ["lab01"];

    fn heard(host: &str, card: &str, switch: &str, port: &str) -> Heard {
        Heard { host: host.to_owned(), card: card.to_owned(), switch: switch.to_owned(), port: port.to_owned() }
    }

    fn neighbor(local: &str, device: &str, remote: Option<&str>, protocol: &str) -> Neighbor {
        Neighbor {
            local_interface: local.to_owned(),
            remote_device: device.to_owned(),
            remote_interface: remote.map(str::to_owned),
            protocol: protocol.to_owned(),
        }
    }

    fn from_host(local: &str, host: &str, card: &str) -> Neighbor {
        neighbor(local, host, Some(card), PROTOCOL)
    }

    /// The synced switches and their neighbours: a Nexus that announces
    /// nothing on Ethernet1/40, and a stack of two members read from a report.
    fn run() -> BTreeMap<String, Vec<Neighbor>> {
        BTreeMap::from([
            ("nexus04".to_owned(), vec![neighbor("Ethernet1/1", "nexus03", Some("Ethernet1/1"), "lldp")]),
            ("sw001-1".to_owned(), Vec::new()),
            ("sw001-2".to_owned(), Vec::new()),
        ])
    }

    fn stacks() -> Stacks {
        Stacks::from([("sw001".to_owned(), BTreeMap::from([(1, "sw001-1".to_owned()), (2, "sw001-2".to_owned())]))])
    }

    struct Merged {
        neighbors: BTreeMap<String, Vec<Neighbor>>,
        warnings: Vec<String>,
    }

    /// The merge, the blades of the run being the hosts of `blades`, and every
    /// card of a host an interface NetBox has, but those of `absent`.
    fn merged_with(
        neighbors: BTreeMap<String, Vec<Neighbor>>,
        heard: &[Heard],
        blades: &[&str],
        absent: &[(&str, &str)],
    ) -> Merged {
        let mut neighbors = neighbors;
        let stacks = stacks();
        let aliases = Aliases::from([("FPLAB2-SW001".to_owned(), "sw001".to_owned())]);
        let blades: BTreeSet<String> = blades.iter().map(|host| (*host).to_owned()).collect();
        let in_netbox = |host: &str, card: &str| !absent.contains(&(host, card));
        let context = HeardContext {
            stacks: &stacks,
            domains: &DOMAINS,
            aliases: &aliases,
            blades: &blades,
            in_netbox: &in_netbox,
        };
        let warnings = merge_heard(&mut neighbors, heard, &context);
        Merged { neighbors, warnings }
    }

    fn merged(neighbors: BTreeMap<String, Vec<Neighbor>>, heard: &[Heard], blades: &[&str]) -> Merged {
        merged_with(neighbors, heard, blades, &[])
    }

    #[test]
    fn a_card_that_hears_a_switch_is_a_neighbour_of_its_port() {
        let found = merged(run(), &[heard("esx01", "vmnic1", "nexus04.lab01", "Ethernet1/40")], &[]);
        assert_eq!(
            found.neighbors["nexus04"],
            [
                neighbor("Ethernet1/1", "nexus03", Some("Ethernet1/1"), "lldp"),
                from_host("Ethernet1/40", "esx01", "vmnic1"),
            ]
        );
        assert_eq!(found.warnings, Vec::<String>::new());
        // A stack holds a port on the member its number names.
        let found = merged(run(), &[heard("esx02", "vmnic0", "sw001", "GigabitEthernet2/0/14")], &[]);
        assert_eq!(found.neighbors["sw001-2"], [from_host("GigabitEthernet2/0/14", "esx02", "vmnic0")]);
        assert_eq!(found.neighbors["sw001-1"], []);
    }

    #[test]
    fn the_serial_a_nexus_adds_to_its_name_is_not_part_of_it() {
        let found = merged(run(), &[heard("esx01", "vmnic1", "nexus04.lab01(FOC0000A0A4)", "Ethernet1/40")], &[]);
        assert_eq!(found.neighbors["nexus04"][1], from_host("Ethernet1/40", "esx01", "vmnic1"));
    }

    #[test]
    fn a_switch_that_is_not_in_the_run_is_not_given_a_neighbour() {
        let elsewhere = [
            heard("esx01", "vmnic1", "nexus09.lab01(FOC0000A0A9)", "Ethernet1/40"),
            // The domain of a provider is no domain of the file: the name without
            // it is compared, caselessly, as the name of a report is.
            heard("esx02", "vmnic2", "OTHER-SW002.provider.example", "GigabitEthernet1/0/22"),
        ];
        let found = merged(run(), &elsewhere, &[]);
        assert_eq!(found.neighbors, run());
        assert_eq!(found.warnings, Vec::<String>::new());
        let known = merged(run(), &[heard("esx02", "vmnic2", "SW001.provider.example", "GigabitEthernet1/0/22")], &[]);
        assert_eq!(known.neighbors["sw001-1"], [from_host("GigabitEthernet1/0/22", "esx02", "vmnic2")]);
        // An alias names the switch as well.
        let aliased = merged(run(), &[heard("esx02", "vmnic3", "FPLAB2-SW001", "GigabitEthernet2/0/22")], &[]);
        assert_eq!(aliased.neighbors["sw001-2"], [from_host("GigabitEthernet2/0/22", "esx02", "vmnic3")]);
    }

    #[test]
    fn the_neighbour_a_switch_announces_wins_over_what_a_host_hears_and_the_difference_is_warned() {
        let mut neighbors = run();
        neighbors.get_mut("nexus04").unwrap().push(neighbor("Ethernet1/40", "esx09.lab01", Some("vmnic0"), "cdp"));
        let found = merged(neighbors.clone(), &[heard("esx01", "vmnic1", "nexus04.lab01", "Ethernet1/40")], &[]);
        assert_eq!(found.neighbors, neighbors);
        assert_eq!(
            found.warnings,
            ["nexus04 Ethernet1/40: the switch announces esx09.lab01 (cdp), esx01 vmnic1 hears this port: the \
              switch is believed"]
        );
        // The same device, announced in its own way: nothing to say.
        let found = merged(neighbors.clone(), &[heard("esx09", "vmnic0", "nexus04", "Eth1/40")], &[]);
        assert_eq!((found.neighbors, found.warnings), (neighbors, Vec::new()));
    }

    #[test]
    fn what_a_host_hears_wins_over_the_description_of_the_port_and_the_difference_is_warned() {
        let mut neighbors = run();
        neighbors.insert("sw001-1".to_owned(), vec![neighbor("GigabitEthernet1/0/14", "esx05", None, "description")]);
        let found = merged(neighbors, &[heard("esx01", "vmnic0", "sw001", "GigabitEthernet1/0/14")], &[]);
        assert_eq!(found.neighbors["sw001-1"], [from_host("GigabitEthernet1/0/14", "esx01", "vmnic0")]);
        assert_eq!(
            found.warnings,
            ["sw001-1 GigabitEthernet1/0/14: the description names esx05, esx01 vmnic0 hears this port: the host is \
              believed"]
        );
        // A description that names the host: replaced without a word.
        let mut neighbors = run();
        neighbors.insert(
            "sw001-1".to_owned(),
            vec![neighbor("GigabitEthernet1/0/14", "esx01.lab01", Some("vmnic0"), "description")],
        );
        let found = merged(neighbors, &[heard("esx01", "vmnic0", "sw001", "GigabitEthernet1/0/14")], &[]);
        assert_eq!(found.neighbors["sw001-1"], [from_host("GigabitEthernet1/0/14", "esx01", "vmnic0")]);
        assert_eq!(found.warnings, Vec::<String>::new());
    }

    #[test]
    fn a_host_inside_a_chassis_never_takes_the_cable_of_its_chassis() {
        // esx04 is a blade of fx01: the switches of the chassis repeat what nexus04
        // announces, whether NetBox cables the port to the chassis yet or not.
        let blade = [heard("esx04", "vmnic1", "nexus04.lab01(FOC0000A0A4)", "Ethernet1/40")];
        let found = merged(run(), &blade, &["esx04"]);
        assert_eq!((found.neighbors, found.warnings), (run(), Vec::new()));
        // A host in no chassis is believed on the same port.
        let found = merged(run(), &blade, &["esx05"]);
        assert_eq!(found.neighbors["nexus04"][1], from_host("Ethernet1/40", "esx04", "vmnic1"));
    }

    #[test]
    fn a_short_name_two_switches_of_the_run_hold_is_resolved_to_neither() {
        let mut neighbors = run();
        neighbors.insert("core01.dc1".to_owned(), Vec::new());
        neighbors.insert("core01.dc2".to_owned(), Vec::new());
        let found =
            merged(neighbors.clone(), &[heard("esx07", "vmnic0", "CORE01.provider.example", "Ethernet1/12")], &[]);
        assert_eq!(found.neighbors, neighbors);
        assert_eq!(
            found.warnings,
            ["esx07 vmnic0 hears CORE01.provider.example, which names several switches of the run (core01.dc1, \
              core01.dc2): left out"]
        );
        // Its full name designates one of them.
        let found = merged(neighbors, &[heard("esx07", "vmnic0", "core01.dc2", "Ethernet1/12")], &[]);
        assert_eq!(found.neighbors["core01.dc2"], [from_host("Ethernet1/12", "esx07", "vmnic0")]);
        assert_eq!(found.neighbors["core01.dc1"], []);
    }

    #[test]
    fn a_card_netbox_does_not_have_leaves_the_description_of_the_port() {
        let mut neighbors = run();
        neighbors.insert("sw001-1".to_owned(), vec![neighbor("GigabitEthernet1/0/14", "esx05", None, "description")]);
        let heard = [heard("esx01", "vmnic0", "sw001", "GigabitEthernet1/0/14")];
        let found = merged_with(neighbors.clone(), &heard, &[], &[("esx01", "vmnic0")]);
        assert_eq!(found.neighbors, neighbors);
        assert_eq!(
            found.warnings,
            ["sw001-1 GigabitEthernet1/0/14: esx01 vmnic0 hears this port, but NetBox has no such interface"]
        );
    }

    #[test]
    fn a_host_that_reported_nothing_leaves_the_cables_as_they_are() {
        let mut neighbors = run();
        neighbors.insert("sw001-1".to_owned(), vec![neighbor("GigabitEthernet1/0/14", "esx05", None, "description")]);
        let found = merged(neighbors.clone(), &[], &[]);
        assert_eq!((found.neighbors, found.warnings), (neighbors, Vec::new()));
    }
}
