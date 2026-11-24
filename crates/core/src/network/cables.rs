//! Cable diff from LLDP and CDP neighbours.

use std::collections::{BTreeMap, BTreeSet};

use super::descriptions::{MANAGEMENT_PORT, PROTOCOL};
use super::hosts::PROTOCOL as HOST;
use super::model::Neighbor;
use super::names::{interface_key, long_interface_name, name_candidates};
use super::stack::member_position;
use super::state::{End, NbCable, NbInterface};
use crate::change::{Action, Change};

/// The NetBox interfaces of one device, keyed by `interface_key(name)`.
pub type Interfaces = BTreeMap<String, NbInterface>;
/// Device name -> its NetBox interfaces, None when NetBox has no such device or
/// when its read failed. Any closure does, one over an in-memory map included:
/// the caller may answer from the state computed during the run, so that a
/// cable towards an interface created in that run is found.
pub type InterfacesOf<'n> = dyn Fn(&str) -> Option<&'n Interfaces> + 'n;
/// A synced device's local port as the warnings show it: (device, port) -> label.
pub type PortLabel<'a> = dyn Fn(&str, &str) -> String + 'a;
/// Stack host name -> member position -> NetBox device name of the member.
pub type Stacks = BTreeMap<String, BTreeMap<u32, String>>;
/// Name announced by a neighbour -> NetBox device name.
pub type Aliases = BTreeMap<String, String>;
/// Device name -> `interface_key(port)` -> description of the port.
pub type Descriptions = BTreeMap<String, BTreeMap<String, String>>;

/// What the cable diff knows of the run, besides the neighbours and the cables.
pub struct CableOptions<'a> {
    /// The stacks, whose interfaces live on the member devices.
    pub stacks: &'a Stacks,
    /// The domains a neighbour may append to its name.
    pub domains: &'a [&'a str],
    /// The devices the run syncs.
    pub synced: &'a BTreeSet<String>,
    /// Whether stale cables between synced devices are deleted and replaced.
    pub prune: bool,
    /// The (device, interface_key) of synced ports whose link is down.
    pub down: &'a BTreeSet<(String, String)>,
    /// Names announced by neighbours -> NetBox device names.
    pub aliases: &'a Aliases,
    /// The synced devices read from a configuration report, which shows no
    /// link: their cables are created, never deleted nor replaced.
    pub unpruned: &'a BTreeSet<String>,
    /// Whether the NetBox read of a device failed (`interfaces_of` gives None
    /// for it too): it is named as such in the warnings. A predicate rather
    /// than a set, so that a caller reading lazily during the diff stays live.
    pub unreadable: &'a dyn Fn(&str) -> bool,
    /// Each synced device's port descriptions (key: interface_key), quoted after
    /// the local port in the warnings: what is plugged in, when the neighbour
    /// cannot say.
    pub descriptions: Option<&'a Descriptions>,
}

/// Labels quoting each port's description (key: interface_key), when it has one.
pub fn port_labeller<'a>(descriptions: Option<&'a Descriptions>) -> impl Fn(&str, &str) -> String + 'a {
    move |device: &str, port: &str| -> String {
        let description = descriptions
            .and_then(|devices| devices.get(device))
            .and_then(|ports| ports.get(&interface_key(port)))
            .filter(|description| !description.is_empty());
        match description {
            Some(description) => format!("{port} \"{description}\""),
            None => port.to_owned(),
        }
    }
}

/// The Netbox names an announced or described name may stand for, in order.
pub fn name_family(name: &str, domains: &[&str], aliases: &Aliases) -> Vec<String> {
    let mut names = name_candidates(name, domains);
    // An alias maps a name a neighbour announces to its Netbox device name.
    let aliased: Vec<String> = names.iter().filter_map(|candidate| aliases.get(candidate)).cloned().collect();
    names.extend(aliased);
    names
}

fn end_label(end: &End) -> String {
    format!("{}:{}", end.device, end.interface)
}

/// A string as Python's `repr` prints it, which is how the warnings quote a port:
/// single quotes, or double quotes when it holds a single quote and no double one.
/// What Python does not print is escaped, so that nothing invisible hides in a name.
fn quoted(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if character == quote => {
                out.push('\\');
                out.push(character);
            }
            _ if !printable(character) => out.push_str(&escaped(character)),
            _ => out.push(character),
        }
    }
    out.push(quote);
    out
}

/// What Python's `str.isprintable()` accepts: every character but the ones
/// of the categories Other (Cc, Cf, Cs, Co, Cn) and Separator (Zl, Zp, and Zs
/// except the space).
fn printable(character: char) -> bool {
    use unicode_general_category::GeneralCategory::*;
    if character == ' ' {
        return true;
    }
    !matches!(
        unicode_general_category::get_general_category(character),
        Control | Format | Surrogate | PrivateUse | Unassigned | LineSeparator | ParagraphSeparator | SpaceSeparator
    )
}

/// The escape Python's `repr` gives a character it does not print, by the
/// size of its code point.
fn escaped(character: char) -> String {
    let code = u32::from(character);
    if code < 0x100 {
        format!("\\x{code:02x}")
    } else if code < 0x1_0000 {
        format!("\\u{code:04x}")
    } else {
        format!("\\U{code:08x}")
    }
}

/// Why a neighbour gives no cable, which says what to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Cause {
    /// Neither a name nor a port.
    Anonymous,
    /// A port but no name.
    Nameless,
    /// A name but no port.
    Portless,
    /// The device's Netbox read failed (`device`).
    Unreadable,
    /// The name is no Netbox device.
    UnknownDevice,
    /// The device exists (`device`) without that port.
    UnknownPort,
    /// The port is the name of an interface of the device (`device`) and the
    /// label of another.
    AmbiguousPort,
    /// A management link to a device without exactly one management-only interface.
    NoManagement,
}

/// A neighbour that gives no cable: the cause, and the device and port it names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Unresolved {
    cause: Cause,
    device: String,
    port: Option<String>,
}

impl Unresolved {
    fn new(cause: Cause, device: &str, port: Option<&str>) -> Self {
        Unresolved { cause, device: device.to_owned(), port: port.map(str::to_owned) }
    }

    /// The port as the warnings print it; Python prints a missing one as `None`.
    fn port_text(&self) -> &str {
        self.port.as_deref().unwrap_or("None")
    }
}

/// One part of a name cut at its numbers. A number orders by its value: by its
/// length once the leading zeros are gone, then digit by digit.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Part {
    Text(String),
    Number(usize, String),
}

/// Ethernet1/9 before Ethernet1/15.
///
/// Texts and numbers alternate, a text first and last (empty if need be), so
/// that two keys always compare a text with a text and a number with a number.
fn natural(name: &str) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut text = String::new();
    let mut digits = String::new();
    for character in name.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        if !digits.is_empty() {
            parts.push(Part::Text(std::mem::take(&mut text)));
            parts.push(number(&std::mem::take(&mut digits)));
        }
        text.push(character);
    }
    if !digits.is_empty() {
        parts.push(Part::Text(std::mem::take(&mut text)));
        parts.push(number(&digits));
    }
    parts.push(Part::Text(text));
    parts
}

fn number(digits: &str) -> Part {
    let significant = digits.trim_start_matches('0');
    Part::Number(significant.len(), significant.to_owned())
}

/// The Netbox devices whose interfaces may hold the neighbour's port, in order.
///
/// Empty for a neighbour without a name or a port: nothing to look up.
fn devices_to_try(neighbor: &Neighbor, stacks: &Stacks, domains: &[&str], aliases: &Aliases) -> Vec<String> {
    let (Some(name), Some(announced)) = (neighbor.announced_name(), neighbor.remote_interface.as_deref()) else {
        return Vec::new();
    };
    let port = long_interface_name(announced, None);
    let mut devices = Vec::new();
    // The announced name, without the spaces some devices pad it with.
    for candidate in name_family(name, domains, aliases) {
        // A stack announces one host name; its interfaces live on the member devices.
        let device = match stacks.get(&candidate) {
            Some(members) => members.get(&member_position(&port).unwrap_or(0)).cloned().unwrap_or_default(),
            None => candidate,
        };
        if !device.is_empty() {
            devices.push(device);
        }
    }
    devices
}

/// Every device the resolution of `neighbors` may read, once each, in diff order.
///
/// Lets the caller read them all ahead of `diff_cables`, in parallel.
pub fn lookup_names(
    neighbors: &BTreeMap<String, Vec<Neighbor>>,
    stacks: &Stacks,
    domains: &[&str],
    aliases: &Aliases,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for found in neighbors.values() {
        for neighbor in found {
            for device in devices_to_try(neighbor, stacks, domains, aliases) {
                if !names.contains(&device) {
                    names.push(device);
                }
            }
        }
    }
    names
}

/// What the resolution of a neighbour reads.
struct Lookup<'a, 'n> {
    interfaces_of: &'a InterfacesOf<'n>,
    stacks: &'a Stacks,
    domains: &'a [&'a str],
    aliases: &'a Aliases,
    unreadable: &'a dyn Fn(&str) -> bool,
}

/// The interfaces whose label is one of the `wanted` interface keys.
fn labelled<'n>(interfaces: &'n Interfaces, wanted: &BTreeSet<String>) -> Vec<&'n NbInterface> {
    interfaces
        .values()
        .filter(|interface| !interface.label.is_empty() && wanted.contains(&interface_key(&interface.label)))
        .collect()
}

/// The NetBox end the neighbour tells, or why it tells none.
fn resolve(neighbor: &Neighbor, lookup: &Lookup<'_, '_>) -> Result<End, Unresolved> {
    let remote = neighbor.remote_interface.as_deref();
    let Some(name) = neighbor.announced_name() else {
        let cause = if remote.is_none() { Cause::Anonymous } else { Cause::Nameless };
        return Err(Unresolved::new(cause, "", remote));
    };
    let Some(announced) = remote else {
        return Err(Unresolved::new(Cause::Portless, name, None));
    };
    let port = long_interface_name(announced, None);
    // The name as announced first: a host's `eth3` is not Cisco's `Eth3` (Ethernet3).
    let mut ports = vec![announced];
    if port != announced {
        ports.push(&port);
    }
    let mut known_device: Option<String> = None;
    let mut unreadable_device: Option<String> = None;
    let wanted: BTreeSet<String> = ports.iter().map(|port_name| interface_key(port_name)).collect();

    // By name on every candidate device first: a label never beats a name. The
    // devices are read one after the other, and no further than the one found.
    let mut readable: Vec<(String, &Interfaces)> = Vec::new();
    for device in devices_to_try(neighbor, lookup.stacks, lookup.domains, lookup.aliases) {
        let Some(interfaces) = (lookup.interfaces_of)(&device) else {
            if unreadable_device.is_none() && (lookup.unreadable)(&device) {
                unreadable_device = Some(device);
            }
            continue;
        };
        if known_device.is_none() {
            known_device = Some(device.clone());
        }
        if announced == MANAGEMENT_PORT {
            let managed: Vec<&NbInterface> = interfaces.values().filter(|interface| interface.mgmt_only).collect();
            if let [only] = managed.as_slice() {
                return Ok(End::new(&device, &only.name));
            }
            continue;
        }
        let found = ports.iter().find_map(|port_name| interfaces.get(&interface_key(port_name)));
        if let Some(found) = found {
            // A firewall port announces its label (its alias), not its name: when
            // another interface carries the port as its label, nothing tells which
            // of the two is plugged in.
            if labelled(interfaces, &wanted).into_iter().any(|interface| !std::ptr::eq(interface, found)) {
                return Err(Unresolved::new(Cause::AmbiguousPort, &device, remote));
            }
            return Ok(End::new(&device, &found.name));
        }
        readable.push((device, interfaces));
    }
    // Then by label; a label two interfaces share names neither.
    for (device, interfaces) in &readable {
        if let [only] = labelled(interfaces, &wanted).as_slice() {
            return Ok(End::new(device, &only.name));
        }
    }
    if let Some(device) = known_device {
        let cause = if announced == MANAGEMENT_PORT { Cause::NoManagement } else { Cause::UnknownPort };
        return Err(Unresolved::new(cause, &device, remote));
    }
    // Not found, but a candidate could not be read: it may well exist.
    if let Some(device) = unreadable_device {
        return Err(Unresolved::new(Cause::Unreadable, &device, remote));
    }
    Err(Unresolved::new(Cause::UnknownDevice, name, remote))
}

/// One warning per cause and switch (or announced device), not per port: a
/// switch facing many servers that announce nothing usable stays readable.
fn unresolved_warnings(device: &str, unresolved: &[(String, Unresolved)], label: &PortLabel<'_>) -> Vec<String> {
    // The local ports of the neighbours unresolved for `cause`, about `name` when given.
    let locals = |cause: Cause, name: Option<&str>| -> BTreeSet<&str> {
        unresolved
            .iter()
            .filter(|(_, u)| u.cause == cause && name.is_none_or(|name| u.device == name))
            .map(|(local, _)| local.as_str())
            .collect()
    };
    // The same, each with the port its neighbour announces.
    let pairs = |cause: Cause, name: Option<&str>| -> BTreeSet<(&str, &str)> {
        unresolved
            .iter()
            .filter(|(_, u)| u.cause == cause && name.is_none_or(|name| u.device == name))
            .map(|(local, u)| (local.as_str(), u.port_text()))
            .collect()
    };
    // The devices named by the neighbours unresolved for `cause`, sorted.
    let devices = |cause: Cause| -> BTreeSet<&str> {
        unresolved.iter().filter(|(_, u)| u.cause == cause).map(|(_, u)| u.device.as_str()).collect()
    };
    // The local ports with the device and port their neighbour names, in port order.
    let by_port = |cause: Cause| {
        let found: BTreeSet<(&str, &str, &str)> = unresolved
            .iter()
            .filter(|(_, u)| u.cause == cause)
            .map(|(local, u)| (local.as_str(), u.device.as_str(), u.port_text()))
            .collect();
        let mut found: Vec<(&str, &str, &str)> = found.into_iter().collect();
        found.sort_by_cached_key(|(local, _, _)| natural(local));
        found
    };
    let ports = |locals: &BTreeSet<&str>| -> String {
        let mut sorted: Vec<&str> = locals.iter().copied().collect();
        sorted.sort_by_cached_key(|local| natural(local));
        sorted.into_iter().map(|local| label(device, local)).collect::<Vec<_>>().join(", ")
    };
    let links = |pairs: &BTreeSet<(&str, &str)>| -> String {
        let mut sorted: Vec<(&str, &str)> = pairs.iter().copied().collect();
        sorted.sort_by_cached_key(|(local, _)| natural(local));
        sorted
            .into_iter()
            .map(|(local, remote)| format!("{} -> {remote}", label(device, local)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    // "1 neighbour announces", "2 neighbours announce".
    let counted = |count: usize| -> String {
        if count == 1 { "1 neighbour announces".to_owned() } else { format!("{count} neighbours announce") }
    };

    let mut warnings = Vec::new();
    let anonymous = locals(Cause::Anonymous, None);
    if !anonymous.is_empty() {
        warnings.push(format!(
            "{device}: {} neither a name nor a port ({})",
            counted(anonymous.len()),
            ports(&anonymous)
        ));
    }
    let nameless = pairs(Cause::Nameless, None);
    if !nameless.is_empty() {
        let nameless_ports = locals(Cause::Nameless, None);
        warnings.push(format!("{device}: {} no name ({})", counted(nameless_ports.len()), links(&nameless)));
    }
    for name in devices(Cause::Portless) {
        let found = locals(Cause::Portless, Some(name));
        warnings.push(format!("{device}: neighbour {name} announces no port ({})", ports(&found)));
    }
    for name in devices(Cause::Unreadable) {
        let found = pairs(Cause::Unreadable, Some(name));
        warnings.push(format!("{device}: neighbour {name} could not be read from Netbox ({})", links(&found)));
    }
    for name in devices(Cause::UnknownDevice) {
        let found = pairs(Cause::UnknownDevice, Some(name));
        warnings.push(format!("{device}: neighbour {name} is not a Netbox device ({})", links(&found)));
    }
    for (local, remote_device, port) in by_port(Cause::UnknownPort) {
        warnings.push(format!(
            "{device} {}: {remote_device} has no interface {} in Netbox",
            label(device, local),
            quoted(port)
        ));
    }
    for (local, remote_device, port) in by_port(Cause::AmbiguousPort) {
        warnings.push(format!(
            "{device} {}: {remote_device} has {} both as an interface name and as the label of another interface \
             in Netbox",
            label(device, local),
            quoted(port)
        ));
    }
    let mut unmanaged: Vec<(&str, &str)> = unresolved
        .iter()
        .filter(|(_, u)| u.cause == Cause::NoManagement)
        .map(|(local, u)| (local.as_str(), u.device.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    unmanaged.sort_by_cached_key(|(local, _)| natural(local));
    for (local, remote_device) in unmanaged {
        warnings.push(format!(
            "{device} {}: {remote_device} has no single management interface in Netbox",
            label(device, local)
        ));
    }
    warnings
}

fn local_end(device: &str, interfaces: Option<&Interfaces>, port: &str) -> Option<End> {
    let local = interfaces?.get(&interface_key(port))?;
    Some(End::new(device, &local.name))
}

/// The two ends of a cable, whichever way round: ordered by label, as the
/// changes print them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Pair {
    a: End,
    b: End,
}

impl Pair {
    fn new(one: End, other: End) -> Self {
        if (end_label(&one), &one) <= (end_label(&other), &other) {
            Pair { a: one, b: other }
        } else {
            Pair { a: other, b: one }
        }
    }

    fn ends(&self) -> [&End; 2] {
        [&self.a, &self.b]
    }
}

/// Resolve the neighbours into cable pairs.
///
/// Local ends whose neighbour is unresolved or ambiguous go into `protected`:
/// the prune must not delete their current cable, since nothing proves it wrong.
fn wanted_pairs(
    neighbors: &BTreeMap<String, Vec<Neighbor>>,
    lookup: &Lookup<'_, '_>,
    warnings: &mut Vec<String>,
    protected: &mut BTreeSet<End>,
    label: &PortLabel<'_>,
    heard: &mut BTreeSet<Pair>,
) -> BTreeSet<Pair> {
    let mut pairs: BTreeSet<Pair> = BTreeSet::new();
    for (device, found) in neighbors {
        // The ports where a host hears this switch: their cable is the host's to tell.
        let by_host: BTreeSet<&str> = found
            .iter()
            .filter(|neighbor| neighbor.protocol == HOST)
            .map(|neighbor| neighbor.local_interface.as_str())
            .collect();
        let local_interfaces = (lookup.interfaces_of)(device);
        let mut remotes: BTreeMap<&str, BTreeSet<End>> = BTreeMap::new();
        let mut unresolved: Vec<(String, Unresolved)> = Vec::new();
        for neighbor in found {
            match resolve(neighbor, lookup) {
                Ok(remote) => {
                    remotes.entry(&neighbor.local_interface).or_default().insert(remote);
                }
                Err(cause) => {
                    unresolved.push((neighbor.local_interface.clone(), cause));
                    if let Some(end) = local_end(device, local_interfaces, &neighbor.local_interface) {
                        protected.insert(end);
                    }
                }
            }
        }
        // A port another neighbour already resolved has its cable: the extra announcer (a
        // NIC firmware LLDP agent next to the host's CDP) says nothing worth a warning.
        unresolved.retain(|(local, _)| !remotes.contains_key(local.as_str()));
        warnings.extend(unresolved_warnings(device, &unresolved, label));
        for (port, found) in remotes {
            let local = local_end(device, local_interfaces, port);
            if found.len() > 1 {
                let mut labels: Vec<String> = found.iter().map(end_label).collect();
                labels.sort();
                warnings.push(format!("{device} {}: neighbours disagree ({})", label(device, port), labels.join(", ")));
                if let Some(local) = local {
                    protected.insert(local);
                }
                continue;
            }
            let Some(remote) = found.into_iter().next() else {
                continue;
            };
            let Some(local) = local else {
                warnings.push(format!("{device} {}: interface not in Netbox yet", label(device, port)));
                continue;
            };
            // A port that hears itself (a looped cable) is no cable NetBox can hold. The
            // Python tool stops there on an error; here the port warns and keeps its cable.
            if local == remote {
                warnings.push(format!("{device} {}: the neighbour is the port itself", label(device, port)));
                protected.insert(local);
                continue;
            }
            if by_host.contains(port) {
                heard.insert(Pair::new(local.clone(), remote.clone()));
            }
            pairs.insert(Pair::new(local, remote));
        }
    }
    // An end claimed by two different links cannot be cabled twice: write neither.
    let mut claims: BTreeMap<End, Vec<Pair>> = BTreeMap::new();
    for pair in &pairs {
        for end in pair.ends() {
            claims.entry(end.clone()).or_default().push(pair.clone());
        }
    }
    let mut claimed: Vec<(&End, &Vec<Pair>)> = claims.iter().collect();
    claimed.sort_by_cached_key(|(end, _)| end_label(end));
    for (end, links) in claimed {
        if links.len() > 1 {
            let mut others: Vec<String> =
                links.iter().flat_map(Pair::ends).filter(|other| *other != end).map(end_label).collect();
            others.sort();
            warnings.push(format!("{} is claimed by several links ({})", end_label(end), others.join(", ")));
            for pair in links {
                pairs.remove(pair);
                protected.extend(pair.ends().into_iter().cloned());
            }
        }
    }
    pairs
}

/// `down` holds the (device, interface_key) of synced ports whose link is down;
/// `aliases` maps names announced by neighbours to Netbox device names;
/// `unpruned` holds the synced devices read from a configuration report, which
/// shows no link: their cables are created, never deleted nor replaced;
/// `unreadable` tells the devices whose Netbox read failed (`interfaces_of`
/// gives None for them too), named as such in the warnings; `descriptions` holds
/// each synced device's port descriptions (key: interface_key), quoted after the
/// local port in the warnings: what is plugged in, when the neighbour cannot say.
///
/// Gives the cable changes, deletions of a replaced cable before its
/// replacement, and the warnings.
pub fn diff_cables(
    neighbors: &BTreeMap<String, Vec<Neighbor>>,
    interfaces_of: &InterfacesOf<'_>,
    cables: &[NbCable],
    options: &CableOptions<'_>,
) -> (Vec<Change>, Vec<String>) {
    let mut warnings: Vec<String> = Vec::new();
    let mut protected: BTreeSet<End> = BTreeSet::new();
    let port_label = port_labeller(options.descriptions);
    let lookup = Lookup {
        interfaces_of,
        stacks: options.stacks,
        domains: options.domains,
        aliases: options.aliases,
        unreadable: options.unreadable,
    };
    let mut heard: BTreeSet<Pair> = BTreeSet::new();
    let pairs = wanted_pairs(neighbors, &lookup, &mut warnings, &mut protected, &port_label, &mut heard);
    // A neighbour announces a device in its own letter case, and NetBox reads a
    // device by a caseless name: an end is written as NetBox (its cables) or,
    // failing that, the configuration (the synced devices) spell that device,
    // so that it is compared with them as one and the same. NetBox comes last:
    // its spelling is the one kept.
    let spellings: BTreeMap<String, &str> = options
        .synced
        .iter()
        .map(String::as_str)
        .chain(neighbors.keys().map(String::as_str))
        .chain(cables.iter().flat_map(|cable| [cable.a.device.as_str(), cable.b.device.as_str()]))
        .map(|name| (name.to_lowercase(), name))
        .collect();
    // Whether a device NetBox spells its own way is one of `names`.
    let among = |names: &BTreeSet<String>, device: &str| names.iter().any(|name| name.eq_ignore_ascii_case(device));
    let spelled = |end: End| match spellings.get(&end.device.to_lowercase()) {
        Some(name) if *name != end.device => End::new(name, &end.interface),
        _ => end,
    };
    let pairs: BTreeSet<Pair> = pairs.into_iter().map(|pair| Pair::new(spelled(pair.a), spelled(pair.b))).collect();
    let heard: BTreeSet<Pair> = heard.into_iter().map(|pair| Pair::new(spelled(pair.a), spelled(pair.b))).collect();
    let protected: BTreeSet<End> = protected.into_iter().map(spelled).collect();
    let mut cable_at: BTreeMap<&End, &NbCable> = BTreeMap::new();
    for cable in cables {
        cable_at.insert(&cable.a, cable);
        cable_at.insert(&cable.b, cable);
    }

    // Whether the cable may be deleted: both ends synced, neither from a report.
    let between_synced = |cable: &NbCable| -> bool {
        [&cable.a.device, &cable.b.device]
            .into_iter()
            .all(|device| among(options.synced, device) && !among(options.unpruned, device))
    };

    let known: BTreeSet<u64> = cables.iter().map(|cable| cable.id).collect();

    // A cable read_cables left out (patch panel, circuit, multi-termination).
    let foreign_cable = |end: &End| -> Option<u64> {
        let interface = interfaces_of(&end.device)?.get(&interface_key(&end.interface))?;
        interface.cable_id.filter(|cable_id| !known.contains(cable_id))
    };

    let deletion = |cable_id: u64| Change::new("cable", Action::Delete, "", &format!("cable {cable_id}")).id(cable_id);

    let mut deleted: BTreeSet<u64> = BTreeSet::new();
    let mut changes: Vec<Change> = Vec::new();
    let mut ordered: Vec<&Pair> = pairs.iter().collect();
    ordered.sort_by_cached_key(|pair| (end_label(&pair.a), end_label(&pair.b)));
    for pair in ordered {
        let (a, b) = (&pair.a, &pair.b);
        let label = format!("{} <-> {}", end_label(a), end_label(b));
        let existing: BTreeMap<u64, &NbCable> =
            pair.ends().into_iter().filter_map(|end| cable_at.get(end)).map(|cable| (cable.id, *cable)).collect();
        if let (1, Some(cable)) = (existing.len(), existing.values().next())
            && Pair::new(cable.a.clone(), cable.b.clone()) == *pair
        {
            continue;
        }
        // Only a cable joining two synced switches may be replaced, and only with prune.
        let foreign: BTreeSet<u64> = pair.ends().into_iter().filter_map(foreign_cable).collect();
        if !existing.is_empty() || !foreign.is_empty() {
            let replaceable = existing.values().all(|cable| between_synced(cable));
            // What the card of a host hears is a proof of its own: its cable
            // replaces the one NetBox has, prune or not, report or not.
            let by_host = heard.contains(pair);
            let replaced = foreign.is_empty() && (by_host || options.prune && replaceable);
            if !replaced {
                let ids: BTreeSet<u64> = existing.keys().chain(&foreign).copied().collect();
                let ids = ids.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
                warnings.push(format!("cable {label} not written: an end is already cabled (cable {ids})"));
                continue;
            }
            for cable_id in existing.keys() {
                if deleted.insert(*cable_id) {
                    changes.push(deletion(*cable_id));
                }
            }
            if by_host {
                let ids = existing.keys().map(u64::to_string).collect::<Vec<_>>().join(", ");
                warnings.push(format!("cable {label} replaces cable {ids}: the host hears it"));
            }
        }
        changes.push(Change::new("cable", Action::Create, "", &label).fields([
            ("a_device", a.device.as_str()),
            ("a_interface", a.interface.as_str()),
            ("b_device", b.device.as_str()),
            ("b_interface", b.interface.as_str()),
        ]));
    }
    if options.prune {
        for cable in cables {
            if deleted.contains(&cable.id) || !between_synced(cable) {
                continue;
            }
            if protected.contains(&cable.a) || protected.contains(&cable.b) {
                continue;
            }
            // A link down shows no neighbour, yet the cable is still plugged in.
            if [&cable.a, &cable.b].into_iter().any(|end| {
                let key = interface_key(&end.interface);
                options.down.iter().any(|(device, port)| device.eq_ignore_ascii_case(&end.device) && *port == key)
            }) {
                continue;
            }
            if !pairs.contains(&Pair::new(cable.a.clone(), cable.b.clone())) {
                deleted.insert(cable.id);
                changes.push(deletion(cable.id));
            }
        }
    }
    (changes, warnings)
}

/// Ports whose description names a Netbox device none of their LLDP or CDP
/// neighbours announces: a server moved, a description left stale.
///
/// Only the device names are compared, as the cable resolver compares them (case,
/// domains, aliases): ports are named too differently from one device to another.
/// A description naming no Netbox device is a label (`FGT-HA`), never compared.
pub fn description_mismatches(
    device: &str,
    described: &[Neighbor],
    announced: &[Neighbor],
    domains: &[&str],
    aliases: &Aliases,
    in_netbox: &dyn Fn(&str) -> bool,
    label: &PortLabel<'_>,
) -> Vec<String> {
    let folded = |name: &str| -> BTreeSet<String> {
        name_family(name, domains, aliases).iter().map(|name| name.to_lowercase()).collect()
    };
    let mut named: BTreeMap<String, Vec<&Neighbor>> = BTreeMap::new();
    for neighbor in announced {
        if neighbor.protocol != PROTOCOL && neighbor.announced_name().is_some() {
            named.entry(interface_key(&neighbor.local_interface)).or_default().push(neighbor);
        }
    }
    let mut claims: Vec<&Neighbor> = described.iter().collect();
    claims.sort_by_cached_key(|claim| natural(&claim.local_interface));
    let mut warnings = Vec::new();
    for claim in claims {
        let Some(speakers) = named.get(&interface_key(&claim.local_interface)) else {
            continue;
        };
        let family = name_family(&claim.remote_device, domains, aliases);
        let Some(existing) = family.iter().find(|name| in_netbox(name)) else {
            continue;
        };
        let wanted = folded(&claim.remote_device);
        if speakers.iter().any(|speaker| !wanted.is_disjoint(&folded(&speaker.remote_device))) {
            continue;
        }
        let heard: Vec<String> =
            speakers.iter().map(|speaker| format!("{} ({})", speaker.remote_device, speaker.protocol)).collect();
        warnings.push(format!(
            "{device} {}: the description names {existing}, the neighbour announces {}",
            label(device, &claim.local_interface),
            heard.join(", ")
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::super::descriptions::MANAGEMENT_PORT;
    use super::super::state::End;
    use super::*;
    use crate::change::Action;

    const DOMAINS: [&str; 1] = ["switch.example.com"];
    const BROADCOM: &str = "Broadcom Adv. Dual 10GBASE-T Ethernet fw_version:AFW_229.2.52.0";

    type Netbox = BTreeMap<String, Interfaces>;

    fn iface(id: u64, name: &str) -> NbInterface {
        NbInterface { mtu: Some(1500), r#type: Some("10gbase-x-sfpp".to_owned()), ..NbInterface::new(id, name) }
    }

    fn labelled(id: u64, name: &str, label: &str) -> NbInterface {
        NbInterface { label: label.to_owned(), ..iface(id, name) }
    }

    fn management(id: u64, name: &str) -> NbInterface {
        NbInterface { mgmt_only: true, ..iface(id, name) }
    }

    /// `netbox` with one more device, its interfaces keyed by their lower-cased name.
    fn with<const N: usize>(mut netbox: Netbox, device: &str, interfaces: [NbInterface; N]) -> Netbox {
        let keyed = interfaces.into_iter().map(|interface| (interface.name.to_lowercase(), interface)).collect();
        netbox.insert(device.to_owned(), keyed);
        netbox
    }

    fn netbox() -> Netbox {
        let netbox = with(Netbox::new(), "nexus01.lab01", [iface(1, "Ethernet1/48"), iface(2, "Ethernet1/30")]);
        let netbox = with(netbox, "nexus02.lab01", [iface(3, "Ethernet1/48")]);
        let netbox = with(netbox, "2960-stack02.lab01", [iface(4, "TenGigabitEthernet2/0/2")]);
        with(netbox, "esx08.lab01", [iface(5, "vmnic1")])
    }

    fn firewalls() -> Netbox {
        let netbox = with(
            netbox(),
            "fw01.lab01",
            [labelled(10, "a", "HA"), labelled(11, "b", "HA2"), labelled(12, "ha2", "spare")],
        );
        with(netbox, "fw02.lab01", [labelled(13, "a", "uplink"), labelled(14, "b", "Uplink")])
    }

    fn server<const N: usize>(interfaces: [NbInterface; N]) -> Netbox {
        with(netbox(), "lab1-pve01.prod", interfaces)
    }

    fn neighbor(local: &str, device: &str, remote: Option<&str>, protocol: &str) -> Neighbor {
        Neighbor {
            local_interface: local.to_owned(),
            remote_device: device.to_owned(),
            remote_interface: remote.map(str::to_owned),
            protocol: protocol.to_owned(),
        }
    }

    fn told<const N: usize>(neighbors: [(&str, Vec<Neighbor>); N]) -> BTreeMap<String, Vec<Neighbor>> {
        neighbors.into_iter().map(|(device, found)| (device.to_owned(), found)).collect()
    }

    fn names<const N: usize>(names: [&str; N]) -> BTreeSet<String> {
        names.into_iter().map(str::to_owned).collect()
    }

    fn strings<const N: usize>(pairs: [(&str, &str); N]) -> BTreeMap<String, String> {
        pairs.into_iter().map(|(key, value)| (key.to_owned(), value.to_owned())).collect()
    }

    fn stacks() -> Stacks {
        let members = BTreeMap::from([(1, "2960-stack01.lab01".to_owned()), (2, "2960-stack02.lab01".to_owned())]);
        BTreeMap::from([("2960-stack.lab01".to_owned(), members)])
    }

    fn cable(id: u64, a: (&str, &str), b: (&str, &str)) -> NbCable {
        NbCable { id, a: End::new(a.0, a.1), b: End::new(b.0, b.1) }
    }

    fn good_48() -> NbCable {
        cable(8, ("nexus01.lab01", "Ethernet1/48"), ("nexus02.lab01", "Ethernet1/48"))
    }

    fn create(a: (&str, &str), b: (&str, &str)) -> Change {
        let key = format!("{}:{} <-> {}:{}", a.0, a.1, b.0, b.1);
        Change::new("cable", Action::Create, "", &key).fields([
            ("a_device", a.0),
            ("a_interface", a.1),
            ("b_device", b.0),
            ("b_interface", b.1),
        ])
    }

    fn create_48() -> Change {
        create(("nexus01.lab01", "Ethernet1/48"), ("nexus02.lab01", "Ethernet1/48"))
    }

    fn delete(id: u64, key: &str) -> Change {
        Change::new("cable", Action::Delete, "", key).id(id)
    }

    fn keys(changes: &[Change]) -> Vec<&str> {
        changes.iter().map(|change| change.key.as_str()).collect()
    }

    /// The two ends of a created cable, whatever their order.
    fn ends(change: &Change) -> BTreeSet<(String, String)> {
        let text = |field: &str| change.fields[field].as_str().expect("a JSON string").to_owned();
        BTreeSet::from([(text("a_device"), text("a_interface")), (text("b_device"), text("b_interface"))])
    }

    fn two_ends(a: (&str, &str), b: (&str, &str)) -> BTreeSet<(String, String)> {
        BTreeSet::from([(a.0.to_owned(), a.1.to_owned()), (b.0.to_owned(), b.1.to_owned())])
    }

    /// One run of `diff_cables`, with the defaults of the lab: both Nexus synced,
    /// the 2960 stack known, no prune.
    struct Run {
        neighbors: BTreeMap<String, Vec<Neighbor>>,
        cables: Vec<NbCable>,
        stacks: Stacks,
        synced: BTreeSet<String>,
        prune: bool,
        netbox: Netbox,
        down: BTreeSet<(String, String)>,
        aliases: Aliases,
        unpruned: BTreeSet<String>,
        unreadable: BTreeSet<String>,
        descriptions: Option<Descriptions>,
    }

    impl Run {
        fn new<const N: usize>(neighbors: [(&str, Vec<Neighbor>); N]) -> Self {
            Run {
                neighbors: told(neighbors),
                cables: Vec::new(),
                stacks: stacks(),
                synced: names(["nexus01.lab01", "nexus02.lab01"]),
                prune: false,
                netbox: netbox(),
                down: BTreeSet::new(),
                aliases: Aliases::new(),
                unpruned: BTreeSet::new(),
                unreadable: BTreeSet::new(),
                descriptions: None,
            }
        }

        fn cables<const N: usize>(mut self, cables: [NbCable; N]) -> Self {
            self.cables = cables.into();
            self
        }

        fn prune(mut self, prune: bool) -> Self {
            self.prune = prune;
            self
        }

        fn netbox(mut self, netbox: Netbox) -> Self {
            self.netbox = netbox;
            self
        }

        fn synced<const N: usize>(mut self, synced: [&str; N]) -> Self {
            self.synced = names(synced);
            self
        }

        fn down(mut self, device: &str, key: &str) -> Self {
            self.down = BTreeSet::from([(device.to_owned(), key.to_owned())]);
            self
        }

        fn aliases<const N: usize>(mut self, aliases: [(&str, &str); N]) -> Self {
            self.aliases = strings(aliases);
            self
        }

        fn unpruned<const N: usize>(mut self, unpruned: [&str; N]) -> Self {
            self.unpruned = names(unpruned);
            self
        }

        fn go(&self) -> (Vec<Change>, Vec<String>) {
            let options = CableOptions {
                stacks: &self.stacks,
                domains: &DOMAINS,
                synced: &self.synced,
                prune: self.prune,
                down: &self.down,
                aliases: &self.aliases,
                unpruned: &self.unpruned,
                unreadable: &|device| self.unreadable.contains(device),
                descriptions: self.descriptions.as_ref(),
            };
            diff_cables(&self.neighbors, &|device| self.netbox.get(device), &self.cables, &options)
        }
    }

    #[test]
    fn link_seen_from_both_sides_gives_one_cable() {
        let (changes, warnings) = Run::new([
            ("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")]),
            ("nexus02.lab01", vec![neighbor("Ethernet1/48", "nexus01.lab01", Some("Ethernet1/48"), "lldp")]),
        ])
        .go();
        assert_eq!(changes, [create_48()]);
        assert_eq!(warnings, [""; 0]);
    }

    #[test]
    fn domain_is_stripped_and_stack_member_resolved() {
        let (changes, _) = Run::new([(
            "nexus01.lab01",
            vec![neighbor(
                "Ethernet1/30",
                "2960-stack.lab01.switch.example.com",
                Some("TenGigabitEthernet2/0/2"),
                "lldp",
            )],
        )])
        .go();
        // Ends are sorted by label: "2960-stack02..." sorts before "nexus01...".
        let a_ends: Vec<(&Value, &Value)> =
            changes.iter().map(|change| (&change.fields["a_device"], &change.fields["a_interface"])).collect();
        assert_eq!(a_ends, [(&json!("2960-stack02.lab01"), &json!("TenGigabitEthernet2/0/2"))]);
    }

    #[test]
    fn lldp_and_cdp_disagreeing_write_nothing() {
        let (changes, warnings) = Run::new([(
            "nexus01.lab01",
            vec![
                neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp"),
                neighbor("Ethernet1/48", "esx08.lab01", Some("vmnic1"), "lldp"),
            ],
        )])
        .go();
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            ["nexus01.lab01 Ethernet1/48: neighbours disagree (esx08.lab01:vmnic1, nexus02.lab01:Ethernet1/48)"]
        );
    }

    #[test]
    fn mac_port_id_is_unresolved() {
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "not advertised", None, "lldp")])]).go();
        assert_eq!(changes, []);
        assert_eq!(warnings, ["nexus01.lab01: 1 neighbour announces neither a name nor a port (Ethernet1/48)"]);
    }

    #[test]
    fn existing_cable_gives_nothing() {
        let (changes, _) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")])])
                .cables([good_48()])
                .prune(true)
                .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn occupied_by_cable_to_unsynced_device() {
        for prune in [false, true] {
            let (changes, warnings) = Run::new([(
                "nexus01.lab01",
                vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")],
            )])
            .cables([cable(9, ("nexus01.lab01", "Ethernet1/48"), ("esx08.lab01", "vmnic1"))])
            .prune(prune)
            .go();
            assert_eq!(changes, []);
            assert_eq!(
                warnings,
                [concat!(
                    "cable nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48 ",
                    "not written: an end is already cabled (cable 9)"
                )]
            );
        }
    }

    #[test]
    fn end_cabled_to_a_non_interface_termination_is_occupied() {
        // A patch-panel front port or a circuit: read_cables leaves such a cable out,
        // only the interface's own cable reference shows the port is taken.
        let taken_on_nexus01 = (
            with(netbox(), "nexus01.lab01", [NbInterface { cable_id: Some(77), ..iface(1, "Ethernet1/48") }]),
            concat!(
                "cable nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48 ",
                "not written: an end is already cabled (cable 77)"
            ),
        );
        let taken_on_nexus02 = (
            with(netbox(), "nexus02.lab01", [NbInterface { cable_id: Some(78), ..iface(3, "Ethernet1/48") }]),
            concat!(
                "cable nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48 ",
                "not written: an end is already cabled (cable 78)"
            ),
        );
        for (taken, warning) in [taken_on_nexus01, taken_on_nexus02] {
            for prune in [false, true] {
                let (changes, warnings) = Run::new([(
                    "nexus01.lab01",
                    vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")],
                )])
                .prune(prune)
                .netbox(taken.clone())
                .go();
                assert_eq!(changes, []);
                assert_eq!(warnings, [warning]);
            }
        }
    }

    #[test]
    fn occupied_by_stale_cable_between_synced_switches() {
        let run = |prune: bool| {
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")])])
                .cables([cable(10, ("nexus01.lab01", "Ethernet1/48"), ("nexus02.lab01", "Ethernet1/47"))])
                .prune(prune)
                .go()
        };
        let (changes, _) = run(true);
        assert_eq!(changes, [delete(10, "cable 10"), create_48()]);
        let (changes, warnings) = run(false);
        assert_eq!(changes, []);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn prune_deletes_stale_cable_between_synced_switches() {
        let stale = cable(11, ("nexus01.lab01", "Ethernet1/30"), ("nexus02.lab01", "Ethernet1/48"));
        let (changes, _) = Run::new([]).cables([stale.clone()]).prune(true).go();
        assert_eq!(changes, [delete(11, "cable 11")]);
        assert_eq!(Run::new([]).cables([stale]).prune(false).go(), (vec![], vec![]));
    }

    #[test]
    fn prune_ignores_cables_to_unselected_switches() {
        // --source nexus01.lab01: nexus02 is a switch, but not synced in this run.
        let (changes, _) = Run::new([])
            .cables([cable(12, ("nexus01.lab01", "Ethernet1/30"), ("nexus02.lab01", "Ethernet1/48"))])
            .synced(["nexus01.lab01"])
            .prune(true)
            .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn local_interface_missing_in_netbox() {
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/9", "nexus02.lab01", Some("Ethernet1/48"), "cdp")])])
                .go();
        assert_eq!(changes, []);
        assert_eq!(warnings, ["nexus01.lab01 Ethernet1/9: interface not in Netbox yet"]);
    }

    #[test]
    fn prune_keeps_cable_when_neighbours_disagree() {
        // The spec says "no cable is written" on a disagreement: deleting is writing.
        let (changes, _) = Run::new([(
            "nexus01.lab01",
            vec![
                neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp"),
                neighbor("Ethernet1/48", "esx08.lab01", Some("vmnic1"), "lldp"),
            ],
        )])
        .cables([good_48()])
        .prune(true)
        .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn prune_keeps_cable_when_neighbour_is_unresolved() {
        let (changes, _) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/99"), "cdp")])])
                .cables([good_48()])
                .prune(true)
                .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn two_pairs_on_one_end_write_nothing() {
        let (changes, warnings) = Run::new([
            ("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")]),
            ("nexus02.lab01", vec![neighbor("Ethernet1/48", "nexus01.lab01", Some("Ethernet1/30"), "cdp")]),
        ])
        .go();
        assert_eq!(changes, []);
        let last = warnings.last().expect("a warning");
        assert!(last.contains("nexus02.lab01:Ethernet1/48 is claimed by several links"), "{last}");
    }

    #[test]
    fn prune_keeps_cable_whose_link_is_down() {
        // A shut port or a link down at run time shows no neighbour: the cable is still there.
        let silent =
            || Run::new([("nexus01.lab01", vec![]), ("nexus02.lab01", vec![])]).cables([good_48()]).prune(true);
        for (device, key) in [("nexus01.lab01", "ethernet1/48"), ("nexus02.lab01", "ethernet1/48")] {
            let (changes, _) = silent().down(device, key).go();
            assert_eq!(changes, []);
        }
        let (changes, _) = silent().go();
        assert_eq!(changes, [delete(8, "cable 8")]);
    }

    #[test]
    fn linux_port_name_is_not_read_as_a_cisco_abbreviation() {
        // `eth3` is a Linux interface, not Cisco's `Eth3` (Ethernet3).
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/30", "db02.lab01", Some("eth3"), "lldp")])])
                .netbox(with(netbox(), "db02.lab01", [iface(6, "eth3")]))
                .go();
        let found: Vec<_> = changes.iter().map(ends).collect();
        assert_eq!(found, [two_ends(("nexus01.lab01", "Ethernet1/30"), ("db02.lab01", "eth3"))]);
        assert_eq!(warnings, [""; 0]);
    }

    #[test]
    fn linux_port_id_parsed_from_lldp_is_resolved() {
        // lldpd set to `portidsubtype ifname` announces `eth3` as port ID: the parser must
        // not turn it into Cisco's Ethernet3 before the resolver tries the name as is.
        // The neighbour below is what the NX-OS parser of the Python tool gives for
        // `{"l_port_id": "Eth1/30", "sys_name": "db02.lab01", "port_id": "eth3",
        // "port_desc": "not advertised"}`; the parser is not part of this crate.
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/30", "db02.lab01", Some("eth3"), "lldp")])])
                .netbox(with(netbox(), "db02.lab01", [iface(6, "eth3")]))
                .go();
        assert_eq!(keys(&changes), ["db02.lab01:eth3 <-> nexus01.lab01:Ethernet1/30"]);
        assert_eq!(warnings, [""; 0]);
    }

    #[test]
    fn short_cisco_port_id_is_expanded_by_the_resolver() {
        // NX-OS LLDP reports the stack's port as `Te1/0/2`; Netbox holds the long name.
        let (changes, _) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/30", "2960-stack.lab01", Some("Te2/0/2"), "lldp")])])
                .go();
        assert_eq!(keys(&changes), ["2960-stack02.lab01:TenGigabitEthernet2/0/2 <-> nexus01.lab01:Ethernet1/30"]);
    }

    #[test]
    fn alias_maps_an_announced_name_to_a_netbox_device() {
        // A FortiGate announces its own hostname, not its Netbox device name.
        let run = || {
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/30", "FGT-81-Acme-Primaire", Some("HA2"), "lldp")])])
                .netbox(with(netbox(), "forti01.lab01", [iface(7, "HA2")]))
        };
        let (changes, _) = run().aliases([("FGT-81-Acme-Primaire", "forti01.lab01")]).go();
        let found: Vec<_> = changes.iter().map(ends).collect();
        assert_eq!(found, [two_ends(("nexus01.lab01", "Ethernet1/30"), ("forti01.lab01", "HA2"))]);
        let (unaliased, warnings) = run().go();
        assert_eq!(unaliased, []);
        assert_eq!(warnings.len(), 1);
    }

    // Unresolved neighbours: one warning per switch and cause, saying what to fix.

    #[test]
    fn neighbours_without_name_nor_port_are_grouped_per_switch() {
        let (_, warnings) = Run::new([(
            "nexus01.lab01",
            vec![neighbor("Ethernet1/16", "not advertised", None, "lldp"), neighbor("Ethernet1/15", "", None, "lldp")],
        )])
        .go();
        assert_eq!(
            warnings,
            ["nexus01.lab01: 2 neighbours announce neither a name nor a port (Ethernet1/15, Ethernet1/16)"]
        );
    }

    #[test]
    fn neighbours_without_name_are_grouped_with_their_ports() {
        let (_, warnings) = Run::new([(
            "nexus01.lab01",
            vec![
                neighbor("Ethernet1/40", "not advertised", Some("TenGigabitEthernet 1/12"), "lldp"),
                neighbor("Ethernet1/39", "not advertised", Some("TenGigabitEthernet 1/11"), "lldp"),
            ],
        )])
        .go();
        assert_eq!(
            warnings,
            [concat!(
                "nexus01.lab01: 2 neighbours announce no name ",
                "(Ethernet1/39 -> TenGigabitEthernet 1/11, Ethernet1/40 -> TenGigabitEthernet 1/12)"
            )]
        );
    }

    #[test]
    fn unknown_device_is_one_warning_per_switch_and_device() {
        let (_, warnings) = Run::new([(
            "nexus01.lab01",
            vec![
                neighbor("Ethernet1/38", "FGT-81-Acme-Primaire", Some("wan1"), "lldp"),
                neighbor("Ethernet1/37", "FGT-81-Acme-Primaire", Some("HA2"), "lldp"),
                neighbor("Ethernet1/39", "FGT-81-Acme-Secondaire", Some("HA"), "lldp"),
            ],
        )])
        .go();
        assert_eq!(
            warnings,
            [
                concat!(
                    "nexus01.lab01: neighbour FGT-81-Acme-Primaire is not a Netbox device ",
                    "(Ethernet1/37 -> HA2, Ethernet1/38 -> wan1)"
                ),
                "nexus01.lab01: neighbour FGT-81-Acme-Secondaire is not a Netbox device (Ethernet1/39 -> HA)",
            ]
        );
    }

    #[test]
    fn known_device_without_the_port_names_the_port() {
        // The only cause fixed port by port: the device exists, its interface does not.
        let (_, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/99"), "cdp")])])
                .go();
        assert_eq!(warnings, ["nexus01.lab01 Ethernet1/48: nexus02.lab01 has no interface 'Ethernet1/99' in Netbox"]);
    }

    #[test]
    fn named_neighbour_without_port_is_grouped_per_device() {
        let (_, warnings) = Run::new([(
            "nexus01.lab01",
            vec![
                neighbor("Ethernet1/9", "pve03.lab01", None, "lldp"),
                neighbor("Ethernet1/10", "pve03.lab01", None, "lldp"),
            ],
        )])
        .go();
        assert_eq!(warnings, ["nexus01.lab01: neighbour pve03.lab01 announces no port (Ethernet1/9, Ethernet1/10)"]);
    }

    #[test]
    fn unresolved_neighbours_still_protect_their_cable_from_prune() {
        let (changes, _) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "FGT-81-Acme-Primaire", Some("HA2"), "lldp")])])
                .cables([good_48()])
                .prune(true)
                .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn real_nexus01_neighbours_give_one_line_per_cause() {
        // From the raw nexus01 outputs: Eth1/15 and Eth1/16 announce `not advertised`
        // with a MAC port ID; Eth1/37-40 face FGT-81-Acme-Primaire, absent from this
        // Netbox; every other neighbour (nexus02, nexus03, the 2960s) resolves.
        //
        // The neighbours below are what the NX-OS parsers of the Python tool give for
        // its `nxos_i2` fixtures (`show lldp neighbors detail | json`, then
        // `show cdp neighbors detail | json`); the parsers are not part of this crate.
        let local = [
            "mgmt0",
            "Ethernet1/15",
            "Ethernet1/16",
            "Ethernet1/30",
            "Ethernet1/36",
            "Ethernet1/37",
            "Ethernet1/38",
            "Ethernet1/39",
            "Ethernet1/40",
            "Ethernet1/48",
            "Ethernet1/50",
            "Ethernet1/51",
            "Ethernet1/52",
        ];
        let mut netbox = Netbox::new();
        netbox.insert(
            "nexus01.lab01".to_owned(),
            local.iter().zip(0..).map(|(name, id)| (name.to_lowercase(), iface(id, name))).collect(),
        );
        let netbox = with(
            netbox,
            "nexus02.lab01",
            [iface(100, "mgmt0"), iface(101, "Ethernet1/48"), iface(102, "Ethernet1/51"), iface(103, "Ethernet1/52")],
        );
        let netbox = with(netbox, "nexus03.lab01", [iface(200, "Ethernet1/50")]);
        let netbox = with(netbox, "2960-stack01.lab01", [iface(300, "TenGigabitEthernet1/0/2")]);
        let netbox = with(netbox, "2960-admin.lab01", [iface(400, "TenGigabitEthernet1/0/2")]);
        let stack = "2960-stack.lab01.switch.example.com";
        let admin = "2960-admin.lab01.switch.example.com";
        let neighbors = vec![
            neighbor("mgmt0", "nexus02.lab01", Some("mgmt0"), "lldp"),
            neighbor("Ethernet1/15", "not advertised", None, "lldp"),
            neighbor("Ethernet1/16", "not advertised", None, "lldp"),
            neighbor("Ethernet1/30", stack, Some("Te1/0/2"), "lldp"),
            neighbor("Ethernet1/37", "FGT-81-Acme-Primaire", Some("HA2"), "lldp"),
            neighbor("Ethernet1/38", "FGT-81-Acme-Primaire", Some("wan1"), "lldp"),
            neighbor("Ethernet1/39", "FGT-81-Acme-Primaire", Some("internal5"), "lldp"),
            neighbor("Ethernet1/40", "FGT-81-Acme-Primaire", Some("internal3"), "lldp"),
            neighbor("Ethernet1/50", "nexus03.lab01", Some("Ethernet1/50"), "lldp"),
            neighbor("Ethernet1/51", "nexus02.lab01", Some("Ethernet1/52"), "lldp"),
            neighbor("Ethernet1/52", "nexus02.lab01", Some("Ethernet1/51"), "lldp"),
            neighbor("Ethernet1/30", stack, Some("TenGigabitEthernet1/0/2"), "cdp"),
            neighbor("Ethernet1/36", admin, Some("TenGigabitEthernet1/0/2"), "cdp"),
            neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp"),
            neighbor("Ethernet1/50", "nexus03.lab01", Some("Ethernet1/50"), "cdp"),
            neighbor("Ethernet1/51", "nexus02.lab01", Some("Ethernet1/52"), "cdp"),
            neighbor("Ethernet1/52", "nexus02.lab01", Some("Ethernet1/51"), "cdp"),
        ];
        let (_, warnings) = Run::new([("nexus01.lab01", neighbors)]).netbox(netbox).go();
        assert_eq!(
            warnings,
            [
                "nexus01.lab01: 2 neighbours announce neither a name nor a port (Ethernet1/15, Ethernet1/16)",
                concat!(
                    "nexus01.lab01: neighbour FGT-81-Acme-Primaire is not a Netbox device ",
                    "(Ethernet1/37 -> HA2, Ethernet1/38 -> wan1, Ethernet1/39 -> internal5, ",
                    "Ethernet1/40 -> internal3)"
                ),
            ]
        );
    }

    #[test]
    fn unresolved_neighbour_on_a_resolved_port_is_silent() {
        // esx09: the ESXi announces itself over CDP, its NIC firmware over LLDP under a name
        // Netbox cannot know; the CDP neighbour already gives the cable.
        let (changes, warnings) = Run::new([(
            "nexus01.lab01",
            vec![
                neighbor("Ethernet1/30", "esx08.lab01", Some("vmnic1"), "cdp"),
                neighbor("Ethernet1/30", BROADCOM, Some("NIC 1/10Gb BASE-TE"), "lldp"),
            ],
        )])
        .go();
        assert_eq!(changes, [create(("esx08.lab01", "vmnic1"), ("nexus01.lab01", "Ethernet1/30"))]);
        assert_eq!(warnings, [""; 0]);
    }

    #[test]
    fn unresolved_neighbour_alone_still_warns() {
        let (_, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/30", "unknown-host", Some("eth0"), "lldp")])]).go();
        assert_eq!(warnings, ["nexus01.lab01: neighbour unknown-host is not a Netbox device (Ethernet1/30 -> eth0)"]);
    }

    #[test]
    fn management_port_resolves_to_the_management_interface() {
        let switch = neighbor("Ethernet1/30", "lab1-pve01.prod", Some(MANAGEMENT_PORT), "description");
        let (changes, warnings) = Run::new([("nexus01.lab01", vec![switch])])
            .netbox(server([iface(10, "eno1"), management(11, "iDrac8")]))
            .go();
        assert_eq!(warnings, [""; 0]);
        let fields: Vec<_> = changes.iter().map(|change| change.fields.clone()).collect();
        let expected: crate::change::Fields = [
            ("a_device", "lab1-pve01.prod"),
            ("a_interface", "iDrac8"),
            ("b_device", "nexus01.lab01"),
            ("b_interface", "Ethernet1/30"),
        ]
        .into_iter()
        .map(|(field, value)| (field.to_owned(), json!(value)))
        .collect();
        assert_eq!(fields, [expected]);
    }

    #[test]
    fn management_port_needs_exactly_one_management_interface() {
        let none = server([iface(10, "eno1")]);
        let several = server([management(11, "iDrac8"), management(12, "BMC")]);
        for netbox in [none, several] {
            let switch = neighbor("Ethernet1/30", "lab1-pve01.prod", Some(MANAGEMENT_PORT), "description");
            let (changes, warnings) = Run::new([("nexus01.lab01", vec![switch])]).netbox(netbox).go();
            assert_eq!(changes, []);
            assert_eq!(
                warnings,
                ["nexus01.lab01 Ethernet1/30: lab1-pve01.prod has no single management interface in Netbox"]
            );
        }
    }

    #[test]
    fn prune_never_deletes_a_cable_of_a_report_switch() {
        // A configuration report shows no link: a cable it does not tell is not proven wrong.
        let (changes, _) = Run::new([("nexus01.lab01", vec![]), ("nexus02.lab01", vec![])])
            .cables([good_48()])
            .prune(true)
            .unpruned(["nexus02.lab01"])
            .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn cable_of_a_report_switch_is_never_replaced() {
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")])])
                .cables([cable(8, ("nexus01.lab01", "Ethernet1/30"), ("nexus02.lab01", "Ethernet1/48"))])
                .prune(true)
                .unpruned(["nexus02.lab01"])
                .go();
        assert_eq!(changes, []);
        assert_eq!(
            warnings.last().map(String::as_str),
            Some(concat!(
                "cable nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48 not written: ",
                "an end is already cabled (cable 8)"
            ))
        );
    }

    #[test]
    fn a_cable_a_host_hears_replaces_the_one_netbox_has_even_on_a_report_and_without_prune() {
        // esx08.lab01 vmnic1 hears the port of the report switch: the cable NetBox
        // has there, towards another device, goes; prune or not.
        let heard = neighbor("TenGigabitEthernet2/0/2", "esx08.lab01", Some("vmnic1"), HOST);
        let (changes, warnings) = Run::new([("2960-stack02.lab01", vec![heard])])
            .cables([cable(8, ("2960-stack02.lab01", "TenGigabitEthernet2/0/2"), ("nexus01.lab01", "Ethernet1/30"))])
            .synced(["2960-stack02.lab01"])
            .unpruned(["2960-stack02.lab01"])
            .go();
        let created = create(("2960-stack02.lab01", "TenGigabitEthernet2/0/2"), ("esx08.lab01", "vmnic1"));
        assert_eq!(changes, [delete(8, "cable 8"), created]);
        assert_eq!(
            warnings,
            ["cable 2960-stack02.lab01:TenGigabitEthernet2/0/2 <-> esx08.lab01:vmnic1 replaces cable 8: the host \
              hears it"]
        );
        // What a switch announces there still needs prune, and two synced switches.
        let announced = neighbor("TenGigabitEthernet2/0/2", "esx08.lab01", Some("vmnic1"), "cdp");
        let (changes, _) = Run::new([("2960-stack02.lab01", vec![announced])])
            .cables([cable(8, ("2960-stack02.lab01", "TenGigabitEthernet2/0/2"), ("nexus01.lab01", "Ethernet1/30"))])
            .synced(["2960-stack02.lab01"])
            .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn lookup_names_lists_every_device_a_neighbour_may_read() {
        // Read ahead of the diff, in parallel: the names the resolution may look up.
        let neighbors = told([
            ("nexus02.lab01", vec![neighbor("Ethernet1/1", "nexus01.lab01", Some("Ethernet1/48"), "cdp")]),
            (
                "nexus01.lab01",
                vec![
                    neighbor("Ethernet1/1", "nexus02.lab01.switch.example.com", Some("Ethernet1/48"), "cdp"),
                    // A stack: its member for the port, never the stack's own name.
                    neighbor("Ethernet1/2", "2960-stack.lab01", Some("Te2/0/2"), "cdp"),
                    neighbor("Ethernet1/3", "FGT-Primary", Some("port1"), "lldp"),
                    neighbor("Ethernet1/4", "", Some("Ethernet1/1"), "cdp"),
                    neighbor("Ethernet1/5", "not advertised", Some("Ethernet1/1"), "lldp"),
                    neighbor("Ethernet1/6", "esx08.lab01", None, "lldp"),
                    neighbor("Ethernet1/7", "nexus02.lab01", Some("Ethernet1/47"), "cdp"),
                ],
            ),
        ]);
        assert_eq!(
            lookup_names(&neighbors, &stacks(), &DOMAINS, &strings([("FGT-Primary", "forti01.lab01")])),
            [
                "nexus02.lab01.switch.example.com",
                "nexus02.lab01",
                "2960-stack02.lab01",
                "FGT-Primary",
                "forti01.lab01",
                "nexus01.lab01",
            ]
        );
    }

    #[test]
    fn neighbour_whose_read_failed_is_not_called_missing() {
        // interfaces_of gives None for both; only the caller knows the read failed.
        let mut unread = netbox();
        unread.remove("nexus02.lab01");
        let mut run =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")])])
                .cables([good_48()])
                .netbox(unread)
                .synced(["nexus01.lab01"])
                .prune(true);
        run.stacks = Stacks::new();
        run.unreadable = names(["nexus02.lab01"]);
        let (changes, warnings) = run.go();
        assert_eq!(
            warnings,
            ["nexus01.lab01: neighbour nexus02.lab01 could not be read from Netbox (Ethernet1/48 -> Ethernet1/48)"]
        );
        // Unresolved, the local end keeps its cable.
        assert_eq!(changes, []);
    }

    #[test]
    fn warnings_quote_the_description_of_the_local_port() {
        // The switch's description often tells what is plugged in where the
        // neighbour announces nothing usable; a port without one is listed bare.
        let mut run = Run::new([(
            "nexus01.lab01",
            vec![
                neighbor("Ethernet1/1", "", None, "lldp"),
                neighbor("Ethernet1/8", "", None, "lldp"),
                neighbor("Ethernet1/2", "", Some("eth0"), "lldp"),
                neighbor("Ethernet1/3", "pve03.lab01", None, "lldp"),
                neighbor("Ethernet1/4", "unknown-host", Some("eth0"), "lldp"),
                neighbor("Ethernet1/5", "nexus02.lab01", Some("Ethernet1/99"), "cdp"),
                neighbor("Ethernet1/6", "esx08.lab01", Some(MANAGEMENT_PORT), "description"),
                neighbor("Ethernet1/7", "broken.lab01", Some("eth0"), "lldp"),
                neighbor("Ethernet1/9", "esx08.lab01", Some("vmnic1"), "lldp"),
                neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp"),
                neighbor("Ethernet1/48", "esx08.lab01", Some("vmnic1"), "lldp"),
            ],
        )])
        .synced(["nexus01.lab01"]);
        run.stacks = Stacks::new();
        run.unreadable = names(["broken.lab01"]);
        run.descriptions = Some(BTreeMap::from([(
            "nexus01.lab01".to_owned(),
            strings([
                ("ethernet1/1", "esx03 vmnic2"),
                ("ethernet1/2", "nas01"),
                ("ethernet1/3", "pve03"),
                ("ethernet1/4", "srv"),
                ("ethernet1/5", "nexus02"),
                ("ethernet1/6", "esx08 idrac"),
                ("ethernet1/7", "broken"),
                ("ethernet1/9", "esx08 vmnic1"),
                ("ethernet1/48", "uplink"),
            ]),
        )]));
        let (_, warnings) = run.go();
        assert_eq!(
            warnings,
            [
                concat!(
                    "nexus01.lab01: 2 neighbours announce neither a name nor a port ",
                    r#"(Ethernet1/1 "esx03 vmnic2", Ethernet1/8)"#
                ),
                r#"nexus01.lab01: 1 neighbour announces no name (Ethernet1/2 "nas01" -> eth0)"#,
                r#"nexus01.lab01: neighbour pve03.lab01 announces no port (Ethernet1/3 "pve03")"#,
                concat!(
                    "nexus01.lab01: neighbour broken.lab01 could not be read from Netbox ",
                    r#"(Ethernet1/7 "broken" -> eth0)"#
                ),
                r#"nexus01.lab01: neighbour unknown-host is not a Netbox device (Ethernet1/4 "srv" -> eth0)"#,
                concat!(
                    r#"nexus01.lab01 Ethernet1/5 "nexus02": nexus02.lab01 has no interface "#,
                    "'Ethernet1/99' in Netbox"
                ),
                concat!(
                    r#"nexus01.lab01 Ethernet1/6 "esx08 idrac": esx08.lab01 has no single management "#,
                    "interface in Netbox"
                ),
                concat!(
                    r#"nexus01.lab01 Ethernet1/48 "uplink": neighbours disagree "#,
                    "(esx08.lab01:vmnic1, nexus02.lab01:Ethernet1/48)"
                ),
                r#"nexus01.lab01 Ethernet1/9 "esx08 vmnic1": interface not in Netbox yet"#,
            ]
        );
    }

    #[test]
    fn description_naming_another_netbox_device_than_the_neighbour_is_reported() {
        let described = [
            neighbor("Ethernet1/9", "pve03.lab01", Some("eno1"), "description"),
            neighbor("Ethernet1/12", "pve03.lab01", Some("eno2"), "description"),
            // A label, not a device: never compared.
            neighbor("Ethernet1/13", "fgt-ha", None, "description"),
            neighbor("Ethernet1/29", "esx09.lab01", Some("vmnic2"), "description"),
            neighbor("Ethernet1/30", "nexus02.lab01", None, "description"),
            neighbor("Ethernet1/31", "esx08.lab01", None, "description"),
            neighbor("Ethernet1/32", "forti01.lab01", None, "description"),
            // No named neighbour on the port: nothing to compare with.
            neighbor("Ethernet1/33", "esx07.lab01", None, "description"),
        ];
        let announced = [
            // Compared case-insensitively.
            neighbor("Ethernet1/9", "PVE03.lab01", Some("eno1"), "lldp"),
            neighbor("Ethernet1/12", "pve05.lab01", Some("eno2"), "lldp"),
            neighbor("Ethernet1/13", "FGT-81-Acme-Primaire", Some("HA2"), "lldp"),
            neighbor("Ethernet1/29", BROADCOM, Some("NIC 1/10Gb BASE-TE"), "lldp"),
            // Without its domain.
            neighbor("Ethernet1/30", "nexus02.lab01.switch.example.com", Some("Ethernet1/30"), "cdp"),
            // One neighbour of the port agreeing is enough: the NIC firmware speaks too.
            neighbor("Ethernet1/31", BROADCOM, Some("NIC 1/10Gb BASE-TE"), "lldp"),
            neighbor("Ethernet1/31", "esx08.lab01.switch.example.com", Some("vmnic1"), "cdp"),
            // Through its alias.
            neighbor("Ethernet1/32", "FGT-81-Acme-Primaire", Some("wan1"), "lldp"),
            neighbor("Ethernet1/33", "", None, "lldp"),
        ];
        let in_netbox = names([
            "pve03.lab01",
            "pve05.lab01",
            "nexus02.lab01",
            "esx07.lab01",
            "esx08.lab01",
            "esx09.lab01",
            "forti01.lab01",
        ]);
        let descriptions = BTreeMap::from([(
            "nexus01.lab01".to_owned(),
            strings([("ethernet1/12", "pve03.lab01/eno2/10G"), ("ethernet1/29", "esx09.lab01/vmnic2")]),
        )]);
        assert_eq!(
            description_mismatches(
                "nexus01.lab01",
                &described,
                &announced,
                &DOMAINS,
                &strings([("FGT-81-Acme-Primaire", "forti01.lab01")]),
                &|name| in_netbox.contains(name),
                &port_labeller(Some(&descriptions)),
            ),
            [
                concat!(
                    r#"nexus01.lab01 Ethernet1/12 "pve03.lab01/eno2/10G": the description names "#,
                    "pve03.lab01, the neighbour announces pve05.lab01 (lldp)"
                ),
                concat!(
                    r#"nexus01.lab01 Ethernet1/29 "esx09.lab01/vmnic2": the description names "#,
                    "esx09.lab01, the neighbour announces ",
                    "Broadcom Adv. Dual 10GBASE-T Ethernet fw_version:AFW_229.2.52.0 (lldp)"
                ),
            ]
        );
    }

    #[test]
    fn neighbour_port_is_found_by_its_label() {
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "fw01.lab01", Some("HA"), "lldp")])])
                .netbox(firewalls())
                .go();
        assert_eq!(warnings, [""; 0]);
        assert_eq!(keys(&changes), ["fw01.lab01:a <-> nexus01.lab01:Ethernet1/48"]);
    }

    #[test]
    fn port_that_is_a_name_and_another_interface_label_names_none() {
        // `HA2` is the label of `b` and, case aside, the name of `ha2`: nothing tells which.
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "fw01.lab01", Some("HA2"), "lldp")])])
                .netbox(firewalls())
                .go();
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            [concat!(
                "nexus01.lab01 Ethernet1/48: fw01.lab01 has 'HA2' both as an interface name and as ",
                "the label of another interface in Netbox"
            )]
        );
    }

    #[test]
    fn ambiguous_port_keeps_the_current_cable_from_the_prune() {
        let (changes, _) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "fw01.lab01", Some("HA2"), "lldp")])])
                .cables([cable(7, ("nexus01.lab01", "Ethernet1/48"), ("nexus02.lab01", "Ethernet1/48"))])
                .prune(true)
                .netbox(firewalls())
                .go();
        assert_eq!(changes, []);
    }

    #[test]
    fn interface_named_as_its_own_label_is_found() {
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "fw03.lab01", Some("wan1"), "lldp")])])
                .netbox(with(netbox(), "fw03.lab01", [labelled(20, "wan1", "WAN1")]))
                .go();
        assert_eq!(warnings, [""; 0]);
        assert_eq!(keys(&changes), ["fw03.lab01:wan1 <-> nexus01.lab01:Ethernet1/48"]);
    }

    #[test]
    fn exact_name_on_a_later_candidate_wins_over_a_label_on_an_earlier_one() {
        // The announced name with its domain, then without: two Netbox devices to try.
        let netbox = with(netbox(), "srv.switch.example.com", [labelled(30, "eno1", "eth0")]);
        let netbox = with(netbox, "srv", [iface(31, "eth0")]);
        let (changes, warnings) = Run::new([(
            "nexus01.lab01",
            vec![neighbor("Ethernet1/48", "srv.switch.example.com", Some("eth0"), "lldp")],
        )])
        .netbox(netbox)
        .go();
        assert_eq!(warnings, [""; 0]);
        assert_eq!(keys(&changes), ["nexus01.lab01:Ethernet1/48 <-> srv:eth0"]);
    }

    #[test]
    fn label_shared_by_two_interfaces_names_none() {
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "fw02.lab01", Some("uplink"), "lldp")])])
                .netbox(firewalls())
                .go();
        assert_eq!(changes, []);
        assert_eq!(warnings, ["nexus01.lab01 Ethernet1/48: fw02.lab01 has no interface 'uplink' in Netbox"]);
    }

    // The protections of the cable step, one test each. Those that the Python
    // tests do not cover under that angle are written from the Python source.

    #[test]
    fn protection_a_cable_is_replaced_only_between_two_devices_the_run_syncs() {
        // Written from the Python source (`between_synced`): the stale cable 10 joins
        // nexus01 and nexus02; it gives way to the announced link only when the run
        // syncs both, whatever `prune` says.
        let run = || {
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")])])
                .cables([cable(10, ("nexus01.lab01", "Ethernet1/48"), ("nexus02.lab01", "Ethernet1/47"))])
                .prune(true)
        };
        let (changes, warnings) = run().go();
        assert_eq!(changes, [delete(10, "cable 10"), create_48()]);
        assert_eq!(warnings, [""; 0]);
        for synced in [["nexus01.lab01"], ["nexus02.lab01"]] {
            let (changes, warnings) = run().synced(synced).go();
            assert_eq!(changes, []);
            assert_eq!(
                warnings,
                [concat!(
                    "cable nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48 ",
                    "not written: an end is already cabled (cable 10)"
                )]
            );
        }
    }

    #[test]
    fn protection_an_unresolved_end_keeps_the_existing_cable_and_warns() {
        // Written from the Python source: its tests check the kept cable and the
        // warning apart, never both in one run.
        let unknown_device = (
            neighbor("Ethernet1/48", "FGT-81-Acme-Primaire", Some("HA2"), "lldp"),
            "nexus01.lab01: neighbour FGT-81-Acme-Primaire is not a Netbox device (Ethernet1/48 -> HA2)",
        );
        let unknown_interface = (
            neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/99"), "cdp"),
            "nexus01.lab01 Ethernet1/48: nexus02.lab01 has no interface 'Ethernet1/99' in Netbox",
        );
        for (unresolved, warning) in [unknown_device, unknown_interface] {
            let (changes, warnings) =
                Run::new([("nexus01.lab01", vec![unresolved])]).cables([good_48()]).prune(true).go();
            assert_eq!(changes, []);
            assert_eq!(warnings, [warning]);
        }
        // The same cable, with no neighbour to protect it, is pruned.
        let (changes, _) = Run::new([("nexus01.lab01", vec![])]).cables([good_48()]).prune(true).go();
        assert_eq!(changes, [delete(8, "cable 8")]);
    }

    #[test]
    fn protection_the_cable_of_a_link_that_is_down_is_not_pruned() {
        // The `down` set holds interface keys: the cable end is compared by its key.
        let run = || Run::new([("nexus01.lab01", vec![]), ("nexus02.lab01", vec![])]).cables([good_48()]).prune(true);
        let (changes, warnings) = run().down("nexus02.lab01", "ethernet1/48").go();
        assert_eq!(changes, []);
        assert_eq!(warnings, [""; 0]);
        // Another port down protects nothing.
        let (changes, _) = run().down("nexus02.lab01", "ethernet1/47").go();
        assert_eq!(changes, [delete(8, "cable 8")]);
    }

    #[test]
    fn protection_a_port_named_by_two_switch_ports_gives_no_cable_and_a_warning() {
        // Written from the Python source: nexus01's Ethernet1/48 and Ethernet1/30 both
        // tell nexus02's Ethernet1/48. Neither cable is written, and all three ends
        // keep their current cable from the prune.
        let run = || {
            Run::new([(
                "nexus01.lab01",
                vec![
                    neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp"),
                    neighbor("Ethernet1/30", "nexus02.lab01", Some("Ethernet1/48"), "cdp"),
                ],
            )])
        };
        let (changes, warnings) = run().go();
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            [concat!(
                "nexus02.lab01:Ethernet1/48 is claimed by several links ",
                "(nexus01.lab01:Ethernet1/30, nexus01.lab01:Ethernet1/48)"
            )]
        );
        let (changes, _) = run().cables([good_48()]).prune(true).go();
        assert_eq!(changes, []);
    }

    #[test]
    fn protection_a_neighbour_without_name_nor_port_gives_nothing() {
        // Written from the Python source (`_devices_to_try`, `_resolve`): nothing is
        // looked up, even when a NetBox device carries the placeholder as its name.
        let anonymous = || {
            [(
                "nexus01.lab01",
                vec![
                    neighbor("Ethernet1/48", "not advertised", None, "lldp"),
                    neighbor("Ethernet1/30", "", None, "lldp"),
                ],
            )]
        };
        assert_eq!(lookup_names(&told(anonymous()), &stacks(), &DOMAINS, &Aliases::new()), [""; 0]);
        let (changes, warnings) =
            Run::new(anonymous()).netbox(with(netbox(), "not advertised", [iface(9, "eth0")])).go();
        assert_eq!(changes, []);
        assert_eq!(
            warnings,
            ["nexus01.lab01: 2 neighbours announce neither a name nor a port (Ethernet1/30, Ethernet1/48)"]
        );
    }

    #[test]
    fn protection_a_management_link_lands_on_the_only_management_interface() {
        let switch = || neighbor("Ethernet1/30", "lab1-pve01.prod", Some(MANAGEMENT_PORT), "description");
        let no_single = ["nexus01.lab01 Ethernet1/30: lab1-pve01.prod has no single management interface in Netbox"];
        // Exactly one: the cable lands on it, whatever its name.
        let (changes, warnings) = Run::new([("nexus01.lab01", vec![switch()])])
            .netbox(server([iface(10, "eno1"), management(11, "iDrac8"), iface(12, "eno2")]))
            .go();
        assert_eq!(changes, [create(("lab1-pve01.prod", "iDrac8"), ("nexus01.lab01", "Ethernet1/30"))]);
        assert_eq!(warnings, [""; 0]);
        // None.
        let (changes, warnings) =
            Run::new([("nexus01.lab01", vec![switch()])]).netbox(server([iface(10, "eno1")])).go();
        assert_eq!(changes, []);
        assert_eq!(warnings, no_single);
        // Several.
        let (changes, warnings) = Run::new([("nexus01.lab01", vec![switch()])])
            .netbox(server([management(11, "iDrac8"), management(12, "BMC")]))
            .go();
        assert_eq!(changes, []);
        assert_eq!(warnings, no_single);
    }

    // What the Python tests leave out, written from the Python source.

    #[test]
    fn name_family_lists_the_name_its_short_forms_then_their_aliases() {
        let aliases = strings([("fgt", "forti01.lab01"), ("other", "unrelated")]);
        assert_eq!(
            name_family("fgt.switch.example.com", &DOMAINS, &aliases),
            ["fgt.switch.example.com", "fgt", "forti01.lab01"]
        );
        assert_eq!(name_family("nexus02.lab01", &DOMAINS, &aliases), ["nexus02.lab01"]);
    }

    #[test]
    fn port_labeller_quotes_the_description_when_there_is_one() {
        let descriptions = BTreeMap::from([(
            "nexus01.lab01".to_owned(),
            strings([("ethernet1/1", "esx03 vmnic2"), ("ethernet1/2", "")]),
        )]);
        let label = port_labeller(Some(&descriptions));
        assert_eq!(label("nexus01.lab01", "Ethernet1/1"), r#"Ethernet1/1 "esx03 vmnic2""#);
        assert_eq!(label("nexus01.lab01", "Ethernet1/2"), "Ethernet1/2");
        assert_eq!(label("nexus01.lab01", "Ethernet1/3"), "Ethernet1/3");
        assert_eq!(label("nexus02.lab01", "Ethernet1/1"), "Ethernet1/1");
        assert_eq!(port_labeller(None)("nexus01.lab01", "Ethernet1/1"), "Ethernet1/1");
    }

    #[test]
    fn a_missing_port_is_quoted_as_python_prints_it() {
        // Python's `{port!r}`: single quotes, double quotes when the name holds a
        // single quote and no double one.
        let (_, warnings) =
            Run::new([("nexus01.lab01", vec![neighbor("Ethernet1/48", "nexus02.lab01", Some("it's"), "cdp")])]).go();
        assert_eq!(warnings, [r#"nexus01.lab01 Ethernet1/48: nexus02.lab01 has no interface "it's" in Netbox"#]);
    }

    #[test]
    fn a_backslash_in_a_quoted_port_is_doubled() {
        // Python: repr('a\\b') prints 'a\\b', the backslash doubled.
        assert_eq!(quoted("a\\b"), r"'a\\b'");
    }

    #[test]
    fn a_line_feed_a_carriage_return_and_a_tab_are_quoted_by_their_short_escape() {
        // Python: repr('a\nb') prints 'a\nb', and likewise '\r' and '\t': never
        // the hexadecimal form these three control characters also have.
        assert_eq!(quoted("a\nb"), r"'a\nb'");
        assert_eq!(quoted("a\rb"), r"'a\rb'");
        assert_eq!(quoted("a\tb"), r"'a\tb'");
    }

    #[test]
    fn a_single_quote_is_escaped_when_the_port_holds_both_kinds_of_quotes() {
        // Python: repr('it\'s "x"') keeps the single quotes around, so it escapes
        // the single quote inside and leaves the double ones as they are.
        assert_eq!(quoted(r#"it's "x""#), r#"'it\'s "x"'"#);
    }

    #[test]
    fn another_control_character_is_quoted_by_its_hexadecimal_escape() {
        // Python: repr('a\x1bb') prints 'a\x1bb', two lower-case hexadecimal digits.
        assert_eq!(quoted("a\u{1b}b"), r"'a\x1bb'");
        assert_eq!(quoted("a\u{1}b"), r"'a\x01b'");
    }

    #[test]
    fn a_character_python_does_not_print_is_quoted_by_its_escape_whatever_its_range() {
        // Python's repr escapes every character `str.isprintable()` refuses (the
        // categories Cc, Cf, Cs, Co, Cn, Zl, Zp, and Zs but the space): by \xhh
        // under U+0100, \uhhhh under U+10000, \Uhhhhhhhh above. A name that holds
        // one would otherwise hide it in the warning.
        // A C1 control character and the no-break space.
        assert_eq!(quoted("a\u{85}b"), r"'a\x85b'");
        assert_eq!(quoted("a\u{a0}b"), r"'a\xa0b'");
        // The soft hyphen and the zero-width space, both of format.
        assert_eq!(quoted("a\u{ad}b"), r"'a\xadb'");
        assert_eq!(quoted("a\u{200b}b"), r"'a\u200bb'");
        // A line separator, and an ideographic space.
        assert_eq!(quoted("a\u{2028}b"), r"'a\u2028b'");
        assert_eq!(quoted("a\u{3000}b"), r"'a\u3000b'");
        // A language tag, above the basic plane.
        assert_eq!(quoted("a\u{e0001}b"), r"'a\U000e0001b'");
    }

    #[test]
    fn a_printable_character_outside_ascii_is_kept_as_it_is() {
        // Python: repr('é ü') prints 'é ü', and an emoji is printable too.
        assert_eq!(quoted("é ü"), "'é ü'");
        assert_eq!(quoted("a\u{1f600}b"), "'a\u{1f600}b'");
    }

    #[test]
    fn ports_are_ordered_by_each_of_their_numbers_not_by_their_digits_joined() {
        // Slot 1 before slot 2, then port 9 before port 10: were the two numbers of
        // a name read as one (19, 110, 21), Ethernet2/1 would come before Ethernet1/10.
        let mut ports = ["Ethernet2/1", "Ethernet1/10", "Ethernet1/9"];
        ports.sort_by_cached_key(|port| natural(port));
        assert_eq!(ports, ["Ethernet1/9", "Ethernet1/10", "Ethernet2/1"]);
    }

    #[test]
    fn a_port_that_hears_itself_gives_no_cable_and_keeps_its_own() {
        // Not in the Python tool, which stops on such a neighbour: see `wanted_pairs`.
        let (changes, warnings) = Run::new([(
            "nexus01.lab01",
            vec![neighbor("Ethernet1/48", "nexus01.lab01", Some("Ethernet1/48"), "lldp")],
        )])
        .cables([good_48()])
        .prune(true)
        .go();
        assert_eq!(changes, []);
        assert_eq!(warnings, ["nexus01.lab01 Ethernet1/48: the neighbour is the port itself"]);
    }
    // Pins the fix of a defect of the Python reference, which looked the raw name up.
    #[test]
    fn a_name_announced_with_spaces_around_is_looked_up_trimmed() {
        let neighbors =
            told([("nexus01.lab01", vec![neighbor("Ethernet1/48", " nexus02.lab01 ", Some("Ethernet1/48"), "lldp")])]);
        assert_eq!(lookup_names(&neighbors, &Stacks::new(), &DOMAINS, &Aliases::new()), ["nexus02.lab01"]);
    }

    // The configuration may spell a device otherwise than NetBox (`sw02` for
    // `SW02`): the cable NetBox holds is still the one LLDP describes.
    #[test]
    fn a_device_the_configuration_spells_in_another_case_keeps_its_cable() {
        let mut sw01 = Interfaces::new();
        sw01.insert("ethernet1/1".into(), NbInterface { cable_id: Some(77), ..NbInterface::new(1, "Ethernet1/1") });
        let mut sw02 = Interfaces::new();
        sw02.insert("ethernet1/1".into(), NbInterface { cable_id: Some(77), ..NbInterface::new(2, "Ethernet1/1") });
        let interfaces_of = |name: &str| -> Option<&Interfaces> {
            match name.to_lowercase().as_str() {
                "sw01" => Some(&sw01),
                "sw02" => Some(&sw02),
                _ => None,
            }
        };
        let neighbors = BTreeMap::from([(
            "sw01".to_owned(),
            vec![Neighbor {
                local_interface: "Ethernet1/1".into(),
                remote_device: "sw02".into(),
                remote_interface: Some("Ethernet1/1".into()),
                protocol: "lldp".into(),
            }],
        )]);
        let cables = [NbCable { id: 77, a: End::new("sw01", "Ethernet1/1"), b: End::new("SW02", "Ethernet1/1") }];
        let synced = names(["sw01", "sw02"]);
        let (stacks, aliases, down, unpruned) = (Stacks::new(), Aliases::new(), BTreeSet::new(), BTreeSet::new());
        let options = CableOptions {
            stacks: &stacks,
            domains: &[],
            synced: &synced,
            prune: true,
            down: &down,
            aliases: &aliases,
            unpruned: &unpruned,
            unreadable: &|_| false,
            descriptions: None,
        };
        assert_eq!(diff_cables(&neighbors, &interfaces_of, &cables, &options), (Vec::new(), Vec::new()));
        // Nothing announced on that port any more: the cable is pruned all the same.
        let silent = BTreeMap::from([("sw01".to_owned(), vec![])]);
        let (changes, _) = diff_cables(&silent, &interfaces_of, &cables, &options);
        assert_eq!(changes, [Change::new("cable", Action::Delete, "", "cable 77").id(77)]);
        // Unless the link of the port is down, whatever the case of the device.
        let down = BTreeSet::from([("sw02".to_owned(), "ethernet1/1".to_owned())]);
        let (changes, _) = diff_cables(&silent, &interfaces_of, &cables, &CableOptions { down: &down, ..options });
        assert_eq!(changes, []);
    }

    // NetBox reads a device by a caseless name (`DeviceFilterSet.name` is
    // `iexact`): `SW02` announced by LLDP is the device `sw02`, and its cable
    // to sw01 is the one NetBox has, not one to replace at every run.
    #[test]
    fn a_neighbour_announced_in_another_case_keeps_its_cable() {
        let mut sw01 = Interfaces::new();
        sw01.insert("ethernet1/1".into(), NbInterface { cable_id: Some(77), ..NbInterface::new(1, "Ethernet1/1") });
        let mut sw02 = Interfaces::new();
        sw02.insert("ethernet1/1".into(), NbInterface { cable_id: Some(77), ..NbInterface::new(2, "Ethernet1/1") });
        let interfaces_of = |name: &str| -> Option<&Interfaces> {
            match name.to_lowercase().as_str() {
                "sw01" => Some(&sw01),
                "sw02" => Some(&sw02),
                _ => None,
            }
        };
        let neighbors = BTreeMap::from([(
            "sw01".to_owned(),
            vec![Neighbor {
                local_interface: "Ethernet1/1".into(),
                remote_device: "SW02".into(),
                remote_interface: Some("Ethernet1/1".into()),
                protocol: "lldp".into(),
            }],
        )]);
        let cables = [NbCable { id: 77, a: End::new("sw01", "Ethernet1/1"), b: End::new("sw02", "Ethernet1/1") }];
        let synced = names(["sw01", "sw02"]);
        let (stacks, aliases, down, unpruned) = (Stacks::new(), Aliases::new(), BTreeSet::new(), BTreeSet::new());
        let options = CableOptions {
            stacks: &stacks,
            domains: &[],
            synced: &synced,
            prune: true,
            down: &down,
            aliases: &aliases,
            unpruned: &unpruned,
            unreadable: &|_| false,
            descriptions: None,
        };
        assert_eq!(diff_cables(&neighbors, &interfaces_of, &cables, &options), (Vec::new(), Vec::new()));
    }
}
