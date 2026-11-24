//! Parsers for IOS 15.2 text outputs.
//!
//! The Python tool this was ported from read these outputs through the
//! ntc-templates TextFSM templates; no maintained TextFSM crate exists, so each
//! command is parsed by hand here, reading the fields those templates captured.
//! Unlike some of the templates, an unknown line inside a recognised output is
//! skipped rather than refused: an output of which nothing is recognised is the
//! failure.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use omnisync_core::network::dot1q::{access, expand_vlan_list, trunk};
use omnisync_core::network::model::{Dot1q, Interface, IpAddress, Neighbor};
use omnisync_core::network::names::{is_mac, long_interface_name, normalise_mac, strip_serial_suffix};
use regex::Regex;

use super::ParseError;

const INTERFACES: &str = "show interfaces";
const SWITCHPORT: &str = "show interfaces switchport";
const LAGS: &str = "show etherchannel summary";
const VLANS: &str = "show vlan brief";
const SWITCH: &str = "show switch";
const INVENTORY: &str = "show inventory";
const LLDP: &str = "show lldp neighbors detail";
const CDP: &str = "show cdp neighbors detail";

/// fddi-default, token-ring-default, fddinet-default, trnet-default.
pub const IOS_RESERVED_VLANS: [u16; 4] = [1002, 1003, 1004, 1005];

fn pattern(text: &str) -> Regex {
    Regex::new(text).expect("valid pattern")
}

// IOS prints a caret line under the command before `% Invalid input ...`, so the
// error is not at the start of the output: look for a `%` line anywhere.
static CLI_ERROR: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?m)^\s*%.*$"));

static INTERFACE_HEADER: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^(\S+)\s+is\s+(.+?),\s+line\s+protocol\s+is\s+(.+?)\s*$"));
static HARDWARE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s+Hardware\s+is\s+([\w \-]+)"));
static MAC: LazyLock<Regex> = LazyLock::new(|| {
    pattern(r"address\s+is\s+([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4})\s+\(bia\s+[a-fA-F0-9.]+\)\s*$")
});
static DESCRIPTION: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s+Description:\s+(.+?)\s*$"));
static INTERNET_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^\s+Internet\s+address\s+is\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s*$"));
static MTU: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s+MTU\s+(\d+)"));
static MEDIA_TYPE: LazyLock<Regex> = LazyLock::new(|| pattern(r"media\s+type\s+is\s*(\S.*?)?\s*$"));

static SWITCHPORT_NAME: LazyLock<Regex> = LazyLock::new(|| pattern(r"^Name:\s+(\S+)"));
static ADMIN_MODE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s*Administrative\s+Mode:\s+(.+?)\s*$"));
static OPER_MODE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s*Operational\s+Mode:\s+(.+?)\s*$"));
static ACCESS_VLAN: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s*Access\s+Mode\s+VLAN:\s+(\d+|unassigned)"));
static NATIVE_VLAN: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s*Trunking\s+Native\s+Mode\s+VLAN:\s+(\d+)"));
static TRUNK_VLANS: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s*Trunking\s+VLANs\s+Enabled:\s*(.*?)\s*$"));
static VLAN_LIST_LINE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s+([\d,\-\s]+)$"));

static LAG_HEADER: LazyLock<Regex> = LazyLock::new(|| pattern(r"^Group\s+Port-channel\s+Protocol"));
static LAG_ROW: LazyLock<Regex> = LazyLock::new(|| pattern(r"^(\d+)\s+(\S+?)\(\D+\)\s+\S+\s*(.*)$"));
static LAG_MEMBER: LazyLock<Regex> = LazyLock::new(|| pattern(r"([\w./]+)\(\D+?\)"));
static LAG_COUNT: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?m)^Number\s+of\s+channel-groups\s+in\s+use"));

static VLAN_HEADER: LazyLock<Regex> = LazyLock::new(|| pattern(r"^VLAN\s+Name"));
static VLAN_ROW: LazyLock<Regex> = LazyLock::new(|| pattern(r"^(\d+)\s+(\S+)\s+(\S+)"));

static SWITCH_RULE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^\s*-{3,}\s*$"));
static SWITCH_ROW: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^\*?\s*(\d+)\s+(\w+)\s+\S+\s+\d+\s+(?:\S+\s+)?\w+\s*$"));

static INVENTORY_NAME: LazyLock<Regex> = LazyLock::new(|| pattern(r#"^NAME:\s+"(.*?)",\s+DESCR:"#));
static INVENTORY_SERIAL: LazyLock<Regex> = LazyLock::new(|| pattern(r"^PID:.*SN:\s*(\w+)"));

static CDP_DEVICE: LazyLock<Regex> = LazyLock::new(|| pattern(r"^Device ID:\s*(\S+)"));
static CDP_PORTS: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^Interface:\s*(.*?),\s+Port ID \(outgoing port\):\s*(.*?)\s*$"));
static CDP_TOTAL: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?m)^\s*Total\s+cdp\s+entries\s+displayed"));

static LLDP_LOCAL: LazyLock<Regex> = LazyLock::new(|| pattern(r"^Local\s+Intf:\s+(\S+)\s*$"));
static LLDP_PORT_ID: LazyLock<Regex> = LazyLock::new(|| pattern(r"^Port\s+id:\s+(.*?)\s*$"));
static LLDP_PORT_DESCRIPTION: LazyLock<Regex> = LazyLock::new(|| pattern(r"^Port\s+Description:\s+(.*?)\s*$"));
static LLDP_SYSTEM_NAME: LazyLock<Regex> = LazyLock::new(|| pattern(r"^System\s+Name:\s+(.+?)\s*$"));
static LLDP_TOTAL: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?m)^\s*Total\s+entries\s+displayed"));
/// The total of a neighbour table, as IOS prints it last.
static CDP_COUNT: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?m)^\s*Total\s+cdp\s+entries\s+displayed\s*:\s*(\d+)"));
static LLDP_COUNT: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?m)^\s*Total\s+entries\s+displayed\s*:\s*(\d+)"));
/// The line of dashes IOS prints before each neighbour of a detail view.
static BLOCK_SEPARATOR: LazyLock<Regex> = LazyLock::new(|| pattern(r"^-{5,}\s*$"));

/// Refuse what the switch answers to a command it rejects.
fn refuse_cli_error(command: &'static str, text: &str) -> Result<(), ParseError> {
    match CLI_ERROR.find(text) {
        Some(line) => {
            let reason: String = line.as_str().trim().chars().take(80).collect();
            Err(ParseError::command(command, reason))
        }
        None => Ok(()),
    }
}

/// A refused command, in a neighbour detail view: IOS prints the error before
/// any neighbour, and what follows the first one is the neighbours' own text,
/// where a `%` line proves nothing.
fn refuse_cli_error_before_neighbours(command: &'static str, text: &str, header: &Regex) -> Result<(), ParseError> {
    let preamble: Vec<&str> =
        text.lines().take_while(|line| !BLOCK_SEPARATOR.is_match(line) && !header.is_match(line)).collect();
    refuse_cli_error(command, &preamble.join("\n"))
}

/// The neighbours read must be the ones IOS counted: the free text of a
/// neighbour may forge a whole block after a line of dashes, never the total
/// printed after the last one.
fn check_count(command: &'static str, text: &str, count: &Regex, read: usize) -> Result<(), ParseError> {
    let announced = count.captures_iter(text).last().and_then(|found| found[1].parse::<usize>().ok());
    match announced {
        Some(announced) if announced != read => {
            Err(ParseError::command(command, format!("{read} neighbours read, {announced} announced")))
        }
        _ => Ok(()),
    }
}

fn nothing_parsed(command: &'static str) -> ParseError {
    ParseError::command(command, "nothing parsed")
}

fn long(name: &str) -> String {
    long_interface_name(name, Some("ios"))
}

fn interface_type(hardware: &str, media: &str) -> Option<&'static str> {
    match hardware {
        "EtherChannel" => Some("lag"),
        "EtherSVI" | "Loopback" => Some("virtual"),
        "Ten Gigabit Ethernet" => Some("10gbase-x-sfpp"),
        // `Hardware is not present` is followed by a second `Hardware is Gigabit
        // Ethernet` line, with no known media: the type is then left unmanaged.
        "Gigabit Ethernet" if media == "10/100/1000BaseTX" => Some("1000base-t"),
        "APM86XXX FastEthernet" => Some("100base-tx"),
        _ => None,
    }
}

/// What `show interfaces` says of one interface, as its lines come.
#[derive(Default)]
struct InterfaceBlock {
    name: String,
    link_status: String,
    hardware: String,
    media: String,
    mac: Option<String>,
    description: String,
    mtu: Option<u32>,
    address: Option<String>,
}

impl InterfaceBlock {
    fn read(&mut self, line: &str) {
        if let Some(found) = HARDWARE.captures(line) {
            self.hardware = found[1].trim().to_owned();
            if let Some(mac) = MAC.captures(line) {
                self.mac = Some(mac[1].to_owned());
            }
        } else if let Some(found) = DESCRIPTION.captures(line) {
            self.description = found[1].to_owned();
        } else if let Some(found) = INTERNET_ADDRESS.captures(line) {
            self.address = Some(format!("{}/{}", &found[1], &found[2]));
        } else if let Some(found) = MTU.captures(line) {
            self.mtu = found[1].parse().ok();
        } else if let Some(found) = MEDIA_TYPE.captures(line) {
            self.media = found.get(1).map_or("", |media| media.as_str()).to_owned();
        }
    }
}

pub fn parse_interfaces(text: &str) -> Result<(BTreeMap<String, Interface>, Vec<IpAddress>), ParseError> {
    refuse_cli_error(INTERFACES, text)?;
    let mut blocks: Vec<InterfaceBlock> = Vec::new();
    for line in text.lines() {
        if let Some(header) = INTERFACE_HEADER.captures(line) {
            blocks.push(InterfaceBlock {
                name: long(&header[1]),
                link_status: header[2].to_owned(),
                ..InterfaceBlock::default()
            });
        } else if let Some(block) = blocks.last_mut() {
            block.read(line);
        }
    }
    if blocks.is_empty() {
        return Err(nothing_parsed(INTERFACES));
    }
    let mut interfaces = BTreeMap::new();
    let mut ips = Vec::new();
    for block in blocks {
        if let Some(address) = block.address {
            ips.push(IpAddress { address, interface: block.name.clone(), vrf: None });
        }
        let interface = Interface {
            description: Some(block.description),
            mtu: block.mtu,
            r#type: interface_type(&block.hardware, &block.media).map(str::to_owned),
            mac: normalise_mac(block.mac.as_deref()),
            link_up: Some(block.link_status == "up"),
            ..Interface::new(&block.name, block.link_status != "administratively down")
        };
        interfaces.insert(block.name, interface);
    }
    // A switch always holds its management IP: none would prune every IP.
    if ips.is_empty() {
        return Err(ParseError::command(INTERFACES, "no IP address"));
    }
    Ok((interfaces, ips))
}

/// What `show interfaces switchport` says of one port.
#[derive(Default)]
struct SwitchportBlock {
    name: String,
    admin_mode: String,
    oper_mode: String,
    access_vlan: Option<u16>,
    native_vlan: Option<u16>,
    /// The items of `Trunking VLANs Enabled`, as written.
    trunk_vlans: String,
    /// The list goes on the next line: the last one ended with a comma.
    in_vlan_list: bool,
}

impl SwitchportBlock {
    fn read(&mut self, line: &str) {
        if self.in_vlan_list
            && let Some(more) = VLAN_LIST_LINE.captures(line)
        {
            self.trunk_vlans.push_str(more[1].trim());
            self.in_vlan_list = self.trunk_vlans.ends_with(',');
            return;
        }
        self.in_vlan_list = false;
        if let Some(found) = ADMIN_MODE.captures(line) {
            self.admin_mode = found[1].to_owned();
        } else if let Some(found) = OPER_MODE.captures(line) {
            self.oper_mode = found[1].to_owned();
        } else if let Some(found) = ACCESS_VLAN.captures(line) {
            self.access_vlan = found[1].parse().ok();
        } else if let Some(found) = NATIVE_VLAN.captures(line) {
            self.native_vlan = found[1].parse().ok();
        } else if let Some(found) = TRUNK_VLANS.captures(line) {
            self.trunk_vlans = found[1].to_owned();
            self.in_vlan_list = self.trunk_vlans.ends_with(',');
        }
    }
}

pub fn parse_switchport(
    text: &str,
    defined: &BTreeSet<u16>,
) -> Result<(BTreeMap<String, Dot1q>, BTreeSet<String>), ParseError> {
    refuse_cli_error(SWITCHPORT, text)?;
    let mut blocks: Vec<SwitchportBlock> = Vec::new();
    for line in text.lines() {
        if let Some(name) = SWITCHPORT_NAME.captures(line) {
            blocks.push(SwitchportBlock { name: long(&name[1]), ..SwitchportBlock::default() });
        } else if let Some(block) = blocks.last_mut() {
            block.read(line);
        }
    }
    if blocks.is_empty() {
        return Err(nothing_parsed(SWITCHPORT));
    }
    let mut modes = BTreeMap::new();
    let mut unmanaged = BTreeSet::new();
    for block in blocks {
        // A dynamic port is described by its operational mode, when it has one.
        let effective = match block.admin_mode.as_str() {
            "static access" | "trunk" => block.admin_mode.as_str(),
            _ => block.oper_mode.as_str(),
        };
        match effective {
            "static access" | "access" => {
                modes.insert(block.name, access(block.access_vlan, defined));
            }
            "trunk" => {
                let dot1q = if block.trunk_vlans.eq_ignore_ascii_case("ALL") {
                    trunk(block.native_vlan, None, defined)
                } else {
                    let allowed = expand_vlan_list(&block.trunk_vlans)
                        .map_err(|error| ParseError::command(SWITCHPORT, error.to_string()))?;
                    trunk(block.native_vlan, Some(&allowed), defined)
                };
                modes.insert(block.name, dot1q);
            }
            _ => {
                unmanaged.insert(block.name);
            }
        }
    }
    Ok((modes, unmanaged))
}

pub fn parse_lag_members(text: &str) -> Result<BTreeMap<String, String>, ParseError> {
    refuse_cli_error(LAGS, text)?;
    let mut members = BTreeMap::new();
    let mut in_table = false;
    let mut lag: Option<String> = None;
    for line in text.lines() {
        if LAG_HEADER.is_match(line) {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        let ports = if let Some(row) = LAG_ROW.captures(line) {
            lag = Some(long(&row[2]));
            row.get(3).map_or("", |ports| ports.as_str())
        } else if line.starts_with(char::is_whitespace) {
            // The ports of a group go on over the next lines.
            line
        } else {
            continue;
        };
        if let Some(lag) = &lag {
            for member in LAG_MEMBER.captures_iter(ports) {
                members.insert(long(&member[1]), lag.clone());
            }
        }
    }
    // A switch without any group still prints its count, and no table.
    if !in_table && !LAG_COUNT.is_match(text) {
        return Err(nothing_parsed(LAGS));
    }
    Ok(members)
}

pub fn parse_vlans(text: &str) -> Result<BTreeMap<u16, String>, ParseError> {
    refuse_cli_error(VLANS, text)?;
    let mut vlans = BTreeMap::new();
    let mut in_table = false;
    for line in text.lines() {
        if VLAN_HEADER.is_match(line) {
            in_table = true;
        } else if in_table
            && let Some(row) = VLAN_ROW.captures(line)
            && let Ok(vid) = row[1].parse::<u16>()
            && !IOS_RESERVED_VLANS.contains(&vid)
        {
            vlans.insert(vid, row[2].to_owned());
        }
    }
    if vlans.is_empty() {
        return Err(nothing_parsed(VLANS));
    }
    Ok(vlans)
}

/// The member number of the master, and every member number, sorted.
pub fn parse_switch(text: &str) -> Result<(u32, Vec<u32>), ParseError> {
    refuse_cli_error(SWITCH, text)?;
    let mut members = Vec::new();
    let mut master = None;
    let mut in_table = false;
    for line in text.lines() {
        if SWITCH_RULE.is_match(line) {
            in_table = true;
        } else if in_table
            && let Some(row) = SWITCH_ROW.captures(line)
            && let Ok(number) = row[1].parse::<u32>()
        {
            members.push(number);
            if &row[2] == "Master" && master.is_none() {
                master = Some(number);
            }
        }
    }
    if members.is_empty() {
        return Err(nothing_parsed(SWITCH));
    }
    members.sort_unstable();
    let master = master.ok_or_else(|| ParseError::command(SWITCH, "no master"))?;
    Ok((master, members))
}

pub fn parse_member_serials(text: &str) -> Result<BTreeMap<u32, String>, ParseError> {
    refuse_cli_error(INVENTORY, text)?;
    let mut serials = BTreeMap::new();
    let mut rows = 0;
    let mut name: Option<String> = None;
    for line in text.lines() {
        if let Some(found) = INVENTORY_NAME.captures(line) {
            name = Some(found[1].to_owned());
            rows += 1;
        } else if let Some(found) = INVENTORY_SERIAL.captures(line) {
            // Stack members are the inventory rows named after their member number.
            if let Some(member) = name.take().and_then(|name| name.parse::<u32>().ok()) {
                serials.insert(member, found[1].to_owned());
            }
        }
    }
    if rows == 0 {
        return Err(nothing_parsed(INVENTORY));
    }
    if serials.is_empty() {
        return Err(ParseError::command(INVENTORY, "no stack member"));
    }
    Ok(serials)
}

/// The neighbour's port as announced: the cable resolver tries it as is, then
/// expanded, since a host's `eth3` is not Cisco's `Eth3` (Ethernet3).
fn remote_port(port: &str) -> Option<String> {
    let trimmed = port.trim();
    (!trimmed.is_empty() && !is_mac(port)).then(|| trimmed.to_owned())
}

/// A port description names a host interface as is (`eth3`, `eno1`): never expanded.
fn described_port(description: &str) -> Option<String> {
    let trimmed = description.trim();
    (!trimmed.is_empty() && !is_mac(description) && trimmed != "not advertised").then(|| trimmed.to_owned())
}

pub fn parse_cdp(text: &str) -> Result<Vec<Neighbor>, ParseError> {
    // A switch with CDP turned off has no CDP neighbour: nothing to refuse.
    if text.contains("CDP is not enabled") {
        return Ok(Vec::new());
    }
    refuse_cli_error_before_neighbours(CDP, text, &CDP_DEVICE)?;
    let mut neighbors = Vec::new();
    // Per block: the header (up to `Version :`, after which the text is the
    // neighbour's own), its device, and whether it named its neighbour.
    let (mut header, mut device, mut named) = (true, None::<String>, false);
    for line in text.lines() {
        if BLOCK_SEPARATOR.is_match(line) {
            (header, device, named) = (true, None, false);
        } else if !header || named {
            continue;
        } else if line.trim_end() == "Version :" {
            header = false;
        } else if let Some(found) = CDP_DEVICE.captures(line) {
            device.get_or_insert_with(|| found[1].to_owned());
        } else if let Some(ports) = CDP_PORTS.captures(line)
            && let Some(device) = device.take()
        {
            named = true;
            neighbors.push(Neighbor {
                local_interface: long(&ports[1]),
                remote_device: strip_serial_suffix(&device),
                remote_interface: remote_port(&ports[2]),
                protocol: "cdp".to_owned(),
            });
        }
    }
    if neighbors.is_empty() && !CDP_TOTAL.is_match(text) {
        return Err(nothing_parsed(CDP));
    }
    check_count(CDP, text, &CDP_COUNT, neighbors.len())?;
    Ok(neighbors)
}

/// What `show lldp neighbors detail` says of one neighbour.
#[derive(Default)]
struct LldpEntry {
    local: String,
    port_id: String,
    port_description: String,
    system_name: String,
}

pub fn parse_lldp(text: &str) -> Result<Vec<Neighbor>, ParseError> {
    if text.contains("LLDP is not enabled") {
        return Ok(Vec::new());
    }
    refuse_cli_error_before_neighbours(LLDP, text, &LLDP_LOCAL)?;
    let mut entries: Vec<LldpEntry> = Vec::new();
    // Per block: the header (up to `System Description:`, after which the text
    // is the neighbour's own), and the one neighbour it describes. Each field
    // is read once: a second one is the neighbour's text, not the switch's.
    let (mut header, mut entry) = (true, None::<LldpEntry>);
    for line in text.lines() {
        if BLOCK_SEPARATOR.is_match(line) {
            entries.extend(entry.take());
            header = true;
            continue;
        }
        if !header {
            continue;
        }
        if line.trim_end().starts_with("System Description:") {
            header = false;
        } else if let Some(found) = LLDP_LOCAL.captures(line) {
            entry.get_or_insert_with(|| LldpEntry { local: found[1].to_owned(), ..LldpEntry::default() });
        } else if let Some(entry) = entry.as_mut() {
            let field = if let Some(found) = LLDP_PORT_ID.captures(line) {
                Some((&mut entry.port_id, found))
            } else if let Some(found) = LLDP_PORT_DESCRIPTION.captures(line) {
                Some((&mut entry.port_description, found))
            } else {
                LLDP_SYSTEM_NAME.captures(line).map(|found| (&mut entry.system_name, found))
            };
            if let Some((field, found)) = field
                && field.is_empty()
            {
                found[1].clone_into(field);
            }
        }
    }
    entries.extend(entry);
    if entries.is_empty() && !LLDP_TOTAL.is_match(text) {
        return Err(nothing_parsed(LLDP));
    }
    check_count(LLDP, text, &LLDP_COUNT, entries.len())?;
    Ok(entries
        .into_iter()
        .map(|entry| Neighbor {
            local_interface: long(&entry.local),
            remote_device: entry.system_name.trim().to_owned(),
            // A MAC as port ID (Linux lldpd): fall back to the port description.
            remote_interface: remote_port(&entry.port_id).or_else(|| described_port(&entry.port_description)),
            protocol: "lldp".to_owned(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use omnisync_core::network::model::Mode;

    use super::*;
    use crate::parsers::fixtures::{IOS, failure, fixture_text};

    // What IOS really prints for a refused command: the caret line comes first.
    const REFUSED: &str = "                    ^\n% Invalid input detected at '^' marker.\n";

    // Shape of IOS 15.2 `show lldp neighbors detail` (the detail view has no
    // capability-codes header, unlike `show lldp neighbors`).
    const IOS_LLDP: &str = "------------------------------------------------
Local Intf: Gi1/0/5
Chassis id: 0225.e71b.e608
Port id: 028c.4e3c.17c8
Port Description: eno4
System Name: pve01.lab01

System Description:
Debian GNU/Linux

Time remaining: 112 seconds
System Capabilities: B,R
Enabled Capabilities: R
Management Addresses - not advertised
Auto Negotiation - supported, enabled
Physical media capabilities:
    1000baseT(FD)
Media Attachment Unit type: 30
Vlan ID: - not advertised

Total entries displayed: 1
";

    fn interfaces() -> BTreeMap<String, Interface> {
        parse_interfaces(&fixture_text(IOS, INTERFACES)).expect("the fixture parses").0
    }

    fn neighbor(local: &str, device: &str, remote: Option<&str>, protocol: &str) -> Neighbor {
        Neighbor {
            local_interface: local.to_owned(),
            remote_device: device.to_owned(),
            remote_interface: remote.map(str::to_owned),
            protocol: protocol.to_owned(),
        }
    }

    fn dot1q<const N: usize>(mode: Mode, untagged: Option<u16>, tagged: [u16; N]) -> Dot1q {
        Dot1q { mode, untagged_vlan: untagged, tagged_vlans: tagged.to_vec() }
    }

    #[test]
    fn interfaces_and_ips() {
        let (interfaces, ips) = parse_interfaces(&fixture_text(IOS, INTERFACES)).expect("the fixture parses");
        assert_eq!(interfaces.len(), 32);
        assert_eq!(interfaces["GigabitEthernet1/0/1"].r#type.as_deref(), Some("1000base-t"));
        assert_eq!(interfaces["TenGigabitEthernet1/0/1"].r#type.as_deref(), Some("10gbase-x-sfpp"));
        assert_eq!(interfaces["FastEthernet0"].r#type.as_deref(), Some("100base-tx"));
        assert_eq!(interfaces["Port-channel1"].r#type.as_deref(), Some("lag"));
        assert_eq!(interfaces["Vlan2800"].r#type.as_deref(), Some("virtual"));
        assert_eq!(interfaces["Vlan2800"].mac.as_deref(), Some("02:27:ED:39:2E:86"));
        assert!(!interfaces["Vlan1"].enabled);
        assert_eq!(
            ips,
            [IpAddress { address: "192.0.2.251/24".to_owned(), interface: "Vlan2800".to_owned(), vrf: None }]
        );
    }

    #[test]
    fn hardware_not_present_leaves_type_unmanaged() {
        // `  Hardware is not present` then `  Hardware is Gigabit Ethernet, address is 0295.a7d6.bad1 ...`
        // and `media type is unknown`.
        assert_eq!(interfaces()["GigabitEthernet1/0/25"].r#type, None);
    }

    #[test]
    fn descriptions_and_mtu_are_read_from_the_raw_output() {
        let interfaces = interfaces();
        // `  Description: IDRAC ESX06 DELL R640` under GigabitEthernet1/0/15.
        assert_eq!(interfaces["GigabitEthernet1/0/15"].description.as_deref(), Some("IDRAC ESX06 DELL R640"));
        // `  Description: to3750` under Port-channel1.
        assert_eq!(interfaces["Port-channel1"].description.as_deref(), Some("to3750"));
        // No `Description:` line under Vlan2800: an empty description, which is a value.
        assert_eq!(interfaces["Vlan2800"].description.as_deref(), Some(""));
        // `  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec, ` under Vlan2800.
        assert_eq!(interfaces["Vlan2800"].mtu, Some(1500));
        // `Vlan2800 is up, line protocol is up ` and `Vlan1 is administratively down, ...`.
        assert!(interfaces["Vlan2800"].enabled);
    }

    #[test]
    fn ios_cli_error_is_parse_error() {
        assert_eq!(
            failure(parse_interfaces("% Invalid input detected at '^' marker.")),
            (INTERFACES, "% Invalid input detected at '^' marker.".to_owned())
        );
    }

    #[test]
    fn switchport() {
        let (modes, unmanaged) =
            parse_switchport(&fixture_text(IOS, SWITCHPORT), &BTreeSet::from([1, 2800])).expect("the fixture parses");
        assert_eq!(modes["GigabitEthernet1/0/1"], dot1q(Mode::Access, Some(2800), []));
        assert_eq!(modes["TenGigabitEthernet1/0/1"], dot1q(Mode::Tagged, Some(1), [2800]));
        assert_eq!(modes["Port-channel1"], dot1q(Mode::Tagged, Some(1), [2800]));
        assert_eq!(unmanaged, BTreeSet::from(["GigabitEthernet1/0/25".to_owned(), "GigabitEthernet1/0/26".to_owned()]));
    }

    #[test]
    fn a_trunk_allowing_every_vlan_is_tagged_all() {
        let text = "Name: Gi1/0/9\nAdministrative Mode: trunk\nOperational Mode: trunk\n\
                    Access Mode VLAN: 1 (default)\nTrunking Native Mode VLAN: 1 (default)\n\
                    Trunking VLANs Enabled: ALL\n";
        let (modes, _) = parse_switchport(text, &BTreeSet::from([1, 2800])).expect("a valid output");
        assert_eq!(modes["GigabitEthernet1/0/9"], dot1q(Mode::TaggedAll, Some(1), []));
    }

    #[test]
    fn a_vlan_list_continued_on_the_next_lines_is_read_whole() {
        let text = "Name: Gi1/0/9\nAdministrative Mode: trunk\nOperational Mode: trunk\n\
                    Access Mode VLAN: 1 (default)\nTrunking Native Mode VLAN: 1 (default)\n\
                    Trunking VLANs Enabled: 10,20-21,\n     30,\n     2800\nPruning VLANs Enabled: 2-1001\n";
        let defined = BTreeSet::from([1, 10, 20, 21, 30, 2800]);
        let (modes, _) = parse_switchport(text, &defined).expect("a valid output");
        assert_eq!(modes["GigabitEthernet1/0/9"], dot1q(Mode::Tagged, Some(1), [10, 20, 21, 30, 2800]));
    }

    #[test]
    fn a_dynamic_port_follows_its_operational_mode() {
        let text = "Name: Gi1/0/9\nAdministrative Mode: dynamic auto\nOperational Mode: static access\n\
                    Access Mode VLAN: 2800 (Admin)\nTrunking Native Mode VLAN: 1 (default)\n\
                    Trunking VLANs Enabled: ALL\n";
        let (modes, unmanaged) = parse_switchport(text, &BTreeSet::from([1, 2800])).expect("a valid output");
        assert_eq!(modes["GigabitEthernet1/0/9"], dot1q(Mode::Access, Some(2800), []));
        assert_eq!(unmanaged, BTreeSet::new());
    }

    #[test]
    fn an_unassigned_access_vlan_is_no_vlan() {
        let text = "Name: Gi1/0/9\nAdministrative Mode: static access\nOperational Mode: down\n\
                    Access Mode VLAN: unassigned\n";
        let (modes, _) = parse_switchport(text, &BTreeSet::from([1])).expect("a valid output");
        assert_eq!(modes["GigabitEthernet1/0/9"], dot1q(Mode::Access, None, []));
    }

    #[test]
    fn lag_without_member() {
        // `1      Po1(SD)          -        `: a group with no port.
        assert_eq!(parse_lag_members(&fixture_text(IOS, LAGS)), Ok(BTreeMap::new()));
    }

    #[test]
    fn lag_members_on_one_line_and_on_the_next() {
        let text = "Number of channel-groups in use: 2\n\
                    Group  Port-channel  Protocol    Ports\n\
                    ------+-------------+-----------+-----------------------------------------------\n\
                    1      Po1(SU)         LACP      Te1/0/1(P)  Te1/0/2(P)\n\
                    2      Po2(SU)          -        Gi1/0/1(P)  Gi1/0/2(P)  Gi1/0/3(P)\n\
                    \x20                                Gi1/0/4(D)\n";
        let members = parse_lag_members(text).expect("a valid output");
        let expected = [
            ("TenGigabitEthernet1/0/1", "Port-channel1"),
            ("TenGigabitEthernet1/0/2", "Port-channel1"),
            ("GigabitEthernet1/0/1", "Port-channel2"),
            ("GigabitEthernet1/0/2", "Port-channel2"),
            ("GigabitEthernet1/0/3", "Port-channel2"),
            ("GigabitEthernet1/0/4", "Port-channel2"),
        ];
        assert_eq!(members, expected.into_iter().map(|(port, lag)| (port.to_owned(), lag.to_owned())).collect());
    }

    #[test]
    fn vlans_skip_reserved() {
        // `1    default ...`, `1002 fddi-default ...` to `1005 trnet-default ...`, `2800 Admin ...`.
        assert_eq!(
            parse_vlans(&fixture_text(IOS, VLANS)),
            Ok(BTreeMap::from([(1, "default".to_owned()), (2800, "Admin".to_owned())]))
        );
    }

    #[test]
    fn stack_single_member() {
        // `*1       Master 02b3.dd4f.1634     1      4       Ready`.
        assert_eq!(parse_switch(&fixture_text(IOS, SWITCH)), Ok((1, vec![1])));
        // `NAME: "1", DESCR: "WS-C2960X-24TD-L"` then `PID: WS-C2960X-24TD-L  , VID: V05  , SN: FCW8657Y7S5`;
        // the two `TenGigabitEthernet1/0/x` rows are modules, not members.
        assert_eq!(
            parse_member_serials(&fixture_text(IOS, INVENTORY)),
            Ok(BTreeMap::from([(1, "FCW8657Y7S5".to_owned())]))
        );
    }

    #[test]
    fn stack_of_two_members_names_its_master() {
        let text = "Switch/Stack Mac Address : 02b3.dd4f.1634\n\
                    \x20                                          H/W   Current\n\
                    Switch#  Role   Mac Address     Priority Version  State \n\
                    ----------------------------------------------------------\n\
                    \x201       Member 02b3.dd4f.1634     1      4       Ready\n\
                    *2       Master 02b3.dd4f.99aa     15     4       Ready\n";
        assert_eq!(parse_switch(text), Ok((2, vec![1, 2])));
    }

    #[test]
    fn a_stack_without_master_is_a_failure() {
        let text = "Switch#  Role   Mac Address     Priority Version  State \n\
                    ----------------------------------------------------------\n\
                    *1       Member 02b3.dd4f.1634     1      4       Ready\n";
        assert_eq!(failure(parse_switch(text)), (SWITCH, "no master".to_owned()));
    }

    #[test]
    fn cdp() {
        // `Device ID: nexus02.lab01(FOC0852S7R5)` and
        // `Interface: TenGigabitEthernet1/0/1,  Port ID (outgoing port): Ethernet1/36`.
        assert_eq!(
            parse_cdp(&fixture_text(IOS, CDP)),
            Ok(vec![
                neighbor("TenGigabitEthernet1/0/1", "nexus02.lab01", Some("Ethernet1/36"), "cdp"),
                neighbor("TenGigabitEthernet1/0/2", "nexus01.lab01", Some("Ethernet1/36"), "cdp"),
            ])
        );
    }

    // The text after `Version :` is the neighbour's own (any host on an access
    // port sends CDP): IOS prints it line by line, so a line in it may look like
    // a field. Only the header of a block names a neighbour.
    /// The first line of the System Description a Nexus sends over LLDP.
    const NXOS_DESCRIPTION: &str = "Cisco Nexus Operating System (NX-OS) Software 7.0(3)I2(4)\n";
    const NXOS_VERSION: &str = "Cisco Nexus Operating System (NX-OS) Software, Version 7.0(3)I2(4)\n";

    #[test]
    fn the_free_text_of_a_neighbour_never_names_a_neighbour_nor_fails_the_switch() {
        let forged =
            "Device ID: core01\nInterface: TenGigabitEthernet1/0/5,  Port ID (outgoing port): Ethernet1/1\n% x\n";
        let text = fixture_text(IOS, CDP).replacen(NXOS_VERSION, &format!("{NXOS_VERSION}{forged}"), 1);
        assert_eq!(
            parse_cdp(&text),
            Ok(vec![
                neighbor("TenGigabitEthernet1/0/1", "nexus02.lab01", Some("Ethernet1/36"), "cdp"),
                neighbor("TenGigabitEthernet1/0/2", "nexus01.lab01", Some("Ethernet1/36"), "cdp"),
            ])
        );
        let forged = "Local Intf: Gi1/0/9\nSystem Name: core01\n% x\n";
        let recorded = fixture_text(IOS, LLDP);
        let text = recorded.replacen(NXOS_DESCRIPTION, &format!("{NXOS_DESCRIPTION}{forged}"), 1);
        assert_eq!(
            parse_lldp(&text),
            Ok(vec![
                neighbor("TenGigabitEthernet1/0/2", "nexus01.lab01", Some("Ethernet1/36"), "lldp"),
                neighbor("TenGigabitEthernet1/0/1", "nexus02.lab01", Some("Ethernet1/36"), "lldp"),
            ])
        );
    }

    // A whole block forged after a line of dashes cannot be told from a real
    // one, but it does not add up: the total IOS prints last is its own.
    #[test]
    fn a_neighbour_forged_by_the_free_text_of_another_fails_the_output() {
        let forged = "\n-------------------------\nDevice ID: core01\nInterface: TenGigabitEthernet1/0/5,  Port ID (outgoing port): Ethernet1/1\n";
        let text = fixture_text(IOS, CDP).replacen(NXOS_VERSION, &format!("{NXOS_VERSION}{forged}"), 1);
        assert_eq!(failure(parse_cdp(&text)), (CDP, "3 neighbours read, 2 announced".to_owned()));
        let forged = "\n------------------------------------------------\nLocal Intf: Gi1/0/9\nSystem Name: core01\n";
        let recorded = fixture_text(IOS, LLDP);
        let text = recorded.replacen(NXOS_DESCRIPTION, &format!("{NXOS_DESCRIPTION}{forged}"), 1);
        assert_eq!(failure(parse_lldp(&text)), (LLDP, "3 neighbours read, 2 announced".to_owned()));
    }

    #[test]
    fn cdp_without_neighbour_is_empty() {
        assert_eq!(parse_cdp("\nTotal cdp entries displayed : 0\n"), Ok(Vec::new()));
    }

    #[test]
    fn lldp_disabled_is_empty() {
        // What 2960-admin printed before LLDP was turned on, whole.
        assert_eq!(parse_lldp("% LLDP is not enabled"), Ok(Vec::new()));
    }

    #[test]
    fn lldp_names_each_neighbour_by_its_system_name_and_port() {
        // `Local Intf: Te1/0/2`, `Port id: Ethernet1/36`, `System Name: nexus01.lab01`;
        // `Local Intf: Te1/0/1`, `Port id: Ethernet1/36`, `System Name: nexus02.lab01`.
        assert_eq!(
            parse_lldp(&fixture_text(IOS, LLDP)),
            Ok(vec![
                neighbor("TenGigabitEthernet1/0/2", "nexus01.lab01", Some("Ethernet1/36"), "lldp"),
                neighbor("TenGigabitEthernet1/0/1", "nexus02.lab01", Some("Ethernet1/36"), "lldp"),
            ])
        );
    }

    // Pins the fix of a defect of the Python reference, where a switch with CDP
    // turned off failed its whole collection while LLDP turned off did not.
    #[test]
    fn cdp_disabled_is_empty() {
        assert_eq!(parse_cdp("% CDP is not enabled\n"), Ok(Vec::new()));
    }

    #[test]
    fn refused_command_with_caret_line_is_parse_error() {
        let refused = "% Invalid input detected at '^' marker.".to_owned();
        assert_eq!(failure(parse_cdp(REFUSED)), (CDP, refused.clone()));
        assert_eq!(failure(parse_lag_members(REFUSED)), (LAGS, refused.clone()));
        assert_eq!(failure(parse_lldp(REFUSED)), (LLDP, refused));
    }

    #[test]
    fn interfaces_without_any_ip_is_a_failure() {
        // A switch always holds its management IP: none would prune every IP.
        let text: String = fixture_text(IOS, INTERFACES)
            .lines()
            .filter(|line| !line.contains("Internet address"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(failure(parse_interfaces(&text)), (INTERFACES, "no IP address".to_owned()));
    }

    #[test]
    fn link_state() {
        // `GigabitEthernet1/0/1 is down, ...` and `GigabitEthernet1/0/3 is up, ...`.
        let interfaces = interfaces();
        assert_eq!(interfaces["GigabitEthernet1/0/1"].link_up, Some(false));
        assert_eq!(interfaces["GigabitEthernet1/0/3"].link_up, Some(true));
    }

    #[test]
    fn ios_lldp_port_description_names_a_server_port() {
        assert_eq!(
            parse_lldp(IOS_LLDP),
            Ok(vec![neighbor("GigabitEthernet1/0/5", "pve01.lab01", Some("eno4"), "lldp")])
        );
    }

    #[test]
    fn lldp_without_neighbour_is_empty() {
        assert_eq!(parse_lldp("\nTotal entries displayed: 0\n"), Ok(Vec::new()));
    }

    #[test]
    fn lldp_port_id_that_is_an_interface_name_is_kept() {
        let text = "Local Intf: Te1/0/1\nPort id: Ethernet1/36\nPort Description: uplink\n\
                    System Name: nexus02.lab01\n\nTotal entries displayed: 1\n";
        assert_eq!(
            parse_lldp(text),
            Ok(vec![neighbor("TenGigabitEthernet1/0/1", "nexus02.lab01", Some("Ethernet1/36"), "lldp")])
        );
    }

    #[test]
    fn an_output_of_which_nothing_is_recognised_is_a_failure() {
        let nothing = "nothing parsed".to_owned();
        let garbage = "lorem ipsum dolor\nsit amet\n";
        assert_eq!(failure(parse_interfaces(garbage)), (INTERFACES, nothing.clone()));
        assert_eq!(failure(parse_switchport(garbage, &BTreeSet::new())), (SWITCHPORT, nothing.clone()));
        assert_eq!(failure(parse_lag_members(garbage)), (LAGS, nothing.clone()));
        assert_eq!(failure(parse_vlans(garbage)), (VLANS, nothing.clone()));
        assert_eq!(failure(parse_switch(garbage)), (SWITCH, nothing.clone()));
        assert_eq!(failure(parse_member_serials(garbage)), (INVENTORY, nothing.clone()));
        assert_eq!(failure(parse_cdp(garbage)), (CDP, nothing.clone()));
        assert_eq!(failure(parse_lldp(garbage)), (LLDP, nothing));
    }

    #[test]
    fn an_empty_output_is_a_failure() {
        let nothing = "nothing parsed".to_owned();
        assert_eq!(failure(parse_interfaces("")), (INTERFACES, nothing.clone()));
        assert_eq!(failure(parse_vlans("\n")), (VLANS, nothing.clone()));
        assert_eq!(failure(parse_lag_members("")), (LAGS, nothing.clone()));
        assert_eq!(failure(parse_cdp("")), (CDP, nothing.clone()));
        assert_eq!(failure(parse_lldp("")), (LLDP, nothing));
    }

    #[test]
    fn the_output_of_another_command_is_a_failure() {
        // A session out of step would hand a parser the answer to the previous command.
        assert_eq!(failure(parse_vlans(&fixture_text(IOS, INTERFACES))).0, VLANS);
        assert_eq!(failure(parse_interfaces(&fixture_text(IOS, VLANS))).0, INTERFACES);
        assert_eq!(failure(parse_switch(&fixture_text(IOS, INVENTORY))).0, SWITCH);
        assert_eq!(failure(parse_member_serials(&fixture_text(IOS, SWITCH))).0, INVENTORY);
        assert_eq!(failure(parse_switchport(&fixture_text(IOS, INTERFACES), &BTreeSet::new())).0, SWITCHPORT);
    }

    #[test]
    fn inventory_without_a_member_row_is_a_failure() {
        let text = "NAME: \"TenGigabitEthernet1/0/1\", DESCR: \"SFP-10GBase-SR\"\n\
                    PID: SFP-10G-SR          , VID: V03  , SN: Y9608367086     \n";
        assert_eq!(failure(parse_member_serials(text)), (INVENTORY, "no stack member".to_owned()));
    }
}
