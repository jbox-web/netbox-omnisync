//! Parsers for NX-OS `| json` outputs (7.0(3)I2 and I4).

use std::collections::{BTreeMap, BTreeSet};

use omnisync_core::network::dot1q::{access, expand_vlan_list, trunk};
use omnisync_core::network::model::{Dot1q, Interface, IpAddress, Neighbor};
use omnisync_core::network::names::{is_mac, long_interface_name, normalise_mac, strip_serial_suffix};
use serde_json::{Map, Value};

use super::ParseError;

const INTERFACES: &str = "show interface | json";
const SWITCHPORT: &str = "show interface switchport | json";
const LAGS: &str = "show port-channel summary | json";
const VLANS: &str = "show vlan brief | json";
const VRFS: &str = "show vrf interface | json";
const IPS: &str = "show ip interface vrf all | json";
const INVENTORY: &str = "show inventory | json";
const LLDP: &str = "show lldp neighbors detail | json";
const CDP: &str = "show cdp neighbors detail | json";

type Row = Map<String, Value>;

// Port hardware (`eth_hw_desc`) -> NetBox interface type.
const TYPES: &[(&str, &str)] = &[
    ("100/1000/10000 Ethernet", "10gbase-x-sfpp"),
    ("40000 Ethernet", "40gbase-x-qsfpp"),
    ("GigabitEthernet", "1000base-t"),
    ("Port-Channel", "lag"),
    ("Loopback", "virtual"),
];

fn load(command: &'static str, text: &str, empty_ok: bool) -> Result<Row, ParseError> {
    let stripped = text.trim();
    if stripped.is_empty() {
        // NX-OS prints nothing instead of JSON when a neighbour table is empty.
        if empty_ok {
            return Ok(Row::new());
        }
        return Err(ParseError::command(command, "empty output"));
    }
    let data: Value = serde_json::from_str(stripped).map_err(|_| {
        let start: String = stripped.chars().take(80).collect();
        ParseError::command(command, format!("not JSON: {start:?}"))
    })?;
    match data {
        Value::Object(object) => Ok(object),
        _ => Err(ParseError::command(command, "JSON output is not an object")),
    }
}

/// NX-OS returns a single row as an object instead of a one-element list.
fn as_list(value: Option<&Value>) -> Vec<&Value> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.iter().collect(),
        Some(single) => vec![single],
    }
}

fn rows<'a>(command: &'static str, data: &'a Row, table: &str, row: &str) -> Result<Vec<&'a Row>, ParseError> {
    let not_an_object = || ParseError::command(command, format!("a {row} is not an object"));
    let items = match data.get(table) {
        // `show ip interface vrf all` returns its tables as lists of {row: ...} items.
        Some(Value::Array(entries)) => {
            let mut items = Vec::new();
            for entry in entries {
                items.extend(as_list(entry.as_object().ok_or_else(not_an_object)?.get(row)));
            }
            items
        }
        Some(Value::Object(container)) => as_list(container.get(row)),
        _ => Vec::new(),
    };
    items.into_iter().map(|item| item.as_object().ok_or_else(not_an_object)).collect()
}

/// The value of a field as text, whether NX-OS quoted it or not; None when absent.
fn text(row: &Row, key: &str) -> Option<String> {
    match row.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn required(command: &'static str, row: &Row, key: &str) -> Result<String, ParseError> {
    text(row, key).ok_or_else(|| ParseError::command(command, format!("row without `{key}`")))
}

fn number<T: std::str::FromStr>(row: &Row, key: &str) -> Option<T> {
    text(row, key)?.trim().parse().ok()
}

fn long(name: &str) -> String {
    long_interface_name(name, Some("nxos"))
}

fn description(row: &Row) -> Option<String> {
    Some(text(row, "desc").unwrap_or_default().trim().to_owned())
}

pub fn parse_interfaces(output: &str) -> Result<BTreeMap<String, Interface>, ParseError> {
    let data = load(INTERFACES, output, false)?;
    let mut interfaces = BTreeMap::new();
    for row in rows(INTERFACES, &data, "TABLE_interface", "ROW_interface")? {
        let name = long(&required(INTERFACES, row, "interface")?);
        let interface = if name.starts_with("Vlan") {
            Interface {
                description: description(row),
                mtu: number(row, "svi_mtu"),
                r#type: Some("virtual".to_owned()),
                mac: normalise_mac(text(row, "svi_mac").as_deref()),
                ..Interface::new(&name, text(row, "svi_admin_state").as_deref() == Some("up"))
            }
        } else {
            let hardware = text(row, "eth_hw_desc").unwrap_or_default();
            Interface {
                description: description(row),
                mtu: number(row, "eth_mtu"),
                r#type: TYPES.iter().find(|(known, _)| *known == hardware).map(|(_, kind)| (*kind).to_owned()),
                mac: normalise_mac(text(row, "eth_hw_addr").as_deref()),
                link_up: text(row, "state").map(|state| state == "up"),
                ..Interface::new(&name, text(row, "admin_state").as_deref() == Some("up"))
            }
        };
        interfaces.insert(name, interface);
    }
    if interfaces.is_empty() {
        return Err(ParseError::command(INTERFACES, "no interface"));
    }
    Ok(interfaces)
}

pub fn parse_switchport(
    output: &str,
    defined: &BTreeSet<u16>,
) -> Result<(BTreeMap<String, Dot1q>, BTreeSet<String>), ParseError> {
    let data = load(SWITCHPORT, output, false)?;
    let rows = rows(SWITCHPORT, &data, "TABLE_interface", "ROW_interface")?;
    // No row would clear the 802.1Q mode of every port in NetBox.
    if rows.is_empty() {
        return Err(ParseError::command(SWITCHPORT, "no interface"));
    }
    let mut modes = BTreeMap::new();
    let mut unmanaged = BTreeSet::new();
    for row in rows {
        let name = long(&required(SWITCHPORT, row, "interface")?);
        match text(row, "oper_mode").as_deref() {
            Some("access") => {
                modes.insert(name, access(number(row, "access_vlan"), defined));
            }
            Some("trunk") => {
                let allowed = expand_vlan_list(&text(row, "trunk_vlans").unwrap_or_default())
                    .map_err(|error| ParseError::command(SWITCHPORT, error.to_string()))?;
                modes.insert(name, trunk(number(row, "native_vlan"), Some(&allowed), defined));
            }
            _ => {
                unmanaged.insert(name);
            }
        }
    }
    Ok((modes, unmanaged))
}

pub fn parse_lag_members(output: &str) -> Result<BTreeMap<String, String>, ParseError> {
    let data = load(LAGS, output, false)?;
    let mut members = BTreeMap::new();
    for channel in rows(LAGS, &data, "TABLE_channel", "ROW_channel")? {
        let lag = long(&required(LAGS, channel, "port-channel")?);
        for member in rows(LAGS, channel, "TABLE_member", "ROW_member")? {
            members.insert(long(&required(LAGS, member, "port")?), lag.clone());
        }
    }
    Ok(members)
}

pub fn parse_vlans(output: &str) -> Result<BTreeMap<u16, String>, ParseError> {
    let data = load(VLANS, output, false)?;
    let mut vlans = BTreeMap::new();
    for row in rows(VLANS, &data, "TABLE_vlanbriefxbrief", "ROW_vlanbriefxbrief")? {
        let vid = required(VLANS, row, "vlanshowbr-vlanid")?
            .trim()
            .parse()
            .map_err(|_| ParseError::command(VLANS, "`vlanshowbr-vlanid` is not a VLAN ID"))?;
        vlans.insert(vid, required(VLANS, row, "vlanshowbr-vlanname")?);
    }
    if vlans.is_empty() {
        return Err(ParseError::command(VLANS, "no VLAN"));
    }
    Ok(vlans)
}

pub fn parse_vrf_map(output: &str) -> Result<BTreeMap<String, String>, ParseError> {
    let data = load(VRFS, output, false)?;
    let mut vrfs = BTreeMap::new();
    for row in rows(VRFS, &data, "TABLE_if", "ROW_if")? {
        vrfs.insert(long(&required(VRFS, row, "if_name")?), required(VRFS, row, "vrf_name")?);
    }
    Ok(vrfs)
}

pub fn parse_ips(output: &str, vrf_of: &BTreeMap<String, String>) -> Result<Vec<IpAddress>, ParseError> {
    // The VRF comes from `show vrf interface`: pairing the TABLE_vrf and TABLE_intf
    // lists of this output by position is not documented behaviour.
    let data = load(IPS, output, false)?;
    let rows = rows(IPS, &data, "TABLE_intf", "ROW_intf")?;
    // A switch always holds its management IP: no row would prune every IP.
    if rows.is_empty() {
        return Err(ParseError::command(IPS, "no IP"));
    }
    let mut ips = Vec::new();
    for row in rows {
        let name = long(&required(IPS, row, "intf-name")?);
        let vrf = vrf_of.get(&name).ok_or_else(|| ParseError::command(IPS, format!("no VRF reported for {name}")))?;
        let address = format!("{}/{}", required(IPS, row, "prefix")?, required(IPS, row, "masklen")?);
        ips.push(IpAddress { address, interface: name, vrf: (vrf != "default").then(|| vrf.clone()) });
    }
    Ok(ips)
}

pub fn parse_serial(output: &str) -> Result<String, ParseError> {
    let data = load(INVENTORY, output, false)?;
    for row in rows(INVENTORY, &data, "TABLE_inv", "ROW_inv")? {
        if text(row, "name").unwrap_or_default().trim_matches('"') == "Chassis" {
            return required(INVENTORY, row, "serialnum");
        }
    }
    Err(ParseError::command(INVENTORY, "no Chassis row"))
}

fn named_port(port: Option<String>) -> Option<String> {
    let port = port?;
    let trimmed = port.trim();
    (!trimmed.is_empty() && !is_mac(&port) && trimmed != "not advertised").then(|| trimmed.to_owned())
}

/// The neighbour's port as announced: the cable resolver tries it as is, then
/// expanded, since a host's `eth3` is not Cisco's `Eth3` (Ethernet3).
fn remote_port(port: Option<String>) -> Option<String> {
    named_port(port)
}

/// A port description names a host interface as is (`eth3`, `eno1`): never expanded.
fn described_port(description: Option<String>) -> Option<String> {
    named_port(description)
}

pub fn parse_lldp(output: &str) -> Result<Vec<Neighbor>, ParseError> {
    let data = load(LLDP, output, true)?;
    let mut neighbors = Vec::new();
    for row in rows(LLDP, &data, "TABLE_nbor_detail", "ROW_nbor_detail")? {
        neighbors.push(Neighbor {
            local_interface: long(&required(LLDP, row, "l_port_id")?),
            remote_device: text(row, "sys_name").unwrap_or_default().trim().to_owned(),
            // Linux lldpd announces a MAC as port ID and the interface name as
            // port description: fall back to the description.
            remote_interface: remote_port(text(row, "port_id")).or_else(|| described_port(text(row, "port_desc"))),
            protocol: "lldp".to_owned(),
        });
    }
    Ok(neighbors)
}

pub fn parse_cdp(output: &str) -> Result<Vec<Neighbor>, ParseError> {
    let data = load(CDP, output, true)?;
    let mut neighbors = Vec::new();
    for row in rows(CDP, &data, "TABLE_cdp_neighbor_detail_info", "ROW_cdp_neighbor_detail_info")? {
        neighbors.push(Neighbor {
            local_interface: long(&required(CDP, row, "intf_id")?),
            remote_device: strip_serial_suffix(&text(row, "device_id").unwrap_or_default()),
            remote_interface: remote_port(text(row, "port_id")),
            protocol: "cdp".to_owned(),
        });
    }
    Ok(neighbors)
}

#[cfg(test)]
mod tests {
    use omnisync_core::network::model::Mode;

    use super::*;
    use crate::parsers::fixtures::{NXOS_I2, NXOS_I4, failure, fixture_text, halved};

    const NEXUS01_VLANS: [u16; 30] = [
        1, 3, 6, 26, 333, 666, 978, 991, 998, 2500, 2600, 2701, 2702, 2703, 2711, 2712, 2713, 2714, 2715, 2716, 2717,
        2800, 2901, 2902, 2903, 3011, 3012, 4091, 4092, 4093,
    ];

    type Parser = Box<dyn Fn(&str) -> Result<(), ParseError>>;

    /// Every parser with the command it reads, its result dropped.
    fn parsers() -> Vec<(&'static str, Parser)> {
        vec![
            ("show interface | json", Box::new(|text| parse_interfaces(text).map(drop))),
            ("show interface switchport | json", Box::new(|text| parse_switchport(text, &defined()).map(drop))),
            ("show port-channel summary | json", Box::new(|text| parse_lag_members(text).map(drop))),
            ("show vlan brief | json", Box::new(|text| parse_vlans(text).map(drop))),
            ("show vrf interface | json", Box::new(|text| parse_vrf_map(text).map(drop))),
            ("show ip interface vrf all | json", Box::new(|text| parse_ips(text, &BTreeMap::new()).map(drop))),
            ("show inventory | json", Box::new(|text| parse_serial(text).map(drop))),
            ("show lldp neighbors detail | json", Box::new(|text| parse_lldp(text).map(drop))),
            ("show cdp neighbors detail | json", Box::new(|text| parse_cdp(text).map(drop))),
        ]
    }

    fn defined() -> BTreeSet<u16> {
        BTreeSet::from(NEXUS01_VLANS)
    }

    fn interfaces(directory: &str) -> BTreeMap<String, Interface> {
        parse_interfaces(&fixture_text(directory, "show interface | json")).expect("a valid output")
    }

    fn switchport(directory: &str) -> (BTreeMap<String, Dot1q>, BTreeSet<String>) {
        parse_switchport(&fixture_text(directory, "show interface switchport | json"), &defined())
            .expect("a valid output")
    }

    fn lag_members(directory: &str) -> BTreeMap<String, String> {
        parse_lag_members(&fixture_text(directory, "show port-channel summary | json")).expect("a valid output")
    }

    fn vrf_map(directory: &str) -> BTreeMap<String, String> {
        parse_vrf_map(&fixture_text(directory, "show vrf interface | json")).expect("a valid output")
    }

    fn ips(directory: &str) -> Vec<IpAddress> {
        parse_ips(&fixture_text(directory, "show ip interface vrf all | json"), &vrf_map(directory))
            .expect("a valid output")
    }

    fn lldp(directory: &str) -> Vec<Neighbor> {
        parse_lldp(&fixture_text(directory, "show lldp neighbors detail | json")).expect("a valid output")
    }

    fn cdp(directory: &str) -> Vec<Neighbor> {
        parse_cdp(&fixture_text(directory, "show cdp neighbors detail | json")).expect("a valid output")
    }

    fn interface(
        name: &str,
        enabled: bool,
        description: &str,
        mtu: u32,
        r#type: &str,
        mac: &str,
        link_up: Option<bool>,
    ) -> Interface {
        Interface {
            description: Some(description.to_owned()),
            mtu: Some(mtu),
            r#type: Some(r#type.to_owned()),
            mac: Some(mac.to_owned()),
            link_up,
            ..Interface::new(name, enabled)
        }
    }

    fn dot1q<const N: usize>(mode: Mode, untagged_vlan: Option<u16>, tagged_vlans: [u16; N]) -> Dot1q {
        Dot1q { mode, untagged_vlan, tagged_vlans: tagged_vlans.to_vec() }
    }

    fn ip(address: &str, interface: &str, vrf: Option<&str>) -> IpAddress {
        IpAddress { address: address.to_owned(), interface: interface.to_owned(), vrf: vrf.map(str::to_owned) }
    }

    fn neighbor(local: &str, device: &str, remote: Option<&str>, protocol: &str) -> Neighbor {
        Neighbor {
            local_interface: local.to_owned(),
            remote_device: device.to_owned(),
            remote_interface: remote.map(str::to_owned),
            protocol: protocol.to_owned(),
        }
    }

    #[test]
    fn ethernet_interface() {
        // `"state": "down"`, `"state_rsn_desc": "Link not connected"`.
        assert_eq!(
            interfaces(NXOS_I2)["Ethernet1/1"],
            interface("Ethernet1/1", true, "ESX01-eth4", 1500, "10gbase-x-sfpp", "02:08:D1:90:97:2D", Some(false))
        );
    }

    #[test]
    fn interface_kinds() {
        let interfaces = interfaces(NXOS_I2);
        assert_eq!(interfaces["Ethernet1/49"].r#type.as_deref(), Some("40gbase-x-qsfpp"));
        assert!(!interfaces["Ethernet1/49"].enabled);
        assert_eq!(interfaces["mgmt0"].r#type.as_deref(), Some("1000base-t"));
        assert_eq!(
            interfaces["port-channel10"],
            interface("port-channel10", true, "vpc-peer-link", 9216, "lag", "02:B5:B7:D1:E5:F8", Some(true))
        );
        assert_eq!(interfaces["Vlan2800"], interface("Vlan2800", true, "", 1500, "virtual", "02:FF:BE:8F:29:B0", None));
    }

    #[test]
    fn loopback_has_no_mac() {
        let interfaces = interfaces(NXOS_I4);
        let loopback = &interfaces["loopback0"];
        assert_eq!(loopback.r#type.as_deref(), Some("virtual"));
        assert_eq!(loopback.mac, None);
    }

    #[test]
    fn every_interface_is_parsed() {
        assert_eq!(interfaces(NXOS_I2).len(), 73);
    }

    #[test]
    fn cli_error_is_parse_error() {
        assert_eq!(failure(parse_interfaces("% Invalid command at '^' marker.")).0, "show interface | json");
        assert_eq!(failure(parse_interfaces("")), ("show interface | json", "empty output".to_owned()));
    }

    #[test]
    fn vlans() {
        let vlans = parse_vlans(&fixture_text(NXOS_I2, "show vlan brief | json")).expect("a valid output");
        assert_eq!(vlans.keys().copied().collect::<Vec<_>>(), NEXUS01_VLANS);
        assert_eq!(vlans[&2800], "Admin");
        assert_eq!(vlans[&1], "default");
    }

    #[test]
    fn switchport_i2() {
        let (modes, unmanaged) = switchport(NXOS_I2);
        assert_eq!(
            modes["Ethernet1/1"],
            dot1q(
                Mode::Tagged,
                Some(1),
                [
                    26, 978, 991, 998, 2500, 2600, 2701, 2702, 2703, 2711, 2712, 2713, 2714, 2715, 2716, 2717, 2800,
                    2901, 2902, 2903, 3011, 3012
                ]
            )
        );
        assert_eq!(modes["Ethernet1/4"], dot1q(Mode::TaggedAll, Some(1), []));
        assert_eq!(modes["Ethernet1/7"], dot1q(Mode::Access, Some(2903), []));
        assert_eq!(unmanaged, BTreeSet::new());
    }

    #[test]
    fn switchport_i4_native_vlan() {
        let (modes, _) = switchport(NXOS_I4);
        assert_eq!(modes["Ethernet1/1"], dot1q(Mode::Tagged, Some(26), [2600, 2712, 2714]));
        assert_eq!(modes["Ethernet1/2"], dot1q(Mode::Access, Some(1), []));
    }

    #[test]
    fn lag_members_of_both_releases() {
        let i2 = lag_members(NXOS_I2);
        assert_eq!(i2["Ethernet1/51"], "port-channel10");
        assert_eq!(i2["Ethernet1/52"], "port-channel10");
        // port-channel1 of nexus03 has a single member, returned as an object, not a list.
        let i4 = lag_members(NXOS_I4);
        assert_eq!(i4["Ethernet1/1"], "port-channel1");
        assert!(!i4.values().any(|lag| lag == "port-channel7"));
    }

    #[test]
    fn vrf_map_names_the_vrf_of_each_interface() {
        let vrf_of = vrf_map(NXOS_I2);
        assert_eq!(vrf_of["mgmt0"], "management");
        assert_eq!(vrf_of["Vlan2800"], "mgmt-sw");
        assert_eq!(vrf_of["Vlan1"], "default");
    }

    #[test]
    fn ips_with_vrf() {
        let mut ips = ips(NXOS_I2);
        ips.sort_by(|a, b| a.address.cmp(&b.address));
        assert_eq!(
            ips,
            [ip("192.0.2.239/24", "Vlan2800", Some("mgmt-sw")), ip("192.168.1.1/24", "mgmt0", Some("management"))]
        );
    }

    #[test]
    fn ips_default_vrf_is_global() {
        assert!(ips(NXOS_I4).contains(&ip("198.18.31.242/30", "Vlan4092", None)));
    }

    #[test]
    fn ip_without_vrf_is_parse_error() {
        // mgmt0 is the first row of TABLE_intf in the nexus01 output.
        let text = fixture_text(NXOS_I2, "show ip interface vrf all | json");
        assert_eq!(
            failure(parse_ips(&text, &BTreeMap::new())),
            ("show ip interface vrf all | json", "no VRF reported for mgmt0".to_owned())
        );
    }

    #[test]
    fn serial() {
        assert_eq!(parse_serial(&fixture_text(NXOS_I2, "show inventory | json")).as_deref(), Ok("FOC9792A4K9"));
        assert_eq!(parse_serial(&fixture_text(NXOS_I4, "show inventory | json")).as_deref(), Ok("FOC9317H9P5"));
    }

    #[test]
    fn lldp_neighbours() {
        let neighbors = lldp(NXOS_I2);
        assert_eq!(neighbors.len(), 11);
        // `"port_id": "Te1/0/2"`: kept as announced, expanded by the cable resolver.
        assert!(neighbors.contains(&neighbor(
            "Ethernet1/30",
            "2960-stack.lab01.switch.example.com",
            Some("Te1/0/2"),
            "lldp"
        )));
        assert!(neighbors.contains(&neighbor("mgmt0", "nexus02.lab01", Some("mgmt0"), "lldp")));
        // A server announcing its MAC address as port ID.
        assert!(neighbors.contains(&neighbor("Ethernet1/15", "not advertised", None, "lldp")));
    }

    #[test]
    fn no_neighbour_is_empty_output() {
        assert_eq!(parse_lldp(""), Ok(Vec::new()));
        assert_eq!(parse_cdp(""), Ok(Vec::new()));
    }

    #[test]
    fn cdp_neighbours() {
        let neighbors = cdp(NXOS_I2);
        assert_eq!(neighbors.len(), 6);
        assert!(neighbors.contains(&neighbor("Ethernet1/48", "nexus02.lab01", Some("Ethernet1/48"), "cdp")));
        assert!(neighbors.contains(&neighbor(
            "Ethernet1/30",
            "2960-stack.lab01.switch.example.com",
            Some("TenGigabitEthernet1/0/2"),
            "cdp"
        )));
    }

    #[test]
    fn empty_ip_and_lag_outputs_are_parse_errors() {
        // An empty output would otherwise prune every IP, primary IP included.
        let vrf_of = BTreeMap::from([("mgmt0".to_owned(), "management".to_owned())]);
        assert_eq!(failure(parse_ips("", &vrf_of)), ("show ip interface vrf all | json", "empty output".to_owned()));
        assert_eq!(failure(parse_lag_members("")), ("show port-channel summary | json", "empty output".to_owned()));
    }

    #[test]
    fn description_is_stripped() {
        // NetBox strips surrounding spaces; keeping them would never converge.
        let text = r#"{"TABLE_interface": {"ROW_interface": {"interface": "Ethernet1/1", "admin_state": "up", "desc": "uplink ", "eth_mtu": "1500"}}}"#;
        let interfaces = parse_interfaces(text).expect("a valid output");
        assert_eq!(interfaces["Ethernet1/1"].description.as_deref(), Some("uplink"));
    }

    #[test]
    fn switchport_without_rows_is_a_failure() {
        // Valid JSON but no table: every port would lose its 802.1Q mode in NetBox.
        assert_eq!(
            failure(parse_switchport("{}", &BTreeSet::from([1]))),
            ("show interface switchport | json", "no interface".to_owned())
        );
    }

    #[test]
    fn ips_without_rows_is_a_failure() {
        // Every switch holds at least its management IP; none would prune them all.
        assert_eq!(
            failure(parse_ips(r#"{"TABLE_intf": []}"#, &BTreeMap::new())),
            ("show ip interface vrf all | json", "no IP".to_owned())
        );
    }

    #[test]
    fn link_state() {
        // `"state": "down"` on Ethernet1/47, `"up"` on Ethernet1/48; an SVI has no link.
        let interfaces = interfaces(NXOS_I2);
        assert_eq!(interfaces["Ethernet1/47"].link_up, Some(false));
        assert_eq!(interfaces["Ethernet1/48"].link_up, Some(true));
        assert_eq!(interfaces["Vlan2800"].link_up, None);
    }

    #[test]
    fn lldp_port_description_names_a_server_port() {
        // Linux lldpd announces a MAC as port ID and the interface name as description.
        let neighbors = lldp(NXOS_I4);
        assert!(neighbors.contains(&neighbor("Ethernet1/8", "pve03.lab01", Some("eno3"), "lldp")));
        assert!(neighbors.contains(&neighbor("Ethernet1/10", "pve03.lab01", Some("enp3s0f0"), "lldp")));
        assert!(neighbors.contains(&neighbor("Ethernet1/1", "db02.prod.global.example.org", Some("eth3"), "lldp")));
        // Neither a usable port ID nor a description: still unresolved.
        assert!(neighbors.contains(&neighbor("Ethernet1/15", "not advertised", None, "lldp")));
    }

    // What follows is not in the Python tests.

    #[test]
    fn garbage_is_a_failure_that_names_the_command() {
        for (command, parser) in parsers() {
            let (named, reason) = failure(parser("lorem ipsum dolor"));
            assert_eq!(named, command);
            assert_eq!(reason, r#"not JSON: "lorem ipsum dolor""#);
        }
    }

    #[test]
    fn truncated_output_is_a_failure_that_names_the_command() {
        for (command, parser) in parsers() {
            for directory in [NXOS_I2, NXOS_I4] {
                let (named, reason) = failure(parser(&halved(&fixture_text(directory, command))));
                assert_eq!(named, command);
                assert!(reason.starts_with("not JSON: "), "{command}: {reason}");
            }
        }
    }

    #[test]
    fn json_that_is_not_an_object_is_a_failure() {
        for (command, parser) in parsers() {
            assert_eq!(failure(parser("[]")), (command, "JSON output is not an object".to_owned()));
        }
    }

    #[test]
    fn interfaces_without_rows_is_a_failure() {
        assert_eq!(failure(parse_interfaces("{}")), ("show interface | json", "no interface".to_owned()));
    }

    #[test]
    fn vlans_without_rows_is_a_failure() {
        assert_eq!(failure(parse_vlans("{}")), ("show vlan brief | json", "no VLAN".to_owned()));
    }

    #[test]
    fn inventory_without_chassis_is_a_failure() {
        let text = r#"{"TABLE_inv": {"ROW_inv": {"name": "\"Slot 1\"", "serialnum": "FOC96781U06"}}}"#;
        assert_eq!(failure(parse_serial(text)), ("show inventory | json", "no Chassis row".to_owned()));
    }

    #[test]
    fn a_row_without_its_name_is_a_failure() {
        let text = r#"{"TABLE_interface": {"ROW_interface": {"admin_state": "up"}}}"#;
        assert_eq!(failure(parse_interfaces(text)), ("show interface | json", "row without `interface`".to_owned()));
        assert_eq!(
            failure(parse_switchport(text, &defined())),
            ("show interface switchport | json", "row without `interface`".to_owned())
        );
    }

    #[test]
    fn a_row_that_is_not_an_object_is_a_failure() {
        let text = r#"{"TABLE_interface": {"ROW_interface": ["Ethernet1/1"]}}"#;
        assert_eq!(
            failure(parse_interfaces(text)),
            ("show interface | json", "a ROW_interface is not an object".to_owned())
        );
    }

    #[test]
    fn a_single_row_is_an_object_instead_of_a_list() {
        let text = r#"{"TABLE_vlanbriefxbrief": {"ROW_vlanbriefxbrief": {"vlanshowbr-vlanid": "26", "vlanshowbr-vlanname": "PPE"}}}"#;
        assert_eq!(parse_vlans(text), Ok(BTreeMap::from([(26, "PPE".to_owned())])));
    }

    #[test]
    fn a_vlan_id_that_is_not_a_vid_is_a_failure() {
        let text = r#"{"TABLE_vlanbriefxbrief": {"ROW_vlanbriefxbrief": {"vlanshowbr-vlanid": "x", "vlanshowbr-vlanname": "PPE"}}}"#;
        assert_eq!(
            failure(parse_vlans(text)),
            ("show vlan brief | json", "`vlanshowbr-vlanid` is not a VLAN ID".to_owned())
        );
    }

    #[test]
    fn numbers_are_read_whether_quoted_or_not() {
        let text = r#"{"TABLE_interface": {"ROW_interface": [
            {"interface": "Ethernet1/1", "admin_state": "up", "eth_mtu": 9216},
            {"interface": "Ethernet1/2", "admin_state": "up", "eth_mtu": "n/a"}]}}"#;
        let interfaces = parse_interfaces(text).expect("a valid output");
        assert_eq!(interfaces["Ethernet1/1"].mtu, Some(9216));
        assert_eq!(interfaces["Ethernet1/2"].mtu, None);
    }

    #[test]
    fn unknown_hardware_leaves_the_type_unmanaged() {
        let text = r#"{"TABLE_interface": {"ROW_interface": {"interface": "Ethernet1/1", "eth_hw_desc": "Ethernet"}}}"#;
        let interfaces = parse_interfaces(text).expect("a valid output");
        assert_eq!(interfaces["Ethernet1/1"].r#type, None);
        // No `admin_state`, no `state`, no `desc`.
        assert!(!interfaces["Ethernet1/1"].enabled);
        assert_eq!(interfaces["Ethernet1/1"].link_up, None);
        assert_eq!(interfaces["Ethernet1/1"].description.as_deref(), Some(""));
    }

    #[test]
    fn a_port_neither_access_nor_trunk_is_unmanaged() {
        let text = r#"{"TABLE_interface": {"ROW_interface": {"interface": "Ethernet1/1", "oper_mode": "fex-fabric"}}}"#;
        let (modes, unmanaged) = parse_switchport(text, &defined()).expect("a valid output");
        assert_eq!(modes, BTreeMap::new());
        assert_eq!(unmanaged, BTreeSet::from(["Ethernet1/1".to_owned()]));
    }

    #[test]
    fn an_invalid_vlan_list_is_a_failure() {
        let text = r#"{"TABLE_interface": {"ROW_interface": {"interface": "Ethernet1/1", "oper_mode": "trunk", "trunk_vlans": "26,x"}}}"#;
        assert_eq!(
            failure(parse_switchport(text, &defined())),
            ("show interface switchport | json", "invalid VLAN list item 'x'".to_owned())
        );
    }

    #[test]
    fn a_neighbour_table_missing_from_the_json_is_no_neighbour() {
        assert_eq!(parse_lldp(r#"{"neigh_hdr": "neigh_hdr"}"#), Ok(Vec::new()));
        assert_eq!(parse_cdp("{}"), Ok(Vec::new()));
    }

    #[test]
    fn cdp_port_that_is_a_mac_is_no_interface() {
        let text = r#"{"TABLE_cdp_neighbor_detail_info": {"ROW_cdp_neighbor_detail_info": {"intf_id": "Ethernet1/14", "device_id": "esx08.lab01", "port_id": "0216.31a4.10d8"}}}"#;
        assert_eq!(parse_cdp(text), Ok(vec![neighbor("Ethernet1/14", "esx08.lab01", None, "cdp")]));
    }

    #[test]
    fn cdp_of_the_second_release() {
        // `"device_id": "esx08.lab01"`, `"intf_id": "Ethernet1/14"`, `"port_id": "vmnic1"`.
        let neighbors = cdp(NXOS_I4);
        assert_eq!(neighbors.len(), 5);
        assert!(neighbors.contains(&neighbor("Ethernet1/14", "esx08.lab01", Some("vmnic1"), "cdp")));
        // `"device_id": "nexus04.lab01(FOC7881K47Q)"`, `"intf_id": "Ethernet1/38"`, `"port_id": "Ethernet1/38"`.
        assert!(neighbors.contains(&neighbor("Ethernet1/38", "nexus04.lab01", Some("Ethernet1/38"), "cdp")));
    }
}
