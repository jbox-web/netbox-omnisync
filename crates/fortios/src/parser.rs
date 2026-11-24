//! Parsers for the FortiOS REST API answers (7.4).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use omnisync_core::network::model::{Dot1q, Interface, IpAddress, Mode};
use omnisync_core::network::names::{interface_key, normalise_mac};
use serde_json::{Map, Value};

use crate::api::{HA, INTERFACES, MONITOR, STATUS};

type Row = Map<String, Value>;

// FortiOS interface type -> NetBox interface type. None: FortiOS does not tell the
// hardware of a physical port, the type is left unmanaged.
const TYPES: &[(&str, Option<&str>)] = &[
    ("physical", None),
    ("aggregate", Some("lag")),
    ("vlan", Some("virtual")),
    ("tunnel", Some("virtual")),
    ("hard-switch", Some("bridge")),
    // No hardware behind them: a loopback, and either end of a link between vdoms.
    ("loopback", Some("virtual")),
    ("vdom-link", Some("virtual")),
];
// The types whose `interface` field names the interface they run over.
const CHILDREN: [&str; 2] = ["vlan", "tunnel"];
const NO_ADDRESS: &str = "0.0.0.0 0.0.0.0";
const NO_MAC: &str = "00:00:00:00:00:00";
// The vdom every FortiGate has: its addresses live in the global table.
const ROOT_VDOM: &str = "root";
// The VLAN IDs of 802.1Q.
const VLAN_IDS: std::ops::RangeInclusive<u64> = 1..=4094;

/// An API answer could not be turned into data: the firewall is skipped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{call}: {reason}")]
pub struct ParseError {
    /// The call whose answer is not what its parser understands, as in `FORTIOS_COMMANDS`.
    pub call: &'static str,
    pub reason: String,
}

impl ParseError {
    fn new(call: &'static str, reason: impl Into<String>) -> Self {
        ParseError { call, reason: reason.into() }
    }
}

/// What the monitor tells about an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortState {
    /// None: the firewall shows no MAC of its own (aggregate, VLAN).
    pub mac: Option<String>,
    pub link_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// Keyed by interface name.
    pub interfaces: BTreeMap<String, Interface>,
    pub ips: Vec<IpAddress>,
    /// VID -> name of the VLAN interface.
    pub vlans: BTreeMap<u16, String>,
}

/// The answer of a call that succeeded, `results` included.
fn answer(call: &'static str, text: &str) -> Result<Row, ParseError> {
    let data: Value = serde_json::from_str(text).map_err(|_| {
        let start: String = text.trim().chars().take(80).collect();
        ParseError::new(call, format!("not JSON: {start:?}"))
    })?;
    let Value::Object(data) = data else {
        return Err(ParseError::new(call, "JSON answer is not an object"));
    };
    let status = data.get("status").unwrap_or(&Value::Null);
    if status != "success" || !data.contains_key("results") {
        return Err(ParseError::new(call, format!("not a successful answer (status {status})")));
    }
    Ok(data)
}

/// The rows of an answer whose `results` is a list.
fn result_rows<'a>(call: &'static str, data: &'a Row, what: &str) -> Result<Vec<&'a Row>, ParseError> {
    let Some(Value::Array(items)) = data.get("results") else {
        return Err(ParseError::new(call, "`results` is not a list"));
    };
    items
        .iter()
        .map(|item| item.as_object().ok_or_else(|| ParseError::new(call, format!("a {what} is not an object"))))
        .collect()
}

/// The answer whose `results` is an object.
fn result_object<'a>(call: &'static str, data: &'a Row) -> Result<&'a Row, ParseError> {
    match data.get("results") {
        Some(Value::Object(results)) => Ok(results),
        _ => Err(ParseError::new(call, "`results` is not an object")),
    }
}

/// A field every row holds; the reason names it when the row does not.
fn field<'a>(row: &'a Row, key: &str) -> Result<&'a Value, String> {
    row.get(key).ok_or_else(|| format!("row without `{key}`"))
}

fn text<'a>(row: &'a Row, key: &str) -> Result<&'a str, String> {
    field(row, key)?.as_str().ok_or_else(|| format!("`{key}` is not a text"))
}

fn list<'a>(row: &'a Row, key: &str) -> Result<&'a Vec<Value>, String> {
    field(row, key)?.as_array().ok_or_else(|| format!("`{key}` is not a list"))
}

/// A name or a serial: a text that is not empty.
fn named<'a>(row: &'a Row, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str).filter(|text| !text.is_empty())
}

fn vlan_id(row: &Row) -> Result<u16, String> {
    let vid = field(row, "vlanid")?.as_u64().filter(|vid| VLAN_IDS.contains(vid));
    vid.and_then(|vid| u16::try_from(vid).ok()).ok_or_else(|| "`vlanid` is not a VLAN ID".to_owned())
}

fn mtu(row: &Row) -> Result<u32, String> {
    let mtu = field(row, "mtu")?.as_u64().and_then(|mtu| u32::try_from(mtu).ok());
    mtu.ok_or_else(|| "`mtu` is not a number".to_owned())
}

/// `monitor/system/interface`: MAC and link of the interfaces the monitor lists.
pub fn parse_monitor(text: &str) -> Result<BTreeMap<String, PortState>, ParseError> {
    let data = answer(MONITOR, text)?;
    let mut states = BTreeMap::new();
    for (name, row) in result_object(MONITOR, &data)? {
        let failed = |reason: String| ParseError::new(MONITOR, format!("{name}: {reason}"));
        let row = row.as_object().ok_or_else(|| failed("not an object".to_owned()))?;
        let mac = self::text(row, "mac").map_err(failed)?;
        let link = field(row, "link").map_err(failed)?;
        let link_up = link.as_bool().ok_or_else(|| failed("`link` is not true or false".to_owned()))?;
        let mac = if mac == NO_MAC { None } else { normalise_mac(Some(mac)) };
        states.insert(name.clone(), PortState { mac, link_up });
    }
    // The firewall always has ports: no state at all is not an answer.
    if states.is_empty() {
        return Err(ParseError::new(MONITOR, "no interface"));
    }
    Ok(states)
}

/// `192.0.2.1 255.255.255.0` as `192.0.2.1/24`.
fn prefix(value: &str) -> Option<String> {
    let mut parts = value.split_whitespace();
    let (Some(address), Some(mask), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    let address: Ipv4Addr = address.parse().ok()?;
    let mask = u32::from(mask.parse::<Ipv4Addr>().ok()?);
    // A mask is ones then zeros, nothing else.
    (mask.leading_ones() + mask.trailing_zeros() == u32::BITS).then(|| format!("{address}/{}", mask.leading_ones()))
}

fn check_names(names: &[&str]) -> Result<(), ParseError> {
    // Interfaces are matched without case in NetBox: two such names would be one.
    let mut by_key: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for name in names {
        by_key.entry(interface_key(name)).or_default().push(name);
    }
    for mut names in by_key.into_values() {
        if names.len() > 1 {
            names.sort_unstable();
            return Err(ParseError::new(
                INTERFACES,
                format!("interfaces {} differ by case only: leave one out with ignore_interfaces", names.join(" and ")),
            ));
        }
    }
    Ok(())
}

/// `cmdb/system/interface`, completed by the monitor; `ignore` holds the
/// interfaces left out of the sync, by their exact name.
pub fn parse_interfaces(
    text: &str,
    monitor: &BTreeMap<String, PortState>,
    ignore: &[String],
) -> Result<Parsed, ParseError> {
    let data = answer(INTERFACES, text)?;
    let reported = result_rows(INTERFACES, &data, "row")?;
    // No interface would let a prune delete every one NetBox holds.
    if reported.is_empty() {
        return Err(ParseError::new(INTERFACES, "no interface"));
    }
    let mut rows: Vec<(&str, &Row)> = Vec::new();
    for row in reported {
        let name = self::text(row, "name").map_err(|reason| ParseError::new(INTERFACES, reason))?;
        if !ignore.iter().any(|ignored| ignored == name) {
            rows.push((name, row));
        }
    }
    if rows.is_empty() {
        return Err(ParseError::new(INTERFACES, "every interface is left out by ignore_interfaces"));
    }
    let failed = |name: &str, reason: String| ParseError::new(INTERFACES, format!("{name}: {reason}"));
    let names: Vec<&str> = rows.iter().map(|(name, _)| *name).collect();
    check_names(&names)?;
    let mut lag_of: BTreeMap<&str, &str> = BTreeMap::new();
    // An interface carrying VLAN interfaces is a trunk of their VIDs.
    let mut carried: BTreeMap<&str, Vec<u16>> = BTreeMap::new();
    for (name, row) in &rows {
        let failed = |reason: String| failed(name, reason);
        match self::text(row, "type").map_err(failed)? {
            "aggregate" => {
                for member in list(row, "member").map_err(failed)? {
                    let member = member.as_object().ok_or_else(|| failed("a member is not an object".to_owned()))?;
                    let port = member.get("interface-name").and_then(Value::as_str);
                    lag_of.insert(port.ok_or_else(|| failed("member without `interface-name`".to_owned()))?, name);
                }
            }
            "vlan" => {
                let over = self::text(row, "interface").map_err(failed)?;
                carried.entry(over).or_default().push(vlan_id(row).map_err(failed)?);
            }
            _ => {}
        }
    }
    let mut interfaces = BTreeMap::new();
    let mut ips = Vec::new();
    let mut vlans = BTreeMap::new();
    for (name, row) in &rows {
        let name = *name;
        let failed = |reason: String| failed(name, reason);
        let kind = self::text(row, "type").map_err(failed)?;
        let Some((_, netbox_type)) = TYPES.iter().find(|(known, _)| *known == kind) else {
            return Err(failed(format!("unsupported interface type '{kind}'")));
        };
        if !list(row, "secondaryip").map_err(failed)?.is_empty() {
            // No recorded sample of their format: ignoring them would let a prune
            // delete the ones NetBox holds.
            return Err(failed("secondary addresses are not supported yet".to_owned()));
        }
        let over = self::text(row, "interface").map_err(failed)?;
        let parent = (CHILDREN.contains(&kind) && !over.is_empty()).then_some(over);
        if let Some(parent) = parent
            && !names.contains(&parent)
        {
            return Err(failed(format!("parent interface {parent} is not reported")));
        }
        let vid = if kind == "vlan" { Some(vlan_id(row).map_err(failed)?) } else { None };
        let dot1q = match (carried.get(name), vid) {
            (Some(vids), _) => {
                let mut tagged_vlans = vids.clone();
                tagged_vlans.sort_unstable();
                Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans })
            }
            (None, Some(vid)) => Some(Dot1q { mode: Mode::Access, untagged_vlan: Some(vid), tagged_vlans: Vec::new() }),
            (None, None) => None,
        };
        // Without an override FortiOS only shows its default, not a setting.
        let overridden = self::text(row, "mtu-override").map_err(failed)? == "enable";
        // Tunnels and hard switches are absent from the monitor.
        let state = monitor.get(name);
        let interface = Interface {
            description: Some(self::text(row, "description").map_err(failed)?.to_owned()),
            mtu: if overridden { Some(mtu(row).map_err(failed)?) } else { None },
            r#type: netbox_type.map(str::to_owned),
            mac: state.and_then(|state| state.mac.clone()),
            lag: lag_of.get(name).map(|lag| (*lag).to_owned()),
            dot1q,
            link_up: state.map(|state| state.link_up),
            parent: parent.map(str::to_owned),
            // What the port announces over LLDP, when it has one.
            label: Some(self::text(row, "alias").map_err(failed)?.to_owned()),
            ..Interface::new(name, self::text(row, "status").map_err(failed)? == "up")
        };
        interfaces.insert(name.to_owned(), interface);
        let address = self::text(row, "ip").map_err(failed)?;
        let vdom = self::text(row, "vdom").map_err(failed)?;
        if address != NO_ADDRESS {
            let address =
                prefix(address).ok_or_else(|| failed(format!("address {address:?} is not an address and a mask")))?;
            let vrf = (vdom != ROOT_VDOM).then(|| vdom.to_owned());
            ips.push(IpAddress { address, interface: name.to_owned(), vrf });
        }
        if let Some(vid) = vid {
            vlans.entry(vid).or_insert_with(|| name.to_owned());
        }
    }
    Ok(Parsed { interfaces, ips, vlans })
}

/// `monitor/system/status`: host name and serial of the unit that answers.
pub fn parse_status(text: &str) -> Result<(String, String), ParseError> {
    let data = answer(STATUS, text)?;
    let hostname = named(result_object(STATUS, &data)?, "hostname");
    let hostname = hostname.ok_or_else(|| ParseError::new(STATUS, "no host name"))?;
    let serial = named(&data, "serial").ok_or_else(|| ParseError::new(STATUS, "no serial"))?;
    Ok((hostname.to_owned(), serial.to_owned()))
}

/// `monitor/system/ha-peer`: host name -> serial of every cluster member, the
/// answering unit included; empty on a standalone firewall.
pub fn parse_ha_peers(text: &str) -> Result<BTreeMap<String, String>, ParseError> {
    let data = answer(HA, text)?;
    let mut peers = BTreeMap::new();
    for row in result_rows(HA, &data, "member")? {
        let hostname = named(row, "hostname").ok_or_else(|| ParseError::new(HA, "member without a host name"))?;
        let serial = named(row, "serial_no")
            .ok_or_else(|| ParseError::new(HA, format!("{hostname}: member without a serial")))?;
        // The second serial would replace the first, and be written to the wrong device.
        if peers.insert(hostname.to_owned(), serial.to_owned()).is_some() {
            return Err(ParseError::new(HA, format!("two members are named {hostname}")));
        }
    }
    Ok(peers)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::fs;
    use std::path::Path;

    /// The answers of FortiOS v7.4.13 (build 2933), one directory per version.
    pub const V7_4_13: &str = "7.4.13";

    /// Return the recorded answer of the FortiOS `version` to `command`, named
    /// like the probe files.
    pub fn fixture_text(version: &str, command: &str) -> String {
        let name: String = command.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(version).join(format!("{name}.txt"));
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    }

    /// The first half of `text`: an answer cut short.
    pub fn halved(text: &str) -> String {
        text.chars().take(text.chars().count() / 2).collect()
    }
}

#[cfg(test)]
mod tests {
    use omnisync_core::network::model::{Dot1q, Mode};
    use serde_json::{Value, json};

    use super::fixtures::{V7_4_13, fixture_text, halved};
    use super::*;

    const CMDB: &str = "cmdb/system/interface?format=name|type|alias|description|status|mtu-override|mtu|vlanid|\
                        interface|member|ip|secondary-IP|secondaryip|vdom";
    const MONITOR: &str = "monitor/system/interface?include_vlan=true&include_aggregate=true";
    const STATUS: &str = "monitor/system/status";
    const HA: &str = "monitor/system/ha-peer";

    type Parser = Box<dyn Fn(&str) -> Result<(), ParseError>>;

    /// Every parser with the call it reads, its result dropped.
    fn parsers() -> Vec<(&'static str, Parser)> {
        vec![
            (CMDB, Box::new(|text| parse_interfaces(text, &BTreeMap::new(), &[]).map(drop))),
            (MONITOR, Box::new(|text| parse_monitor(text).map(drop))),
            (STATUS, Box::new(|text| parse_status(text).map(drop))),
            (HA, Box::new(|text| parse_ha_peers(text).map(drop))),
        ]
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn monitor() -> BTreeMap<String, PortState> {
        parse_monitor(&fixture_text(V7_4_13, MONITOR)).expect("a valid answer")
    }

    fn try_parsed(cmdb: Option<&str>, ignore: &[&str]) -> Result<Parsed, ParseError> {
        let recorded;
        let cmdb = match cmdb {
            Some(cmdb) => cmdb,
            None => {
                recorded = fixture_text(V7_4_13, CMDB);
                &recorded
            }
        };
        parse_interfaces(cmdb, &monitor(), &names(ignore))
    }

    /// The recorded answers, `dmz` left out.
    fn parsed() -> Parsed {
        try_parsed(None, &["dmz"]).expect("a valid answer")
    }

    fn parsed_from(cmdb: &str) -> Parsed {
        try_parsed(Some(cmdb), &["dmz"]).expect("a valid answer")
    }

    /// The recorded cmdb answer with some fields of one interface replaced, others removed.
    fn altered(name: &str, fields: Value, removed: &[&str]) -> String {
        let mut data: Value = serde_json::from_str(&fixture_text(V7_4_13, CMDB)).expect("the fixture is JSON");
        let rows = data["results"].as_array_mut().expect("a list of rows");
        let mut matching: Vec<&mut Value> = rows.iter_mut().filter(|row| row["name"] == name).collect();
        assert_eq!(matching.len(), 1, "one row named {name}");
        let row = matching[0].as_object_mut().expect("a row");
        for (key, value) in fields.as_object().expect("an object of fields") {
            row.insert(key.clone(), value.clone());
        }
        for field in removed {
            row.remove(*field).expect("the field is recorded");
        }
        data.to_string()
    }

    fn edited(name: &str, fields: Value) -> String {
        altered(name, fields, &[])
    }

    fn without(name: &str, field: &str) -> String {
        altered(name, json!({}), &[field])
    }

    /// An interface as a firewall reports it: a description and a label, here empty.
    fn interface(name: &str, enabled: bool) -> Interface {
        Interface { description: Some(String::new()), label: Some(String::new()), ..Interface::new(name, enabled) }
    }

    fn tagged(vlans: &[u16]) -> Dot1q {
        Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: vlans.to_vec() }
    }

    fn access(vlan: u16) -> Dot1q {
        Dot1q { mode: Mode::Access, untagged_vlan: Some(vlan), tagged_vlans: Vec::new() }
    }

    fn ip(address: &str, interface: &str, vrf: Option<&str>) -> IpAddress {
        IpAddress { address: address.to_owned(), interface: interface.to_owned(), vrf: vrf.map(str::to_owned) }
    }

    fn reason<T: std::fmt::Debug>(result: Result<T, ParseError>) -> String {
        result.expect_err("a parse failure").reason
    }

    fn success(results: Value) -> String {
        json!({"status": "success", "results": results}).to_string()
    }

    #[test]
    fn every_interface_but_the_ignored_one() {
        let interfaces = parsed().interfaces;
        // 53 in the answer, `dmz` left out.
        assert_eq!(interfaces.len(), 52);
        assert!(!interfaces.contains_key("dmz"));
        assert!(interfaces.contains_key("DMZ"));
    }

    #[test]
    fn physical_port_member_of_an_aggregate() {
        assert_eq!(
            parsed().interfaces["x1"],
            Interface {
                mac: Some("02:00:5E:00:28:DE".to_owned()),
                lag: Some("PO2".to_owned()),
                link_up: Some(true),
                ..interface("x1", true)
            }
        );
    }

    #[test]
    fn physical_port_down_with_a_description() {
        assert_eq!(
            parsed().interfaces["wan1"],
            Interface {
                description: Some("OUTSIDE to LABLU/BS-SW001 G1/0/6".to_owned()),
                mac: Some("02:00:5E:00:28:CE".to_owned()),
                link_up: Some(false),
                label: Some("OUTSIDE".to_owned()),
                ..interface("wan1", false)
            }
        );
    }

    #[test]
    fn aggregate_carrying_vlans_is_tagged_with_them() {
        assert_eq!(
            parsed().interfaces["PO2"],
            Interface {
                description: Some("Port-Channel 2 to LABLU/BS-SW001 PO2".to_owned()),
                r#type: Some("lag".to_owned()),
                dot1q: Some(tagged(&[4, 10, 11, 12, 15, 17, 18, 24, 25, 27])),
                link_up: Some(true),
                label: Some("Port-Channel 2".to_owned()),
                ..interface("PO2", true)
            }
        );
    }

    #[test]
    fn single_member_aggregate() {
        let interfaces = parsed().interfaces;
        assert_eq!(interfaces["wan2"].lag.as_deref(), Some("PO1"));
        assert_eq!(interfaces["PO1"].dot1q, Some(tagged(&[954])));
    }

    #[test]
    fn aggregate_without_member_nor_vlan() {
        assert_eq!(
            parsed().interfaces["fortilink"],
            Interface { r#type: Some("lag".to_owned()), link_up: Some(false), ..interface("fortilink", false) }
        );
    }

    #[test]
    fn vlan_interface_runs_over_its_aggregate() {
        assert_eq!(
            parsed().interfaces["HOUSING"],
            Interface {
                description: Some("HOUSING".to_owned()),
                r#type: Some("virtual".to_owned()),
                dot1q: Some(access(12)),
                link_up: Some(true),
                parent: Some("PO2".to_owned()),
                ..interface("HOUSING", true)
            }
        );
    }

    #[test]
    fn vlan_carrying_tunnels_only_stays_access() {
        let internet = &parsed().interfaces["INTERNET"];
        assert_eq!((internet.parent.as_deref(), internet.dot1q.clone()), (Some("PO1"), Some(access(954))));
    }

    #[test]
    fn tunnel_runs_over_its_uplink_and_is_absent_from_the_monitor() {
        assert_eq!(
            parsed().interfaces["VPN_DC2"],
            Interface {
                r#type: Some("virtual".to_owned()),
                parent: Some("INTERNET".to_owned()),
                ..interface("VPN_DC2", true)
            }
        );
    }

    #[test]
    fn system_tunnel_has_no_parent() {
        assert_eq!(parsed().interfaces["ssl.root"].parent, None);
    }

    #[test]
    fn hard_switch_is_a_bridge() {
        assert_eq!(
            parsed().interfaces["lan"],
            Interface { r#type: Some("bridge".to_owned()), ..interface("lan", false) }
        );
    }

    #[test]
    fn alias_becomes_the_label() {
        let interfaces = parsed().interfaces;
        let labels: BTreeMap<&str, &str> = interfaces
            .iter()
            .filter_map(|(name, interface)| Some((name.as_str(), interface.label.as_deref()?)))
            .filter(|(_, label)| !label.is_empty())
            .collect();
        assert_eq!(
            labels,
            BTreeMap::from([
                ("PO1", "Port-Channel 1"),
                ("PO2", "Port-Channel 2"),
                ("ssl.root", "SSL VPN interface"),
                ("wan1", "OUTSIDE"),
            ])
        );
        // An interface without an alias still reports a label, an empty one.
        assert_eq!(interfaces["x1"].label.as_deref(), Some(""));
    }

    #[test]
    fn mtu_is_managed_only_when_overridden() {
        assert!(parsed().interfaces.values().all(|interface| interface.mtu.is_none()));
        let cmdb = edited("HOUSING", json!({"mtu-override": "enable", "mtu": 9000}));
        assert_eq!(parsed_from(&cmdb).interfaces["HOUSING"].mtu, Some(9000));
    }

    #[test]
    fn addresses_become_prefixes_in_the_global_table() {
        let mut ips = parsed().ips;
        ips.sort_by(|a, b| a.interface.cmp(&b.interface));
        assert_eq!(
            ips,
            [
                ip("10.0.12.1/24", "ADMIN", None),
                ip("10.0.11.1/24", "BO", None),
                ip("10.0.10.1/24", "DMZ", None),
                ip("10.0.24.1/24", "ESX", None),
                ip("10.0.27.1/24", "ESX-BACKUP", None),
                ip("10.0.25.1/24", "ESX-STORAGE", None),
                ip("10.0.13.1/24", "HOUSING", None),
                ip("10.0.17.1/24", "ILO", None),
                ip("10.0.15.1/24", "INTERCLUSTER", None),
                ip("10.0.16.1/24", "INTERCO-EXT", None),
                ip("198.51.100.68/28", "INTERNET", None),
                ip("169.254.1.1/24", "fortilink", None),
                ip("10.99.254.54/24", "mgmt", None),
                ip("203.0.113.134/26", "wan1", None),
            ]
        );
    }

    #[test]
    fn another_vdom_is_a_vrf() {
        let ips = parsed_from(&edited("HOUSING", json!({"vdom": "customer"}))).ips;
        assert!(ips.contains(&ip("10.0.13.1/24", "HOUSING", Some("customer"))));
    }

    #[test]
    fn secondary_addresses_stop_the_collection() {
        let cmdb = edited("HOUSING", json!({"secondaryip": [{"id": 1}]}));
        let error = try_parsed(Some(&cmdb), &["dmz"]).expect_err("a parse failure");
        assert_eq!(error.call, CMDB);
        assert_eq!(error.reason, "HOUSING: secondary addresses are not supported yet");
    }

    #[test]
    fn site_vlans_take_the_interface_names() {
        let expected: BTreeMap<u16, String> = [
            (4, "ADMIN"),
            (10, "DMZ"),
            (11, "BO"),
            (12, "HOUSING"),
            (15, "INTERCLUSTER"),
            (17, "INTERCO-EXT"),
            (18, "ILO"),
            (24, "ESX"),
            (25, "ESX-STORAGE"),
            (27, "ESX-BACKUP"),
            (954, "INTERNET"),
        ]
        .into_iter()
        .map(|(vid, name)| (vid, name.to_owned()))
        .collect();
        assert_eq!(parsed().vlans, expected);
    }

    #[test]
    fn first_vlan_interface_of_a_vid_names_it() {
        // In the answer `ADMIN` (VID 4) comes before `BO`.
        let cmdb = edited("BO", json!({"vlanid": 4}));
        assert_eq!(parsed_from(&cmdb).vlans[&4], "ADMIN");
    }

    #[test]
    fn names_differing_by_case_only_stop_the_collection() {
        let error = try_parsed(None, &[]).expect_err("a parse failure");
        assert_eq!(error.call, CMDB);
        assert_eq!(error.reason, "interfaces DMZ and dmz differ by case only: leave one out with ignore_interfaces");
    }

    #[test]
    fn unknown_interface_type_stops_the_collection() {
        let cmdb = edited("port1", json!({"type": "redundant"}));
        assert_eq!(reason(try_parsed(Some(&cmdb), &["dmz"])), "port1: unsupported interface type 'redundant'");
    }

    // A loopback and the two ends of a link between vdoms are interfaces of no
    // hardware: virtual, as a VLAN or a tunnel. Without them in the list, a
    // FortiGate that has one could not be synced without ignoring it.
    #[test]
    fn a_loopback_and_a_vdom_link_are_virtual() {
        for kind in ["loopback", "vdom-link"] {
            let cmdb = edited("port1", json!({"type": kind}));
            let parsed = try_parsed(Some(&cmdb), &["dmz"]).expect(kind);
            assert_eq!(parsed.interfaces["port1"].r#type.as_deref(), Some("virtual"), "{kind}");
        }
    }

    #[test]
    fn parent_left_out_stops_the_collection() {
        assert_eq!(
            reason(try_parsed(None, &["dmz", "INTERNET"])),
            "VPN_DC2: parent interface INTERNET is not reported"
        );
    }

    #[test]
    fn ignored_member_is_not_attached() {
        let interfaces = try_parsed(None, &["dmz", "x2"]).expect("a valid answer").interfaces;
        assert!(!interfaces.contains_key("x2"));
        assert_eq!(interfaces["x1"].lag.as_deref(), Some("PO2"));
    }

    #[test]
    fn monitor_gives_the_mac_and_the_link() {
        let monitor = monitor();
        // "x1":{"id":"x1","name":"x1","alias":"","mac":"02:00:5e:00:28:de",…,"link":true
        assert_eq!(monitor["x1"], PortState { mac: Some("02:00:5E:00:28:DE".to_owned()), link_up: true });
        // "wan1":{"id":"wan1","name":"wan1","alias":"(OUTSIDE)","mac":"02:00:5e:00:28:ce",…,"link":false
        assert_eq!(monitor["wan1"], PortState { mac: Some("02:00:5E:00:28:CE".to_owned()), link_up: false });
        // "PO2":{"id":"PO2","name":"PO2","alias":"(Port-Channel 2)","mac":"00:00:00:00:00:00",…,"link":true
        assert_eq!(monitor["PO2"], PortState { mac: None, link_up: true });
        // Tunnels and hard switches are absent from the monitor.
        assert!(!monitor.contains_key("VPN_DC2"));
        assert!(!monitor.contains_key("lan"));
    }

    #[test]
    fn status_gives_the_host_name_and_the_serial() {
        assert_eq!(
            parse_status(&fixture_text(V7_4_13, STATUS)),
            Ok(("LABLU-FWL01".to_owned(), "FG101FTK22000001".to_owned()))
        );
    }

    #[test]
    fn ha_peers_give_the_serial_of_every_member() {
        assert_eq!(
            parse_ha_peers(&fixture_text(V7_4_13, HA)),
            Ok(BTreeMap::from([
                ("LABLU-FWL01".to_owned(), "FG101FTK22000001".to_owned()),
                ("LABBS-FWL01".to_owned(), "FG101FTK22000002".to_owned()),
            ]))
        );
    }

    #[test]
    fn standalone_firewall_has_no_peer() {
        assert_eq!(parse_ha_peers(r#"{"status": "success", "results": []}"#), Ok(BTreeMap::new()));
    }

    #[test]
    fn answer_that_is_not_a_successful_one() {
        for text in ["", "<html>login</html>", "[]", r#"{"status": "error"}"#] {
            for (call, parser) in parsers() {
                let error = parser(text).expect_err("a parse failure");
                assert_eq!(error.call, call, "{text:?}");
            }
        }
    }

    #[test]
    fn each_kind_of_garbage_is_named() {
        assert_eq!(reason(parse_status("")), r#"not JSON: """#);
        assert_eq!(reason(parse_status(" <html>login</html>\n")), r#"not JSON: "<html>login</html>""#);
        assert_eq!(reason(parse_status("[]")), "JSON answer is not an object");
        assert_eq!(reason(parse_status(r#"{"status": "error"}"#)), r#"not a successful answer (status "error")"#);
        assert_eq!(reason(parse_status(r#"{"results": {}}"#)), "not a successful answer (status null)");
        // A success without the results it announces.
        assert_eq!(reason(parse_status(r#"{"status": "success"}"#)), r#"not a successful answer (status "success")"#);
    }

    #[test]
    fn only_the_start_of_what_is_not_json_is_quoted() {
        let page = "x".repeat(200);
        assert_eq!(reason(parse_monitor(&page)), format!("not JSON: {:?}", "x".repeat(80)));
    }

    #[test]
    fn answer_cut_short_fails_naming_its_call() {
        for (call, parser) in parsers() {
            let error = parser(&halved(&fixture_text(V7_4_13, call))).expect_err("a parse failure");
            assert_eq!(error.call, call);
            assert!(error.reason.starts_with("not JSON: "), "{}", error.reason);
        }
    }

    #[test]
    fn recorded_answers_parse() {
        // The contrary of the failures above, on the same parsers.
        for (call, parser) in parsers() {
            // The cmdb answer holds `dmz` and `DMZ`: without `ignore` it is refused.
            if call != CMDB {
                assert_eq!(parser(&fixture_text(V7_4_13, call)), Ok(()), "{call}");
            }
        }
    }

    #[test]
    fn results_of_another_shape_fail_naming_their_call() {
        for results in [json!("x"), json!(7), json!(null), json!([7]), json!({"x1": 7})] {
            for (call, parser) in parsers() {
                let error = parser(&success(results.clone())).expect_err("a parse failure");
                assert_eq!(error.call, call, "{results}");
            }
        }
    }

    #[test]
    fn no_interface_is_never_an_answer() {
        // Nothing reported would let a prune delete every interface NetBox holds.
        assert_eq!(reason(parse_interfaces(&success(json!([])), &BTreeMap::new(), &[])), "no interface");
        assert_eq!(reason(parse_monitor(&success(json!({})))), "no interface");
        // The wrong container is not an empty answer either.
        assert_eq!(reason(parse_interfaces(&success(json!({})), &BTreeMap::new(), &[])), "`results` is not a list");
        assert_eq!(reason(parse_monitor(&success(json!([])))), "`results` is not an object");
    }

    #[test]
    fn every_interface_left_out_is_never_an_answer() {
        let one = success(json!([{"name": "port1"}]));
        assert_eq!(
            reason(parse_interfaces(&one, &BTreeMap::new(), &names(&["port1"]))),
            "every interface is left out by ignore_interfaces"
        );
    }

    #[test]
    fn interface_row_without_a_field_stops_the_collection() {
        for field in
            ["type", "alias", "description", "status", "mtu-override", "interface", "ip", "secondaryip", "vdom"]
        {
            let error = try_parsed(Some(&without("HOUSING", field)), &["dmz"]).expect_err("a parse failure");
            assert_eq!(error.call, CMDB);
            assert_eq!(error.reason, format!("HOUSING: row without `{field}`"));
        }
        // Read on a VLAN interface, on an aggregate, and under an override only.
        assert_eq!(reason(try_parsed(Some(&without("HOUSING", "vlanid")), &["dmz"])), "HOUSING: row without `vlanid`");
        assert_eq!(reason(try_parsed(Some(&without("PO2", "member")), &["dmz"])), "PO2: row without `member`");
        let overridden = altered("HOUSING", json!({"mtu-override": "enable"}), &["mtu"]);
        assert_eq!(reason(try_parsed(Some(&overridden), &["dmz"])), "HOUSING: row without `mtu`");
        assert_eq!(reason(try_parsed(Some(&success(json!([{"type": "vlan"}]))), &[])), "row without `name`");
    }

    #[test]
    fn interface_field_of_another_type_stops_the_collection() {
        for (name, fields, expected) in [
            ("HOUSING", json!({"name": 7}), "`name` is not a text"),
            ("HOUSING", json!({"description": null}), "HOUSING: `description` is not a text"),
            ("HOUSING", json!({"vlanid": "12"}), "HOUSING: `vlanid` is not a VLAN ID"),
            ("HOUSING", json!({"vlanid": 4095}), "HOUSING: `vlanid` is not a VLAN ID"),
            ("HOUSING", json!({"vlanid": 0}), "HOUSING: `vlanid` is not a VLAN ID"),
            ("HOUSING", json!({"mtu-override": "enable", "mtu": "big"}), "HOUSING: `mtu` is not a number"),
            ("HOUSING", json!({"secondaryip": "none"}), "HOUSING: `secondaryip` is not a list"),
            ("PO2", json!({"member": [{"name": "x1"}]}), "PO2: member without `interface-name`"),
            ("PO2", json!({"member": ["x1"]}), "PO2: a member is not an object"),
        ] {
            assert_eq!(reason(try_parsed(Some(&edited(name, fields.clone())), &["dmz"])), expected, "{fields}");
        }
    }

    #[test]
    fn address_that_is_not_an_address_and_a_mask_stops_the_collection() {
        for (address, expected) in [
            ("10.0.13.1", "HOUSING: address \"10.0.13.1\" is not an address and a mask"),
            (
                "10.0.13.1 255.255.255.0 x",
                "HOUSING: address \"10.0.13.1 255.255.255.0 x\" is not an address and a mask",
            ),
            ("10.0.13 255.255.255.0", "HOUSING: address \"10.0.13 255.255.255.0\" is not an address and a mask"),
            // Not a mask: its bits are not contiguous.
            ("10.0.13.1 255.0.255.0", "HOUSING: address \"10.0.13.1 255.0.255.0\" is not an address and a mask"),
            ("", "HOUSING: address \"\" is not an address and a mask"),
        ] {
            let cmdb = edited("HOUSING", json!({"ip": address}));
            assert_eq!(reason(try_parsed(Some(&cmdb), &["dmz"])), expected);
        }
    }

    #[test]
    fn masks_of_every_length_become_prefix_lengths() {
        for (mask, expected) in [
            ("255.255.255.255", "10.0.13.1/32"),
            ("255.255.255.252", "10.0.13.1/30"),
            ("255.255.254.0", "10.0.13.1/23"),
            ("255.0.0.0", "10.0.13.1/8"),
            ("0.0.0.0", "10.0.13.1/0"),
        ] {
            let cmdb = edited("HOUSING", json!({"ip": format!("10.0.13.1 {mask}")}));
            assert!(parsed_from(&cmdb).ips.contains(&ip(expected, "HOUSING", None)), "{mask}");
        }
    }

    #[test]
    fn monitor_row_of_another_shape_stops_the_collection() {
        let row = |fields: Value| success(json!({"x1": fields}));
        assert_eq!(reason(parse_monitor(&row(json!({"link": true})))), "x1: row without `mac`");
        assert_eq!(reason(parse_monitor(&row(json!({"mac": 7, "link": true})))), "x1: `mac` is not a text");
        assert_eq!(reason(parse_monitor(&row(json!({"mac": "02:00:5e:00:28:de"})))), "x1: row without `link`");
        assert_eq!(
            reason(parse_monitor(&row(json!({"mac": "02:00:5e:00:28:de", "link": "up"})))),
            "x1: `link` is not true or false"
        );
        assert_eq!(reason(parse_monitor(&success(json!({"x1": 7})))), "x1: not an object");
    }

    #[test]
    fn status_without_host_name_or_serial_stops_the_collection() {
        let status = |results: Value, serial: Value| {
            json!({"status": "success", "results": results, "serial": serial}).to_string()
        };
        assert_eq!(reason(parse_status(&status(json!({}), json!("FG101FTK22000001")))), "no host name");
        assert_eq!(reason(parse_status(&status(json!({"hostname": ""}), json!("FG101FTK22000001")))), "no host name");
        assert_eq!(reason(parse_status(&status(json!({"hostname": "LABLU-FWL01"}), json!(null)))), "no serial");
        assert_eq!(reason(parse_status(&status(json!({"hostname": "LABLU-FWL01"}), json!("")))), "no serial");
        assert_eq!(reason(parse_status(&success(json!({"hostname": "LABLU-FWL01"})))), "no serial");
        assert_eq!(reason(parse_status(&success(json!([])))), "`results` is not an object");
    }

    #[test]
    fn ha_peer_without_host_name_or_serial_stops_the_collection() {
        assert_eq!(
            reason(parse_ha_peers(&success(json!([{"serial_no": "FG101FTK22000002"}])))),
            "member without a host name"
        );
        assert_eq!(
            reason(parse_ha_peers(&success(json!([{"hostname": "LABBS-FWL01"}])))),
            "LABBS-FWL01: member without a serial"
        );
        assert_eq!(
            reason(parse_ha_peers(&success(json!([{"hostname": "LABBS-FWL01", "serial_no": ""}])))),
            "LABBS-FWL01: member without a serial"
        );
        assert_eq!(reason(parse_ha_peers(&success(json!({})))), "`results` is not a list");
    }

    #[test]
    fn two_ha_peers_of_the_same_host_name_stop_the_collection() {
        // One of the two serials would be lost, and the other written to the wrong device.
        let peers = success(json!([
            {"hostname": "FortiGate-101F", "serial_no": "FG101FTK22000001"},
            {"hostname": "FortiGate-101F", "serial_no": "FG101FTK22000002"},
        ]));
        assert_eq!(reason(parse_ha_peers(&peers)), "two members are named FortiGate-101F");
    }
}
