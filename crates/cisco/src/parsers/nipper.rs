//! Parser for the HTML configuration reports Nipper produces for Cisco switches.
//!
//! Used for switches nobody may log into (managed by a provider): the report is the
//! only view of their configuration. It gives the ports, their state, their
//! descriptions, their 802.1Q mode and the VLAN of an access port; MTU, MACs, the
//! VLANs of a trunk, LAG membership, IPs and serials are not in a usable form and
//! stay unmanaged. What its columns mean was observed: `tests/fixtures/README.md`.

use std::collections::BTreeSet;
use std::ops::Deref;

use omnisync_core::network::model::{DeviceState, Dot1q, Interface, Mode};
use scraper::{ElementRef, Html, Selector};

use super::ParseError;

/// A table of the page, as rows of cell texts.
type Table = Vec<Vec<String>>;

// Port name prefix -> NetBox interface type. A physical port name does not tell
// the media (TenGigabitEthernet is an SFP+ cage or mGig RJ45): its type is unmanaged.
const TYPES: [(&str, &str); 2] = [("Port-channel", "lag"), ("Vlan", "virtual")];
const SWITCHPORT_HEADER: [&str; 3] = ["Interface", "Active", "Description"];
const INTERFACES_HEADER: [&str; 3] = ["Interface", "Active", "IP Address"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NipperReport {
    pub hostname: String,
    pub location: Option<String>,
    pub ios_version: Option<String>,
    pub state: DeviceState,
}

fn selector(css: &str) -> Selector {
    Selector::parse(css).expect("valid selector")
}

/// The text of a cell, its runs of white space collapsed.
fn cell_text(cell: ElementRef<'_>) -> String {
    cell.text().collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The table a row belongs to: the closest one around it.
fn table_of(row: ElementRef<'_>) -> Option<ElementRef<'_>> {
    row.ancestors().filter_map(ElementRef::wrap).find(|element| element.value().name() == "table")
}

/// Every table of the page, as rows of cell texts.
fn tables(page: &Html) -> Vec<Table> {
    let (table, row, cell) = (selector("table"), selector("tr"), selector("td, th"));
    page.select(&table)
        .map(|element| {
            element
                .select(&row)
                .filter(|found| table_of(*found).is_some_and(|owner| owner.id() == element.id()))
                .map(|found| {
                    found.select(&cell).filter(|cell| cell.parent() == Some(*found.deref())).map(cell_text).collect()
                })
                .collect()
        })
        .collect()
}

fn starts_with(table: &Table, header: &[&str]) -> bool {
    table.first().is_some_and(|first| first.len() >= header.len() && first.iter().zip(header).all(|(a, b)| a == b))
}

/// The `Description | Setting` tables, merged: first value of each setting.
fn setting<'t>(tables: &'t [Table], name: &str) -> Option<&'t str> {
    tables
        .iter()
        .filter(|table| starts_with(table, &["Description", "Setting"]))
        .flat_map(|table| table.iter().skip(1))
        .find(|row| row.len() >= 2 && row[0] == name)
        .map(|row| row[1].as_str())
}

fn interface(name: &str, active: &str, description: Option<&str>) -> Interface {
    Interface {
        description: description.map(str::to_owned),
        r#type: TYPES.iter().find(|(prefix, _)| name.starts_with(prefix)).map(|(_, kind)| (*kind).to_owned()),
        lag_managed: false,
        dot1q_managed: false,
        ..Interface::new(name, active == "Yes")
    }
}

/// Where the columns `VLAN` and `Mode` of the switchport table are, when it has both.
fn dot1q_columns(header: &[String]) -> Option<(usize, usize)> {
    let column = |name: &str| header.iter().position(|cell| cell == name);
    Some((column("VLAN")?, column("Mode")?))
}

/// `port` with what its row says of its 802.1Q.
///
/// The `Mode` column is the administrative mode of the port and the `VLAN` one
/// its access VLAN, whatever the mode: on a trunk it is not the native VLAN,
/// and no column lists the VLANs the trunk allows. Those stay unknown, and
/// NetBox keeps the ones it has. A mode that is neither `Access` nor `Trunk`
/// tells nothing.
fn with_dot1q(port: Interface, vlan: Option<&str>, mode: Option<&str>) -> Interface {
    let dot1q = |mode, untagged_vlan| Some(Dot1q { mode, untagged_vlan, tagged_vlans: Vec::new() });
    match mode {
        Some("Access") => {
            let vid = vlan.and_then(|vlan| vlan.parse::<u16>().ok());
            Interface {
                dot1q: dot1q(Mode::Access, vid),
                dot1q_managed: true,
                untagged_vlan_managed: vid.is_some(),
                ..port
            }
        }
        Some("Trunk") => Interface {
            dot1q: dot1q(Mode::Tagged, None),
            dot1q_managed: true,
            untagged_vlan_managed: false,
            tagged_vlans_managed: false,
            ..port
        },
        _ => port,
    }
}

pub fn parse_report(html: &str) -> Result<NipperReport, ParseError> {
    let tables = tables(&Html::parse_document(html));
    let hostname = setting(&tables, "Hostname").filter(|hostname| !hostname.is_empty());
    let ports = tables.iter().find(|table| starts_with(table, &SWITCHPORT_HEADER));
    let (Some(hostname), Some(ports)) = (hostname, ports) else {
        return Err(ParseError::Report("no hostname or switchport table".to_owned()));
    };
    // A page cut short lists fewer ports than the switch has: a prune would
    // delete the others.
    if !html.trim_end().to_ascii_lowercase().ends_with("</html>") {
        return Err(ParseError::Report("the page is cut short".to_owned()));
    }
    // The report gives a switchport row to a routed port as well (the management
    // port of a stack, as an access port of VLAN 1): a port the interfaces table
    // gives an address is not a switchport, and its 802.1Q stays unmanaged.
    let routed: BTreeSet<&str> = tables
        .iter()
        .filter(|table| starts_with(table, &INTERFACES_HEADER))
        .flat_map(|table| table.iter().skip(1))
        .filter(|row| row.len() >= 3 && !row[2].is_empty() && row[2] != "None")
        .map(|row| row[0].as_str())
        .collect();
    let columns = ports.first().and_then(|header| dot1q_columns(header));
    let mut state = DeviceState { ips_managed: false, ..DeviceState::default() };
    for row in ports.iter().skip(1).filter(|row| row.len() >= 3) {
        let port = interface(&row[0], &row[1], Some(&row[2]));
        let port = match columns {
            Some((vlan, mode)) if !routed.contains(row[0].as_str()) => {
                with_dot1q(port, row.get(vlan).map(String::as_str), row.get(mode).map(String::as_str))
            }
            _ => port,
        };
        state.interfaces.insert(row[0].clone(), port);
    }
    // The interfaces table also lists the SVIs, which have no switchport: without
    // them a prune would delete their NetBox interfaces. It has no Description
    // column, so their description is unmanaged.
    for table in tables.iter().filter(|table| starts_with(table, &INTERFACES_HEADER)) {
        for row in table.iter().skip(1).filter(|row| row.len() >= 2) {
            if !state.interfaces.contains_key(&row[0]) {
                state.interfaces.insert(row[0].clone(), interface(&row[0], &row[1], None));
            }
        }
    }
    Ok(NipperReport {
        hostname: hostname.to_owned(),
        location: setting(&tables, "Location").map(str::to_owned),
        ios_version: setting(&tables, "IOS Version").map(str::to_owned),
        state,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use omnisync_core::network::model::{Dot1q, Mode};

    use super::*;
    use crate::parsers::fixtures::{halved, nipper_report};

    fn state(name: &str) -> DeviceState {
        parse_report(&nipper_report(name)).expect("the fixture parses").state
    }

    #[test]
    fn report_identity() {
        // `<td>Hostname</td>` / `<td>FPLAB1-SW001</td>` in the general settings table.
        let report = parse_report(&nipper_report("fplab1-sw001")).expect("the fixture parses");
        assert_eq!(report.hostname, "FPLAB1-SW001");
        assert_eq!(report.location.as_deref(), Some("Customer:EXAMPLE - Rack: SITE1 R01"));
        assert_eq!(report.ios_version.as_deref(), Some("16.3"));
    }

    #[test]
    fn every_port_of_the_switchport_and_interfaces_tables() {
        // 138 switchport ports, plus the SVIs only the interfaces table lists.
        let state = state("fplab1-sw001");
        assert_eq!(state.interfaces.len(), 141);
        assert_eq!(self::state("fplab2-sw001").interfaces.len(), 142);
        let svi = &state.interfaces["Vlan952"];
        assert!(svi.enabled);
        assert_eq!(svi.r#type.as_deref(), Some("virtual"));
        assert!(!svi.dot1q_managed);
    }

    #[test]
    fn svi_description_stays_unmanaged() {
        // The interfaces table has no Description column: the report says nothing of it.
        assert_eq!(state("fplab1-sw001").interfaces["Vlan952"].description, None);
    }

    #[test]
    fn port_fields() {
        let interfaces = state("fplab1-sw001").interfaces;
        let port = &interfaces["TenGigabitEthernet1/0/40"];
        assert!(port.enabled);
        assert_eq!(port.description.as_deref(), Some("N:lab1-pve01 enp129s0 10G Vlan 10-11-12"));
        assert!(!interfaces["GigabitEthernet1/0/1"].enabled);
        assert_eq!(interfaces["Port-channel40"].r#type.as_deref(), Some("lag"));
        assert_eq!(
            interfaces["Port-channel40"].description.as_deref(),
            Some("N:lab1-pve01 enp129s0 + enp130s0 10G Vlan 10-11-12")
        );
    }

    #[test]
    fn physical_port_type_stays_unmanaged() {
        // A port name does not tell the media: Te1/0/40 may be an SFP+ cage or mGig RJ45.
        let interfaces = state("fplab1-sw001").interfaces;
        assert_eq!(interfaces["TenGigabitEthernet1/0/40"].r#type, None);
        assert_eq!(interfaces["GigabitEthernet1/0/1"].r#type, None);
        assert_eq!(interfaces["GigabitEthernet0/0"].r#type, None);
    }

    #[test]
    fn unreported_fields_stay_unmanaged() {
        let state = state("fplab1-sw001");
        let port = &state.interfaces["TenGigabitEthernet1/0/40"];
        assert_eq!(port.mtu, None);
        assert_eq!(port.mac, None);
        assert!(!port.lag_managed);
        assert!(!state.ips_managed);
        assert_eq!(state.serial, None);
        assert_eq!(state.member_serials, BTreeMap::new());
        assert_eq!(state.vlans, BTreeMap::new());
        assert_eq!(state.ips, []);
        assert_eq!(state.neighbors, []);
    }

    #[test]
    fn not_a_nipper_report() {
        assert_eq!(
            parse_report("<html><body>Login</body></html>"),
            Err(ParseError::Report("no hostname or switchport table".to_owned()))
        );
    }

    // What follows is not in the Python tests.

    #[test]
    fn a_port_without_description_has_an_empty_one() {
        // An empty Description cell is a value: the port has no description.
        let html = "<html><body><table><tr><th>Description</th><th>Setting</th></tr>\
                    <tr><td>Hostname</td><td>SW1</td></tr></table>\
                    <table><tr><th>Interface</th><th>Active</th><th>Description</th></tr>\
                    <tr><td>GigabitEthernet1/0/1</td><td>No</td><td></td></tr></table></body></html>";
        let report = parse_report(html).expect("a valid report");
        assert_eq!(report.state.interfaces["GigabitEthernet1/0/1"].description.as_deref(), Some(""));
        assert_eq!(report.location, None);
    }

    #[test]
    fn cell_texts_are_decoded_and_their_spaces_collapsed() {
        let html = "<html><body><table><tr><th>Description</th><th>Setting</th></tr>\
                    <tr><td>Hostname</td><td> SW1 </td></tr></table>\
                    <table><tr><th>Interface</th><th>Active</th><th>Description</th></tr>\
                    <tr><td>GigabitEthernet1/0/1</td><td>Yes</td><td>a &amp;  b\n <b>c</b></td></tr></table></body></html>";
        let report = parse_report(html).expect("a valid report");
        assert_eq!(report.hostname, "SW1");
        assert_eq!(report.state.interfaces["GigabitEthernet1/0/1"].description.as_deref(), Some("a & b c"));
    }

    // What the columns VLAN and Mode are is in `tests/fixtures/README.md`.

    #[test]
    fn the_mode_and_the_access_vlan_of_a_port_come_from_the_report() {
        let interfaces = state("fplab1-sw001").interfaces;
        // `GigabitEthernet1/0/1 | No | IAS3.S1 G1/2 | 1511 | Access`
        let port = &interfaces["GigabitEthernet1/0/1"];
        assert!(port.dot1q_managed);
        assert_eq!(port.dot1q, Some(Dot1q { mode: Mode::Access, untagged_vlan: Some(1511), tagged_vlans: Vec::new() }));
        assert!(port.untagged_vlan_managed);
        assert!(port.tagged_vlans_managed);
        // `Port-channel24 | Yes | LAB1-PRE01 ETH0-ETH1 T:HOU V:12 | 12 | Access`
        let aggregate = &interfaces["Port-channel24"];
        assert_eq!(
            aggregate.dot1q,
            Some(Dot1q { mode: Mode::Access, untagged_vlan: Some(12), tagged_vlans: Vec::new() })
        );
    }

    #[test]
    fn a_trunk_of_the_report_has_no_vlan_list_of_its_own() {
        let interfaces = state("fplab1-sw001").interfaces;
        // `GigabitEthernet1/0/5 | Yes | fplab1-rt002_Gi0/0 D:Interco-Directe | 2 | Trunk`: the 2 is the
        // access VLAN of the port, not its native one, and the VLANs it allows are in no column.
        let port = &interfaces["GigabitEthernet1/0/5"];
        assert!(port.dot1q_managed);
        assert_eq!(port.dot1q, Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: Vec::new() }));
        assert!(!port.untagged_vlan_managed);
        assert!(!port.tagged_vlans_managed);
        // `Port-channel40 | Yes | N:lab1-pve01 enp129s0 + enp130s0 10G Vlan 10-11-12 | 2 | Trunk`
        let aggregate = &interfaces["Port-channel40"];
        assert_eq!(aggregate.dot1q, Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: Vec::new() }));
        assert!(!aggregate.untagged_vlan_managed);
        assert!(!aggregate.tagged_vlans_managed);
    }

    #[test]
    fn a_port_without_mode_in_the_report_stays_unmanaged() {
        // A table without the columns, a mode that is neither of the two, an empty one.
        let report = |header: &str, row: &str| {
            format!(
                "<html><body><table><tr><th>Description</th><th>Setting</th></tr>\
                 <tr><td>Hostname</td><td>SW1</td></tr></table>\
                 <table><tr><th>Interface</th><th>Active</th><th>Description</th>{header}</tr>\
                 <tr><td>GigabitEthernet1/0/1</td><td>Yes</td><td>uplink</td>{row}</tr></table></body></html>"
            )
        };
        let columns = "<th>VLAN</th><th>Mode</th>";
        for (header, row) in
            [("", ""), (columns, "<td>12</td><td>Dynamic Auto</td>"), (columns, "<td>12</td><td></td>"), (columns, "")]
        {
            let port =
                &parse_report(&report(header, row)).expect("a valid report").state.interfaces["GigabitEthernet1/0/1"];
            assert!(!port.dot1q_managed, "{header} {row}");
            assert_eq!(port.dot1q, None, "{header} {row}");
        }
    }

    #[test]
    fn the_columns_are_found_by_their_name_wherever_they_are() {
        let html = "<html><body><table><tr><th>Description</th><th>Setting</th></tr>\
                    <tr><td>Hostname</td><td>SW1</td></tr></table>\
                    <table><tr><th>Interface</th><th>Active</th><th>Description</th><th>Mode</th><th>Speed</th>\
                    <th>VLAN</th></tr>\
                    <tr><td>GigabitEthernet1/0/1</td><td>Yes</td><td>uplink</td><td>Access</td><td>Auto</td>\
                    <td>12</td></tr></table></body></html>";
        let port = &parse_report(html).expect("a valid report").state.interfaces["GigabitEthernet1/0/1"];
        assert_eq!(port.dot1q, Some(Dot1q { mode: Mode::Access, untagged_vlan: Some(12), tagged_vlans: Vec::new() }));
    }

    #[test]
    fn an_access_port_whose_vlan_is_not_a_number_keeps_the_one_netbox_has() {
        let html = "<html><body><table><tr><th>Description</th><th>Setting</th></tr>\
                    <tr><td>Hostname</td><td>SW1</td></tr></table>\
                    <table><tr><th>Interface</th><th>Active</th><th>Description</th><th>VLAN</th><th>Mode</th></tr>\
                    <tr><td>GigabitEthernet1/0/1</td><td>Yes</td><td>uplink</td><td>N/A</td><td>Access</td></tr>\
                    </table></body></html>";
        let port = &parse_report(html).expect("a valid report").state.interfaces["GigabitEthernet1/0/1"];
        assert_eq!(port.dot1q, Some(Dot1q { mode: Mode::Access, untagged_vlan: None, tagged_vlans: Vec::new() }));
        assert!(!port.untagged_vlan_managed);
        assert!(port.tagged_vlans_managed);
    }

    #[test]
    fn a_port_the_report_gives_an_address_is_not_a_switchport() {
        // `GigabitEthernet0/0 | Yes | N:sw01-c2-s1.adm Gi0/46 and sw02-c2-s1.adm Gi0/46 | 1 | Access` in the
        // switchport table, and `GigabitEthernet0/0 | Yes | 192.0.2.1 255.255.248.0` in the interfaces one:
        // the routed management port of the stack, which `show interfaces switchport` does not list.
        let interfaces = state("fplab1-sw001").interfaces;
        let management = &interfaces["GigabitEthernet0/0"];
        assert!(!management.dot1q_managed);
        assert_eq!(management.dot1q, None);
        // `GigabitEthernet1/0/1 | No | None` in the interfaces table: a switchport.
        assert!(interfaces["GigabitEthernet1/0/1"].dot1q_managed);
    }

    // A report cut short would list fewer ports, and a prune would then delete the others.
    #[test]
    fn a_report_cut_short_is_a_failure() {
        // Cut inside the last table, the switchport one: its first rows are still there.
        let whole = nipper_report("fplab1-sw001");
        let cut: String = whole.chars().take(whole.chars().count() - 300).collect();
        assert_eq!(parse_report(&cut), Err(ParseError::Report("the page is cut short".to_owned())));
        // Cut before that table: nothing tells the ports.
        assert_eq!(
            parse_report(&halved(&whole)),
            Err(ParseError::Report("no hostname or switchport table".to_owned()))
        );
    }
}
