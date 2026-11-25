//! Read a switch: run its closed list of commands and build its state, or read
//! its configuration report.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use omnisync_core::network::descriptions::{
    neighbors_from_descriptions, vlans_against_descriptions, vlans_from_descriptions,
};
use omnisync_core::network::inventory::Source;
use omnisync_core::network::model::{DeviceState, Dot1q, Interface};

use crate::commands::{Platform, commands};
use crate::parsers::{ParseError, ios, nipper, nxos};
use crate::runner::{CollectionError, CommandRunner};

/// Number of commands a source of this type runs; a report type reads one file.
pub fn command_count(r#type: &str) -> usize {
    Platform::from_type(r#type).map_or(1, |platform| commands(platform).len())
}

/// Build the state of a switch from its configuration report, without SSH.
pub fn collect_report(source: &Source) -> Result<DeviceState, CollectionError> {
    let Some(path) = source.report.as_deref() else {
        return Err(CollectionError("no report file configured".to_owned()));
    };
    let failed = |why: String| CollectionError(format!("report {}: {why}", path.display()));
    let bytes = fs::read(path).map_err(|error| failed(error.to_string()))?;
    // A wrong decoding would write corrupted descriptions to NetBox.
    let html = String::from_utf8(bytes).map_err(|_| failed("not UTF-8".to_owned()))?;
    let report = nipper::parse_report(&html).map_err(|error| failed(error.to_string()))?;
    // A report copied under the wrong name would be synced onto another switch.
    let short_name = source.name.split('.').next().unwrap_or(&source.name);
    if report.hostname.to_lowercase() != short_name.to_lowercase() {
        return Err(failed(format!("hostname {}, not {}", report.hostname, source.name)));
    }
    Ok(add_descriptions(source, report.state))
}

/// Add what the port descriptions tell: the neighbours, and the VLANs.
///
/// The VLANs complete a switch known by a report, which does not list those a
/// trunk allows. A switch whose configuration was read is believed: its
/// descriptions are only compared, and a difference is a warning.
pub fn add_descriptions(source: &Source, state: DeviceState) -> DeviceState {
    let mut state = add_description_neighbors(source, state);
    if let Some(pattern) = &source.neighbor_pattern {
        let warnings = if source.report.is_some() {
            vlans_from_descriptions(&mut state.interfaces, pattern)
        } else {
            vlans_against_descriptions(&state.interfaces, pattern, &state.vlans.keys().copied().collect())
        };
        state.warnings.extend(warnings);
    }
    state
}

/// Add the neighbours the port descriptions tell, on the ports LLDP and CDP leave
/// silent or where they only announce a neighbour without a name nor a port.
pub fn add_description_neighbors(source: &Source, mut state: DeviceState) -> DeviceState {
    if let Some(pattern) = &source.neighbor_pattern {
        // An anonymous neighbour tells nothing: the description still speaks there.
        let announced: BTreeSet<String> = state
            .neighbors
            .iter()
            .filter(|neighbor| !neighbor.anonymous())
            .map(|neighbor| neighbor.local_interface.clone())
            .collect();
        let told = neighbors_from_descriptions(&state.interfaces, pattern, &source.neighbor_suffix, &announced);
        state.neighbors.extend(told);
    }
    state
}

/// Command outputs of one switch, by the key of their command.
struct Outputs(BTreeMap<&'static str, String>);

impl Outputs {
    async fn read<R: CommandRunner>(platform: Platform, runner: &mut R) -> Result<Self, CollectionError> {
        let mut outputs = BTreeMap::new();
        for (key, command) in commands(platform) {
            outputs.insert(*key, runner.run(command).await?);
        }
        Ok(Outputs(outputs))
    }

    /// A parse failure names its command: the parsers put it in their error.
    fn parse<T>(&self, key: &str, parser: impl FnOnce(&str) -> Result<T, ParseError>) -> Result<T, CollectionError> {
        let output = self.0.get(key).map_or("", String::as_str);
        parser(output).map_err(|error| CollectionError(error.to_string()))
    }
}

fn merge(
    interfaces: BTreeMap<String, Interface>,
    mut modes: BTreeMap<String, Dot1q>,
    unmanaged: &BTreeSet<String>,
    lags: &BTreeMap<String, String>,
) -> BTreeMap<String, Interface> {
    interfaces
        .into_iter()
        .map(|(name, interface)| {
            let merged = Interface {
                lag: lags.get(&name).cloned(),
                dot1q: modes.remove(&name),
                dot1q_managed: !unmanaged.contains(&name),
                ..interface
            };
            (name, merged)
        })
        .collect()
}

fn build_nxos(outputs: &Outputs) -> Result<DeviceState, CollectionError> {
    let vlans = outputs.parse("vlans", nxos::parse_vlans)?;
    let defined: BTreeSet<u16> = vlans.keys().copied().collect();
    let (modes, unmanaged) = outputs.parse("switchport", |text| nxos::parse_switchport(text, &defined))?;
    let interfaces = merge(
        outputs.parse("interfaces", nxos::parse_interfaces)?,
        modes,
        &unmanaged,
        &outputs.parse("lags", nxos::parse_lag_members)?,
    );
    let vrf_of = outputs.parse("vrfs", nxos::parse_vrf_map)?;
    let mut neighbors = outputs.parse("lldp", nxos::parse_lldp)?;
    neighbors.extend(outputs.parse("cdp", nxos::parse_cdp)?);
    Ok(DeviceState {
        serial: Some(outputs.parse("inventory", nxos::parse_serial)?),
        interfaces,
        vlans,
        ips: outputs.parse("ips", |text| nxos::parse_ips(text, &vrf_of))?,
        neighbors,
        ..DeviceState::default()
    })
}

fn build_ios(outputs: &Outputs) -> Result<DeviceState, CollectionError> {
    let vlans = outputs.parse("vlans", ios::parse_vlans)?;
    let defined: BTreeSet<u16> = vlans.keys().copied().collect();
    let (modes, unmanaged) = outputs.parse("switchport", |text| ios::parse_switchport(text, &defined))?;
    let (parsed, ips) = outputs.parse("interfaces", ios::parse_interfaces)?;
    let interfaces = merge(parsed, modes, &unmanaged, &outputs.parse("lags", ios::parse_lag_members)?);
    let (master, numbers) = outputs.parse("switch", ios::parse_switch)?;
    let serials = outputs.parse("inventory", ios::parse_member_serials)?;
    let missing: Vec<u32> = numbers.iter().copied().filter(|number| !serials.contains_key(number)).collect();
    if !missing.is_empty() {
        return Err(CollectionError(format!("show inventory: no serial for stack member(s) {missing:?}")));
    }
    let mut neighbors = outputs.parse("lldp", ios::parse_lldp)?;
    neighbors.extend(outputs.parse("cdp", ios::parse_cdp)?);
    Ok(DeviceState {
        serial: serials.get(&master).cloned(),
        interfaces,
        vlans,
        ips,
        neighbors,
        member_serials: numbers.iter().filter_map(|number| Some((*number, serials.get(number)?.clone()))).collect(),
        ..DeviceState::default()
    })
}

/// Run the commands of the platform, in order, and build the state of the switch.
pub async fn collect<R: CommandRunner>(platform: Platform, runner: &mut R) -> Result<DeviceState, CollectionError> {
    let outputs = Outputs::read(platform, runner).await?;
    match platform {
        Platform::Nxos => build_nxos(&outputs),
        Platform::Ios => build_ios(&outputs),
    }
}

#[cfg(test)]
mod tests {
    use omnisync_core::network::inventory::Kind;
    use omnisync_core::network::model::{Mode, Neighbor};
    use regex::Regex;

    use super::*;
    use crate::commands::{IOS_COMMANDS, NXOS_COMMANDS};
    use crate::parsers::fixtures::{IOS, NIPPER, NXOS_I2, fixture_text};

    /// Command runner that answers from the recorded switch outputs, except for
    /// the commands it is told to answer otherwise.
    struct FixtureRunner {
        directory: &'static str,
        answers: BTreeMap<&'static str, &'static str>,
        commands: Vec<String>,
    }

    impl FixtureRunner {
        fn new(directory: &'static str) -> Self {
            FixtureRunner { directory, answers: BTreeMap::new(), commands: Vec::new() }
        }

        fn answering(directory: &'static str, command: &'static str, answer: &'static str) -> Self {
            FixtureRunner { answers: BTreeMap::from([(command, answer)]), ..FixtureRunner::new(directory) }
        }
    }

    impl CommandRunner for FixtureRunner {
        async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
            self.commands.push(command.to_owned());
            Ok(match self.answers.get(command) {
                Some(answer) => (*answer).to_owned(),
                None => fixture_text(self.directory, command),
            })
        }
    }

    fn dot1q(mode: Mode, untagged: u16) -> Dot1q {
        Dot1q { mode, untagged_vlan: Some(untagged), tagged_vlans: Vec::new() }
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(NIPPER).join(name)
    }

    fn report_source(name: &str, report: std::path::PathBuf) -> Source {
        Source { report: Some(report), ..Source::new(name, Kind::Switch, "nipper", "") }
    }

    fn failure(result: Result<DeviceState, CollectionError>) -> String {
        result.expect_err("a collection failure").0
    }

    #[tokio::test]
    async fn collect_nxos() {
        let state = collect(Platform::Nxos, &mut FixtureRunner::new(NXOS_I2)).await.expect("the fixtures parse");
        assert_eq!(state.serial.as_deref(), Some("FOC9792A4K9"));
        assert_eq!(state.interfaces["Ethernet1/51"].lag.as_deref(), Some("port-channel10"));
        assert_eq!(state.interfaces["Ethernet1/7"].dot1q, Some(dot1q(Mode::Access, 2903)));
        assert_eq!(state.interfaces["Vlan2800"].dot1q, None);
        assert!(state.interfaces["Vlan2800"].dot1q_managed);
        // 11 LLDP + 6 CDP neighbours in the nexus01 outputs.
        assert_eq!(state.neighbors.len(), 17);
        assert_eq!(state.ips.len(), 2);
        assert_eq!(state.member_serials, BTreeMap::new());
    }

    #[tokio::test]
    async fn collect_ios() {
        let state = collect(Platform::Ios, &mut FixtureRunner::new(IOS)).await.expect("the fixtures parse");
        assert_eq!(state.serial.as_deref(), Some("FCW8657Y7S5"));
        assert_eq!(state.member_serials, BTreeMap::from([(1, "FCW8657Y7S5".to_owned())]));
        assert_eq!(state.vlans, BTreeMap::from([(1, "default".to_owned()), (2800, "Admin".to_owned())]));
        assert!(!state.interfaces["GigabitEthernet1/0/25"].dot1q_managed);
        assert_eq!(state.interfaces["GigabitEthernet1/0/1"].dot1q, Some(dot1q(Mode::Access, 2800)));
    }

    #[tokio::test]
    async fn the_commands_run_are_the_closed_list_in_order() {
        let mut nxos = FixtureRunner::new(NXOS_I2);
        collect(Platform::Nxos, &mut nxos).await.expect("the fixtures parse");
        assert_eq!(nxos.commands, NXOS_COMMANDS.map(|(_, command)| command));
        let mut ios = FixtureRunner::new(IOS);
        collect(Platform::Ios, &mut ios).await.expect("the fixtures parse");
        assert_eq!(ios.commands, IOS_COMMANDS.map(|(_, command)| command));
    }

    #[tokio::test]
    async fn refused_command_fails_collection() {
        // Answers like a read-only account that is not allowed one command.
        let mut runner = FixtureRunner::answering(NXOS_I2, "show inventory | json", "% Permission denied for the role");
        assert_eq!(
            failure(collect(Platform::Nxos, &mut runner).await),
            r#"show inventory | json: not JSON: "% Permission denied for the role""#
        );
    }

    #[tokio::test]
    async fn refused_ios_command_fails_collection() {
        // IOS read-only account refused `show etherchannel summary`.
        let refused = "                    ^\n% Invalid input detected at '^' marker.\n";
        let mut runner = FixtureRunner::answering(IOS, "show etherchannel summary", refused);
        assert_eq!(
            failure(collect(Platform::Ios, &mut runner).await),
            "show etherchannel summary: % Invalid input detected at '^' marker."
        );
    }

    #[tokio::test]
    async fn malformed_output_fails_collection_naming_the_command() {
        // NX-OS answers valid JSON of an unexpected shape.
        let malformed = r#"{"TABLE_vlanbriefxbrief": {"ROW_vlanbriefxbrief": [{"unexpected": 1}]}}"#;
        let mut runner = FixtureRunner::answering(NXOS_I2, "show vlan brief | json", malformed);
        assert_eq!(
            failure(collect(Platform::Nxos, &mut runner).await),
            "show vlan brief | json: row without `vlanshowbr-vlanid`"
        );
    }

    #[tokio::test]
    async fn a_stack_member_without_serial_fails_collection() {
        let two_members = "Switch#  Role   Mac Address     Priority Version  State \n\
                           ----------------------------------------------------------\n\
                           *1       Master 02b3.dd4f.1634     1      4       Ready\n\
                           \x202       Member 02b3.dd4f.99aa     1      4       Ready\n";
        let mut runner = FixtureRunner::answering(IOS, "show switch", two_members);
        assert_eq!(
            failure(collect(Platform::Ios, &mut runner).await),
            "show inventory: no serial for stack member(s) [2]"
        );
    }

    #[test]
    fn command_counts() {
        assert_eq!(command_count("nxos"), 9);
        assert_eq!(command_count("ios"), 8);
        // A report type reads one file.
        assert_eq!(command_count("nipper"), 1);
    }

    #[test]
    fn report_file_missing() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("absent.html");
        let message = failure(collect_report(&report_source("fplab1-sw001", path.clone())));
        assert!(message.starts_with(&format!("report {}: No such file", path.display())), "{message}");
    }

    #[test]
    fn report_is_not_a_nipper_report() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("login.html");
        fs::write(&path, "<html><body>Login</body></html>").expect("the page is written");
        assert_eq!(
            failure(collect_report(&report_source("fplab1-sw001", path.clone()))),
            format!("report {}: not a Nipper Cisco switch report (no hostname or switchport table)", path.display())
        );
    }

    #[test]
    fn report_without_pattern_has_no_neighbours() {
        let state = collect_report(&report_source("fplab1-sw001", fixture_path("fplab1-sw001.html")))
            .expect("the fixture parses");
        // 138 switchport ports and 3 SVIs.
        assert_eq!(state.interfaces.len(), 141);
        assert_eq!(state.neighbors, []);
    }

    /// Reads the host of a Proxmox node and its port, and the VLANs of a `V:` pair wherever it is.
    fn vlan_pattern() -> Regex {
        Regex::new(r"(?i)(?:\b(?P<host>lab1-pve\d+)(?:[\s_-]+(?P<port>[a-z0-9]+))?.*?)??\bV:(?P<vlans>[0-9,-]+)")
            .expect("valid pattern")
    }

    #[test]
    fn the_vlans_of_a_report_come_from_its_columns_and_from_its_descriptions() {
        let source = Source {
            neighbor_pattern: Some(vlan_pattern()),
            ..report_source("fplab1-sw001", fixture_path("fplab1-sw001.html"))
        };
        let state = collect_report(&source).expect("the fixture parses");
        // `TenGigabitEthernet1/1/8 | Yes | description CTA/CTB/LE-143095 V:4-6,10-12,14-19,952 | 2 | Trunk`
        // and `TenGigabitEthernet2/1/8 | Yes | CTA/CTB/LE-143135 V:4-6,10-12,14-19,952 | 2 | Trunk` are the
        // two trunks of the report whose description has a list.
        let listed: Vec<&str> = state
            .interfaces
            .values()
            .filter(|interface| interface.dot1q.as_ref().is_some_and(|dot1q| dot1q.mode == Mode::Tagged))
            .filter(|interface| interface.tagged_vlans_managed)
            .map(|interface| interface.name.as_str())
            .collect();
        assert_eq!(listed, ["TenGigabitEthernet1/1/8", "TenGigabitEthernet2/1/8"]);
        let trunk = &state.interfaces["TenGigabitEthernet1/1/8"];
        assert_eq!(
            trunk.dot1q,
            Some(Dot1q {
                mode: Mode::Tagged,
                untagged_vlan: None,
                tagged_vlans: vec![4, 5, 6, 10, 11, 12, 14, 15, 16, 17, 18, 19, 952]
            })
        );
        assert!(!trunk.untagged_vlan_managed);
        // `TenGigabitEthernet1/0/40 | Yes | N:lab1-pve01 enp129s0 10G Vlan 10-11-12 | 2 | Trunk`: the former
        // form is not a list, the trunk keeps the VLANs NetBox has.
        assert!(!state.interfaces["TenGigabitEthernet1/0/40"].tagged_vlans_managed);
        // `Port-channel24 | Yes | LAB1-PRE01 ETH0-ETH1 T:HOU V:12 | 12 | Access`: every access port whose
        // description has a `V:` says the VLAN of the report.
        assert_eq!(state.interfaces["Port-channel24"].dot1q, Some(dot1q(Mode::Access, 12)));
        assert_eq!(state.warnings, [] as [&str; 0]);
    }

    /// The pattern the README gives for the convention it recommends.
    fn convention() -> Regex {
        Regex::new(concat!(
            r"(?i)^(?:\[No Monitor\]\s+)?(?:(?:i?drac|ilo)[-\s]+)?",
            r"(?:(?P<host>[a-z0-9][a-z0-9.-]*)(?:/(?P<port>\S+?))?(?:/\d+[MG])?(?:\s+|$))?",
            r"(?:.*?\bV:(?P<vlans>\S+))?",
        ))
        .expect("valid pattern")
    }

    // fplab1-sw001-convention.html is the stack of fplab1-sw001.html once its descriptions were rewritten.
    #[test]
    fn a_report_whose_descriptions_follow_the_convention_gives_the_vlans_of_its_trunks() {
        let source = Source {
            neighbor_pattern: Some(convention()),
            ..report_source("fplab1-sw001", fixture_path("fplab1-sw001-convention.html"))
        };
        let state = collect_report(&source).expect("the fixture parses");
        let vlans = |name: &str| {
            let port = &state.interfaces[name];
            let dot1q = port.dot1q.as_ref().expect("a mode");
            (dot1q.mode, port.tagged_vlans_managed.then(|| dot1q.tagged_vlans.clone()))
        };
        // `TenGigabitEthernet1/0/40 | Yes | lab1-pve01.prod/enp129s0/10G V:10-12 | 2 | Trunk`
        assert_eq!(vlans("TenGigabitEthernet1/0/40"), (Mode::Tagged, Some(vec![10, 11, 12])));
        // `Port-channel40 | Yes | lab1-pve01.prod/bond0/10G V:10-12 | 2 | Trunk`
        assert_eq!(vlans("Port-channel40"), (Mode::Tagged, Some(vec![10, 11, 12])));
        // `GigabitEthernet1/0/5 | Yes | lab1-rt02.prod/GigabitEthernet0/0 V:952,954,1511 D:Interco-Directe | 2 | Trunk`
        assert_eq!(vlans("GigabitEthernet1/0/5"), (Mode::Tagged, Some(vec![952, 954, 1511])));
        // `GigabitEthernet2/0/6 | Yes | [No Monitor] lab1-fw01.prod/wan2/1G D:sans V:954 T:HST
        // IP:192.0.2.8/255.255.255.240 | 2 | Trunk`
        assert_eq!(vlans("GigabitEthernet2/0/6"), (Mode::Tagged, Some(vec![954])));
        // `TenGigabitEthernet1/1/8 | Yes | N:CIRCUIT CTA/CTB/LE-143095 V:4-7,10-12,14-22,24-27,952,954 | 2 | Trunk`
        let circuit = vec![4, 5, 6, 7, 10, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 952, 954];
        assert_eq!(vlans("TenGigabitEthernet1/1/8"), (Mode::Tagged, Some(circuit)));
        // `Port-channel18 | Yes | [No Monitor] lab1-c190-01.prod/a0a/10G V:all | 2 | Trunk`
        assert_eq!(vlans("Port-channel18"), (Mode::TaggedAll, Some(vec![])));
        // `Port-channel56 | Yes | CTA/CTB/LE-143095 - CTA/CTB/LE-143135 | 2 | Trunk`: no list.
        assert_eq!(vlans("Port-channel56"), (Mode::Tagged, None));
        // `Port-channel25 | No | N:Unused-Interface | 2 | Trunk`: an unused trunk.
        assert_eq!(vlans("Port-channel25"), (Mode::Tagged, None));
        // Of the 64 trunks of the report, 46 have a list in their description and 6 say `all`.
        let trunks =
            || state.interfaces.values().filter(|port| port.dot1q.as_ref().is_some_and(|d| d.mode != Mode::Access));
        assert_eq!(trunks().count(), 64);
        assert_eq!(trunks().filter(|port| port.tagged_vlans_managed).count(), 52);
        assert_eq!(trunks().filter(|port| port.dot1q.as_ref().is_some_and(|d| d.mode == Mode::TaggedAll)).count(), 6);
        // `Port-channel24 | Yes | lab1-pre01.prod/bond0/1G T:HOU V:12 | 12 | Access`: the 23 access ports
        // whose description has a `V:` say the VLAN of their column, so nothing is warned about.
        assert_eq!(state.interfaces["Port-channel24"].dot1q, Some(dot1q(Mode::Access, 12)));
        assert_eq!(state.warnings, [] as [&str; 0]);
        // The same pattern still tells the cables:
        // `GigabitEthernet1/0/27 | Yes | [No Monitor] drac-lab1-pve01.prod V:18 | 18 | Access`.
        let neighbor = |local: &str| state.neighbors.iter().find(|neighbor| neighbor.local_interface == local);
        let told = |local: &str| neighbor(local).map(|n| (n.remote_device.as_str(), n.remote_interface.as_deref()));
        assert_eq!(told("TenGigabitEthernet1/0/40"), Some(("lab1-pve01.prod", Some("enp129s0"))));
        assert_eq!(told("GigabitEthernet1/0/27"), Some(("lab1-pve01.prod", Some("<management>"))));
        assert_eq!(told("GigabitEthernet1/0/5"), Some(("lab1-rt02.prod", Some("gigabitethernet0/0"))));
        // A description that names no host gives no neighbour, and a port-channel never does.
        assert_eq!(told("TenGigabitEthernet1/1/8"), None);
        assert_eq!(told("Port-channel40"), None);
    }

    #[test]
    fn a_malformed_list_is_never_read_in_part_by_the_pattern_of_the_convention() {
        let source = Source { neighbor_pattern: Some(convention()), ..report_source("sw1", "sw1.html".into()) };
        let trunk = |name: &str, description: &str| Interface {
            description: Some(description.to_owned()),
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: Vec::new() }),
            untagged_vlan_managed: false,
            tagged_vlans_managed: false,
            ..Interface::new(name, true)
        };
        let ports = [
            trunk("Te1/0/1", "lab1-esx01.prod/vmnic0/10G V:10-12x"),
            trunk("Te1/0/2", "lab1-esx02.prod/vmnic0 V:allx"),
        ];
        let interfaces = ports.iter().cloned().map(|port| (port.name.clone(), port)).collect();
        let state = add_descriptions(&source, DeviceState { interfaces, ..DeviceState::default() });
        assert_eq!(state.interfaces.values().cloned().collect::<Vec<_>>(), ports);
        assert_eq!(
            state.warnings,
            [
                "Te1/0/1: the VLANs of its description cannot be read (invalid VLAN list item '10-12x'); the tagged \
                 VLANs NetBox has are left as they are",
                "Te1/0/2: the VLANs of its description cannot be read (invalid VLAN list item 'allx'); the tagged \
                 VLANs NetBox has are left as they are",
            ]
        );
    }

    #[test]
    fn a_report_without_pattern_takes_its_vlans_from_its_columns_alone() {
        let state = collect_report(&report_source("fplab1-sw001", fixture_path("fplab1-sw001.html")))
            .expect("the fixture parses");
        assert!(!state.interfaces["TenGigabitEthernet1/1/8"].tagged_vlans_managed);
        assert_eq!(state.interfaces["Port-channel24"].dot1q, Some(dot1q(Mode::Access, 12)));
    }

    #[test]
    fn a_port_whose_neighbour_is_announced_keeps_the_vlans_of_its_description() {
        let source = Source { neighbor_pattern: Some(vlan_pattern()), ..report_source("sw1", "sw1.html".into()) };
        let trunk = Interface {
            description: Some("lab1-pve01 eno1 V:10-12".to_owned()),
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: None, tagged_vlans: Vec::new() }),
            untagged_vlan_managed: false,
            tagged_vlans_managed: false,
            ..Interface::new("Te1/0/1", true)
        };
        let announced = Neighbor {
            local_interface: "Te1/0/1".to_owned(),
            remote_device: "lab1-pve01.prod".to_owned(),
            remote_interface: Some("eno1".to_owned()),
            protocol: "lldp".to_owned(),
        };
        let state = DeviceState {
            interfaces: BTreeMap::from([("Te1/0/1".to_owned(), trunk)]),
            neighbors: vec![announced.clone()],
            ..DeviceState::default()
        };
        let state = add_descriptions(&source, state);
        // The description gives no second neighbour, and still its VLANs.
        assert_eq!(state.neighbors, [announced]);
        assert_eq!(
            state.interfaces["Te1/0/1"].dot1q.as_ref().map(|dot1q| dot1q.tagged_vlans.clone()),
            Some(vec![10, 11, 12])
        );
        assert!(state.interfaces["Te1/0/1"].tagged_vlans_managed);
    }

    #[test]
    fn the_configuration_of_a_switch_read_over_ssh_is_believed_and_its_description_compared() {
        let source = Source {
            neighbor_pattern: Some(vlan_pattern()),
            ..Source::new("nexus01.lab01", Kind::Switch, "nxos", "192.0.2.239")
        };
        let trunk = Interface {
            description: Some("lab1-pve01 eno1 V:10-12".to_owned()),
            dot1q: Some(Dot1q { mode: Mode::Tagged, untagged_vlan: Some(1), tagged_vlans: vec![10, 11] }),
            ..Interface::new("Ethernet1/1", true)
        };
        let state = DeviceState {
            interfaces: BTreeMap::from([("Ethernet1/1".to_owned(), trunk.clone())]),
            // The switch defines VLAN 12, which the port does not allow.
            vlans: [1, 10, 11, 12].into_iter().map(|vid| (vid, format!("VLAN{vid:04}"))).collect(),
            ..DeviceState::default()
        };
        let state = add_descriptions(&source, state);
        assert_eq!(state.interfaces["Ethernet1/1"], trunk);
        assert_eq!(
            state.warnings,
            ["Ethernet1/1: its description says VLAN 10-12, its configuration says 10-11; the configuration is \
                 believed"]
        );
    }

    #[test]
    fn report_of_another_switch_fails_collection() {
        let path = fixture_path("fplab1-sw001.html");
        assert_eq!(
            failure(collect_report(&report_source("fplab2-sw001", path.clone()))),
            format!("report {}: hostname FPLAB1-SW001, not fplab2-sw001", path.display())
        );
    }

    #[test]
    fn report_hostname_matched_case_insensitively_without_domain() {
        let source = report_source("fplab1-sw001.prod", fixture_path("fplab1-sw001.html"));
        assert_eq!(collect_report(&source).expect("the fixture parses").interfaces.len(), 141);
    }

    #[test]
    fn report_not_in_utf8_fails_collection() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("fplab1-sw001.html");
        // `é` in Windows-1252 is the single byte E9, which is not UTF-8.
        fs::write(&path, b"<html><body>Baie r\xe9seau</body></html>").expect("the page is written");
        assert_eq!(
            failure(collect_report(&report_source("fplab1-sw001", path.clone()))),
            format!("report {}: not UTF-8", path.display())
        );
    }

    #[test]
    fn a_source_without_report_fails_collection() {
        let source = Source::new("fplab1-sw001", Kind::Switch, "nipper", "");
        assert_eq!(failure(collect_report(&source)), "no report file configured");
    }

    #[test]
    fn description_completes_a_port_whose_neighbour_is_anonymous() {
        // A neighbour announcing neither a name nor a port tells nothing: the port's
        // description is then its only source. A named neighbour keeps the port.
        let pattern = Regex::new(r"(?i)^(?P<host>[a-z0-9][a-z0-9.-]*)(?:/(?P<port>[^/\s]+))?").expect("valid pattern");
        let source = Source {
            neighbor_pattern: Some(pattern),
            ..Source::new("nexus01.lab01", Kind::Switch, "nxos", "192.0.2.239")
        };
        let interfaces: BTreeMap<String, Interface> = [
            ("Ethernet1/15", "c190b-ctrl02.lab01/e0c"),
            ("Ethernet1/16", "c190b-ctrl01.lab01/e0c"),
            ("Ethernet1/17", "pve01.lab01/eno1"),
        ]
        .into_iter()
        .map(|(name, description)| {
            let interface = Interface {
                description: Some(description.to_owned()),
                link_up: Some(true),
                ..Interface::new(name, true)
            };
            (name.to_owned(), interface)
        })
        .collect();
        let neighbor = |local: &str, device: &str, remote: Option<&str>, protocol: &str| Neighbor {
            local_interface: local.to_owned(),
            remote_device: device.to_owned(),
            remote_interface: remote.map(str::to_owned),
            protocol: protocol.to_owned(),
        };
        let announced = vec![
            neighbor("Ethernet1/15", "", None, "lldp"),
            neighbor("Ethernet1/16", "not advertised", None, "cdp"),
            neighbor("Ethernet1/17", "pve01.lab01", Some("eno2"), "lldp"),
        ];
        let state = DeviceState { interfaces, neighbors: announced.clone(), ..DeviceState::default() };
        let mut expected = announced;
        expected.push(neighbor("Ethernet1/15", "c190b-ctrl02.lab01", Some("e0c"), "description"));
        expected.push(neighbor("Ethernet1/16", "c190b-ctrl01.lab01", Some("e0c"), "description"));
        assert_eq!(add_description_neighbors(&source, state).neighbors, expected);
    }
}
