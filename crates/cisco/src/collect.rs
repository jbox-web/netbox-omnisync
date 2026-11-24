//! Read a switch: run its closed list of commands and build its state, or read
//! its configuration report.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use omnisync_core::network::descriptions::neighbors_from_descriptions;
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
    Ok(add_description_neighbors(source, report.state))
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
