//! Which sources a run is about: the `--kind`, `--type` and `--source` filters
//! applied to the sources of the configuration.
//!
//! A filter given several times widens (any of its values); two different
//! filters narrow (a source must pass each of them). When the file says which
//! host launches each source (`runner`), the filters choose among the sources
//! of the host of the run. Nothing here reads the configuration file, asks
//! the system for the name of the host, nor contacts anything.

use std::collections::BTreeSet;
use std::fmt;

use clap::ValueEnum;
use omnisync_core::network::inventory::{Inventory, Kind};

use crate::config::{Hypervisor, Runners};

/// What a source is in NetBox terms: the value of `--kind`, and the `kind` of
/// an entry of the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub enum SourceKind {
    Hypervisor,
    // The BMCs of servers: read once a day, never with `--kind hypervisor`.
    // Not a doc comment: clap would print it, and turn the values of `--kind` into a list.
    Bmc,
    Switch,
    Router,
    Firewall,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Hypervisor => "hypervisor",
            SourceKind::Bmc => "bmc",
            SourceKind::Switch => "switch",
            SourceKind::Router => "router",
            SourceKind::Firewall => "firewall",
        }
    }

    /// Whether the source is reconciled with the hypervisors (a hypervisor, a
    /// BMC), not run with the network sources.
    pub fn is_inventory(self) -> bool {
        matches!(self, SourceKind::Hypervisor | SourceKind::Bmc)
    }
}

impl From<Kind> for SourceKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Switch => SourceKind::Switch,
            Kind::Router => SourceKind::Router,
            Kind::Firewall => SourceKind::Firewall,
        }
    }
}

/// How a source is read: the value of `--type`, and the `type` of an entry of
/// the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub enum SourceType {
    Vmware,
    Proxmox,
    Redfish,
    Ios,
    Nxos,
    Nipper,
    Fortios,
}

impl SourceType {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceType::Vmware => "vmware",
            SourceType::Proxmox => "proxmox",
            SourceType::Redfish => "redfish",
            SourceType::Ios => "ios",
            SourceType::Nxos => "nxos",
            SourceType::Nipper => "nipper",
            SourceType::Fortios => "fortios",
        }
    }
}

/// The filters of the command line; an empty one lets every source through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub kinds: Vec<SourceKind>,
    pub types: Vec<SourceType>,
    pub names: Vec<String>,
}

impl Filter {
    /// No filter at all: every source runs.
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty() && self.types.is_empty() && self.names.is_empty()
    }
}

/// The filter as it was typed, to name it in an error.
impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kinds = self.kinds.iter().map(|kind| format!("--kind {}", kind.as_str()));
        let types = self.types.iter().map(|r#type| format!("--type {}", r#type.as_str()));
        let names = self.names.iter().map(|name| format!("--source {name}"));
        f.write_str(&kinds.chain(types).chain(names).collect::<Vec<_>>().join(" "))
    }
}

/// A source of the configuration, as the selection sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub kind: SourceKind,
    /// The `type` of the entry, as written in the file.
    pub r#type: String,
    /// The host the file says launches it (`runner`); None in a file one host runs.
    pub runner: Option<String>,
}

impl Candidate {
    pub fn new(name: &str, kind: SourceKind, r#type: &str) -> Self {
        Candidate { name: name.to_owned(), kind, r#type: r#type.to_owned(), runner: None }
    }

    /// The same source, launched by `host`.
    #[must_use]
    pub fn run_by(mut self, host: &str) -> Self {
        self.runner = Some(host.to_owned());
        self
    }
}

/// The host of a run of a file that says which host launches each source:
/// its name, and the hosts the file lists (`runners`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host<'h> {
    pub name: &'h str,
    pub runners: &'h [String],
}

/// The selection cannot be run: nothing is contacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    /// `--source` names that are not in the configuration, sorted.
    #[error("unknown source(s): {}", .0.join(", "))]
    Unknown(Vec<String>),
    /// Filters were given and no source passes them all: most likely a
    /// mistake, and never a reason to report that NetBox matches the sources.
    #[error("no source matches {0}")]
    Nothing(String),
    /// The host of the run is not one the file lists: a machine renamed or
    /// rebuilt under another name must fail, not stop launching its sources
    /// without a word.
    #[error("{host} is not one of runners ({}): it runs no source of this file", .runners.join(", "))]
    NotARunner { host: String, runners: Vec<String> },
    /// `--source` names that another host launches, each with that host, in
    /// the order of the file.
    #[error("not run by {host}: {}", elsewhere(.sources))]
    Elsewhere { host: String, sources: Vec<(String, String)> },
    /// Filters were given and no source of the host passes them all.
    #[error("no source of {host} matches {filter}")]
    NothingOf { host: String, filter: String },
}

/// `name (run by host)` for each source, as an error lists them.
fn elsewhere(sources: &[(String, String)]) -> String {
    let named: Vec<String> = sources.iter().map(|(name, host)| format!("{name} (run by {host})")).collect();
    named.join(", ")
}

/// Every source of the configuration: the network ones, then the hypervisors
/// and the BMCs, each in the order of the file, with the host `runners` says
/// launches it.
pub fn candidates(inventory: &Inventory, hypervisors: &[Hypervisor], runners: &Runners) -> Vec<Candidate> {
    let network =
        inventory.sources.iter().map(|source| Candidate::new(&source.name, source.kind.into(), &source.r#type));
    let hypervisors = hypervisors.iter().map(|source| {
        let kind = if source.r#type.is_bmc() { SourceKind::Bmc } else { SourceKind::Hypervisor };
        Candidate::new(&source.name, kind, source.r#type.as_str())
    });
    network
        .chain(hypervisors)
        .map(|candidate| match runners.of(&candidate.name) {
            Some(host) => candidate.run_by(host),
            None => candidate,
        })
        .collect()
}

/// The sources that pass every filter, in the order of `candidates`: among
/// all of them without a `host` (a file one host runs), among those `host`
/// launches otherwise, so that a run without filter is the sources of its host.
///
/// A `--source` that is not a candidate is an error whatever the other
/// filters say; so is a host the file does not list, a `--source` another
/// host launches, and a filter no source passes.
pub fn select<'c>(
    filter: &Filter,
    candidates: &'c [Candidate],
    host: Option<&Host<'_>>,
) -> Result<Vec<&'c Candidate>, SelectError> {
    let unknown: BTreeSet<&str> = filter
        .names
        .iter()
        .map(String::as_str)
        .filter(|name| !candidates.iter().any(|candidate| candidate.name == *name))
        .collect();
    if !unknown.is_empty() {
        return Err(SelectError::Unknown(unknown.into_iter().map(str::to_owned).collect()));
    }
    let own = |candidate: &Candidate| host.is_none_or(|host| candidate.runner.as_deref() == Some(host.name));
    if let Some(host) = host {
        if !host.runners.iter().any(|runner| runner == host.name) {
            return Err(SelectError::NotARunner { host: host.name.to_owned(), runners: host.runners.to_vec() });
        }
        let sources: Vec<(String, String)> = candidates
            .iter()
            .filter(|candidate| filter.names.contains(&candidate.name) && !own(candidate))
            .map(|candidate| (candidate.name.clone(), candidate.runner.clone().unwrap_or_default()))
            .collect();
        if !sources.is_empty() {
            return Err(SelectError::Elsewhere { host: host.name.to_owned(), sources });
        }
    }
    let passes = |candidate: &&Candidate| {
        own(candidate)
            && (filter.kinds.is_empty() || filter.kinds.contains(&candidate.kind))
            && (filter.types.is_empty() || filter.types.iter().any(|r#type| r#type.as_str() == candidate.r#type))
            && (filter.names.is_empty() || filter.names.contains(&candidate.name))
    };
    let selected: Vec<&Candidate> = candidates.iter().filter(passes).collect();
    if selected.is_empty() && !filter.is_empty() {
        return Err(match host {
            Some(host) => SelectError::NothingOf { host: host.name.to_owned(), filter: filter.to_string() },
            None => SelectError::Nothing(filter.to_string()),
        });
    }
    Ok(selected)
}

/// The names of the selected sources that run as network sources.
pub fn network_names(selected: &[&Candidate]) -> BTreeSet<String> {
    selected.iter().filter(|candidate| !candidate.kind.is_inventory()).map(|candidate| candidate.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use omnisync_core::network::inventory::{Secret, Source, Wanted};

    use super::*;
    use crate::config::{Credentials, HypervisorType};

    fn fleet() -> Vec<Candidate> {
        vec![
            Candidate::new("nexus01.lab01", SourceKind::Switch, "nxos"),
            Candidate::new("2960-admin.lab01", SourceKind::Switch, "ios"),
            Candidate::new("fplab1-sw001", SourceKind::Switch, "nipper"),
            Candidate::new("core01.lab01", SourceKind::Router, "ios"),
            Candidate::new("fw01.lab01", SourceKind::Firewall, "fortios"),
            Candidate::new("pve01.lab01", SourceKind::Hypervisor, "proxmox"),
            Candidate::new("vcenter01.lab01", SourceKind::Hypervisor, "vmware"),
        ]
    }

    fn filter(kinds: &[SourceKind], types: &[SourceType], names: &[&str]) -> Filter {
        Filter {
            kinds: kinds.to_vec(),
            types: types.to_vec(),
            names: names.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    fn selected(filter: &Filter) -> Vec<String> {
        let fleet = fleet();
        select(filter, &fleet, None).unwrap().into_iter().map(|candidate| candidate.name.clone()).collect()
    }

    #[test]
    fn no_filter_selects_every_source() {
        assert_eq!(
            selected(&Filter::default()),
            [
                "nexus01.lab01",
                "2960-admin.lab01",
                "fplab1-sw001",
                "core01.lab01",
                "fw01.lab01",
                "pve01.lab01",
                "vcenter01.lab01"
            ]
        );
    }

    #[test]
    fn a_kind_selects_the_sources_of_that_kind() {
        assert_eq!(
            selected(&filter(&[SourceKind::Switch], &[], &[])),
            ["nexus01.lab01", "2960-admin.lab01", "fplab1-sw001"]
        );
        assert_eq!(selected(&filter(&[SourceKind::Router], &[], &[])), ["core01.lab01"]);
        assert_eq!(selected(&filter(&[SourceKind::Firewall], &[], &[])), ["fw01.lab01"]);
        assert_eq!(selected(&filter(&[SourceKind::Hypervisor], &[], &[])), ["pve01.lab01", "vcenter01.lab01"]);
    }

    #[test]
    fn a_type_selects_the_sources_of_that_type() {
        assert_eq!(selected(&filter(&[], &[SourceType::Nxos], &[])), ["nexus01.lab01"]);
        assert_eq!(selected(&filter(&[], &[SourceType::Ios], &[])), ["2960-admin.lab01", "core01.lab01"]);
        assert_eq!(selected(&filter(&[], &[SourceType::Nipper], &[])), ["fplab1-sw001"]);
        assert_eq!(selected(&filter(&[], &[SourceType::Fortios], &[])), ["fw01.lab01"]);
        assert_eq!(selected(&filter(&[], &[SourceType::Proxmox], &[])), ["pve01.lab01"]);
        assert_eq!(selected(&filter(&[], &[SourceType::Vmware], &[])), ["vcenter01.lab01"]);
    }

    #[test]
    fn a_name_selects_that_source() {
        assert_eq!(selected(&filter(&[], &[], &["fw01.lab01"])), ["fw01.lab01"]);
        assert_eq!(selected(&filter(&[], &[], &["pve01.lab01"])), ["pve01.lab01"]);
    }

    #[test]
    fn a_repeated_filter_widens() {
        assert_eq!(
            selected(&filter(&[SourceKind::Router, SourceKind::Firewall], &[], &[])),
            ["core01.lab01", "fw01.lab01"]
        );
        assert_eq!(
            selected(&filter(&[], &[SourceType::Nxos, SourceType::Vmware], &[])),
            ["nexus01.lab01", "vcenter01.lab01"]
        );
        // In the order of the configuration, whatever the order of the command line.
        assert_eq!(selected(&filter(&[], &[], &["pve01.lab01", "nexus01.lab01"])), ["nexus01.lab01", "pve01.lab01"]);
        assert_eq!(selected(&filter(&[], &[], &["fw01.lab01", "fw01.lab01"])), ["fw01.lab01"]);
    }

    #[test]
    fn different_filters_narrow() {
        assert_eq!(selected(&filter(&[SourceKind::Switch], &[SourceType::Ios], &[])), ["2960-admin.lab01"]);
        assert_eq!(
            selected(&filter(&[SourceKind::Switch, SourceKind::Router], &[SourceType::Ios], &[])),
            ["2960-admin.lab01", "core01.lab01"]
        );
        assert_eq!(selected(&filter(&[SourceKind::Switch], &[], &["nexus01.lab01", "fw01.lab01"])), ["nexus01.lab01"]);
        assert_eq!(
            selected(&filter(&[SourceKind::Hypervisor], &[SourceType::Proxmox], &["pve01.lab01"])),
            ["pve01.lab01"]
        );
    }

    #[test]
    fn an_unknown_source_is_an_error() {
        let fleet = fleet();
        let error = select(&filter(&[], &[], &["nexus09.lab01"]), &fleet, None).unwrap_err();
        assert_eq!(error, SelectError::Unknown(vec!["nexus09.lab01".to_owned()]));
        assert_eq!(error.to_string(), "unknown source(s): nexus09.lab01");
    }

    #[test]
    fn unknown_sources_are_all_named_sorted_and_once() {
        let fleet = fleet();
        let names = ["zz", "nexus01.lab01", "aa", "zz"];
        let error = select(&filter(&[], &[], &names), &fleet, None).unwrap_err();
        assert_eq!(error.to_string(), "unknown source(s): aa, zz");
    }

    #[test]
    fn an_unknown_source_is_an_error_whatever_the_other_filters() {
        let fleet = fleet();
        let error =
            select(&filter(&[SourceKind::Firewall], &[], &["fw01.lab01", "nexus09.lab01"]), &fleet, None).unwrap_err();
        assert_eq!(error.to_string(), "unknown source(s): nexus09.lab01");
    }

    #[test]
    fn filters_that_no_source_passes_are_an_error() {
        let fleet = fleet();
        let error = select(&filter(&[SourceKind::Firewall], &[SourceType::Nxos], &[]), &fleet, None).unwrap_err();
        assert_eq!(error.to_string(), "no source matches --kind firewall --type nxos");
        let error =
            select(&filter(&[SourceKind::Router], &[], &["fw01.lab01", "pve01.lab01"]), &fleet, None).unwrap_err();
        assert_eq!(error.to_string(), "no source matches --kind router --source fw01.lab01 --source pve01.lab01");
        let error = select(&filter(&[SourceKind::Hypervisor], &[], &[]), &fleet[..5], None).unwrap_err();
        assert_eq!(error.to_string(), "no source matches --kind hypervisor");
    }

    const SYNC01: &str = "sync01.lab01";
    const SAT01: &str = "sat01.lab02";

    fn runners() -> Vec<String> {
        vec![SYNC01.to_owned(), SAT01.to_owned()]
    }

    /// The fleet in a file two hosts run: the satellite launches the router
    /// and the Proxmox of its site, the central server everything else.
    fn shared_fleet() -> Vec<Candidate> {
        let on_the_satellite = ["core01.lab01", "pve01.lab01"];
        fleet()
            .into_iter()
            .map(|candidate| {
                let host = if on_the_satellite.contains(&candidate.name.as_str()) { SAT01 } else { SYNC01 };
                candidate.run_by(host)
            })
            .collect()
    }

    /// What `host` selects in the shared fleet with `filter`: the names, or the refusal.
    fn selected_on(host: &str, filter: &Filter) -> Result<Vec<String>, String> {
        let (fleet, runners) = (shared_fleet(), runners());
        select(filter, &fleet, Some(&Host { name: host, runners: &runners }))
            .map(|selected| selected.into_iter().map(|candidate| candidate.name.clone()).collect())
            .map_err(|error| error.to_string())
    }

    #[test]
    fn without_runners_every_source_is_a_candidate_of_the_run() {
        // A file one host runs: no host is asked for, and nothing is left out.
        let fleet = fleet();
        assert!(fleet.iter().all(|candidate| candidate.runner.is_none()));
        assert_eq!(select(&Filter::default(), &fleet, None).unwrap().len(), 7);
        assert_eq!(selected(&filter(&[SourceKind::Router], &[], &[])), ["core01.lab01"]);
    }

    #[test]
    fn no_filter_selects_the_sources_of_the_host() {
        assert_eq!(
            selected_on(SYNC01, &Filter::default()).unwrap(),
            ["nexus01.lab01", "2960-admin.lab01", "fplab1-sw001", "fw01.lab01", "vcenter01.lab01"]
        );
        assert_eq!(selected_on(SAT01, &Filter::default()).unwrap(), ["core01.lab01", "pve01.lab01"]);
    }

    #[test]
    fn a_filter_narrows_among_the_sources_of_the_host() {
        assert_eq!(selected_on(SYNC01, &filter(&[SourceKind::Hypervisor], &[], &[])).unwrap(), ["vcenter01.lab01"]);
        assert_eq!(selected_on(SAT01, &filter(&[SourceKind::Hypervisor], &[], &[])).unwrap(), ["pve01.lab01"]);
        assert_eq!(selected_on(SYNC01, &filter(&[], &[SourceType::Ios], &[])).unwrap(), ["2960-admin.lab01"]);
        assert_eq!(selected_on(SAT01, &filter(&[], &[SourceType::Ios], &[])).unwrap(), ["core01.lab01"]);
        assert_eq!(selected_on(SAT01, &filter(&[], &[], &["pve01.lab01"])).unwrap(), ["pve01.lab01"]);
    }

    #[test]
    fn a_source_of_another_host_is_an_error_naming_that_host() {
        assert_eq!(
            selected_on(SYNC01, &filter(&[], &[], &["pve01.lab01"])).unwrap_err(),
            "not run by sync01.lab01: pve01.lab01 (run by sat01.lab02)"
        );
        // Whatever else is asked for, and every one of them, in the order of the file.
        assert_eq!(
            selected_on(SYNC01, &filter(&[], &[], &["pve01.lab01", "nexus01.lab01", "core01.lab01"])).unwrap_err(),
            "not run by sync01.lab01: core01.lab01 (run by sat01.lab02), pve01.lab01 (run by sat01.lab02)"
        );
        // A name the file does not have is unknown on every host.
        assert_eq!(
            selected_on(SYNC01, &filter(&[], &[], &["pve09.lab01"])).unwrap_err(),
            "unknown source(s): pve09.lab01"
        );
    }

    #[test]
    fn a_host_that_is_not_in_the_list_is_an_error_naming_the_runners() {
        let refusal = "sync02.lab01 is not one of runners (sync01.lab01, sat01.lab02): it runs no source of this file";
        assert_eq!(selected_on("sync02.lab01", &Filter::default()).unwrap_err(), refusal);
        assert_eq!(selected_on("sync02.lab01", &filter(&[SourceKind::Switch], &[], &[])).unwrap_err(), refusal);
        // The short name of a host of the list is not its name.
        assert_eq!(
            selected_on("sat01", &Filter::default()).unwrap_err(),
            "sat01 is not one of runners (sync01.lab01, sat01.lab02): it runs no source of this file"
        );
    }

    #[test]
    fn a_filter_no_source_of_the_host_passes_names_the_host() {
        assert_eq!(
            selected_on(SAT01, &filter(&[SourceKind::Switch], &[], &[])).unwrap_err(),
            "no source of sat01.lab02 matches --kind switch"
        );
        assert_eq!(
            selected_on(SYNC01, &filter(&[SourceKind::Router], &[SourceType::Ios], &[])).unwrap_err(),
            "no source of sync01.lab01 matches --kind router --type ios"
        );
    }

    #[test]
    fn the_candidates_carry_the_host_the_file_gives_them() {
        let text = "runners = [\"sync01.lab01\", \"sat01.lab02\"]\n\
                    [netbox]\nurl = \"https://netbox.example.net\"\n\
                    [ssh]\nusername = \"sync\"\nauth = \"agent\"\n\
                    [[sources]]\nname = \"nexus01.lab01\"\nkind = \"switch\"\ntype = \"nxos\"\n\
                    host = \"192.0.2.239\"\nrunner = \"sync01.lab01\"\n\
                    [[sources]]\nname = \"pve01.lab01\"\nkind = \"hypervisor\"\ntype = \"proxmox\"\n\
                    host = \"192.0.2.10\"\nrunner = \"sat01.lab02\"\n";
        let config = crate::config::parse(std::path::Path::new("config.toml"), text, &BTreeMap::new()).unwrap();
        assert_eq!(
            candidates(&config.inventory, &config.hypervisors, &config.runners),
            [
                Candidate::new("nexus01.lab01", SourceKind::Switch, "nxos").run_by("sync01.lab01"),
                Candidate::new("pve01.lab01", SourceKind::Hypervisor, "proxmox").run_by("sat01.lab02"),
            ]
        );
    }

    #[test]
    fn no_filter_on_an_empty_configuration_selects_nothing() {
        assert_eq!(select(&Filter::default(), &[], None), Ok(vec![]));
    }

    #[test]
    fn the_network_names_leave_the_hypervisors_out() {
        let fleet = fleet();
        let all = select(&Filter::default(), &fleet, None).unwrap();
        let expected = ["2960-admin.lab01", "core01.lab01", "fplab1-sw001", "fw01.lab01", "nexus01.lab01"];
        assert_eq!(network_names(&all).into_iter().collect::<Vec<_>>(), expected);
        let hypervisors = select(&filter(&[SourceKind::Hypervisor], &[], &[]), &fleet, None).unwrap();
        assert!(network_names(&hypervisors).is_empty());
    }

    /// The fleet, and the BMCs of its servers.
    fn fleet_with_bmcs() -> Vec<Candidate> {
        let mut fleet = fleet();
        fleet.push(Candidate::new("bmc.lab01", SourceKind::Bmc, "redfish"));
        fleet
    }

    fn selected_with_bmcs(filter: &Filter) -> Vec<String> {
        let fleet = fleet_with_bmcs();
        select(filter, &fleet, None).unwrap().into_iter().map(|candidate| candidate.name.clone()).collect()
    }

    #[test]
    fn selecting_the_hypervisors_never_selects_a_bmc_source() {
        // The hypervisors are synced every few minutes; a BMC is read once a day.
        assert_eq!(
            selected_with_bmcs(&filter(&[SourceKind::Hypervisor], &[], &[])),
            ["pve01.lab01", "vcenter01.lab01"]
        );
        assert_eq!(
            selected_with_bmcs(&filter(&[], &[SourceType::Proxmox, SourceType::Vmware], &[])),
            ["pve01.lab01", "vcenter01.lab01"]
        );
    }

    #[test]
    fn a_bmc_source_is_selected_by_its_kind_its_type_or_its_name() {
        assert_eq!(selected_with_bmcs(&filter(&[SourceKind::Bmc], &[], &[])), ["bmc.lab01"]);
        assert_eq!(selected_with_bmcs(&filter(&[], &[SourceType::Redfish], &[])), ["bmc.lab01"]);
        assert_eq!(selected_with_bmcs(&filter(&[], &[], &["bmc.lab01"])), ["bmc.lab01"]);
        // Asked for with the hypervisors, it runs with them.
        assert_eq!(
            selected_with_bmcs(&filter(&[SourceKind::Hypervisor, SourceKind::Bmc], &[], &[])),
            ["pve01.lab01", "vcenter01.lab01", "bmc.lab01"]
        );
        // Without filter everything runs.
        assert_eq!(selected_with_bmcs(&Filter::default()).last().map(String::as_str), Some("bmc.lab01"));
        assert_eq!(selected_with_bmcs(&Filter::default()).len(), 8);
    }

    #[test]
    fn a_bmc_source_is_reconciled_with_the_hypervisors_not_run_as_a_network_source() {
        assert!(SourceKind::Bmc.is_inventory() && SourceKind::Hypervisor.is_inventory());
        for kind in [SourceKind::Switch, SourceKind::Router, SourceKind::Firewall] {
            assert!(!kind.is_inventory(), "{kind:?}");
        }
        let fleet = fleet_with_bmcs();
        let bmcs = select(&filter(&[SourceKind::Bmc], &[], &[]), &fleet, None).unwrap();
        assert!(network_names(&bmcs).is_empty());
        assert_eq!((SourceKind::Bmc.as_str(), SourceType::Redfish.as_str()), ("bmc", "redfish"));
    }

    #[test]
    fn the_candidates_are_the_sources_of_the_configuration() {
        let inventory = Inventory {
            sources: vec![
                Source::new("nexus01.lab01", Kind::Switch, "nxos", "192.0.2.239"),
                Source::new("core01.lab01", Kind::Router, "ios", "192.0.2.1"),
                Source::new("fw01.lab01", Kind::Firewall, "fortios", "192.0.2.2"),
            ],
            domains: Vec::new(),
            netbox_url: "https://netbox.example.net".to_owned(),
            netbox_token: Wanted::Held(Secret::new("token-value")),
            aliases: BTreeMap::new(),
        };
        let hypervisor = Hypervisor {
            name: "vcenter01.lab01".to_owned(),
            r#type: HypervisorType::Vmware,
            host: "192.0.2.20".to_owned(),
            port: None,
            validate_certs: true,
            ca_file: None,
            site: None,
            tenant: None,
            host_role: None,
            vm_role: None,
            domain: None,
            ignore_templates: true,
            ignored_subnets: Vec::new(),
            permitted_subnets: Vec::new(),
            interface_filter: None,
            dns_name_lookup: false,
            dns_servers: Vec::new(),
            create_devices: true,
            prune: true,
            vlan_group: None,
            bmcs: Vec::new(),
            credentials: Wanted::Held(Credentials::Token { token: Secret::new("vc-secret") }),
            neighbors: false,
            ssh: None,
        };
        // An entry of kind `bmc` is loaded with the hypervisors, and is a candidate of its own kind.
        let bmcs = Hypervisor {
            name: "bmc.lab01".to_owned(),
            r#type: HypervisorType::Redfish,
            host: String::new(),
            ..hypervisor.clone()
        };
        assert_eq!(
            candidates(&inventory, &[hypervisor, bmcs], &Runners::default()),
            [
                Candidate::new("nexus01.lab01", SourceKind::Switch, "nxos"),
                Candidate::new("core01.lab01", SourceKind::Router, "ios"),
                Candidate::new("fw01.lab01", SourceKind::Firewall, "fortios"),
                Candidate::new("vcenter01.lab01", SourceKind::Hypervisor, "vmware"),
                Candidate::new("bmc.lab01", SourceKind::Bmc, "redfish"),
            ]
        );
    }
}
