//! Read a firewall: fetch its closed list of API calls and build its state.

use std::collections::BTreeMap;
use std::future::Future;

pub use omnisync_core::network::collect::CollectionError;
use omnisync_core::network::inventory::Source;
use omnisync_core::network::model::DeviceState;

use crate::api::FORTIOS_COMMANDS;
use crate::parser::{self, ParseError};

/// Fetches the answers of one firewall; implemented by the API client and by
/// the fakes of the tests.
pub trait Fetcher {
    /// The answer to one call of `FORTIOS_COMMANDS`, or why the firewall did not give it.
    fn run(&mut self, command: &str) -> impl Future<Output = Result<String, CollectionError>> + Send;
}

/// Answers of one firewall, by the key of their call.
struct Outputs(BTreeMap<&'static str, String>);

impl Outputs {
    async fn read<F: Fetcher>(fetcher: &mut F) -> Result<Self, CollectionError> {
        let mut outputs = BTreeMap::new();
        for (key, command) in FORTIOS_COMMANDS {
            outputs.insert(key, fetcher.run(command).await?);
        }
        Ok(Outputs(outputs))
    }

    /// A parse failure names its call: the parsers put it in their error.
    fn parse<T>(&self, key: &str, parser: impl FnOnce(&str) -> Result<T, ParseError>) -> Result<T, CollectionError> {
        let output = self.0.get(key).map_or("", String::as_str);
        parser(output).map_err(|error| CollectionError(error.to_string()))
    }
}

/// Number of calls the collection of a firewall makes.
pub const fn command_count() -> usize {
    FORTIOS_COMMANDS.len()
}

/// Fetch the calls of `FORTIOS_COMMANDS`, in order, and build the state of the firewall.
///
/// `source` is the inventory entry, which a firewall needs: its name, the
/// members of its cluster and the interfaces left out.
pub async fn collect<F: Fetcher>(fetcher: &mut F, source: &Source) -> Result<DeviceState, CollectionError> {
    let outputs = Outputs::read(fetcher).await?;
    let (hostname, serial) = outputs.parse("status", parser::parse_status)?;
    // An address answered by another firewall would be synced onto this device. In
    // a cluster the unit that answers changes with the failover: any member is right.
    let short_name = source.name.split('.').next().unwrap_or(&source.name);
    let answering = hostname.to_lowercase();
    let member = short_name.to_lowercase() == answering
        || source.ha_peers.iter().any(|(peer, _)| peer.to_lowercase() == answering);
    if !member {
        return Err(CollectionError(format!("the firewall that answers is {hostname}, not {}", source.name)));
    }
    let monitor = outputs.parse("monitor", parser::parse_monitor)?;
    let parsed =
        outputs.parse("interfaces", |text| parser::parse_interfaces(text, &monitor, &source.ignore_interfaces))?;
    Ok(DeviceState {
        serial: Some(serial),
        interfaces: parsed.interfaces,
        vlans: parsed.vlans,
        ips: parsed.ips,
        // The neighbours of a firewall are not read: its cables are left to NetBox.
        neighbors: Vec::new(),
        peer_serials: outputs.parse("ha", parser::parse_ha_peers)?,
        vlan_names_managed: false,
        ..DeviceState::default()
    })
}

#[cfg(test)]
mod tests {
    use omnisync_core::network::inventory::Kind;

    use super::*;
    use crate::parser::fixtures::{V7_4_13, fixture_text};

    /// Fetcher that answers from the recorded firewall answers, except for the
    /// calls it is told to refuse or to answer otherwise.
    #[derive(Default)]
    struct FixtureFetcher {
        refused: BTreeMap<&'static str, &'static str>,
        answers: BTreeMap<&'static str, String>,
        commands: Vec<String>,
    }

    impl Fetcher for FixtureFetcher {
        async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
            self.commands.push(command.to_owned());
            if let Some(why) = self.refused.get(command) {
                return Err(CollectionError((*why).to_owned()));
            }
            Ok(match self.answers.get(command) {
                Some(answer) => answer.clone(),
                None => fixture_text(V7_4_13, command),
            })
        }
    }

    fn firewall(name: &str) -> Source {
        Source {
            username: "readonly".to_owned(),
            ignore_interfaces: vec!["dmz".to_owned()],
            ..Source::new(name, Kind::Firewall, "fortios", "192.0.2.1")
        }
    }

    fn failure(result: Result<DeviceState, CollectionError>) -> String {
        result.expect_err("a collection failure").0
    }

    #[tokio::test]
    async fn collect_fortios() {
        let mut fetcher = FixtureFetcher::default();
        let state = collect(&mut fetcher, &firewall("lablu-fwl01.dc1")).await.expect("the fixtures parse");
        assert_eq!(
            fetcher.commands,
            [
                "cmdb/system/interface?format=name|type|alias|description|status|mtu-override|mtu|vlanid|\
                 interface|member|ip|secondary-IP|secondaryip|vdom",
                "monitor/system/interface?include_vlan=true&include_aggregate=true",
                "monitor/system/status",
                "monitor/system/ha-peer",
            ]
        );
        assert_eq!(command_count(), 4);
        assert_eq!(state.serial.as_deref(), Some("FG101FTK22000001"));
        // 53 interfaces in the answer, `dmz` ignored; 14 of them carry an address.
        assert_eq!(state.interfaces.len(), 52);
        assert_eq!(state.ips.len(), 14);
        assert_eq!(state.interfaces["HOUSING"].parent.as_deref(), Some("PO2"));
        assert_eq!(state.vlans[&12], "HOUSING");
        assert_eq!(state.neighbors, []);
    }

    #[tokio::test]
    async fn collect_fortios_gives_the_cluster_and_leaves_the_vlan_names_unmanaged() {
        let state =
            collect(&mut FixtureFetcher::default(), &firewall("lablu-fwl01.dc1")).await.expect("the fixtures parse");
        // "results":[{"serial_no":"FG101FTK22000001",…,"hostname":"LABLU-FWL01",…},
        //            {"serial_no":"FG101FTK22000002",…,"hostname":"LABBS-FWL01"}]
        assert_eq!(
            state.peer_serials,
            BTreeMap::from([
                ("LABBS-FWL01".to_owned(), "FG101FTK22000002".to_owned()),
                ("LABLU-FWL01".to_owned(), "FG101FTK22000001".to_owned()),
            ])
        );
        // The names in `vlans` are interface names, not VLAN names.
        assert!(!state.vlan_names_managed);
        assert!(state.ips_managed);
        assert_eq!(state.member_serials, BTreeMap::new());
    }

    #[tokio::test]
    async fn fortios_case_collision_fails_collection_naming_the_call() {
        let source = Source { ignore_interfaces: Vec::new(), ..firewall("lablu-fwl01.dc1") };
        assert_eq!(
            failure(collect(&mut FixtureFetcher::default(), &source).await),
            "cmdb/system/interface?format=name|type|alias|description|status|mtu-override|mtu|vlanid|\
             interface|member|ip|secondary-IP|secondaryip|vdom: \
             interfaces DMZ and dmz differ by case only: leave one out with ignore_interfaces"
        );
    }

    #[tokio::test]
    async fn fortios_of_another_firewall_fails_collection() {
        assert_eq!(
            failure(collect(&mut FixtureFetcher::default(), &firewall("fw09.dc1")).await),
            "the firewall that answers is LABLU-FWL01, not fw09.dc1"
        );
    }

    #[tokio::test]
    async fn fortios_host_name_may_be_a_cluster_member() {
        let source = Source {
            ha_peers: vec![
                ("LABBS-FWL01".to_owned(), "fw02.dc1".to_owned()),
                ("LABLU-FWL01".to_owned(), "fw01.dc1".to_owned()),
            ],
            ..firewall("fw01.dc1")
        };
        let state = collect(&mut FixtureFetcher::default(), &source).await.expect("a member answers");
        assert_eq!(state.serial.as_deref(), Some("FG101FTK22000001"));
    }

    #[tokio::test]
    async fn fortios_cluster_member_is_matched_without_case() {
        let source =
            Source { ha_peers: vec![("lablu-fwl01".to_owned(), "fw01.dc1".to_owned())], ..firewall("fw01.dc1") };
        let state = collect(&mut FixtureFetcher::default(), &source).await.expect("a member answers");
        assert_eq!(state.serial.as_deref(), Some("FG101FTK22000001"));
    }

    #[tokio::test]
    async fn fortios_refused_call_fails_collection() {
        let mut fetcher = FixtureFetcher {
            refused: BTreeMap::from([("monitor/system/ha-peer", "monitor/system/ha-peer: HTTP 403")]),
            ..FixtureFetcher::default()
        };
        assert_eq!(
            failure(collect(&mut fetcher, &firewall("lablu-fwl01.dc1")).await),
            "monitor/system/ha-peer: HTTP 403"
        );
    }

    #[tokio::test]
    async fn fortios_answer_cut_short_fails_collection_naming_the_call() {
        // A login page served instead of the answer: the session expired on the way.
        let mut fetcher = FixtureFetcher {
            answers: BTreeMap::from([("monitor/system/status", "<html>login</html>".to_owned())]),
            ..FixtureFetcher::default()
        };
        assert_eq!(
            failure(collect(&mut fetcher, &firewall("lablu-fwl01.dc1")).await),
            r#"monitor/system/status: not JSON: "<html>login</html>""#
        );
    }

    #[tokio::test]
    async fn fortios_without_any_interface_fails_collection() {
        // An empty list would let a prune delete every interface NetBox holds.
        let empty = r#"{"status": "success", "results": []}"#.to_owned();
        let mut fetcher =
            FixtureFetcher { answers: BTreeMap::from([(crate::api::INTERFACES, empty)]), ..FixtureFetcher::default() };
        assert_eq!(
            failure(collect(&mut fetcher, &firewall("lablu-fwl01.dc1")).await),
            "cmdb/system/interface?format=name|type|alias|description|status|mtu-override|mtu|vlanid|\
             interface|member|ip|secondary-IP|secondaryip|vdom: no interface"
        );
    }
}
