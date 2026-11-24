//! What NetBox holds of the kinds the hypervisor sources describe.
//!
//! The reconciliation is a pure function of the whole current state: this
//! module reads that state, every requested kind in full, and hands it over as
//! [`Current`] objects. All or nothing: a kind that could not be read would
//! look empty, and the reconciliation would create every object of it again.

use std::collections::{BTreeMap, BTreeSet};

use futures::future::try_join_all;
use omnisync_core::gateway::{Gateway, GatewayError, Row};
use omnisync_core::inventory::identity::current_objects;
use omnisync_core::inventory::model::{Current, Kind};
use serde_json::Value;

/// A kind could not be read: nothing is loaded.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("reading {endpoint}: {error}")]
pub struct LoadError {
    /// The endpoint whose list failed.
    pub endpoint: String,
    #[source]
    pub error: GatewayError,
}

/// The current state, as [`reconcile`](omnisync_core::inventory::reconcile::reconcile) takes it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Loaded {
    /// Every identified object of the requested kinds, in dependency order.
    pub current: Vec<Current>,
    /// The rows left out because they cannot be identified: the tool neither
    /// updates nor deletes them, and the run goes on.
    pub warnings: Vec<String>,
    /// For `Run.unique_ip_vrfs`: the tables in which NetBox refuses a second
    /// object for one address. Lower-cased VRF names, and `""` for the global
    /// table, which is taken as enforcing (see [`load`]).
    pub unique_ip_vrfs: BTreeSet<String>,
}

/// The tables in which an address is unique: the global one, and the VRFs
/// among the rows of `ipam.vrfs` that do not say `enforce_unique: false`.
fn unique_ip_vrfs(vrfs: &[Row]) -> BTreeSet<String> {
    let enforcing = |vrf: &&Row| vrf.get("enforce_unique").and_then(Value::as_bool).unwrap_or(true);
    let names = vrfs.iter().filter(enforcing).filter_map(|vrf| vrf.get("name").and_then(Value::as_str));
    std::iter::once(String::new()).chain(names.map(str::to_lowercase)).collect()
}

/// Reads everything NetBox holds of `kinds`, and nothing else.
///
/// A run passes every kind (`Kind::ALL`), whatever its sources report: what a
/// source stopped reporting altogether (its last disk, its last cluster) is an
/// orphan of a kind no desired object has, and the report lists the orphans
/// with or without `--prune`. The lists are asked for all at once, the gateway
/// bounding the requests in flight; the result is the same whatever the order
/// they answer in.
///
/// The first list that fails fails the load, naming its endpoint: a partial
/// state would make the reconciliation create duplicates. A row that cannot be
/// identified is only a warning: it is one object the tool leaves alone.
///
/// `unique_ip_vrfs` holds the VRFs read with `enforce_unique` (a VRF without
/// the field counts as enforcing, NetBox's default for a VRF), and always the
/// global table: NetBox does not expose `ENFORCE_GLOBAL_UNIQUE`, whose default
/// is on, and taking a table as unique only turns a duplicate NetBox might
/// have accepted into a warning. Without `Kind::Vrf` in `kinds` no VRF is
/// read, and only the global table is listed.
pub async fn load<G: Gateway>(gateway: &G, kinds: &BTreeSet<Kind>) -> Result<Loaded, LoadError> {
    load_shown(gateway, kinds, &|_| {}).await
}

/// [`load`], telling `listed` the endpoint of each list as it answers: the
/// lists are the units of the progress of a run. A list that fails is not told.
pub async fn load_shown<G: Gateway>(
    gateway: &G,
    kinds: &BTreeSet<Kind>,
    listed: &(dyn Fn(&str) + Sync),
) -> Result<Loaded, LoadError> {
    let no_filter = Vec::new();
    let lists = kinds.iter().map(|&kind| {
        let no_filter = &no_filter;
        async move {
            let endpoint = kind.endpoint();
            match gateway.list(endpoint, no_filter).await {
                Ok(rows) => {
                    listed(endpoint);
                    Ok((kind, rows))
                }
                Err(error) => Err(LoadError { endpoint: endpoint.to_owned(), error }),
            }
        }
    });
    // Keyed by kind: the order the lists answered in is gone here.
    let rows: BTreeMap<Kind, Vec<Row>> = try_join_all(lists).await?.into_iter().collect();
    let unique_ip_vrfs = unique_ip_vrfs(rows.get(&Kind::Vrf).map(Vec::as_slice).unwrap_or_default());
    let (current, warnings) = current_objects(&rows);
    Ok(Loaded { current, warnings, unique_ip_vrfs })
}

#[cfg(test)]
mod tests {
    use omnisync_core::Write;
    use std::sync::Mutex;

    use omnisync_core::gateway::Filters;
    use serde_json::json;

    use super::*;
    use crate::testing::FakeGateway;

    /// A NetBox that says which lists were asked for and in which order they
    /// answered, makes each list wait a chosen number of turns, and may fail one.
    #[derive(Default)]
    struct Observed {
        netbox: FakeGateway,
        /// `start <endpoint>` and `end <endpoint>`, as they happen.
        events: Mutex<Vec<String>>,
        /// Turns a list of an endpoint waits before answering; one by default,
        /// so that no list answers before the others were asked.
        turns: BTreeMap<&'static str, usize>,
        failing: Option<&'static str>,
    }

    impl Observed {
        fn event(&self, what: &str, endpoint: &str) {
            self.events.lock().expect("the event log").push(format!("{what} {endpoint}"));
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().expect("the event log").clone()
        }

        fn listed(&self) -> Vec<String> {
            let mut listed: Vec<String> =
                self.events().iter().filter_map(|event| event.strip_prefix("start ").map(str::to_owned)).collect();
            listed.sort();
            listed
        }
    }

    impl Gateway for Observed {
        async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
            self.event("start", endpoint);
            for _ in 0..self.turns.get(endpoint).copied().unwrap_or(1) {
                tokio::task::yield_now().await;
            }
            self.event("end", endpoint);
            if self.failing == Some(endpoint) {
                return Err(GatewayError::Request("GET answered 500 Internal Server Error".to_owned()));
            }
            self.netbox.list(endpoint, filters).await
        }

        async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
            self.netbox.create(endpoint, payload).await
        }

        async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
            self.netbox.update(endpoint, id, payload).await
        }

        async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
            self.netbox.delete(endpoint, id).await
        }
        async fn check_write(&self, write: Write, endpoint: &str, fields: &[String]) -> Result<(), GatewayError> {
            self.netbox.check_write(write, endpoint, fields).await
        }
    }

    fn kinds<const N: usize>(kinds: [Kind; N]) -> BTreeSet<Kind> {
        kinds.into()
    }

    fn names<const N: usize>(names: [&str; N]) -> BTreeSet<String> {
        names.into_iter().map(str::to_owned).collect()
    }

    /// A cluster with a virtual machine, its interface, and a VRF nobody asked for.
    fn small_netbox() -> (FakeGateway, [u64; 3]) {
        let netbox = FakeGateway::new();
        let cluster = netbox.add("virtualization.clusters", json!({"name": "PVE-Lab"}));
        let vm = netbox.add("virtualization.virtual_machines", json!({"name": "web01", "cluster": cluster}));
        let eth0 = netbox.add("virtualization.interfaces", json!({"name": "eth0", "virtual_machine": vm}));
        netbox.add("ipam.vrfs", json!({"name": "Prod"}));
        netbox.add("dcim.devices", json!({"name": "esx01", "site": 12}));
        (netbox, [cluster, vm, eth0])
    }

    fn summary(loaded: &Loaded) -> Vec<(Kind, u64, Vec<String>)> {
        loaded.current.iter().map(|object| (object.kind, object.id, object.identity.key().to_vec())).collect()
    }

    fn key<const N: usize>(parts: [&str; N]) -> Vec<String> {
        parts.into_iter().map(str::to_owned).collect()
    }

    // Loading

    #[tokio::test]
    async fn the_rows_of_the_requested_kinds_become_identified_objects() {
        let (netbox, [cluster, vm, eth0]) = small_netbox();
        let wanted = kinds([Kind::Cluster, Kind::VirtualMachine, Kind::VmInterface]);
        let loaded = load(&netbox, &wanted).await.expect("loaded");
        assert_eq!(
            summary(&loaded),
            [
                (Kind::Cluster, cluster, key(["pve-lab"])),
                (Kind::VirtualMachine, vm, key(["web01", "pve-lab"])),
                (Kind::VmInterface, eth0, key(["web01", "pve-lab", "eth0"])),
            ]
        );
        assert_eq!(loaded.current[2].parent, Some((Kind::VirtualMachine, vm)));
        assert_eq!(loaded.current[1].row["name"], json!("web01"));
        assert_eq!(loaded.warnings, Vec::<String>::new());
    }

    #[tokio::test]
    async fn each_list_that_answered_is_told_once() {
        // A run shows the read of NetBox list by list: without this the whole
        // read is one unit, and its progress stands still until the last list.
        let (netbox, _) = small_netbox();
        let wanted = kinds([Kind::Cluster, Kind::VirtualMachine, Kind::VmInterface]);
        let told: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let listed = |endpoint: &str| told.lock().expect("the endpoints told").push(endpoint.to_owned());
        load_shown(&netbox, &wanted, &listed).await.expect("loaded");
        let mut told = told.into_inner().expect("the endpoints told");
        told.sort();
        assert_eq!(told, ["virtualization.clusters", "virtualization.interfaces", "virtualization.virtual_machines"]);
    }

    #[tokio::test]
    async fn a_kind_that_is_not_requested_is_never_listed() {
        let (netbox, _) = small_netbox();
        let observed = Observed { netbox, ..Observed::default() };
        let wanted = kinds([Kind::Cluster, Kind::VirtualMachine, Kind::VmInterface]);
        let loaded = load(&observed, &wanted).await.expect("loaded");
        assert_eq!(
            observed.listed(),
            ["virtualization.clusters", "virtualization.interfaces", "virtualization.virtual_machines"]
        );
        // The device and the VRF are in NetBox, and stay out of the state.
        assert_eq!(loaded.current.len(), 3);
        // No VRF was read: only the global table is known to be unique.
        assert_eq!(loaded.unique_ip_vrfs, names([""]));
    }

    #[tokio::test]
    async fn every_list_is_asked_for_before_the_first_one_answers() {
        let (netbox, _) = small_netbox();
        let observed = Observed { netbox, ..Observed::default() };
        load(&observed, &kinds([Kind::Cluster, Kind::Vrf, Kind::Device])).await.expect("loaded");
        let events = observed.events();
        let started: BTreeSet<&str> = events[..3].iter().map(String::as_str).collect();
        assert_eq!(started, BTreeSet::from(["start dcim.devices", "start ipam.vrfs", "start virtualization.clusters"]));
        assert_eq!(events.len(), 6);
    }

    #[tokio::test]
    async fn a_failed_list_fails_the_whole_load_naming_the_endpoint() {
        let (netbox, _) = small_netbox();
        let observed = Observed { netbox, failing: Some("virtualization.virtual_machines"), ..Observed::default() };
        let wanted = kinds([Kind::Cluster, Kind::VirtualMachine, Kind::VmInterface]);
        let error = load(&observed, &wanted).await.expect_err("one list failed");
        assert_eq!(error.endpoint, "virtualization.virtual_machines");
        assert_eq!(error.error, GatewayError::Request("GET answered 500 Internal Server Error".to_owned()));
        assert_eq!(
            error.to_string(),
            "reading virtualization.virtual_machines: GET answered 500 Internal Server Error"
        );
    }

    #[tokio::test]
    async fn rows_that_cannot_be_identified_are_warnings_not_errors() {
        let (netbox, [cluster, vm, eth0]) = small_netbox();
        let unnamed = netbox.add("virtualization.clusters", json!({"name": null}));
        // The interfaces are asked for without the virtual machines they are identified through.
        let loaded = load(&netbox, &kinds([Kind::Cluster, Kind::VmInterface])).await.expect("loaded");
        assert_eq!(summary(&loaded), [(Kind::Cluster, cluster, key(["pve-lab"]))]);
        assert_eq!(
            loaded.warnings,
            [
                format!("virtualization.clusters {unnamed} ignored: cluster row without name"),
                format!("virtualization.interfaces {eth0} ignored: vm_interface {eth0}: its vm {vm} was not read"),
            ]
        );
    }

    #[tokio::test]
    async fn the_result_does_not_depend_on_the_order_in_which_the_lists_answer() {
        let wanted = kinds([Kind::Cluster, Kind::VirtualMachine, Kind::VmInterface]);
        let ends = |observed: &Observed| -> Vec<String> {
            observed.events().iter().filter_map(|event| event.strip_prefix("end ").map(str::to_owned)).collect()
        };

        let (netbox, [cluster, vm, eth0]) = small_netbox();
        let parents_first = Observed {
            netbox,
            turns: BTreeMap::from([
                ("virtualization.clusters", 1),
                ("virtualization.virtual_machines", 2),
                ("virtualization.interfaces", 3),
            ]),
            ..Observed::default()
        };
        let in_order = load(&parents_first, &wanted).await.expect("loaded");
        assert_eq!(
            ends(&parents_first),
            ["virtualization.clusters", "virtualization.virtual_machines", "virtualization.interfaces"]
        );

        // The interfaces answer first, then the virtual machines they are identified through.
        let (netbox, _) = small_netbox();
        let children_first = Observed {
            netbox,
            turns: BTreeMap::from([
                ("virtualization.clusters", 3),
                ("virtualization.virtual_machines", 2),
                ("virtualization.interfaces", 1),
            ]),
            ..Observed::default()
        };
        let reversed = load(&children_first, &wanted).await.expect("loaded");
        assert_eq!(
            ends(&children_first),
            ["virtualization.interfaces", "virtualization.virtual_machines", "virtualization.clusters"]
        );

        assert_eq!(reversed, in_order);
        assert_eq!(
            summary(&reversed),
            [
                (Kind::Cluster, cluster, key(["pve-lab"])),
                (Kind::VirtualMachine, vm, key(["web01", "pve-lab"])),
                (Kind::VmInterface, eth0, key(["web01", "pve-lab", "eth0"])),
            ]
        );
        assert_eq!(reversed.warnings, Vec::<String>::new());
    }

    #[tokio::test]
    async fn the_tables_with_unique_addresses_are_the_enforcing_vrfs_and_the_global_one() {
        let netbox = FakeGateway::new();
        netbox.add("ipam.vrfs", json!({"name": "Prod", "enforce_unique": true}));
        netbox.add("ipam.vrfs", json!({"name": "Lab-Overlap", "enforce_unique": false}));
        // A VRF enforces unless it says otherwise.
        netbox.add("ipam.vrfs", json!({"name": "Mgmt"}));
        let loaded = load(&netbox, &kinds([Kind::Vrf])).await.expect("loaded");
        assert_eq!(loaded.unique_ip_vrfs, names(["", "mgmt", "prod"]));
        assert_eq!(loaded.current.len(), 3);
    }

    #[tokio::test]
    async fn an_empty_netbox_is_an_empty_state() {
        let loaded = load(&FakeGateway::new(), &kinds(Kind::ALL)).await.expect("loaded");
        assert_eq!(loaded, Loaded { current: Vec::new(), warnings: Vec::new(), unique_ip_vrfs: names([""]) });
    }
}
