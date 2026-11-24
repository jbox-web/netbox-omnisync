//! One run over the network sources: collect, VLANs, devices, cables, deletions.
//!
//! Every failure is typed and carries its own message: an error line is the
//! name of what failed followed by that message.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use futures::future::join_all;
use futures::stream::{self, StreamExt};
use omnisync_cisco::collect::{add_description_neighbors, collect_report};
use omnisync_cisco::runner::CommandRunner;
use omnisync_core::change::{Action, Change};
use omnisync_core::inventory::model::VlanGroups;
use omnisync_core::network::cables::{
    CableOptions, Descriptions, Interfaces, Stacks, description_mismatches, diff_cables, lookup_names, name_family,
    port_labeller,
};
use omnisync_core::network::collect::CollectionError;
use omnisync_core::network::descriptions::{PROTOCOL as DESCRIPTION, neighbors_from_descriptions};
use omnisync_core::network::diff::diff_device;
use omnisync_core::network::hosts::{Heard, HeardContext, merge_heard};
use omnisync_core::network::inventory::{API_TYPES, Inventory, REPORT_TYPES, Source};
use omnisync_core::network::model::{DeviceState, Neighbor};
use omnisync_core::network::names::interface_key;
use omnisync_core::network::stack::{DesiredDevice, desired_devices};
use omnisync_core::network::state::NbDevice;
use omnisync_core::network::vlans::{VlanHome, diff_vlans, mark_foreign_vlans};
use omnisync_core::progress::Progress;
use omnisync_core::{Filters, Gateway, GatewayError, Outcome, Row, Write};
use omnisync_fortios::collect::Fetcher;
use omnisync_netbox::ReportingGateway;
use omnisync_netbox::apply::{Applier, planned_writes};
use omnisync_netbox::state::{
    StateError, combine_cables, missing_vrfs, read_device, read_device_cables, read_group_vlans, read_interfaces,
    read_ips_by_host, read_parent_device, read_site_vlans, read_vc_master, read_vc_members, read_vlan_group,
    unique_ip_tables,
};
use tokio::time::Instant;

/// Sources are collected at the same time, at most this many at once.
pub const MAX_PARALLEL_SSH: usize = 8;
/// Then read from NetBox at the same time, at most this many at once: lower, to
/// spare the NetBox workers.
pub const MAX_PARALLEL_NETBOX: usize = 4;

/// What a run is asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Write the changes to NetBox; otherwise only report them.
    pub apply: bool,
    /// Also delete what NetBox holds and the sources no longer have.
    pub prune: bool,
    /// The sources to run, by name; empty: every source of the inventory.
    pub only: BTreeSet<String>,
    /// The sites that keep their VLANs in a NetBox VLAN group (`[[vlan_groups]]`).
    pub vlan_groups: VlanGroups,
    /// The switch port each card of each host hears, as the hypervisors of
    /// the run told it: a neighbour of that port at the cable step.
    pub heard: Vec<Heard>,
}

/// How many collections and how many NetBox reads run at once.
#[derive(Debug, Clone, Copy)]
struct Limits {
    collect: usize,
    netbox: usize,
}

/// A count as the progress takes it.
fn units(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// The run's progress, shared by the collections and the reads that run at the
/// same time.
///
/// The units done are counted so the total stays consistent. Nothing here
/// tells an interrupted run to stop: an interrupt drops the future of the run,
/// and with it every collection and every read still going.
struct Tracker<'p> {
    progress: &'p dyn Progress,
    done: AtomicU64,
    total: AtomicU64,
}

/// Writes announced to the bar, until they are counted.
struct Writes {
    units: u64,
    before: usize,
}

impl<'p> Tracker<'p> {
    fn new(progress: &'p dyn Progress) -> Self {
        Tracker { progress, done: AtomicU64::new(0), total: AtomicU64::new(0) }
    }

    fn advance(&self, units: u64, lane: Option<&str>) {
        for _ in 0..units {
            self.progress.advance(lane);
        }
        self.done.fetch_add(units, Ordering::Relaxed);
    }

    fn begin(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
        self.progress.begin(total);
    }

    fn resize(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
        self.progress.resize(total);
    }

    /// Writes or reads about to happen: each one becomes a unit of the bar.
    fn grow(&self, units: u64) {
        if units > 0 {
            self.resize(self.total.load(Ordering::Relaxed) + units);
        }
    }

    /// `count` writes are about to be made, `applied` changes being written so far.
    fn writing(&self, count: usize, applied: usize) -> Writes {
        let units = units(count);
        self.grow(units);
        Writes { units, before: applied }
    }

    /// The writes were made, or stopped early: all of them count in the bar.
    fn written(&self, writes: Writes, applied: usize) {
        let missing = writes.units.saturating_sub(units(applied.saturating_sub(writes.before)));
        if missing > 0 {
            self.advance(missing, None);
        }
    }

    fn step(&self, label: &str) {
        self.progress.step(label);
    }

    fn doing(&self, label: &str) {
        self.progress.doing(label);
    }

    fn note(&self, text: &str) {
        self.progress.note(text);
    }

    fn lane_start(&self, lane: &str, total: u64) {
        self.progress.lane_start(lane, total);
    }

    fn lane_doing(&self, lane: &str, label: &str) {
        self.progress.lane_doing(lane, label);
    }

    fn lane_end(&self, lane: &str) {
        self.progress.lane_end(lane);
    }

    fn end(&self) {
        self.progress.end();
    }
}

/// Ends the progress when the run is over, however it ends: an interrupted run
/// is dropped, and must not leave its bar on the terminal.
struct Finish<'t, 'p>(&'t Tracker<'p>);

impl Drop for Finish<'_, '_> {
    fn drop(&mut self) {
        self.0.end();
    }
}

/// What a collector tells the run about the commands of one source: each one
/// shows before it runs, so that a stuck command stays in sight, and counts as
/// a unit of the bar once answered.
pub struct CommandLog<'a> {
    lane: &'a str,
    tracker: &'a Tracker<'a>,
    ran: AtomicUsize,
}

impl CommandLog<'_> {
    /// `command` is about to run.
    pub fn starting(&self, command: &str) {
        self.tracker.lane_doing(self.lane, command);
    }

    /// The command announced last was answered.
    pub fn finished(&self) {
        self.ran.fetch_add(1, Ordering::Relaxed);
        self.tracker.advance(1, Some(self.lane));
    }
}

/// Shows each show command, or each API request of a firewall, before it runs:
/// a stuck command stays in sight.
pub struct ReportingRunner<'a, R> {
    runner: R,
    log: &'a CommandLog<'a>,
}

impl<'a, R> ReportingRunner<'a, R> {
    pub fn new(runner: R, log: &'a CommandLog<'a>) -> Self {
        ReportingRunner { runner, log }
    }
}

impl<R: CommandRunner + Send> CommandRunner for ReportingRunner<'_, R> {
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        self.log.starting(command);
        let output = self.runner.run(command).await?;
        self.log.finished();
        Ok(output)
    }
}

impl<R: Fetcher + Send> Fetcher for ReportingRunner<'_, R> {
    async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
        self.log.starting(command);
        let output = self.runner.run(command).await?;
        self.log.finished();
        Ok(output)
    }
}

/// Reads one source that is not read from a report file: a switch over SSH, a
/// firewall over its API.
pub trait Collector: Send + Sync {
    /// The state of `source`, or why it could not be collected completely.
    ///
    /// `commands` is told of each command (or request) as it runs: a runner
    /// wrapped in a [`ReportingRunner`] does it.
    fn collect(
        &self,
        source: &Source,
        commands: &CommandLog<'_>,
    ) -> impl Future<Output = Result<DeviceState, CollectionError>> + Send;
}

/// The gateway of the run, borrowed: each announcer of its calls wraps it.
struct Shared<'g, G>(&'g G);

impl<G: Gateway> Gateway for Shared<'_, G> {
    async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
        self.0.list(endpoint, filters).await
    }

    async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
        self.0.create(endpoint, payload).await
    }

    async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
        self.0.update(endpoint, id, payload).await
    }

    async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
        self.0.delete(endpoint, id).await
    }

    async fn check_write(&self, write: Write, endpoint: &str, fields: &[String]) -> Result<(), GatewayError> {
        self.0.check_write(write, endpoint, fields).await
    }
}

/// A collected source and its NetBox side.
struct Target<'s> {
    source: &'s Source,
    /// The devices the source describes, each with what NetBox holds of it.
    devices: Vec<(DesiredDevice, NbDevice)>,
    vlans: BTreeMap<u16, String>,
    members: Option<BTreeMap<u32, String>>,
    vlan_names_managed: bool,
}

/// The VLANs each source carries, by where NetBox keeps them: at the site of
/// each of its devices (the members of a stack may sit on two), or in the
/// VLAN group of that site. `homes` gives the home of each site id.
fn vlans_by_scope(
    targets: &[Target<'_>],
    homes: &BTreeMap<u64, VlanHome>,
) -> BTreeMap<VlanHome, BTreeMap<String, BTreeMap<u16, String>>> {
    let mut by_scope: BTreeMap<VlanHome, BTreeMap<String, BTreeMap<u16, String>>> = BTreeMap::new();
    for target in targets {
        for (_, snapshot) in &target.devices {
            let home = homes.get(&snapshot.site_id).cloned().unwrap_or(VlanHome::Site(snapshot.site_id));
            by_scope.entry(home).or_default().insert(target.source.name.clone(), target.vlans.clone());
        }
    }
    by_scope
}

/// Where NetBox keeps the VLANs of the site of each device of `targets`, by
/// site id, and the sources left out: a site the configuration puts in a
/// VLAN group NetBox does not hold fails the sources that have a device
/// there, each with the reason, and no other.
///
/// The group is a prerequisite, as the devices are: it is never created.
async fn vlan_homes<'s, G: Gateway>(
    targets: Vec<Target<'s>>,
    groups: &VlanGroups,
    gateway: &G,
) -> (Vec<Target<'s>>, BTreeMap<u64, VlanHome>, Vec<String>) {
    let mut homes: BTreeMap<u64, VlanHome> = BTreeMap::new();
    // Each group is read once, whatever it answers.
    let mut read: BTreeMap<String, Result<u64, String>> = BTreeMap::new();
    let mut kept = Vec::new();
    let mut failures = Vec::new();
    for target in targets {
        let mut failure = None;
        for (_, snapshot) in &target.devices {
            let Some(group) = groups.group_of(&snapshot.site) else {
                continue;
            };
            let id = match read.get(group) {
                Some(id) => id.clone(),
                None => {
                    let id = read_vlan_group(gateway, group).await.map_err(describe);
                    read.insert(group.to_owned(), id.clone());
                    id
                }
            };
            match id {
                Ok(id) => {
                    homes.insert(snapshot.site_id, VlanHome::Group { id, name: group.to_owned() });
                }
                Err(message) => failure = Some(message),
            }
        }
        match failure {
            Some(message) => failures.push(format!("{}: {message}", target.source.name)),
            None => kept.push(target),
        }
    }
    (kept, homes, failures)
}

/// What the run is made of.
struct Scope<'a> {
    inventory: &'a Inventory,
    selected: Vec<&'a Source>,
    options: &'a Options,
    limits: Limits,
}

// Every failure is typed and carries its own message.
fn describe(error: impl Display) -> String {
    error.to_string()
}

fn fail(outcome: &mut Outcome, tracker: &Tracker<'_>, message: String) {
    tracker.note(&format!("error: {message}"));
    outcome.errors.push(message);
}

/// Run `work` on every item at the same time, at most `limit` at once; the
/// outcome of each, in the order of the items.
///
/// `finished` is told of each outcome as it comes, with the number of items
/// finished so far. Nothing is spawned: dropping the future drops every work
/// still going, and an item not started yet never starts.
async fn pool<'i, I, T, Fut>(
    items: &'i [I],
    limit: usize,
    work: impl Fn(&'i I) -> Fut,
    mut finished: impl FnMut(&'i I, &T, usize),
) -> Vec<T>
where
    Fut: Future<Output = T>,
{
    let mut outcomes: Vec<Option<T>> = items.iter().map(|_| None).collect();
    let mut running = stream::iter(items.iter().enumerate())
        .map(|(index, item)| {
            let work = work(item);
            async move { (index, item, work.await) }
        })
        .buffer_unordered(limit);
    let mut number = 0;
    while let Some((index, item, outcome)) = running.next().await {
        number += 1;
        finished(item, &outcome, number);
        outcomes[index] = Some(outcome);
    }
    outcomes.into_iter().flatten().collect()
}

/// Number of units the collection of a source of this type is worth: its show
/// commands, the requests of its API for a firewall, one for a report file.
fn command_count(r#type: &str) -> usize {
    if API_TYPES.contains(&r#type) {
        omnisync_fortios::collect::command_count()
    } else {
        omnisync_cisco::collect::command_count(r#type)
    }
}

/// Collect one source: no NetBox access.
async fn collect_one<C: Collector>(
    source: &Source,
    collector: &C,
    tracker: &Tracker<'_>,
) -> Result<DeviceState, CollectionError> {
    let count = units(command_count(&source.r#type));
    tracker.lane_start(&source.name, count);
    if REPORT_TYPES.contains(&source.r#type.as_str()) {
        if let Some(report) = &source.report {
            tracker.lane_doing(&source.name, &format!("read {}", report.display()));
        }
        let state = collect_report(source);
        tracker.advance(count, Some(&source.name));
        tracker.lane_end(&source.name);
        return state;
    }
    let log = CommandLog { lane: &source.name, tracker, ran: AtomicUsize::new(0) };
    let state = collector.collect(source, &log).await.map(|state| add_description_neighbors(source, state));
    // The commands a failed source did not reach still count as done.
    tracker.advance(count.saturating_sub(units(log.ran.load(Ordering::Relaxed))), None);
    tracker.lane_end(&source.name);
    state
}

/// Collect every source at once; the outcome of each, in the order of the sources.
///
/// Nothing is spawned: an interrupt drops the collections with the run, instead
/// of waiting for sources still connecting (up to their SSH timeouts) while the
/// process holds the run lock. Dropping them is harmless: they only read, every
/// NetBox write happens later, in order, and known_hosts is replaced atomically.
async fn collect_all<C: Collector>(
    selected: &[&Source],
    collector: &C,
    tracker: &Tracker<'_>,
    limit: usize,
) -> Vec<Result<DeviceState, CollectionError>> {
    let total = selected.len();
    pool(
        selected,
        limit,
        |source| collect_one(source, collector, tracker),
        |source, outcome, number| match outcome {
            Err(error) => tracker.note(&format!("error: {}: {error}", source.name)),
            Ok(_) => tracker.step(&format!("collected {} ({number}/{total})", source.name)),
        },
    )
    .await
}

/// The virtual chassis of a stack, None for a source that is not one.
fn virtual_chassis(source: &Source) -> Option<&str> {
    source.virtual_chassis.as_deref().filter(|chassis| !chassis.is_empty())
}

/// The NetBox side of a collected source.
async fn target<'s, G: Gateway>(source: &'s Source, state: &DeviceState, gateway: &G) -> Result<Target<'s>, String> {
    let vrfs = state.ips.iter().filter_map(|ip| ip.vrf.clone()).filter(|vrf| !vrf.is_empty());
    let missing = missing_vrfs(gateway, vrfs).await.map_err(describe)?;
    if !missing.is_empty() {
        let missing: Vec<&str> = missing.iter().map(String::as_str).collect();
        return Err(format!("VRF missing in Netbox: {}", missing.join(", ")));
    }
    let mut members = None;
    let mut master = None;
    if let Some(chassis) = virtual_chassis(source) {
        members = Some(read_vc_members(gateway, chassis).await.map_err(describe)?);
        master = read_vc_master(gateway, chassis).await.map_err(describe)?;
    }
    let desired = desired_devices(source, state, members.as_ref(), master.as_deref()).map_err(describe)?;
    let mut devices = Vec::new();
    for device in desired {
        let snapshot = read_device(gateway, &device.name).await.map_err(describe)?;
        devices.push((device, snapshot));
    }
    Ok(Target { source, devices, vlans: state.vlans.clone(), members, vlan_names_managed: state.vlan_names_managed })
}

/// The NetBox side of one source, reads only, each shown in the lane of the source.
async fn read_one<'s, G: Gateway>(
    source: &'s Source,
    state: &DeviceState,
    gateway: &G,
    tracker: &Tracker<'_>,
) -> Result<Target<'s>, String> {
    tracker.lane_start(&source.name, 1);
    let reporting = ReportingGateway::new(Shared(gateway), |label: &str| tracker.lane_doing(&source.name, label));
    let read = target(source, state, &reporting).await;
    tracker.advance(1, Some(&source.name));
    tracker.lane_end(&source.name);
    read
}

/// Read the NetBox side of every collected source at once; the outcome of each.
///
/// Nothing is spawned, as for the collection: they only read, every NetBox
/// write happens later, so an interrupt need not wait for them.
async fn read_all<'s, G: Gateway>(
    collected: &[(&'s Source, DeviceState)],
    gateway: &G,
    tracker: &Tracker<'_>,
    limit: usize,
) -> Vec<Result<Target<'s>, String>> {
    let total = collected.len();
    pool(
        collected,
        limit,
        |(source, state)| read_one(source, state, gateway, tracker),
        |(source, _), _, number| tracker.step(&format!("read Netbox {} ({number}/{total})", source.name)),
    )
    .await
}

/// `read` each key from NetBox, at most `limit` at once; the outcome of each,
/// in the order of the keys.
///
/// Each read is a unit of the bar. Reads only, nothing spawned: an interrupt
/// returns at once, and no other read starts.
async fn read_pool<'k, K, T, Fut>(
    keys: &'k [K],
    limit: usize,
    read: impl Fn(&'k K) -> Fut,
    tracker: &Tracker<'_>,
) -> Vec<T>
where
    Fut: Future<Output = T>,
{
    if keys.is_empty() {
        return Vec::new();
    }
    tracker.grow(units(keys.len()));
    let counted = |key| {
        let read = read(key);
        async move {
            // Any failure is the outcome of that key only: the caller decides.
            let outcome = read.await;
            tracker.advance(1, None);
            outcome
        }
    };
    pool(keys, limit, counted, |_, _, _| {}).await
}

/// Host name announced by each stack of the inventory -> its NetBox members.
///
/// Built from the whole inventory, so that a neighbour stack resolves to its
/// members even when `--source` leaves the stack out of the run. The stacks
/// of the run were read with their NetBox side and are taken from there; the
/// others are read at once, the gateway bounding the requests in flight.
async fn stacks<G: Gateway>(
    inventory: &Inventory,
    targets: &[Target<'_>],
    gateway: &G,
    outcome: &mut Outcome,
) -> Stacks {
    let mut stacks: Stacks =
        targets.iter().filter_map(|target| Some((target.source.name.clone(), target.members.clone()?))).collect();
    let unread: Vec<(&Source, &str)> = inventory
        .sources
        .iter()
        .filter(|source| !stacks.contains_key(&source.name))
        .filter_map(|source| Some((source, virtual_chassis(source)?)))
        .collect();
    let read = join_all(unread.iter().map(|(_, chassis)| read_vc_members(gateway, chassis))).await;
    for ((source, _), members) in unread.into_iter().zip(read) {
        match members {
            Ok(members) => {
                stacks.insert(source.name.clone(), members);
            }
            // NetBox read failures of any type only cost the alias.
            Err(error) => outcome.warnings.push(format!("{}: stack members unknown: {error}", source.name)),
        }
    }
    stacks
}

// Read at write time: the master's port-channels may have been created this run.
async fn sibling_interface_ids<G: Gateway>(
    gateway: &G,
    target: &Target<'_>,
    name: &str,
) -> Result<BTreeMap<String, u64>, StateError> {
    let mut ids = BTreeMap::new();
    for (device, _) in &target.devices {
        if device.name != name {
            for (key, interface) in read_interfaces(gateway, &device.name).await? {
                ids.insert(key, interface.id);
            }
        }
    }
    Ok(ids)
}

/// The NetBox interfaces of the devices the cable step may consult, all read
/// ahead of it: the synced devices, then every device their neighbours or their
/// descriptions may resolve to. A name outside of them is not a NetBox device.
#[derive(Default)]
struct InterfaceCache {
    /// None: NetBox has no such device, or its read failed.
    found: BTreeMap<String, Option<Interfaces>>,
    /// The devices whose failed read was reported.
    unreadable: RefCell<BTreeSet<String>>,
    /// Failed reads of names read ahead, reported once the diff consults them: a
    /// candidate name never needed must not warn.
    pending: RefCell<BTreeMap<String, String>>,
    /// The warnings of the failed reads consulted since they were last taken.
    due: RefCell<Vec<String>>,
}

/// Starts each warning of `outcome` with the source of its device.
fn attribute(outcome: &mut Outcome, owners: &BTreeMap<String, String>) {
    let warnings = std::mem::take(&mut outcome.warnings);
    outcome.warnings = warnings.into_iter().map(|warning| attributed(owners, warning)).collect();
}

/// `warning`, starting with the source of the device it starts with (its
/// name, then `: `, ` ` or `:`), as the errors of a source do; unchanged when
/// it already starts with that source, or with no device of `sources`
/// (device -> source), being then about the run.
fn attributed(sources: &BTreeMap<String, String>, warning: String) -> String {
    let device = sources.keys().filter(|device| {
        warning.strip_prefix(device.as_str()).is_some_and(|rest| rest.starts_with(' ') || rest.starts_with(':'))
    });
    // The longest name wins: `2960-stack01.lab01` before a source named `2960-stack01`.
    match device.max_by_key(|device| device.len()).map(|device| &sources[device]) {
        Some(source) if !warning.strip_prefix(source.as_str()).is_some_and(|rest| rest.starts_with(": ")) => {
            format!("{source}: {warning}")
        }
        _ => warning,
    }
}

fn read_failure(name: &str, error: impl Display) -> String {
    format!("{name}: Netbox read failed: {error}")
}

impl InterfaceCache {
    /// Keep the read of `name`; gives the warning of a failure reported `now`.
    fn store(&mut self, name: &str, read: Result<Interfaces, StateError>, now: bool) -> Option<String> {
        let (interfaces, failure) = match read {
            Ok(interfaces) => (Some(interfaces), None),
            Err(StateError::NotFound(_)) => (None, None),
            // A failed read makes the device unresolved, which also shields its
            // cables from the prune; it is reported, never silently absorbed.
            Err(error) => (None, Some(error)),
        };
        // Kept under the name in lower case: NetBox reads a device caselessly.
        let key = name.to_lowercase();
        self.found.insert(key.clone(), interfaces);
        let failure = failure?;
        if now {
            self.unreadable.get_mut().insert(key);
            return Some(read_failure(name, failure));
        }
        self.pending.get_mut().insert(key, failure.to_string());
        None
    }

    /// The interfaces of `name`, None when NetBox has no such device or when
    /// its read failed: a failure not reported yet becomes due.
    fn consult(&self, name: &str) -> Option<&Interfaces> {
        let key = name.to_lowercase();
        if let Some(error) = self.pending.borrow_mut().remove(&key) {
            self.unreadable.borrow_mut().insert(key.clone());
            self.due.borrow_mut().push(read_failure(name, error));
        }
        self.found.get(&key)?.as_ref()
    }

    /// `consult`, as the cable diff and the applier take it.
    fn interfaces_of<'c>(&'c self) -> impl Fn(&str) -> Option<&'c Interfaces> + 'c {
        move |name| self.consult(name)
    }

    /// Whether the interfaces of `name` were read, without consulting them.
    fn has(&self, name: &str) -> bool {
        self.found.get(&name.to_lowercase()).is_some_and(Option::is_some)
    }

    /// Whether the read of `name` failed and was reported.
    fn unreadable(&self, name: &str) -> bool {
        self.unreadable.borrow().contains(&name.to_lowercase())
    }

    /// The warnings of the failed reads consulted since the last call.
    fn take_due(&self) -> Vec<String> {
        std::mem::take(&mut *self.due.borrow_mut())
    }
}

/// Run every source of the inventory, or those of `options.only`.
///
/// Dropping the returned future interrupts the run: every NetBox write is made
/// by this future itself, one after the other, so nothing is left half-written
/// beyond the request in flight, and the progress is ended.
pub async fn run<G: Gateway, C: Collector>(
    inventory: &Inventory,
    gateway: &G,
    collector: &C,
    options: &Options,
    progress: &dyn Progress,
) -> Outcome {
    let limits = Limits { collect: MAX_PARALLEL_SSH, netbox: MAX_PARALLEL_NETBOX };
    run_limited(inventory, gateway, collector, options, progress, limits).await
}

async fn run_limited<G: Gateway, C: Collector>(
    inventory: &Inventory,
    gateway: &G,
    collector: &C,
    options: &Options,
    progress: &dyn Progress,
    limits: Limits,
) -> Outcome {
    let started = Instant::now();
    let mut outcome = Outcome::default();
    let known: BTreeSet<&str> = inventory.sources.iter().map(|source| source.name.as_str()).collect();
    let unknown: Vec<&str> = options.only.iter().map(String::as_str).filter(|name| !known.contains(name)).collect();
    if !unknown.is_empty() {
        outcome.errors.push(format!("unknown network source(s): {}", unknown.join(", ")));
        return outcome;
    }
    let selected: Vec<&Source> = inventory
        .sources
        .iter()
        .filter(|source| options.only.is_empty() || options.only.contains(&source.name))
        .collect();
    let tracker = Tracker::new(progress);
    // Units: each show command and the NetBox read of each source, the VLAN step,
    // one per device (one per source until the stacks are split), the cables, and
    // the interface deletions when writing.
    let after_collection = 2 + u64::from(options.apply);
    let collection: u64 = selected.iter().map(|source| units(command_count(&source.r#type)) + 1).sum();
    tracker.begin(collection + units(selected.len()) + after_collection);
    let scope = Scope { inventory, selected, options, limits };
    {
        let _finish = Finish(&tracker);
        sync(&scope, gateway, collector, &tracker, &mut outcome).await;
    }
    outcome.seconds = Some(started.elapsed().as_secs_f64());
    outcome
}

/// What a diff would write, checked against NetBox without being sent: the
/// report of a dry run tells what the real run would be refused.
async fn check_planned<G: Gateway>(gateway: &G, changes: &[Change]) -> Result<(), GatewayError> {
    for (write, endpoint, fields) in planned_writes(changes) {
        gateway.check_write(write, endpoint, &fields).await?;
    }
    Ok(())
}

async fn sync<G: Gateway, C: Collector>(
    scope: &Scope<'_>,
    netbox: &G,
    collector: &C,
    tracker: &Tracker<'_>,
    outcome: &mut Outcome,
) {
    let Scope { inventory, selected, options, limits } = scope;
    let (apply, prune) = (options.apply, options.prune);
    // Every NetBox call shows in the progress while it runs; the parallel reads
    // of the sources show theirs in the lane of their source.
    let gateway = ReportingGateway::new(Shared(netbox), |label: &str| tracker.doing(label));
    let mut applier = Applier::new(&gateway).on_applied(|| tracker.advance(1, None));

    // Collection: every source at once, then their NetBox side, also at once.
    // Outcomes are taken in inventory order so that the report does not depend
    // on timing. A source that fails any step is dropped from the whole run.
    tracker.step(&format!("collect {} switch(es)", selected.len()));
    let outcomes = collect_all(selected, collector, tracker, limits.collect).await;
    let mut failures: Vec<Option<String>> = Vec::new();
    let mut collected: Vec<(&Source, DeviceState)> = Vec::new();
    for (source, outcome) in selected.iter().zip(outcomes) {
        match outcome {
            Ok(state) => {
                collected.push((source, state));
                failures.push(None);
            }
            // Any failure drops this source only.
            Err(error) => failures.push(Some(describe(error))),
        }
    }
    let mut reads = read_all(&collected, netbox, tracker, limits.netbox).await.into_iter();
    let mut targets: Vec<Target<'_>> = Vec::new();
    for (source, failure) in selected.iter().zip(failures) {
        if let Some(message) = failure {
            outcome.errors.push(format!("{}: {message}", source.name));
            // Its NetBox read unit, never run.
            tracker.advance(1, None);
            continue;
        }
        match reads.next() {
            Some(Ok(target)) => targets.push(target),
            Some(Err(message)) => fail(outcome, tracker, format!("{}: {message}", source.name)),
            None => {}
        }
    }

    // Where the VLANs of each site are kept: at the site, or in the VLAN group
    // the configuration puts it in. A group NetBox does not hold drops the
    // sources of its sites, and those only.
    let (mut targets, homes, failures) = vlan_homes(targets, &options.vlan_groups, &gateway).await;
    for failure in failures {
        fail(outcome, tracker, failure);
    }
    applier.set_vlan_homes(homes.clone());

    let devices_count: usize = targets.iter().map(|target| target.devices.len()).sum();
    // The source of each device of the run, to start its warnings with.
    let owners: BTreeMap<String, String> = targets
        .iter()
        .flat_map(|target| target.devices.iter().map(|(device, _)| (device.name.clone(), target.source.name.clone())))
        .collect();
    tracker.resize(tracker.done.load(Ordering::Relaxed) + 1 + units(devices_count) + 1 + u64::from(apply));

    // The VLANs of each site, or of its group, from every collected source.
    let by_scope = vlans_by_scope(&targets, &homes);
    let unnamed: BTreeSet<String> =
        targets.iter().filter(|target| !target.vlan_names_managed).map(|target| target.source.name.clone()).collect();
    // The device writes point at these VLANs: any failure here ends the run.
    tracker.step("VLANs");
    for (home, wanted) in &by_scope {
        let step = async {
            let (current, sited) = match home {
                VlanHome::Site(site_id) => (read_site_vlans(&gateway, *site_id).await, BTreeMap::new()),
                VlanHome::Group { id, .. } => match read_group_vlans(&gateway, *id).await {
                    Ok(read) => (Ok(read.vlans), read.sited),
                    Err(error) => (Err(error), BTreeMap::new()),
                },
            };
            let current = current.map_err(describe)?;
            // A VLAN of the group that also has a site: NetBox refuses it on a
            // port of another site. Told; neither created again nor renamed.
            let mut wanted = wanted.clone();
            for (vid, site) in &sited {
                let message = format!(
                    "{home}: VLAN {vid} also has the site {site}, and a VLAN several sites share has none: clear its site"
                );
                tracker.note(&format!("error: {message}"));
                outcome.errors.push(message);
                for vlans in wanted.values_mut() {
                    vlans.remove(vid);
                }
            }
            // A port only knows the number of its VLAN: one that is on the
            // VLAN of its site, from before the site joined the group, is
            // read as on a VLAN to rewrite, and the device step puts it on the one of the
            // group. The VLAN of the site is left where it is.
            if matches!(home, VlanHome::Group { .. }) {
                let devices = targets.iter_mut().flat_map(|target| target.devices.iter_mut());
                for (_, snapshot) in devices.filter(|(_, snapshot)| homes.get(&snapshot.site_id) == Some(home)) {
                    mark_foreign_vlans(snapshot, &current);
                }
            }
            let diff = diff_vlans(home, &wanted, &current, &unnamed);
            let changes = diff.changes;
            outcome.changes.extend(changes.iter().cloned());
            outcome.warnings.extend(diff.warnings);
            // A VLAN NetBox would refuse: left out, so that the others are
            // written; the ports that need it fail with their device.
            for error in diff.errors {
                let message = format!("{home}: {error}");
                tracker.note(&format!("error: {message}"));
                outcome.errors.push(message);
            }
            if apply && !changes.is_empty() {
                let writes = tracker.writing(changes.len(), applier.applied);
                let written = applier.apply_vlans(&changes).await;
                tracker.written(writes, applier.applied);
                written.map_err(describe)?;
            } else if !apply {
                check_planned(&gateway, &changes).await.map_err(describe)?;
            }
            Ok::<(), String>(())
        };
        if let Err(message) = step.await {
            fail(outcome, tracker, format!("{home} VLANs: {message}"));
            outcome.applied = applier.applied;
            attribute(outcome, &owners);
            return;
        }
    }
    tracker.advance(1, None);

    // Devices.
    let mut synced: BTreeSet<String> = BTreeSet::new();
    let mut deletions: Vec<Change> = Vec::new();
    let verb = if apply { "write" } else { "diff" };
    let mut number = 0;
    for target in &targets {
        for (device, current) in &target.devices {
            number += 1;
            tracker.step(&format!("{verb} {} ({number}/{devices_count})", device.name));
            let started = Instant::now();
            let written = applier.applied;
            let step = async {
                let hosts = device.ips.iter().map(|ip| ip.address.split('/').next().unwrap_or_default().to_owned());
                let ips_by_host = read_ips_by_host(&gateway, hosts).await.map_err(describe)?;
                let vrfs = device.ips.iter().map(|ip| ip.vrf.clone());
                let unique_tables = unique_ip_tables(&gateway, vrfs).await.map_err(describe)?;
                let (changes, warnings) = diff_device(device, current, &ips_by_host, prune, &unique_tables);
                outcome.changes.extend(changes.iter().cloned());
                outcome.warnings.extend(warnings);
                let count = changes.len();
                let (gone, main): (Vec<Change>, Vec<Change>) = changes
                    .into_iter()
                    .partition(|change| change.kind == "interface" && change.action == Action::Delete);
                if apply {
                    let lag_ids = match target.members {
                        Some(_) => sibling_interface_ids(&gateway, target, &device.name).await.map_err(describe)?,
                        None => BTreeMap::new(),
                    };
                    let writes = tracker.writing(main.len(), applier.applied);
                    let result = applier.apply_device(current, &main, &lag_ids).await;
                    tracker.written(writes, applier.applied);
                    result.map_err(describe)?;
                    tracker.note(&format!(
                        "{}: {} change(s) written in {} s",
                        device.name,
                        applier.applied - written,
                        started.elapsed().as_secs_f64().round_ties_even()
                    ));
                } else {
                    check_planned(&gateway, &main).await.map_err(describe)?;
                    tracker.note(&format!("{}: {count} change(s) to write", device.name));
                }
                Ok::<Vec<Change>, String>(gone)
            };
            match step.await {
                // One device failing, for any reason, must not stop the report or the others.
                Err(message) => {
                    // The source first, as every error of a source: the
                    // monitoring knows a failure by it. A member of a stack or
                    // a peer of a cluster is named after it, for the operator.
                    let named = if device.name == target.source.name {
                        format!("{}: {message}", device.name)
                    } else {
                        format!("{}: {}: {message}", target.source.name, device.name)
                    };
                    fail(outcome, tracker, named);
                    tracker.advance(1, None);
                }
                Ok(gone) => {
                    tracker.advance(1, None);
                    synced.insert(device.name.clone());
                    deletions.extend(gone);
                }
            }
        }
    }

    // Cables, read after the device writes so that new interfaces are visible.
    tracker.step("cables");
    let stacks = stacks(inventory, &targets, &gateway, outcome).await;
    let domains: Vec<&str> = inventory.domains.iter().map(String::as_str).collect();
    let aliases = &inventory.aliases;
    let devices = || {
        targets
            .iter()
            .flat_map(|target| target.devices.iter().map(move |(device, snapshot)| (target, device, snapshot)))
    };
    // One parallel read ahead of the diff: the synced devices, then every device
    // their neighbours may resolve to.
    let mut neighbors: BTreeMap<String, Vec<Neighbor>> = devices()
        .filter(|(_, device, _)| synced.contains(&device.name))
        .map(|(_, device, _)| (device.name.clone(), device.neighbors.clone()))
        .collect();
    // The devices the port descriptions name, on the ports where LLDP or CDP also
    // speaks: compared with what the neighbour announces, after the cables.
    let mut claims: Vec<(&DesiredDevice, Vec<Neighbor>)> = Vec::new();
    for (target, device, _) in devices() {
        let Some(pattern) = &target.source.neighbor_pattern else {
            continue;
        };
        if !synced.contains(&device.name) {
            continue;
        }
        let spoken: BTreeSet<String> = device
            .neighbors
            .iter()
            .filter(|neighbor| neighbor.protocol != DESCRIPTION && neighbor.announced_name().is_some())
            .map(|neighbor| interface_key(&neighbor.local_interface))
            .collect();
        let told =
            neighbors_from_descriptions(&device.interfaces, pattern, &target.source.neighbor_suffix, &BTreeSet::new());
        let claimed = told.into_iter().filter(|claim| spoken.contains(&interface_key(&claim.local_interface)));
        claims.push((device, claimed.collect()));
    }
    let described = claims
        .iter()
        .flat_map(|(_, claimed)| claimed)
        .flat_map(|claim| name_family(&claim.remote_device, &domains, aliases));
    let names = synced.len();
    let mut keys: Vec<String> = synced.iter().cloned().collect();
    // The hosts that hear a switch: the far end of the cables they tell.
    let hosts: Vec<String> =
        options.heard.iter().map(|heard| heard.host.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let lookups = lookup_names(&neighbors, &stacks, &domains, aliases).into_iter().chain(described);
    for name in lookups.chain(hosts.iter().cloned()) {
        if !keys.contains(&name) {
            keys.push(name);
        }
    }
    let interface_reads = read_pool(&keys, limits.netbox, |name| read_interfaces(&gateway, name), tracker).await;
    let mut cache = InterfaceCache::default();
    for (index, (name, read)) in keys.iter().zip(interface_reads).enumerate() {
        // The synced devices are all consulted: their failures are reported now, in order.
        outcome.warnings.extend(cache.store(name, read, index < names));
    }
    // A synced device whose interfaces cannot be read now is left out of the cable
    // step: without its interfaces its ends would look free and its cables prunable.
    let cable_synced: BTreeSet<String> = synced.iter().filter(|name| cache.has(name)).cloned().collect();
    neighbors.retain(|name, _| cable_synced.contains(name));
    let device_ids: Vec<u64> = devices()
        .filter(|(_, device, _)| cable_synced.contains(&device.name))
        .map(|(_, _, snapshot)| snapshot.id)
        .collect();
    let descriptions: Descriptions = devices()
        .map(|(_, device, _)| {
            let described = device.interfaces.iter().filter_map(|(name, interface)| {
                let description = interface.description.as_deref().filter(|description| !description.is_empty())?;
                Some((interface_key(name), description.to_owned()))
            });
            (device.name.clone(), described.collect())
        })
        .collect();
    let interfaces_of = cache.interfaces_of();
    let step = async {
        let per_device = read_pool(&device_ids, limits.netbox, |id| read_device_cables(&gateway, *id), tracker).await;
        // One device's cables unread: the cable step fails, as a sequential read would.
        let cables = per_device.into_iter().collect::<Result<Vec<_>, _>>().map_err(describe)?;
        // What the hosts hear, on the ports of the synced switches. A blade hears
        // what the switches of its chassis repeat: the device each host is
        // installed in is read, and a host whose one cannot be read is left out.
        if !options.heard.is_empty() {
            let parents = read_pool(&hosts, limits.netbox, |name| read_parent_device(&gateway, name), tracker).await;
            let mut blades: BTreeSet<String> = BTreeSet::new();
            let mut unknown: BTreeSet<&str> = BTreeSet::new();
            for (host, parent) in hosts.iter().zip(parents) {
                match parent {
                    Ok(Some(_)) => {
                        blades.insert(host.clone());
                    }
                    // Not in NetBox: its cards are not either, which the merge says.
                    Ok(None) | Err(StateError::NotFound(_)) => {}
                    Err(error) => {
                        outcome.warnings.push(format!("{host}: what its cards hear is left out: {error}"));
                        unknown.insert(host);
                    }
                }
            }
            let heard: Vec<Heard> =
                options.heard.iter().filter(|heard| !unknown.contains(heard.host.as_str())).cloned().collect();
            let in_netbox = |host: &str, card: &str| {
                interfaces_of(host).is_some_and(|interfaces| interfaces.contains_key(&interface_key(card)))
            };
            let context =
                HeardContext { stacks: &stacks, domains: &domains, aliases, blades: &blades, in_netbox: &in_netbox };
            outcome.warnings.extend(merge_heard(&mut neighbors, &heard, &context));
        }
        let down: BTreeSet<(String, String)> = devices()
            .flat_map(|(_, device, _)| {
                let down = device.interfaces.iter().filter(|(_, interface)| interface.link_up == Some(false));
                down.map(|(name, _)| (device.name.clone(), interface_key(name)))
            })
            .collect();
        // A report shows no link, and a firewall's neighbours are not read:
        // neither can tell that a cable is gone.
        let unpruned: BTreeSet<String> = devices()
            .filter(|(target, _, _)| {
                let r#type = target.source.r#type.as_str();
                REPORT_TYPES.contains(&r#type) || API_TYPES.contains(&r#type)
            })
            .map(|(_, device, _)| device.name.clone())
            .collect();
        let known = CableOptions {
            stacks: &stacks,
            domains: &domains,
            synced: &cable_synced,
            prune,
            down: &down,
            aliases,
            unpruned: &unpruned,
            // Live: the failed read of a name read ahead is known once consulted.
            unreadable: &|name| cache.unreadable(name),
            // The source's descriptions: what is plugged in, where a neighbour cannot say.
            descriptions: Some(&descriptions),
        };
        let (changes, warnings) = diff_cables(&neighbors, &interfaces_of, &combine_cables(cables), &known);
        outcome.warnings.extend(cache.take_due());
        outcome.changes.extend(changes.iter().cloned());
        outcome.warnings.extend(warnings);
        if apply {
            let writes = tracker.writing(changes.len(), applier.applied);
            let written = applier.apply_cables(&changes, &interfaces_of).await;
            tracker.written(writes, applier.applied);
            outcome.warnings.extend(cache.take_due());
            written.map_err(describe)?;
        } else {
            check_planned(&gateway, &changes).await.map_err(describe)?;
        }
        Ok::<(), String>(())
    };
    // The report is always printed, whatever the cable step raised.
    if let Err(message) = step.await {
        fail(outcome, tracker, format!("cables: {message}"));
    }
    let label = port_labeller(Some(&descriptions));
    for (device, claimed) in &claims {
        let mismatches = description_mismatches(
            &device.name,
            claimed,
            &device.neighbors,
            &domains,
            aliases,
            &|name| cache.consult(name).is_some(),
            &label,
        );
        outcome.warnings.extend(cache.take_due());
        outcome.warnings.extend(mismatches);
    }
    tracker.advance(1, None);
    // Interfaces go last: their IPs were re-attached above. A pruned interface is
    // gone from the source whatever happened to the cables, so a cable failure does
    // not keep it.
    if apply {
        tracker.step("interface deletions");
        let writes = tracker.writing(deletions.len(), applier.applied);
        let written = applier.apply_interface_deletions(&deletions).await;
        tracker.written(writes, applier.applied);
        if let Err(error) = written {
            fail(outcome, tracker, format!("interface deletions: {error}"));
        }
        tracker.advance(1, None);
    }
    outcome.applied = applier.applied;
    attribute(outcome, &owners);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::future::pending;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use futures::FutureExt;
    use futures::future::BoxFuture;
    use omnisync_cisco::collect::collect;
    use omnisync_cisco::commands::Platform;
    use omnisync_core::change::Change;
    use omnisync_core::gateway::filters;
    use omnisync_core::network::inventory::{Kind, Secret, Wanted};
    use omnisync_core::progress::NullProgress;
    use omnisync_core::{Action, Filters, GatewayError, Row};
    use omnisync_netbox::testing::FakeGateway;
    use regex::Regex;
    use serde_json::{Value, json};
    use tokio::sync::{Barrier, Notify};
    use tokio::time::timeout;

    use super::*;

    const NXOS_I2: &str = "nxos_i2";
    const NXOS_I4: &str = "nxos_i4";
    const IOS: &str = "ios";
    const NIPPER: &str = "nipper";

    /// The recorded outputs of the Cisco crate.
    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../cisco/tests/fixtures")
    }

    /// Command runner that answers from the recorded switch outputs.
    struct FixtureRunner {
        directory: &'static str,
    }

    impl CommandRunner for FixtureRunner {
        async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
            // Named like the probe files.
            let name: String = command.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
            let path = fixtures().join(self.directory).join(format!("{name}.txt"));
            fs::read_to_string(&path).map_err(|error| CollectionError(format!("{}: {error}", path.display())))
        }
    }

    /// What a test makes a switch wait on, or fail with.
    type Gate = Arc<dyn Fn() -> BoxFuture<'static, Result<(), CollectionError>> + Send + Sync>;

    fn gate<F, Fut>(wait: F) -> Gate
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), CollectionError>> + Send + 'static,
    {
        Arc::new(move || wait().boxed())
    }

    /// How one switch answers: from which recorded outputs, after which waits.
    struct Answer {
        directory: &'static str,
        /// Awaited before the first command: the connection.
        connect: Option<Gate>,
        /// Awaited by the first command.
        first_command: Option<Gate>,
    }

    impl Answer {
        fn from(directory: &'static str) -> Self {
            Answer { directory, connect: None, first_command: None }
        }

        fn gated(directory: &'static str, first_command: Gate) -> Self {
            Answer { first_command: Some(first_command), ..Answer::from(directory) }
        }
    }

    type Started = Mutex<BTreeMap<String, Vec<String>>>;

    /// Answers from the fixtures, but its first command waits on `gate`.
    struct GatedRunner<'c> {
        fixtures: FixtureRunner,
        gate: Option<Gate>,
        name: String,
        started: &'c Started,
    }

    impl CommandRunner for GatedRunner<'_> {
        async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
            self.started.lock().unwrap().entry(self.name.clone()).or_default().push(command.to_owned());
            if let Some(gate) = self.gate.take() {
                gate().await?;
            }
            self.fixtures.run(command).await
        }
    }

    type AnswerOf = Box<dyn Fn(&Source) -> Result<Answer, CollectionError> + Send + Sync>;

    /// The switches of a test, read from the recorded outputs: no SSH.
    struct Switches {
        answer: AnswerOf,
        /// The switches a connection was asked for, in order.
        connections: Mutex<Vec<String>>,
        /// The switches whose connection came through, in order.
        connected: Mutex<Vec<String>>,
        /// The commands each switch started, in order.
        started: Started,
    }

    impl Switches {
        fn new(answer: impl Fn(&Source) -> Result<Answer, CollectionError> + Send + Sync + 'static) -> Self {
            Switches {
                answer: Box::new(answer),
                connections: Mutex::new(Vec::new()),
                connected: Mutex::new(Vec::new()),
                started: Mutex::new(BTreeMap::new()),
            }
        }

        fn fixtures(directory: &'static str) -> Self {
            Switches::new(move |_| Ok(Answer::from(directory)))
        }

        /// nexus01 answers with the I2 outputs, any other switch with the I4 ones.
        fn two_fixtures() -> Self {
            Switches::new(|source| Ok(Answer::from(by_name(source))))
        }

        fn started_by(&self, name: &str) -> Vec<String> {
            self.started.lock().unwrap().get(name).cloned().unwrap_or_default()
        }
    }

    fn by_name(source: &Source) -> &'static str {
        if source.name == "nexus01.lab01" { NXOS_I2 } else { NXOS_I4 }
    }

    impl Collector for Switches {
        async fn collect(&self, source: &Source, commands: &CommandLog<'_>) -> Result<DeviceState, CollectionError> {
            self.connections.lock().unwrap().push(source.name.clone());
            let answer = (self.answer)(source)?;
            if let Some(connect) = &answer.connect {
                connect().await?;
            }
            self.connected.lock().unwrap().push(source.name.clone());
            let platform = Platform::from_type(&source.r#type)
                .ok_or_else(|| CollectionError(format!("{} is not read over SSH", source.r#type)))?;
            let runner = GatedRunner {
                fixtures: FixtureRunner { directory: answer.directory },
                gate: answer.first_command,
                name: source.name.clone(),
                started: &self.started,
            };
            collect(platform, &mut ReportingRunner::new(runner, commands)).await
        }
    }

    /// A report switch is read from its file: asking for a connection is a failure.
    struct NoSsh;

    impl Collector for NoSsh {
        async fn collect(&self, source: &Source, _commands: &CommandLog<'_>) -> Result<DeviceState, CollectionError> {
            panic!("{} is read from its report, not over SSH", source.name)
        }
    }

    /// Fetcher that answers from the recorded firewall answers of the FortiOS crate.
    struct FixtureFetcher;

    impl Fetcher for FixtureFetcher {
        async fn run(&mut self, command: &str) -> Result<String, CollectionError> {
            // Named like the probe files.
            let name: String = command.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../fortios/tests/fixtures/7.4.13")
                .join(format!("{name}.txt"));
            fs::read_to_string(&path).map_err(|error| CollectionError(format!("{}: {error}", path.display())))
        }
    }

    /// The firewalls of a test, read from the recorded API answers (those of the
    /// cluster LABLU-FWL01 / LABBS-FWL01): no connection.
    struct Firewalls;

    impl Collector for Firewalls {
        async fn collect(&self, source: &Source, commands: &CommandLog<'_>) -> Result<DeviceState, CollectionError> {
            omnisync_fortios::collect::collect(&mut ReportingRunner::new(FixtureFetcher, commands), source).await
        }
    }

    type ListHook = Box<dyn Fn(&str, &Filters) -> BoxFuture<'static, Result<(), GatewayError>> + Send + Sync>;

    /// A NetBox whose reads go through a hook first, and which may refuse the
    /// creations of one endpoint.
    struct Hooked {
        inner: FakeGateway,
        on_list: ListHook,
        refused: Option<(&'static str, &'static str)>,
        /// A field NetBox does not take: the check of a write refuses it.
        dropped: Option<&'static str>,
    }

    impl Hooked {
        fn new<F>(inner: FakeGateway, on_list: F) -> Self
        where
            F: Fn(&str, &Filters) -> BoxFuture<'static, Result<(), GatewayError>> + Send + Sync + 'static,
        {
            Hooked { inner, on_list: Box::new(on_list), refused: None, dropped: None }
        }

        /// Fails the reads `failing` gives a message for.
        fn failing_reads<F>(inner: FakeGateway, failing: F) -> Self
        where
            F: Fn(&str, &Filters) -> Option<&'static str> + Send + Sync + 'static,
        {
            Hooked::new(inner, move |endpoint, filters| {
                let outcome = failing(endpoint, filters).map_or(Ok(()), |message| Err(request(message)));
                async move { outcome }.boxed()
            })
        }

        /// Refuses every creation on `endpoint` with `message`.
        fn refusing(inner: FakeGateway, endpoint: &'static str, message: &'static str) -> Self {
            Hooked { refused: Some((endpoint, message)), ..Hooked::failing_reads(inner, |_, _| None) }
        }
    }

    impl Gateway for Hooked {
        async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
            (self.on_list)(endpoint, filters).await?;
            self.inner.list(endpoint, filters).await
        }

        async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
            match self.refused {
                Some((refused, message)) if refused == endpoint => Err(request(message)),
                _ => self.inner.create(endpoint, payload).await,
            }
        }

        async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
            self.inner.update(endpoint, id, payload).await
        }

        async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
            self.inner.delete(endpoint, id).await
        }

        async fn check_write(&self, write: Write, endpoint: &str, fields: &[String]) -> Result<(), GatewayError> {
            match fields.iter().find(|field| Some(field.as_str()) == self.dropped) {
                Some(field) => Err(GatewayError::UnknownField { endpoint: endpoint.to_owned(), field: field.clone() }),
                None => self.inner.check_write(write, endpoint, fields).await,
            }
        }
    }

    fn request(message: &str) -> GatewayError {
        GatewayError::Request(message.to_owned())
    }

    fn filter<'f>(filters: &'f Filters, key: &str) -> Option<&'f str> {
        filters.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str())
    }

    #[derive(Debug, Clone, PartialEq)]
    enum Event {
        Begin(u64),
        Resize(u64),
        Step(String),
        Doing(String),
        Advance(Option<String>),
        LaneStart(String, u64),
        LaneDoing(String, String),
        LaneEnd(String),
        Note(String),
        End,
    }

    fn step(label: &str) -> Event {
        Event::Step(label.to_owned())
    }

    type OnStep = Box<dyn Fn(&str) + Send + Sync>;

    #[derive(Default)]
    struct Recording {
        events: Mutex<Vec<Event>>,
        /// Called with the label of each step, after it is recorded.
        on_step: Option<OnStep>,
    }

    impl Recording {
        fn watching(on_step: impl Fn(&str) + Send + Sync + 'static) -> Self {
            Recording { events: Mutex::new(Vec::new()), on_step: Some(Box::new(on_step)) }
        }

        fn record(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }

        fn events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }

        fn total(&self) -> u64 {
            let mut sizes = self.events().into_iter().filter_map(|event| match event {
                Event::Begin(total) | Event::Resize(total) => Some(total),
                _ => None,
            });
            sizes.next_back().expect("the run began")
        }

        fn advanced(&self) -> u64 {
            self.events().iter().filter(|event| matches!(event, Event::Advance(_))).count() as u64
        }

        fn steps(&self) -> Vec<String> {
            self.events()
                .into_iter()
                .filter_map(|event| match event {
                    Event::Step(label) => Some(label),
                    _ => None,
                })
                .collect()
        }

        fn doing(&self) -> Vec<String> {
            doing(&self.events())
        }

        fn notes(&self) -> Vec<String> {
            self.events()
                .into_iter()
                .filter_map(|event| match event {
                    Event::Note(text) => Some(text),
                    _ => None,
                })
                .collect()
        }
    }

    fn doing(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Doing(label) => Some(label.clone()),
                _ => None,
            })
            .collect()
    }

    impl Progress for Recording {
        fn begin(&self, total: u64) {
            self.record(Event::Begin(total));
        }

        fn resize(&self, total: u64) {
            self.record(Event::Resize(total));
        }

        fn step(&self, label: &str) {
            self.record(step(label));
            if let Some(on_step) = &self.on_step {
                on_step(label);
            }
        }

        fn doing(&self, label: &str) {
            self.record(Event::Doing(label.to_owned()));
        }

        fn advance(&self, lane: Option<&str>) {
            self.record(Event::Advance(lane.map(str::to_owned)));
        }

        fn lane_start(&self, lane: &str, total: u64) {
            self.record(Event::LaneStart(lane.to_owned(), total));
        }

        fn lane_doing(&self, lane: &str, label: &str) {
            self.record(Event::LaneDoing(lane.to_owned(), label.to_owned()));
        }

        fn lane_end(&self, lane: &str) {
            self.record(Event::LaneEnd(lane.to_owned()));
        }

        fn note(&self, text: &str) {
            self.record(Event::Note(text.to_owned()));
        }

        fn end(&self) {
            self.record(Event::End);
        }
    }

    fn switch(name: &str, host: &str, r#type: &str) -> Source {
        Source {
            username: "user".to_owned(),
            password: Some(Wanted::Held(Secret::new("secret"))),
            ..Source::new(name, Kind::Switch, r#type, host)
        }
    }

    fn nexus01() -> Source {
        switch("nexus01.lab01", "192.0.2.239", "nxos")
    }

    fn nexus03() -> Source {
        switch("nexus03.lab01", "192.0.2.242", "nxos")
    }

    fn inventory(sources: Vec<Source>, domains: &[&str]) -> Inventory {
        Inventory {
            sources,
            domains: domains.iter().map(|domain| (*domain).to_owned()).collect(),
            netbox_url: "https://netbox.example".to_owned(),
            netbox_token: Wanted::Held(Secret::new("token")),
            aliases: BTreeMap::new(),
        }
    }

    /// nexus01 alone.
    fn nexus_inventory() -> Inventory {
        inventory(vec![nexus01()], &["switch.example.com"])
    }

    fn options(apply: bool, prune: bool) -> Options {
        Options { apply, prune, only: BTreeSet::new(), ..Options::default() }
    }

    async fn sync<G: Gateway, C: Collector>(
        inventory: &Inventory,
        netbox: &G,
        collector: &C,
        apply: bool,
        prune: bool,
    ) -> Outcome {
        run(inventory, netbox, collector, &options(apply, prune), &NullProgress).await
    }

    fn add_vrfs(netbox: &FakeGateway) {
        for vrf in ["management", "mgmt-sw"] {
            netbox.add("ipam.vrfs", json!({"name": vrf}));
        }
    }

    fn add_device(netbox: &FakeGateway, name: &str, site: u64) -> u64 {
        netbox.add("dcim.devices", json!({"name": name, "site": site, "serial": ""}))
    }

    fn add_interface(netbox: &FakeGateway, device: u64, name: &str, r#type: &str) -> u64 {
        netbox.add("dcim.interfaces", json!({"device": device, "name": name, "type": r#type}))
    }

    fn add_cable(netbox: &FakeGateway, a: u64, b: u64) -> u64 {
        netbox.add(
            "dcim.cables",
            json!({
                "a_terminations": [{"object_type": "dcim.interface", "object_id": a}],
                "b_terminations": [{"object_type": "dcim.interface", "object_id": b}],
                "status": "connected",
            }),
        )
    }

    /// nexus01 as documented by hand: its address on a fictitious `admin` port.
    fn netbox_with(with_vrfs: bool) -> FakeGateway {
        let netbox = FakeGateway::new();
        if with_vrfs {
            add_vrfs(&netbox);
        }
        let device = add_device(&netbox, "nexus01.lab01", 12);
        let admin = add_interface(&netbox, device, "admin", "virtual");
        let ip = netbox.add(
            "ipam.ip_addresses",
            json!({
                "address": "192.0.2.239/24",
                "vrf": null,
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": admin,
                "status": "active",
            }),
        );
        netbox.set("dcim.devices", device, "primary_ip4", json!(ip));
        netbox
    }

    fn netbox() -> FakeGateway {
        netbox_with(true)
    }

    fn id_of(netbox: &FakeGateway, endpoint: &str, name: &str) -> u64 {
        netbox.find(endpoint, "name", &json!(name)).unwrap_or_else(|| panic!("no {endpoint} named {name}"))
    }

    /// Every record of an endpoint, as the API renders it.
    async fn all(netbox: &FakeGateway, endpoint: &str) -> Vec<Row> {
        netbox.list(endpoint, &filters::<&str, &str>([])).await.expect("the fake lists")
    }

    /// The interfaces of a device: name -> id.
    async fn ports(netbox: &FakeGateway, device: u64) -> BTreeMap<String, u64> {
        let rows = netbox.list("dcim.interfaces", &filters([("device_id", device)])).await.expect("the fake lists");
        rows.iter().map(|row| (row["name"].as_str().unwrap().to_owned(), row["id"].as_u64().unwrap())).collect()
    }

    /// The two ends of every cable.
    async fn cabled(netbox: &FakeGateway) -> Vec<BTreeSet<u64>> {
        all(netbox, "dcim.cables")
            .await
            .iter()
            .map(|cable| {
                ["a_terminations", "b_terminations"]
                    .iter()
                    .flat_map(|side| cable[*side].as_array().unwrap())
                    .map(|end| end["object_id"].as_u64().unwrap())
                    .collect()
            })
            .collect()
    }

    fn of_kind<'o>(outcome: &'o Outcome, kind: &str) -> Vec<&'o Change> {
        outcome.changes.iter().filter(|change| change.kind == kind).collect()
    }

    fn cable_deletions(outcome: &Outcome) -> Vec<&Change> {
        of_kind(outcome, "cable").into_iter().filter(|change| change.action == Action::Delete).collect()
    }

    fn cable_keys(outcome: &Outcome) -> Vec<&str> {
        of_kind(outcome, "cable").into_iter().map(|change| change.key.as_str()).collect()
    }

    fn containing<'o>(lines: &'o [String], part: &str) -> Vec<&'o String> {
        lines.iter().filter(|line| line.contains(part)).collect()
    }

    #[tokio::test]
    async fn apply_then_diff_is_empty() {
        let netbox = netbox();
        let switches = Switches::fixtures(NXOS_I2);
        let first = sync(&nexus_inventory(), &netbox, &switches, true, true).await;
        assert_eq!(first.errors, [] as [&str; 0]);
        assert_eq!(first.applied, first.changes.len());
        let second = sync(&nexus_inventory(), &netbox, &switches, false, true).await;
        assert_eq!(second.changes, []);
        assert_eq!(second.errors, [] as [&str; 0]);
    }

    #[tokio::test]
    async fn management_ip_keeps_its_object() {
        let netbox = netbox();
        let ip_id = all(&netbox, "ipam.ip_addresses").await[0]["id"].as_u64().unwrap();
        sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), true, true).await;
        let record = netbox.row("ipam.ip_addresses", ip_id).expect("the address is kept");
        let interface = netbox.row("dcim.interfaces", record["assigned_object_id"].as_u64().unwrap()).unwrap();
        assert_eq!(interface["name"], json!("Vlan2800"));
        let device = netbox.row("dcim.devices", id_of(&netbox, "dcim.devices", "nexus01.lab01")).unwrap();
        assert_eq!(device["primary_ip4"], json!(ip_id));
        assert_eq!(netbox.find("dcim.interfaces", "name", &json!("admin")), None);
    }

    #[tokio::test]
    async fn diff_mode_writes_nothing() {
        let netbox = netbox();
        let outcome = sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), false, true).await;
        assert!(!outcome.changes.is_empty());
        assert_eq!(netbox.writes(), []);
    }

    // A diff writes nothing, yet tells what the real run would be refused:
    // the fields of the writes it would make are checked against NetBox.
    #[tokio::test]
    async fn diff_mode_checks_the_fields_of_the_writes_it_would_make() {
        let netbox = Hooked { dropped: Some("description"), ..Hooked::failing_reads(netbox(), |_, _| None) };
        let outcome = sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), false, true).await;
        assert_eq!(
            outcome.errors,
            ["nexus01.lab01: unknown field description on dcim.interfaces: NetBox would drop it"]
        );
        assert_eq!(netbox.inner.writes(), []);
        // Taken by NetBox, the same diff says nothing more than its changes.
        let netbox = Hooked::failing_reads(super::tests::netbox(), |_, _| None);
        let outcome = sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), false, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert!(!outcome.changes.is_empty());
    }

    #[tokio::test]
    async fn missing_vrf_skips_the_switch() {
        let netbox = netbox_with(false);
        let outcome = sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), true, true).await;
        assert_eq!(outcome.changes, []);
        assert_eq!(outcome.errors, ["nexus01.lab01: VRF missing in Netbox: management, mgmt-sw"]);
        assert_eq!(netbox.writes(), []);
    }

    #[tokio::test]
    async fn unknown_device_filter() {
        let only = Options { only: BTreeSet::from(["nexus09.lab01".to_owned()]), ..options(false, false) };
        let outcome = run(&nexus_inventory(), &netbox(), &Switches::fixtures(NXOS_I2), &only, &NullProgress).await;
        // Switches, routers and firewalls alike: the message names network sources.
        assert_eq!(outcome.errors, ["unknown network source(s): nexus09.lab01"]);
    }

    #[tokio::test]
    async fn rerun_after_failure_converges() {
        let netbox = netbox();
        let switches = Switches::fixtures(NXOS_I2);
        // 30 VLAN creations come first; the 40th write falls in the middle of the
        // interface writes, between an interface creation and its MAC address.
        netbox.fail_after(Some(40));
        let failed = sync(&nexus_inventory(), &netbox, &switches, true, true).await;
        assert!(!failed.errors.is_empty());
        netbox.fail_after(None);
        sync(&nexus_inventory(), &netbox, &switches, true, true).await;
        assert_eq!(sync(&nexus_inventory(), &netbox, &switches, false, true).await.changes, []);
    }

    fn stack_netbox() -> FakeGateway {
        let netbox = FakeGateway::new();
        let chassis = netbox.add("dcim.virtual_chassis", json!({"name": "2960-stack"}));
        let master = netbox.add(
            "dcim.devices",
            json!({
                "name": "2960-stack01.lab01", "site": 12, "serial": "", "virtual_chassis": chassis, "vc_position": 1,
            }),
        );
        netbox.set("dcim.virtual_chassis", chassis, "master", json!(master));
        netbox
    }

    // The members of a stack may sit on two sites: the VLANs the stack carries
    // are those of each of them, not of the first member alone.
    #[test]
    fn the_vlans_of_a_source_go_to_the_site_of_each_of_its_devices() {
        let stack = switch("stack.lab01", "192.0.2.251", "ios");
        let member = |id: u64, name: &str, site_id: u64| {
            let nb = NbDevice {
                id,
                name: name.to_owned(),
                site_id,
                site: String::new(),
                serial: String::new(),
                primary_ip4: None,
                interfaces: BTreeMap::new(),
                ips: Vec::new(),
            };
            (DesiredDevice::new(name, None), nb)
        };
        let vlans = BTreeMap::from([(26, "PPE".to_owned())]);
        let target = Target {
            source: &stack,
            devices: vec![member(1, "stack01.lab01", 12), member(2, "stack02.lab01", 13)],
            vlans: vlans.clone(),
            members: None,
            vlan_names_managed: true,
        };
        let wanted = BTreeMap::from([("stack.lab01".to_owned(), vlans)]);
        let by_site = vlans_by_scope(std::slice::from_ref(&target), &BTreeMap::new());
        assert_eq!(
            by_site,
            BTreeMap::from([(VlanHome::Site(12), wanted.clone()), (VlanHome::Site(13), wanted.clone())])
        );
        // The site of the second member keeps its VLANs in a group: they go there, those of the first to its site.
        let east = VlanHome::Group { id: 7, name: "East".to_owned() };
        let by_scope = vlans_by_scope(&[target], &BTreeMap::from([(13, east.clone())]));
        assert_eq!(by_scope, BTreeMap::from([(VlanHome::Site(12), wanted.clone()), (east, wanted)]));
    }

    // NetBox reads a device caselessly: the interfaces read under one spelling
    // are those of the device under any other.
    #[test]
    fn the_interfaces_of_a_device_are_found_whatever_the_case_of_its_name() {
        let mut cache = InterfaceCache::default();
        assert_eq!(cache.store("sw02", Ok(Interfaces::new()), true), None);
        assert!(cache.has("SW02"));
        assert_eq!(cache.interfaces_of()("SW02"), Some(&Interfaces::new()));
    }

    #[tokio::test]
    async fn stack_is_synced_through_its_virtual_chassis() {
        let netbox = stack_netbox();
        let stack = Source {
            virtual_chassis: Some("2960-stack".to_owned()),
            ..switch("2960-stack.lab01", "192.0.2.251", "ios")
        };
        let inventory = inventory(vec![stack], &[]);
        let switches = Switches::fixtures(IOS);
        let first = sync(&inventory, &netbox, &switches, true, true).await;
        assert_eq!(first.errors, [] as [&str; 0]);
        assert_eq!(sync(&inventory, &netbox, &switches, false, true).await.changes, []);
    }

    // The members of a stack of the run are read once, with its NetBox side:
    // the cable step takes them from there rather than asking NetBox again.
    #[tokio::test]
    async fn the_members_of_a_stack_of_the_run_are_read_once() {
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        let netbox = Hooked::failing_reads(stack_netbox(), move |endpoint, _| {
            if endpoint == "dcim.virtual_chassis" {
                counted.fetch_add(1, Ordering::Relaxed);
            }
            None
        });
        let stack = Source {
            virtual_chassis: Some("2960-stack".to_owned()),
            ..switch("2960-stack.lab01", "192.0.2.251", "ios")
        };
        let outcome = sync(&inventory(vec![stack], &[]), &netbox, &Switches::fixtures(IOS), false, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        // Its members and its master, read with the NetBox side of the stack.
        assert_eq!(asked.load(Ordering::Relaxed), 2);
    }

    // The check of the monitoring knows a failure by the name of its source:
    // the error of a member of a stack names the source first, then the
    // member, which the operator needs.
    #[tokio::test]
    async fn the_error_of_a_device_that_is_not_its_source_names_the_source_then_the_device() {
        let netbox = Hooked { dropped: Some("description"), ..Hooked::failing_reads(stack_netbox(), |_, _| None) };
        let stack = Source {
            virtual_chassis: Some("2960-stack".to_owned()),
            ..switch("2960-stack.lab01", "192.0.2.251", "ios")
        };
        let outcome = sync(&inventory(vec![stack], &[]), &netbox, &Switches::fixtures(IOS), false, true).await;
        assert_eq!(
            outcome.errors,
            [
                "2960-stack.lab01: 2960-stack01.lab01: unknown field description on dcim.interfaces: NetBox would drop it"
            ]
        );
    }

    #[tokio::test]
    async fn unexpected_error_on_one_switch_does_not_stop_the_others() {
        // A NetBox answering with an unexpected error for one device.
        let fake = FakeGateway::new();
        add_vrfs(&fake);
        add_device(&fake, "nexus01.lab01", 12);
        let netbox = Hooked::failing_reads(fake, |endpoint, filters| {
            (endpoint == "dcim.devices" && filter(filters, "name") == Some("nexus03.lab01"))
                .then_some("502 Bad Gateway")
        });
        let inventory = inventory(vec![nexus01(), nexus03()], &[]);
        let outcome = sync(&inventory, &netbox, &Switches::two_fixtures(), true, false).await;
        assert_eq!(outcome.errors, ["nexus03.lab01: 502 Bad Gateway"]);
        assert!(outcome.applied > 0);
    }

    #[tokio::test]
    async fn stack_neighbour_resolved_when_the_stack_is_not_selected() {
        let netbox = netbox();
        let chassis = netbox.add("dcim.virtual_chassis", json!({"name": "2960-stack"}));
        let member = netbox.add(
            "dcim.devices",
            json!({"name": "2960-stack01.lab01", "site": 12, "virtual_chassis": chassis, "vc_position": 1}),
        );
        add_interface(&netbox, member, "TenGigabitEthernet1/0/2", "10gbase-x-sfpp");
        let stack = Source {
            virtual_chassis: Some("2960-stack".to_owned()),
            ..switch("2960-stack.lab01", "192.0.2.252", "ios")
        };
        let inventory = inventory(vec![nexus01(), stack], &["switch.example.com"]);
        let only = Options { only: BTreeSet::from(["nexus01.lab01".to_owned()]), ..options(false, false) };
        let outcome = run(&inventory, &netbox, &Switches::fixtures(NXOS_I2), &only, &NullProgress).await;
        // Neither applied nor re-read here: the local Ethernet1/30 does not exist yet, so
        // check the neighbour is resolved to the member, not reported as unknown.
        let unknown: Vec<&String> = outcome
            .warnings
            .iter()
            .filter(|warning| warning.contains("2960-stack.lab01") && warning.contains("not found"))
            .collect();
        assert_eq!(unknown, [] as [&String; 0]);
    }

    #[tokio::test]
    async fn failed_interface_read_never_prunes_cables() {
        let fake = FakeGateway::new();
        add_vrfs(&fake);
        let nexus01_id = add_device(&fake, "nexus01.lab01", 12);
        let nexus03_id = add_device(&fake, "nexus03.lab01", 12);
        let a = add_interface(&fake, nexus01_id, "Ethernet1/48", "other");
        let b = add_interface(&fake, nexus03_id, "Ethernet1/48", "other");
        add_cable(&fake, a, b);
        // Answers the first interface read of nexus01, then fails the next ones.
        let reads = Arc::new(AtomicUsize::new(0));
        let failing_device = nexus01_id.to_string();
        let netbox = Hooked::failing_reads(fake, move |endpoint, filters| {
            let read = endpoint == "dcim.interfaces" && filter(filters, "device_id") == Some(failing_device.as_str());
            (read && reads.fetch_add(1, Ordering::SeqCst) >= 1).then_some("502 Bad Gateway")
        });
        let inventory = inventory(vec![nexus01(), nexus03()], &[]);
        let outcome = sync(&inventory, &netbox, &Switches::two_fixtures(), false, true).await;
        assert_eq!(cable_deletions(&outcome), [] as [&Change; 0]);
        assert!(!containing(&outcome.warnings, "Netbox read failed").is_empty(), "{:?}", outcome.warnings);
        // nexus01 exists: its read failed, which its neighbour's warning must say.
        let unread = "nexus03.lab01: neighbour nexus01.lab01 could not be read from Netbox \
                      (Ethernet1/50 \"nexus01.lab01/1/50\" -> Ethernet1/50)";
        assert!(outcome.warnings.iter().any(|warning| warning == unread), "{:?}", outcome.warnings);
        assert_eq!(containing(&outcome.warnings, "nexus01.lab01 is not a Netbox device"), [] as [&String; 0]);
    }

    /// nexus02 Ethernet1/48, the CDP neighbour of nexus01 Ethernet1/48 in the fixture.
    fn with_nexus02_neighbour(netbox: &FakeGateway) -> u64 {
        let nexus02 = add_device(netbox, "nexus02.lab01", 12);
        add_interface(netbox, nexus02, "Ethernet1/48", "other")
    }

    #[tokio::test]
    async fn port_cabled_to_a_patch_panel_is_left_alone() {
        let netbox = netbox();
        with_nexus02_neighbour(&netbox);
        let nexus01_id = id_of(&netbox, "dcim.devices", "nexus01.lab01");
        let port = add_interface(&netbox, nexus01_id, "Ethernet1/48", "other");
        let panel = add_device(&netbox, "pp-a01", 12);
        let front = netbox.add("dcim.front_ports", json!({"device": panel, "name": "1"}));
        netbox.add(
            "dcim.cables",
            json!({
                "a_terminations": [{"object_type": "dcim.interface", "object_id": port}],
                "b_terminations": [{"object_type": "dcim.frontport", "object_id": front}],
                "status": "connected",
            }),
        );
        let switches = Switches::fixtures(NXOS_I2);
        let outcome = sync(&nexus_inventory(), &netbox, &switches, true, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(of_kind(&outcome, "cable"), [] as [&Change; 0]);
        assert_eq!(sync(&nexus_inventory(), &netbox, &switches, false, true).await.changes, []);
    }

    #[tokio::test]
    async fn cable_failure_does_not_block_interface_deletions() {
        let fake = netbox();
        with_nexus02_neighbour(&fake);
        let netbox = Hooked::refusing(fake, "dcim.cables", "cable refused");
        let outcome = sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), true, true).await;
        assert!(!containing(&outcome.errors, "cable refused").is_empty(), "{:?}", outcome.errors);
        assert_eq!(netbox.inner.find("dcim.interfaces", "name", &json!("admin")), None);
    }

    fn two_nexus(enforce_unique: bool) -> (FakeGateway, Inventory) {
        let netbox = netbox();
        let vrf = id_of(&netbox, "ipam.vrfs", "management");
        netbox.set("ipam.vrfs", vrf, "enforce_unique", json!(enforce_unique));
        add_device(&netbox, "nexus03.lab01", 12);
        (netbox, inventory(vec![nexus01(), nexus03()], &[]))
    }

    /// The devices holding the address both switches have on mgmt0, sorted.
    async fn mgmt0_ips(netbox: &FakeGateway) -> Vec<String> {
        let mut holders: Vec<String> = all(netbox, "ipam.ip_addresses")
            .await
            .iter()
            .filter(|row| row["address"] == json!("192.168.1.1/24"))
            .map(|row| row["assigned_object"]["device"]["name"].as_str().unwrap().to_owned())
            .collect();
        holders.sort();
        holders
    }

    #[tokio::test]
    async fn shared_ip_in_a_unique_vrf_does_not_stop_the_second_switch() {
        let (netbox, inventory) = two_nexus(true);
        let outcome = sync(&inventory, &netbox, &Switches::two_fixtures(), true, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(mgmt0_ips(&netbox).await, ["nexus01.lab01"]);
        assert!(
            !containing(&outcome.warnings, "VRF management enforces unique addresses").is_empty(),
            "{:?}",
            outcome.warnings
        );
        let nexus03 = netbox.row("dcim.devices", id_of(&netbox, "dcim.devices", "nexus03.lab01")).unwrap();
        assert_ne!(nexus03["serial"], json!(""));
    }

    #[tokio::test]
    async fn shared_ip_in_a_non_unique_vrf_is_held_by_both_switches() {
        let (netbox, inventory) = two_nexus(false);
        let outcome = sync(&inventory, &netbox, &Switches::two_fixtures(), true, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(mgmt0_ips(&netbox).await, ["nexus01.lab01", "nexus03.lab01"]);
    }

    #[tokio::test]
    async fn vlan_read_failure_is_reported_not_raised() {
        let netbox =
            Hooked::failing_reads(netbox(), |endpoint, _| (endpoint == "ipam.vlans").then_some("502 Bad Gateway"));
        let outcome = sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), true, true).await;
        assert_eq!(outcome.errors, ["site 12 VLANs: 502 Bad Gateway"]);
        assert_eq!(netbox.inner.writes(), []);
    }

    #[tokio::test]
    async fn ips_are_read_once_per_device() {
        // The cable step only needs interfaces; the device snapshot holds the IPs.
        let ip_reads = Arc::new(AtomicUsize::new(0));
        let counted = ip_reads.clone();
        let netbox = Hooked::failing_reads(netbox(), move |endpoint, filters| {
            let names: Vec<&str> = filters.iter().map(|(name, _)| name.as_str()).collect();
            if endpoint == "ipam.ip_addresses" && names == ["device_id"] {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            None
        });
        sync(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), true, true).await;
        assert_eq!(ip_reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replaced_mac_leaves_no_stale_object_with_prune() {
        let netbox = netbox();
        let nexus01_id = id_of(&netbox, "dcim.devices", "nexus01.lab01");
        let port = add_interface(&netbox, nexus01_id, "Ethernet1/1", "other");
        let old = netbox.add(
            "dcim.mac_addresses",
            json!({
                "mac_address": "00:11:22:33:44:55",
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": port,
            }),
        );
        netbox.set("dcim.interfaces", port, "primary_mac_address", json!(old));
        let switches = Switches::fixtures(NXOS_I2);
        let outcome = sync(&nexus_inventory(), &netbox, &switches, true, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let macs: Vec<Value> = all(&netbox, "dcim.mac_addresses")
            .await
            .iter()
            .filter(|row| row["assigned_object_id"] == json!(port))
            .map(|row| row["mac_address"].clone())
            .collect();
        assert_eq!(macs, [json!("02:08:D1:90:97:2D")]);
        assert_eq!(sync(&nexus_inventory(), &netbox, &switches, false, true).await.changes, []);
    }

    #[tokio::test]
    async fn cable_on_a_down_link_is_not_pruned() {
        // Ethernet1/47 is down in the nexus01 fixture and has no neighbour.
        let netbox = netbox();
        let nexus01_id = id_of(&netbox, "dcim.devices", "nexus01.lab01");
        let nexus02_id = add_device(&netbox, "nexus02.lab01", 12);
        let a = add_interface(&netbox, nexus01_id, "Ethernet1/47", "other");
        let b = add_interface(&netbox, nexus02_id, "Ethernet1/47", "other");
        add_cable(&netbox, a, b);
        let inventory = inventory(vec![nexus01(), switch("nexus02.lab01", "192.0.2.240", "nxos")], &[]);
        // nexus02 answers with the nexus03 outputs: both switches are synced, so the
        // cable joins two synced switches and only its down link protects it.
        let outcome = sync(&inventory, &netbox, &Switches::two_fixtures(), false, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(cable_deletions(&outcome), [] as [&Change; 0]);
    }

    // The NX-OS command set of docs/design.md, in collection order.
    const NXOS_SHOW: [&str; 9] = [
        "show interface | json",
        "show interface switchport | json",
        "show port-channel summary | json",
        "show vlan brief | json",
        "show ip interface vrf all | json",
        "show vrf interface | json",
        "show inventory | json",
        "show lldp neighbors detail | json",
        "show cdp neighbors detail | json",
    ];

    #[tokio::test]
    async fn progress_follows_the_run() {
        let progress = Recording::default();
        let netbox = netbox();
        let switches = Switches::fixtures(NXOS_I2);
        let outcome = run(&nexus_inventory(), &netbox, &switches, &options(true, true), &progress).await;
        let events = progress.events();
        let stages: Vec<Event> = events
            .iter()
            .filter(|event| matches!(event, Event::Begin(_) | Event::Step(_) | Event::End))
            .cloned()
            .collect();
        // 10 collection units, VLANs, one device, cables, interface deletions.
        assert_eq!(
            stages,
            [
                Event::Begin(14),
                step("collect 1 switch(es)"),
                step("collected nexus01.lab01 (1/1)"),
                // The NetBox side of each switch is a step of its own: the title must not
                // keep naming the last switch collected over SSH.
                step("read Netbox nexus01.lab01 (1/1)"),
                step("VLANs"),
                step("write nexus01.lab01 (1/1)"),
                step("cables"),
                step("interface deletions"),
                Event::End,
            ]
        );
        let collection: Vec<&Event> = events
            .iter()
            .filter(|event| matches!(event, Event::LaneStart(..) | Event::LaneDoing(..) | Event::LaneEnd(_)))
            .collect();
        // A lane for the SSH collection, then one for the NetBox read of the switch.
        let lane_starts: Vec<&Event> =
            collection.iter().copied().filter(|event| matches!(event, Event::LaneStart(..))).collect();
        assert_eq!(
            lane_starts,
            [&Event::LaneStart("nexus01.lab01".to_owned(), 9), &Event::LaneStart("nexus01.lab01".to_owned(), 1)]
        );
        let lane_doing: Vec<(String, String)> = collection
            .iter()
            .filter_map(|event| match event {
                Event::LaneDoing(lane, label) => Some((lane.clone(), label.clone())),
                _ => None,
            })
            .collect();
        let commands: Vec<(String, String)> =
            NXOS_SHOW.iter().map(|command| ("nexus01.lab01".to_owned(), (*command).to_owned())).collect();
        assert_eq!(lane_doing[..NXOS_SHOW.len()], commands);
        // Each NetBox read of the switch shows in its lane while it runs.
        let reads = &lane_doing[NXOS_SHOW.len()..];
        assert!(reads.contains(&("nexus01.lab01".to_owned(), "GET dcim.devices name=nexus01.lab01".to_owned())));
        assert!(!reads.is_empty());
        assert!(reads.iter().all(|(lane, label)| lane == "nexus01.lab01" && label.starts_with("GET ")), "{reads:?}");
        assert_eq!(collection.last(), Some(&&Event::LaneEnd("nexus01.lab01".to_owned())));
        // Every write is a unit of its own, and so is every read of the cable step (one
        // device lookup per interface read, one cable read per synced device): the
        // total counts them, the bar ends full.
        assert!(outcome.applied > 0);
        let cables = events.iter().position(|event| *event == step("cables")).expect("the cable step");
        let cable_reads: Vec<String> = doing(&events[cables..])
            .into_iter()
            .filter(|label| {
                label.starts_with("GET dcim.devices name=") || label.starts_with("GET dcim.cables device_id=")
            })
            .collect();
        assert!(cable_reads.len() >= 2, "{cable_reads:?}");
        assert_eq!(progress.total(), 14 + outcome.applied as u64 + cable_reads.len() as u64);
        assert_eq!(progress.advanced(), progress.total());
        // Each NetBox call shows while it runs.
        let doing = progress.doing();
        assert!(doing.contains(&"GET dcim.devices name=nexus01.lab01".to_owned()));
        assert!(doing.contains(&"POST dcim.interfaces Ethernet1/1".to_owned()));
        // One summary line per device stays in sight.
        let notes = progress.notes();
        let written = containing(&notes, "nexus01.lab01: ");
        assert_eq!(written.len(), 1, "{notes:?}");
        let summary = Regex::new(r"^nexus01\.lab01: \d+ change\(s\) written in \d+ s$").unwrap();
        assert!(summary.is_match(written[0]), "{}", written[0]);
    }

    #[tokio::test]
    async fn diff_mode_summary_line() {
        let progress = Recording::default();
        let outcome =
            run(&nexus_inventory(), &netbox(), &Switches::fixtures(NXOS_I2), &options(false, true), &progress).await;
        let device_changes = outcome.changes.iter().filter(|change| change.device == "nexus01.lab01").count();
        assert!(progress.notes().contains(&format!("nexus01.lab01: {device_changes} change(s) to write")));
        assert_eq!(progress.advanced(), progress.total());
    }

    /// nexus01 answers, nexus03 cannot be reached.
    fn nexus03_down() -> Switches {
        Switches::new(|source| {
            if source.name == "nexus03.lab01" {
                return Err(CollectionError("unreachable".to_owned()));
            }
            Ok(Answer::from(NXOS_I2))
        })
    }

    #[tokio::test]
    async fn progress_notes_a_failed_switch_and_still_completes() {
        let netbox = netbox();
        add_device(&netbox, "nexus03.lab01", 12);
        let inventory = inventory(vec![nexus01(), nexus03()], &[]);
        let progress = Recording::default();
        run(&inventory, &netbox, &nexus03_down(), &options(false, false), &progress).await;
        let events = progress.events();
        assert!(events.contains(&Event::Note("error: nexus03.lab01: unreachable".to_owned())), "{events:?}");
        assert!(events.contains(&step("diff nexus01.lab01 (1/1)")), "{events:?}");
        assert_eq!(progress.advanced(), progress.total());
        assert_eq!(events.last(), Some(&Event::End));
    }

    #[tokio::test]
    async fn unreached_commands_of_a_failed_switch_still_count_as_done() {
        let netbox = netbox();
        add_device(&netbox, "nexus03.lab01", 12);
        let inventory = inventory(vec![nexus01(), nexus03()], &[]);
        let progress = Recording::default();
        run(&inventory, &netbox, &nexus03_down(), &options(false, false), &progress).await;
        let events = progress.events();
        // Two switches of 9 commands and one NetBox read each, then VLANs and cables.
        assert_eq!(events.first(), Some(&Event::Begin(24)));
        let resized = events.iter().position(|event| matches!(event, Event::Resize(_))).expect("the bar is resized");
        // Once the collection is over its 20 units are done, although nexus03 ran
        // no command and was never read from NetBox; one device is left to diff.
        let advances = events[..resized].iter().filter(|event| matches!(event, Event::Advance(_))).count();
        assert_eq!(advances, 20);
        assert_eq!(events[resized], Event::Resize(23));
    }

    /// nexus01 and nexus03, the second one added to `netbox`.
    fn two_switch_run(netbox: &FakeGateway) -> Inventory {
        add_device(netbox, "nexus03.lab01", 12);
        inventory(vec![nexus01(), nexus03()], &[])
    }

    /// Waits for the other party of `barrier`, five seconds at most.
    async fn meet(barrier: &Barrier) -> bool {
        timeout(Duration::from_secs(5), barrier.wait()).await.is_ok()
    }

    /// Waits for `signal`, five seconds at most.
    async fn signalled(signal: &Notify) -> bool {
        timeout(Duration::from_secs(5), signal.notified()).await.is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn switches_are_collected_at_the_same_time() {
        // Each switch waits for the other to have started: collected one after the
        // other, the first would wait alone and the barrier would break.
        let barrier = Arc::new(Barrier::new(2));
        let netbox = netbox();
        let inventory = two_switch_run(&netbox);
        let switches = Switches::new(move |source| {
            let barrier = barrier.clone();
            let together = gate(move || {
                let barrier = barrier.clone();
                async move { if meet(&barrier).await { Ok(()) } else { Err(CollectionError("collected alone".to_owned())) } }
            });
            Ok(Answer::gated(by_name(source), together))
        });
        let outcome = sync(&inventory, &netbox, &switches, false, false).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn report_follows_the_inventory_order_whatever_finishes_first() {
        let second_done = Arc::new(Notify::new());
        let switches = Switches::new(move |source| {
            let second_done = second_done.clone();
            if source.name == "nexus01.lab01" {
                // nexus01 fails only once nexus03 has failed.
                let late = gate(move || {
                    let second_done = second_done.clone();
                    async move {
                        assert!(signalled(&second_done).await, "nexus03 never failed");
                        Err(CollectionError("nexus01 down".to_owned()))
                    }
                });
                return Ok(Answer::gated(NXOS_I2, late));
            }
            let early = gate(move || {
                second_done.notify_one();
                async { Err(CollectionError("nexus03 down".to_owned())) }
            });
            Ok(Answer::gated(NXOS_I2, early))
        });
        let netbox = netbox();
        let outcome = sync(&two_switch_run(&netbox), &netbox, &switches, false, false).await;
        assert_eq!(outcome.errors, ["nexus01.lab01: nexus01 down", "nexus03.lab01: nexus03 down"]);
    }

    /// Drops `run` as soon as `interrupt` is signalled: what Ctrl-C does to a run.
    async fn interrupted(interrupt: &Notify, run: impl Future<Output = Outcome>) {
        let dropped = async {
            tokio::select! {
                biased;
                () = interrupt.notified() => {}
                _ = run => panic!("the run ended before the interrupt"),
            }
        };
        timeout(Duration::from_secs(5), dropped).await.expect("the interrupt returns at once");
    }

    /// What is left of the run after an interrupt gets its chance to go on.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    /// A progress that signals `interrupt` once nexus01 is collected.
    fn interrupting_after_nexus01(interrupt: &Arc<Notify>) -> Recording {
        let interrupt = interrupt.clone();
        Recording::watching(move |label| {
            if label.starts_with("collected nexus01.lab01") {
                interrupt.notify_one();
            }
        })
    }

    #[tokio::test]
    async fn interrupt_stops_the_other_switches_at_their_next_command() {
        let release = Arc::new(Notify::new());
        let held = release.clone();
        let switches = Switches::new(move |source| {
            if source.name == "nexus01.lab01" {
                return Ok(Answer::from(NXOS_I2));
            }
            let held = held.clone();
            let hold = gate(move || {
                let held = held.clone();
                async move {
                    held.notified().await;
                    Ok(())
                }
            });
            Ok(Answer::gated(NXOS_I2, hold))
        });
        let interrupt = Arc::new(Notify::new());
        let progress = interrupting_after_nexus01(&interrupt);
        let netbox = netbox();
        let inventory = two_switch_run(&netbox);
        interrupted(&interrupt, run(&inventory, &netbox, &switches, &options(false, false), &progress)).await;
        release.notify_one();
        settle().await;
        // nexus03 was held in its first command; it runs no other one.
        assert_eq!(switches.started_by("nexus03.lab01"), [NXOS_SHOW[0]]);
        // The progress is ended, whatever interrupted the run.
        assert_eq!(progress.events().last(), Some(&Event::End));
    }

    #[tokio::test]
    async fn alias_creates_the_cable_to_a_fortigate() {
        let netbox = netbox();
        let forti = add_device(&netbox, "forti01.lab01", 12);
        add_interface(&netbox, forti, "HA2", "other");
        let inventory = Inventory {
            aliases: BTreeMap::from([("FGT-81-Acme-Primaire".to_owned(), "forti01.lab01".to_owned())]),
            ..nexus_inventory()
        };
        let outcome = sync(&inventory, &netbox, &Switches::fixtures(NXOS_I2), true, false).await;
        let keys = cable_keys(&outcome);
        assert!(
            keys.contains(&"nexus01.lab01:Ethernet1/37 <-> forti01.lab01:HA2")
                || keys.contains(&"forti01.lab01:HA2 <-> nexus01.lab01:Ethernet1/37"),
            "{keys:?}"
        );
    }

    #[tokio::test]
    async fn interrupt_does_not_wait_for_a_switch_still_connecting() {
        // A switch can take up to its SSH timeouts to connect: an interrupt must not
        // wait for it, or the process keeps the run lock meanwhile.
        let connecting = Arc::new(Notify::new());
        let waited = connecting.clone();
        let switches = Switches::new(move |source| {
            if source.name == "nexus01.lab01" {
                return Ok(Answer::from(NXOS_I2));
            }
            let waited = waited.clone();
            let slow = gate(move || {
                let waited = waited.clone();
                async move {
                    waited.notified().await;
                    Ok(())
                }
            });
            Ok(Answer { connect: Some(slow), ..Answer::from(NXOS_I2) })
        });
        let interrupt = Arc::new(Notify::new());
        let progress = interrupting_after_nexus01(&interrupt);
        let netbox = netbox();
        let inventory = two_switch_run(&netbox);
        interrupted(&interrupt, run(&inventory, &netbox, &switches, &options(false, false), &progress)).await;
        connecting.notify_one();
        settle().await;
        // Its connection is given up with the run.
        assert_eq!(*switches.connected.lock().unwrap(), ["nexus01.lab01"]);
        assert_eq!(progress.events().last(), Some(&Event::End));
    }

    /// Signals `interrupt`, then never answers.
    fn interrupt_then_hold<E: Send + 'static>(
        interrupt: &Arc<Notify>,
    ) -> impl Future<Output = Result<(), E>> + Send + 'static + use<E> {
        let interrupt = interrupt.clone();
        async move {
            interrupt.notify_one();
            pending().await
        }
    }

    #[tokio::test]
    async fn no_switch_connects_after_an_interrupt() {
        // One connection at a time: nexus03 waits for nexus01's slot. Ctrl-C arrives
        // while nexus01 runs its first command: nexus03 must give up, not connect.
        let interrupt = Arc::new(Notify::new());
        let signal = interrupt.clone();
        let switches = Switches::new(move |source| {
            if source.name != "nexus01.lab01" {
                return Ok(Answer::from(NXOS_I2));
            }
            let signal = signal.clone();
            Ok(Answer::gated(NXOS_I2, gate(move || interrupt_then_hold(&signal))))
        });
        let netbox = netbox();
        let inventory = two_switch_run(&netbox);
        let one_at_a_time = Limits { collect: 1, netbox: MAX_PARALLEL_NETBOX };
        let diff = options(false, false);
        let run = run_limited(&inventory, &netbox, &switches, &diff, &NullProgress, one_at_a_time);
        interrupted(&interrupt, run).await;
        settle().await;
        assert_eq!(*switches.connections.lock().unwrap(), ["nexus01.lab01"]);
    }

    type NetboxGate = Arc<dyn Fn() -> BoxFuture<'static, Result<(), GatewayError>> + Send + Sync>;

    fn netbox_gate<F, Fut>(wait: F) -> NetboxGate
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), GatewayError>> + Send + 'static,
    {
        Arc::new(move || wait().boxed())
    }

    /// The two-switch NetBox, calling `gates[name]` on the first read of each
    /// device by name; also gives the device names read, in order.
    fn gated_netbox(gates: BTreeMap<&'static str, NetboxGate>) -> (Hooked, Inventory, Arc<Mutex<Vec<String>>>) {
        let fake = netbox();
        let inventory = two_switch_run(&fake);
        let device_reads = Arc::new(Mutex::new(Vec::new()));
        let reads = device_reads.clone();
        let netbox = Hooked::new(fake, move |endpoint, filters| {
            let mut wait = None;
            if endpoint == "dcim.devices"
                && let Some(name) = filter(filters, "name")
            {
                let mut reads = reads.lock().unwrap();
                let first = !reads.iter().any(|read: &String| read == name);
                reads.push(name.to_owned());
                if first {
                    wait = gates.get(name).cloned();
                }
            }
            async move {
                match wait {
                    Some(wait) => wait().await,
                    None => Ok(()),
                }
            }
            .boxed()
        });
        (netbox, inventory, device_reads)
    }

    #[tokio::test(start_paused = true)]
    async fn switches_are_read_from_netbox_at_the_same_time() {
        // Read one after the other, the first switch would wait alone and the barrier
        // would break.
        let barrier = Arc::new(Barrier::new(2));
        let together = netbox_gate(move || {
            let barrier = barrier.clone();
            async move { if meet(&barrier).await { Ok(()) } else { Err(request("read alone")) } }
        });
        let gates = BTreeMap::from([("nexus01.lab01", together.clone()), ("nexus03.lab01", together)]);
        let (netbox, inventory, _) = gated_netbox(gates);
        let outcome = sync(&inventory, &netbox, &Switches::two_fixtures(), false, false).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn netbox_read_errors_follow_the_inventory_whatever_finishes_first() {
        let second_done = Arc::new(Notify::new());
        let waited = second_done.clone();
        // nexus01's read fails only once nexus03's has failed.
        let late = netbox_gate(move || {
            let waited = waited.clone();
            async move {
                assert!(signalled(&waited).await, "nexus03's read never failed");
                Err(request("nexus01 502"))
            }
        });
        let early = netbox_gate(move || {
            second_done.notify_one();
            async { Err(request("nexus03 502")) }
        });
        let (netbox, inventory, _) = gated_netbox(BTreeMap::from([("nexus01.lab01", late), ("nexus03.lab01", early)]));
        let outcome = sync(&inventory, &netbox, &Switches::two_fixtures(), false, false).await;
        assert_eq!(outcome.errors, ["nexus01.lab01: nexus01 502", "nexus03.lab01: nexus03 502"]);
    }

    #[tokio::test]
    async fn no_netbox_read_starts_after_an_interrupt() {
        // One read at a time: nexus03 waits for nexus01's slot. Ctrl-C arrives while
        // nexus01 is being read: nexus03 must give up, not read.
        let interrupt = Arc::new(Notify::new());
        let signal = interrupt.clone();
        let hold = netbox_gate(move || interrupt_then_hold(&signal));
        let (netbox, inventory, device_reads) = gated_netbox(BTreeMap::from([("nexus01.lab01", hold)]));
        let switches = Switches::two_fixtures();
        let one_at_a_time = Limits { collect: MAX_PARALLEL_SSH, netbox: 1 };
        let diff = options(false, false);
        let run = run_limited(&inventory, &netbox, &switches, &diff, &NullProgress, one_at_a_time);
        interrupted(&interrupt, run).await;
        settle().await;
        assert_eq!(*device_reads.lock().unwrap(), ["nexus01.lab01"]);
    }

    type CableGate = Arc<dyn Fn(usize) -> BoxFuture<'static, Result<(), GatewayError>> + Send + Sync>;

    /// The cable step of a run on nexus01 and its CDP neighbour nexus02: `gate`
    /// is called on each interface read made once the cable step has started,
    /// with the number of such reads so far.
    struct CableStep {
        netbox: Hooked,
        progress: Recording,
        /// The interface reads of the cable step.
        reads: Arc<AtomicUsize>,
    }

    fn cable_step(gate: CableGate) -> CableStep {
        let fake = netbox();
        // A second device to read in the cable step: nexus01's CDP neighbour.
        with_nexus02_neighbour(&fake);
        let in_cables = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let (started, counted) = (in_cables.clone(), reads.clone());
        let netbox = Hooked::new(fake, move |endpoint, _| {
            let mut wait = None;
            if started.load(Ordering::SeqCst) && endpoint == "dcim.interfaces" {
                let number = counted.fetch_add(1, Ordering::SeqCst) + 1;
                wait = Some(gate(number));
            }
            async move {
                match wait {
                    Some(wait) => wait.await,
                    None => Ok(()),
                }
            }
            .boxed()
        });
        let progress = Recording::watching(move |label| {
            if label == "cables" {
                in_cables.store(true, Ordering::SeqCst);
            }
        });
        CableStep { netbox, progress, reads }
    }

    #[tokio::test(start_paused = true)]
    async fn cable_step_reads_run_at_the_same_time() {
        // Read one after the other, the first read would wait alone and the barrier
        // would break, failing both reads.
        let barrier = Arc::new(Barrier::new(2));
        let first_two_meet: CableGate = Arc::new(move |number| {
            let barrier = barrier.clone();
            async move { if number > 2 || meet(&barrier).await { Ok(()) } else { Err(request("read alone")) } }.boxed()
        });
        let cables = cable_step(first_two_meet);
        let switches = Switches::fixtures(NXOS_I2);
        let outcome =
            run(&nexus_inventory(), &cables.netbox, &switches, &options(false, false), &cables.progress).await;
        assert_eq!(containing(&outcome.warnings, "Netbox read failed"), [] as [&String; 0]);
        assert!(cables.reads.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn each_cable_step_read_advances_the_bar() {
        let cables = cable_step(Arc::new(|_| async { Ok(()) }.boxed()));
        let switches = Switches::fixtures(NXOS_I2);
        run(&nexus_inventory(), &cables.netbox, &switches, &options(false, false), &cables.progress).await;
        let events = cables.progress.events();
        let start = events.iter().position(|event| *event == step("cables")).expect("the cable step");
        let advances = events[start..].iter().filter(|event| matches!(event, Event::Advance(_))).count();
        // nexus01 and nexus02 interfaces, nexus01's cables, then the step itself.
        assert!(advances >= 4, "{advances}");
        assert_eq!(cables.progress.advanced(), cables.progress.total());
    }

    #[tokio::test]
    async fn no_cable_step_read_starts_after_an_interrupt() {
        // One read at a time; Ctrl-C arrives during the first: no other read follows.
        let interrupt = Arc::new(Notify::new());
        let signal = interrupt.clone();
        let hold_the_first: CableGate = Arc::new(move |number| {
            let hold = interrupt_then_hold(&signal);
            async move { if number == 1 { hold.await } else { Ok(()) } }.boxed()
        });
        let cables = cable_step(hold_the_first);
        let switches = Switches::fixtures(NXOS_I2);
        let one_at_a_time = Limits { collect: MAX_PARALLEL_SSH, netbox: 1 };
        let (inventory, diff) = (nexus_inventory(), options(false, false));
        let run = run_limited(&inventory, &cables.netbox, &switches, &diff, &cables.progress, one_at_a_time);
        interrupted(&interrupt, run).await;
        settle().await;
        assert_eq!(cables.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bar_ends_full_when_a_write_fails() {
        let netbox = netbox();
        // Fails in the middle of the device writes (30 VLAN creations come first).
        netbox.fail_after(Some(40));
        let progress = Recording::default();
        let outcome =
            run(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), &options(true, true), &progress).await;
        assert!(!outcome.errors.is_empty());
        assert_eq!(progress.advanced(), progress.total());
    }

    fn nipper(name: &str) -> Source {
        Source {
            report: Some(fixtures().join(NIPPER).join(format!("{name}.html"))),
            neighbor_pattern: Some(Regex::new(r"(?i)\b(?P<host>lab1-pve\d+)(?:[\s_-]+(?P<port>[a-z0-9]+))?").unwrap()),
            neighbor_suffix: ".prod".to_owned(),
            ..Source::new(name, Kind::Switch, "nipper", "")
        }
    }

    #[tokio::test]
    async fn nipper_report_is_synced_without_ssh() {
        let netbox = FakeGateway::new();
        let switch_id = add_device(&netbox, "fplab1-sw001", 13);
        let pve = add_device(&netbox, "lab1-pve01.prod", 13);
        let nic = add_interface(&netbox, pve, "enp129s0", "10gbase-x-sfpp");
        let inventory = inventory(vec![nipper("fplab1-sw001")], &[]);
        let outcome = sync(&inventory, &netbox, &NoSsh, true, false).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let ports = ports(&netbox, switch_id).await;
        // 138 switchport ports and 3 SVIs.
        assert_eq!(ports.len(), 141);
        assert_eq!(cabled(&netbox).await, [BTreeSet::from([ports["TenGigabitEthernet1/0/40"], nic])]);
        assert_eq!(sync(&inventory, &netbox, &NoSsh, false, false).await.changes, []);
    }

    #[tokio::test]
    async fn nipper_stack_is_split_and_cabled_to_management_ports() {
        let netbox = FakeGateway::new();
        let chassis = netbox.add("dcim.virtual_chassis", json!({"name": "fplab1-sw001"}));
        let members: Vec<u64> = [1, 2]
            .into_iter()
            .map(|position| {
                netbox.add(
                    "dcim.devices",
                    json!({
                        "name": format!("fplab1-sw001-{position}"), "site": 13, "serial": "",
                        "virtual_chassis": chassis, "vc_position": position,
                    }),
                )
            })
            .collect();
        netbox.set("dcim.virtual_chassis", chassis, "master", json!(members[0]));
        let pve = add_device(&netbox, "lab1-pve01.prod", 13);
        let nic = add_interface(&netbox, pve, "enp130s0", "10gbase-x-sfpp");
        let idrac = netbox
            .add("dcim.interfaces", json!({"device": pve, "name": "iDrac8", "type": "1000base-t", "mgmt_only": true}));
        let stack = Source { virtual_chassis: Some("fplab1-sw001".to_owned()), ..nipper("fplab1-sw001") };
        let inventory = inventory(vec![stack], &[]);
        let outcome = sync(&inventory, &netbox, &NoSsh, true, false).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let first = ports(&netbox, members[0]).await;
        let second = ports(&netbox, members[1]).await;
        assert!(first.contains_key("Port-channel40"));
        assert!(second.contains_key("TenGigabitEthernet2/0/40"));
        let cabled = cabled(&netbox).await;
        assert!(cabled.contains(&BTreeSet::from([second["TenGigabitEthernet2/0/40"], nic])), "{cabled:?}");
        assert!(cabled.contains(&BTreeSet::from([first["GigabitEthernet1/0/27"], idrac])), "{cabled:?}");
        assert_eq!(netbox.row("dcim.interfaces", nic).unwrap()["device"], json!(pve));
        assert_eq!(sync(&inventory, &netbox, &NoSsh, false, false).await.changes, []);
    }

    fn heard(host: &str, card: &str, switch: &str, port: &str) -> Heard {
        Heard { host: host.to_owned(), card: card.to_owned(), switch: switch.to_owned(), port: port.to_owned() }
    }

    fn hearing(apply: bool, heard: Vec<Heard>) -> Options {
        Options { heard, ..options(apply, false) }
    }

    #[tokio::test]
    async fn the_cable_of_a_report_switch_follows_what_the_host_hears() {
        let netbox = FakeGateway::new();
        let switch_id = add_device(&netbox, "fplab1-sw001", 13);
        let pve = add_device(&netbox, "lab1-pve01.prod", 13);
        let pve_nic = add_interface(&netbox, pve, "enp129s0", "10gbase-x-sfpp");
        let esx = add_device(&netbox, "esx01.lab", 13);
        let vmnic0 = add_interface(&netbox, esx, "vmnic0", "1000base-t");
        let vmnic1 = add_interface(&netbox, esx, "vmnic1", "10gbase-x-sfpp");
        let inventory = inventory(vec![nipper("fplab1-sw001")], &[]);
        // The switch, as a provider names it: its short name is the one of the report.
        let heard = vec![
            heard("esx01.lab", "vmnic0", "FPLAB1-SW001.provider.example", "GigabitEthernet1/0/2"),
            // Described as the port of lab1-pve01: the host is believed.
            heard("esx01.lab", "vmnic1", "FPLAB1-SW001.provider.example", "TenGigabitEthernet1/0/40"),
        ];
        let outcome = run(&inventory, &netbox, &NoSsh, &hearing(true, heard.clone()), &NullProgress).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let ports = ports(&netbox, switch_id).await;
        let cabled = cabled(&netbox).await;
        assert!(cabled.contains(&BTreeSet::from([ports["GigabitEthernet1/0/2"], vmnic0])), "{cabled:?}");
        assert!(cabled.contains(&BTreeSet::from([ports["TenGigabitEthernet1/0/40"], vmnic1])), "{cabled:?}");
        assert!(!cabled.iter().any(|ends| ends.contains(&pve_nic)), "{cabled:?}");
        assert!(
            outcome.warnings.iter().any(|warning| warning.starts_with(
                "fplab1-sw001: fplab1-sw001 TenGigabitEthernet1/0/40: the description names lab1-pve01.prod, esx01.lab vmnic1 hears"
            )),
            "{:?}",
            outcome.warnings
        );
        // A second run writes nothing.
        let again = run(&inventory, &netbox, &NoSsh, &hearing(false, heard), &NullProgress).await;
        assert_eq!(again.changes, []);
    }

    #[tokio::test]
    async fn a_wrong_cable_of_a_report_switch_is_replaced_by_what_the_host_hears() {
        let netbox = FakeGateway::new();
        let switch_id = add_device(&netbox, "fplab1-sw001", 13);
        let esx = add_device(&netbox, "esx01.lab", 13);
        let vmnic2 = add_interface(&netbox, esx, "vmnic2", "1000base-t");
        let vmnic3 = add_interface(&netbox, esx, "vmnic3", "1000base-t");
        let port = add_interface(&netbox, switch_id, "GigabitEthernet1/0/14", "1000base-t");
        // Cabled to the wrong card, as the descriptions of East had it.
        let wrong = add_cable(&netbox, port, vmnic3);
        let inventory = inventory(vec![nipper("fplab1-sw001")], &[]);
        let heard = vec![heard("esx01.lab", "vmnic2", "fplab1-sw001", "GigabitEthernet1/0/14")];
        // Without prune: what the host hears is a proof of its own.
        let outcome = run(&inventory, &netbox, &NoSsh, &hearing(true, heard), &NullProgress).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(
            cable_keys(&outcome),
            [format!("cable {wrong}"), "esx01.lab:vmnic2 <-> fplab1-sw001:GigabitEthernet1/0/14".to_owned()]
        );
        let cabled = cabled(&netbox).await;
        assert!(cabled.contains(&BTreeSet::from([port, vmnic2])), "{cabled:?}");
        assert!(!cabled.iter().any(|ends| ends.contains(&vmnic3)), "{cabled:?}");
        assert!(
            outcome.warnings.contains(&format!(
                "cable esx01.lab:vmnic2 <-> fplab1-sw001:GigabitEthernet1/0/14 replaces cable {wrong}: the host hears it"
            )),
            "{:?}",
            outcome.warnings
        );
    }

    #[tokio::test]
    async fn a_blade_never_takes_the_cable_of_its_chassis() {
        let netbox = FakeGateway::new();
        let switch_id = add_device(&netbox, "fplab1-sw001", 13);
        let chassis = add_device(&netbox, "fx01.lab", 13);
        let uplink = add_interface(&netbox, chassis, "TenGigabitEthernet 0/12", "10gbase-x-sfpp");
        let blade = netbox
            .add("dcim.devices", json!({"name": "esx04.lab", "site": 13, "serial": "", "parent_device": chassis}));
        add_interface(&netbox, blade, "vmnic1", "10gbase-x-sfpp");
        let port = add_interface(&netbox, switch_id, "GigabitEthernet1/0/14", "1000base-t");
        add_cable(&netbox, port, uplink);
        let inventory = inventory(vec![nipper("fplab1-sw001")], &[]);
        let heard = vec![heard("esx04.lab", "vmnic1", "fplab1-sw001", "GigabitEthernet1/0/14")];
        let outcome = run(&inventory, &netbox, &NoSsh, &hearing(false, heard), &NullProgress).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(cable_keys(&outcome), [] as [&str; 0]);
        assert!(!outcome.warnings.iter().any(|warning| warning.contains("esx04.lab")), "{:?}", outcome.warnings);
    }

    fn nexus_pattern() -> Regex {
        Regex::new(r"(?i)^(?:i?drac[-\s]+)?(?P<host>[a-z0-9][a-z0-9.-]*)(?:/(?P<port>[^/\s]+))?").unwrap()
    }

    #[tokio::test]
    async fn ssh_switch_descriptions_complete_lldp_and_cdp() {
        let netbox = FakeGateway::new();
        add_vrfs(&netbox);
        let switch_id = add_device(&netbox, "nexus03.lab01", 12);
        let pve = add_device(&netbox, "pve02.lab01", 12);
        let idrac = netbox
            .add("dcim.interfaces", json!({"device": pve, "name": "iDrac7", "type": "1000base-t", "mgmt_only": true}));
        let described = Source { neighbor_pattern: Some(nexus_pattern()), ..nexus03() };
        let inventory = inventory(vec![described], &[]);
        let outcome = sync(&inventory, &netbox, &Switches::fixtures(NXOS_I4), true, false).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let port = ports(&netbox, switch_id).await["Ethernet1/7"];
        let cabled = cabled(&netbox).await;
        assert!(cabled.contains(&BTreeSet::from([port, idrac])), "{cabled:?}");
    }

    #[tokio::test]
    async fn prune_keeps_the_cables_of_a_nipper_switch() {
        // Neither report tells this link: nothing proves the cable wrong.
        let netbox = FakeGateway::new();
        let ends: Vec<u64> = ["fplab1-sw001", "fplab2-sw001"]
            .into_iter()
            .map(|name| {
                let device = add_device(&netbox, name, 13);
                add_interface(&netbox, device, "GigabitEthernet1/0/2", "other")
            })
            .collect();
        add_cable(&netbox, ends[0], ends[1]);
        let inventory = inventory(vec![nipper("fplab1-sw001"), nipper("fplab2-sw001")], &[]);
        let outcome = sync(&inventory, &netbox, &NoSsh, false, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(cable_deletions(&outcome), [] as [&Change; 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn result_holds_the_run_duration() {
        let netbox = netbox();
        let slow = Switches::new(|_| {
            let sleep = gate(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(())
            });
            Ok(Answer::gated(NXOS_I2, sleep))
        });
        let outcome = sync(&nexus_inventory(), &netbox, &slow, false, false).await;
        let seconds = outcome.seconds.expect("a run holds its duration");
        assert!((0.3..5.0).contains(&seconds), "{seconds}");
    }

    #[tokio::test]
    async fn failed_read_of_a_name_never_consulted_is_not_reported() {
        // Read ahead, the alias is never needed: nexus02.lab01, tried first, has the port.
        let fake = netbox();
        let port = with_nexus02_neighbour(&fake);
        // Every port nexus01's neighbours announce on nexus02: none falls back to the alias.
        let nexus02 = fake.row("dcim.interfaces", port).unwrap()["device"].as_u64().unwrap();
        for name in ["mgmt0", "Ethernet1/51", "Ethernet1/52"] {
            add_interface(&fake, nexus02, name, "other");
        }
        // Fails every read of the alias.
        let netbox = Hooked::failing_reads(fake, |endpoint, filters| {
            (endpoint == "dcim.devices" && filter(filters, "name") == Some("nexus02-alias.lab01"))
                .then_some("502 Bad Gateway")
        });
        let inventory = Inventory {
            aliases: BTreeMap::from([("nexus02.lab01".to_owned(), "nexus02-alias.lab01".to_owned())]),
            ..nexus_inventory()
        };
        let outcome = sync(&inventory, &netbox, &Switches::fixtures(NXOS_I2), true, false).await;
        assert_eq!(containing(&outcome.warnings, "nexus02-alias.lab01"), [] as [&String; 0]);
        let keys = cable_keys(&outcome);
        assert!(keys.contains(&"nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48"), "{keys:?}");
    }

    #[tokio::test]
    async fn cable_warnings_quote_the_switch_port_description() {
        // nexus01's Ethernet1/50 is described "nexus03.lab01/1/50" on the switch.
        let outcome = sync(&nexus_inventory(), &netbox(), &Switches::fixtures(NXOS_I2), false, false).await;
        let unknown = "nexus01.lab01: neighbour nexus03.lab01 is not a Netbox device \
                       (Ethernet1/50 \"nexus03.lab01/1/50\" -> Ethernet1/50)";
        assert!(outcome.warnings.iter().any(|warning| warning == unknown), "{:?}", outcome.warnings);
    }

    // A warning starts with the source it is about, as an error does: the
    // check takes it back at the next run of that source. A member of a
    // stack is its source's; a device of no source of the run (a neighbour)
    // leaves the warning to the run.
    #[test]
    fn a_warning_is_given_the_source_of_the_device_it_starts_with() {
        let sources = BTreeMap::from([
            ("nexus01.lab01".to_owned(), "nexus01.lab01".to_owned()),
            ("2960-stack01.lab01".to_owned(), "2960-stack.lab01".to_owned()),
            ("2960-stack02.lab01".to_owned(), "2960-stack.lab01".to_owned()),
        ]);
        let given = |warning: &str| attributed(&sources, warning.to_owned());
        assert_eq!(
            given("2960-stack02.lab01 GigabitEthernet2/0/1: interface not in Netbox yet"),
            "2960-stack.lab01: 2960-stack02.lab01 GigabitEthernet2/0/1: interface not in Netbox yet"
        );
        assert_eq!(
            given("2960-stack01.lab01:TenGigabitEthernet1/0/2 is claimed by several links (a, b)"),
            "2960-stack.lab01: 2960-stack01.lab01:TenGigabitEthernet1/0/2 is claimed by several links (a, b)"
        );
        assert_eq!(
            given("nexus01.lab01 Ethernet1/48: neighbours disagree (a, b)"),
            "nexus01.lab01: nexus01.lab01 Ethernet1/48: neighbours disagree (a, b)"
        );
        // Already its source's, as the members' errors are.
        assert_eq!(
            given("nexus01.lab01: neighbour x is not a Netbox device (y)"),
            "nexus01.lab01: neighbour x is not a Netbox device (y)"
        );
        // A name that only starts like a device is not that device.
        assert_eq!(given("nexus01.lab01b: Netbox read failed: 502"), "nexus01.lab01b: Netbox read failed: 502");
        assert_eq!(
            given("cable a <-> b not written: an end is already cabled (cable 7)"),
            "cable a <-> b not written: an end is already cabled (cable 7)"
        );
    }

    #[tokio::test]
    async fn description_naming_another_device_than_the_neighbour_is_warned() {
        // nexus01's Ethernet1/48 is described "br01.lab01.example.cust-ge0/1/1" while CDP
        // announces nexus02.lab01 there. The FGT-* descriptions name no NetBox device.
        let netbox = netbox();
        with_nexus02_neighbour(&netbox);
        add_device(&netbox, "br01.lab01.example.cust-ge0", 12);
        let described = Source { neighbor_pattern: Some(nexus_pattern()), ..nexus01() };
        let inventory = inventory(vec![described], &["switch.example.com"]);
        let outcome = sync(&inventory, &netbox, &Switches::fixtures(NXOS_I2), false, false).await;
        assert_eq!(
            containing(&outcome.warnings, "the description names"),
            ["nexus01.lab01: nexus01.lab01 Ethernet1/48 \"br01.lab01.example.cust-ge0/1/1\": the description \
              names br01.lab01.example.cust-ge0, the neighbour announces nexus02.lab01 (cdp)"]
        );
    }

    fn firewall() -> Source {
        Source {
            username: "readonly".to_owned(),
            password: Some(Wanted::Held(Secret::new("secret"))),
            tls_fingerprint: Some("ab".repeat(32)),
            ha_peers: vec![
                ("LABLU-FWL01".to_owned(), "lablu-fwl01.dc1".to_owned()),
                ("LABBS-FWL01".to_owned(), "labbs-fwl01.dc1".to_owned()),
            ],
            ignore_interfaces: vec!["dmz".to_owned()],
            ..Source::new("lablu-fwl01.dc1", Kind::Firewall, "fortios", "10.0.13.1")
        }
    }

    fn firewalls() -> Inventory {
        inventory(vec![firewall()], &[])
    }

    /// What the cluster answers, as recorded: among its 52 interfaces, the
    /// aggregates PO1 and PO2 (over x1 and x2), the VLANs HOUSING (12, over PO2,
    /// carrying 10.0.13.1/24, the address the API answers on) and INTERNET
    /// (954, over PO1), and the tunnel VPN_DC2 over INTERNET.
    fn firewall_api() -> Firewalls {
        Firewalls
    }

    /// A cluster as documented by hand: one fictitious `eth0` per member.
    fn firewall_netbox() -> (FakeGateway, BTreeMap<String, u64>) {
        firewall_netbox_at(FakeGateway::new(), 12)
    }

    /// The same cluster at the site `east-01`, which the configuration of
    /// `east()` puts in the VLAN group `East`: the NetBox, and the id of the site.
    fn grouped_firewall_netbox() -> (FakeGateway, u64) {
        let netbox = FakeGateway::new();
        let site = netbox.add("dcim.sites", json!({"name": "east-01", "slug": "east-01"}));
        (firewall_netbox_at(netbox, site).0, site)
    }

    /// The options of a run that writes, the site `east-01` being in the VLAN group `East`.
    fn east() -> Options {
        let mut vlan_groups = VlanGroups::default();
        vlan_groups.insert("East-01", "East");
        Options { vlan_groups, ..options(true, true) }
    }

    /// The NetBox ids of the VLANs the interfaces point to, untagged or tagged, with their number.
    async fn pointed_vlans(netbox: &FakeGateway) -> BTreeSet<(u64, u64)> {
        let mut pointed = BTreeSet::new();
        for row in netbox.list("dcim.interfaces", &Vec::new()).await.unwrap() {
            let tagged = row["tagged_vlans"].as_array().cloned().unwrap_or_default();
            for vlan in tagged.iter().chain(row.get("untagged_vlan").filter(|vlan| vlan.is_object())) {
                pointed.insert((vlan["vid"].as_u64().unwrap(), vlan["id"].as_u64().unwrap()));
            }
        }
        pointed
    }

    /// (number, id, has a site, id of its group) of every VLAN NetBox holds.
    async fn vlans(netbox: &FakeGateway) -> Vec<(u64, u64, bool, Option<u64>)> {
        let rows = netbox.list("ipam.vlans", &Vec::new()).await.unwrap();
        let vlan = |row: &Row| {
            let site = row.get("site").is_some_and(|site| !site.is_null());
            let group = row.get("group").and_then(|group| group.get("id")).and_then(Value::as_u64);
            (row["vid"].as_u64().unwrap(), row["id"].as_u64().unwrap(), site, group)
        };
        rows.iter().map(vlan).collect()
    }

    // The requirement: the VLANs of a site that is in a VLAN group are those
    // of the group. The ports the site had on its own VLANs are moved to the
    // ones of the group, which are created there, at no site; the VLANs of the
    // site are left where they are, as this family never deletes a VLAN.
    #[tokio::test]
    async fn a_site_that_joins_a_vlan_group_gets_its_vlans_in_the_group_and_its_ports_moved_to_them() {
        let (netbox, _) = grouped_firewall_netbox();
        let group = netbox.add("ipam.vlan_groups", json!({"name": "East", "slug": "east"}));
        // Before the site joins the group: its VLANs are its own.
        let before = sync(&firewalls(), &netbox, &firewall_api(), true, true).await;
        assert_eq!(before.errors, [] as [&str; 0]);
        let of_the_site = vlans(&netbox).await;
        // The VLANs of the recorded cluster, HOUSING (12) and INTERNET (954) among them: all at the site.
        assert!(of_the_site.iter().all(|vlan| vlan.2 && vlan.3.is_none()), "{of_the_site:?}");
        let numbers: BTreeSet<u64> = of_the_site.iter().map(|vlan| vlan.0).collect();
        assert!(numbers.contains(&12) && numbers.contains(&954), "{numbers:?}");
        let pointed = pointed_vlans(&netbox).await;
        let site_ids: BTreeSet<u64> = of_the_site.iter().map(|vlan| vlan.1).collect();
        let pointed_numbers: BTreeSet<u64> = pointed.iter().map(|(vid, _)| *vid).collect();
        assert!(pointed_numbers.contains(&12) && pointed_numbers.contains(&954), "{pointed_numbers:?}");
        assert!(pointed.iter().all(|(_, id)| site_ids.contains(id)));

        let outcome = run(&firewalls(), &netbox, &firewall_api(), &east(), &NullProgress).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let after = vlans(&netbox).await;
        let in_group: Vec<&(u64, u64, bool, Option<u64>)> = after.iter().filter(|vlan| vlan.3.is_some()).collect();
        // The same VLANs, by their number, in the group and at no site.
        assert!(in_group.iter().all(|vlan| !vlan.2 && vlan.3 == Some(group)), "{in_group:?}");
        assert_eq!(in_group.iter().map(|vlan| vlan.0).collect::<BTreeSet<u64>>(), numbers);
        // Every port is on the VLAN of the group that has the number it was on.
        let group_ids: BTreeSet<u64> = in_group.iter().map(|vlan| vlan.1).collect();
        let moved = pointed_vlans(&netbox).await;
        assert_eq!(moved.iter().map(|(vid, _)| *vid).collect::<BTreeSet<u64>>(), pointed_numbers);
        assert!(moved.iter().all(|(_, id)| group_ids.contains(id)), "{moved:?}");
        // The VLANs of the site are still there.
        assert!(site_ids.iter().all(|id| netbox.row("ipam.vlans", *id).is_some()));
        // And a second run has nothing left to write.
        let again = run(&firewalls(), &netbox, &firewall_api(), &east(), &NullProgress).await;
        assert_eq!((again.changes, again.errors), (vec![], vec![]));
    }

    // The site joined the group and a port is still untagged on a VLAN of the
    // site that the firewall does not put there: the port is cleared, as it
    // would be of any VLAN the source does not report.
    #[tokio::test]
    async fn a_port_left_on_a_vlan_of_its_site_that_the_device_does_not_want_is_cleared() {
        let (netbox, _) = grouped_firewall_netbox();
        netbox.add("ipam.vlan_groups", json!({"name": "East", "slug": "east"}));
        let before = sync(&firewalls(), &netbox, &firewall_api(), true, true).await;
        assert_eq!(before.errors, [] as [&str; 0]);
        // PO2 is a trunk without native VLAN; someone set one of the site's VLANs on it.
        let po2 = netbox.find("dcim.interfaces", "name", &json!("PO2")).expect("PO2");
        assert_eq!(netbox.row("dcim.interfaces", po2).unwrap()["untagged_vlan"], Value::Null);
        let internet = netbox.find("ipam.vlans", "vid", &json!(954)).expect("VLAN 954 of the site");
        netbox.set("dcim.interfaces", po2, "untagged_vlan", json!(internet));
        let outcome = run(&firewalls(), &netbox, &firewall_api(), &east(), &NullProgress).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert_eq!(netbox.row("dcim.interfaces", po2).unwrap()["untagged_vlan"], Value::Null);
        let again = run(&firewalls(), &netbox, &firewall_api(), &east(), &NullProgress).await;
        assert_eq!((again.changes, again.errors), (vec![], vec![]));
    }

    // The group is a prerequisite, as the device is.
    #[tokio::test]
    async fn a_source_whose_vlan_group_netbox_does_not_hold_is_an_error_and_writes_nothing() {
        let (netbox, _) = grouped_firewall_netbox();
        let outcome = run(&firewalls(), &netbox, &firewall_api(), &east(), &NullProgress).await;
        assert_eq!(outcome.errors, ["lablu-fwl01.dc1: VLAN group East not found in Netbox"]);
        assert_eq!(netbox.writes(), []);
        assert_eq!(outcome.changes, []);
    }

    // A VLAN of the group that also has a site: NetBox refuses it on a port of
    // another site of the group. Told, never created again nor renamed.
    #[tokio::test]
    async fn a_vlan_of_the_group_that_also_has_a_site_is_an_error_naming_it() {
        let (netbox, site) = grouped_firewall_netbox();
        let group = netbox.add("ipam.vlan_groups", json!({"name": "East", "slug": "east"}));
        netbox.add("ipam.vlans", json!({"group": group, "site": site, "vid": 12, "name": "Housing"}));
        let outcome = run(&firewalls(), &netbox, &firewall_api(), &east(), &NullProgress).await;
        assert_eq!(
            outcome.errors.first().map(String::as_str),
            Some(
                "VLAN group East: VLAN 12 also has the site east-01, and a VLAN several sites share has none: clear its \
                 site"
            )
        );
        // It is neither created again in the group nor renamed after the firewall.
        let twelve: Vec<(u64, u64, bool, Option<u64>)> =
            vlans(&netbox).await.into_iter().filter(|vlan| vlan.0 == 12).collect();
        assert_eq!(twelve.len(), 1, "{twelve:?}");
        assert!(!outcome.changes.iter().any(|change| change.kind == "vlan" && change.key == "12"));
    }

    // NetBox refuses two VLANs of a group under one name: told before the write, which would end the run.
    #[tokio::test]
    async fn a_vlan_whose_name_another_vlan_of_the_group_has_is_an_error_naming_both() {
        let (netbox, _) = grouped_firewall_netbox();
        let group = netbox.add("ipam.vlan_groups", json!({"name": "East", "slug": "east"}));
        netbox.add("ipam.vlans", json!({"group": group, "vid": 99, "name": "INTERNET"}));
        let outcome = run(&firewalls(), &netbox, &firewall_api(), &east(), &NullProgress).await;
        assert_eq!(
            outcome.errors.first().map(String::as_str),
            Some("VLAN group East: VLAN 954: its name INTERNET is the one of VLAN 99 in VLAN group East; not created")
        );
        // The other VLANs of the cluster are created in the group all the same: HOUSING (12) is, INTERNET is not.
        let held = vlans(&netbox).await;
        assert!(held.iter().all(|vlan| vlan.3 == Some(group)), "{held:?}");
        let numbers: BTreeSet<u64> = held.iter().map(|vlan| vlan.0).collect();
        assert!(numbers.contains(&12) && numbers.contains(&99) && !numbers.contains(&954), "{numbers:?}");
    }

    fn firewall_netbox_at(netbox: FakeGateway, site: u64) -> (FakeGateway, BTreeMap<String, u64>) {
        let mut ids = BTreeMap::new();
        for (name, address) in [("lablu-fwl01.dc1", "10.0.13.1/24"), ("labbs-fwl01.dc1", "10.0.13.2/24")] {
            let device = add_device(&netbox, name, site);
            let eth0 = add_interface(&netbox, device, "eth0", "other");
            let ip = netbox.add(
                "ipam.ip_addresses",
                json!({
                    "address": address,
                    "vrf": null,
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": eth0,
                    "status": "active",
                }),
            );
            netbox.set("dcim.devices", device, "primary_ip4", json!(ip));
            ids.insert(name.to_owned(), device);
            ids.insert(format!("{name} eth0"), eth0);
            ids.insert(format!("{name} ip"), ip);
        }
        (netbox, ids)
    }

    /// The stored interface of `device` named `name`.
    async fn named(netbox: &FakeGateway, device: u64, name: &str) -> Row {
        let id = ports(netbox, device).await[name];
        netbox.row("dcim.interfaces", id).expect("the interface is stored")
    }

    #[tokio::test]
    async fn firewall_cluster_apply_then_diff_is_empty() {
        let (netbox, ids) = firewall_netbox();
        let api = firewall_api();
        let first = sync(&firewalls(), &netbox, &api, true, true).await;
        assert_eq!(first.errors, [] as [&str; 0]);
        assert_eq!(first.applied, first.changes.len());
        let second = sync(&firewalls(), &netbox, &api, false, true).await;
        assert_eq!((second.changes, second.errors), (vec![], vec![]));
        let (entry, peer) = (ids["lablu-fwl01.dc1"], ids["labbs-fwl01.dc1"]);
        let serial = |device: u64| netbox.row("dcim.devices", device).unwrap()["serial"].clone();
        assert_eq!((serial(entry), serial(peer)), (json!("FG101FTK22000001"), json!("FG101FTK22000002")));
        // The address the API answers on moved from the fictitious port to its interface.
        let housing = named(&netbox, entry, "HOUSING").await;
        let address = netbox.row("ipam.ip_addresses", ids["lablu-fwl01.dc1 ip"]).unwrap();
        assert_eq!(address["assigned_object_id"], housing["id"]);
        assert_eq!(netbox.row("dcim.devices", entry).unwrap()["primary_ip4"], json!(ids["lablu-fwl01.dc1 ip"]));
        assert_eq!(netbox.row("dcim.interfaces", ids["lablu-fwl01.dc1 eth0"]), None);
        // A tunnel over a VLAN over an aggregate.
        let internet = named(&netbox, entry, "INTERNET").await;
        assert_eq!(named(&netbox, entry, "VPN_DC2").await["parent"], internet["id"]);
        assert_eq!(internet["parent"], named(&netbox, entry, "PO1").await["id"]);
    }

    #[tokio::test]
    async fn each_api_request_of_a_firewall_is_a_unit_of_the_bar() {
        let (netbox, _) = firewall_netbox();
        let progress = Recording::default();
        let outcome = run(&firewalls(), &netbox, &firewall_api(), &options(false, true), &progress).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let events = progress.events();
        // The four API requests and the NetBox read of the firewall, then its
        // device, the VLANs and the cables.
        assert_eq!(events.first(), Some(&Event::Begin(8)));
        assert!(events.contains(&Event::LaneStart("lablu-fwl01.dc1".to_owned(), 4)), "{events:?}");
        assert_eq!(progress.advanced(), progress.total());
    }

    #[tokio::test]
    async fn firewall_cluster_peer_is_left_as_netbox_has_it() {
        let (netbox, ids) = firewall_netbox();
        let peer = ids["labbs-fwl01.dc1"];
        // A port without an address: nothing but the device being unmanaged keeps it.
        add_interface(&netbox, peer, "console", "other");
        let outcome = sync(&firewalls(), &netbox, &firewall_api(), true, true).await;
        assert_eq!(outcome.warnings, [] as [&str; 0]);
        let names: Vec<Value> = all(&netbox, "dcim.interfaces")
            .await
            .iter()
            .filter(|row| row["device"]["id"] == json!(peer))
            .map(|row| row["name"].clone())
            .collect();
        assert_eq!(names, [json!("eth0"), json!("console")]);
        assert_eq!(netbox.row("dcim.devices", peer).unwrap()["primary_ip4"], json!(ids["labbs-fwl01.dc1 ip"]));
        assert!(netbox.row("ipam.ip_addresses", ids["labbs-fwl01.dc1 ip"]).is_some());
    }

    #[tokio::test]
    async fn firewall_names_a_site_vlan_only_when_it_creates_it() {
        let (netbox, _) = firewall_netbox();
        let housing = netbox.add("ipam.vlans", json!({"site": 12, "vid": 12, "name": "VLAN12-Housing"}));
        let outcome = sync(&firewalls(), &netbox, &firewall_api(), true, true).await;
        assert_eq!(outcome.warnings, [] as [&str; 0]);
        assert_eq!(netbox.row("ipam.vlans", housing).unwrap()["name"], json!("VLAN12-Housing"));
        let internet = netbox.find("ipam.vlans", "vid", &json!(954)).expect("VLAN 954 is created");
        assert_eq!(netbox.row("ipam.vlans", internet).unwrap()["name"], json!("INTERNET"));
    }

    #[tokio::test]
    async fn firewall_cables_are_never_pruned() {
        let (netbox, ids) = firewall_netbox();
        let ends: Vec<u64> = ["lablu-fwl01.dc1", "labbs-fwl01.dc1"]
            .into_iter()
            .map(|name| add_interface(&netbox, ids[name], "x1", "other"))
            .collect();
        let cable = netbox.add(
            "dcim.cables",
            json!({
                "a_terminations": [{"object_type": "dcim.interface", "object_id": ends[0]}],
                "b_terminations": [{"object_type": "dcim.interface", "object_id": ends[1]}],
            }),
        );
        let outcome = sync(&firewalls(), &netbox, &firewall_api(), true, true).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        assert!(netbox.row("dcim.cables", cable).is_some());
    }

    #[tokio::test]
    async fn a_device_whose_collection_fails_is_left_out_and_writes_nothing() {
        let netbox = netbox();
        let nexus03_id = add_device(&netbox, "nexus03.lab01", 12);
        // With pruning, anything known of nexus03 would delete this port.
        let stale = add_interface(&netbox, nexus03_id, "Ethernet9/9", "other");
        let inventory = inventory(vec![nexus01(), nexus03()], &[]);
        let outcome = sync(&inventory, &netbox, &nexus03_down(), true, true).await;
        assert_eq!(outcome.errors, ["nexus03.lab01: unreachable"]);
        // nexus01 is written all the same.
        assert!(outcome.applied > 0);
        assert_eq!(outcome.changes.iter().filter(|change| change.device == "nexus03.lab01").count(), 0);
        assert_eq!(netbox.row("dcim.devices", nexus03_id).unwrap()["serial"], json!(""));
        assert_eq!(ports(&netbox, nexus03_id).await, BTreeMap::from([("Ethernet9/9".to_owned(), stale)]));
        let touched: Vec<_> =
            netbox.writes().into_iter().filter(|(_, _, id)| [nexus03_id, stale].contains(id)).collect();
        assert_eq!(touched, []);
    }

    #[tokio::test]
    async fn a_vlan_failure_stops_before_any_device_write() {
        let netbox = Hooked::refusing(netbox(), "ipam.vlans", "vlan refused");
        let progress = Recording::default();
        let outcome =
            run(&nexus_inventory(), &netbox, &Switches::fixtures(NXOS_I2), &options(true, true), &progress).await;
        assert_eq!(outcome.errors.len(), 1, "{:?}", outcome.errors);
        assert!(outcome.errors[0].starts_with("site 12 VLANs: "), "{}", outcome.errors[0]);
        assert!(outcome.errors[0].ends_with(": vlan refused"), "{}", outcome.errors[0]);
        assert_eq!(netbox.inner.writes(), []);
        assert_eq!(outcome.applied, 0);
        // The run ended there: no device was diffed, no later step began.
        assert_eq!(outcome.changes.iter().filter(|change| change.kind != "vlan").count(), 0);
        assert_eq!(
            progress.steps(),
            ["collect 1 switch(es)", "collected nexus01.lab01 (1/1)", "read Netbox nexus01.lab01 (1/1)", "VLANs"]
        );
        assert_eq!(progress.events().last(), Some(&Event::End));
    }

    #[tokio::test]
    async fn interface_deletions_run_last_and_only_when_applying() {
        let netbox = netbox();
        // A cable to create: a write of the cable step, which the deletions follow.
        with_nexus02_neighbour(&netbox);
        let admin = id_of(&netbox, "dcim.interfaces", "admin");
        let switches = Switches::fixtures(NXOS_I2);
        let progress = Recording::default();
        let outcome = run(&nexus_inventory(), &netbox, &switches, &options(true, true), &progress).await;
        assert_eq!(outcome.errors, [] as [&str; 0]);
        let writes = netbox.writes();
        let deletion = |write: &(&str, String, u64)| write.0 == "delete" && write.1 == "dcim.interfaces";
        let first_deletion = writes.iter().position(deletion).expect("an interface is deleted");
        assert!(writes.contains(&("delete", "dcim.interfaces".to_owned(), admin)));
        assert!(writes[..first_deletion].iter().any(|write| write.0 == "create" && write.1 == "dcim.cables"));
        assert!(writes[first_deletion..].iter().all(deletion), "{:?}", &writes[first_deletion..]);
        assert_eq!(progress.steps().last().map(String::as_str), Some("interface deletions"));

        // Without applying: the deletions are reported, the step never runs.
        let netbox = self::netbox();
        let progress = Recording::default();
        let outcome = run(&nexus_inventory(), &netbox, &switches, &options(false, true), &progress).await;
        let deleted: Vec<&str> = of_kind(&outcome, "interface")
            .into_iter()
            .filter(|change| change.action == Action::Delete)
            .map(|change| change.key.as_str())
            .collect();
        assert_eq!(deleted, ["admin"]);
        assert_eq!(netbox.writes(), []);
        assert!(!progress.steps().contains(&"interface deletions".to_owned()));
        assert_eq!(progress.steps().last().map(String::as_str), Some("cables"));
    }
}
