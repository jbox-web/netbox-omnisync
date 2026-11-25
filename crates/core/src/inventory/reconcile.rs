//! The reconciliation of what the sources ask for with what NetBox holds.
//!
//! One pure function for every hypervisor source: no I/O, no clock, no global
//! state, and an output sorted so that two runs on the same input print the
//! same report. The applier writes the steps in the order given; a dry run
//! prints them.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{Map, Value, json};

use crate::change::{Action, Change, Fields};
use crate::gateway::Row;

use super::model::{
    ANY_VRF, Current, Desired, Identity, Kind, LEGACY_TAGS, SOURCE_TAG_PREFIX, TOOL_TAG, Tag, Target, VlanGroups,
};

/// What became of a source in this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    /// Configured but left out of this run (`--source` named another one).
    Skipped,
    /// Ran and failed: what it reported is partial.
    Failed,
    /// Ran to the end: what it did not report does not exist any more.
    Succeeded,
    /// Ran to the end, but a part of what it reads could not be read (one BMC
    /// out of ten): what it reports is whole and is written; what it does not
    /// report says nothing, so its tags stay and it has no orphan.
    Partial,
}

impl SourceStatus {
    /// Whether what the source reports is written.
    fn reports(self) -> bool {
        matches!(self, SourceStatus::Succeeded | SourceStatus::Partial)
    }
}

/// What the reconciliation needs to know about a configured source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFacts {
    pub name: String,
    /// Slug (and name) of the source's ownership tag; starts with `source-`.
    pub tag: String,
    pub status: SourceStatus,
    /// Delete the orphans of this source.
    pub prune: bool,
    /// Create a device this source reports and NetBox does not have.
    pub create_devices: bool,
}

/// The facts of a run. Every configured source is listed, the ones left out of
/// the run included: that is how their tags are told from an old tool's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Run {
    pub sources: Vec<SourceFacts>,
    /// Source names, the first one winning an object two sources report.
    pub priority: Vec<String>,
    /// The tables in which NetBox refuses a second object for the same
    /// address: VRF names in lower case, `""` for the global table.
    pub unique_ip_vrfs: BTreeSet<String>,
    /// A tag whose description starts with one of these was created from a
    /// source's own tags: it is removed from an object once the source no
    /// longer reports it there. Any other tag is somebody else's.
    pub source_tag_markers: Vec<String>,
}

/// When a step is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Creations and updates, in dependency order.
    Write,
    /// References to an object of the same or a later kind (a primary IP, a
    /// primary MAC, a parent interface), once every object exists.
    Link,
    /// Deletions, in reverse dependency order.
    Delete,
}

/// A reference of a step, for the applier: the NetBox id when the target is
/// already there, `None` when this run creates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub kind: Kind,
    pub identity: Identity,
    pub id: Option<u64>,
}

/// One write, with what the applier needs beyond the printable change.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub phase: Phase,
    pub kind: Kind,
    pub identity: Identity,
    /// What a report prints. A reference is shown by the name of its target,
    /// `tags` as the full sorted list of tag names, `custom_fields` as the
    /// changed keys only. `id` is `None` on an update of an object this run
    /// creates.
    pub change: Change,
    /// The reference fields of `change.fields`; `None` clears the reference.
    pub references: BTreeMap<String, Option<Link>>,
    /// The reference-list fields of `change.fields`.
    pub reference_lists: BTreeMap<String, Vec<Link>>,
}

/// A warning of a reconciliation, and the source it is about: the one that
/// reports the object (the winner of a difference two sources settle), the
/// one an orphan is held for, or None for the run as a whole. The run starts
/// the text with that name, as it starts an error with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub source: Option<String>,
    pub text: String,
}

impl Warning {
    fn about(source: &str, text: String) -> Self {
        Warning { source: Some(source.to_owned()), text }
    }
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{source}: {}", self.text),
            None => f.write_str(&self.text),
        }
    }
}

impl PartialEq<&str> for Warning {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl PartialEq<String> for Warning {
    fn eq(&self, other: &String) -> bool {
        self.text == *other
    }
}

/// The outcome of a reconciliation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub warnings: Vec<Warning>,
    /// Orphans left in place because their source does not prune.
    pub orphans_kept: Vec<String>,
    /// What a source asks for and NetBox would refuse, each starting with
    /// the name of the source: the object is left out, the rest is written,
    /// and the run is told it failed.
    pub errors: Vec<String>,
}

impl Plan {
    /// The changes, in the order they are written.
    pub fn changes(&self) -> Vec<Change> {
        self.steps.iter().map(|step| step.change.clone()).collect()
    }
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        _ => false,
    }
}

fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// NetBox renders a choice field as `{value, label}`; the tool writes the value.
fn plain(value: &Value) -> &Value {
    match value {
        Value::Object(choice) if choice.contains_key("label") => choice.get("value").unwrap_or(value),
        _ => value,
    }
}

/// Whether NetBox already shows `wanted`, whatever way it renders it.
///
/// A first run on a NetBox the old tools filled must write nothing but tags:
/// a choice equals its value, a number equals its other spellings (`2`, `2.0`,
/// `"2.00"`), and `null` equals the empty text or list NetBox may store in
/// its place. Two texts are compared as texts.
pub fn same_value(wanted: &Value, current: &Value) -> bool {
    let current = plain(current);
    if wanted == current || (is_empty(wanted) && is_empty(current)) {
        return true;
    }
    match (wanted, current) {
        (Value::Number(_), _) | (_, Value::Number(_)) => match (number(wanted), number(current)) {
            (Some(wanted), Some(current)) => wanted == current,
            _ => false,
        },
        (Value::Array(wanted), Value::Array(current)) => {
            wanted.len() == current.len()
                && wanted.iter().zip(current).all(|(wanted, current)| same_value(wanted, current))
        }
        _ => false,
    }
}

/// An object in the maps of a reconciliation: its kind and identity key. An
/// IP address reported by a source carries its holder as well (see `scoped`).
type Key = (Kind, Vec<String>);

/// What the reconciliation decided for a reported object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// It is this NetBox object (index in the current state).
    Match(usize),
    Create,
    /// Neither created nor updated; its dependents are skipped with it.
    Skip,
}

/// What a reference resolves to.
enum Resolution {
    Existing(u64),
    Created,
    Skipped,
    Missing,
    Ambiguous,
}

/// The NetBox objects that have an identity.
enum Lookup {
    None,
    One(usize),
    Many(Vec<usize>),
}

/// An object as the sources that report it want it, once merged.
struct Wanted<'a> {
    /// The report of the source that wins, completed by the reports that only
    /// complete the object (`Desired::complement`).
    content: Cow<'a, Desired>,
    /// The sources that own the object, the winner first. Empty when every
    /// report only completes it.
    reporters: Vec<&'a SourceFacts>,
    unknown: BTreeSet<Kind>,
    ensure_only: bool,
    /// A report that only completes the object was added to the one of its
    /// winner: a part of `content` is not the winner's.
    completed: bool,
    /// No source owns the object: it is completed where it exists, never
    /// created, tagged or deleted.
    complement_only: bool,
}

/// What the merged report holds where a completing report has a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Nothing,
    /// A value its source only writes when NetBox has none: a fallback.
    Fallback,
    Same,
    Other,
}

fn held<V: PartialEq>(current: Option<&V>, fallback: bool, value: &V) -> Held {
    match current {
        None => Held::Nothing,
        Some(_) if fallback => Held::Fallback,
        Some(current) if current == value => Held::Same,
        Some(_) => Held::Other,
    }
}

/// The device or virtual machine an object belongs to, from its key.
fn holder(kind: Kind, key: &[String]) -> Option<Key> {
    match kind {
        Kind::Device | Kind::VirtualMachine => Some((kind, key.to_vec())),
        Kind::Interface => Some((Kind::Device, key.get(..1)?.to_vec())),
        Kind::VmInterface | Kind::VirtualDisk => {
            Some((Kind::VirtualMachine, key.get(..key.len().checked_sub(1)?)?.to_vec()))
        }
        _ => None,
    }
}

/// The key of an IP address as held by `holder`.
///
/// The identity of an address is its host and VRF, yet two machines may each
/// hold the same one (a virtual address, `172.17.0.1` on every Docker host):
/// what two holders report are two objects, never one reported twice.
fn scoped(key: &[String], holder: Option<&Key>) -> Key {
    let mut scoped = key.to_vec();
    if let Some((kind, parts)) = holder {
        scoped.push("@".to_owned());
        scoped.push(kind.label().to_owned());
        scoped.extend(parts.iter().cloned());
    }
    (Kind::IpAddress, scoped)
}

fn assigned(desired: &Desired) -> Option<&Target> {
    desired.references.get("assigned_object").and_then(Option::as_ref)
}

/// The key under which a reported object is decided.
fn wanted_key(desired: &Desired) -> Key {
    if desired.kind == Kind::IpAddress {
        let holder = assigned(desired).and_then(|target| holder(target.kind, target.identity.key()));
        return scoped(desired.identity.key(), holder.as_ref());
    }
    (desired.kind, desired.identity.key().to_vec())
}

/// The object a reported one cannot exist without.
fn parent_key(desired: &Desired) -> Option<Key> {
    match desired.kind {
        Kind::Interface | Kind::VmInterface | Kind::VirtualDisk => holder(desired.kind, desired.identity.key()),
        Kind::MacAddress | Kind::IpAddress => {
            assigned(desired).map(|target| (target.kind, target.identity.key().to_vec()))
        }
        _ => None,
    }
}

fn describe(kind: Kind, owner: &str, label: &str) -> String {
    if owner.is_empty() || owner == label {
        format!("{} {label}", kind.label())
    } else {
        format!("{} {owner} {label}", kind.label())
    }
}

/// The device or virtual machine a reported object is shown under.
fn owner_of(desired: &Desired) -> &str {
    match desired.identity.owner() {
        "" => assigned(desired).map(|target| target.identity.owner()).unwrap_or_default(),
        owner => owner,
    }
}

fn describe_desired(desired: &Desired) -> String {
    describe(desired.kind, owner_of(desired), desired.identity.label())
}

fn describe_current(current: &Current) -> String {
    describe(current.kind, current.identity.owner(), current.identity.label())
}

/// Whether two reports ask for the same object.
fn alike(left: &Desired, right: &Desired) -> bool {
    // What is only written at creation, and whether the object only has to
    // exist, are left out: two sources that differ there say the same thing
    // of the object, and the first of the priority decides its creation.
    // A report that only wants the object to exist writes nothing once it
    // does: it never disagrees with another.
    if left.ensure_only || right.ensure_only {
        return true;
    }
    left.fields == right.fields
        && left.references == right.references
        && left.reference_lists == right.reference_lists
        && left.tags == right.tags
        && left.custom_fields == right.custom_fields
        && left.only_when_empty == right.only_when_empty
}

/// What a report shows of a current value.
fn shown(value: &Value) -> Value {
    plain(value).clone()
}

/// What a report shows of a nested object: its name.
fn shown_nested(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return Value::Null;
    };
    ["display", "name", "model", "address", "prefix"]
        .into_iter()
        .find_map(|key| object.get(key).filter(|name| name.is_string()).cloned())
        .or_else(|| object.get("id").map(|id| Value::String(id.to_string())))
        .unwrap_or(Value::Null)
}

fn nested_id(row: &Row, field: &str) -> Option<u64> {
    row.get(field).and_then(|nested| nested.get("id")).and_then(Value::as_u64)
}

/// The ids a row lists under a many-to-many field (`tagged_vlans`).
fn listed_ids<'r>(row: &'r Row, field: &str) -> impl Iterator<Item = u64> + 'r {
    let items = row.get(field).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    items.iter().filter_map(|item| item.get("id").and_then(Value::as_u64).or(item.as_u64()))
}

/// The network an address is in, written as NetBox writes a prefix.
fn network(address: &str) -> Option<String> {
    let (host, length) = address.split_once('/')?;
    let length: u32 = length.parse().ok()?;
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V4(host) if length <= 32 => {
            let mask = u32::MAX.checked_shl(32 - length).unwrap_or(0);
            Some(format!("{}/{length}", Ipv4Addr::from(u32::from(host) & mask)))
        }
        IpAddr::V6(host) if length <= 128 => {
            let mask = u128::MAX.checked_shl(128 - length).unwrap_or(0);
            Some(format!("{}/{length}", Ipv6Addr::from(u128::from(host) & mask)))
        }
        _ => None,
    }
}

fn sorted_names(mut names: Vec<String>) -> Vec<String> {
    names.sort_by_key(|name| (name.to_lowercase(), name.clone()));
    names.dedup();
    names
}

fn caseless_set(names: &[String]) -> BTreeSet<String> {
    names.iter().map(|name| name.to_lowercase()).collect()
}

/// The two halves of what is written on an object: now, and once the objects
/// of the same or a later kind exist.
#[derive(Default)]
struct Writes {
    fields: Fields,
    before: Fields,
    references: BTreeMap<String, Option<Link>>,
    reference_lists: BTreeMap<String, Vec<Link>>,
}

struct Reconciler<'a> {
    run: &'a Run,
    current: &'a [Current],
    by_name: BTreeMap<&'a str, &'a SourceFacts>,
    by_tag: BTreeMap<&'a str, &'a SourceFacts>,
    by_key: BTreeMap<Key, Vec<usize>>,
    /// IP addresses and prefixes by their first part, whatever the VRF.
    by_first: BTreeMap<(Kind, &'a str), Vec<usize>>,
    by_id: BTreeMap<(Kind, u64), usize>,
    /// Names, in lower case, of the tags that came from a source's own tags.
    source_tag_names: BTreeSet<String>,
    /// The name NetBox holds for a tag, by slug: an ownership tag is known by
    /// its slug, and attached by the name it has there.
    tag_names: BTreeMap<String, String>,
    decisions: BTreeMap<Key, Decision>,
    /// The devices and virtual machines reported under a name NetBox does not
    /// know and recognised by their MAC addresses: the NetBox object each is.
    recognised: BTreeMap<Key, usize>,
    /// The key NetBox still holds each of them under: what is reported under
    /// the new name is looked up under the old one.
    renamed: BTreeMap<Key, Vec<String>>,
    claimed: BTreeSet<usize>,
    /// Matched objects this plan moves under another parent: they no longer
    /// keep the one NetBox has them under.
    moved: BTreeSet<usize>,
    /// NetBox objects that a skipped report is about: not ours to orphan.
    spoken_for: BTreeSet<usize>,
    /// Matched objects whose dependents of some kinds could not be read.
    unknown_at: BTreeMap<(Kind, u64), BTreeSet<Kind>>,
    /// Objects a matched row still points to through an unreported field.
    pointed_at: BTreeSet<(Kind, u64)>,
    /// The names of the VLANs this run creates in a VLAN group, by group id,
    /// with the number of the VLAN: NetBox makes a name unique in a group.
    vlan_names: BTreeMap<(u64, String), String>,
    steps: Vec<Step>,
    warnings: Vec<Warning>,
    orphans_kept: Vec<String>,
    errors: Vec<String>,
}

impl<'a> Reconciler<'a> {
    /// A warning about `source`.
    fn warn(&mut self, source: &str, text: String) {
        self.warnings.push(Warning::about(source, text));
    }

    fn new(current: &'a [Current], run: &'a Run) -> Self {
        let mut by_key: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
        let mut by_first: BTreeMap<(Kind, &str), Vec<usize>> = BTreeMap::new();
        let mut by_id = BTreeMap::new();
        let mut source_tag_names = BTreeSet::new();
        let tag_names = tag_names_by_slug(current);
        // By id, so that "the first one" never depends on the order NetBox answered in.
        let mut order: Vec<usize> = (0..current.len()).collect();
        order.sort_by_key(|&index| (current[index].kind, current[index].id));
        for index in order {
            let object = &current[index];
            by_key.entry((object.kind, object.identity.key().to_vec())).or_default().push(index);
            by_id.insert((object.kind, object.id), index);
            if matches!(object.kind, Kind::IpAddress | Kind::Prefix)
                && let Some(first) = object.identity.key().first()
            {
                by_first.entry((object.kind, first.as_str())).or_default().push(index);
            }
            let description = object.row.get("description").and_then(Value::as_str).unwrap_or_default();
            if object.kind == Kind::Tag
                && run.source_tag_markers.iter().any(|marker| is_marked(description, marker))
                && let Some(name) = object.identity.key().first()
            {
                source_tag_names.insert(name.clone());
            }
        }
        Reconciler {
            run,
            current,
            by_name: run.sources.iter().map(|facts| (facts.name.as_str(), facts)).collect(),
            by_tag: run.sources.iter().map(|facts| (facts.tag.as_str(), facts)).collect(),
            by_key,
            by_first,
            by_id,
            source_tag_names,
            tag_names,
            decisions: BTreeMap::new(),
            recognised: BTreeMap::new(),
            renamed: BTreeMap::new(),
            claimed: BTreeSet::new(),
            moved: BTreeSet::new(),
            spoken_for: BTreeSet::new(),
            unknown_at: BTreeMap::new(),
            pointed_at: BTreeSet::new(),
            vlan_names: BTreeMap::new(),
            steps: Vec::new(),
            warnings: Vec::new(),
            orphans_kept: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Position of a source in the priority; a source left out of it comes last.
    fn priority(&self, source: &str) -> usize {
        self.run.priority.iter().position(|name| name == source).unwrap_or(usize::MAX)
    }

    /// Groups the reports by object and settles the ones two sources disagree on.
    fn merge(&mut self, desired: &'a [Desired]) -> BTreeMap<Key, Wanted<'a>> {
        let mut ignored: BTreeMap<&str, usize> = BTreeMap::new();
        let mut groups: BTreeMap<Key, Vec<(&'a Desired, &'a SourceFacts)>> = BTreeMap::new();
        for object in desired {
            // What a failed source reports is partial: writing it could clear
            // what the source simply did not get to.
            match self.by_name.get(object.source.as_str()) {
                Some(facts) if facts.status.reports() => {
                    groups.entry(wanted_key(object)).or_default().push((object, facts));
                }
                _ => *ignored.entry(object.source.as_str()).or_default() += 1,
            }
        }
        for (source, count) in ignored {
            let reason = if self.by_name.contains_key(source) { "did not succeed" } else { "is not configured" };
            self.warnings
                .push(Warning::about(source, format!("source {source} {reason}: {count} reported object(s) ignored")));
        }
        let mut wanted = BTreeMap::new();
        for (key, mut reports) in groups {
            // Stable: two reports of one source stay in the order given.
            reports.sort_by_key(|(_, facts)| (self.priority(&facts.name), facts.name.as_str()));
            // The reports that own the object are settled as a whole; the ones
            // that only complete it are then added to the winner field by field.
            let (owners, complements): (Vec<_>, Vec<_>) =
                reports.iter().copied().partition(|(report, _)| !report.complement);
            let complement_only = owners.is_empty();
            // A report that only wants the object to exist says nothing of its
            // fields: the first report that describes it wins, whatever the
            // priority of the ones that only ensure it.
            let first = owners.iter().position(|(report, _)| !report.ensure_only).unwrap_or(0);
            let (content, winner) = if complement_only { complements[0] } else { owners[first] };
            let mut reporters = if complement_only { Vec::new() } else { vec![winner] };
            let others = owners.iter().enumerate().filter(|(index, _)| *index != first).map(|(_, report)| report);
            for &(other, facts) in others {
                if !alike(content, other) {
                    let what = describe_desired(content);
                    let text = if facts.name == winner.name {
                        format!("{what}: reported twice, differently, by {}; the first report wins", winner.name)
                    } else {
                        format!(
                            "{what}: reported differently by {} and {}; {} wins (source priority)",
                            winner.name, facts.name, winner.name
                        )
                    };
                    self.warn(&winner.name, text);
                }
                if reporters.iter().all(|reporter| reporter.name != facts.name) {
                    reporters.push(facts);
                }
            }
            let mut content = Cow::Borrowed(content);
            let mut origins = BTreeMap::new();
            for &(report, facts) in complements.iter().skip(usize::from(complement_only)) {
                self.complete(&mut content, &mut origins, winner, report, facts);
            }
            let unknown = reports.iter().flat_map(|(report, _)| report.unknown_dependents.iter().copied()).collect();
            let ensure_only = !complement_only && owners.iter().all(|(report, _)| report.ensure_only);
            let completed = !complement_only && !complements.is_empty();
            wanted.insert(key, Wanted { content, reporters, unknown, ensure_only, completed, complement_only });
        }
        wanted
    }

    /// Whether `source` wins over `other` when both give a value: the first of
    /// the priority, then the first by name, as between two whole reports.
    fn wins(&self, source: &SourceFacts, other: &SourceFacts) -> bool {
        (self.priority(&source.name), source.name.as_str()) < (self.priority(&other.name), other.name.as_str())
    }

    /// Whether a source left out of this run, that wins over `winner`, holds
    /// the object: it carries the tag of that source, which only a run of the
    /// source that still reported the object leaves there.
    fn held_by_a_better_source(&self, existing: &Current, winner: &SourceFacts) -> bool {
        existing
            .tags
            .iter()
            .filter_map(|tag| self.by_tag.get(tag.slug.as_str()))
            .any(|facts| facts.status == SourceStatus::Skipped && self.wins(facts, winner))
    }

    /// Whether the value a completing report gives for `name` is taken, given
    /// what the merged report holds there, which `holder` reported.
    ///
    /// Nothing held, or a fallback: taken, whatever the priority — a source
    /// that knows beats one that does not, or that only fills an empty field.
    /// Another value: the priority decides, and the difference is a warning
    /// naming the field and both sources.
    fn takes(&mut self, what: &str, name: &str, held: Held, holder: &SourceFacts, facts: &SourceFacts) -> bool {
        match held {
            Held::Nothing | Held::Fallback => true,
            Held::Same => false,
            Held::Other => {
                let taken = self.wins(facts, holder);
                let (winner, loser) = if taken { (facts, holder) } else { (holder, facts) };
                let text = format!(
                    "{what}: {name} reported differently by {} and {}; {} wins (source priority)",
                    winner.name, loser.name, winner.name
                );
                self.warn(&winner.name, text);
                taken
            }
        }
    }

    /// Adds to `content` what `report`, which only completes the object, says
    /// of it: its fields, references and custom fields, one by one.
    /// `origins` remembers which source each value taken so far came from;
    /// the others came from `owner`.
    fn complete(
        &mut self,
        content: &mut Cow<'a, Desired>,
        origins: &mut BTreeMap<String, &'a SourceFacts>,
        owner: &'a SourceFacts,
        report: &'a Desired,
        facts: &'a SourceFacts,
    ) {
        let what = describe_desired(report);
        for (name, value) in &report.fields {
            let fallback = content.only_when_empty.contains(name);
            let reported = if content.references.contains_key(name) { Held::Other } else { Held::Nothing };
            let held = content.fields.get(name).map_or(reported, |current| held(Some(current), fallback, value));
            let holder = origins.get(name).copied().unwrap_or(owner);
            if self.takes(&what, name, held, holder, facts) {
                let content = content.to_mut();
                content.references.remove(name);
                content.fields.insert(name.clone(), value.clone());
                content.only_when_empty.remove(name);
                origins.insert(name.clone(), facts);
            }
        }
        for (name, target) in &report.references {
            let fallback = content.only_when_empty.contains(name);
            let reported = if content.fields.contains_key(name) { Held::Other } else { Held::Nothing };
            let held = content.references.get(name).map_or(reported, |current| held(Some(current), fallback, target));
            let holder = origins.get(name).copied().unwrap_or(owner);
            if self.takes(&what, name, held, holder, facts) {
                let content = content.to_mut();
                content.fields.remove(name);
                content.references.insert(name.clone(), target.clone());
                content.only_when_empty.remove(name);
                origins.insert(name.clone(), facts);
            }
        }
        for (name, value) in &report.custom_fields {
            let shown = format!("custom field {name}");
            let held = held(content.custom_fields.get(name), false, value);
            let holder = origins.get(&shown).copied().unwrap_or(owner);
            if self.takes(&what, &shown, held, holder, facts) {
                content.to_mut().custom_fields.insert(name.clone(), value.clone());
                origins.insert(shown, facts);
            }
        }
    }

    /// Whether a tool, this one or one it replaces, put its mark on the object.
    fn owned(&self, object: &Current) -> bool {
        object.tags.iter().any(|tag| {
            tag.slug == TOOL_TAG || LEGACY_TAGS.contains(&tag.slug.as_str()) || tag.slug.starts_with(SOURCE_TAG_PREFIX)
        })
    }

    /// The key NetBox holds an object under when the device or virtual machine
    /// it belongs to is renamed by this run: the identity of an interface, a
    /// disk or a MAC address starts with the name of its holder, and NetBox
    /// still has the old one. `None` for everything else.
    fn held_key(&self, kind: Kind, key: &[String]) -> Option<Vec<String>> {
        if self.renamed.is_empty() {
            return None;
        }
        match kind {
            Kind::Interface | Kind::VmInterface | Kind::VirtualDisk => {
                let reported = holder(kind, key)?;
                let mut held = self.renamed.get(&reported)?.clone();
                held.extend_from_slice(key.get(reported.1.len()..)?);
                Some(held)
            }
            // The address, the content type of the interface, then its key.
            Kind::MacAddress => {
                let interface = Kind::from_content_type(key.get(1)?)?;
                let mut held = key.get(..2)?.to_vec();
                held.extend(self.held_key(interface, key.get(2..)?)?);
                Some(held)
            }
            _ => None,
        }
    }

    /// Whether a NetBox device or virtual machine may be what `key` is, under
    /// another name: an object a tool holds for a source that reports `key`.
    ///
    /// Held: it carries the tag of this tool or of a tool it replaces, so a
    /// machine made by hand is never renamed. For the source: it carries the
    /// tag of a reporter, so nothing is taken from another source. And every
    /// source it is held for ran to the end: one that failed, was left out or
    /// was read in part (`SourceStatus::Partial`) said nothing of what it did
    /// not report, and may still know the object under the name it has. A
    /// virtual machine is only looked for in the cluster it is reported in.
    fn may_be(&self, candidate: &Current, key: &Key, reporters: &[&SourceFacts]) -> bool {
        // The cheapest test first: most candidates are of another kind.
        if candidate.kind != key.0 {
            return false;
        }
        let slugs = || candidate.tags.iter().map(|tag| tag.slug.as_str());
        let held = slugs().any(|slug| slug == TOOL_TAG || LEGACY_TAGS.contains(&slug));
        let for_the_source = slugs().any(|slug| reporters.iter().any(|facts| facts.tag == slug));
        let all_heard =
            slugs().filter_map(|slug| self.by_tag.get(slug)).all(|facts| facts.status == SourceStatus::Succeeded);
        let same_cluster = candidate.kind != Kind::VirtualMachine || candidate.identity.key().get(1) == key.1.get(1);
        candidate.kind == key.0 && held && for_the_source && all_heard && same_cluster
    }

    /// Recognises the devices and virtual machines reported under a name
    /// NetBox does not know, by the MAC addresses of their interfaces.
    ///
    /// A host or a machine renamed in its source is otherwise a new object,
    /// and the one NetBox has an orphan: deleted with its interfaces, its
    /// addresses, and whatever was documented on it. The candidates are the
    /// objects `may_be` accepts that no reported object has by its identity;
    /// each counts for the reported MAC addresses its interfaces hold. A
    /// single candidate is the object; between several, the best one only
    /// when it has at least twice the matches of the second (the rule of
    /// netbox-sync), since a generated address is shared by every clone of a
    /// template. Anything less is not guessed: a warning, and the object is
    /// handled as today. A NetBox object two reported ones would each be is
    /// taken for neither.
    ///
    /// A report that only completes its object (`Desired::complement`) has no
    /// part in this: nobody owns what it names, so it is never looked for
    /// under another name, and the object it names is not kept from being
    /// the one an owner renamed.
    fn recognise(&mut self, wanted: &BTreeMap<Key, Wanted<'a>>) {
        let mut taken = BTreeSet::new();
        let mut unknown = Vec::new();
        let owned = wanted.iter().filter(|(_, object)| !object.complement_only).map(|(key, _)| key);
        for key in owned.filter(|(kind, _)| matches!(kind, Kind::Device | Kind::VirtualMachine)) {
            match self.lookup(key) {
                Lookup::None => unknown.push(key),
                Lookup::One(index) => {
                    taken.insert(index);
                }
                Lookup::Many(indexes) => taken.extend(indexes),
            }
        }
        if unknown.is_empty() {
            return;
        }
        let mut reported: BTreeMap<Key, BTreeSet<&str>> = BTreeMap::new();
        for object in wanted.iter().filter(|(key, _)| key.0 == Kind::MacAddress).map(|(_, object)| &*object.content) {
            let holder = parent_key(object).and_then(|(kind, key)| holder(kind, &key));
            if let (Some(holder), Some(address)) = (holder, object.identity.key().first()) {
                reported.entry(holder).or_default().insert(address);
            }
        }
        let mut held: BTreeMap<(Kind, u64), BTreeSet<&str>> = BTreeMap::new();
        for object in self.current.iter().filter(|object| object.kind == Kind::MacAddress) {
            if let (Some(holder), Some(address)) = (self.holder_of(object), object.identity.key().first()) {
                held.entry(holder).or_default().insert(address);
            }
        }
        // Only an object that holds a MAC address can share one: the others are
        // never looked at, whatever the size of NetBox.
        let holders: Vec<(usize, &BTreeSet<&str>)> =
            held.iter().filter_map(|(id, addresses)| Some((*self.by_id.get(id)?, addresses))).collect();
        let mut chosen: BTreeMap<usize, Vec<&Key>> = BTreeMap::new();
        for key in unknown {
            let Some(addresses) = reported.get(key) else {
                continue;
            };
            let reporters = &wanted[key].reporters;
            let mut matches: Vec<(usize, usize)> = holders
                .iter()
                .filter(|(index, _)| !taken.contains(index))
                .filter_map(|&(index, holds)| {
                    let shared = holds.intersection(addresses).count();
                    (shared > 0 && self.may_be(&self.current[index], key, reporters)).then_some((shared, index))
                })
                .collect();
            matches.sort_by_key(|&(shared, index)| (std::cmp::Reverse(shared), self.current[index].id));
            let clear = match matches.as_slice() {
                [] => continue,
                [_] => true,
                [best, second, ..] => best.0 >= 2 * second.0,
            };
            if clear {
                chosen.entry(matches[0].1).or_default().push(key);
            } else {
                let candidates: Vec<String> = matches
                    .iter()
                    .map(|&(shared, index)| format!("{}: {shared}", describe_current(&self.current[index])))
                    .collect();
                let text = format!(
                    "{}: not found by name, and its MAC addresses match several objects ({}) without a clear best; \
                     none is taken",
                    describe_desired(&wanted[key].content),
                    candidates.join(", ")
                );
                self.warn(&wanted[key].content.source, text);
            }
        }
        for (index, keys) in chosen {
            if let [key] = keys.as_slice() {
                self.recognised.insert((*key).clone(), index);
                self.renamed.insert((*key).clone(), self.current[index].identity.key().to_vec());
                continue;
            }
            for key in &keys {
                let others: Vec<String> = keys
                    .iter()
                    .filter(|other| *other != key)
                    .map(|other| describe_desired(&wanted[*other].content))
                    .collect();
                let text = format!(
                    "{}: not found by name, and its MAC addresses match {}, which {} {} as well; \
                     it is taken for neither",
                    describe_desired(&wanted[*key].content),
                    describe_current(&self.current[index]),
                    others.join(" and "),
                    if others.len() == 1 { "matches" } else { "match" }
                );
                self.warn(&wanted[*key].content.source, text);
            }
        }
    }

    /// The new name of the object a report that only completes it names,
    /// when an owner renames that object in this run: NetBox still holds it
    /// under the name the completing report gives, whether the owner's report
    /// was decided before or not.
    fn completed_under_its_old_name(&self, key: &Key, object: &Wanted<'a>) -> Option<String> {
        if !object.complement_only || self.recognised.is_empty() {
            return None;
        }
        let held = self.by_key.get(key)?;
        let (renamed, _) = self.recognised.iter().find(|(_, index)| held.contains(index))?;
        renamed.1.first().cloned()
    }

    /// The NetBox objects with the identity of `key`, the claimed ones included.
    fn candidates(&self, key: &Key) -> Vec<usize> {
        let (kind, parts) = key;
        let any_vrf = matches!(kind, Kind::IpAddress | Kind::Prefix) && parts.get(1).is_some_and(|vrf| vrf == ANY_VRF);
        if !any_vrf {
            let held = self.held_key(*kind, parts).map(|parts| (*kind, parts));
            return self.by_key.get(held.as_ref().unwrap_or(key)).cloned().unwrap_or_default();
        }
        let first = parts.first().map(String::as_str).unwrap_or_default();
        let everywhere = self.by_first.get(&(*kind, first)).cloned().unwrap_or_default();
        // Held in several tables and the source cannot tell which: the global one.
        let global: Vec<usize> = everywhere
            .iter()
            .copied()
            .filter(|&index| self.current[index].identity.key().get(1).is_some_and(String::is_empty))
            .collect();
        if everywhere.len() > 1 && !global.is_empty() { global } else { everywhere }
    }

    /// The one NetBox object with the identity of `key`. Between several, the
    /// one a tool owns: a namesake made by hand is not the object the old
    /// tools were keeping.
    fn lookup(&self, key: &Key) -> Lookup {
        let free: Vec<usize> = self.candidates(key).into_iter().filter(|index| !self.claimed.contains(index)).collect();
        match free.as_slice() {
            [] => Lookup::None,
            [one] => Lookup::One(*one),
            _ => {
                let owned: Vec<usize> =
                    free.iter().copied().filter(|&index| self.owned(&self.current[index])).collect();
                match owned.as_slice() {
                    [one] => Lookup::One(*one),
                    _ => Lookup::Many(free),
                }
            }
        }
    }

    /// The NetBox object a decided key is, if it is one.
    fn matched(&self, key: &Key) -> Option<&'a Current> {
        match self.decisions.get(key) {
            Some(Decision::Match(index)) => Some(&self.current[*index]),
            _ => None,
        }
    }

    /// The device or virtual machine holding a NetBox address.
    fn holder_of(&self, address: &Current) -> Option<(Kind, u64)> {
        let interface = self.by_id.get(&address.parent?)?;
        self.current[*interface].parent
    }

    /// Finds the NetBox object of a reported IP address.
    ///
    /// An address is the reporter's when it is on the reported interface, on
    /// another interface of the same device or virtual machine (it moved), or
    /// on nothing at all. One assigned to another device or virtual machine is
    /// never taken: both may hold it, and NetBox is right about the other.
    fn decide_ip(&mut self, desired: &Desired, interface: Option<&Key>) -> Decision {
        let vrf = desired.identity.key().get(1).map(String::as_str).unwrap_or_default();
        let host = desired.identity.key().first().map(String::as_str).unwrap_or_default();
        let any_vrf = vrf == ANY_VRF;
        let in_table = |object: &Current| any_vrf || object.identity.key().get(1).is_some_and(|held| held == vrf);
        let global = |object: &Current| object.identity.key().get(1).is_some_and(String::is_empty);
        let everywhere: Vec<usize> = self
            .by_first
            .get(&(Kind::IpAddress, host))
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(|&index| in_table(&self.current[index]))
            .collect();
        let free: Vec<usize> = everywhere.iter().copied().filter(|index| !self.claimed.contains(index)).collect();
        // Assigned by NetBox to something that is not an interface (an FHRP
        // group holds a VIP): held, though it has no parent this tool knows.
        let held_elsewhere = |object: &Current| {
            object.parent.is_none() && object.row.get("assigned_object_type").is_some_and(|kind| !kind.is_null())
        };
        let wanted_interface = interface.and_then(|key| self.matched(key)).map(|object| (object.kind, object.id));
        // The holder of an interface this run creates is the one it is reported under.
        let wanted_holder = match interface.and_then(|key| self.matched(key)) {
            Some(object) => object.parent,
            None => interface
                .and_then(|(kind, key)| holder(*kind, key))
                .and_then(|key| self.matched(&key))
                .map(|object| (object.kind, object.id)),
        };
        let own = free
            .iter()
            .copied()
            .find(|&index| wanted_interface.is_some() && self.current[index].parent == wanted_interface)
            .or_else(|| {
                let moved =
                    |index: &usize| wanted_holder.is_some() && self.holder_of(&self.current[*index]) == wanted_holder;
                free.iter().copied().find(moved)
            })
            .or_else(|| {
                let loose = |index: &usize| {
                    let object = &self.current[*index];
                    object.parent.is_none() && !held_elsewhere(object) && (!any_vrf || global(object))
                };
                free.iter().copied().find(loose)
            });
        if let Some(index) = own {
            return Decision::Match(index);
        }
        let mut holders: Vec<&str> = everywhere
            .iter()
            .map(|&index| &self.current[index])
            .filter(|object| (object.parent.is_some() || held_elsewhere(object)) && (!any_vrf || global(object)))
            .map(|object| match object.identity.owner() {
                "" => "another object",
                owner => owner,
            })
            .collect();
        holders.sort_unstable();
        holders.dedup();
        let Some(first) = holders.first() else {
            return Decision::Create;
        };
        let others = match holders.len() - 1 {
            0 => String::new(),
            more => format!(" and {more} other(s)"),
        };
        let what =
            format!("ip {} of {}: also assigned to {first}{others}", desired.identity.label(), owner_of(desired));
        let table = if any_vrf { "" } else { vrf };
        if self.run.unique_ip_vrfs.contains(table) {
            // NetBox would refuse the duplicate, and the refusal would stop the run.
            self.warn(&desired.source, format!("{what}; not created, its table enforces unique addresses"));
            Decision::Skip
        } else {
            self.warn(&desired.source, format!("{what}; a second address is created"));
            Decision::Create
        }
    }

    /// Whether a VLAN NetBox lacks can be created in the VLAN group it is
    /// reported in; a VLAN of a site, or of no scope, always can.
    ///
    /// The group is a prerequisite: without it the VLAN would be created with
    /// neither group nor site, a global VLAN no run would find again, made
    /// anew at every run. And NetBox makes a name unique in a group: a second
    /// VLAN under a name the group has would be refused, and a refused write
    /// stops the run. Both are errors of the source, told before any write;
    /// the VLAN is skipped, and what refers to it is left as NetBox has it.
    fn vlan_creation(&mut self, desired: &Desired, object: &Wanted<'a>) -> Decision {
        let Some(Some(group)) = desired.references.get("group") else {
            return Decision::Create;
        };
        let source = object.reporters.first().map_or(desired.source.as_str(), |facts| facts.name.as_str());
        let (label, group_name) = (desired.identity.label(), group.identity.label());
        let index = match self.lookup(&(group.kind, group.identity.key().to_vec())) {
            Lookup::One(index) => index,
            unusable => {
                let why = match unusable {
                    Lookup::Many(_) => "is the name of several VLAN groups of NetBox",
                    _ => "is not in NetBox",
                };
                self.errors
                    .push(format!("{source}: vlan {label}: VLAN group {group_name} {why}; the VLAN is not created"));
                return Decision::Skip;
            }
        };
        let group_id = self.current[index].id;
        // A VLAN of the group that also has a site is identified by its site,
        // so it is not found here; NetBox would refuse a second VLAN of that
        // number in the group, and would refuse the one it has on an
        // interface of another site.
        let vid = desired.fields.get("vid").and_then(Value::as_u64);
        let sited = self.current.iter().find(|object| {
            object.kind == Kind::Vlan
                && nested_id(&object.row, "group") == Some(group_id)
                && object.row.get("vid").and_then(Value::as_u64) == vid
                && nested_id(&object.row, "site").is_some()
        });
        if let Some(sited) = sited {
            let site = sited.row.get("site").and_then(|site| site.get("name")).and_then(Value::as_str);
            self.errors.push(format!(
                "{source}: vlan {label}: VLAN {label} of VLAN group {group_name} also has the site {}, and a VLAN \
                 several sites share has none: clear its site; the VLAN is not created",
                site.unwrap_or("?")
            ));
            return Decision::Skip;
        }
        let name = desired.create_only.get("name").or_else(|| desired.fields.get("name")).and_then(Value::as_str);
        let Some(name) = name else {
            return Decision::Create;
        };
        let named = |object: &&Current| {
            object.kind == Kind::Vlan
                && nested_id(&object.row, "group") == Some(group_id)
                && object.row.get("name").and_then(Value::as_str) == Some(name)
        };
        let held = self.current.iter().find(named).map(|object| object.identity.label().to_owned());
        let taken = held.or_else(|| self.vlan_names.get(&(group_id, name.to_owned())).cloned());
        if let Some(other) = taken {
            self.errors.push(format!(
                "{source}: vlan {label}: its name {name} is the one of VLAN {other} in VLAN group {group_name}; \
                 the VLAN is not created"
            ));
            return Decision::Skip;
        }
        self.vlan_names.insert((group_id, name.to_owned()), label.to_owned());
        Decision::Create
    }

    /// Decides, in dependency order, what each reported object is in NetBox.
    fn decide(&mut self, wanted: &BTreeMap<Key, Wanted<'a>>) {
        self.recognise(wanted);
        for (key, object) in wanted {
            let desired: &Desired = &object.content;
            let what = describe_desired(desired);
            let parent = parent_key(desired);
            let orphaned_by = match &parent {
                None => None,
                Some(parent) => match self.decisions.get(parent) {
                    Some(Decision::Skip) => Some(None),
                    Some(_) => None,
                    // Not reported in this run: it must at least be in NetBox.
                    None => match self.lookup(parent) {
                        Lookup::One(_) => None,
                        Lookup::None => Some(Some("is neither in NetBox nor reported")),
                        Lookup::Many(_) => Some(Some("matches several NetBox objects")),
                    },
                },
            };
            let decision = if let Some(reason) = orphaned_by {
                if let (Some(reason), Some((kind, _))) = (reason, &parent) {
                    self.warn(&desired.source, format!("{what}: its {} {reason}; skipped", kind.label()));
                }
                Decision::Skip
            } else if desired.kind == Kind::IpAddress {
                self.decide_ip(desired, parent.as_ref())
            } else if let Some(&index) = self.recognised.get(key) {
                // Known under another name: it is in NetBox, whatever
                // `create_devices` says of the ones that are not.
                Decision::Match(index)
            } else if let Some(renamed) = self.completed_under_its_old_name(key, object) {
                // The object an owner renames in this run: it is never written twice.
                let text = format!(
                    "{what}: renamed {renamed} by this run, and {} only completes it under the name it had; skipped",
                    desired.source
                );
                self.warn(&desired.source, text);
                Decision::Skip
            } else {
                let base = (desired.kind, desired.identity.key().to_vec());
                match self.lookup(&base) {
                    Lookup::One(index) => Decision::Match(index),
                    // Nobody owns it: there is nothing to complete.
                    Lookup::None if object.complement_only => {
                        let text = format!(
                            "{what}: not in NetBox, and {} only completes an object that exists; skipped",
                            desired.source
                        );
                        self.warn(&desired.source, text);
                        Decision::Skip
                    }
                    Lookup::None if desired.kind == Kind::Device && !object.reporters[0].create_devices => {
                        let text = format!(
                            "{what}: not in NetBox and create_devices is off for {}; skipped with its dependents",
                            object.reporters[0].name
                        );
                        self.warn(&object.reporters[0].name, text);
                        Decision::Skip
                    }
                    Lookup::None => Decision::Create,
                    Lookup::Many(indexes) => {
                        let ids: Vec<String> =
                            indexes.iter().map(|&index| self.current[index].id.to_string()).collect();
                        let text = format!(
                            "{what}: {} objects in NetBox have this identity (ids {}); skipped with its dependents",
                            ids.len(),
                            ids.join(", ")
                        );
                        self.warn(&desired.source, text);
                        Decision::Skip
                    }
                }
            };
            let decision = match decision {
                Decision::Create if desired.kind == Kind::Vlan => self.vlan_creation(desired, object),
                decided => decided,
            };
            match decision {
                Decision::Match(index) => {
                    self.claimed.insert(index);
                }
                // Whatever NetBox has under that identity is reported, only not
                // written: it is not an orphan.
                Decision::Skip => {
                    let base = (desired.kind, desired.identity.key().to_vec());
                    self.spoken_for.extend(self.candidates(&base));
                }
                Decision::Create => {}
            }
            self.decisions.insert(key.clone(), decision);
        }
    }

    fn resolve(&self, target: &Target, referrer: &Desired) -> Resolution {
        let base = (target.kind, target.identity.key().to_vec());
        let holder = holder(referrer.kind, referrer.identity.key());
        let key =
            if target.kind == Kind::IpAddress { scoped(target.identity.key(), holder.as_ref()) } else { base.clone() };
        match self.decisions.get(&key) {
            Some(Decision::Match(index)) => return Resolution::Existing(self.current[*index].id),
            Some(Decision::Create) => return Resolution::Created,
            Some(Decision::Skip) => return Resolution::Skipped,
            None => {}
        }
        if target.kind == Kind::IpAddress {
            // Not reported under that holder: an address NetBox has on it already.
            let holder = holder.and_then(|key| self.matched(&key)).map(|object| (object.kind, object.id));
            let held = self
                .candidates(&base)
                .into_iter()
                .find(|&index| holder.is_some() && self.holder_of(&self.current[index]) == holder);
            return held.map_or(Resolution::Missing, |index| Resolution::Existing(self.current[index].id));
        }
        match self.lookup(&base) {
            Lookup::One(index) => Resolution::Existing(self.current[index].id),
            Lookup::None => Resolution::Missing,
            Lookup::Many(_) => Resolution::Ambiguous,
        }
    }

    /// Resolves a reference; `None`, with a warning, when it cannot be: the
    /// field is then left as NetBox has it rather than cleared.
    fn link(&mut self, desired: &Desired, field: &str, target: &Target) -> Option<Link> {
        let id = match self.resolve(target, desired) {
            Resolution::Existing(id) => Some(id),
            Resolution::Created => None,
            unresolved => {
                let reason = match unresolved {
                    Resolution::Skipped => "is skipped",
                    Resolution::Ambiguous => "matches several NetBox objects",
                    _ => "is neither in NetBox nor reported",
                };
                let text = format!(
                    "{}: {field} refers to {} {}, which {reason}; field left untouched",
                    describe_desired(desired),
                    target.kind.label(),
                    target.identity.label()
                );
                self.warn(&desired.source, text);
                return None;
            }
        };
        Some(Link { kind: target.kind, identity: target.identity.clone(), id })
    }

    /// The tags an object must carry, given the ones it has.
    ///
    /// Kept: every tag that is neither an ownership tag nor a tag that came
    /// from a source. Removed: the tags of the old tools (adoption), the tag
    /// of a source that ran to the end without reporting the object, and a
    /// source-made tag the object no longer has in its source.
    fn tags(&self, current: &[Tag], reporters: &[&SourceFacts], reported: Option<&BTreeSet<String>>) -> Vec<String> {
        let reported_names: BTreeSet<String> = reported.into_iter().flatten().map(|name| name.to_lowercase()).collect();
        let mut names = Vec::new();
        let mut slugs = BTreeSet::new();
        for tag in current {
            let keep = if tag.slug == TOOL_TAG {
                true
            } else if let Some(facts) = self.by_tag.get(tag.slug.as_str()) {
                facts.status != SourceStatus::Succeeded || reporters.iter().any(|reporter| reporter.name == facts.name)
            } else if LEGACY_TAGS.contains(&tag.slug.as_str()) || tag.slug.starts_with(SOURCE_TAG_PREFIX) {
                false
            } else {
                let name = tag.name.to_lowercase();
                reported.is_none() || reported_names.contains(&name) || !self.source_tag_names.contains(&name)
            };
            if keep {
                names.push(tag.name.clone());
                slugs.insert(tag.slug.as_str());
            }
        }
        let mut wanted = names.clone();
        let ownership = std::iter::once(TOOL_TAG).chain(reporters.iter().map(|facts| facts.tag.as_str()));
        let name_of = |slug: &str| self.tag_names.get(slug).cloned().unwrap_or_else(|| slug.to_owned());
        wanted.extend(ownership.filter(|slug| !slugs.contains(slug)).map(name_of));
        let held = caseless_set(&names);
        wanted.extend(reported.into_iter().flatten().filter(|name| !held.contains(&name.to_lowercase())).cloned());
        sorted_names(wanted)
    }

    fn step(&mut self, phase: Phase, desired: &Desired, action: Action, id: Option<u64>, writes: Writes) {
        let mut change = Change::new(desired.kind.label(), action, owner_of(desired), desired.identity.label());
        change.fields = writes.fields;
        change.before = writes.before;
        change.id = id;
        self.steps.push(Step {
            phase,
            kind: desired.kind,
            identity: desired.identity.clone(),
            change,
            references: writes.references,
            reference_lists: writes.reference_lists,
        });
    }

    /// What a row points to through a reference field: the content type (of a
    /// generic relation only) and the id; `None` when the field is empty.
    fn held_reference<'r>(row: &'r Row, kind: Kind, field: &str) -> Option<(&'r str, u64)> {
        if kind.generic_fields().contains(&field) {
            let content_type = row.get(&format!("{field}_type")).and_then(Value::as_str);
            let id = row.get(&format!("{field}_id")).and_then(Value::as_u64);
            content_type.zip(id)
        } else {
            nested_id(row, field).map(|id| ("", id))
        }
    }

    /// Whether the row already points where a reference says.
    fn points_to(row: &Row, kind: Kind, field: &str, link: Option<&Link>) -> bool {
        let generic = kind.generic_fields().contains(&field);
        let held = Self::held_reference(row, kind, field);
        match (link, held) {
            (None, None) => true,
            (Some(Link { kind: target, id: Some(id), .. }), Some((content_type, held))) => {
                *id == held && (!generic || content_type == target.content_type())
            }
            _ => false,
        }
    }

    /// Writes one reported object: its creation, or the update of what differs.
    fn write(&mut self, key: &Key, object: &Wanted<'a>) {
        let desired: &Desired = &object.content;
        let existing = match self.decisions.get(key) {
            Some(Decision::Match(index)) => Some(&self.current[*index]),
            Some(Decision::Create) => None,
            _ => return,
        };
        if let Some(existing) = existing {
            if !object.unknown.is_empty() {
                self.unknown_at.insert((existing.kind, existing.id), object.unknown.clone());
            }
            // The source says nothing of this field, or only fills it when it
            // is empty: what NetBox has there is still in use, and its target
            // is no orphan.
            for (field, target) in desired.kind.reference_fields() {
                let reported = desired.references.contains_key(*field) || desired.fields.contains_key(*field);
                if (!reported || desired.only_when_empty.contains(*field))
                    && let Some(id) = nested_id(&existing.row, field)
                {
                    self.pointed_at.insert((*target, id));
                }
            }
            // The same of a list the source says nothing of (the tagged VLANs
            // of an interface): what NetBox lists there is still in use.
            for (field, target) in desired.kind.reference_list_fields() {
                if !desired.reference_lists.contains_key(*field) {
                    self.pointed_at.extend(listed_ids(&existing.row, field).map(|id| (*target, id)));
                }
            }
            if object.ensure_only && !self.owned(existing) {
                return;
            }
            // A run of both sources would have had this report lose as a whole
            // and only add its tag: a source that runs apart (another host,
            // another kind) writes no more, or each would write its values
            // over the other's at every run. What the object points to is
            // still in use. A report another source completes is written as
            // before: what completes it is not the loser's to drop.
            if let Some(&winner) = object.reporters.first()
                && !object.completed
                && self.held_by_a_better_source(existing, winner)
            {
                for (field, target) in desired.kind.reference_fields() {
                    if let Some(id) = nested_id(&existing.row, field) {
                        self.pointed_at.insert((*target, id));
                    }
                }
                for (field, target) in desired.kind.reference_list_fields() {
                    self.pointed_at.extend(listed_ids(&existing.row, field).map(|id| (*target, id)));
                }
                let mut now = Writes::default();
                if desired.kind.taggable() {
                    let held: Vec<String> = existing.tags.iter().map(|tag| tag.name.clone()).collect();
                    let wanted = self.tags(&existing.tags, &object.reporters, None);
                    if caseless_set(&wanted) != caseless_set(&held) {
                        now.fields.insert("tags".to_owned(), json!(wanted));
                        now.before.insert("tags".to_owned(), json!(sorted_names(held)));
                        self.step(Phase::Write, desired, Action::Update, Some(existing.id), now);
                    }
                }
                return;
            }
        }
        let row = existing.map(|existing| &existing.row);
        let mut now = Writes::default();
        let mut later = Writes::default();
        for (name, value) in &desired.fields {
            let held = row.and_then(|row| row.get(name)).unwrap_or(&Value::Null);
            // Somebody chose that value: it is neither overwritten nor a difference.
            if row.is_some() && desired.only_when_empty.contains(name) && !is_empty(plain(held)) {
                continue;
            }
            let same = match (desired.kind.caseless_field(), value.as_str(), held.as_str()) {
                (Some(caseless), Some(value), Some(held)) if caseless == name => {
                    value.to_lowercase() == held.to_lowercase()
                }
                _ => same_value(value, held),
            };
            if row.is_none() || !same {
                now.fields.insert(name.clone(), value.clone());
                if row.is_some() {
                    now.before.insert(name.clone(), shown(held));
                }
            }
        }
        if row.is_none() {
            for (name, value) in &desired.create_only {
                now.fields.entry(name.clone()).or_insert_with(|| value.clone());
            }
        }
        for (field, target) in &desired.references {
            // Decided before the target is resolved: a reference that stays as
            // it is has nothing to warn about.
            if let Some(row) = row
                && desired.only_when_empty.contains(field)
                && Self::held_reference(row, desired.kind, field).is_some()
            {
                continue;
            }
            let link = match target {
                Some(target) => match self.link(desired, field, target) {
                    Some(link) => Some(link),
                    None => continue,
                },
                None => None,
            };
            let late = target.as_ref().is_some_and(|target| target.kind.rank() >= desired.kind.rank());
            let writes = if late { &mut later } else { &mut now };
            match row {
                // Nothing to clear on an object that does not exist yet.
                None if link.is_none() => continue,
                None => {}
                Some(row) if Self::points_to(row, desired.kind, field, link.as_ref()) => continue,
                Some(row) => {
                    writes.before.insert(field.clone(), shown_nested(row.get(field).unwrap_or(&Value::Null)));
                }
            }
            let label = link.as_ref().map_or(Value::Null, |link| Value::String(link.identity.label().to_owned()));
            writes.fields.insert(field.clone(), label);
            writes.references.insert(field.clone(), link);
        }
        // Rewritten under another parent: it no longer keeps the one NetBox has it under.
        let parent_field = match desired.kind {
            Kind::Interface => Some("device"),
            Kind::VmInterface | Kind::VirtualDisk => Some("virtual_machine"),
            Kind::MacAddress | Kind::IpAddress => Some("assigned_object"),
            _ => None,
        };
        if let Some(Decision::Match(index)) = self.decisions.get(key)
            && let Some(field) = parent_field
            && (now.references.contains_key(field) || later.references.contains_key(field))
        {
            self.moved.insert(*index);
        }
        for (field, targets) in &desired.reference_lists {
            let links: Vec<Link> = targets.iter().filter_map(|target| self.link(desired, field, target)).collect();
            // One target short: the list is left as it is rather than truncated.
            if links.len() != targets.len() {
                continue;
            }
            let held =
                row.and_then(|row| row.get(field)).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
            if row.is_some() {
                let held_ids: BTreeSet<Option<u64>> =
                    held.iter().map(|item| item.get("id").and_then(Value::as_u64).or(item.as_u64())).collect();
                let wanted_ids: BTreeSet<Option<u64>> = links.iter().map(|link| link.id).collect();
                if held_ids == wanted_ids && links.iter().all(|link| link.id.is_some()) {
                    continue;
                }
            } else if links.is_empty() {
                continue;
            }
            let late = targets.iter().any(|target| target.kind.rank() >= desired.kind.rank());
            let writes = if late { &mut later } else { &mut now };
            if row.is_some() {
                let mut names: Vec<Value> = held.iter().map(shown_nested).collect();
                names.sort_by_key(Value::to_string);
                writes.before.insert(field.clone(), Value::Array(names));
            }
            let labels = links.iter().map(|link| Value::String(link.identity.label().to_owned())).collect();
            writes.fields.insert(field.clone(), Value::Array(labels));
            writes.reference_lists.insert(field.clone(), links);
        }
        let held_custom = row.and_then(|row| row.get("custom_fields")).and_then(Value::as_object);
        let mut custom = Map::new();
        let mut custom_before = Map::new();
        for (name, value) in &desired.custom_fields {
            let held = held_custom.and_then(|custom| custom.get(name)).unwrap_or(&Value::Null);
            if row.is_none() || !same_value(value, held) {
                custom.insert(name.clone(), value.clone());
                custom_before.insert(name.clone(), shown(held));
            }
        }
        if !custom.is_empty() {
            now.fields.insert("custom_fields".to_owned(), Value::Object(custom));
            if row.is_some() {
                now.before.insert("custom_fields".to_owned(), Value::Object(custom_before));
            }
        }
        // An object nobody owns keeps its tags: completing it is not adopting it.
        if desired.kind.taggable() && !object.complement_only {
            let held = existing.map(|existing| existing.tags.as_slice()).unwrap_or_default();
            let held_names: Vec<String> = held.iter().map(|tag| tag.name.clone()).collect();
            let wanted = self.tags(held, &object.reporters, desired.tags.as_ref());
            if row.is_none() || caseless_set(&wanted) != caseless_set(&held_names) {
                now.fields.insert("tags".to_owned(), json!(wanted));
                if row.is_some() {
                    now.before.insert("tags".to_owned(), json!(sorted_names(held_names)));
                }
            }
        }
        let id = existing.map(|existing| existing.id);
        match existing {
            None => self.step(Phase::Write, desired, Action::Create, None, now),
            Some(_) if !now.fields.is_empty() => self.step(Phase::Write, desired, Action::Update, id, now),
            Some(_) => {}
        }
        if !later.fields.is_empty() {
            self.step(Phase::Link, desired, Action::Update, id, later);
        }
    }

    /// Whether the source of an ancestor said it could not read objects of this kind.
    fn unknown_to_its_source(&self, object: &Current) -> bool {
        let mut above = object.parent;
        // A parent chain is three objects deep at most; the bound stops a loop in bad data.
        for _ in 0..8 {
            let Some(parent) = above else {
                return false;
            };
            if self.unknown_at.get(&parent).is_some_and(|kinds| kinds.contains(&object.kind)) {
                return true;
            }
            above = self.by_id.get(&parent).and_then(|&index| self.current[index].parent);
        }
        false
    }

    /// How many parents an interface has above it.
    fn depth(&self, object: &Current) -> usize {
        let mut depth = 0;
        let mut above = nested_id(&object.row, "parent");
        while let Some(parent) = above
            && depth < 8
        {
            depth += 1;
            above =
                self.by_id.get(&(object.kind, parent)).and_then(|&index| nested_id(&self.current[index].row, "parent"));
        }
        depth
    }

    /// Deletes, or releases, what a source that ran to the end no longer reports.
    fn orphans(&mut self) {
        let unmatched: Vec<usize> = (0..self.current.len())
            .filter(|index| !self.claimed.contains(index) && !self.spoken_for.contains(index))
            .collect();
        // The prefixes of the addresses kept because their machine could not be
        // read: the source would have reported them from those very addresses.
        let kept_networks: BTreeSet<(String, String)> = unmatched
            .iter()
            .map(|&index| &self.current[index])
            .filter(|object| object.kind == Kind::IpAddress && self.unknown_to_its_source(object))
            .filter_map(|object| {
                let network = network(object.row.get("address")?.as_str()?)?;
                Some((network, object.identity.key().get(1)?.clone()))
            })
            .collect();
        let mut doomed = BTreeSet::new();
        for index in unmatched {
            let object = &self.current[index];
            let sources: Vec<&SourceFacts> =
                object.tags.iter().filter_map(|tag| self.by_tag.get(tag.slug.as_str()).copied()).collect();
            // An old tool that still claims the object may still be running.
            let shared_with_an_old_tool = object.tags.iter().any(|tag| {
                !self.by_tag.contains_key(tag.slug.as_str())
                    && (LEGACY_TAGS.contains(&tag.slug.as_str()) || tag.slug.starts_with(SOURCE_TAG_PREFIX))
            });
            // Only a source that ran to the end can say an object is gone: one
            // left out of the run, or failed, said nothing.
            let gone: Vec<&SourceFacts> =
                sources.iter().copied().filter(|facts| facts.status == SourceStatus::Succeeded).collect();
            // Only what this tool tagged itself is its to delete: an object it
            // never adopted may be anyone's, whatever source tag it carries.
            let held_by_this_tool = object.tags.iter().any(|tag| tag.slug == TOOL_TAG);
            if gone.is_empty() || shared_with_an_old_tool || !held_by_this_tool {
                continue;
            }
            let in_kept_network = object.kind == Kind::Prefix
                && object
                    .identity
                    .key()
                    .first()
                    .zip(object.identity.key().get(1))
                    .is_some_and(|(prefix, vrf)| kept_networks.contains(&(prefix.clone(), vrf.clone())));
            if self.unknown_to_its_source(object)
                || self.pointed_at.contains(&(object.kind, object.id))
                || in_kept_network
            {
                continue;
            }
            let released: BTreeSet<&str> =
                gone.iter().filter(|facts| facts.prune).map(|facts| facts.tag.as_str()).collect();
            if released.is_empty() {
                self.orphans_kept.push(describe_current(object));
            } else if released.len() == sources.len() {
                doomed.insert(index);
            } else {
                // Another source still claims it: only the claim of the one that dropped it goes.
                let held: Vec<String> = object.tags.iter().map(|tag| tag.name.clone()).collect();
                let kept = object.tags.iter().filter(|tag| !released.contains(tag.slug.as_str()));
                let mut change =
                    Change::new(object.kind.label(), Action::Update, object.identity.owner(), object.identity.label());
                change
                    .fields
                    .insert("tags".to_owned(), json!(sorted_names(kept.map(|tag| tag.name.clone()).collect())));
                change.before.insert("tags".to_owned(), json!(sorted_names(held)));
                change.id = Some(object.id);
                self.steps.push(Step {
                    phase: Phase::Write,
                    kind: object.kind,
                    identity: object.identity.clone(),
                    change,
                    references: BTreeMap::new(),
                    reference_lists: BTreeMap::new(),
                });
            }
        }
        // What keeps an orphan: a dependent NetBox would delete with it (a child
        // that stays where it is, not one this plan moves elsewhere), or a row
        // this run leaves as it is that still refers to it through a plain
        // foreign key (NetBox refuses the delete, PROTECT, or clears the field
        // without a word, SET_NULL). Built once, then spared up to the top of
        // the chain: sparing an object keeps what it holds as well.
        let order = |index: &usize| (self.current[*index].kind, self.current[*index].id);
        let mut holders: BTreeMap<usize, Vec<(usize, bool)>> = BTreeMap::new();
        for (index, object) in self.current.iter().enumerate() {
            if let Some(&parent) = object.parent.as_ref().and_then(|parent| self.by_id.get(parent))
                && !self.moved.contains(&index)
            {
                holders.entry(parent).or_default().push((index, true));
            }
            // A matched row keeps what it points to through `pointed_at`.
            if self.claimed.contains(&index) {
                continue;
            }
            for (field, target) in object.kind.reference_fields() {
                if let Some(&held) = nested_id(&object.row, field).and_then(|id| self.by_id.get(&(*target, id))) {
                    holders.entry(held).or_default().push((index, false));
                }
            }
            // A list NetBox would take the orphan off without a word (the
            // tagged VLANs of a port) holds it as a foreign key does.
            for (field, target) in object.kind.reference_list_fields() {
                for held in listed_ids(&object.row, field).filter_map(|id| self.by_id.get(&(*target, id))) {
                    holders.entry(*held).or_default().push((index, false));
                }
            }
        }
        // In (kind, id) order: the warnings do not depend on the order NetBox answered in.
        for list in holders.values_mut() {
            list.sort_by_key(|(index, _)| order(index));
        }
        loop {
            let mut candidates: Vec<usize> = doomed.iter().copied().collect();
            candidates.sort_by_key(order);
            let spared = candidates.into_iter().find_map(|orphan| {
                let &(holder, dependent) = holders.get(&orphan)?.iter().find(|(holder, _)| !doomed.contains(holder))?;
                Some((orphan, holder, dependent))
            });
            let Some((orphan, holder, dependent)) = spared else {
                break;
            };
            doomed.remove(&orphan);
            // The source the orphan was held for: the one whose run let it go.
            let source = self.current[orphan]
                .tags
                .iter()
                .find_map(|tag| self.by_tag.get(tag.slug.as_str()))
                .map(|facts| facts.name.clone());
            let (orphan, holder) = (describe_current(&self.current[orphan]), describe_current(&self.current[holder]));
            let text = if dependent {
                format!("{orphan}: not deleted, NetBox would delete {holder} with it")
            } else {
                format!("{orphan}: not deleted, {holder} still refers to it")
            };
            self.warnings.push(Warning { source, text });
        }
        for index in doomed {
            let object = &self.current[index];
            let mut change =
                Change::new(object.kind.label(), Action::Delete, object.identity.owner(), object.identity.label());
            change.id = Some(object.id);
            self.steps.push(Step {
                phase: Phase::Delete,
                kind: object.kind,
                identity: object.identity.clone(),
                change,
                references: BTreeMap::new(),
                reference_lists: BTreeMap::new(),
            });
        }
    }

    /// Orders the steps: writes then links in dependency order, deletions in
    /// the reverse order with a child interface before its parent.
    fn sorted_steps(&mut self) -> Vec<Step> {
        let mut steps = std::mem::take(&mut self.steps);
        steps.sort_by_cached_key(|step| {
            let deletion = step.phase == Phase::Delete;
            let rank = if deletion { Kind::ALL.len() - step.kind.rank() } else { step.kind.rank() };
            let depth = step
                .change
                .id
                .filter(|_| deletion)
                .and_then(|id| self.by_id.get(&(step.kind, id)))
                .map_or(0, |&index| self.depth(&self.current[index]));
            (
                step.phase,
                rank,
                std::cmp::Reverse(depth),
                step.change.device.clone(),
                step.change.key.clone(),
                step.identity.key().to_vec(),
                step.change.id,
            )
        });
        steps
    }
}

/// Compares what the sources ask for with what NetBox holds.
///
/// `desired` is everything the sources of this run reported; `current` is
/// everything NetBox holds of the kinds they may report, whoever owns it;
/// `run` says what became of each configured source.
pub fn reconcile(desired: &[Desired], current: &[Current], run: &Run) -> Plan {
    let mut reconciler = Reconciler::new(current, run);
    let wanted = reconciler.merge(desired);
    reconciler.decide(&wanted);
    for (key, object) in &wanted {
        reconciler.write(key, object);
    }
    reconciler.orphans();
    let steps = reconciler.sorted_steps();
    reconciler.orphans_kept.sort();
    Plan { steps, warnings: reconciler.warnings, orphans_kept: reconciler.orphans_kept, errors: reconciler.errors }
}

/// The most interfaces a warning names; the others are counted.
const NAMED_INTERFACES: usize = 10;

/// The VLANs of a site that nobody owns, whose site keeps its VLANs in a
/// VLAN group that holds the same VLAN: one warning each, with the
/// interfaces that still point to it.
///
/// Such a VLAN is never touched: no tool made it, so it is nobody's orphan.
/// Once its site is in a group it is a leftover, which someone has to move
/// the last interfaces off and delete by hand. A VLAN a tool owns is not told
/// here: the orphan rule deletes it, or says what keeps it.
pub fn site_vlan_leftovers(current: &[Current], groups: &VlanGroups) -> Vec<String> {
    if groups.is_empty() {
        return Vec::new();
    }
    let name = |object: &Current, field: &str| {
        let nested = object.row.get(field).and_then(|nested| nested.get("name")).and_then(Value::as_str);
        nested.map(str::to_lowercase)
    };
    let vid = |object: &Current| object.row.get("vid").and_then(Value::as_u64);
    let vlans = || current.iter().filter(|object| object.kind == Kind::Vlan);
    // The VLANs each group holds for several sites: those that have no site.
    let held: BTreeSet<(String, u64)> = vlans()
        .filter(|object| name(object, "site").is_none())
        .filter_map(|object| Some((name(object, "group")?, vid(object)?)))
        .collect();
    let owned = |object: &Current| {
        object.tags.iter().any(|tag| {
            tag.slug == TOOL_TAG || LEGACY_TAGS.contains(&tag.slug.as_str()) || tag.slug.starts_with(SOURCE_TAG_PREFIX)
        })
    };
    let mut leftovers: Vec<(String, u64, u64, &Current, &str)> = vlans()
        .filter(|object| !owned(object))
        .filter_map(|object| {
            let (site, vid) = (name(object, "site")?, vid(object)?);
            let group = groups.group_of(&site)?;
            held.contains(&(group.to_lowercase(), vid)).then_some((site, vid, object.id, object, group))
        })
        .collect();
    leftovers.sort_by(|left, right| (&left.0, left.1, left.2).cmp(&(&right.0, right.1, right.2)));
    let mut warnings = Vec::new();
    for (_, vid, id, vlan, group) in leftovers {
        let site = vlan.row.get("site").and_then(|site| site.get("name")).and_then(Value::as_str).unwrap_or_default();
        let points = |object: &&Current| {
            matches!(object.kind, Kind::Interface | Kind::VmInterface)
                && (nested_id(&object.row, "untagged_vlan") == Some(id)
                    || listed_ids(&object.row, "tagged_vlans").any(|listed| listed == id))
        };
        let mut users: Vec<String> = current.iter().filter(points).map(describe_current).collect();
        users.sort();
        let what = format!(
            "vlan {vid} of site {site}: VLAN group {group} holds this VLAN, and nobody owns the one of the site"
        );
        warnings.push(if users.is_empty() {
            format!("{what}; no interface points to it any more: delete it by hand")
        } else {
            let more = match users.len().saturating_sub(NAMED_INTERFACES) {
                0 => String::new(),
                more => format!(", and {more} more"),
            };
            let named: Vec<&str> = users.iter().take(NAMED_INTERFACES).map(String::as_str).collect();
            format!(
                "{what}; {} interface(s) still point to it ({}{more}): move them, then delete it by hand",
                users.len(),
                named.join(", ")
            )
        });
    }
    warnings
}

/// Whether a tag description carries `marker`: the whole description, or the
/// marker followed by `: ` and the description the source gave the tag. Text
/// that merely starts like it ("netbox-omnisync-legacy notes") is somebody's.
fn is_marked(description: &str, marker: &str) -> bool {
    !marker.is_empty() && description.strip_prefix(marker).is_some_and(|rest| rest.is_empty() || rest.starts_with(": "))
}

/// The name of each tag NetBox holds, by slug.
fn tag_names_by_slug(current: &[Current]) -> BTreeMap<String, String> {
    let text = |object: &Current, key: &str| object.row.get(key).and_then(Value::as_str).map(str::to_owned);
    let tags = current.iter().filter(|object| object.kind == Kind::Tag);
    tags.filter_map(|tag| Some((text(tag, "slug")?, text(tag, "name")?))).collect()
}

/// The ownership tags the run attaches and NetBox does not hold yet: the tag
/// of the tool and the tag of each source that was read, named after their
/// slug. A tag NetBox already holds under that slug is left as it is, whatever
/// its name: the tools this one replaces named theirs `Source: <name>`, and
/// NetBox refuses a second tag of the same slug.
pub fn ownership_tags(run: &Run, current: &[Current]) -> Vec<Desired> {
    let held = tag_names_by_slug(current);
    let mut asked = BTreeSet::new();
    let mut tags = Vec::new();
    for facts in run.sources.iter().filter(|facts| facts.status.reports()) {
        for slug in [TOOL_TAG, facts.tag.as_str()] {
            if !held.contains_key(slug) && asked.insert(slug) {
                let tag = Desired::new(Kind::Tag, Identity::named(slug), &facts.name);
                tags.push(tag.field("name", slug).create_only("slug", slug).ensure_only());
            }
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use crate::inventory::identity::current_objects;
    use crate::inventory::model::{VlanGroups, VlanScope, VrfKey};

    use super::*;
    use crate::inventory::custom_fields::{self, Definition, FieldType};

    const PVE: &str = "pve1";

    /// Custom fields of the tests alone: a field is reconciled whatever its name.
    static UUID: Definition = Definition { name: "uuid", field_type: FieldType::Text, label: "UUID", description: "" };
    static VMID: Definition = Definition { name: "vmid", field_type: FieldType::Text, label: "VMID", description: "" };

    fn row(value: Value) -> Row {
        value.as_object().cloned().expect("a JSON object")
    }

    /// The current state for hand-written rows, as the loader would build it.
    fn netbox<const N: usize>(rows: [(Kind, Value); N]) -> Vec<Current> {
        let mut by_kind: BTreeMap<Kind, Vec<Row>> = BTreeMap::new();
        for (kind, value) in rows {
            by_kind.entry(kind).or_default().push(row(value));
        }
        let (current, warnings) = current_objects(&by_kind);
        assert_eq!(warnings, Vec::<String>::new());
        current
    }

    /// Nested tags whose name is their slug.
    fn tagged<const N: usize>(slugs: [&str; N]) -> Value {
        Value::Array(slugs.iter().map(|slug| json!({"id": 1, "name": slug, "slug": slug})).collect())
    }

    fn owned_by(source: &str) -> Value {
        json!([
            {"id": 1, "name": "netbox-omnisync", "slug": "netbox-omnisync"},
            {"id": 2, "name": format!("source-{source}"), "slug": format!("source-{source}")}
        ])
    }

    fn source(name: &str) -> SourceFacts {
        SourceFacts {
            name: name.to_owned(),
            tag: format!("source-{name}"),
            status: SourceStatus::Succeeded,
            prune: false,
            create_devices: true,
        }
    }

    fn pruning(name: &str) -> SourceFacts {
        SourceFacts { prune: true, ..source(name) }
    }

    fn run<const N: usize>(sources: [SourceFacts; N]) -> Run {
        Run {
            priority: sources.iter().map(|facts| facts.name.clone()).collect(),
            sources: sources.into(),
            unique_ip_vrfs: BTreeSet::new(),
            source_tag_markers: vec!["netbox-omnisync".to_owned(), "NetBox-synced".to_owned()],
        }
    }

    fn change(kind: &str, action: Action, device: &str, key: &str) -> Change {
        Change::new(kind, action, device, key)
    }

    fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Fields {
        pairs.into_iter().map(|(key, value)| (key.to_owned(), value)).collect()
    }

    fn nothing() -> Plan {
        Plan::default()
    }

    fn cluster_row() -> (Kind, Value) {
        (Kind::Cluster, json!({"id": 3, "name": "pve", "tags": []}))
    }

    /// A virtual machine the way NetBox 4.5 to 4.7 render it.
    fn vm_row(id: u64, name: &str, tags: Value) -> (Kind, Value) {
        (
            Kind::VirtualMachine,
            json!({
                "id": id, "name": name, "status": {"value": "active", "label": "Active"},
                "cluster": {"id": 3, "name": "pve", "display": "pve"},
                "vcpus": 2.0, "memory": 4096, "comments": "", "platform": null, "primary_ip4": null,
                "custom_fields": {"owner_team": "web", "uuid": null}, "tags": tags
            }),
        )
    }

    fn vm_identity(name: &str) -> Identity {
        Identity::virtual_machine(name, "pve")
    }

    /// The same virtual machine the way a source reports it.
    fn vm(name: &str, source: &str) -> Desired {
        Desired::new(Kind::VirtualMachine, vm_identity(name), source)
            .field("name", name)
            .field("status", "active")
            .field("vcpus", 2)
            .field("memory", 4096)
            .reference("cluster", Kind::Cluster, Identity::named("pve"))
    }

    fn nic_row(id: u64, vm_id: u64, vm_name: &str, name: &str, tags: Value) -> (Kind, Value) {
        (
            Kind::VmInterface,
            json!({
                "id": id, "name": name, "enabled": true, "parent": null,
                "virtual_machine": {"id": vm_id, "name": vm_name}, "tags": tags
            }),
        )
    }

    fn nic(vm_name: &str, name: &str, source: &str) -> Desired {
        Desired::new(Kind::VmInterface, Identity::vm_interface(&vm_identity(vm_name), name), source)
            .field("name", name)
            .field("enabled", true)
            .reference("virtual_machine", Kind::VirtualMachine, vm_identity(vm_name))
    }

    fn ip_row(
        id: u64,
        address: &str,
        nic_id: Option<u64>,
        nic_name: &str,
        vm_name: &str,
        tags: Value,
    ) -> (Kind, Value) {
        let assigned = match nic_id {
            Some(nic_id) => json!({
                "id": nic_id, "name": nic_name, "display": nic_name, "virtual_machine": {"id": 1, "name": vm_name}
            }),
            None => Value::Null,
        };
        (
            Kind::IpAddress,
            json!({
                "id": id, "address": address, "vrf": null,
                "assigned_object_type": nic_id.map(|_| "virtualization.vminterface"),
                "assigned_object_id": nic_id, "assigned_object": assigned, "tags": tags
            }),
        )
    }

    fn ip(address: &str, vm_name: &str, nic_name: &str, source: &str) -> Desired {
        Desired::new(Kind::IpAddress, Identity::ip_address(address, VrfKey::Unknown), source)
            .field("address", address)
            .reference("assigned_object", Kind::VmInterface, Identity::vm_interface(&vm_identity(vm_name), nic_name))
    }

    fn device_row(id: u64, name: &str, site_id: u64, tags: Value) -> (Kind, Value) {
        (
            Kind::Device,
            json!({
                "id": id, "name": name, "site": {"id": site_id, "name": format!("site{site_id}")},
                "status": {"value": "active", "label": "Active"}, "tags": tags
            }),
        )
    }

    fn device(name: &str, source: &str) -> Desired {
        Desired::new(Kind::Device, Identity::device(name), source).field("name", name).field("status", "active")
    }

    fn pnic_row(id: u64, device_id: u64, device_name: &str, name: &str, tags: Value) -> (Kind, Value) {
        (
            Kind::Interface,
            json!({"id": id, "name": name, "parent": null, "device": {"id": device_id, "name": device_name}, "tags": tags}),
        )
    }

    fn pnic(device_name: &str, name: &str, source: &str) -> Desired {
        Desired::new(Kind::Interface, Identity::interface(device_name, name), source).field("name", name).reference(
            "device",
            Kind::Device,
            Identity::device(device_name),
        )
    }

    // Field comparison

    #[test]
    fn a_choice_field_equals_its_value() {
        assert!(same_value(&json!("active"), &json!({"value": "active", "label": "Active"})));
        assert!(!same_value(&json!("offline"), &json!({"value": "active", "label": "Active"})));
    }

    #[test]
    fn a_number_equals_its_other_renderings() {
        assert!(same_value(&json!(2), &json!(2.0)));
        assert!(same_value(&json!(1), &json!("1.0")));
        assert!(same_value(&json!("1.00"), &json!(1)));
        assert!(!same_value(&json!(2), &json!(3.0)));
        // Two texts are compared as texts: `10` and `10.0` may be two names.
        assert!(!same_value(&json!("10"), &json!("10.0")));
    }

    #[test]
    fn null_equals_an_empty_text_or_list_and_nothing_else() {
        assert!(same_value(&json!(""), &Value::Null));
        assert!(same_value(&Value::Null, &json!("")));
        assert!(same_value(&json!([]), &Value::Null));
        assert!(!same_value(&json!("web"), &Value::Null));
        assert!(!same_value(&Value::Null, &json!("web")));
        // `false` is a value: an interface disabled on the host is not "unknown".
        assert!(!same_value(&json!(false), &Value::Null));
        assert!(!same_value(&json!(0), &Value::Null));
    }

    // Creation and update

    #[test]
    fn a_missing_object_is_created_with_its_fields_create_only_fields_and_ownership_tags() {
        let platform = Desired::new(Kind::Platform, Identity::named("Debian 12"), PVE)
            .field("name", "Debian 12")
            .create_only("slug", "debian-12");
        let plan = reconcile(&[platform], &[], &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("platform", Action::Create, "", "Debian 12").fields([
                ("name", json!("Debian 12")),
                ("slug", json!("debian-12")),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
            ])]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn a_created_object_refers_to_an_existing_one_by_its_name_and_its_id() {
        let wanted = vm("web01", PVE).custom_field(&UUID, "42d0").tags(["service-apache"]);
        let plan = reconcile(&[wanted], &netbox([cluster_row()]), &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Create, "web01", "web01").fields([
                ("cluster", json!("pve")),
                ("custom_fields", json!({"uuid": "42d0"})),
                ("memory", json!(4096)),
                ("name", json!("web01")),
                ("status", json!("active")),
                ("tags", json!(["netbox-omnisync", "service-apache", "source-pve1"])),
                ("vcpus", json!(2)),
            ])]
        );
        assert_eq!(plan.steps[0].phase, Phase::Write);
        assert_eq!(plan.steps[0].kind, Kind::VirtualMachine);
        assert_eq!(plan.steps[0].identity, vm_identity("web01"));
        assert_eq!(
            plan.steps[0].references,
            BTreeMap::from([(
                "cluster".to_owned(),
                Some(Link { kind: Kind::Cluster, identity: Identity::named("pve"), id: Some(3) })
            )])
        );
    }

    #[test]
    fn a_reference_to_an_object_created_in_the_same_run_carries_no_id() {
        let cluster = Desired::new(Kind::Cluster, Identity::named("pve-new"), PVE).field("name", "pve-new");
        let wanted = Desired::new(Kind::VirtualMachine, Identity::virtual_machine("web01", "pve-new"), PVE)
            .field("name", "web01")
            .reference("cluster", Kind::Cluster, Identity::named("pve-new"));
        // Given in the wrong order: the output follows the dependency order.
        let plan = reconcile(&[wanted, cluster], &[], &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [
                change("cluster", Action::Create, "", "pve-new")
                    .fields([("name", json!("pve-new")), ("tags", json!(["netbox-omnisync", "source-pve1"]))]),
                change("vm", Action::Create, "web01", "web01").fields([
                    ("cluster", json!("pve-new")),
                    ("name", json!("web01")),
                    ("tags", json!(["netbox-omnisync", "source-pve1"])),
                ]),
            ]
        );
        assert_eq!(
            plan.steps[1].references["cluster"],
            Some(Link { kind: Kind::Cluster, identity: Identity::named("pve-new"), id: None })
        );
    }

    #[test]
    fn only_the_differing_managed_fields_are_updated_with_their_previous_values() {
        let current = netbox([cluster_row(), vm_row(10, "web01", owned_by(PVE))]);
        let wanted = vm("web01", PVE).field("vcpus", 4).field("memory", 8192);
        let plan = reconcile(&[wanted], &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("memory", json!(8192)), ("vcpus", json!(4))])
                .before([("memory", json!(4096)), ("vcpus", json!(2.0))])
                .id(10)]
        );
    }

    #[test]
    fn an_unreported_field_is_untouched_while_an_empty_one_clears() {
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["comments"] = json!("do not reboot before 8pm");
        value["description"] = json!("old description");
        let current = netbox([cluster_row(), (kind, value)]);
        // `comments` is not reported; `description` is reported empty.
        let wanted = vm("web01", PVE).field("description", "");
        let plan = reconcile(&[wanted], &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("description", json!(""))])
                .before([("description", json!("old description"))])
                .id(10)]
        );
    }

    #[test]
    fn a_create_only_field_is_not_patched() {
        let current =
            netbox([(Kind::Platform, json!({"id": 8, "name": "Debian 12", "slug": "debian", "tags": owned_by(PVE)}))]);
        let platform = Desired::new(Kind::Platform, Identity::named("Debian 12"), PVE)
            .field("name", "Debian 12")
            .create_only("slug", "debian-12");
        assert_eq!(reconcile(&[platform], &current, &run([source(PVE)])), nothing());
    }

    #[test]
    fn a_difference_of_case_alone_on_the_identifying_name_is_not_a_change() {
        let current = netbox([
            (Kind::Site, json!({"id": 1, "name": "HARBOR", "slug": "jag", "tags": owned_by(PVE)})),
            device_row(12, "esx01", 1, owned_by(PVE)),
            pnic_row(30, 12, "esx01", "Port-Channel1", owned_by(PVE)),
        ]);
        let site = Desired::new(Kind::Site, Identity::named("Harbor"), PVE).field("name", "Harbor");
        let wanted = [site, device("esx01", PVE), pnic("esx01", "port-channel1", PVE)];
        assert_eq!(reconcile(&wanted, &current, &run([source(PVE)])), nothing());
    }

    #[test]
    fn a_device_or_a_virtual_machine_named_in_another_case_is_the_one_netbox_has() {
        // NetBox refuses a second `Web01` next to `web01`: creating it would stop the run.
        let current = netbox([
            cluster_row(),
            device_row(12, "esx01", 1, owned_by(PVE)),
            pnic_row(30, 12, "esx01", "vmnic0", owned_by(PVE)),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
        ]);
        let wanted = [device("ESX01", PVE), pnic("ESX01", "vmnic0", PVE), vm("Web01", PVE), nic("Web01", "eth0", PVE)];
        assert_eq!(reconcile(&wanted, &current, &run([pruning(PVE)])), nothing());
    }

    #[test]
    fn a_virtual_machine_named_in_another_case_is_updated_never_created() {
        let current = netbox([cluster_row(), vm_row(10, "web01", owned_by(PVE))]);
        let plan = reconcile(&[vm("Web01", PVE).field("vcpus", 4)], &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "Web01", "Web01")
                .fields([("vcpus", json!(4))])
                .before([("vcpus", json!(2.0))])
                .id(10)]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    // Fields written only when NetBox holds none

    /// `web01` with one interface and two addresses on it, the second one
    /// (id 71) entered by hand.
    fn with_two_addresses(primary: Value) -> Vec<Current> {
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["primary_ip4"] = primary;
        netbox([
            cluster_row(),
            (kind, value),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", Some(40), "eth0", "web01", owned_by(PVE)),
            ip_row(71, "10.0.0.9/24", Some(40), "eth0", "web01", tagged([])),
        ])
    }

    fn with_a_primary_ip_when_none() -> [Desired; 3] {
        let address = Identity::ip_address("10.0.0.5/24", VrfKey::Unknown);
        [
            vm("web01", PVE).reference("primary_ip4", Kind::IpAddress, address).only_when_empty("primary_ip4"),
            nic("web01", "eth0", PVE),
            ip("10.0.0.5/24", "web01", "eth0", PVE),
        ]
    }

    #[test]
    fn a_reference_written_only_when_empty_is_written_when_netbox_has_none() {
        let plan = reconcile(&with_a_primary_ip_when_none(), &with_two_addresses(Value::Null), &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("primary_ip4", json!("10.0.0.5/24"))])
                .before([("primary_ip4", Value::Null)])
                .id(10)]
        );
        assert_eq!(plan.steps[0].phase, Phase::Link);
        assert_eq!(plan.steps[0].references["primary_ip4"].as_ref().and_then(|link| link.id), Some(70));
    }

    #[test]
    fn a_reference_written_only_when_empty_is_left_alone_when_netbox_has_another() {
        let by_hand = json!({"id": 71, "address": "10.0.0.9/24", "display": "10.0.0.9/24"});
        let plan = reconcile(&with_a_primary_ip_when_none(), &with_two_addresses(by_hand), &run([source(PVE)]));
        assert_eq!(plan, nothing());
    }

    #[test]
    fn a_reference_written_only_when_empty_and_already_set_is_not_even_resolved() {
        // The target is unknown: without the mode this is a warning.
        let ghost = Identity::ip_address("10.0.0.77/24", VrfKey::Unknown);
        let mut wanted = with_a_primary_ip_when_none();
        wanted[0] = vm("web01", PVE).reference("primary_ip4", Kind::IpAddress, ghost).only_when_empty("primary_ip4");
        let by_hand = json!({"id": 71, "address": "10.0.0.9/24", "display": "10.0.0.9/24"});
        assert_eq!(reconcile(&wanted, &with_two_addresses(by_hand), &run([source(PVE)])), nothing());
    }

    #[test]
    fn a_reference_written_only_when_empty_is_written_at_creation() {
        let plan = reconcile(&with_a_primary_ip_when_none(), &netbox([cluster_row()]), &run([source(PVE)]));
        let last = plan.steps.last().expect("a link step");
        assert_eq!((last.phase, last.change.action, last.change.id), (Phase::Link, Action::Update, None));
        assert_eq!(last.change.fields, fields([("primary_ip4", json!("10.0.0.5/24"))]));
    }

    #[test]
    fn a_field_written_only_when_empty_is_written_once_and_never_overwritten() {
        let wanted = vm("web01", PVE).field("description", "imported from pve1").only_when_empty("description");
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["description"] = json!("");
        let empty = netbox([cluster_row(), (kind, value.clone())]);
        assert_eq!(
            reconcile(std::slice::from_ref(&wanted), &empty, &run([source(PVE)])).changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("description", json!("imported from pve1"))])
                .before([("description", json!(""))])
                .id(10)]
        );
        value["description"] = json!("ask Alice before any reboot");
        let by_hand = netbox([cluster_row(), (kind, value)]);
        assert_eq!(reconcile(&[wanted], &by_hand, &run([source(PVE)])), nothing());
    }

    #[test]
    fn the_object_kept_by_a_reference_written_only_when_empty_is_not_an_orphan() {
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["platform"] = json!({"id": 8, "name": "Debian 11", "display": "Debian 11"});
        let current = netbox([
            cluster_row(),
            (Kind::Platform, json!({"id": 8, "name": "Debian 11", "tags": owned_by(PVE)})),
            (kind, value),
        ]);
        let wanted = [
            Desired::new(Kind::Platform, Identity::named("Debian 12"), PVE).field("name", "Debian 12"),
            vm("web01", PVE)
                .reference("platform", Kind::Platform, Identity::named("Debian 12"))
                .only_when_empty("platform"),
        ];
        // The source prunes and no longer reports Debian 11, yet web01 still runs on it in NetBox.
        let plan = reconcile(&wanted, &current, &run([pruning(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("platform", Action::Create, "", "Debian 12")
                .fields([("name", json!("Debian 12")), ("tags", json!(["netbox-omnisync", "source-pve1"]))])]
        );
    }

    #[test]
    fn two_reports_that_differ_only_by_the_mode_of_a_field_are_not_alike() {
        let plain = vm("web01", PVE).field("description", "a");
        let marked = plain.clone().only_when_empty("description");
        assert!(alike(&plain, &plain.clone()));
        assert!(!alike(&plain, &marked));
    }

    // References

    #[test]
    fn a_reference_is_updated_when_it_points_elsewhere_and_cleared_when_reported_empty() {
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["platform"] = json!({"id": 8, "name": "Debian 11", "display": "Debian 11"});
        value["role"] = json!({"id": 5, "name": "Web", "display": "Web"});
        let current = netbox([
            cluster_row(),
            (Kind::Platform, json!({"id": 8, "name": "Debian 11", "tags": []})),
            (Kind::Platform, json!({"id": 9, "name": "Debian 12", "tags": []})),
            (kind, value),
        ]);
        let wanted =
            vm("web01", PVE).reference("platform", Kind::Platform, Identity::named("Debian 12")).no_reference("role");
        let plan = reconcile(&[wanted], &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("platform", json!("Debian 12")), ("role", Value::Null)])
                .before([("platform", json!("Debian 11")), ("role", json!("Web"))])
                .id(10)]
        );
        assert_eq!(
            plan.steps[0].references,
            BTreeMap::from([
                (
                    "platform".to_owned(),
                    Some(Link { kind: Kind::Platform, identity: Identity::named("Debian 12"), id: Some(9) })
                ),
                ("role".to_owned(), None),
            ])
        );
    }

    #[test]
    fn a_reference_that_cannot_be_resolved_is_left_untouched_with_a_warning() {
        let current = netbox([cluster_row(), vm_row(10, "web01", owned_by(PVE))]);
        let wanted = vm("web01", PVE).reference("platform", Kind::Platform, Identity::named("Ghost OS"));
        let plan = reconcile(&[wanted], &current, &run([source(PVE)]));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            ["vm web01: platform refers to platform Ghost OS, which is neither in NetBox nor reported; \
              field left untouched"]
        );
    }

    #[test]
    fn a_reference_to_a_later_kind_is_written_once_its_target_exists() {
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
        ]);
        let address = Identity::ip_address("10.0.0.5/24", VrfKey::Unknown);
        let wanted = [
            vm("web01", PVE).reference("primary_ip4", Kind::IpAddress, address.clone()),
            nic("web01", "eth0", PVE),
            ip("10.0.0.5/24", "web01", "eth0", PVE),
        ];
        let plan = reconcile(&wanted, &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [
                change("ip", Action::Create, "web01", "10.0.0.5/24").fields([
                    ("address", json!("10.0.0.5/24")),
                    ("assigned_object", json!("eth0")),
                    ("tags", json!(["netbox-omnisync", "source-pve1"])),
                ]),
                change("vm", Action::Update, "web01", "web01")
                    .fields([("primary_ip4", json!("10.0.0.5/24"))])
                    .before([("primary_ip4", Value::Null)])
                    .id(10),
            ]
        );
        assert_eq!(plan.steps[0].phase, Phase::Write);
        assert_eq!(
            plan.steps[0].references["assigned_object"],
            Some(Link {
                kind: Kind::VmInterface,
                identity: Identity::vm_interface(&vm_identity("web01"), "eth0"),
                id: Some(40)
            })
        );
        assert_eq!(plan.steps[1].phase, Phase::Link);
        assert_eq!(
            plan.steps[1].references["primary_ip4"],
            Some(Link { kind: Kind::IpAddress, identity: address, id: None })
        );
    }

    #[test]
    fn a_late_reference_of_an_object_created_in_this_run_is_an_update_without_id() {
        let current = netbox([cluster_row()]);
        let address = Identity::ip_address("10.0.0.5/24", VrfKey::Unknown);
        let wanted = [
            vm("web01", PVE).reference("primary_ip4", Kind::IpAddress, address),
            nic("web01", "eth0", PVE),
            ip("10.0.0.5/24", "web01", "eth0", PVE),
        ];
        let plan = reconcile(&wanted, &current, &run([source(PVE)]));
        let summary: Vec<(Phase, &str, Action, Option<u64>)> = plan
            .steps
            .iter()
            .map(|step| (step.phase, step.change.kind.as_str(), step.change.action, step.change.id))
            .collect();
        assert_eq!(
            summary,
            [
                (Phase::Write, "vm", Action::Create, None),
                (Phase::Write, "vm_interface", Action::Create, None),
                (Phase::Write, "ip", Action::Create, None),
                (Phase::Link, "vm", Action::Update, None),
            ]
        );
        assert!(!plan.steps[0].change.fields.contains_key("primary_ip4"));
        assert_eq!(plan.steps[3].change.fields, fields([("primary_ip4", json!("10.0.0.5/24"))]));
    }

    #[test]
    fn a_generic_relation_is_compared_on_its_type_and_id() {
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            nic_row(41, 10, "web01", "eth1", owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", Some(41), "eth1", "web01", owned_by(PVE)),
        ]);
        let base = [vm("web01", PVE), nic("web01", "eth0", PVE), nic("web01", "eth1", PVE)];
        let mut on_eth1 = base.to_vec();
        on_eth1.push(ip("10.0.0.5/24", "web01", "eth1", PVE));
        assert_eq!(reconcile(&on_eth1, &current, &run([source(PVE)])), nothing());
        // The address moved to another interface of the same virtual machine.
        let mut on_eth0 = base.to_vec();
        on_eth0.push(ip("10.0.0.5/24", "web01", "eth0", PVE));
        assert_eq!(
            reconcile(&on_eth0, &current, &run([source(PVE)])).changes(),
            [change("ip", Action::Update, "web01", "10.0.0.5/24")
                .fields([("assigned_object", json!("eth0"))])
                .before([("assigned_object", json!("eth1"))])
                .id(70)]
        );
    }

    #[test]
    fn a_list_of_references_is_compared_as_a_set_of_ids() {
        let vlan = |id: u64, vid: u64| {
            (
                Kind::Vlan,
                json!({"id": id, "vid": vid, "name": format!("v{vid}"), "site": null, "group": null, "tags": []}),
            )
        };
        let (kind, mut value) = pnic_row(30, 12, "esx01", "vmnic0", owned_by(PVE));
        value["tagged_vlans"] = json!([{"id": 92, "vid": 20, "name": "v20"}, {"id": 91, "vid": 10, "name": "v10"}]);
        let current = netbox([
            vlan(91, 10),
            vlan(92, 20),
            vlan(93, 30),
            device_row(12, "esx01", 1, owned_by(PVE)),
            (kind, value),
        ]);
        let target = |vid: u64| Target::new(Kind::Vlan, Identity::vlan(VlanScope::Global, vid));
        let same = [
            device("esx01", PVE),
            pnic("esx01", "vmnic0", PVE).reference_list("tagged_vlans", [target(10), target(20)]),
        ];
        assert_eq!(reconcile(&same, &current, &run([source(PVE)])), nothing());
        let other = [
            device("esx01", PVE),
            pnic("esx01", "vmnic0", PVE).reference_list("tagged_vlans", [target(10), target(30)]),
        ];
        let plan = reconcile(&other, &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("interface", Action::Update, "esx01", "vmnic0")
                .fields([("tagged_vlans", json!(["10", "30"]))])
                .before([("tagged_vlans", json!(["v10", "v20"]))])
                .id(30)]
        );
        let ids: Vec<Option<u64>> = plan.steps[0].reference_lists["tagged_vlans"].iter().map(|link| link.id).collect();
        assert_eq!(ids, [Some(91), Some(93)]);
    }

    // Ownership and adoption

    /// A virtual machine left by netbox-sync: its ownership tags, one tag from
    /// vSphere and one set by hand.
    fn left_by_the_old_tool() -> Vec<Current> {
        let tags = json!([
            {"id": 1, "name": "NetBox-synced", "slug": "netbox-synced"},
            {"id": 2, "name": "Source: vcenter-old", "slug": "source-vcenter-old"},
            {"id": 3, "name": "service-apache", "slug": "service-apache"},
            {"id": 4, "name": "backup-gold", "slug": "backup-gold"}
        ]);
        netbox([cluster_row(), vm_row(10, "web01", tags)])
    }

    #[test]
    fn adoption_changes_only_tags() {
        let wanted = vm("web01", "vc1").tags(["service-apache"]);
        let plan = reconcile(&[wanted], &left_by_the_old_tool(), &run([source("vc1")]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("tags", json!(["backup-gold", "netbox-omnisync", "service-apache", "source-vc1"]))])
                .before([("tags", json!(["backup-gold", "NetBox-synced", "service-apache", "Source: vcenter-old"]))])
                .id(10)]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn every_tag_of_the_old_tools_is_removed_on_adoption() {
        let tags = tagged([
            "netbox-synced",
            "netbox-synced-orphaned",
            "netbox-ssot",
            "netbox-ssot-orphan",
            "type-proxmox",
            "proxmox-netbox-sync",
            "source-old-pve",
        ]);
        let current = netbox([cluster_row(), vm_row(10, "web01", tags)]);
        let plan = reconcile(&[vm("web01", PVE)], &current, &run([source(PVE)]));
        assert_eq!(plan.changes()[0].fields, fields([("tags", json!(["netbox-omnisync", "source-pve1"]))]));
    }

    /// The tag netbox-ssot and netbox-sync made for a source: its slug is the
    /// one of this tool, its name is not.
    fn old_source_tag() -> (Kind, Value) {
        (Kind::Tag, json!({"id": 2, "name": "Source: pve1", "slug": "source-pve1", "description": ""}))
    }

    #[test]
    fn the_tag_of_a_source_is_attached_under_the_name_netbox_holds_for_its_slug() {
        let platform_row = (Kind::Platform, json!({"id": 8, "name": "Debian 12", "tags": tagged(["netbox-ssot"])}));
        let current = netbox([old_source_tag(), platform_row]);
        let platform = Desired::new(Kind::Platform, Identity::named("Debian 12"), PVE).field("name", "Debian 12");
        let plan = reconcile(&[platform], &current, &run([source(PVE)]));
        assert_eq!(plan.changes()[0].fields, fields([("tags", json!(["netbox-omnisync", "Source: pve1"]))]));
    }

    fn ownership_tag(name: &str, source: &str) -> Desired {
        Desired::new(Kind::Tag, Identity::named(name), source)
            .field("name", name)
            .create_only("slug", name)
            .ensure_only()
    }

    #[test]
    fn the_ownership_tags_netbox_lacks_are_asked_for() {
        let facts = [source(PVE), SourceFacts { status: SourceStatus::Skipped, ..source("vc1") }];
        assert_eq!(
            ownership_tags(&run(facts), &[]),
            [ownership_tag("netbox-omnisync", PVE), ownership_tag("source-pve1", PVE)]
        );
    }

    #[test]
    fn an_ownership_tag_netbox_holds_under_another_name_is_not_asked_for_again() {
        // Two tags of the same slug are refused by NetBox.
        let current = netbox([old_source_tag()]);
        assert_eq!(ownership_tags(&run([source(PVE)]), &current), [ownership_tag("netbox-omnisync", PVE)]);
    }

    #[test]
    fn a_source_that_failed_asks_for_no_tag() {
        let facts = [SourceFacts { status: SourceStatus::Failed, ..source(PVE) }];
        assert_eq!(ownership_tags(&run(facts), &[]), []);
    }

    #[test]
    fn an_object_this_tool_never_tagged_is_never_its_orphan() {
        // Left by an old tool with the tag of the source alone: nothing says
        // this tool ever held it, so nothing lets it delete it.
        let tags = json!([{"id": 2, "name": "Source: pve1", "slug": "source-pve1"}]);
        let current = netbox([cluster_row(), vm_row(10, "gone01", tags)]);
        let plan = reconcile(&[], &current, &run([pruning(PVE)]));
        assert_eq!(plan.changes(), []);
        // The same machine, once this tool has tagged it, is its orphan.
        let current = netbox([cluster_row(), vm_row(10, "gone01", owned_by(PVE))]);
        let plan = reconcile(&[], &current, &run([pruning(PVE)]));
        assert_eq!(plan.changes(), [change("vm", Action::Delete, "gone01", "gone01").id(10)]);
    }

    #[test]
    fn a_second_run_after_adoption_changes_nothing() {
        // The state the adoption above leaves, as NetBox renders it.
        let tags = tagged(["backup-gold", "netbox-omnisync", "service-apache", "source-vc1"]);
        let current = netbox([cluster_row(), vm_row(10, "web01", tags)]);
        let wanted = vm("web01", "vc1").tags(["service-apache"]);
        assert_eq!(reconcile(&[wanted], &current, &run([source("vc1")])), nothing());
    }

    #[test]
    fn the_tag_of_a_configured_source_left_out_of_the_run_is_not_an_old_tool_s() {
        let tags = tagged(["netbox-omnisync", "source-pve1", "source-vc1"]);
        let current = netbox([(Kind::Platform, json!({"id": 8, "name": "Debian 12", "tags": tags}))]);
        let platform = Desired::new(Kind::Platform, Identity::named("Debian 12"), PVE).field("name", "Debian 12");
        let facts = [source(PVE), SourceFacts { status: SourceStatus::Skipped, ..source("vc1") }];
        assert_eq!(reconcile(&[platform], &current, &run(facts)), nothing());
    }

    #[test]
    fn an_object_found_by_its_identity_that_no_tool_owns_is_taken_over() {
        let current = netbox([cluster_row(), vm_row(10, "web01", tagged(["backup-gold"]))]);
        assert_eq!(
            reconcile(&[vm("web01", PVE)], &current, &run([source(PVE)])).changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("tags", json!(["backup-gold", "netbox-omnisync", "source-pve1"]))])
                .before([("tags", json!(["backup-gold"]))])
                .id(10)]
        );
    }

    #[test]
    fn an_object_only_ensured_is_created_when_missing_and_left_alone_when_nobody_owns_it() {
        let site = Desired::new(Kind::Site, Identity::named("Harbor"), PVE)
            .field("name", "Harbor")
            .field("description", "main site")
            .ensure_only();
        let by_hand = netbox([(Kind::Site, json!({"id": 1, "name": "Harbor", "description": "", "tags": []}))]);
        assert_eq!(reconcile(std::slice::from_ref(&site), &by_hand, &run([source(PVE)])), nothing());
        assert_eq!(
            reconcile(std::slice::from_ref(&site), &[], &run([source(PVE)])).changes(),
            [change("site", Action::Create, "", "Harbor").fields([
                ("description", json!("main site")),
                ("name", json!("Harbor")),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
            ])]
        );
        // Tagged by an old tool: it was the tool's, so it is adopted and managed.
        let owned = netbox([(
            Kind::Site,
            json!({"id": 1, "name": "Harbor", "description": "main site", "tags": tagged(["netbox-synced"])}),
        )]);
        assert_eq!(
            reconcile(&[site], &owned, &run([source(PVE)])).changes(),
            [change("site", Action::Update, "", "Harbor")
                .fields([("tags", json!(["netbox-omnisync", "source-pve1"]))])
                .before([("tags", json!(["netbox-synced"]))])
                .id(1)]
        );
    }

    // Tags from the source, custom fields

    fn with_source_tags() -> Vec<Current> {
        let from_source = "netbox-omnisync: from vSphere";
        netbox([
            (
                Kind::Tag,
                json!({"id": 3, "name": "service-apache", "slug": "service-apache", "description": from_source}),
            ),
            (Kind::Tag, json!({"id": 5, "name": "service-nginx", "slug": "service-nginx", "description": from_source})),
            (Kind::Tag, json!({"id": 4, "name": "backup-gold", "slug": "backup-gold", "description": "set by ops"})),
            cluster_row(),
            vm_row(10, "web01", tagged(["netbox-omnisync", "source-pve1", "service-apache", "backup-gold"])),
        ])
    }

    #[test]
    fn tags_from_the_source_are_managed_and_any_other_tag_is_left_alone() {
        let wanted = vm("web01", PVE).tags(["service-nginx"]);
        assert_eq!(
            reconcile(&[wanted], &with_source_tags(), &run([source(PVE)])).changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("tags", json!(["backup-gold", "netbox-omnisync", "service-nginx", "source-pve1"]))])
                .before([("tags", json!(["backup-gold", "netbox-omnisync", "service-apache", "source-pve1"]))])
                .id(10)]
        );
    }

    #[test]
    fn the_marker_is_the_whole_description_or_followed_by_a_colon() {
        let tag = |id: u64, name: &str, description: &str| {
            (Kind::Tag, json!({"id": id, "name": name, "slug": name, "description": description}))
        };
        let current = netbox([
            tag(3, "marked", "netbox-omnisync"),
            tag(4, "described", "netbox-omnisync: Icinga: Daemon Nginx"),
            // Text written by hand that merely starts like the marker.
            tag(5, "lookalike", "netbox-omnisync-legacy notes"),
            tag(6, "spaced", "netbox-omnisync managed? ask ops"),
            cluster_row(),
            vm_row(
                10,
                "web01",
                tagged(["netbox-omnisync", "source-pve1", "marked", "described", "lookalike", "spaced"]),
            ),
        ]);
        let wanted = vm("web01", PVE).tags(Vec::<String>::new());
        assert_eq!(
            reconcile(&[wanted], &current, &run([source(PVE)])).changes()[0].fields,
            fields([("tags", json!(["lookalike", "netbox-omnisync", "source-pve1", "spaced"]))])
        );
    }

    #[test]
    fn tags_the_source_could_not_read_are_left_as_they_are() {
        assert_eq!(reconcile(&[vm("web01", PVE)], &with_source_tags(), &run([source(PVE)])), nothing());
    }

    #[test]
    fn an_empty_tag_set_removes_the_tags_that_came_from_the_source() {
        let wanted = vm("web01", PVE).tags(Vec::<String>::new());
        assert_eq!(
            reconcile(&[wanted], &with_source_tags(), &run([source(PVE)])).changes()[0].fields,
            fields([("tags", json!(["backup-gold", "netbox-omnisync", "source-pve1"]))])
        );
    }

    #[test]
    fn custom_fields_are_merged_on_the_managed_keys_only() {
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["custom_fields"] = json!({"owner_team": "web", "uuid": null, "vmid": 105});
        let current = netbox([cluster_row(), (kind, value)]);
        // `vmid` is already right, `owner_team` is not ours.
        let wanted = vm("web01", PVE).custom_field(&UUID, "42d0").custom_field(&VMID, 105);
        assert_eq!(
            reconcile(&[wanted], &current, &run([source(PVE)])).changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("custom_fields", json!({"uuid": "42d0"}))])
                .before([("custom_fields", json!({"uuid": null}))])
                .id(10)]
        );
    }

    // Several sources

    #[test]
    fn what_two_sources_would_only_write_at_creation_is_not_a_disagreement() {
        // The same tag from two sources, each with its own colour for the day
        // it creates it: they say the same thing of the tag.
        let tag = |source: &str, colour: &str| {
            Desired::new(Kind::Tag, Identity::named("service-apache"), source)
                .field("name", "service-apache")
                .create_only("color", colour)
        };
        let ensured = tag("vc2", "9e9e9e").ensure_only();
        let plan = reconcile(&[tag("vc1", "00add8"), ensured], &[], &run([source("vc1"), source("vc2")]));
        assert_eq!(plan.warnings, Vec::<String>::new());
        // The first source of the priority still decides what the creation writes.
        assert_eq!(plan.changes()[0].fields.get("color"), Some(&json!("00add8")));
    }

    #[test]
    fn two_sources_that_only_want_an_object_to_exist_do_not_disagree() {
        // A prefix two clusters share, each naming itself in a custom field:
        // nothing of it is ever written once it exists.
        let prefix = |source: &str| {
            Desired::new(Kind::Prefix, Identity::prefix("192.0.2.0/24", VrfKey::Unknown), source)
                .field("prefix", "192.0.2.0/24")
                .custom_field(&custom_fields::SOURCE, source)
                .ensure_only()
        };
        let plan = reconcile(&[prefix("vc1"), prefix("vc2")], &[], &run([source("vc1"), source("vc2")]));
        assert_eq!(plan.warnings, Vec::<String>::new());
        // As soon as two of them mean to keep it up to date, a difference is one.
        let kept = |source: &str| Desired { ensure_only: false, ..prefix(source) };
        let plan = reconcile(&[kept("vc1"), kept("vc2")], &[], &run([source("vc1"), source("vc2")]));
        assert_eq!(
            plan.warnings,
            ["prefix 192.0.2.0/24: reported differently by vc1 and vc2; vc1 wins (source priority)"]
        );
    }

    // A report that only wants the prefix to exist says nothing of its
    // description: it never keeps a source that describes it from writing it,
    // whatever the priority, and the two never disagree.
    #[test]
    fn a_report_that_only_wants_an_object_to_exist_never_keeps_another_from_describing_it() {
        let prefix = |source: &str| {
            Desired::new(Kind::Prefix, Identity::prefix("10.0.0.0/24", VrfKey::Global), source)
                .field("prefix", "10.0.0.0/24")
        };
        let ensured = prefix("vc1").ensure_only();
        let described = prefix("vc2").field("description", "LAN prod");
        let plan = reconcile(&[ensured, described], &[], &run([source("vc1"), source("vc2")]));
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert_eq!(plan.changes()[0].fields.get("description"), Some(&json!("LAN prod")));
    }

    #[test]
    fn the_first_source_of_the_priority_wins_and_the_other_is_warned() {
        let facts = Run { priority: vec!["vc2".to_owned(), "vc1".to_owned()], ..run([source("vc1"), source("vc2")]) };
        let wanted = [vm("web01", "vc1").field("memory", 2048), vm("web01", "vc2").field("memory", 8192)];
        let plan = reconcile(&wanted, &netbox([cluster_row()]), &facts);
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Create, "web01", "web01").fields([
                ("cluster", json!("pve")),
                ("memory", json!(8192)),
                ("name", json!("web01")),
                ("status", json!("active")),
                ("tags", json!(["netbox-omnisync", "source-vc1", "source-vc2"])),
                ("vcpus", json!(2)),
            ])]
        );
        assert_eq!(plan.warnings, ["vm web01: reported differently by vc2 and vc1; vc2 wins (source priority)"]);
    }

    #[test]
    fn an_object_two_sources_report_alike_is_shared_without_a_warning() {
        let platform = |source: &str| {
            Desired::new(Kind::Platform, Identity::named("Debian 12"), source).field("name", "Debian 12")
        };
        let plan = reconcile(&[platform("vc1"), platform(PVE)], &[], &run([source(PVE), source("vc1")]));
        assert_eq!(
            plan.changes(),
            [change("platform", Action::Create, "", "Debian 12").fields([
                ("name", json!("Debian 12")),
                ("tags", json!(["netbox-omnisync", "source-pve1", "source-vc1"])),
            ])]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    fn sources(plan: &Plan) -> Vec<Option<&str>> {
        plan.warnings.iter().map(|warning| warning.source.as_deref()).collect()
    }

    // The run starts a warning with the source it is about, as it starts an
    // error: the check takes it back at the next run of that source alone.
    // An object is the source's that reports it; a difference two sources
    // settle, the winner's (the one the warning says wins); an orphan kept,
    // the source it was held for; a report ignored, its source.
    #[test]
    fn a_warning_names_the_source_it_is_about() {
        let facts = Run { unique_ip_vrfs: BTreeSet::from([String::new()]), ..run([pruning(PVE)]) };
        let held = reconcile(&both_vms_report_the_address(), &held_by_another_vm(), &facts);
        assert_eq!(sources(&held), [Some(PVE)]);

        let priority =
            Run { priority: vec!["vc2".to_owned(), "vc1".to_owned()], ..run([source("vc1"), source("vc2")]) };
        let wanted = [vm("web01", "vc1").field("memory", 2048), vm("web01", "vc2").field("memory", 8192)];
        let settled = reconcile(&wanted, &netbox([cluster_row()]), &priority);
        assert_eq!(sources(&settled), [Some("vc2")]);

        let orphan = netbox([
            (Kind::Cluster, json!({"id": 3, "name": "old", "tags": owned_by(PVE)})),
            (
                Kind::VirtualMachine,
                json!({"id": 9, "name": "handmade", "cluster": {"id": 3, "name": "old"}, "tags": []}),
            ),
        ]);
        assert_eq!(sources(&reconcile(&[], &orphan, &run([pruning(PVE)]))), [Some(PVE)]);

        let failed = [source(PVE), SourceFacts { status: SourceStatus::Failed, ..source("vc1") }];
        let ignored = reconcile(&[vm("web01", "vc1")], &netbox([cluster_row()]), &run(failed));
        assert_eq!(sources(&ignored), [Some("vc1")]);
    }

    #[test]
    fn what_a_source_that_did_not_succeed_reports_is_ignored() {
        let facts = [source(PVE), SourceFacts { status: SourceStatus::Failed, ..source("vc1") }];
        let wanted = [vm("web01", "vc1"), vm("web02", "vc1"), vm("web03", "ghost")];
        let plan = reconcile(&wanted, &netbox([cluster_row()]), &run(facts));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            [
                "source ghost is not configured: 1 reported object(s) ignored",
                "source vc1 did not succeed: 2 reported object(s) ignored",
            ]
        );
    }

    // Orphans

    fn two_sources_worth() -> Vec<Current> {
        netbox([cluster_row(), vm_row(11, "old-pve", owned_by(PVE)), vm_row(12, "old-vc", owned_by("vc1"))])
    }

    #[test]
    fn an_orphan_is_deleted_only_when_its_source_prunes() {
        let current = two_sources_worth();
        let plan = reconcile(&[], &current, &run([pruning(PVE), source("vc1")]));
        assert_eq!(plan.changes(), [change("vm", Action::Delete, "old-pve", "old-pve").id(11)]);
        assert_eq!(plan.steps[0].phase, Phase::Delete);
        assert_eq!(plan.orphans_kept, ["vm old-vc"]);
    }

    #[test]
    fn a_source_left_out_of_the_run_never_has_its_objects_orphaned() {
        let facts = [pruning(PVE), SourceFacts { status: SourceStatus::Skipped, ..pruning("vc1") }];
        let plan = reconcile(&[], &two_sources_worth(), &run(facts));
        assert_eq!(plan.changes(), [change("vm", Action::Delete, "old-pve", "old-pve").id(11)]);
        assert_eq!(plan.orphans_kept, Vec::<String>::new());
    }

    #[test]
    fn a_failed_source_keeps_its_orphans() {
        let facts = [pruning(PVE), SourceFacts { status: SourceStatus::Failed, ..pruning("vc1") }];
        let plan = reconcile(&[], &two_sources_worth(), &run(facts));
        assert_eq!(plan.changes(), [change("vm", Action::Delete, "old-pve", "old-pve").id(11)]);
        assert_eq!(plan.orphans_kept, Vec::<String>::new());
    }

    #[test]
    fn an_object_without_the_tag_of_a_source_of_this_run_is_never_an_orphan() {
        let current = netbox([
            cluster_row(),
            // Made by hand.
            vm_row(11, "by-hand", tagged([])),
            // Left by an old tool and not adopted yet.
            vm_row(12, "old-tool", tagged(["netbox-ssot", "type-proxmox"])),
            // The tool's, but of no source.
            vm_row(13, "no-source", tagged(["netbox-omnisync"])),
            // Ours, and still claimed by an old tool that may be running.
            vm_row(14, "shared", tagged(["netbox-omnisync", "source-pve1", "netbox-synced"])),
        ]);
        assert_eq!(reconcile(&[], &current, &run([pruning(PVE)])), nothing());
    }

    #[test]
    fn an_orphan_another_source_still_claims_only_loses_the_tag_of_the_source_that_dropped_it() {
        let tags = tagged(["netbox-omnisync", "source-pve1", "source-vc1"]);
        let current = netbox([(Kind::Platform, json!({"id": 8, "name": "Debian 12", "tags": tags}))]);
        let facts = [pruning(PVE), SourceFacts { status: SourceStatus::Skipped, ..pruning("vc1") }];
        assert_eq!(
            reconcile(&[], &current, &run(facts)).changes(),
            [change("platform", Action::Update, "", "Debian 12")
                .fields([("tags", json!(["netbox-omnisync", "source-vc1"]))])
                .before([("tags", json!(["netbox-omnisync", "source-pve1", "source-vc1"]))])
                .id(8)]
        );
    }

    #[test]
    fn a_source_that_stops_reporting_a_shared_object_loses_its_tag_on_it() {
        let tags = tagged(["netbox-omnisync", "source-pve1", "source-vc1"]);
        let current = netbox([(Kind::Platform, json!({"id": 8, "name": "Debian 12", "tags": tags}))]);
        let platform = Desired::new(Kind::Platform, Identity::named("Debian 12"), "vc1").field("name", "Debian 12");
        assert_eq!(
            reconcile(&[platform], &current, &run([source(PVE), source("vc1")])).changes(),
            [change("platform", Action::Update, "", "Debian 12")
                .fields([("tags", json!(["netbox-omnisync", "source-vc1"]))])
                .before([("tags", json!(["netbox-omnisync", "source-pve1", "source-vc1"]))])
                .id(8)]
        );
    }

    // --- Two sources run apart -----------------------------------------------

    const SHARED: &str = "192.168.10.0/24";

    fn skipped(name: &str) -> SourceFacts {
        SourceFacts { status: SourceStatus::Skipped, ..source(name) }
    }

    /// The prefix two sources report, as NetBox has it: who wrote it last is
    /// in its custom field `source`.
    fn shared_prefix_row(written_by: &str, tags: Value) -> (Kind, Value) {
        (
            Kind::Prefix,
            json!({
                "id": 80, "prefix": SHARED, "vrf": null, "custom_fields": {"source": written_by}, "tags": tags
            }),
        )
    }

    /// As a Proxmox reports the network of an address: it only wants it to exist.
    fn shared_prefix(source: &str) -> Desired {
        Desired::new(Kind::Prefix, Identity::prefix(SHARED, VrfKey::Unknown), source)
            .field("prefix", SHARED)
            .custom_field(&custom_fields::SOURCE, source)
            .ensure_only()
    }

    #[test]
    fn an_object_a_better_source_left_out_of_the_run_holds_is_left_as_netbox_has_it() {
        let current = netbox([shared_prefix_row("pve-a", tagged(["netbox-omnisync", "source-pve-a"]))]);
        // pve-a is ranked first and is not in this run: a run of both would
        // have had pve-b lose, and only add its tag.
        let plan = reconcile(&[shared_prefix("pve-b")], &current, &run([skipped("pve-a"), source("pve-b")]));
        assert_eq!(
            plan.changes(),
            [change("prefix", Action::Update, "", SHARED)
                .fields([("tags", json!(["netbox-omnisync", "source-pve-a", "source-pve-b"]))])
                .before([("tags", json!(["netbox-omnisync", "source-pve-a"]))])
                .id(80)]
        );
        assert_eq!(plan.warnings, Vec::<Warning>::new());
    }

    #[test]
    fn two_sources_run_apart_never_write_an_object_back_and_forth() {
        // What the run of pve-b alone left: its tag, and the value of pve-a.
        let both = tagged(["netbox-omnisync", "source-pve-a", "source-pve-b"]);
        let current = netbox([shared_prefix_row("pve-a", both)]);
        let of_a = reconcile(&[shared_prefix("pve-a")], &current, &run([source("pve-a"), skipped("pve-b")]));
        assert_eq!(of_a, nothing());
        let of_b = reconcile(&[shared_prefix("pve-b")], &current, &run([skipped("pve-a"), source("pve-b")]));
        assert_eq!(of_b, nothing());
    }

    #[test]
    fn an_object_a_worse_source_left_out_holds_is_written_by_the_better_one() {
        let current = netbox([shared_prefix_row("pve-a", tagged(["netbox-omnisync", "source-pve-a"]))]);
        // pve-b is ranked first: it writes, and pve-a, left out, keeps its tag.
        let plan = reconcile(&[shared_prefix("pve-b")], &current, &run([source("pve-b"), skipped("pve-a")]));
        assert_eq!(
            plan.changes(),
            [change("prefix", Action::Update, "", SHARED)
                .fields([
                    ("custom_fields", json!({"source": "pve-b"})),
                    ("tags", json!(["netbox-omnisync", "source-pve-a", "source-pve-b"]))
                ])
                .before([
                    ("custom_fields", json!({"source": "pve-a"})),
                    ("tags", json!(["netbox-omnisync", "source-pve-a"]))
                ])
                .id(80)]
        );
    }

    #[test]
    fn an_object_the_better_source_no_longer_holds_is_written_by_the_one_that_runs() {
        // pve-a no longer reports the prefix: its own run took its tag back.
        let current = netbox([shared_prefix_row("pve-a", tagged(["netbox-omnisync", "source-pve-b"]))]);
        let plan = reconcile(&[shared_prefix("pve-b")], &current, &run([skipped("pve-a"), source("pve-b")]));
        assert_eq!(
            plan.changes(),
            [change("prefix", Action::Update, "", SHARED)
                .fields([("custom_fields", json!({"source": "pve-b"}))])
                .before([("custom_fields", json!({"source": "pve-a"}))])
                .id(80)]
        );
    }

    #[test]
    fn a_reference_of_an_object_left_to_a_better_source_is_still_in_use() {
        let (kind, mut value) = vm_row(10, "web01", tagged(["netbox-omnisync", "source-pve-a"]));
        value["platform"] = json!({"id": 8, "name": "Debian 11", "display": "Debian 11"});
        let current = netbox([
            cluster_row(),
            (Kind::Platform, json!({"id": 8, "name": "Debian 11", "tags": owned_by("pve-b")})),
            (kind, value),
        ]);
        let wanted = [
            Desired::new(Kind::Platform, Identity::named("Debian 12"), "pve-b").field("name", "Debian 12"),
            vm("web01", "pve-b").reference("platform", Kind::Platform, Identity::named("Debian 12")),
        ];
        // pve-b prunes and no longer reports Debian 11, yet web01, which pve-a
        // holds, is left on it.
        let plan = reconcile(&wanted, &current, &run([skipped("pve-a"), pruning("pve-b")]));
        assert_eq!(
            plan.changes(),
            [
                change("platform", Action::Create, "", "Debian 12")
                    .fields([("name", json!("Debian 12")), ("tags", json!(["netbox-omnisync", "source-pve-b"]))]),
                change("vm", Action::Update, "web01", "web01")
                    .fields([("tags", json!(["netbox-omnisync", "source-pve-a", "source-pve-b"]))])
                    .before([("tags", json!(["netbox-omnisync", "source-pve-a"]))])
                    .id(10),
            ]
        );
    }

    #[test]
    fn what_completes_an_object_a_better_source_left_out_holds_is_still_written() {
        let (kind, mut value) = device_row(5, "pve01.lab01", 1, tagged(["netbox-omnisync", "source-pve-a"]));
        value["serial"] = json!("");
        let current = netbox([(kind, value)]);
        let wanted = [
            device("pve01.lab01", "pve-b"),
            Desired::new(Kind::Device, Identity::device("pve01.lab01"), "bmc1").complement().field("serial", "SVCTAG1"),
        ];
        // pve-b alone would leave the device to pve-a; what the BMC knows of it is no report of pve-b.
        let plan = reconcile(&wanted, &current, &run([skipped("pve-a"), source("pve-b"), source("bmc1")]));
        assert_eq!(
            plan.changes(),
            [change("device", Action::Update, "pve01.lab01", "pve01.lab01")
                .fields([
                    ("serial", json!("SVCTAG1")),
                    ("tags", json!(["netbox-omnisync", "source-pve-a", "source-pve-b"]))
                ])
                .before([("serial", json!("")), ("tags", json!(["netbox-omnisync", "source-pve-a"]))])
                .id(5)]
        );
    }

    fn mac_row(id: u64, address: &str, nic_id: u64, tags: Value) -> (Kind, Value) {
        (
            Kind::MacAddress,
            json!({
                "id": id, "mac_address": address, "assigned_object_type": "virtualization.vminterface",
                "assigned_object_id": nic_id, "tags": tags
            }),
        )
    }

    fn disk_row(id: u64, vm_id: u64, name: &str, tags: Value) -> (Kind, Value) {
        (
            Kind::VirtualDisk,
            json!({"id": id, "name": name, "virtual_machine": {"id": vm_id, "name": "x"}, "tags": tags}),
        )
    }

    #[test]
    fn a_stopped_vm_keeps_its_interfaces_and_addresses() {
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            mac_row(60, "BC:24:11:AA:BB:CC", 40, owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", Some(40), "eth0", "web01", owned_by(PVE)),
            disk_row(51, 10, "scsi1", owned_by(PVE)),
        ]);
        // Stopped: the guest agent says nothing of interfaces and addresses,
        // but the disks are in the configuration and scsi1 is gone.
        let stopped = vm("web01", PVE).field("status", "offline").unknown_dependents([
            Kind::VmInterface,
            Kind::MacAddress,
            Kind::IpAddress,
        ]);
        let plan = reconcile(&[stopped], &current, &run([pruning(PVE)]));
        assert_eq!(
            plan.changes(),
            [
                change("vm", Action::Update, "web01", "web01")
                    .fields([("status", json!("offline"))])
                    .before([("status", json!("active"))])
                    .id(10),
                change("disk", Action::Delete, "web01", "scsi1").id(51),
            ]
        );
        assert_eq!(plan.orphans_kept, Vec::<String>::new());
    }

    #[test]
    fn the_prefix_of_an_address_kept_for_a_stopped_vm_is_kept() {
        let prefix = |id: u64, prefix: &str| {
            (Kind::Prefix, json!({"id": id, "prefix": prefix, "vrf": null, "tags": owned_by(PVE)}))
        };
        let current = netbox([
            cluster_row(),
            prefix(80, "10.0.0.0/24"),
            prefix(81, "10.9.0.0/24"),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", Some(40), "eth0", "web01", owned_by(PVE)),
        ]);
        let stopped = vm("web01", PVE).unknown_dependents([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]);
        assert_eq!(
            reconcile(&[stopped], &current, &run([pruning(PVE)])).changes(),
            [change("prefix", Action::Delete, "", "10.9.0.0/24").id(81)]
        );
    }

    #[test]
    fn an_object_a_matched_row_still_points_to_through_an_unreported_field_is_kept() {
        let platform = |id: u64, name: &str| (Kind::Platform, json!({"id": id, "name": name, "tags": owned_by(PVE)}));
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["platform"] = json!({"id": 8, "name": "Debian 12"});
        let current = netbox([cluster_row(), platform(8, "Debian 12"), platform(9, "Debian 9"), (kind, value)]);
        // The agent is silent: the source reports no platform at all.
        assert_eq!(
            reconcile(&[vm("web01", PVE)], &current, &run([pruning(PVE)])).changes(),
            [change("platform", Action::Delete, "", "Debian 9").id(9)]
        );
    }

    #[test]
    fn deletions_come_out_in_reverse_dependency_order() {
        let (child_kind, mut child) = nic_row(42, 11, "old", "eth0.100", owned_by(PVE));
        child["parent"] = json!({"id": 41, "name": "eth0"});
        let current = netbox([
            (Kind::Cluster, json!({"id": 3, "name": "pve", "tags": owned_by(PVE)})),
            device_row(12, "esx01", 1, owned_by(PVE)),
            pnic_row(30, 12, "esx01", "vmnic0", owned_by(PVE)),
            vm_row(11, "old", owned_by(PVE)),
            nic_row(41, 11, "old", "eth0", owned_by(PVE)),
            (child_kind, child),
            disk_row(50, 11, "scsi0", owned_by(PVE)),
            mac_row(60, "BC:24:11:AA:BB:CC", 41, owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", Some(41), "eth0", "old", owned_by(PVE)),
        ]);
        let plan = reconcile(&[], &current, &run([pruning(PVE)]));
        let order: Vec<(&str, Action, Option<u64>)> =
            plan.steps.iter().map(|step| (step.change.kind.as_str(), step.change.action, step.change.id)).collect();
        assert_eq!(
            order,
            [
                ("ip", Action::Delete, Some(70)),
                ("mac", Action::Delete, Some(60)),
                ("disk", Action::Delete, Some(50)),
                // A child interface goes before its parent, whatever their names.
                ("vm_interface", Action::Delete, Some(42)),
                ("vm_interface", Action::Delete, Some(41)),
                ("interface", Action::Delete, Some(30)),
                ("vm", Action::Delete, Some(11)),
                ("device", Action::Delete, Some(12)),
                ("cluster", Action::Delete, Some(3)),
            ]
        );
    }

    #[test]
    fn an_orphan_is_not_deleted_when_netbox_would_delete_a_kept_object_with_it() {
        let current = netbox([
            device_row(12, "esx01", 1, owned_by(PVE)),
            pnic_row(30, 12, "esx01", "vmnic9", owned_by(PVE)),
            (
                Kind::IpAddress,
                json!({
                    "id": 71, "address": "192.0.2.9/24", "vrf": null, "assigned_object_type": "dcim.interface",
                    "assigned_object_id": 30,
                    "assigned_object": {"id": 30, "name": "vmnic9", "device": {"id": 12, "name": "esx01"}},
                    "tags": []
                }),
            ),
        ]);
        // vmnic9 is gone from the host, but somebody put an address on it by hand.
        let plan = reconcile(&[device("esx01", PVE)], &current, &run([pruning(PVE)]));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            ["interface esx01 vmnic9: not deleted, NetBox would delete ip esx01 192.0.2.9/24 with it"]
        );
    }

    // Devices

    #[test]
    fn create_devices_off_skips_a_missing_device_and_its_dependents() {
        let facts = SourceFacts { create_devices: false, ..source(PVE) };
        let host_ip = Desired::new(Kind::IpAddress, Identity::ip_address("10.0.1.1/24", VrfKey::Unknown), PVE)
            .field("address", "10.0.1.1/24")
            .reference("assigned_object", Kind::Interface, Identity::interface("esx01", "vmk0"));
        let wanted = [device("esx01", PVE), pnic("esx01", "vmk0", PVE), host_ip];
        let plan = reconcile(&wanted, &[], &run([facts.clone()]));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            ["device esx01: not in NetBox and create_devices is off for pve1; skipped with its dependents"]
        );
        // A device that exists is managed as usual.
        let current = netbox([device_row(12, "esx01", 1, owned_by(PVE))]);
        let plan = reconcile(&wanted[..2], &current, &run([facts]));
        assert_eq!(
            plan.changes(),
            [change("interface", Action::Create, "esx01", "vmk0").fields([
                ("device", json!("esx01")),
                ("name", json!("vmk0")),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
            ])]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn a_virtual_machine_whose_host_device_is_not_created_only_loses_that_reference() {
        let facts = SourceFacts { create_devices: false, ..source(PVE) };
        let current = netbox([cluster_row(), vm_row(10, "web01", owned_by(PVE))]);
        let wanted =
            [device("esx01", PVE), vm("web01", PVE).reference("device", Kind::Device, Identity::device("esx01"))];
        let plan = reconcile(&wanted, &current, &run([facts]));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            [
                "device esx01: not in NetBox and create_devices is off for pve1; skipped with its dependents",
                "vm web01: device refers to device esx01, which is skipped; field left untouched",
            ]
        );
    }

    #[test]
    fn two_netbox_objects_with_the_identity_of_a_reported_one_are_not_guessed_between() {
        let twins = netbox([device_row(12, "esx01", 1, tagged([])), device_row(13, "esx01", 2, tagged([]))]);
        let wanted = [device("esx01", PVE), pnic("esx01", "vmk0", PVE)];
        let plan = reconcile(&wanted, &twins, &run([source(PVE)]));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            ["device esx01: 2 objects in NetBox have this identity (ids 12, 13); skipped with its dependents"]
        );
        // One of the two is already the tool's: that is the one.
        let one_owned = netbox([device_row(12, "esx01", 1, tagged([])), device_row(13, "esx01", 2, owned_by(PVE))]);
        let plan = reconcile(&wanted[..1], &one_owned, &run([source(PVE)]));
        assert_eq!(plan, nothing());
    }

    // IP addresses

    fn held_by_another_vm() -> Vec<Current> {
        netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            vm_row(11, "other", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            nic_row(41, 11, "other", "eth0", owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", Some(41), "eth0", "other", owned_by(PVE)),
        ])
    }

    fn both_vms_report_the_address() -> Vec<Desired> {
        vec![
            vm("web01", PVE),
            vm("other", PVE),
            nic("web01", "eth0", PVE),
            nic("other", "eth0", PVE),
            ip("10.0.0.5/24", "web01", "eth0", PVE),
            ip("10.0.0.5/24", "other", "eth0", PVE),
        ]
    }

    #[test]
    fn an_ip_address_is_never_taken_from_another_owner() {
        // A virtual address both machines hold: the object of `other` stays
        // where it is, and web01 gets its own.
        let plan = reconcile(&both_vms_report_the_address(), &held_by_another_vm(), &run([pruning(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("ip", Action::Create, "web01", "10.0.0.5/24").fields([
                ("address", json!("10.0.0.5/24")),
                ("assigned_object", json!("eth0")),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
            ])]
        );
        assert_eq!(plan.warnings, ["ip 10.0.0.5/24 of web01: also assigned to other; a second address is created"]);
    }

    #[test]
    fn an_ip_address_is_not_taken_from_an_owner_that_reports_nothing_in_this_run() {
        // `other` belongs to a source left out of the run: nothing claims its
        // address in this run, and it is still not web01's to take.
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            vm_row(11, "other", owned_by("vc1")),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            nic_row(41, 11, "other", "eth0", owned_by("vc1")),
            ip_row(70, "10.0.0.5/24", Some(41), "eth0", "other", owned_by("vc1")),
        ]);
        let wanted = [vm("web01", PVE), nic("web01", "eth0", PVE), ip("10.0.0.5/24", "web01", "eth0", PVE)];
        let facts = [pruning(PVE), SourceFacts { status: SourceStatus::Skipped, ..pruning("vc1") }];
        let plan = reconcile(&wanted, &current, &run(facts));
        assert_eq!(
            plan.changes(),
            [change("ip", Action::Create, "web01", "10.0.0.5/24").fields([
                ("address", json!("10.0.0.5/24")),
                ("assigned_object", json!("eth0")),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
            ])]
        );
        assert_eq!(plan.warnings, ["ip 10.0.0.5/24 of web01: also assigned to other; a second address is created"]);
    }

    #[test]
    fn an_ip_address_held_elsewhere_is_not_created_where_netbox_enforces_unique_addresses() {
        let facts = Run { unique_ip_vrfs: BTreeSet::from([String::new()]), ..run([pruning(PVE)]) };
        let plan = reconcile(&both_vms_report_the_address(), &held_by_another_vm(), &facts);
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            ["ip 10.0.0.5/24 of web01: also assigned to other; not created, its table enforces unique addresses"]
        );
    }

    #[test]
    fn an_unassigned_ip_address_is_adopted_and_assigned() {
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", None, "", "", tagged([])),
        ]);
        let wanted = [vm("web01", PVE), nic("web01", "eth0", PVE), ip("10.0.0.5/24", "web01", "eth0", PVE)];
        assert_eq!(
            reconcile(&wanted, &current, &run([source(PVE)])).changes(),
            [change("ip", Action::Update, "web01", "10.0.0.5/24")
                .fields([("assigned_object", json!("eth0")), ("tags", json!(["netbox-omnisync", "source-pve1"]))])
                .before([("assigned_object", Value::Null), ("tags", json!([]))])
                .id(70)]
        );
    }

    #[test]
    fn an_ip_address_whose_vrf_the_source_does_not_know_keeps_the_vrf_netbox_has() {
        let (kind, mut value) = ip_row(70, "10.0.0.5/24", Some(40), "eth0", "web01", owned_by(PVE));
        value["vrf"] = json!({"id": 5, "name": "Prod"});
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            (kind, value),
        ]);
        let wanted = [vm("web01", PVE), nic("web01", "eth0", PVE), ip("10.0.0.5/24", "web01", "eth0", PVE)];
        assert_eq!(reconcile(&wanted, &current, &run([pruning(PVE)])), nothing());
    }

    #[test]
    fn a_mask_corrected_on_the_host_updates_the_address() {
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            ip_row(70, "10.0.0.5/32", Some(40), "eth0", "web01", owned_by(PVE)),
        ]);
        let wanted = [vm("web01", PVE), nic("web01", "eth0", PVE), ip("10.0.0.5/24", "web01", "eth0", PVE)];
        assert_eq!(
            reconcile(&wanted, &current, &run([pruning(PVE)])).changes(),
            [change("ip", Action::Update, "web01", "10.0.0.5/24")
                .fields([("address", json!("10.0.0.5/24"))])
                .before([("address", json!("10.0.0.5/32"))])
                .id(70)]
        );
    }

    #[test]
    fn a_prefix_whose_vrf_the_source_does_not_know_is_found_in_the_vrf_netbox_has() {
        let current = netbox([(
            Kind::Prefix,
            json!({"id": 80, "prefix": "10.0.0.0/24", "vrf": {"id": 5, "name": "Prod"}, "tags": owned_by(PVE)}),
        )]);
        let prefix = Desired::new(Kind::Prefix, Identity::prefix("10.0.0.0/24", VrfKey::Unknown), PVE)
            .field("prefix", "10.0.0.0/24");
        assert_eq!(reconcile(&[prefix], &current, &run([pruning(PVE)])), nothing());
    }

    // Renames

    const MAC_1: &str = "BC:24:11:00:00:01";
    const MAC_2: &str = "BC:24:11:00:00:02";
    const MAC_3: &str = "BC:24:11:00:00:03";

    fn mac(address: &str, vm_name: &str, nic_name: &str, source: &str) -> Desired {
        let interface = Identity::vm_interface(&vm_identity(vm_name), nic_name);
        let target = Target::new(Kind::VmInterface, interface.clone());
        Desired::new(Kind::MacAddress, Identity::mac_address(address, Some(&target)), source)
            .field("mac_address", address)
            .reference("assigned_object", Kind::VmInterface, interface)
    }

    fn disk(vm_name: &str, name: &str, source: &str) -> Desired {
        Desired::new(Kind::VirtualDisk, Identity::virtual_disk(&vm_identity(vm_name), name), source)
            .field("name", name)
            .reference("virtual_machine", Kind::VirtualMachine, vm_identity(vm_name))
    }

    /// A virtual machine of the cluster `pve` in NetBox, with one interface
    /// (`eth0`, `eth1`…, ids from `10 × id + 100`) per address given, each
    /// holding a MAC address object (the id of its interface plus 100):
    /// everything under `tags`.
    fn vm_with_macs(id: u64, name: &str, addresses: &[&str], tags: &Value) -> Vec<(Kind, Value)> {
        let mut rows = vec![vm_row(id, name, tags.clone())];
        for (position, address) in (0u64..).zip(addresses) {
            let nic_id = id * 10 + 100 + position;
            rows.push(nic_row(nic_id, id, name, &format!("eth{position}"), tags.clone()));
            rows.push(mac_row(nic_id + 100, address, nic_id, tags.clone()));
        }
        rows
    }

    /// The same machine as a source reports it: its interfaces and their addresses.
    fn reported_vm(name: &str, addresses: &[&str], source: &str) -> Vec<Desired> {
        let mut objects = vec![vm(name, source)];
        for (position, address) in addresses.iter().enumerate() {
            let nic_name = format!("eth{position}");
            objects.push(nic(name, &nic_name, source));
            objects.push(mac(address, name, &nic_name, source));
        }
        objects
    }

    fn state(groups: Vec<Vec<(Kind, Value)>>) -> Vec<Current> {
        let mut by_kind: BTreeMap<Kind, Vec<Row>> = BTreeMap::new();
        for (kind, value) in groups.into_iter().flatten() {
            by_kind.entry(kind).or_default().push(row(value));
        }
        let (current, warnings) = current_objects(&by_kind);
        assert_eq!(warnings, Vec::<String>::new());
        current
    }

    /// Action, kind and key of each change, in the order of the plan.
    fn summary(plan: &Plan) -> Vec<(Action, &str, &str)> {
        plan.steps
            .iter()
            .map(|step| (step.change.action, step.change.kind.as_str(), step.change.key.as_str()))
            .collect()
    }

    /// What a machine reported with one interface and its address creates.
    fn created_with_one_interface<'a>(name: &'a str, address: &'a str) -> Vec<(Action, &'a str, &'a str)> {
        vec![(Action::Create, "vm", name), (Action::Create, "vm_interface", "eth0"), (Action::Create, "mac", address)]
    }

    #[test]
    fn a_renamed_virtual_machine_is_recognised_by_its_mac_address_and_renamed_in_place() {
        // web01 with eth0 (its MAC address and an IP address) and a disk.
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            mac_row(60, MAC_1, 40, owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", Some(40), "eth0", "web01", owned_by(PVE)),
            disk_row(50, 10, "scsi0", owned_by(PVE)),
        ]);
        // The source now calls it web02; nothing else changed.
        let wanted = [
            vm("web02", PVE),
            nic("web02", "eth0", PVE),
            mac(MAC_1, "web02", "eth0", PVE),
            ip("10.0.0.5/24", "web02", "eth0", PVE),
            disk("web02", "scsi0", PVE),
        ];
        let plan = reconcile(&wanted, &current, &run([pruning(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web02", "web02")
                .fields([("name", json!("web02"))])
                .before([("name", json!("web01"))])
                .id(10)]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert_eq!(plan.orphans_kept, Vec::<String>::new());
    }

    #[test]
    fn a_renamed_device_is_recognised_by_the_mac_address_of_an_interface_and_renamed_in_place() {
        // esx01 with vmnic0, its MAC address and an IP address.
        let current = netbox([
            device_row(12, "esx01", 1, owned_by(PVE)),
            pnic_row(30, 12, "esx01", "vmnic0", owned_by(PVE)),
            (
                Kind::MacAddress,
                json!({
                    "id": 61, "mac_address": MAC_1, "assigned_object_type": "dcim.interface",
                    "assigned_object_id": 30, "tags": owned_by(PVE)
                }),
            ),
            (
                Kind::IpAddress,
                json!({
                    "id": 71, "address": "10.0.0.2/24", "vrf": null, "assigned_object_type": "dcim.interface",
                    "assigned_object_id": 30,
                    "assigned_object": {"id": 30, "name": "vmnic0", "device": {"id": 12, "name": "esx01"}},
                    "tags": owned_by(PVE)
                }),
            ),
        ]);
        let vmnic0 = Identity::interface("esx02", "vmnic0");
        let target = Target::new(Kind::Interface, vmnic0.clone());
        let wanted = [
            device("esx02", PVE),
            pnic("esx02", "vmnic0", PVE),
            Desired::new(Kind::MacAddress, Identity::mac_address(MAC_1, Some(&target)), PVE)
                .field("mac_address", MAC_1)
                .reference("assigned_object", Kind::Interface, vmnic0.clone()),
            Desired::new(Kind::IpAddress, Identity::ip_address("10.0.0.2/24", VrfKey::Unknown), PVE)
                .field("address", "10.0.0.2/24")
                .reference("assigned_object", Kind::Interface, vmnic0),
        ];
        let expected = [change("device", Action::Update, "esx02", "esx02")
            .fields([("name", json!("esx02"))])
            .before([("name", json!("esx01"))])
            .id(12)];
        let plan = reconcile(&wanted, &current, &run([pruning(PVE)]));
        assert_eq!(plan.changes(), expected);
        assert_eq!(plan.warnings, Vec::<String>::new());
        // It is in NetBox: `create_devices` has no say in its renaming.
        let renaming_only = SourceFacts { create_devices: false, ..pruning(PVE) };
        let plan = reconcile(&wanted, &current, &run([renaming_only]));
        assert_eq!(plan.changes(), expected);
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_object_the_old_tools_left_is_recognised_and_adopted_under_its_new_name() {
        // netbox-sync tagged what it synced `NetBox-synced` and `Source: <name>`.
        let old = json!([
            {"id": 5, "name": "NetBox-synced", "slug": "netbox-synced"},
            {"id": 6, "name": "Source: pve1", "slug": "source-pve1"}
        ]);
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &old)]);
        let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([pruning(PVE)]));
        let adopted = json!(["netbox-omnisync", "Source: pve1"]);
        let left = json!(["NetBox-synced", "Source: pve1"]);
        assert_eq!(
            plan.changes(),
            [
                change("vm", Action::Update, "web02", "web02")
                    .fields([("name", json!("web02")), ("tags", adopted.clone())])
                    .before([("name", json!("web01")), ("tags", left.clone())])
                    .id(10),
                change("vm_interface", Action::Update, "web02", "eth0")
                    .fields([("tags", adopted.clone())])
                    .before([("tags", left.clone())])
                    .id(200),
                change("mac", Action::Update, "web02", MAC_1)
                    .fields([("tags", adopted)])
                    .before([("tags", left)])
                    .id(300),
            ]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn candidates_that_match_alike_are_not_guessed_between() {
        // Two machines cloned from one template kept its generated address.
        let current = state(vec![
            vec![cluster_row()],
            vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE)),
            vm_with_macs(11, "web03", &[MAC_1], &owned_by(PVE)),
        ]);
        let plan = reconcile(&reported_vm("web09", &[MAC_1], PVE), &current, &run([source(PVE)]));
        assert_eq!(summary(&plan), created_with_one_interface("web09", MAC_1));
        assert_eq!(
            plan.warnings,
            ["vm web09: not found by name, and its MAC addresses match several objects \
              (vm web01: 1, vm web03: 1) without a clear best; none is taken"]
        );
    }

    #[test]
    fn a_best_candidate_short_of_twice_the_matches_of_the_second_is_not_taken() {
        let current = state(vec![
            vec![cluster_row()],
            vm_with_macs(10, "web01", &[MAC_1, MAC_2], &owned_by(PVE)),
            vm_with_macs(11, "web03", &[MAC_1, MAC_2, MAC_3], &owned_by(PVE)),
        ]);
        // Three addresses on web03 against two on web01: one and a half times.
        let plan = reconcile(&reported_vm("web09", &[MAC_1, MAC_2, MAC_3], PVE), &current, &run([source(PVE)]));
        assert_eq!(
            summary(&plan),
            [
                (Action::Create, "vm", "web09"),
                (Action::Create, "vm_interface", "eth0"),
                (Action::Create, "vm_interface", "eth1"),
                (Action::Create, "vm_interface", "eth2"),
                (Action::Create, "mac", MAC_1),
                (Action::Create, "mac", MAC_2),
                (Action::Create, "mac", MAC_3),
            ]
        );
        assert_eq!(
            plan.warnings,
            ["vm web09: not found by name, and its MAC addresses match several objects \
              (vm web03: 3, vm web01: 2) without a clear best; none is taken"]
        );
    }

    #[test]
    fn the_best_candidate_is_taken_when_it_has_twice_the_matches_of_the_second() {
        let current = state(vec![
            vec![cluster_row()],
            vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE)),
            vm_with_macs(11, "web03", &[MAC_1, MAC_2], &owned_by(PVE)),
        ]);
        // Two addresses on web03 against one on web01: it is web03.
        let plan = reconcile(&reported_vm("web09", &[MAC_1, MAC_2], PVE), &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web09", "web09")
                .fields([("name", json!("web09"))])
                .before([("name", json!("web03"))])
                .id(11)]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_address_every_machine_has_designates_none() {
        let null = "00:00:00:00:00:00";
        let current = state(vec![
            vec![cluster_row()],
            vm_with_macs(10, "web01", &[null], &owned_by(PVE)),
            vm_with_macs(11, "web03", &[null, MAC_2], &owned_by(PVE)),
            vm_with_macs(12, "web04", &[null], &owned_by(PVE)),
        ]);
        let plan = reconcile(&reported_vm("web09", &[null], PVE), &current, &run([source(PVE)]));
        assert_eq!(summary(&plan), created_with_one_interface("web09", null));
        assert_eq!(
            plan.warnings,
            ["vm web09: not found by name, and its MAC addresses match several objects \
              (vm web01: 1, vm web03: 1, vm web04: 1) without a clear best; none is taken"]
        );
    }

    #[test]
    fn an_object_another_reported_one_matched_by_name_is_never_a_candidate() {
        // web02 is a clone of web01, with the address of web01: web01 is still
        // reported, it is not what web02 is.
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE))]);
        let mut wanted = reported_vm("web01", &[MAC_1], PVE);
        wanted.extend(reported_vm("web02", &[MAC_1], PVE));
        let plan = reconcile(&wanted, &current, &run([pruning(PVE)]));
        assert_eq!(summary(&plan), created_with_one_interface("web02", MAC_1));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn two_reported_objects_never_end_on_the_same_netbox_object() {
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE))]);
        let mut wanted = reported_vm("web02", &[MAC_1], PVE);
        wanted.extend(reported_vm("web03", &[MAC_1], PVE));
        let plan = reconcile(&wanted, &current, &run([source(PVE)]));
        assert_eq!(
            summary(&plan),
            [
                (Action::Create, "vm", "web02"),
                (Action::Create, "vm", "web03"),
                (Action::Create, "vm_interface", "eth0"),
                (Action::Create, "vm_interface", "eth0"),
                (Action::Create, "mac", MAC_1),
                (Action::Create, "mac", MAC_1),
            ]
        );
        assert_eq!(
            plan.warnings,
            [
                "vm web02: not found by name, and its MAC addresses match vm web01, which vm web03 matches as well; \
                 it is taken for neither",
                "vm web03: not found by name, and its MAC addresses match vm web01, which vm web02 matches as well; \
                 it is taken for neither",
            ]
        );
    }

    #[test]
    fn an_object_reported_without_a_mac_address_is_not_looked_for() {
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE))]);
        // Stopped: its interfaces could not be read.
        let stopped = vm("web02", PVE).unknown_dependents([Kind::VmInterface, Kind::MacAddress, Kind::IpAddress]);
        let plan = reconcile(&[stopped], &current, &run([source(PVE)]));
        assert_eq!(summary(&plan), [(Action::Create, "vm", "web02")]);
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_object_that_shares_no_mac_address_is_never_a_candidate() {
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE))]);
        let plan = reconcile(&reported_vm("web02", &[MAC_2], PVE), &current, &run([source(PVE)]));
        assert_eq!(summary(&plan), created_with_one_interface("web02", MAC_2));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_object_of_another_source_is_never_a_candidate() {
        // web01 is the one of pve2, which ran and may well have dropped it:
        // that is for pve2 to say.
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by("pve2"))]);
        let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([source(PVE), source("pve2")]));
        assert_eq!(summary(&plan), created_with_one_interface("web02", MAC_1));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_object_no_tool_holds_for_the_source_is_never_a_candidate() {
        for tags in [
            // Made by hand.
            tagged([]),
            // The tag of the source alone: no tool says it holds it.
            tagged(["source-pve1"]),
            // The tool's, but of no source.
            tagged(["netbox-omnisync"]),
            // An old tool's, for a source that is not this one.
            tagged(["netbox-synced", "source-vcenter-old"]),
        ] {
            let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &tags)]);
            let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([pruning(PVE)]));
            assert_eq!(summary(&plan), created_with_one_interface("web02", MAC_1), "tags {tags}");
            assert_eq!(plan.warnings, Vec::<String>::new(), "tags {tags}");
        }
    }

    #[test]
    fn an_object_also_held_for_a_source_that_did_not_succeed_is_never_a_candidate() {
        let shared = json!([
            {"id": 1, "name": "netbox-omnisync", "slug": "netbox-omnisync"},
            {"id": 2, "name": "source-pve1", "slug": "source-pve1"},
            {"id": 3, "name": "source-pve2", "slug": "source-pve2"}
        ]);
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &shared)]);
        for status in [SourceStatus::Failed, SourceStatus::Skipped] {
            // pve2 said nothing in this run: it may still know the machine as web01.
            let silent = SourceFacts { status, ..pruning("pve2") };
            let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([pruning(PVE), silent]));
            // web02 is new; web01 stays, and only loses the tag of pve1, which dropped it.
            assert_eq!(
                summary(&plan),
                [
                    (Action::Update, "vm", "web01"),
                    (Action::Create, "vm", "web02"),
                    (Action::Update, "vm_interface", "eth0"),
                    (Action::Create, "vm_interface", "eth0"),
                    (Action::Update, "mac", MAC_1),
                    (Action::Create, "mac", MAC_1),
                ],
                "{status:?}"
            );
            let renamed =
                plan.steps.iter().any(|step| step.change.fields.contains_key("name") && step.change.id.is_some());
            assert!(!renamed, "{status:?}");
            assert_eq!(plan.warnings, Vec::<String>::new(), "{status:?}");
        }
    }

    #[test]
    fn what_a_source_that_did_not_succeed_reports_renames_nothing() {
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE))]);
        let failed = SourceFacts { status: SourceStatus::Failed, ..pruning(PVE) };
        let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([failed]));
        assert_eq!(plan.changes(), []);
        assert_eq!(plan.warnings, ["source pve1 did not succeed: 3 reported object(s) ignored"]);
    }

    #[test]
    fn a_virtual_machine_of_another_cluster_is_never_a_candidate() {
        let (kind, mut web01) = vm_row(10, "web01", owned_by(PVE));
        web01["cluster"] = json!({"id": 4, "name": "other", "display": "other"});
        let current = netbox([
            cluster_row(),
            (Kind::Cluster, json!({"id": 4, "name": "other", "tags": []})),
            (kind, web01),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            mac_row(60, MAC_1, 40, owned_by(PVE)),
        ]);
        let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([source(PVE)]));
        assert_eq!(summary(&plan), created_with_one_interface("web02", MAC_1));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn a_device_and_a_virtual_machine_are_never_taken_for_one_another() {
        // A machine that routes for its host, with the address of the host's bridge.
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE))]);
        let vmbr0 = Identity::interface("esx02", "vmbr0");
        let target = Target::new(Kind::Interface, vmbr0.clone());
        let wanted = [
            device("esx02", PVE),
            pnic("esx02", "vmbr0", PVE),
            Desired::new(Kind::MacAddress, Identity::mac_address(MAC_1, Some(&target)), PVE)
                .field("mac_address", MAC_1)
                .reference("assigned_object", Kind::Interface, vmbr0),
        ];
        let plan = reconcile(&wanted, &current, &run([source(PVE)]));
        assert_eq!(
            summary(&plan),
            [
                (Action::Create, "device", "esx02"),
                (Action::Create, "interface", "vmbr0"),
                (Action::Create, "mac", MAC_1)
            ]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());

        // The other way round: the bridge of esx01 holds the address a new machine reports.
        let current = netbox([
            cluster_row(),
            device_row(12, "esx01", 1, owned_by(PVE)),
            pnic_row(30, 12, "esx01", "vmbr0", owned_by(PVE)),
            (
                Kind::MacAddress,
                json!({
                    "id": 61, "mac_address": MAC_1, "assigned_object_type": "dcim.interface",
                    "assigned_object_id": 30, "tags": owned_by(PVE)
                }),
            ),
        ]);
        let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([source(PVE)]));
        assert_eq!(summary(&plan), created_with_one_interface("web02", MAC_1));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    // A report that only completes an object (a BMC), and a source read in part

    const BMC: &str = "bmc1";

    fn type_row(id: u64, manufacturer: (u64, &str), model: &str, tags: Value) -> (Kind, Value) {
        let nested = json!({"id": manufacturer.0, "name": manufacturer.1});
        (Kind::DeviceType, json!({"id": id, "model": model, "manufacturer": nested, "tags": tags}))
    }

    fn maker_row(id: u64, name: &str, tags: Value) -> (Kind, Value) {
        (Kind::Manufacturer, json!({"id": id, "name": name, "tags": tags}))
    }

    /// A server as NetBox renders it, with the type and the serial it has.
    fn server_row(name: &str, device_type: (u64, &str), serial: &str, tags: Value) -> (Kind, Value) {
        let nested = json!({"id": device_type.0, "model": device_type.1, "display": device_type.1});
        (Kind::Device, json!({"id": 5, "name": name, "device_type": nested, "serial": serial, "tags": tags}))
    }

    /// A NetBox holding the server `pve01.lab01` with its two possible device types.
    fn server_room(device_type: (u64, &str), serial: &str, tags: Value) -> Vec<Current> {
        netbox([
            maker_row(20, "Generic Manufacturer", owned_by(PVE)),
            maker_row(21, "Dell", json!([])),
            type_row(30, (20, "Generic Manufacturer"), "Generic Model", owned_by(PVE)),
            type_row(31, (21, "Dell"), "PowerEdge R630", json!([])),
            server_row("pve01.lab01", device_type, serial, tags),
        ])
    }

    const GENERIC: (u64, &str) = (30, "Generic Model");
    const R630: (u64, &str) = (31, "PowerEdge R630");

    /// What a hypervisor that knows nothing of the hardware reports: the
    /// server, with a generic device type it only writes on a device that has none.
    fn hypervisor_reports(source: &str) -> Vec<Desired> {
        let generic = Identity::device_type("Generic Manufacturer", "Generic Model");
        vec![
            Desired::new(Kind::Manufacturer, Identity::named("Generic Manufacturer"), source)
                .field("name", "Generic Manufacturer"),
            Desired::new(Kind::DeviceType, generic.clone(), source).field("model", "Generic Model").reference(
                "manufacturer",
                Kind::Manufacturer,
                Identity::named("Generic Manufacturer"),
            ),
            Desired::new(Kind::Device, Identity::device("pve01.lab01"), source)
                .field("name", "pve01.lab01")
                .reference("device_type", Kind::DeviceType, generic)
                .only_when_empty("device_type"),
        ]
    }

    /// What a BMC reports of the same server: a type that only has to exist,
    /// and the device completed with that type and its serial.
    fn bmc_reports(source: &str, serial: &str) -> Vec<Desired> {
        let r630 = Identity::device_type("Dell", "PowerEdge R630");
        vec![
            Desired::new(Kind::Manufacturer, Identity::named("Dell"), source).field("name", "Dell").ensure_only(),
            Desired::new(Kind::DeviceType, r630.clone(), source)
                .field("model", "PowerEdge R630")
                .reference("manufacturer", Kind::Manufacturer, Identity::named("Dell"))
                .ensure_only(),
            Desired::new(Kind::Device, Identity::device("pve01.lab01"), source)
                .complement()
                .reference("device_type", Kind::DeviceType, r630)
                .field("serial", serial),
        ]
    }

    /// The two sources, ranked as given: `[]` leaves the order to their names.
    fn ranked<const N: usize>(priority: [&str; N]) -> Run {
        Run { priority: priority.iter().map(|name| (*name).to_owned()).collect(), ..run([pruning(PVE), source(BMC)]) }
    }

    /// Every way the two sources can be ranked.
    fn rankings() -> [Run; 3] {
        [ranked([]), ranked([PVE, BMC]), ranked([BMC, PVE])]
    }

    fn both(serial: &str) -> Vec<Desired> {
        hypervisor_reports(PVE).into_iter().chain(bmc_reports(BMC, serial)).collect()
    }

    #[test]
    fn what_a_bmc_knows_wins_over_the_fallback_of_a_hypervisor_whatever_the_priority() {
        for run in rankings() {
            let current = server_room(GENERIC, "", owned_by(PVE));
            let plan = reconcile(&both("SVCTAG1"), &current, &run);
            assert_eq!(plan.warnings, Vec::<String>::new(), "{:?}", run.priority);
            // One write: the type and the serial of the device. Its tags stay
            // the hypervisor's: the BMC does not own it. The Dell objects were
            // only needed to exist, and are left as somebody made them.
            assert_eq!(
                plan.changes(),
                [change("device", Action::Update, "pve01.lab01", "pve01.lab01")
                    .fields([("device_type", json!("PowerEdge R630")), ("serial", json!("SVCTAG1"))])
                    .before([("device_type", json!("Generic Model")), ("serial", json!(""))])
                    .id(5)],
                "{:?}",
                run.priority
            );
        }
    }

    #[test]
    fn a_device_a_bmc_completed_is_stable_whoever_reports_it_next() {
        let current = server_room(R630, "SVCTAG1", owned_by(PVE));
        // Both sources again, in every ranking: nothing moves.
        for run in rankings() {
            assert_eq!(reconcile(&both("SVCTAG1"), &current, &run), nothing(), "{:?}", run.priority);
        }
        // The hypervisor alone, the BMC source left out (it runs once a day):
        // the generic type is a fallback, and the serial is not its to say.
        let skipped = SourceFacts { status: SourceStatus::Skipped, ..source(BMC) };
        let alone = run([pruning(PVE), skipped]);
        assert_eq!(reconcile(&hypervisor_reports(PVE), &current, &alone), nothing());
        // The BMC alone, the hypervisor left out.
        let skipped = SourceFacts { status: SourceStatus::Skipped, ..pruning(PVE) };
        let alone = run([skipped, source(BMC)]);
        assert_eq!(reconcile(&bmc_reports(BMC, "SVCTAG1"), &current, &alone), nothing());
    }

    #[test]
    fn a_bmc_alone_completes_a_device_and_never_tags_it() {
        // A server made by hand, which no tool owns.
        let current = server_room(GENERIC, "", json!([]));
        let plan = reconcile(&bmc_reports(BMC, "SVCTAG1"), &current, &run([source(BMC)]));
        assert_eq!(plan.warnings, Vec::<String>::new());
        // No `tags` among the fields: the device is not adopted.
        assert_eq!(
            plan.changes(),
            [change("device", Action::Update, "pve01.lab01", "pve01.lab01")
                .fields([("device_type", json!("PowerEdge R630")), ("serial", json!("SVCTAG1"))])
                .before([("device_type", json!("Generic Model")), ("serial", json!(""))])
                .id(5)]
        );
    }

    #[test]
    fn a_report_that_only_completes_never_creates_its_object() {
        // The device types exist, the device does not.
        let current =
            netbox([maker_row(21, "Dell", json!([])), type_row(31, (21, "Dell"), "PowerEdge R630", json!([]))]);
        // Even with `create_devices` on: there is no owner to create it for.
        let plan = reconcile(&bmc_reports(BMC, "SVCTAG1"), &current, &run([source(BMC)]));
        assert_eq!(plan.changes(), []);
        assert_eq!(
            plan.warnings,
            ["device pve01.lab01: not in NetBox, and bmc1 only completes an object that exists; skipped"]
        );
    }

    /// A host as a source that knows its hardware reports it (a vCenter).
    fn known_host(source: &str, serial: &str) -> Desired {
        Desired::new(Kind::Device, Identity::device("pve01.lab01"), source)
            .field("name", "pve01.lab01")
            .field("serial", serial)
            .reference("device_type", Kind::DeviceType, Identity::device_type("Dell", "PowerEdge R630"))
    }

    /// A NetBox holding that host and its type, without the generic one that source never reports.
    fn known_room(serial: &str) -> Vec<Current> {
        netbox([
            maker_row(21, "Dell", json!([])),
            type_row(31, (21, "Dell"), "PowerEdge R630", json!([])),
            server_row("pve01.lab01", R630, serial, owned_by(PVE)),
        ])
    }

    #[test]
    fn two_sources_that_know_a_field_differently_are_settled_by_the_priority_field_by_field() {
        let current = known_room("OLD");
        let reports: Vec<Desired> =
            std::iter::once(known_host(PVE, "FROM-VC")).chain(bmc_reports(BMC, "FROM-BMC")).collect();
        let serial =
            |plan: &Plan| plan.changes().iter().map(|change| change.fields["serial"].clone()).collect::<Vec<_>>();
        // The BMC first: its serial is written. The device type, on which both agree, is no difference.
        let plan = reconcile(&reports, &current, &ranked([BMC, PVE]));
        assert_eq!(serial(&plan), [json!("FROM-BMC")]);
        assert_eq!(
            plan.warnings,
            ["device pve01.lab01: serial reported differently by bmc1 and pve1; bmc1 wins (source priority)"]
        );
        // The hypervisor first: its own.
        let plan = reconcile(&reports, &current, &ranked([PVE, BMC]));
        assert_eq!(serial(&plan), [json!("FROM-VC")]);
        assert_eq!(
            plan.warnings,
            ["device pve01.lab01: serial reported differently by pve1 and bmc1; pve1 wins (source priority)"]
        );
        // Unranked: the first by name, as for two whole reports.
        let plan = reconcile(&reports, &current, &ranked([]));
        assert_eq!(serial(&plan), [json!("FROM-BMC")]);
    }

    #[test]
    fn two_sources_that_know_a_field_differently_never_write_it_back_and_forth() {
        // What the winner wrote is what the same two reports find at the next run.
        let reports: Vec<Desired> =
            std::iter::once(known_host(PVE, "FROM-VC")).chain(bmc_reports(BMC, "FROM-BMC")).collect();
        for (run, kept) in [(ranked([BMC, PVE]), "FROM-BMC"), (ranked([PVE, BMC]), "FROM-VC"), (ranked([]), "FROM-BMC")]
        {
            let current = known_room(kept);
            assert_eq!(reconcile(&reports, &current, &run).changes(), [], "{:?}", run.priority);
        }
    }

    #[test]
    fn a_completing_report_that_agrees_with_the_owner_says_nothing() {
        let current = known_room("SVCTAG1");
        let reports: Vec<Desired> =
            std::iter::once(known_host(PVE, "SVCTAG1")).chain(bmc_reports(BMC, "SVCTAG1")).collect();
        for run in rankings() {
            assert_eq!(reconcile(&reports, &current, &run), nothing(), "{:?}", run.priority);
        }
    }

    #[test]
    fn a_source_read_in_part_is_written_and_says_nothing_of_what_it_did_not_report() {
        // pve1 could read `web01` and not `gone01`; `shared01` is also vc1's, which reports it.
        let shared = json!([
            {"id": 1, "name": "netbox-omnisync", "slug": "netbox-omnisync"},
            {"id": 2, "name": "source-pve1", "slug": "source-pve1"},
            {"id": 3, "name": "source-vc1", "slug": "source-vc1"}
        ]);
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            vm_row(11, "gone01", owned_by(PVE)),
            vm_row(12, "shared01", shared),
        ]);
        let reports = [vm("web01", PVE).field("vcpus", 4), vm("shared01", "vc1")];
        let partial = SourceFacts { status: SourceStatus::Partial, ..pruning(PVE) };
        let plan = reconcile(&reports, &current, &run([partial, pruning("vc1")]));
        // What it did read is written; nothing is deleted, no tag is taken back.
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("vcpus", json!(4))])
                .before([("vcpus", json!(2.0))])
                .id(10)]
        );
        assert_eq!(plan.orphans_kept, Vec::<String>::new());
        // The same reports from a source that ran to the end: `gone01` is deleted, and the tag of
        // pve1 leaves `shared01`.
        let plan = reconcile(&reports, &current, &run([pruning(PVE), pruning("vc1")]));
        let touched: Vec<(Action, String)> =
            plan.changes().into_iter().map(|change| (change.action, change.key)).collect();
        assert_eq!(
            touched,
            [
                (Action::Update, "shared01".to_owned()),
                (Action::Update, "web01".to_owned()),
                (Action::Delete, "gone01".to_owned())
            ]
        );
    }

    #[test]
    fn a_source_read_in_part_asks_for_its_tags() {
        let facts = [SourceFacts { status: SourceStatus::Partial, ..source(BMC) }];
        let slugs: Vec<String> =
            ownership_tags(&run(facts), &[]).iter().map(|tag| tag.identity.label().to_owned()).collect();
        assert_eq!(slugs, ["netbox-omnisync", "source-bmc1"]);
    }

    // Renames, completing reports and sources read in part, together

    /// `esx01` in NetBox, held for pve1, with `vmnic0` and its MAC address; no serial yet.
    fn esx01_room(tags: &Value) -> Vec<Current> {
        let (kind, mut esx01) = device_row(12, "esx01", 1, tags.clone());
        esx01["serial"] = json!("");
        netbox([
            (kind, esx01),
            pnic_row(30, 12, "esx01", "vmnic0", tags.clone()),
            (
                Kind::MacAddress,
                json!({
                    "id": 61, "mac_address": MAC_1, "assigned_object_type": "dcim.interface",
                    "assigned_object_id": 30, "tags": tags.clone()
                }),
            ),
        ])
    }

    /// A host with `vmnic0` and its MAC address, as a hypervisor reports it.
    fn reported_host(name: &str, source: &str) -> Vec<Desired> {
        let vmnic0 = Identity::interface(name, "vmnic0");
        let target = Target::new(Kind::Interface, vmnic0.clone());
        vec![
            device(name, source),
            pnic(name, "vmnic0", source),
            Desired::new(Kind::MacAddress, Identity::mac_address(MAC_1, Some(&target)), source)
                .field("mac_address", MAC_1)
                .reference("assigned_object", Kind::Interface, vmnic0),
        ]
    }

    /// What a BMC says of the device `name`: its serial, completing it.
    fn completed(name: &str, serial: &str) -> Desired {
        Desired::new(Kind::Device, Identity::device(name), BMC).complement().field("serial", serial)
    }

    fn renamed_esx02() -> Change {
        change("device", Action::Update, "esx02", "esx02")
            .fields([("name", json!("esx02"))])
            .before([("name", json!("esx01"))])
            .id(12)
    }

    #[test]
    fn a_report_that_only_completes_is_never_looked_for_by_its_mac_addresses() {
        // The worst case: the device even carries the tag of the completing source.
        let current = esx01_room(&tagged(["netbox-omnisync", "source-bmc1"]));
        // Nobody owns `esx02`: a BMC alone names it, with the interface and the address of `esx01`.
        let reports: Vec<Desired> = reported_host("esx02", BMC).into_iter().map(Desired::complement).collect();
        let plan = reconcile(&reports, &current, &run([source(BMC)]));
        // Neither renamed nor created; its interface and its address are skipped with it.
        assert_eq!(plan.changes(), []);
        assert_eq!(
            plan.warnings,
            ["device esx02: not in NetBox, and bmc1 only completes an object that exists; skipped"]
        );
    }

    #[test]
    fn a_completing_report_under_the_old_name_does_not_keep_a_renamed_device_from_being_recognised() {
        let current = esx01_room(&owned_by(PVE));
        // The hypervisor renamed the host; the BMC entry still names it `esx01`. Whichever of
        // the two names comes first.
        for renamed in ["esx00", "esx02"] {
            let mut reports = reported_host(renamed, PVE);
            reports.push(completed("esx01", "SVCTAG1"));
            for run in rankings() {
                let plan = reconcile(&reports, &current, &run);
                // Renamed in place: not created anew, nor deleted under its old name. What the
                // BMC says waits for its entry to name the device as it is now called.
                assert_eq!(
                    plan.changes(),
                    [change("device", Action::Update, renamed, renamed)
                        .fields([("name", json!(renamed))])
                        .before([("name", json!("esx01"))])
                        .id(12)],
                    "{renamed} {:?}",
                    run.priority
                );
                assert_eq!(
                    plan.warnings,
                    [format!(
                        "device esx01: renamed {renamed} by this run, and bmc1 only completes it under the name it \
                         had; skipped"
                    )],
                    "{renamed} {:?}",
                    run.priority
                );
                assert_eq!(plan.orphans_kept, Vec::<String>::new(), "{renamed} {:?}", run.priority);
            }
        }
    }

    #[test]
    fn a_renamed_device_is_completed_under_its_new_name_in_the_write_that_renames_it() {
        let current = esx01_room(&owned_by(PVE));
        let mut reports = reported_host("esx02", PVE);
        reports.push(completed("esx02", "SVCTAG1"));
        for run in rankings() {
            let plan = reconcile(&reports, &current, &run);
            assert_eq!(
                plan.changes(),
                [change("device", Action::Update, "esx02", "esx02")
                    .fields([("name", json!("esx02")), ("serial", json!("SVCTAG1"))])
                    .before([("name", json!("esx01")), ("serial", json!(""))])
                    .id(12)],
                "{:?}",
                run.priority
            );
            assert_eq!(plan.warnings, Vec::<String>::new(), "{:?}", run.priority);
        }
    }

    #[test]
    fn a_completing_source_read_in_part_does_not_keep_a_device_from_being_recognised() {
        // The BMC source could not read one BMC: it holds no device, so it is not asked.
        let current = esx01_room(&owned_by(PVE));
        let partial = SourceFacts { status: SourceStatus::Partial, ..source(BMC) };
        let plan = reconcile(&reported_host("esx02", PVE), &current, &run([pruning(PVE), partial]));
        assert_eq!(plan.changes(), [renamed_esx02()]);
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_object_also_held_for_a_source_read_in_part_is_never_a_candidate() {
        let shared = json!([
            {"id": 1, "name": "netbox-omnisync", "slug": "netbox-omnisync"},
            {"id": 2, "name": "source-pve1", "slug": "source-pve1"},
            {"id": 3, "name": "source-pve2", "slug": "source-pve2"}
        ]);
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &shared)]);
        // pve2 read a part of its cluster only: `web01` may be in the part it did not read.
        let partial = SourceFacts { status: SourceStatus::Partial, ..pruning("pve2") };
        let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([pruning(PVE), partial]));
        // As for a source that failed: web02 is new, and web01 only loses the tag of pve1.
        assert_eq!(
            summary(&plan),
            [
                (Action::Update, "vm", "web01"),
                (Action::Create, "vm", "web02"),
                (Action::Update, "vm_interface", "eth0"),
                (Action::Create, "vm_interface", "eth0"),
                (Action::Update, "mac", MAC_1),
                (Action::Create, "mac", MAC_1),
            ]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn a_source_read_in_part_renames_nothing_it_reports_under_a_new_name() {
        let current = state(vec![vec![cluster_row()], vm_with_macs(10, "web01", &[MAC_1], &owned_by(PVE))]);
        // pve1 did not report `web01`, which says nothing: the machine may be in what it could not read.
        let partial = SourceFacts { status: SourceStatus::Partial, ..pruning(PVE) };
        let plan = reconcile(&reported_vm("web02", &[MAC_1], PVE), &current, &run([partial]));
        // What it reports is written, as a new machine; web01 is neither renamed nor an orphan.
        assert_eq!(summary(&plan), created_with_one_interface("web02", MAC_1));
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert_eq!(plan.orphans_kept, Vec::<String>::new());
    }

    // NetBox protects a cluster that still holds a machine (`VirtualMachine.cluster`
    // is PROTECT): the delete would be refused, and stop every later step of the plan.
    #[test]
    fn an_orphan_a_machine_nobody_reported_still_points_to_is_not_deleted() {
        let current = netbox([
            (Kind::Cluster, json!({"id": 3, "name": "old", "tags": owned_by(PVE)})),
            (
                Kind::VirtualMachine,
                json!({"id": 9, "name": "handmade", "cluster": {"id": 3, "name": "old"}, "tags": []}),
            ),
        ]);
        let plan = reconcile(&[], &current, &run([pruning(PVE)]));
        assert_eq!(plan.steps, Vec::<Step>::new());
        assert_eq!(plan.warnings, ["cluster old: not deleted, vm handmade still refers to it"]);
    }

    // `Device.platform` is SET_NULL in NetBox: deleting the platform would clear
    // it, without a word, on a device the tool does not own.
    #[test]
    fn an_orphan_a_device_of_someone_else_still_uses_is_not_deleted() {
        let current = netbox([
            (Kind::Platform, json!({"id": 5, "name": "ubuntu", "slug": "ubuntu", "tags": owned_by(PVE)})),
            (Kind::Device, json!({"id": 20, "name": "hand01", "platform": {"id": 5, "name": "ubuntu"}, "tags": []})),
        ]);
        let plan = reconcile(&[], &current, &run([pruning(PVE)]));
        assert_eq!(plan.steps, Vec::<Step>::new());
        assert_eq!(plan.warnings, ["platform ubuntu: not deleted, device hand01 still refers to it"]);
    }

    // --- VLAN groups ---------------------------------------------------------

    const EAST: &str = "East";

    fn group_row() -> (Kind, Value) {
        (Kind::VlanGroup, json!({"id": 7, "name": EAST, "slug": "east", "tags": []}))
    }

    /// The VLAN `vid` of the site `east-01`.
    fn site_vlan_row(id: u64, vid: u64, name: &str, tags: Value) -> (Kind, Value) {
        let site = json!({"id": 2, "name": "east-01"});
        (Kind::Vlan, json!({"id": id, "vid": vid, "name": name, "site": site, "group": null, "tags": tags}))
    }

    /// The VLAN `vid` of the group, which has no site.
    fn group_vlan_row(id: u64, vid: u64, name: &str, tags: Value) -> (Kind, Value) {
        let group = json!({"id": 7, "name": EAST});
        (Kind::Vlan, json!({"id": id, "vid": vid, "name": name, "site": null, "group": group, "tags": tags}))
    }

    fn group_vlan_identity(vid: u64) -> Identity {
        Identity::vlan(VlanScope::Group(EAST), vid)
    }

    /// A VLAN of the group as a source declares it: it only has to exist.
    fn group_vlan(vid: u64, name: &str, source: &str) -> Desired {
        Desired::new(Kind::Vlan, group_vlan_identity(vid), source)
            .field("vid", vid)
            .create_only("name", name)
            .ensure_only()
            .reference("group", Kind::VlanGroup, Identity::named(EAST))
    }

    /// `nic_row` with the VLANs the interface points to.
    fn port_row(id: u64, name: &str, untagged: Option<u64>, tagged: &[u64], tags: Value) -> (Kind, Value) {
        let vlans: Vec<Value> = tagged.iter().map(|id| json!({"id": id, "vid": 10, "name": "VLAN10"})).collect();
        (
            Kind::VmInterface,
            json!({
                "id": id, "name": name, "enabled": true, "parent": null,
                "virtual_machine": {"id": 1, "name": "web"}, "mode": {"value": "access", "label": "Access"},
                "untagged_vlan": untagged.map(|id| json!({"id": id, "vid": 10, "name": "VLAN10"})),
                "tagged_vlans": vlans, "tags": tags
            }),
        )
    }

    fn access_port(name: &str, source: &str) -> Desired {
        nic("web", name, source).field("mode", "access").reference("untagged_vlan", Kind::Vlan, group_vlan_identity(10))
    }

    // The site joined a VLAN group: its interfaces are moved to the VLAN of the
    // group, and the VLAN of the site, which the source owned and no longer
    // reports, goes after them, in the same run.
    #[test]
    fn the_vlan_of_a_site_that_joined_a_group_goes_once_its_interfaces_point_to_the_one_of_the_group() {
        let current = netbox([
            group_row(),
            site_vlan_row(30, 10, "VLAN10", owned_by(PVE)),
            group_vlan_row(31, 10, "prod", json!([])),
            cluster_row(),
            vm_row(1, "web", owned_by(PVE)),
            port_row(10, "eth0", Some(30), &[], owned_by(PVE)),
        ]);
        let desired = [vm("web", PVE), access_port("eth0", PVE), group_vlan(10, "VLAN10", PVE)];
        let plan = reconcile(&desired, &current, &run([pruning(PVE)]));
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert_eq!(plan.errors, Vec::<String>::new());
        let steps: Vec<(Phase, Action, &str, &str, Option<u64>)> = plan
            .steps
            .iter()
            .map(|step| {
                (step.phase, step.change.action, step.change.kind.as_str(), step.change.key.as_str(), step.change.id)
            })
            .collect();
        // The reference first, the deletion after: NetBox never has to clear the field itself.
        assert_eq!(
            steps,
            [
                (Phase::Write, Action::Update, "vm_interface", "eth0", Some(10)),
                (Phase::Delete, Action::Delete, "vlan", "10", Some(30)),
            ]
        );
        let moved = &plan.steps[0];
        assert_eq!(moved.references["untagged_vlan"].as_ref().and_then(|link| link.id), Some(31));
        // The VLAN of the group nobody owns is used as it is: neither renamed nor tagged.
        assert!(!plan.steps.iter().any(|step| step.change.id == Some(31)));
    }

    // A second run finds the interface on the VLAN of the group and the VLAN of the site gone.
    #[test]
    fn a_site_in_a_vlan_group_is_stable_once_moved() {
        let current = netbox([
            group_row(),
            group_vlan_row(31, 10, "prod", json!([])),
            cluster_row(),
            vm_row(1, "web", owned_by(PVE)),
            port_row(10, "eth0", Some(31), &[], owned_by(PVE)),
        ]);
        let desired = [vm("web", PVE), access_port("eth0", PVE), group_vlan(10, "VLAN10", PVE)];
        assert_eq!(reconcile(&desired, &current, &run([pruning(PVE)])), nothing());
    }

    // Rule 4 of the orphans: an interface this run leaves as it is (the port of
    // a switch, a machine made by hand) still uses the VLAN of the site.
    #[test]
    fn the_vlan_of_a_site_an_interface_nobody_reported_still_uses_is_not_deleted() {
        for (untagged, tagged) in [(Some(30), vec![]), (None, vec![30])] {
            let current = netbox([
                group_row(),
                site_vlan_row(30, 10, "VLAN10", owned_by(PVE)),
                group_vlan_row(31, 10, "prod", json!([])),
                cluster_row(),
                vm_row(1, "web", json!([])),
                port_row(10, "eth0", untagged, &tagged, json!([])),
            ]);
            let plan = reconcile(&[group_vlan(10, "VLAN10", PVE)], &current, &run([pruning(PVE)]));
            assert_eq!(plan.steps, Vec::<Step>::new(), "{untagged:?} {tagged:?}");
            // NetBox would take the VLAN off the interface without a word, tagged or not.
            assert_eq!(plan.warnings, ["vlan 10: not deleted, vm_interface web eth0 still refers to it"]);
        }
    }

    // The source reports the interface, and says nothing of its tagged VLANs:
    // the ones NetBox has there are still in use.
    #[test]
    fn the_vlan_of_a_site_a_reported_interface_still_carries_tagged_is_not_deleted() {
        let current = netbox([
            site_vlan_row(30, 10, "VLAN10", owned_by(PVE)),
            cluster_row(),
            vm_row(1, "web", owned_by(PVE)),
            port_row(10, "eth0", None, &[30], owned_by(PVE)),
        ]);
        let desired = [vm("web", PVE), nic("web", "eth0", PVE)];
        let plan = reconcile(&desired, &current, &run([pruning(PVE)]));
        assert_eq!(plan.steps, Vec::<Step>::new());
    }

    // The group is a prerequisite. Without it the VLAN would be created with
    // neither group nor site: a global VLAN no run would ever find again.
    #[test]
    fn a_vlan_whose_group_is_not_in_netbox_is_an_error_and_is_not_created_without_it() {
        let current =
            netbox([cluster_row(), vm_row(1, "web", owned_by(PVE)), port_row(10, "eth0", None, &[], owned_by(PVE))]);
        let desired = [vm("web", PVE), access_port("eth0", PVE), group_vlan(10, "VLAN10", PVE)];
        let plan = reconcile(&desired, &current, &run([pruning(PVE)]));
        assert_eq!(plan.errors, ["pve1: vlan 10: VLAN group East is not in NetBox; the VLAN is not created"]);
        assert_eq!(plan.steps, Vec::<Step>::new());
        assert_eq!(
            plan.warnings,
            ["vm_interface web eth0: untagged_vlan refers to vlan 10, which is skipped; field left untouched"]
        );
    }

    // A VLAN of the group that also has a site is identified by its site: it
    // is not the VLAN of the group the source looks for, and NetBox would
    // refuse a second VLAN of that number in the group.
    #[test]
    fn a_vlan_of_the_group_that_also_has_a_site_is_an_error_naming_it_and_is_not_created_again() {
        let sited = json!({"id": 30, "vid": 20, "name": "prod", "site": {"id": 1, "name": "east-02"},
            "group": {"id": 7, "name": EAST}, "tags": []});
        let current = netbox([group_row(), (Kind::Vlan, sited)]);
        let plan = reconcile(&[group_vlan(20, "VLAN20", PVE)], &current, &run([pruning(PVE)]));
        assert_eq!(
            plan.errors,
            ["pve1: vlan 20: VLAN 20 of VLAN group East also has the site east-02, and a VLAN several sites share \
              has none: clear its site; the VLAN is not created"]
        );
        assert_eq!(plan.steps, Vec::<Step>::new());
    }

    // NetBox refuses two VLANs of a group under one name, and a refused write
    // stops the run: the conflict is told before, naming both VLANs.
    #[test]
    fn a_vlan_whose_name_another_vlan_of_the_group_has_is_an_error_naming_both() {
        let current = netbox([group_row(), group_vlan_row(31, 120, "dmz", json!([]))]);
        let desired = [group_vlan(130, "dmz", PVE), group_vlan(140, "lan", PVE)];
        let plan = reconcile(&desired, &current, &run([pruning(PVE)]));
        assert_eq!(
            plan.errors,
            ["pve1: vlan 130: its name dmz is the one of VLAN 120 in VLAN group East; the VLAN is not created"]
        );
        // The other one is created.
        let created: Vec<&str> = plan.steps.iter().map(|step| step.change.key.as_str()).collect();
        assert_eq!(created, ["140"]);
    }

    #[test]
    fn two_vlans_a_run_would_create_under_one_name_in_a_group_are_not_both_created() {
        let current = netbox([group_row()]);
        let desired = [group_vlan(120, "dmz", PVE), group_vlan(130, "dmz", "vc1")];
        let plan = reconcile(&desired, &current, &run([pruning(PVE), pruning("vc1")]));
        assert_eq!(
            plan.errors,
            ["vc1: vlan 130: its name dmz is the one of VLAN 120 in VLAN group East; the VLAN is not created"]
        );
        let created: Vec<&str> = plan.steps.iter().map(|step| step.change.key.as_str()).collect();
        assert_eq!(created, ["120"]);
    }

    // The same name at a site is no conflict: NetBox only makes it unique in a group.
    #[test]
    fn two_vlans_of_a_site_may_share_a_name() {
        let site = |vid: u64| {
            Desired::new(Kind::Vlan, Identity::vlan(VlanScope::Site("east-01"), vid), PVE)
                .field("vid", vid)
                .create_only("name", "dmz")
                .ensure_only()
        };
        let plan = reconcile(&[site(120), site(130)], &[], &run([pruning(PVE)]));
        assert_eq!(plan.errors, Vec::<String>::new());
        assert_eq!(plan.steps.len(), 2);
    }

    fn east() -> VlanGroups {
        let mut groups = VlanGroups::default();
        groups.insert("east-02", EAST);
        groups.insert("east-01", EAST);
        groups
    }

    // The VLAN of a site nobody owns is never touched: once its site is in a
    // group that holds the same VLAN, it is told, with what still uses it.
    #[test]
    fn a_vlan_of_a_site_nobody_owns_that_its_group_holds_too_is_a_warning_with_its_interfaces() {
        let fw = json!({"id": 20, "name": "port3", "parent": null, "device": {"id": 5, "name": "fw01"},
            "untagged_vlan": {"id": 40, "vid": 15}, "tagged_vlans": [], "tags": []});
        let current = netbox([
            group_row(),
            site_vlan_row(40, 15, "housing", json!([])),
            group_vlan_row(41, 15, "housing", json!([])),
            // Owned: the orphan rule deals with it, not this warning.
            site_vlan_row(42, 16, "old", owned_by(PVE)),
            group_vlan_row(43, 16, "new", json!([])),
            // The group does not hold this one.
            site_vlan_row(44, 17, "alone", json!([])),
            (Kind::Interface, fw),
            cluster_row(),
            vm_row(1, "web", json!([])),
            port_row(10, "eth1", None, &[40], json!([])),
        ]);
        assert_eq!(
            site_vlan_leftovers(&current, &east()),
            ["vlan 15 of site east-01: VLAN group East holds this VLAN, and nobody owns the one of the site; \
              2 interface(s) still point to it (interface fw01 port3, vm_interface web eth1): move them, then \
              delete it by hand"]
        );
        // A site that is in no group keeps its VLANs, whatever a group holds.
        assert_eq!(site_vlan_leftovers(&current, &VlanGroups::default()), Vec::<String>::new());
    }

    #[test]
    fn a_leftover_vlan_no_interface_points_to_is_told_as_ready_to_delete() {
        let current =
            netbox([group_row(), site_vlan_row(40, 15, "housing", json!([])), group_vlan_row(41, 15, "h", json!([]))]);
        assert_eq!(
            site_vlan_leftovers(&current, &east()),
            ["vlan 15 of site east-01: VLAN group East holds this VLAN, and nobody owns the one of the site; \
              no interface points to it any more: delete it by hand"]
        );
    }

    // The address moves to the new interface in this very plan: the old one,
    // which the source no longer reports, keeps nothing and goes in the same run.
    #[test]
    fn an_interface_whose_address_moves_to_another_one_is_deleted_in_the_same_run() {
        let current = netbox([
            cluster_row(),
            vm_row(1, "web", owned_by(PVE)),
            nic_row(10, 1, "web", "eth0", owned_by(PVE)),
            ip_row(50, "10.0.0.5/24", Some(10), "eth0", "web", owned_by(PVE)),
        ]);
        let desired = [vm("web", PVE), nic("web", "ens18", PVE), ip("10.0.0.5/24", "web", "ens18", PVE)];
        let plan = reconcile(&desired, &current, &run([pruning(PVE)]));
        assert!(summary(&plan).contains(&(Action::Delete, "vm_interface", "eth0")), "{:?}", summary(&plan));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    // NetBox answers in an order of its own: the warning names the same holder,
    // the first by kind and id, whatever that order.
    #[test]
    fn the_holder_a_kept_orphan_is_shown_with_does_not_depend_on_the_order_of_netbox() {
        let current = netbox([
            (Kind::Cluster, json!({"id": 3, "name": "old", "tags": owned_by(PVE)})),
            (Kind::VirtualMachine, json!({"id": 9, "name": "b", "cluster": {"id": 3, "name": "old"}, "tags": []})),
            (Kind::VirtualMachine, json!({"id": 8, "name": "a", "cluster": {"id": 3, "name": "old"}, "tags": []})),
        ]);
        let plan = reconcile(&[], &current, &run([pruning(PVE)]));
        assert_eq!(plan.warnings, ["cluster old: not deleted, vm a still refers to it"]);
    }

    // A VIP NetBox assigns to an FHRP group is held by that group, not loose:
    // the machine that reports it (keepalived) never takes it over.
    #[test]
    fn an_address_netbox_assigns_to_an_fhrp_group_is_never_taken_over() {
        let current = netbox([
            cluster_row(),
            vm_row(1, "lb1", owned_by(PVE)),
            nic_row(10, 1, "lb1", "eth0", owned_by(PVE)),
            (
                Kind::IpAddress,
                json!({
                    "id": 50, "address": "10.0.0.1/24", "vrf": null,
                    "assigned_object_type": "ipam.fhrpgroup", "assigned_object_id": 7,
                    "assigned_object": {"id": 7, "name": "VRRP 1", "display": "VRRP 1"}, "tags": []
                }),
            ),
        ]);
        let desired = [vm("lb1", PVE), nic("lb1", "eth0", PVE), ip("10.0.0.1/24", "lb1", "eth0", PVE)];
        let plan = reconcile(&desired, &current, &run([pruning(PVE)]));
        assert!(plan.steps.iter().all(|step| step.change.id != Some(50)), "{:?}", summary(&plan));
        assert_eq!(plan.warnings.len(), 1, "{:?}", plan.warnings);
        assert!(plan.warnings[0].text.starts_with("ip 10.0.0.1/24 of "), "{:?}", plan.warnings);
        assert!(plan.warnings[0].text.contains("also assigned to another object"), "{:?}", plan.warnings);
    }

    // A first run against a large NetBox: thousands of machines it does not
    // know by name, tens of thousands of objects. Recognition only looks at the
    // objects that hold a MAC address: the others can match nothing.
    #[test]
    fn recognition_on_a_large_netbox_takes_the_time_of_what_holds_a_mac_address() {
        let mut by_kind: BTreeMap<Kind, Vec<Row>> = BTreeMap::new();
        by_kind.entry(Kind::Cluster).or_default().push(row(cluster_row().1));
        for id in 0..20_000_u64 {
            by_kind.entry(Kind::VirtualMachine).or_default().push(row(vm_row(
                1000 + id,
                &format!("old{id}"),
                owned_by(PVE),
            )
            .1));
        }
        let (current, _) = current_objects(&by_kind);
        let mut wanted = Vec::new();
        for id in 0..2_000_u64 {
            let name = format!("new{id}");
            let address = format!("02:00:00:{:02X}:{:02X}:00", id / 256, id % 256);
            wanted.extend([vm(&name, PVE), nic(&name, "eth0", PVE), mac(&address, &name, "eth0", PVE)]);
        }
        let started = std::time::Instant::now();
        let plan = reconcile(&wanted, &current, &run([source(PVE)]));
        let spent = started.elapsed();
        assert_eq!(plan.warnings, Vec::<String>::new());
        assert!(spent < std::time::Duration::from_secs(3), "{spent:?}");
    }

    // Edges of the rules above

    #[test]
    fn an_object_without_a_label_is_not_a_choice() {
        // A JSON custom field may hold an object with a `value` of its own.
        assert!(!same_value(&json!("active"), &json!({"value": "active"})));
        assert!(same_value(&json!({"value": "active"}), &json!({"value": "active"})));
    }

    #[test]
    fn two_lists_are_the_same_when_their_items_are_the_same_one_by_one() {
        // Each item is a value of its own: a number in another spelling, a choice.
        assert!(same_value(&json!([2, "active"]), &json!([2.0, {"value": "active", "label": "Active"}])));
        assert!(!same_value(&json!([1, 2]), &json!([1, 3])));
        // A list that starts as another one is not that one.
        assert!(!same_value(&json!([1]), &json!([1, 2])));
        assert!(!same_value(&json!([1, 2]), &json!([1])));
    }

    #[test]
    fn the_network_of_an_address_is_its_prefix_in_either_family() {
        assert_eq!(network("10.0.0.5/24").as_deref(), Some("10.0.0.0/24"));
        assert_eq!(network("10.0.0.5/32").as_deref(), Some("10.0.0.5/32"));
        assert_eq!(network("2001:db8::5/64").as_deref(), Some("2001:db8::/64"));
        assert_eq!(network("2001:db8:0:1::5/127").as_deref(), Some("2001:db8:0:1::4/127"));
        assert_eq!(network("2001:db8::5/128").as_deref(), Some("2001:db8::5/128"));
        assert_eq!(network("2001:db8::5/0").as_deref(), Some("::/0"));
    }

    #[test]
    fn an_address_whose_mask_is_longer_than_its_family_allows_has_no_network() {
        assert_eq!(network("10.0.0.5/33"), None);
        assert_eq!(network("2001:db8::5/129"), None);
    }

    #[test]
    fn a_source_that_completes_a_field_twice_differently_keeps_what_it_said_first() {
        // As between two whole reports of one source: the first report wins.
        let again =
            Desired::new(Kind::Device, Identity::device("pve01.lab01"), BMC).complement().field("serial", "SECOND");
        let reports: Vec<Desired> = bmc_reports(BMC, "FIRST").into_iter().chain([again]).collect();
        let plan = reconcile(&reports, &server_room(GENERIC, "", json!([])), &run([source(BMC)]));
        assert_eq!(
            plan.changes(),
            [change("device", Action::Update, "pve01.lab01", "pve01.lab01")
                .fields([("device_type", json!("PowerEdge R630")), ("serial", json!("FIRST"))])
                .before([("device_type", json!("Generic Model")), ("serial", json!(""))])
                .id(5)]
        );
    }

    #[test]
    fn only_the_mark_of_a_tool_makes_an_ensured_object_the_tool_s() {
        let site = Desired::new(Kind::Site, Identity::named("Harbor"), PVE)
            .field("name", "Harbor")
            .field("description", "main site")
            .ensure_only();
        // A tag somebody set by hand is not a mark of ownership: the site stays as it is.
        let by_hand = netbox([(
            Kind::Site,
            json!({"id": 1, "name": "Harbor", "description": "", "tags": tagged(["backup-gold"])}),
        )]);
        assert_eq!(reconcile(std::slice::from_ref(&site), &by_hand, &run([source(PVE)])), nothing());
        // The tag of this tool alone is one: the site is managed, and gets the tag of its source.
        let marked = netbox([(
            Kind::Site,
            json!({"id": 1, "name": "Harbor", "description": "main site", "tags": tagged(["netbox-omnisync"])}),
        )]);
        assert_eq!(
            reconcile(&[site], &marked, &run([source(PVE)])).changes(),
            [change("site", Action::Update, "", "Harbor")
                .fields([("tags", json!(["netbox-omnisync", "source-pve1"]))])
                .before([("tags", json!(["netbox-omnisync"]))])
                .id(1)]
        );
    }

    fn prefix_row(id: u64, vrf: Value, tags: Value) -> (Kind, Value) {
        (Kind::Prefix, json!({"id": id, "prefix": "10.0.0.0/24", "vrf": vrf, "tags": tags}))
    }

    fn prefix(vrf: VrfKey<'_>) -> Desired {
        Desired::new(Kind::Prefix, Identity::prefix("10.0.0.0/24", vrf), PVE).field("prefix", "10.0.0.0/24")
    }

    #[test]
    fn a_prefix_reported_in_a_table_is_never_the_one_another_table_holds() {
        let current = netbox([prefix_row(80, json!({"id": 5, "name": "Prod"}), owned_by(PVE))]);
        // The source knows the table: the global one, where NetBox has no such prefix.
        let plan = reconcile(&[prefix(VrfKey::Global)], &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("prefix", Action::Create, "", "10.0.0.0/24")
                .fields([("prefix", json!("10.0.0.0/24")), ("tags", json!(["netbox-omnisync", "source-pve1"]))])]
        );
    }

    #[test]
    fn a_prefix_held_in_several_vrfs_and_not_in_the_global_table_is_not_guessed_between() {
        let current = netbox([
            prefix_row(80, json!({"id": 5, "name": "Prod"}), tagged([])),
            prefix_row(81, json!({"id": 6, "name": "Lab"}), tagged([])),
        ]);
        let plan = reconcile(&[prefix(VrfKey::Unknown)], &current, &run([source(PVE)]));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            ["prefix 10.0.0.0/24: 2 objects in NetBox have this identity (ids 80, 81); skipped with its dependents"]
        );
    }

    #[test]
    fn a_prefix_held_in_a_vrf_and_in_the_global_table_is_the_global_one_when_the_source_cannot_tell() {
        let current = netbox([
            prefix_row(80, json!({"id": 5, "name": "Prod"}), tagged([])),
            prefix_row(81, Value::Null, tagged([])),
        ]);
        let plan = reconcile(&[prefix(VrfKey::Unknown)], &current, &run([source(PVE)]));
        // Neither is owned: the global one is found, and taken over.
        assert_eq!(
            plan.changes(),
            [change("prefix", Action::Update, "", "10.0.0.0/24")
                .fields([("tags", json!(["netbox-omnisync", "source-pve1"]))])
                .before([("tags", json!([]))])
                .id(81)]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_unassigned_ip_address_of_a_vrf_is_adopted_by_a_report_that_names_this_vrf() {
        let (kind, mut value) = ip_row(70, "10.0.0.5/24", None, "", "", tagged([]));
        value["vrf"] = json!({"id": 5, "name": "Prod"});
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            (kind, value),
        ]);
        let in_prod = Desired::new(Kind::IpAddress, Identity::ip_address("10.0.0.5/24", VrfKey::Named("Prod")), PVE)
            .field("address", "10.0.0.5/24")
            .reference("assigned_object", Kind::VmInterface, Identity::vm_interface(&vm_identity("web01"), "eth0"));
        let wanted = [vm("web01", PVE), nic("web01", "eth0", PVE), in_prod];
        assert_eq!(
            reconcile(&wanted, &current, &run([source(PVE)])).changes(),
            [change("ip", Action::Update, "web01", "10.0.0.5/24")
                .fields([("assigned_object", json!("eth0")), ("tags", json!(["netbox-omnisync", "source-pve1"]))])
                .before([("assigned_object", Value::Null), ("tags", json!([]))])
                .id(70)]
        );
    }

    #[test]
    fn an_ip_address_another_machine_holds_in_a_vrf_is_no_duplicate_of_one_created_in_the_global_table() {
        let (kind, mut value) = ip_row(70, "10.0.0.5/24", Some(41), "eth0", "other", owned_by(PVE));
        value["vrf"] = json!({"id": 5, "name": "Prod"});
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            vm_row(11, "other", owned_by(PVE)),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            nic_row(41, 11, "other", "eth0", owned_by(PVE)),
            (kind, value),
        ]);
        // The source does not know the VRF: `other` keeps its address where it
        // is, and the one of web01 goes to the global table, where it is alone.
        let plan = reconcile(&both_vms_report_the_address(), &current, &run([pruning(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("ip", Action::Create, "web01", "10.0.0.5/24").fields([
                ("address", json!("10.0.0.5/24")),
                ("assigned_object", json!("eth0")),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
            ])]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn a_reference_to_an_address_the_source_does_not_report_is_the_one_netbox_has_on_that_machine() {
        // The bridge address of every Docker host: web02 holds one as well, under a lower id.
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            vm_row(11, "web02", tagged([])),
            nic_row(40, 10, "web01", "eth0", owned_by(PVE)),
            nic_row(41, 11, "web02", "eth0", tagged([])),
            ip_row(70, "172.17.0.1/16", Some(41), "eth0", "web02", tagged([])),
            ip_row(71, "172.17.0.1/16", Some(40), "eth0", "web01", tagged([])),
        ]);
        let address = Identity::ip_address("172.17.0.1/16", VrfKey::Unknown);
        let wanted = [vm("web01", PVE).reference("primary_ip4", Kind::IpAddress, address), nic("web01", "eth0", PVE)];
        let plan = reconcile(&wanted, &current, &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("primary_ip4", json!("172.17.0.1/16"))])
                .before([("primary_ip4", Value::Null)])
                .id(10)]
        );
        assert_eq!(plan.steps[0].references["primary_ip4"].as_ref().and_then(|link| link.id), Some(71));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn a_reference_that_several_netbox_objects_match_is_left_untouched_with_a_warning() {
        let current = netbox([
            cluster_row(),
            (Kind::Platform, json!({"id": 8, "name": "Debian 12", "tags": []})),
            (Kind::Platform, json!({"id": 9, "name": "debian 12", "tags": []})),
            vm_row(10, "web01", owned_by(PVE)),
        ]);
        let wanted = vm("web01", PVE).reference("platform", Kind::Platform, Identity::named("Debian 12"));
        let plan = reconcile(&[wanted], &current, &run([source(PVE)]));
        assert_eq!(plan.steps, []);
        assert_eq!(
            plan.warnings,
            ["vm web01: platform refers to platform Debian 12, which matches several NetBox objects; \
              field left untouched"]
        );
    }

    #[test]
    fn a_reference_reported_empty_where_netbox_has_none_is_not_a_change() {
        let current = netbox([cluster_row(), vm_row(10, "web01", owned_by(PVE))]);
        let wanted = vm("web01", PVE).no_reference("platform");
        assert_eq!(reconcile(&[wanted], &current, &run([source(PVE)])), nothing());
    }

    #[test]
    fn a_reference_reported_empty_is_not_written_at_creation() {
        // Nothing to clear on an object that does not exist yet.
        let wanted = vm("web01", PVE).no_reference("platform");
        let plan = reconcile(&[wanted], &netbox([cluster_row()]), &run([source(PVE)]));
        assert_eq!(
            plan.changes(),
            [change("vm", Action::Create, "web01", "web01").fields([
                ("cluster", json!("pve")),
                ("memory", json!(4096)),
                ("name", json!("web01")),
                ("status", json!("active")),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
                ("vcpus", json!(2)),
            ])]
        );
        let references: Vec<&str> = plan.steps[0].references.keys().map(String::as_str).collect();
        assert_eq!(references, ["cluster"]);
    }

    #[test]
    fn the_object_a_reported_reference_no_longer_points_to_is_an_orphan() {
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["platform"] = json!({"id": 8, "name": "Debian 11", "display": "Debian 11"});
        let current = netbox([
            cluster_row(),
            (Kind::Platform, json!({"id": 8, "name": "Debian 11", "tags": owned_by(PVE)})),
            (kind, value),
        ]);
        let wanted = [
            Desired::new(Kind::Platform, Identity::named("Debian 12"), PVE).field("name", "Debian 12"),
            vm("web01", PVE).reference("platform", Kind::Platform, Identity::named("Debian 12")),
        ];
        // The source says where web01 runs now: nothing keeps Debian 11.
        assert_eq!(
            reconcile(&wanted, &current, &run([pruning(PVE)])).changes(),
            [
                change("platform", Action::Create, "", "Debian 12")
                    .fields([("name", json!("Debian 12")), ("tags", json!(["netbox-omnisync", "source-pve1"]))]),
                change("vm", Action::Update, "web01", "web01")
                    .fields([("platform", json!("Debian 12"))])
                    .before([("platform", json!("Debian 11"))])
                    .id(10),
                change("platform", Action::Delete, "", "Debian 11").id(8),
            ]
        );
    }

    #[test]
    fn a_difference_of_case_on_a_field_that_does_not_identify_the_object_is_a_change() {
        let (kind, mut value) = vm_row(10, "web01", owned_by(PVE));
        value["description"] = json!("Web Server");
        let current = netbox([cluster_row(), (kind, value)]);
        let wanted = vm("web01", PVE).field("description", "web server");
        assert_eq!(
            reconcile(&[wanted], &current, &run([source(PVE)])).changes(),
            [change("vm", Action::Update, "web01", "web01")
                .fields([("description", json!("web server"))])
                .before([("description", json!("Web Server"))])
                .id(10)]
        );
    }

    #[test]
    fn a_list_of_references_to_an_earlier_kind_is_written_with_the_object() {
        let current = netbox([
            (Kind::Vlan, json!({"id": 91, "vid": 10, "name": "v10", "site": null, "group": null, "tags": []})),
            device_row(12, "esx01", 1, owned_by(PVE)),
        ]);
        let vlan = Target::new(Kind::Vlan, Identity::vlan(VlanScope::Global, 10));
        let wanted = [device("esx01", PVE), pnic("esx01", "vmnic0", PVE).reference_list("tagged_vlans", [vlan])];
        let plan = reconcile(&wanted, &current, &run([source(PVE)]));
        // The VLAN exists before the interface does: no second step is needed.
        assert_eq!(
            plan.changes(),
            [change("interface", Action::Create, "esx01", "vmnic0").fields([
                ("device", json!("esx01")),
                ("name", json!("vmnic0")),
                ("tagged_vlans", json!(["10"])),
                ("tags", json!(["netbox-omnisync", "source-pve1"])),
            ])]
        );
        assert_eq!(plan.steps[0].phase, Phase::Write);
    }

    // Two devices may bear one name, on two sites. The one recognised under its
    // new name takes the interface reported there, which NetBox has on its
    // namesake: that one, which the source no longer reports, keeps nothing.
    #[test]
    fn a_device_whose_interface_moves_to_another_one_is_deleted_in_the_same_run() {
        let current = netbox([
            device_row(12, "esx01", 1, owned_by(PVE)),
            device_row(13, "esx01", 2, owned_by(PVE)),
            pnic_row(30, 12, "esx01", "vmnic0", owned_by(PVE)),
            pnic_row(31, 13, "esx01", "vmnic1", owned_by(PVE)),
            (
                Kind::MacAddress,
                json!({
                    "id": 61, "mac_address": MAC_1, "assigned_object_type": "dcim.interface",
                    "assigned_object_id": 31, "tags": owned_by(PVE)
                }),
            ),
        ]);
        let vmnic1 = Identity::interface("esx02", "vmnic1");
        let target = Target::new(Kind::Interface, vmnic1.clone());
        let wanted = [
            device("esx02", PVE),
            pnic("esx02", "vmnic0", PVE),
            pnic("esx02", "vmnic1", PVE),
            Desired::new(Kind::MacAddress, Identity::mac_address(MAC_1, Some(&target)), PVE)
                .field("mac_address", MAC_1)
                .reference("assigned_object", Kind::Interface, vmnic1),
        ];
        let plan = reconcile(&wanted, &current, &run([pruning(PVE)]));
        assert_eq!(
            plan.changes(),
            [
                change("device", Action::Update, "esx02", "esx02")
                    .fields([("name", json!("esx02"))])
                    .before([("name", json!("esx01"))])
                    .id(13),
                change("interface", Action::Update, "esx02", "vmnic0")
                    .fields([("device", json!("esx02"))])
                    .before([("device", json!("esx01"))])
                    .id(30),
                change("device", Action::Delete, "esx01", "esx01").id(12),
            ]
        );
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    // The same with two virtual machines of one name in one cluster (NetBox
    // allows it for two tenants): the interface and the disk both move.
    #[test]
    fn a_virtual_machine_whose_interface_and_disk_move_to_another_one_is_deleted_in_the_same_run() {
        let current = netbox([
            cluster_row(),
            vm_row(10, "web01", owned_by(PVE)),
            vm_row(11, "web01", owned_by(PVE)),
            nic_row(40, 11, "web01", "eth0", owned_by(PVE)),
            nic_row(41, 10, "web01", "eth1", owned_by(PVE)),
            mac_row(60, MAC_1, 41, owned_by(PVE)),
            disk_row(50, 11, "scsi0", owned_by(PVE)),
        ]);
        let wanted = [
            vm("web02", PVE),
            nic("web02", "eth0", PVE),
            nic("web02", "eth1", PVE),
            mac(MAC_1, "web02", "eth1", PVE),
            disk("web02", "scsi0", PVE),
        ];
        let plan = reconcile(&wanted, &current, &run([pruning(PVE)]));
        assert_eq!(
            summary(&plan),
            [
                (Action::Update, "vm", "web02"),
                (Action::Update, "vm_interface", "eth0"),
                (Action::Update, "disk", "scsi0"),
                (Action::Delete, "vm", "web01"),
            ]
        );
        assert_eq!(plan.steps[3].change.id, Some(11));
        assert_eq!(plan.warnings, Vec::<String>::new());
    }

    #[test]
    fn an_orphan_prefix_is_deleted_with_the_orphan_address_that_is_in_it() {
        // Only an address kept because its machine could not be read keeps its prefix.
        let current = netbox([
            prefix_row(80, Value::Null, owned_by(PVE)),
            ip_row(70, "10.0.0.5/24", None, "", "", owned_by(PVE)),
        ]);
        assert_eq!(
            reconcile(&[], &current, &run([pruning(PVE)])).changes(),
            [
                change("ip", Action::Delete, "", "10.0.0.5/24").id(70),
                change("prefix", Action::Delete, "", "10.0.0.0/24").id(80),
            ]
        );
    }
}
