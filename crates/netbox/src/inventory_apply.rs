//! Writes the plan of a reconciliation to NetBox, step by step.
//!
//! The reconciliation names every object by its identity; this module turns
//! those names into the NetBox ids the API wants, learning the id of each
//! object it creates on the way. The steps are written in the order given,
//! which is the dependency order: nothing is reordered here.

use std::collections::BTreeMap;

use omnisync_core::change::Action;
use omnisync_core::gateway::{Gateway, Row, Write};
use omnisync_core::inventory::model::{Identity, Kind};
use omnisync_core::inventory::reconcile::{Link, Plan, Step};
use serde_json::{Value, json};

use crate::apply::ApplyError;

/// A gateway that can tell it refuses writes.
///
/// A dry run prints the plan and writes nothing. The applier asks before the
/// first step rather than finding out from a refused write: a plan must never
/// be half-attempted, and a refusal is otherwise an error like any other.
pub trait DryRun {
    fn dry_run(&self) -> bool;
}

/// What became of a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Number of steps written.
    pub written: usize,
    /// The gateway is in dry run: no write was attempted.
    pub dry_run: bool,
}

/// Writes `plan.steps` in the order given, and stops at the first failure.
///
/// The payload of a step is the fields of its change, where:
/// - a reference becomes the id of its target: the one the reconciliation
///   found, or the one of the object this run created earlier under that kind
///   and identity; a reference to nothing becomes `null`;
/// - a generic relation unfolds into `<field>_type` and `<field>_id`;
/// - a list of references becomes the list of ids;
/// - `tags` becomes the full list as `{"name": …}` objects (NetBox replaces
///   the set), `custom_fields` goes as it is (NetBox merges the given keys).
///
/// An update without id is written to the object this run created under the
/// identity of the step. A target that was never created is an error raised
/// before anything is sent for the step.
///
/// `on_applied` is called once per step written. The error of a failed step
/// names it and carries the number of steps written before it; what follows
/// is not attempted, since it may depend on what failed.
///
/// On a gateway in dry run nothing is attempted at all, and `plan` remains
/// what the report prints.
pub async fn apply<G, F>(gateway: &G, plan: &Plan, on_applied: F) -> Result<Applied, ApplyError>
where
    G: Gateway + DryRun,
    F: Fn() + Send + Sync,
{
    if gateway.dry_run() {
        // Nothing is written, but what the real run would be refused is said:
        // the fields of each write are checked against NetBox.
        for step in &plan.steps {
            let write = match step.change.action {
                Action::Create => Write::Create,
                Action::Update => Write::Update,
                Action::Delete => continue,
            };
            let checked = gateway.check_write(write, step.kind.endpoint(), &written_fields(step)).await;
            if let Err(error) = checked {
                return Err(ApplyError { message: format!("{}: {error}", name(step)), applied: 0 });
            }
        }
        return Ok(Applied { written: 0, dry_run: true });
    }
    let mut writer = Writer { gateway, on_applied, written: 0, created: BTreeMap::new() };
    for step in &plan.steps {
        if let Err(message) = writer.write(step).await {
            return Err(ApplyError { message: format!("{}: {message}", name(step)), applied: writer.written });
        }
    }
    Ok(Applied { written: writer.written, dry_run: false })
}

/// How an error names a step: `create vm_interface web01 eth0`. The device is
/// left out when there is none, or when the object is the device itself.
fn name(step: &Step) -> String {
    let change = &step.change;
    if change.device.is_empty() || change.device == change.key {
        format!("{} {} {}", change.action, change.kind, change.key)
    } else {
        format!("{} {} {} {}", change.action, change.kind, change.device, change.key)
    }
}

/// An object this run created.
struct Created {
    id: u64,
    /// The interface it was assigned to at creation, for an address: what
    /// tells apart two objects created under one identity.
    assigned: Option<(Kind, Vec<String>)>,
}

/// The objects created so far under one kind and identity key. Several for an
/// IP address two machines each hold: its identity is its host and VRF, and
/// the reconciliation then asks for one object per holder.
type CreatedObjects = BTreeMap<(Kind, Vec<String>), Vec<Created>>;

/// Whether `interface` is an interface of the device or virtual machine that
/// `holder` writes: its key is the key of its holder, then its name.
fn holds(holder: &Step, interface: &(Kind, Vec<String>)) -> bool {
    let (kind, key) = interface;
    let held_by = match kind {
        Kind::Interface => Kind::Device,
        Kind::VmInterface => Kind::VirtualMachine,
        _ => return false,
    };
    let holder_key = holder.identity.key();
    holder.kind == held_by && key.len() == holder_key.len() + 1 && key.starts_with(holder_key)
}

/// The names of the fields the write of `step` sends, sorted: those of
/// `Writer::payload`, a generic relation as its two halves.
fn written_fields(step: &Step) -> Vec<String> {
    let mut fields = Vec::new();
    for field in step.change.fields.keys() {
        if step.references.contains_key(field) && step.kind.generic_fields().contains(&field.as_str()) {
            fields.push(format!("{field}_type"));
            fields.push(format!("{field}_id"));
        } else {
            fields.push(field.clone());
        }
    }
    fields.sort();
    fields
}

struct Writer<'g, G, F> {
    gateway: &'g G,
    on_applied: F,
    written: usize,
    created: CreatedObjects,
}

impl<G: Gateway, F: Fn()> Writer<'_, G, F> {
    fn done(&mut self) {
        self.written += 1;
        (self.on_applied)();
    }

    /// The id of the object this run created under `kind` and `identity`, as
    /// `referrer` means it: the only one, or between several the one assigned
    /// to an interface of the referrer.
    fn created_id(&self, kind: Kind, identity: &Identity, referrer: &Step) -> Result<u64, &'static str> {
        let created = self.created.get(&(kind, identity.key().to_vec())).map(Vec::as_slice).unwrap_or_default();
        let own: Vec<&Created> = match created {
            [one] => vec![one],
            several => several
                .iter()
                .filter(|object| object.assigned.as_ref().is_some_and(|interface| holds(referrer, interface)))
                .collect(),
        };
        match own.as_slice() {
            [one] => Ok(one.id),
            _ if created.is_empty() => Err("which this run did not create"),
            _ => Err("which this run created several times, none of them being its own"),
        }
    }

    /// The id a reference of `step` is written as.
    fn target(&self, step: &Step, field: &str, link: &Link) -> Result<u64, String> {
        if let Some(id) = link.id {
            return Ok(id);
        }
        self.created_id(link.kind, &link.identity, step)
            .map_err(|reason| format!("{field} refers to {} {}, {reason}", link.kind.label(), link.identity.label()))
    }

    /// What is sent for a step: its fields, the references resolved to ids.
    fn payload(&self, step: &Step) -> Result<Row, String> {
        let mut payload = Row::new();
        for (field, value) in &step.change.fields {
            if let Some(link) = step.references.get(field) {
                let id = match link {
                    Some(link) => json!(self.target(step, field, link)?),
                    None => Value::Null,
                };
                if step.kind.generic_fields().contains(&field.as_str()) {
                    let content_type = link.as_ref().map_or(Value::Null, |link| json!(link.kind.content_type()));
                    payload.insert(format!("{field}_type"), content_type);
                    payload.insert(format!("{field}_id"), id);
                } else {
                    payload.insert(field.clone(), id);
                }
            } else if let Some(links) = step.reference_lists.get(field) {
                let ids: Result<Vec<u64>, String> = links.iter().map(|link| self.target(step, field, link)).collect();
                payload.insert(field.clone(), json!(ids?));
            } else if field == "tags" && step.kind.taggable() {
                // The change lists the names; NetBox finds a tag by the attributes given.
                let names = value.as_array().map(Vec::as_slice).unwrap_or_default();
                let tags = names.iter().map(|name| json!({"name": name})).collect();
                payload.insert(field.clone(), Value::Array(tags));
            } else {
                payload.insert(field.clone(), value.clone());
            }
        }
        Ok(payload)
    }

    /// Writes one step. Everything that can be refused locally is checked
    /// before the call: a step is sent whole or not at all.
    async fn write(&mut self, step: &Step) -> Result<(), String> {
        let endpoint = step.kind.endpoint();
        let key = (step.kind, step.identity.key().to_vec());
        match step.change.action {
            Action::Create => {
                let payload = self.payload(step)?;
                let answer = self.gateway.create(endpoint, &payload).await.map_err(|error| error.to_string())?;
                // The object exists from here on, whatever the answer looks like.
                self.done();
                let id = answer
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or("NetBox answered without the id of the created object")?;
                let assigned = step.references.get("assigned_object").and_then(Option::as_ref);
                let assigned = assigned.map(|link| (link.kind, link.identity.key().to_vec()));
                self.created.entry(key).or_default().push(Created { id, assigned });
            }
            Action::Update => {
                let created = self.created.get(&key).map(Vec::as_slice).unwrap_or_default();
                let own = match created {
                    [one] => Some(one.id),
                    _ => None,
                };
                let id = step.change.id.or(own).ok_or("no NetBox id, and this run did not create it")?;
                let payload = self.payload(step)?;
                self.gateway.update(endpoint, id, &payload).await.map_err(|error| error.to_string())?;
                self.done();
            }
            Action::Delete => {
                let id = step.change.id.ok_or("no NetBox id")?;
                self.gateway.delete(endpoint, id).await.map_err(|error| error.to_string())?;
                self.done();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use std::collections::BTreeSet;

    use omnisync_core::change::Change;
    use omnisync_core::gateway::{Filters, GatewayError};
    use omnisync_core::inventory::model::{Desired, Identity, Target, VlanScope, VrfKey};
    use omnisync_core::inventory::reconcile::{Phase, Run, SourceFacts, SourceStatus, reconcile};

    use super::*;
    use crate::inventory_state::load;
    use crate::testing::FakeGateway;

    const PVE: &str = "pve1";
    const CLUSTERS: &str = "virtualization.clusters";
    const VMS: &str = "virtualization.virtual_machines";
    const VM_INTERFACES: &str = "virtualization.interfaces";
    const DISKS: &str = "virtualization.virtual_disks";
    const MACS: &str = "dcim.mac_addresses";
    const IPS: &str = "ipam.ip_addresses";

    // Hand-written steps

    /// A step as the reconciliation builds one, written by hand.
    struct Build(Step);

    impl Build {
        fn new(phase: Phase, kind: Kind, identity: &Identity, action: Action, id: Option<u64>) -> Self {
            let mut change = Change::new(kind.label(), action, identity.owner(), identity.label());
            change.id = id;
            Build(Step {
                phase,
                kind,
                identity: identity.clone(),
                change,
                references: BTreeMap::new(),
                reference_lists: BTreeMap::new(),
            })
        }

        fn create(kind: Kind, identity: &Identity) -> Self {
            Build::new(Phase::Write, kind, identity, Action::Create, None)
        }

        fn update(kind: Kind, identity: &Identity, id: Option<u64>) -> Self {
            Build::new(Phase::Write, kind, identity, Action::Update, id)
        }

        /// The second-step update of an object, `id` being `None` when this run creates it.
        fn link(kind: Kind, identity: &Identity, id: Option<u64>) -> Self {
            Build::new(Phase::Link, kind, identity, Action::Update, id)
        }

        fn delete(kind: Kind, identity: &Identity, id: Option<u64>) -> Self {
            Build::new(Phase::Delete, kind, identity, Action::Delete, id)
        }

        fn field(mut self, name: &str, value: Value) -> Self {
            self.0.change.fields.insert(name.to_owned(), value);
            self
        }

        fn tags<const N: usize>(self, names: [&str; N]) -> Self {
            self.field("tags", json!(names.as_slice()))
        }

        /// A reference: the change shows the name of the target, the step carries the link.
        fn reference(mut self, field: &str, kind: Kind, identity: &Identity, id: Option<u64>) -> Self {
            self.0.change.fields.insert(field.to_owned(), json!(identity.label()));
            self.0.references.insert(field.to_owned(), Some(Link { kind, identity: identity.clone(), id }));
            self
        }

        fn cleared(mut self, field: &str) -> Self {
            self.0.change.fields.insert(field.to_owned(), Value::Null);
            self.0.references.insert(field.to_owned(), None);
            self
        }

        fn list(mut self, field: &str, links: Vec<Link>) -> Self {
            let shown: Vec<&str> = links.iter().map(|link| link.identity.label()).collect();
            self.0.change.fields.insert(field.to_owned(), json!(shown));
            self.0.reference_lists.insert(field.to_owned(), links);
            self
        }

        fn done(self) -> Step {
            self.0
        }
    }

    fn plan(steps: Vec<Step>) -> Plan {
        Plan { steps, ..Plan::default() }
    }

    fn tag(netbox: &FakeGateway, name: &str, slug: &str) -> u64 {
        netbox.add("extras.tags", json!({"name": name, "slug": slug}))
    }

    /// A NetBox holding the two ownership tags of the tool, and their ids.
    fn netbox() -> (FakeGateway, u64, u64) {
        let netbox = FakeGateway::new();
        let tool = tag(&netbox, "netbox-omnisync", "netbox-omnisync");
        let source = tag(&netbox, "source-pve1", "source-pve1");
        (netbox, tool, source)
    }

    const OWNED: [&str; 2] = ["netbox-omnisync", "source-pve1"];

    fn stored(netbox: &FakeGateway, endpoint: &str, id: u64) -> Row {
        netbox.row(endpoint, id).unwrap_or_else(|| panic!("no {endpoint} object with id {id}"))
    }

    fn found(netbox: &FakeGateway, endpoint: &str, field: &str, value: &str) -> u64 {
        netbox.find(endpoint, field, &json!(value)).unwrap_or_else(|| panic!("no {endpoint} with {field} {value}"))
    }

    fn web01() -> Identity {
        Identity::virtual_machine("web01", "pve-lab")
    }

    fn eth0_of(virtual_machine: &Identity) -> Identity {
        Identity::vm_interface(virtual_machine, "eth0")
    }

    fn no_callback() {}

    /// A gateway that keeps what was sent to NetBox, payloads included.
    struct Sent {
        netbox: FakeGateway,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Sent {
        fn to(netbox: FakeGateway) -> Self {
            Sent { netbox, calls: Mutex::new(Vec::new()) }
        }

        fn record(&self, call: String, payload: &Row) {
            self.calls.lock().expect("the calls").push((call, Value::Object(payload.clone())));
        }

        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().expect("the calls").clone()
        }
    }

    impl Gateway for Sent {
        async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
            self.netbox.list(endpoint, filters).await
        }

        async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
            self.record(format!("POST {endpoint}"), payload);
            self.netbox.create(endpoint, payload).await
        }

        async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
            self.record(format!("PATCH {endpoint} {id}"), payload);
            self.netbox.update(endpoint, id, payload).await
        }

        async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
            self.record(format!("DELETE {endpoint} {id}"), &Row::new());
            self.netbox.delete(endpoint, id).await
        }
        async fn check_write(&self, write: Write, endpoint: &str, fields: &[String]) -> Result<(), GatewayError> {
            self.netbox.check_write(write, endpoint, fields).await
        }
    }

    impl DryRun for Sent {
        fn dry_run(&self) -> bool {
            self.netbox.dry_run()
        }
    }

    // Objects created in the same run

    #[tokio::test]
    async fn a_vm_is_created_in_the_cluster_created_in_the_same_run() {
        let (netbox, tool, source) = netbox();
        let cluster = Identity::named("pve-lab");
        let steps = vec![
            Build::create(Kind::Cluster, &cluster).field("name", json!("pve-lab")).tags(OWNED).done(),
            Build::create(Kind::VirtualMachine, &web01())
                .field("name", json!("web01"))
                .field("vcpus", json!(2))
                .reference("cluster", Kind::Cluster, &cluster, None)
                .tags(OWNED)
                .done(),
        ];
        let reported = AtomicUsize::new(0);
        let applied = apply(&netbox, &plan(steps), || {
            reported.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(applied, Ok(Applied { written: 2, dry_run: false }));
        assert_eq!(reported.load(Ordering::SeqCst), 2);
        let cluster_id = found(&netbox, CLUSTERS, "name", "pve-lab");
        let vm_id = found(&netbox, VMS, "name", "web01");
        let vm = stored(&netbox, VMS, vm_id);
        assert_eq!(vm["cluster"], json!(cluster_id));
        assert_eq!(vm["vcpus"], json!(2));
        assert_eq!(vm["tags"], json!([tool, source]));
        assert_eq!(netbox.writes(), [("create", CLUSTERS.to_owned(), cluster_id), ("create", VMS.to_owned(), vm_id)]);
    }

    #[tokio::test]
    async fn an_interface_then_its_mac_then_the_primary_mac_link() {
        let (netbox, _, _) = netbox();
        let vm_id = netbox.add(VMS, json!({"name": "web01"}));
        let eth0 = eth0_of(&web01());
        let mac = Identity::mac_address("BC:24:11:AA:BB:CC", Some(&Target::new(Kind::VmInterface, eth0.clone())));
        let steps = vec![
            Build::create(Kind::VmInterface, &eth0)
                .field("name", json!("eth0"))
                .reference("virtual_machine", Kind::VirtualMachine, &web01(), Some(vm_id))
                .tags(OWNED)
                .done(),
            Build::create(Kind::MacAddress, &mac)
                .field("mac_address", json!("BC:24:11:AA:BB:CC"))
                .reference("assigned_object", Kind::VmInterface, &eth0, None)
                .tags(OWNED)
                .done(),
            Build::link(Kind::VmInterface, &eth0, None)
                .reference("primary_mac_address", Kind::MacAddress, &mac, None)
                .done(),
        ];
        assert_eq!(apply(&netbox, &plan(steps), no_callback).await, Ok(Applied { written: 3, dry_run: false }));
        let interface_id = found(&netbox, VM_INTERFACES, "name", "eth0");
        let mac_id = found(&netbox, MACS, "mac_address", "BC:24:11:AA:BB:CC");
        let interface = stored(&netbox, VM_INTERFACES, interface_id);
        assert_eq!(interface["virtual_machine"], json!(vm_id));
        assert_eq!(interface["primary_mac_address"], json!(mac_id));
        let mac_row = stored(&netbox, MACS, mac_id);
        assert_eq!(mac_row["assigned_object_type"], json!("virtualization.vminterface"));
        assert_eq!(mac_row["assigned_object_id"], json!(interface_id));
        // The generic relation is sent as its two halves only.
        assert_eq!(mac_row.get("assigned_object"), None);
        assert_eq!(
            netbox.writes(),
            [
                ("create", VM_INTERFACES.to_owned(), interface_id),
                ("create", MACS.to_owned(), mac_id),
                ("update", VM_INTERFACES.to_owned(), interface_id),
            ]
        );
    }

    #[tokio::test]
    async fn an_ip_on_an_interface_created_in_the_same_run_then_primary_ip_of_the_vm() {
        let (netbox, _, _) = netbox();
        let cluster_id = netbox.add(CLUSTERS, json!({"name": "pve-lab"}));
        let eth0 = eth0_of(&web01());
        let address = Identity::ip_address("192.0.2.21/24", VrfKey::Unknown);
        let steps = vec![
            Build::create(Kind::VirtualMachine, &web01())
                .field("name", json!("web01"))
                .reference("cluster", Kind::Cluster, &Identity::named("pve-lab"), Some(cluster_id))
                .tags(OWNED)
                .done(),
            Build::create(Kind::VmInterface, &eth0)
                .field("name", json!("eth0"))
                .reference("virtual_machine", Kind::VirtualMachine, &web01(), None)
                .tags(OWNED)
                .done(),
            Build::create(Kind::IpAddress, &address)
                .field("address", json!("192.0.2.21/24"))
                .reference("assigned_object", Kind::VmInterface, &eth0, None)
                .tags(OWNED)
                .done(),
            // The virtual machine has no id either: it is the one created above.
            Build::link(Kind::VirtualMachine, &web01(), None)
                .reference("primary_ip4", Kind::IpAddress, &address, None)
                .done(),
        ];
        assert_eq!(apply(&netbox, &plan(steps), no_callback).await, Ok(Applied { written: 4, dry_run: false }));
        let vm_id = found(&netbox, VMS, "name", "web01");
        let interface_id = found(&netbox, VM_INTERFACES, "name", "eth0");
        let ip_id = found(&netbox, IPS, "address", "192.0.2.21/24");
        let ip = stored(&netbox, IPS, ip_id);
        assert_eq!(ip["assigned_object_type"], json!("virtualization.vminterface"));
        assert_eq!(ip["assigned_object_id"], json!(interface_id));
        assert_eq!(stored(&netbox, VM_INTERFACES, interface_id)["virtual_machine"], json!(vm_id));
        assert_eq!(stored(&netbox, VMS, vm_id)["primary_ip4"], json!(ip_id));
        assert_eq!(netbox.writes().last(), Some(&("update", VMS.to_owned(), vm_id)));
    }

    #[tokio::test]
    async fn an_address_two_machines_each_create_is_linked_to_its_own_machine() {
        // 172.17.0.1 on every Docker host: one identity, two objects in one run.
        let (netbox, _, _) = netbox();
        netbox.enforce_global_unique(false);
        let address = Identity::ip_address("172.17.0.1/16", VrfKey::Unknown);
        let machines = [web01(), Identity::virtual_machine("web02", "pve-lab")];
        let mut steps = Vec::new();
        for machine in &machines {
            let name = json!(machine.label());
            steps.push(Build::create(Kind::VirtualMachine, machine).field("name", name).tags(OWNED).done());
        }
        for machine in &machines {
            steps.push(
                Build::create(Kind::VmInterface, &eth0_of(machine))
                    .field("name", json!("docker0"))
                    .reference("virtual_machine", Kind::VirtualMachine, machine, None)
                    .tags(OWNED)
                    .done(),
            );
        }
        for machine in &machines {
            steps.push(
                Build::create(Kind::IpAddress, &address)
                    .field("address", json!("172.17.0.1/16"))
                    .reference("assigned_object", Kind::VmInterface, &eth0_of(machine), None)
                    .tags(OWNED)
                    .done(),
            );
        }
        for machine in &machines {
            steps.push(
                Build::link(Kind::VirtualMachine, machine, None)
                    .reference("primary_ip4", Kind::IpAddress, &address, None)
                    .done(),
            );
        }
        assert_eq!(apply(&netbox, &plan(steps), no_callback).await, Ok(Applied { written: 8, dry_run: false }));
        for name in ["web01", "web02"] {
            let vm_id = found(&netbox, VMS, "name", name);
            let primary = stored(&netbox, VMS, vm_id)["primary_ip4"].as_u64().expect("a primary IP");
            let interface = stored(&netbox, IPS, primary)["assigned_object_id"].as_u64().expect("an interface");
            assert_eq!(stored(&netbox, VM_INTERFACES, interface)["virtual_machine"], json!(vm_id), "{name}");
        }
    }

    #[tokio::test]
    async fn an_address_two_devices_each_create_is_linked_to_its_own_device() {
        // 192.168.122.1 on the libvirt bridge of every hypervisor: one identity, two objects in one run.
        let (netbox, _, _) = netbox();
        netbox.enforce_global_unique(false);
        let site_id = netbox.add("dcim.sites", json!({"name": "Lab"}));
        let address = Identity::ip_address("192.168.122.1/24", VrfKey::Unknown);
        let names = ["pve01", "pve02"];
        let mut steps = Vec::new();
        for name in names {
            steps.push(
                Build::create(Kind::Device, &Identity::device(name))
                    .field("name", json!(name))
                    .reference("site", Kind::Site, &Identity::named("Lab"), Some(site_id))
                    .tags(OWNED)
                    .done(),
            );
        }
        for name in names {
            steps.push(
                Build::create(Kind::Interface, &Identity::interface(name, "virbr0"))
                    .field("name", json!("virbr0"))
                    .field("type", json!("bridge"))
                    .reference("device", Kind::Device, &Identity::device(name), None)
                    .tags(OWNED)
                    .done(),
            );
        }
        for name in names {
            steps.push(
                Build::create(Kind::IpAddress, &address)
                    .field("address", json!("192.168.122.1/24"))
                    .reference("assigned_object", Kind::Interface, &Identity::interface(name, "virbr0"), None)
                    .tags(OWNED)
                    .done(),
            );
        }
        for name in names {
            steps.push(
                Build::link(Kind::Device, &Identity::device(name), None)
                    .reference("primary_ip4", Kind::IpAddress, &address, None)
                    .done(),
            );
        }
        assert_eq!(apply(&netbox, &plan(steps), no_callback).await, Ok(Applied { written: 8, dry_run: false }));
        for name in names {
            let device_id = found(&netbox, "dcim.devices", "name", name);
            let primary = stored(&netbox, "dcim.devices", device_id)["primary_ip4"].as_u64().expect("a primary IP");
            let interface = stored(&netbox, IPS, primary)["assigned_object_id"].as_u64().expect("an interface");
            assert_eq!(stored(&netbox, "dcim.interfaces", interface)["device"], json!(device_id), "{name}");
        }
    }

    #[tokio::test]
    async fn an_address_created_twice_that_is_nobody_s_own_is_not_guessed() {
        let (netbox, _, _) = netbox();
        netbox.enforce_global_unique(false);
        let vm_id = netbox.add(VMS, json!({"name": "web01"}));
        let address = Identity::ip_address("172.17.0.1/16", VrfKey::Unknown);
        let loose = || Build::create(Kind::IpAddress, &address).field("address", json!("172.17.0.1/16")).done();
        let steps = vec![
            loose(),
            loose(),
            Build::link(Kind::VirtualMachine, &web01(), Some(vm_id))
                .reference("primary_ip4", Kind::IpAddress, &address, None)
                .done(),
        ];
        let error = apply(&netbox, &plan(steps), no_callback).await.expect_err("which of the two?");
        assert_eq!(
            error.message,
            "update vm web01: primary_ip4 refers to ip 172.17.0.1/16, \
             which this run created several times, none of them being its own"
        );
        assert_eq!(error.applied, 2);
        assert_eq!(stored(&netbox, VMS, vm_id).get("primary_ip4"), None);
    }

    // Payloads

    #[tokio::test]
    async fn adoption_sends_the_tags_and_nothing_else() {
        let (netbox, tool, source) = netbox();
        let old = tag(&netbox, "NetBox-synced", "netbox-synced");
        let gold = tag(&netbox, "backup-gold", "backup-gold");
        let vm_id = netbox.add(VMS, json!({"name": "web01", "comments": "ask before reboot", "tags": [old, gold]}));
        let sent = Sent::to(netbox);
        let steps = vec![
            Build::update(Kind::VirtualMachine, &web01(), Some(vm_id))
                .tags(["backup-gold", "netbox-omnisync", "source-pve1"])
                .done(),
        ];
        assert_eq!(apply(&sent, &plan(steps), no_callback).await, Ok(Applied { written: 1, dry_run: false }));
        assert_eq!(
            sent.calls(),
            [(
                format!("PATCH {VMS} {vm_id}"),
                json!({"tags": [{"name": "backup-gold"}, {"name": "netbox-omnisync"}, {"name": "source-pve1"}]})
            )]
        );
        let vm = stored(&sent.netbox, VMS, vm_id);
        assert_eq!(vm["tags"], json!([gold, tool, source]));
        assert_eq!(vm["comments"], json!("ask before reboot"));
        assert_eq!(vm["name"], json!("web01"));
    }

    #[tokio::test]
    async fn references_generic_relations_lists_and_custom_fields_are_sent_in_the_api_shape() {
        let (netbox, _, _) = netbox();
        let site_id = netbox.add("dcim.sites", json!({"name": "Lab"}));
        let vrf_id = netbox.add("ipam.vrfs", json!({"name": "Prod"}));
        let vlan_id = netbox.add("ipam.vlans", json!({"vid": 10, "name": "users", "site": site_id}));
        let device_id = netbox.add("dcim.devices", json!({"name": "pve01", "site": site_id}));
        let nic_id = netbox.add("dcim.interfaces", json!({"device": device_id, "name": "eno1", "type": "other"}));
        let ip_id = netbox.add(
            IPS,
            json!({"address": "192.0.2.10/24", "vrf": vrf_id, "assigned_object_type": "dcim.interface",
                   "assigned_object_id": nic_id, "custom_fields": {"owner_team": "infra"}}),
        );
        let sent = Sent::to(netbox);
        let users = Identity::vlan(VlanScope::Site("Lab"), 10);
        let voice = Identity::vlan(VlanScope::Site("Lab"), 20);
        let steps = vec![
            Build::create(Kind::Cluster, &Identity::named("pve-lab"))
                .field("name", json!("pve-lab"))
                .reference("scope", Kind::Site, &Identity::named("Lab"), Some(site_id))
                .done(),
            Build::create(Kind::Vlan, &voice).field("vid", json!(20)).field("name", json!("voice")).done(),
            Build::update(Kind::Interface, &Identity::interface("pve01", "eno1"), Some(nic_id))
                .reference("untagged_vlan", Kind::Vlan, &users, Some(vlan_id))
                .list(
                    "tagged_vlans",
                    vec![
                        Link { kind: Kind::Vlan, identity: users.clone(), id: Some(vlan_id) },
                        Link { kind: Kind::Vlan, identity: voice.clone(), id: None },
                    ],
                )
                .done(),
            Build::update(Kind::IpAddress, &Identity::ip_address("192.0.2.10/24", VrfKey::Named("Prod")), Some(ip_id))
                .cleared("assigned_object")
                .cleared("vrf")
                .field("description", json!("was the gateway"))
                .field("custom_fields", json!({"uuid": "42d0"}))
                .done(),
        ];
        assert_eq!(apply(&sent, &plan(steps), no_callback).await, Ok(Applied { written: 4, dry_run: false }));
        let voice_id = found(&sent.netbox, "ipam.vlans", "name", "voice");
        assert_eq!(
            sent.calls(),
            [
                (
                    format!("POST {CLUSTERS}"),
                    json!({"name": "pve-lab", "scope_type": "dcim.site", "scope_id": site_id})
                ),
                ("POST ipam.vlans".to_owned(), json!({"vid": 20, "name": "voice"})),
                (
                    format!("PATCH dcim.interfaces {nic_id}"),
                    json!({"untagged_vlan": vlan_id, "tagged_vlans": [vlan_id, voice_id]})
                ),
                (
                    format!("PATCH {IPS} {ip_id}"),
                    json!({
                        "assigned_object_type": null, "assigned_object_id": null, "vrf": null,
                        "description": "was the gateway", "custom_fields": {"uuid": "42d0"}
                    })
                ),
            ]
        );
        // NetBox merges the custom fields given into the ones it has.
        assert_eq!(stored(&sent.netbox, IPS, ip_id)["custom_fields"], json!({"owner_team": "infra", "uuid": "42d0"}));
    }

    // Deletions

    #[tokio::test]
    async fn deletions_are_written_in_the_order_given() {
        let (netbox, _, _) = netbox();
        let vm_id = netbox.add(VMS, json!({"name": "web01"}));
        let first = netbox.add(DISKS, json!({"name": "scsi0", "virtual_machine": vm_id}));
        let second = netbox.add(DISKS, json!({"name": "scsi1", "virtual_machine": vm_id}));
        let kept = netbox.add(DISKS, json!({"name": "scsi2", "virtual_machine": vm_id}));
        // Neither by id nor by name: the order of the plan.
        let steps = vec![
            Build::delete(Kind::VirtualDisk, &Identity::virtual_disk(&web01(), "scsi1"), Some(second)).done(),
            Build::delete(Kind::VirtualDisk, &Identity::virtual_disk(&web01(), "scsi0"), Some(first)).done(),
            Build::delete(Kind::VirtualMachine, &web01(), Some(vm_id)).done(),
        ];
        assert_eq!(apply(&netbox, &plan(steps), no_callback).await, Ok(Applied { written: 3, dry_run: false }));
        assert_eq!(
            netbox.writes(),
            [
                ("delete", DISKS.to_owned(), second),
                ("delete", DISKS.to_owned(), first),
                ("delete", VMS.to_owned(), vm_id)
            ]
        );
        assert_eq!(netbox.row(DISKS, first), None);
        assert!(netbox.row(DISKS, kept).is_some());
    }

    // Failures

    #[tokio::test]
    async fn the_first_failed_write_stops_everything_after_it() {
        let (netbox, _, _) = netbox();
        let named = |name: &str| Build::create(Kind::ClusterType, &Identity::named(name)).field("name", json!(name));
        let steps = vec![
            named("Proxmox").tags(OWNED).done(),
            // NetBox refuses a tag it does not have; the step after it is valid.
            named("vSphere").tags(["ghost"]).done(),
            named("Hyper-V").tags(OWNED).done(),
        ];
        let reported = AtomicUsize::new(0);
        let error = apply(&netbox, &plan(steps), || {
            reported.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .expect_err("the second write is refused");
        assert_eq!(error.applied, 1);
        assert_eq!(
            error.message,
            "create cluster_type vSphere: Related object not found using the provided attributes: {\"name\":\"ghost\"}"
        );
        assert_eq!(reported.load(Ordering::SeqCst), 1);
        let proxmox = found(&netbox, "virtualization.cluster_types", "name", "Proxmox");
        assert_eq!(netbox.writes(), [("create", "virtualization.cluster_types".to_owned(), proxmox)]);
        assert_eq!(netbox.find("virtualization.cluster_types", "name", &json!("Hyper-V")), None);
    }

    #[tokio::test]
    async fn a_reference_whose_target_was_never_created_is_an_error_before_anything_is_sent() {
        let (netbox, _, _) = netbox();
        let sent = Sent::to(netbox);
        let steps = vec![
            Build::create(Kind::ClusterType, &Identity::named("Proxmox")).field("name", json!("Proxmox")).done(),
            Build::create(Kind::VirtualMachine, &web01())
                .field("name", json!("web01"))
                .reference("cluster", Kind::Cluster, &Identity::named("pve-lab"), None)
                .done(),
            Build::create(Kind::VmInterface, &eth0_of(&web01())).field("name", json!("eth0")).done(),
        ];
        let error = apply(&sent, &plan(steps), no_callback).await.expect_err("the cluster was never created");
        assert_eq!(error.message, "create vm web01: cluster refers to cluster pve-lab, which this run did not create");
        assert_eq!(error.applied, 1);
        let calls: Vec<String> = sent.calls().into_iter().map(|(call, _)| call).collect();
        assert_eq!(calls, ["POST virtualization.cluster_types"]);
        assert_eq!(sent.netbox.find(VMS, "name", &json!("web01")), None);
    }

    #[tokio::test]
    async fn a_list_of_references_with_a_target_never_created_is_an_error_as_well() {
        let (netbox, _, _) = netbox();
        let device_id = netbox.add("dcim.devices", json!({"name": "pve01", "site": 12}));
        let nic_id = netbox.add("dcim.interfaces", json!({"device": device_id, "name": "eno1", "type": "other"}));
        let voice = Identity::vlan(VlanScope::Global, 20);
        let steps = vec![
            Build::update(Kind::Interface, &Identity::interface("pve01", "eno1"), Some(nic_id))
                .list("tagged_vlans", vec![Link { kind: Kind::Vlan, identity: voice, id: None }])
                .done(),
        ];
        let error = apply(&netbox, &plan(steps), no_callback).await.expect_err("the VLAN was never created");
        assert_eq!(
            error.message,
            "update interface pve01 eno1: tagged_vlans refers to vlan 20, which this run did not create"
        );
        assert_eq!(netbox.writes(), []);
    }

    #[tokio::test]
    async fn an_update_or_a_deletion_of_an_object_without_id_is_an_error() {
        let (netbox, _, _) = netbox();
        let update = vec![Build::link(Kind::VirtualMachine, &web01(), None).field("comments", json!("x")).done()];
        let error = apply(&netbox, &plan(update), no_callback).await.expect_err("nothing to update");
        assert_eq!(error.message, "update vm web01: no NetBox id, and this run did not create it");
        assert_eq!(error.applied, 0);
        let deletion = vec![Build::delete(Kind::VmInterface, &eth0_of(&web01()), None).done()];
        let error = apply(&netbox, &plan(deletion), no_callback).await.expect_err("nothing to delete");
        assert_eq!(error.message, "delete vm_interface web01 eth0: no NetBox id");
        assert_eq!(netbox.writes(), []);
    }

    /// A NetBox whose answer to a creation carries no id.
    struct NoId;

    impl Gateway for NoId {
        async fn list(&self, _: &str, _: &Filters) -> Result<Vec<Row>, GatewayError> {
            Ok(Vec::new())
        }

        async fn create(&self, _: &str, payload: &Row) -> Result<Row, GatewayError> {
            Ok(payload.clone())
        }

        async fn update(&self, _: &str, _: u64, _: &Row) -> Result<(), GatewayError> {
            Ok(())
        }

        async fn delete(&self, _: &str, _: u64) -> Result<(), GatewayError> {
            Ok(())
        }
        async fn check_write(&self, _: Write, _: &str, _: &[String]) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    impl DryRun for NoId {
        fn dry_run(&self) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn a_creation_answered_without_an_id_is_an_error() {
        let steps = vec![Build::create(Kind::Site, &Identity::named("Lab")).field("name", json!("Lab")).done()];
        let error = apply(&NoId, &plan(steps), no_callback).await.expect_err("no id to remember");
        assert_eq!(error.message, "create site Lab: NetBox answered without the id of the created object");
        // The object exists in NetBox: the write is counted.
        assert_eq!(error.applied, 1);
    }

    // Dry run

    #[tokio::test]
    async fn nothing_is_written_nor_attempted_in_dry_run() {
        let (netbox, _, _) = netbox();
        let vm_id = netbox.add(VMS, json!({"name": "web01", "comments": ""}));
        let old = netbox.add(VMS, json!({"name": "old01"}));
        netbox.refuse_writes(true);
        let whole = plan(vec![
            Build::create(Kind::Cluster, &Identity::named("pve-lab"))
                .field("name", json!("pve-lab"))
                .tags(OWNED)
                .done(),
            Build::update(Kind::VirtualMachine, &web01(), Some(vm_id)).field("comments", json!("managed")).done(),
            Build::delete(Kind::VirtualMachine, &Identity::virtual_machine("old01", ""), Some(old)).done(),
        ]);
        let before = whole.clone();
        let reported = AtomicUsize::new(0);
        let applied = apply(&netbox, &whole, || {
            reported.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(applied, Ok(Applied { written: 0, dry_run: true }));
        assert_eq!(reported.load(Ordering::SeqCst), 0);
        assert_eq!(netbox.refused(), []);
        assert_eq!(netbox.writes(), []);
        assert_eq!(stored(&netbox, VMS, vm_id)["comments"], json!(""));
        assert!(netbox.row(VMS, old).is_some());
        // The report still has every change to print.
        assert_eq!(whole, before);
        assert_eq!(whole.changes().len(), 3);
    }

    /// A gateway in dry run whose NetBox does not take one field: a dry run
    /// must tell what the real run would be refused, without writing.
    struct Picky {
        netbox: FakeGateway,
        dropped: &'static str,
        checked: Mutex<Vec<(Write, String, Vec<String>)>>,
    }

    impl Gateway for Picky {
        async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
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
            self.checked.lock().expect("the checks").push((write, endpoint.to_owned(), fields.to_vec()));
            match fields.iter().find(|field| *field == self.dropped) {
                Some(field) => Err(GatewayError::UnknownField { endpoint: endpoint.to_owned(), field: field.clone() }),
                None => Ok(()),
            }
        }
    }

    impl DryRun for Picky {
        fn dry_run(&self) -> bool {
            true
        }
    }

    // What a dry run checks must be what the real run sends: the fields of
    // each write sent, compared with those `written_fields` gives for its step.
    #[tokio::test]
    async fn the_fields_a_dry_run_checks_are_those_the_writes_send() {
        let (netbox, _, _) = netbox();
        let cluster_id = netbox.add(CLUSTERS, json!({"name": "pve-lab"}));
        let eth0 = eth0_of(&web01());
        let address = Identity::ip_address("192.0.2.21/24", VrfKey::Unknown);
        let steps = vec![
            Build::create(Kind::VirtualMachine, &web01())
                .field("name", json!("web01"))
                .field("custom_fields", json!({"source": "pve1"}))
                .reference("cluster", Kind::Cluster, &Identity::named("pve-lab"), Some(cluster_id))
                .tags(OWNED)
                .done(),
            Build::create(Kind::VmInterface, &eth0)
                .field("name", json!("eth0"))
                .reference("virtual_machine", Kind::VirtualMachine, &web01(), None)
                .tags(OWNED)
                .done(),
            Build::create(Kind::IpAddress, &address)
                .field("address", json!("192.0.2.21/24"))
                .reference("assigned_object", Kind::VmInterface, &eth0, None)
                .tags(OWNED)
                .done(),
            Build::link(Kind::VirtualMachine, &web01(), None)
                .reference("primary_ip4", Kind::IpAddress, &address, None)
                .done(),
        ];
        let whole = plan(steps);
        let sent = Sent::to(netbox);
        assert_eq!(apply(&sent, &whole, no_callback).await, Ok(Applied { written: 4, dry_run: false }));
        let calls = sent.calls();
        assert_eq!(calls.len(), whole.steps.len());
        for (step, (call, payload)) in whole.steps.iter().zip(calls) {
            let mut fields: Vec<String> = payload.as_object().expect("a payload").keys().cloned().collect();
            fields.sort();
            assert_eq!(fields, written_fields(step), "{call}");
        }
    }

    #[tokio::test]
    async fn a_dry_run_checks_the_fields_of_every_write_and_sends_none() {
        let (netbox, _, _) = netbox();
        let vm_id = netbox.add(VMS, json!({"name": "web01", "comments": ""}));
        let eth0 = eth0_of(&web01());
        let address = Identity::ip_address("192.0.2.21/24", VrfKey::Unknown);
        let whole = plan(vec![
            Build::update(Kind::VirtualMachine, &web01(), Some(vm_id)).field("comments", json!("managed")).done(),
            Build::create(Kind::IpAddress, &address)
                .field("address", json!("192.0.2.21/24"))
                .reference("assigned_object", Kind::VmInterface, &eth0, None)
                .tags(OWNED)
                .done(),
            Build::delete(Kind::VirtualMachine, &Identity::virtual_machine("old01", ""), Some(41)).done(),
        ]);
        let gateway = Picky { netbox, dropped: "", checked: Mutex::default() };
        assert_eq!(apply(&gateway, &whole, || {}).await, Ok(Applied { written: 0, dry_run: true }));
        // The fields as the writes would send them: a generic relation as its two halves.
        let fields = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect::<Vec<String>>();
        assert_eq!(
            *gateway.checked.lock().unwrap(),
            [
                (Write::Update, VMS.to_owned(), fields(&["comments"])),
                (
                    Write::Create,
                    IPS.to_owned(),
                    fields(&["address", "assigned_object_id", "assigned_object_type", "tags"])
                ),
            ]
        );
        assert_eq!(gateway.netbox.writes(), []);

        // A field NetBox would drop fails the dry run, naming the step.
        let gateway = Picky { dropped: "comments", ..gateway };
        let refused = apply(&gateway, &whole, || {}).await.expect_err("a field NetBox would drop");
        assert_eq!(
            refused.message,
            "update vm web01: unknown field comments on virtualization.virtual_machines: NetBox would drop it"
        );
        assert_eq!(gateway.netbox.writes(), []);
    }

    // The whole chain: load, reconcile, apply, and again

    fn named(kind: Kind, name: &str, slug: &str) -> Desired {
        Desired::new(kind, Identity::named(name), PVE).field("name", name).create_only("slug", slug)
    }

    fn vm_interface(machine: &Identity, mac: &Identity) -> Desired {
        Desired::new(Kind::VmInterface, eth0_of(machine), PVE)
            .field("name", "eth0")
            .field("enabled", true)
            .reference("virtual_machine", Kind::VirtualMachine, machine.clone())
            .reference("primary_mac_address", Kind::MacAddress, mac.clone())
    }

    fn mac_address(address: &str, interface: &Identity) -> (Identity, Desired) {
        let identity = Identity::mac_address(address, Some(&Target::new(Kind::VmInterface, interface.clone())));
        let desired = Desired::new(Kind::MacAddress, identity.clone(), PVE).field("mac_address", address).reference(
            "assigned_object",
            Kind::VmInterface,
            interface.clone(),
        );
        (identity, desired)
    }

    fn ip_address(address: &str, kind: Kind, interface: &Identity) -> Desired {
        Desired::new(Kind::IpAddress, Identity::ip_address(address, VrfKey::Unknown), PVE)
            .field("address", address)
            .field("status", "active")
            .reference("assigned_object", kind, interface.clone())
    }

    /// A small Proxmox cluster as a source reports it: one host with two
    /// interfaces and an address, two virtual machines with an interface, a
    /// MAC and an address each, one disk.
    fn lab() -> Vec<Desired> {
        lab_named("pve01", "web01")
    }

    /// The same cluster, its host and its first virtual machine under the
    /// names given: what the source reports once one of them is renamed.
    fn lab_named(host_name: &str, web_name: &str) -> Vec<Desired> {
        let cluster = Identity::named("pve-lab");
        let host = Identity::device(host_name);
        let r640 = Identity::device_type("Dell", "PowerEdge R640");
        let web = Identity::virtual_machine(web_name, "pve-lab");
        let db = Identity::virtual_machine("db01", "pve-lab");
        let (web_mac, web_mac_object) = mac_address("BC:24:11:00:00:01", &eth0_of(&web));
        let (db_mac, db_mac_object) = mac_address("BC:24:11:00:00:02", &eth0_of(&db));
        let machine = |identity: &Identity, name: &str| {
            Desired::new(Kind::VirtualMachine, identity.clone(), PVE)
                .field("name", name)
                .field("status", "active")
                .field("vcpus", 2)
                .field("memory", 4096)
                .reference("cluster", Kind::Cluster, cluster.clone())
        };
        let host_interface = |name: &str| {
            Desired::new(Kind::Interface, Identity::interface(host_name, name), PVE)
                .field("name", name)
                .field("type", "other")
                .reference("device", Kind::Device, host.clone())
        };
        vec![
            named(Kind::Tag, "netbox-omnisync", "netbox-omnisync"),
            named(Kind::Tag, "source-pve1", "source-pve1"),
            named(Kind::Site, "Lab", "lab").ensure_only(),
            named(Kind::Manufacturer, "Dell", "dell"),
            Desired::new(Kind::DeviceType, r640.clone(), PVE)
                .field("model", "PowerEdge R640")
                .create_only("slug", "poweredge-r640")
                .reference("manufacturer", Kind::Manufacturer, Identity::named("Dell")),
            named(Kind::Role, "Hypervisor", "hypervisor"),
            named(Kind::ClusterType, "Proxmox", "proxmox"),
            Desired::new(Kind::Cluster, cluster.clone(), PVE)
                .field("name", "pve-lab")
                .field("status", "active")
                .reference("type", Kind::ClusterType, Identity::named("Proxmox"))
                .reference("scope", Kind::Site, Identity::named("Lab")),
            Desired::new(Kind::Device, host.clone(), PVE)
                .field("name", host_name)
                .field("status", "active")
                .reference("site", Kind::Site, Identity::named("Lab"))
                .reference("device_type", Kind::DeviceType, r640)
                .reference("role", Kind::Role, Identity::named("Hypervisor"))
                .reference("cluster", Kind::Cluster, cluster.clone()),
            host_interface("eno1"),
            host_interface("eno2"),
            ip_address("192.0.2.10/24", Kind::Interface, &Identity::interface(host_name, "eno1")),
            machine(&web, web_name)
                .reference("primary_ip4", Kind::IpAddress, Identity::ip_address("192.0.2.21/24", VrfKey::Unknown))
                .only_when_empty("primary_ip4"),
            machine(&db, "db01"),
            vm_interface(&web, &web_mac),
            vm_interface(&db, &db_mac),
            web_mac_object,
            db_mac_object,
            ip_address("192.0.2.21/24", Kind::VmInterface, &eth0_of(&web)),
            ip_address("192.0.2.22/24", Kind::VmInterface, &eth0_of(&db)),
            Desired::new(Kind::VirtualDisk, Identity::virtual_disk(&web, "scsi0"), PVE)
                .field("name", "scsi0")
                .field("size", 32000)
                .reference("virtual_machine", Kind::VirtualMachine, web),
        ]
    }

    /// Loads every kind, as a run does, and reconciles: one run, up to the plan.
    async fn planned(netbox: &FakeGateway, desired: &[Desired]) -> Plan {
        let kinds: BTreeSet<Kind> = Kind::ALL.into();
        let loaded = load(netbox, &kinds).await.expect("loaded");
        assert_eq!(loaded.warnings, Vec::<String>::new());
        let run = Run {
            sources: vec![SourceFacts {
                name: PVE.to_owned(),
                tag: "source-pve1".to_owned(),
                status: SourceStatus::Succeeded,
                prune: true,
                create_devices: true,
            }],
            priority: vec![PVE.to_owned()],
            unique_ip_vrfs: loaded.unique_ip_vrfs,
            source_tag_markers: Vec::new(),
        };
        reconcile(desired, &loaded.current, &run)
    }

    fn count(netbox: &FakeGateway, endpoint: &str) -> usize {
        netbox.writes().iter().filter(|(kind, written, _)| *kind == "create" && written == endpoint).count()
    }

    #[tokio::test]
    async fn a_second_run_on_what_the_first_one_wrote_changes_nothing() {
        let netbox = FakeGateway::new();
        let desired = lab();
        let first = planned(&netbox, &desired).await;
        assert_eq!(first.warnings, Vec::<String>::new());
        // 21 objects, then the primary MAC of two interfaces and the primary IP of web01.
        let applied = apply(&netbox, &first, no_callback).await;
        assert_eq!(applied, Ok(Applied { written: 24, dry_run: false }));
        assert_eq!(count(&netbox, VMS), 2);
        assert_eq!(count(&netbox, IPS), 3);
        assert_eq!(count(&netbox, MACS), 2);
        assert_eq!(count(&netbox, "dcim.interfaces"), 2);
        let web_id = found(&netbox, VMS, "name", "web01");
        let web_ip = found(&netbox, IPS, "address", "192.0.2.21/24");
        assert_eq!(stored(&netbox, VMS, web_id)["primary_ip4"], json!(web_ip));
        let cluster = stored(&netbox, CLUSTERS, found(&netbox, CLUSTERS, "name", "pve-lab"));
        assert_eq!(cluster["scope_type"], json!("dcim.site"));
        assert_eq!(cluster["scope_id"], json!(found(&netbox, "dcim.sites", "name", "Lab")));

        let second = planned(&netbox, &desired).await;
        assert_eq!(second, Plan::default());
    }

    /// The same cluster as the old tools left it: their ownership tags, names
    /// in their own letter case, slugs of their own making, numbers as NetBox
    /// stores them, a site and a tag made by hand.
    fn left_by_the_old_tools() -> (FakeGateway, u64, u64) {
        let netbox = FakeGateway::new();
        let synced = tag(&netbox, "NetBox-synced", "netbox-synced");
        let old_source = tag(&netbox, "Source: vcenter-old", "source-vcenter-old");
        let ssot = tag(&netbox, "netbox-ssot", "netbox-ssot");
        let gold = tag(&netbox, "backup-gold", "backup-gold");
        let owned = json!([synced, old_source]);
        let site = netbox.add("dcim.sites", json!({"name": "Lab", "slug": "lab-1"}));
        let dell = netbox.add("dcim.manufacturers", json!({"name": "Dell", "slug": "dell-inc", "tags": owned}));
        let r640 = netbox.add(
            "dcim.device_types",
            json!({"model": "PowerEdge R640", "slug": "r640", "manufacturer": dell, "tags": owned}),
        );
        let role = netbox.add("dcim.device_roles", json!({"name": "Hypervisor", "slug": "hv", "tags": owned}));
        let kind =
            netbox.add("virtualization.cluster_types", json!({"name": "Proxmox", "slug": "pve", "tags": [ssot]}));
        let cluster = netbox.add(
            CLUSTERS,
            json!({"name": "PVE-Lab", "status": "active", "type": kind, "scope_type": "dcim.site",
                   "scope_id": site, "tags": [ssot]}),
        );
        let host = netbox.add(
            "dcim.devices",
            json!({"name": "pve01", "status": "active", "site": site, "device_type": r640, "role": role,
                   "cluster": cluster, "tags": owned}),
        );
        let eno1 =
            netbox.add("dcim.interfaces", json!({"device": host, "name": "eno1", "type": "other", "tags": owned}));
        netbox.add("dcim.interfaces", json!({"device": host, "name": "eno2", "type": "other", "tags": owned}));
        netbox.add(
            IPS,
            json!({"address": "192.0.2.10/24", "status": "active", "vrf": null,
                   "assigned_object_type": "dcim.interface", "assigned_object_id": eno1, "tags": owned}),
        );
        let mut web = 0;
        for (name, mac, address, tags) in [
            ("Web01", "BC:24:11:00:00:01", "192.0.2.21/24", json!([synced, old_source, gold])),
            ("db01", "BC:24:11:00:00:02", "192.0.2.22/24", owned.clone()),
        ] {
            let machine = netbox.add(
                VMS,
                json!({"name": name, "status": "active", "vcpus": 2.0, "memory": 4096, "cluster": cluster,
                       "tags": tags}),
            );
            let interface = netbox.add(
                VM_INTERFACES,
                json!({"name": "eth0", "enabled": true, "virtual_machine": machine, "tags": owned}),
            );
            let mac = netbox.add(
                MACS,
                json!({"mac_address": mac, "assigned_object_type": "virtualization.vminterface",
                       "assigned_object_id": interface, "tags": owned}),
            );
            netbox.set(VM_INTERFACES, interface, "primary_mac_address", json!(mac));
            let ip = netbox.add(
                IPS,
                json!({"address": address, "status": "active", "vrf": null,
                       "assigned_object_type": "virtualization.vminterface", "assigned_object_id": interface,
                       "tags": owned}),
            );
            if name == "Web01" {
                netbox.set(VMS, machine, "primary_ip4", json!(ip));
                netbox.add(DISKS, json!({"name": "scsi0", "size": 32000, "virtual_machine": machine, "tags": owned}));
                web = machine;
            }
        }
        (netbox, web, gold)
    }

    #[tokio::test]
    async fn adopting_what_the_old_tools_left_changes_tags_only_and_once() {
        let (netbox, web, gold) = left_by_the_old_tools();
        let desired = lab();
        let first = planned(&netbox, &desired).await;
        assert_eq!(first.warnings, Vec::<String>::new());

        // The two tags of the tool do not exist yet.
        let created: Vec<(&str, &str)> = first
            .steps
            .iter()
            .filter(|step| step.change.action == Action::Create)
            .map(|step| (step.change.kind.as_str(), step.change.key.as_str()))
            .collect();
        assert_eq!(created, [("tag", "netbox-omnisync"), ("tag", "source-pve1")]);
        // Everything else is the tag set of an object the old tools owned;
        // the site, made by hand and only needed to exist, is left alone.
        let mut adopted: BTreeMap<&str, usize> = BTreeMap::new();
        for step in first.steps.iter().filter(|step| step.change.action != Action::Create) {
            let fields: Vec<&str> = step.change.fields.keys().map(String::as_str).collect();
            assert_eq!((step.change.action, step.phase, fields), (Action::Update, Phase::Write, vec!["tags"]));
            *adopted.entry(step.change.kind.as_str()).or_default() += 1;
        }
        assert_eq!(
            adopted,
            BTreeMap::from([
                ("cluster", 1),
                ("cluster_type", 1),
                ("device", 1),
                ("device_type", 1),
                ("disk", 1),
                ("interface", 2),
                ("ip", 3),
                ("mac", 2),
                ("manufacturer", 1),
                ("role", 1),
                ("vm", 2),
                ("vm_interface", 2),
            ])
        );
        let of_web = first.steps.iter().find(|step| step.change.id == Some(web) && step.kind == Kind::VirtualMachine);
        assert_eq!(
            of_web.map(|step| &step.change.fields["tags"]),
            Some(&json!(["backup-gold", "netbox-omnisync", "source-pve1"]))
        );

        assert_eq!(apply(&netbox, &first, no_callback).await, Ok(Applied { written: 20, dry_run: false }));
        let tool = found(&netbox, "extras.tags", "name", "netbox-omnisync");
        let source = found(&netbox, "extras.tags", "name", "source-pve1");
        let web_row = stored(&netbox, VMS, web);
        assert_eq!(web_row["tags"], json!([gold, tool, source]));
        // The name keeps the letter case NetBox had.
        assert_eq!(web_row["name"], json!("Web01"));
        // Nothing but the two tags was created: no object was duplicated.
        let writes = netbox.writes();
        let created_in: Vec<&str> =
            writes.iter().filter(|(kind, _, _)| *kind == "create").map(|(_, endpoint, _)| endpoint.as_str()).collect();
        assert_eq!(created_in, ["extras.tags", "extras.tags"]);

        let second = planned(&netbox, &desired).await;
        assert_eq!(second, Plan::default());
    }

    // Renames

    /// What was written since `since` writes, as (operation, endpoint).
    fn written_since(netbox: &FakeGateway, since: usize) -> Vec<(&'static str, String)> {
        netbox.writes().into_iter().skip(since).map(|(operation, endpoint, _)| (operation, endpoint)).collect()
    }

    #[tokio::test]
    async fn a_virtual_machine_renamed_in_its_source_is_renamed_in_place_with_everything_under_it() {
        let netbox = FakeGateway::new();
        let first = planned(&netbox, &lab()).await;
        assert_eq!(apply(&netbox, &first, no_callback).await, Ok(Applied { written: 24, dry_run: false }));
        let web = found(&netbox, VMS, "name", "web01");
        let eth0 = netbox.find(VM_INTERFACES, "virtual_machine", &json!(web)).expect("the interface of web01");
        let mac = found(&netbox, MACS, "mac_address", "BC:24:11:00:00:01");
        let ip = found(&netbox, IPS, "address", "192.0.2.21/24");
        let disk = found(&netbox, DISKS, "name", "scsi0");

        // The source now calls web01 `www01`: same interface, MAC, address and disk.
        let renamed = lab_named("pve01", "www01");
        let second = planned(&netbox, &renamed).await;
        assert_eq!(second.warnings, Vec::<String>::new());
        assert_eq!(
            second.changes(),
            [Change::new("vm", Action::Update, "www01", "www01")
                .fields([("name", json!("www01"))])
                .before([("name", json!("web01"))])
                .id(web)]
        );
        assert_eq!(apply(&netbox, &second, no_callback).await, Ok(Applied { written: 1, dry_run: false }));
        assert_eq!(written_since(&netbox, 24), [("update", VMS.to_owned())]);

        // The same NetBox objects, still under the machine: nothing was made anew.
        assert_eq!(stored(&netbox, VMS, web)["name"], json!("www01"));
        assert_eq!(netbox.find(VMS, "name", &json!("web01")), None);
        assert_eq!(stored(&netbox, VM_INTERFACES, eth0)["virtual_machine"], json!(web));
        assert_eq!(stored(&netbox, VM_INTERFACES, eth0)["primary_mac_address"], json!(mac));
        assert_eq!(stored(&netbox, MACS, mac)["assigned_object_id"], json!(eth0));
        assert_eq!(stored(&netbox, IPS, ip)["assigned_object_id"], json!(eth0));
        assert_eq!(stored(&netbox, VMS, web)["primary_ip4"], json!(ip));
        assert_eq!(stored(&netbox, DISKS, disk)["virtual_machine"], json!(web));

        let third = planned(&netbox, &renamed).await;
        assert_eq!(third, Plan::default());
    }

    /// The cluster with the MAC address of `eno1` of its host: a host is
    /// recognised by the addresses of its interfaces.
    fn lab_with_the_mac_of_its_host(host_name: &str) -> Vec<Desired> {
        let eno1 = Identity::interface(host_name, "eno1");
        let address = "D4:AE:52:00:00:01";
        let identity = Identity::mac_address(address, Some(&Target::new(Kind::Interface, eno1.clone())));
        let mut desired = lab_named(host_name, "web01");
        desired.push(Desired::new(Kind::MacAddress, identity, PVE).field("mac_address", address).reference(
            "assigned_object",
            Kind::Interface,
            eno1,
        ));
        desired
    }

    #[tokio::test]
    async fn a_host_renamed_in_its_source_is_renamed_in_place_with_everything_under_it() {
        let netbox = FakeGateway::new();
        let first = planned(&netbox, &lab_with_the_mac_of_its_host("pve01")).await;
        // The 24 writes of the cluster, and the MAC address of the host.
        assert_eq!(apply(&netbox, &first, no_callback).await, Ok(Applied { written: 25, dry_run: false }));
        let host = found(&netbox, "dcim.devices", "name", "pve01");
        let eno1 = found(&netbox, "dcim.interfaces", "name", "eno1");
        let eno2 = found(&netbox, "dcim.interfaces", "name", "eno2");
        let mac = found(&netbox, MACS, "mac_address", "D4:AE:52:00:00:01");
        let ip = found(&netbox, IPS, "address", "192.0.2.10/24");

        // The source now calls the host `pve02`.
        let renamed = lab_with_the_mac_of_its_host("pve02");
        let second = planned(&netbox, &renamed).await;
        assert_eq!(second.warnings, Vec::<String>::new());
        assert_eq!(
            second.changes(),
            [Change::new("device", Action::Update, "pve02", "pve02")
                .fields([("name", json!("pve02"))])
                .before([("name", json!("pve01"))])
                .id(host)]
        );
        assert_eq!(apply(&netbox, &second, no_callback).await, Ok(Applied { written: 1, dry_run: false }));
        assert_eq!(written_since(&netbox, 25), [("update", "dcim.devices".to_owned())]);

        assert_eq!(stored(&netbox, "dcim.devices", host)["name"], json!("pve02"));
        assert_eq!(netbox.find("dcim.devices", "name", &json!("pve01")), None);
        assert_eq!(stored(&netbox, "dcim.interfaces", eno1)["device"], json!(host));
        assert_eq!(stored(&netbox, "dcim.interfaces", eno2)["device"], json!(host));
        assert_eq!(stored(&netbox, MACS, mac)["assigned_object_id"], json!(eno1));
        assert_eq!(stored(&netbox, IPS, ip)["assigned_object_id"], json!(eno1));

        let third = planned(&netbox, &renamed).await;
        assert_eq!(third, Plan::default());
    }
}
