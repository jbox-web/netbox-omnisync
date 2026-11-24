//! The collection of a vCenter: everything the source reads, or nothing.
//!
//! A vCenter that cannot be read whole is not read at all: with a part
//! missing, the run would delete from NetBox what was merely not read.

use std::collections::{BTreeMap, BTreeSet};

use crate::client::{ClientError, Session, Tag, VsphereClient};
use crate::model::{Host, Machine, Node, Reference};
use crate::soap::{CardHint, ObjectContent};
use crate::xml::Element;

/// A distributed switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedSwitch {
    pub id: String,
    pub name: Option<String>,
    pub uuid: Option<String>,
}

/// A port group of a distributed switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedPortGroup {
    pub id: String,
    pub name: Option<String>,
    pub key: Option<String>,
    pub switch: Option<Reference>,
    /// `config.defaultPortConfig`, as vCenter gives it: no answer of a real
    /// vCenter was observed for it yet.
    pub default_port_config: Option<Element>,
}

/// What was read of a vCenter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// `VMware vCenter Server 6.7.0 build-22509751`.
    pub server: String,
    pub api_version: String,
    pub datacenters: Vec<Node>,
    pub folders: Vec<Node>,
    /// The clusters, then the standalone compute resources: a host that is in
    /// no cluster is alone in one of these.
    pub clusters: Vec<Node>,
    pub switches: Vec<DistributedSwitch>,
    pub port_groups: Vec<DistributedPortGroup>,
    pub hosts: Vec<Host>,
    pub machines: Vec<Machine>,
    pub tags: Vec<Tag>,
    /// The cards of each connected host, by the id of the host, with the
    /// switch port each one hears: only when the collection wants them, and
    /// only for the hosts whose hint could be read.
    pub hints: BTreeMap<String, Vec<CardHint>>,
    /// What could not be read without failing the collection: the hint of a host.
    pub warnings: Vec<String>,
}

impl Inventory {
    /// The cluster, or standalone compute resource, of a host.
    pub fn cluster_of(&self, host: &Host) -> Option<&Node> {
        let parent = host.parent.as_ref()?;
        self.clusters.iter().find(|cluster| cluster.id == parent.id)
    }

    /// The datacenter above an object, through the folders it is in.
    pub fn datacenter_of(&self, reference: &Reference) -> Option<&Node> {
        let mut reference = reference;
        // As many steps as there are folders at most: a loop among them ends here.
        for _ in 0..=self.folders.len() {
            if let Some(datacenter) = self.datacenters.iter().find(|datacenter| datacenter.id == reference.id) {
                return Some(datacenter);
            }
            reference = self.folders.iter().find(|folder| folder.id == reference.id)?.parent.as_ref()?;
        }
        None
    }

    /// The tags an object carries.
    pub fn tags_of(&self, kind: &str, id: &str) -> Vec<&Tag> {
        let carries = |tag: &&Tag| tag.objects.iter().any(|object| object.kind == kind && object.id == id);
        self.tags.iter().filter(carries).collect()
    }
}

/// Why a vCenter was not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollectError {
    #[error(transparent)]
    Client(#[from] ClientError),
    /// A vCenter always has a datacenter: without one, what answered is not
    /// an inventory, and syncing it would empty NetBox of this source.
    #[error("the vCenter reports no datacenter: an empty inventory is never synced")]
    Empty,
}

/// What a collection reads besides the inventory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Wanted {
    /// The switch port each physical card of each host hears (`QueryNetworkHint`).
    pub hints: bool,
}

/// Reads a whole vCenter in one session, ended whatever was read.
pub async fn collect(client: &VsphereClient) -> Result<Inventory, CollectError> {
    collect_with(client, &Wanted::default()).await
}

/// Reads a whole vCenter in one session, and what else is wanted.
pub async fn collect_with(client: &VsphereClient, wanted: &Wanted) -> Result<Inventory, CollectError> {
    let session = client.login().await?;
    let inventory = read(client, &session, wanted).await;
    // Whatever was read: a session left open counts against the limit of the server.
    let _ = session.logout().await;
    inventory
}

/// The properties read of each kind of object.
const NODE: [&str; 2] = ["name", "parent"];
const COMPUTE: [&str; 3] = ["name", "parent", "host"];
const SWITCH: [&str; 2] = ["name", "uuid"];
const PORT_GROUP: [&str; 4] = ["name", "key", "config.defaultPortConfig", "config.distributedVirtualSwitch"];
const HOST: [&str; 10] = [
    "name",
    "parent",
    "summary.config.product",
    "summary.hardware",
    "summary.runtime.connectionState",
    "config.network.pnic",
    "config.network.vnic",
    "config.network.vswitch",
    "config.network.portgroup",
    "config.network.proxySwitch",
];
const MACHINE: [&str; 17] = [
    "name",
    "config.annotation",
    "config.guestFullName",
    "config.hardware.device",
    "config.hardware.memoryMB",
    "config.hardware.numCPU",
    "config.instanceUuid",
    "config.uuid",
    "config.template",
    "config.extraConfig",
    "guest.guestFullName",
    "guest.net",
    "guest.ipStack",
    "guest.hostName",
    "guest.toolsRunningStatus",
    "runtime.host",
    "runtime.powerState",
];

async fn read(client: &VsphereClient, session: &Session<'_>, wanted: &Wanted) -> Result<Inventory, CollectError> {
    // Every kind at once, and the tags: they are independent, and the client
    // caps the requests in flight. The tags run to their end whatever the other
    // reads give: dropped half way, they would leave their REST session open.
    let (objects, tags) = futures::join!(
        async {
            futures::try_join!(
                session.objects("Datacenter", &NODE),
                session.objects("Folder", &NODE),
                session.objects("ClusterComputeResource", &COMPUTE),
                session.objects("ComputeResource", &COMPUTE),
                session.objects("DistributedVirtualSwitch", &SWITCH),
                session.objects("DistributedVirtualPortgroup", &PORT_GROUP),
                session.objects("HostSystem", &HOST),
                session.objects("VirtualMachine", &MACHINE),
            )
        },
        client.tags(),
    );
    let (datacenters, folders, clusters, standalone, switches, port_groups, hosts, machines) = objects?;
    let tags = tags?;
    let hosts: Vec<Host> = hosts.iter().map(Host::of).collect();
    let (hints, warnings) = if wanted.hints { read_hints(session, &hosts).await } else { Default::default() };
    // Without a session every read above answers "nothing", as a success:
    // the session is proven alive after them, or none of them is kept.
    session.ensure_alive().await?;
    if datacenters.is_empty() {
        return Err(CollectError::Empty);
    }
    let mut clusters: Vec<Node> = clusters.iter().map(Node::of).collect();
    // A cluster is a compute resource too: only the others are added.
    let known: BTreeSet<String> = clusters.iter().map(|cluster| cluster.id.clone()).collect();
    clusters.extend(standalone.iter().map(Node::of).filter(|resource| !known.contains(&resource.id)));
    let switch = |object: &ObjectContent| DistributedSwitch {
        id: object.id.clone(),
        name: object.text("name").map(str::to_owned),
        uuid: object.text("uuid").map(str::to_owned),
    };
    let port_group = |object: &ObjectContent| {
        let switch = object.properties.get("config.distributedVirtualSwitch");
        DistributedPortGroup {
            id: object.id.clone(),
            name: object.text("name").map(str::to_owned),
            key: object.text("key").map(str::to_owned),
            switch: switch
                .and_then(|switch| Some(Reference { kind: switch.reference.clone()?, id: switch.text.clone() })),
            default_port_config: object.properties.get("config.defaultPortConfig").cloned(),
        }
    };
    Ok(Inventory {
        server: session.content().full_name.clone(),
        api_version: session.content().api_version.clone(),
        datacenters: datacenters.iter().map(Node::of).collect(),
        folders: folders.iter().map(Node::of).collect(),
        clusters,
        switches: switches.iter().map(switch).collect(),
        port_groups: port_groups.iter().map(port_group).collect(),
        hosts,
        machines: machines.iter().map(Machine::of).collect(),
        tags,
        hints,
        warnings,
    })
}

/// The network system of each host, asked apart from the other properties:
/// only a collection that wants the hints needs it.
const NETWORK_SYSTEM: [&str; 1] = ["configManager.networkSystem"];

/// The cards of each connected host with the switch port each one hears, by
/// host id, and a warning for each host whose hint could not be read: the
/// others are kept, and the collection goes on.
///
/// The hints are not the inventory: a failure to read the network systems is
/// one warning, and the vCenter is read all the same.
async fn read_hints(session: &Session<'_>, hosts: &[Host]) -> (BTreeMap<String, Vec<CardHint>>, Vec<String>) {
    let objects = match session.objects("HostSystem", &NETWORK_SYSTEM).await {
        Ok(objects) => objects,
        Err(error) => {
            let warning = format!("the switch ports the cards of the hosts hear cannot be read: {error}");
            return (BTreeMap::new(), vec![warning]);
        }
    };
    let systems: BTreeMap<String, String> = objects
        .into_iter()
        .filter_map(|object| Some((object.id.clone(), object.text(NETWORK_SYSTEM[0])?.to_owned())))
        .filter(|(_, system)| !system.is_empty())
        .collect();
    // A host that is not connected answers nothing of its cards.
    let asked: Vec<(&Host, &String)> = hosts
        .iter()
        .filter(|host| host.connection_state.as_deref() == Some("connected"))
        .filter_map(|host| Some((host, systems.get(&host.id)?)))
        .collect();
    // Every host at once: the client caps the requests in flight.
    let answers = futures::future::join_all(asked.iter().map(|(_, system)| session.network_hint(system))).await;
    let mut hints = BTreeMap::new();
    let mut warnings = Vec::new();
    for ((host, _), answer) in asked.into_iter().zip(answers) {
        match answer {
            Ok(cards) => {
                hints.insert(host.id.clone(), cards);
            }
            Err(error) => {
                let name = host.name.as_deref().unwrap_or(&host.id);
                warnings.push(format!("{name}: the switch ports its cards hear cannot be read: {error}"));
            }
        }
    }
    (hints, warnings)
}
