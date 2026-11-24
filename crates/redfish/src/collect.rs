//! Reads one BMC whole, with the calls of the closed list and nothing else.
//!
//! The calls, one after the other:
//!
//! 1. the service root;
//! 2. the systems, then the first one: the server;
//! 3. the manager the system links to (`Links.ManagedBy`, or `links.ManagedBy`
//!    on iLO 4), when it links to one: the BMC itself;
//! 4. the MAC addresses of the server: the ones the system gives itself when
//!    it does (`HostCorrelation.HostMACAddress`, iLO 4), else its Ethernet
//!    interfaces, then each of them.
//!
//! That is four reads on an iLO 4, and five plus one per card on an iDRAC. An
//! answer that is missing, refused or not what it should be fails the whole
//! BMC: a part of a BMC is never reported.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::client::{Call, ClientError, RedfishClient};
use crate::model::{Bmc, Manager, System};

/// Why a BMC could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollectError {
    #[error(transparent)]
    Client(#[from] ClientError),
    /// An answer that was read and does not hold what the collection needs.
    #[error("GET {path}: {reason}")]
    Unexpected { path: String, reason: String },
}

/// A link to another resource, as Redfish writes one (`@odata.id`) or as
/// iLO 4 writes it under `links` (`href`).
#[derive(Debug, Default, Deserialize)]
struct WireLink {
    #[serde(rename = "@odata.id", alias = "href")]
    path: Option<String>,
}

/// A collection: the links to its members, and how many it has in all.
#[derive(Debug, Default, Deserialize)]
struct WireCollection {
    #[serde(rename = "Members", default)]
    members: Vec<WireLink>,
    #[serde(rename = "Members@odata.count")]
    count: Option<u64>,
    #[serde(rename = "Members@odata.nextLink")]
    next: Option<String>,
}

impl WireCollection {
    /// The members, when the answer holds them all. A collection given in
    /// pages is refused: its next pages are not among the calls of the client,
    /// and read as a whole it would be a server with fewer cards.
    fn whole(&self, call: &Call) -> Result<&[WireLink], CollectError> {
        let given = self.members.len() as u64;
        match self.count {
            Some(count) if self.next.is_some() || count > given => Err(CollectError::Unexpected {
                path: call.path().unwrap_or_default().to_owned(),
                reason: format!("{given} of {count} members given, the rest in pages that are never asked"),
            }),
            None if self.next.is_some() => Err(CollectError::Unexpected {
                path: call.path().unwrap_or_default().to_owned(),
                reason: format!("{given} members given, the rest in pages that are never asked"),
            }),
            _ => Ok(&self.members),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct WireRoot {
    #[serde(rename = "RedfishVersion")]
    redfish_version: Option<String>,
}

/// The links of a system: `Links` in Redfish, `links` on iLO 4 (Redfish 1.0).
#[derive(Debug, Default, Deserialize)]
struct WireSystemLinks {
    #[serde(rename = "ManagedBy", default)]
    managed_by: Vec<WireLink>,
}

/// What iLO 4 says of the host next to the system itself.
#[derive(Debug, Default, Deserialize)]
struct WireHostCorrelation {
    #[serde(rename = "HostMACAddress", default)]
    mac_addresses: Vec<Option<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct WireSystem {
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "SKU")]
    sku: Option<String>,
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "EthernetInterfaces")]
    ethernet_interfaces: Option<WireLink>,
    #[serde(rename = "Links")]
    links: Option<WireSystemLinks>,
    #[serde(rename = "links")]
    legacy_links: Option<WireSystemLinks>,
    #[serde(rename = "HostCorrelation")]
    host_correlation: Option<WireHostCorrelation>,
}

#[derive(Debug, Default, Deserialize)]
struct WireManager {
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "FirmwareVersion")]
    firmware_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct WireEthernetInterface {
    #[serde(rename = "MACAddress")]
    mac_address: Option<String>,
}

/// A text without the spaces around it; `None` when nothing is left: a blank
/// value is a value the BMC does not have.
fn text(value: Option<String>) -> Option<String> {
    value.map(|text| text.trim().to_owned()).filter(|text| !text.is_empty())
}

/// What `call` answers, read as `T`. The reason of a mismatch is not serde's:
/// it would quote the answer.
async fn read<T: DeserializeOwned>(client: &RedfishClient, call: &Call) -> Result<T, CollectError> {
    let answer: Value = client.get(call).await?;
    serde_json::from_value(answer).map_err(|_| CollectError::Unexpected {
        path: call.path().unwrap_or_default().to_owned(),
        reason: "the answer does not have the expected shape".to_owned(),
    })
}

/// The path a link gives; an error naming `from`, the resource holding the link, when it gives none.
fn linked(link: Option<&WireLink>, from: &Call, what: &str) -> Result<String, CollectError> {
    link.and_then(|link| link.path.clone()).ok_or_else(|| CollectError::Unexpected {
        path: from.path().unwrap_or_default().to_owned(),
        reason: format!("no {what} in the answer"),
    })
}

/// The MAC addresses of the Ethernet interfaces of a system, each read in turn.
async fn interface_addresses(client: &RedfishClient, interfaces: String) -> Result<Vec<String>, CollectError> {
    let call = Call::EthernetInterfaces(interfaces);
    let collection: WireCollection = read(client, &call).await?;
    let mut addresses = Vec::new();
    for member in collection.whole(&call)? {
        let card = Call::EthernetInterface(linked(Some(member), &call, "path of a member")?);
        let interface: WireEthernetInterface = read(client, &card).await?;
        addresses.extend(text(interface.mac_address));
    }
    Ok(addresses)
}

/// Reads the BMC behind `client`.
pub async fn collect(client: &RedfishClient) -> Result<Bmc, CollectError> {
    let root: WireRoot = read(client, &Call::ServiceRoot).await?;
    let systems: WireCollection = read(client, &Call::Systems).await?;
    // A BMC without system has nothing to say of a server: an error, not an empty answer.
    let system_call = Call::System(linked(systems.whole(&Call::Systems)?.first(), &Call::Systems, "system")?);
    let system: WireSystem = read(client, &system_call).await?;

    let links = system.links.or(system.legacy_links).unwrap_or_default();
    let manager = match links.managed_by.first().and_then(|link| link.path.clone()) {
        Some(path) => {
            let manager: WireManager = read(client, &Call::Manager(path)).await?;
            Some(Manager { model: text(manager.model), firmware_version: text(manager.firmware_version) })
        }
        None => None,
    };

    let correlated: Vec<String> = system
        .host_correlation
        .map(|host| host.mac_addresses.into_iter().filter_map(text).collect())
        .unwrap_or_default();
    let mac_addresses = if correlated.is_empty() {
        match system.ethernet_interfaces.and_then(|link| link.path) {
            Some(interfaces) => interface_addresses(client, interfaces).await?,
            None => Vec::new(),
        }
    } else {
        correlated
    };

    Ok(Bmc {
        redfish_version: text(root.redfish_version),
        system: System {
            manufacturer: text(system.manufacturer),
            model: text(system.model),
            sku: text(system.sku),
            serial_number: text(system.serial_number),
            host_name: text(system.host_name),
            mac_addresses,
        },
        manager,
    })
}
