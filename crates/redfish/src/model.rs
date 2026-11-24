//! What a BMC says of the server it manages, as plain data.
//!
//! `None` means "not reported": the BMC left the value out, or answered an
//! empty or blank one. A serial made of sixteen spaces (seen on an iLO 4) is
//! no serial. Nothing here is a NetBox name yet: the vendor is as the BMC
//! writes it, and which of `sku` and `serial_number` is the serial NetBox
//! wants depends on the vendor (see `translate`).

/// One BMC, read whole.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bmc {
    /// The version of Redfish the service speaks (`1.4.0`).
    pub redfish_version: Option<String>,
    /// The first system of the BMC: the server.
    pub system: System,
    /// The BMC itself, when the system links to it.
    pub manager: Option<Manager>,
}

/// The server a BMC manages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct System {
    /// `Manufacturer`, as written (`Dell Inc.`, `HPE`).
    pub manufacturer: Option<String>,
    /// `Model` (`PowerEdge R640`).
    pub model: Option<String>,
    /// `SKU`: the service tag on a Dell, the product reference on an HPE.
    pub sku: Option<String>,
    /// `SerialNumber`: the serial on an HPE, another identifier on a Dell.
    pub serial_number: Option<String>,
    /// `HostName`: what the operating system told the BMC, in full or not.
    pub host_name: Option<String>,
    /// The `MACAddress` of each Ethernet interface the BMC lists for the
    /// system, as written and in the order given. Never the
    /// `PermanentMACAddress`: the address in use is the one NetBox holds. A
    /// BMC does not list every card: enough to recognise the server, not to
    /// inventory it.
    pub mac_addresses: Vec<String>,
}

/// The BMC itself: what tells an iDRAC 7 from an iDRAC 9. Read to be shown,
/// never written to NetBox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manager {
    /// `Model` (`13G Monolithic`); an iLO 4 reports none.
    pub model: Option<String>,
    /// `FirmwareVersion` (`2.86.86.86`, `iLO 4 v2.82`).
    pub firmware_version: Option<String>,
}
