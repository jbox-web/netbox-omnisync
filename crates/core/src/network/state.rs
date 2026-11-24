//! The NetBox side of a network device, as plain data.
//!
//! The readers that fill these from the API live next to the NetBox client;
//! the diff functions only see these types.

use std::collections::BTreeMap;

/// A device, virtual chassis or object the run needs is missing from NetBox.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct NotFound(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbInterface {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub description: String,
    pub mtu: Option<u32>,
    pub r#type: Option<String>,
    pub mac: Option<String>,
    pub lag: Option<String>,
    pub mode: Option<String>,
    pub untagged_vlan: Option<u16>,
    /// Sorted.
    pub tagged_vlans: Vec<u16>,
    /// The NetBox id of the untagged VLAN, and the number and the id of each
    /// tagged one: two VLANs may have the same number, at a site and in a
    /// VLAN group, untagged and tagged on one port.
    pub untagged_vlan_id: Option<u64>,
    pub tagged_vlan_ids: Vec<(u16, u64)>,
    pub cable_id: Option<u64>,
    /// (id, address) of every MAC object assigned to the interface, primary included.
    pub macs: Vec<(u64, String)>,
    /// Out-of-band management port (iLO, iDRAC, BMC): where a description-told
    /// management link lands.
    pub mgmt_only: bool,
    /// Name of the parent interface of a virtual one.
    pub parent: Option<String>,
    pub label: String,
}

impl NbInterface {
    /// An enabled interface with nothing else set.
    pub fn new(id: u64, name: &str) -> Self {
        NbInterface {
            id,
            name: name.to_owned(),
            enabled: true,
            description: String::new(),
            mtu: None,
            r#type: None,
            mac: None,
            lag: None,
            mode: None,
            untagged_vlan: None,
            tagged_vlans: Vec::new(),
            untagged_vlan_id: None,
            tagged_vlan_ids: Vec::new(),
            cable_id: None,
            macs: Vec::new(),
            mgmt_only: false,
            parent: None,
            label: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbIp {
    pub id: u64,
    pub address: String,
    pub vrf: Option<String>,
    /// Name of the device, virtual machine or other object that holds the address.
    pub device: Option<String>,
    pub interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct End {
    pub device: String,
    pub interface: String,
}

impl End {
    pub fn new(device: &str, interface: &str) -> Self {
        End { device: device.to_owned(), interface: interface.to_owned() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbCable {
    pub id: u64,
    pub a: End,
    pub b: End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbDevice {
    pub id: u64,
    pub name: String,
    pub site_id: u64,
    /// Name of the site: the VLAN groups of the configuration name their
    /// sites. Empty when NetBox does not give it.
    pub site: String,
    pub serial: String,
    pub primary_ip4: Option<String>,
    /// Keyed by `interface_key(name)`.
    pub interfaces: BTreeMap<String, NbInterface>,
    pub ips: Vec<NbIp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_netbox_interface_is_enabled_and_bare() {
        let interface = NbInterface::new(7, "Ethernet1/1");
        assert_eq!(interface.id, 7);
        assert_eq!(interface.name, "Ethernet1/1");
        assert!(interface.enabled);
        assert_eq!(interface.description, "");
        assert!(interface.tagged_vlans.is_empty());
        assert!(!interface.mgmt_only);
    }

    #[test]
    fn cable_ends_order_by_device_then_interface() {
        let mut ends =
            vec![End::new("sw2", "Ethernet1/1"), End::new("sw1", "Ethernet1/2"), End::new("sw1", "Ethernet1/1")];
        ends.sort();
        assert_eq!(
            ends,
            [End::new("sw1", "Ethernet1/1"), End::new("sw1", "Ethernet1/2"), End::new("sw2", "Ethernet1/1")]
        );
    }

    #[test]
    fn not_found_prints_its_message() {
        assert_eq!(NotFound("device sw1 not found in Netbox".to_owned()).to_string(), "device sw1 not found in Netbox");
    }
}
