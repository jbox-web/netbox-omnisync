//! Normalised view of what was collected on a network device.

use std::collections::BTreeMap;

/// 802.1Q modes, with their NetBox values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Access,
    Tagged,
    TaggedAll,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Access => "access",
            Mode::Tagged => "tagged",
            Mode::TaggedAll => "tagged-all",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot1q {
    pub mode: Mode,
    pub untagged_vlan: Option<u16>,
    pub tagged_vlans: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub enabled: bool,
    /// None: the source does not report it, left unmanaged; "" clears it.
    pub description: Option<String>,
    /// None: the device does not report it, the field is left unmanaged.
    pub mtu: Option<u32>,
    /// None: the port hardware is not in the type table, the field is left unmanaged.
    pub r#type: Option<String>,
    /// None: the device does not report a MAC for this interface, left unmanaged.
    pub mac: Option<String>,
    pub lag: Option<String>,
    /// False: the source does not tell the LAG membership (a configuration report),
    /// the NetBox LAG of the interface is left as is.
    pub lag_managed: bool,
    /// None with dot1q_managed=true means a routed interface: no 802.1Q mode.
    pub dot1q: Option<Dot1q>,
    pub dot1q_managed: bool,
    /// Operational link state; None: no physical link (SVI). Not synced to NetBox: it
    /// keeps the cable of a link that is down from being pruned.
    pub link_up: Option<bool>,
    /// Interface a virtual one runs over (a VLAN over its aggregate, a tunnel over
    /// its uplink). None: the source does not report it, left unmanaged.
    pub parent: Option<String>,
    /// A second name of the interface (the alias of a firewall port, which is what
    /// it announces to its neighbours). None: the source reports none, left unmanaged.
    pub label: Option<String>,
}

impl Interface {
    /// An interface with every optional value unreported and the default flags.
    pub fn new(name: &str, enabled: bool) -> Self {
        Interface {
            name: name.to_owned(),
            enabled,
            description: None,
            mtu: None,
            r#type: None,
            mac: None,
            lag: None,
            lag_managed: true,
            dot1q: None,
            dot1q_managed: true,
            link_up: None,
            parent: None,
            label: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpAddress {
    /// Address with mask, e.g. "192.0.2.239/24".
    pub address: String,
    pub interface: String,
    /// None: global table.
    pub vrf: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Neighbor {
    pub local_interface: String,
    pub remote_device: String,
    /// None: the neighbour's port ID is not an interface name (a MAC address).
    pub remote_interface: Option<String>,
    pub protocol: String,
}

impl Neighbor {
    /// The device name the neighbour announces, None if it announces none.
    pub fn announced_name(&self) -> Option<&str> {
        let name = self.remote_device.trim();
        if name.is_empty() || name == "not advertised" { None } else { Some(name) }
    }

    /// Neither a name nor a port: the neighbour tells nothing usable.
    pub fn anonymous(&self) -> bool {
        self.announced_name().is_none() && self.remote_interface.is_none()
    }
}

/// Everything collected on one target: a switch over SSH, a firewall over its API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceState {
    pub serial: Option<String>,
    /// Keyed by interface name.
    pub interfaces: BTreeMap<String, Interface>,
    /// VID -> name of the VLANs defined on the device.
    pub vlans: BTreeMap<u16, String>,
    pub ips: Vec<IpAddress>,
    pub neighbors: Vec<Neighbor>,
    /// Stack member number -> serial, IOS only.
    pub member_serials: BTreeMap<u32, String>,
    /// Host name of each HA cluster member -> serial, FortiOS only.
    pub peer_serials: BTreeMap<String, String>,
    /// False: the names in `vlans` are not VLAN names (the interface names of a
    /// firewall); they only name a VLAN that no switch defines, at its creation.
    pub vlan_names_managed: bool,
    /// False: the source does not tell the IP addresses (a configuration report),
    /// `ips` is empty and the NetBox IPs and primary IP are left as they are.
    pub ips_managed: bool,
}

impl Default for DeviceState {
    fn default() -> Self {
        DeviceState {
            serial: None,
            interfaces: BTreeMap::new(),
            vlans: BTreeMap::new(),
            ips: Vec::new(),
            neighbors: Vec::new(),
            member_serials: BTreeMap::new(),
            peer_serials: BTreeMap::new(),
            vlan_names_managed: true,
            ips_managed: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neighbor(device: &str, interface: Option<&str>) -> Neighbor {
        Neighbor {
            local_interface: "Ethernet1/1".to_owned(),
            remote_device: device.to_owned(),
            remote_interface: interface.map(str::to_owned),
            protocol: "lldp".to_owned(),
        }
    }

    #[test]
    fn modes_carry_their_netbox_values() {
        assert_eq!(Mode::Access.as_str(), "access");
        assert_eq!(Mode::Tagged.as_str(), "tagged");
        assert_eq!(Mode::TaggedAll.as_str(), "tagged-all");
    }

    #[test]
    fn a_neighbour_announces_its_trimmed_name() {
        assert_eq!(neighbor(" nexus02.lab01 ", None).announced_name(), Some("nexus02.lab01"));
    }

    #[test]
    fn an_empty_or_unadvertised_name_is_no_name() {
        assert_eq!(neighbor("", None).announced_name(), None);
        assert_eq!(neighbor("not advertised", None).announced_name(), None);
    }

    #[test]
    fn a_neighbour_is_anonymous_only_without_name_and_without_port() {
        assert!(neighbor("not advertised", None).anonymous());
        assert!(!neighbor("not advertised", Some("Ethernet1/2")).anonymous());
        assert!(!neighbor("nexus02.lab01", None).anonymous());
    }

    #[test]
    fn a_new_interface_reports_nothing_and_manages_lag_and_dot1q() {
        let interface = Interface::new("Ethernet1/1", true);
        assert_eq!(interface.description, None);
        assert_eq!(interface.mtu, None);
        assert!(interface.lag_managed);
        assert!(interface.dot1q_managed);
        assert_eq!(interface.link_up, None);
    }

    #[test]
    fn a_default_device_state_manages_vlan_names_and_ips() {
        let state = DeviceState::default();
        assert!(state.vlan_names_managed);
        assert!(state.ips_managed);
        assert!(state.interfaces.is_empty());
    }
}
