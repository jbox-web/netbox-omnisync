//! What a collection returns: plain data, with no handle on the API.
//!
//! Two rules shape these types. Sizes keep the unit Proxmox gives them (bytes),
//! so nothing is rounded before the caller decides how to. And what could not
//! be read is `None`, never an empty list: the caller keeps what NetBox has
//! for an unknown, and deletes for an empty.

/// The status of a guest that can be asked about itself.
pub(crate) const RUNNING: &str = "running";

/// A Proxmox VE cluster, or a standalone node, as read by one collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxCluster {
    /// The version the API announced: the collection was read with its rules.
    pub version: ProxmoxVersion,
    /// Empty on a standalone node, which has no cluster: the caller then names
    /// the cluster after the source.
    pub name: String,
    /// Sorted by name.
    pub nodes: Vec<Node>,
    /// The nodes Proxmox says are offline, by name: not read, so their guests
    /// are not reported, and the source cannot say any of them is gone.
    pub offline: Vec<String>,
}

/// The answer of `GET /version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxVersion {
    /// The full version, e.g. `8.4.21`.
    pub version: String,
    /// The release, e.g. `8.4`; empty when the API does not give it.
    pub release: String,
}

impl ProxmoxVersion {
    /// The major version (`8` for `8.4.21`), which selects the rules of the
    /// collection; `None` when the version does not start with a number.
    pub fn major(&self) -> Option<u32> {
        let digits = self.version.find(|character: char| !character.is_ascii_digit()).unwrap_or(self.version.len());
        self.version[..digits].parse().ok()
    }
}

/// A node of the cluster, with everything read from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    /// Logical CPUs (`cpuinfo.cpus`).
    pub cpus: u64,
    /// Total memory, in bytes.
    pub memory_total_bytes: u64,
    /// Sorted by name.
    pub networks: Vec<NodeNetwork>,
    /// Sorted by VMID.
    pub vms: Vec<Vm>,
    /// Sorted by VMID.
    pub containers: Vec<Container>,
}

/// A network interface of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeNetwork {
    pub name: String,
    /// The Proxmox type as given: `eth`, `bond`, `bridge`, `vlan`, `OVSBond`,
    /// `OVSBridge`, `OVSIntPort`, `alias`… The mapping to a NetBox type is the caller's.
    pub kind: String,
    /// Proxmox leaves `active` out for an interface that is down.
    pub active: bool,
    /// The interfaces a bond aggregates, in the order Proxmox lists them;
    /// empty for anything that is not a bond.
    pub bond_members: Vec<String>,
    /// The VLAN of a sub-interface (`bond2.25`, type `vlan`); `None` for
    /// anything else, and for one whose VLAN id Proxmox does not give.
    pub vlan: Option<NodeVlan>,
}

/// The VLAN a sub-interface of a node carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeVlan {
    /// `vlan-id`.
    pub id: u16,
    /// `vlan-raw-device`: the interface the VLAN is carried on.
    pub raw_device: Option<String>,
}

/// A QEMU virtual machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vm {
    pub vmid: u64,
    pub name: String,
    /// `running`, `stopped`… as Proxmox gives it.
    pub status: String,
    pub template: bool,
    pub cpus: u64,
    /// Configured memory, in bytes.
    pub max_memory_bytes: u64,
    /// In the order Proxmox lists them.
    pub tags: Vec<String>,
    /// The `ostype` of the configuration (`l26`, `win11`…), when set.
    pub os_type: Option<String>,
    /// Sorted by bus (virtio, scsi, sata, ide) then by index.
    pub disks: Vec<Disk>,
    /// The network cards of the configuration (`netN`), which say the VLAN
    /// of each: known whether the VM runs or not.
    pub nics: GuestNics,
    /// What the guest agent reports, the loopback `lo` left out. `None` when
    /// unknown: the VM is not running, or its agent did not answer. A known
    /// VM without interface is `Some` of an empty list.
    pub interfaces: Option<Vec<GuestInterface>>,
    /// What the guest agent says of the system. `None` when unknown, as for
    /// the interfaces.
    pub os_info: Option<GuestOsInfo>,
}

impl Vm {
    /// Only a running VM has a guest agent to ask.
    pub fn is_running(&self) -> bool {
        self.status == RUNNING
    }
}

/// The bus a disk is attached to; ordered as the disks are listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiskBus {
    Virtio,
    Scsi,
    Sata,
    Ide,
}

/// A drive of a VM that has a size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub bus: DiskBus,
    /// The number after the bus in the configuration key: `1` for `scsi1`.
    pub index: u32,
    /// The volume, first token of the configuration value: `local-lvm:vm-101-disk-0`.
    pub name: String,
    /// Whole mebibytes, rounded down.
    pub size_mib: u64,
    /// The drive is declared `media=cdrom`: an ISO image or a cloud-init
    /// drive, which Proxmox gives a size too. Whether it counts as a virtual
    /// disk is the caller's decision.
    pub cdrom: bool,
}

/// A network card of a guest as its configuration declares it: one `netN`
/// line (`virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=10` for a VM,
/// `name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,tag=10` for a container).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestNic {
    /// The key of the line: `net0`.
    pub key: String,
    /// In upper case: the agent and the configuration do not write it alike.
    pub mac: String,
    pub bridge: Option<String>,
    /// `tag=`: the VLAN the bridge puts the card in.
    pub tag: Option<u16>,
    /// `trunks=`: the VLANs the card carries tagged, as inclusive ranges in
    /// the order written (`10;20-22` is `[(10, 10), (20, 22)]`). Empty
    /// without the option.
    pub trunks: Vec<(u16, u16)>,
}

/// The network cards of the configuration of a guest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestNics {
    /// Sorted by the number of their key.
    pub read: Vec<GuestNic>,
    /// The keys of the lines that could not be read, sorted likewise: what
    /// they say of a VLAN is unknown, never "no VLAN".
    pub unread: Vec<String>,
}

/// A network interface seen from inside a VM by the guest agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestInterface {
    pub name: String,
    /// As the agent writes it; `None` when it gives none.
    pub mac: Option<String>,
    /// In the order of the agent: the caller picks a primary address by position.
    pub addresses: Vec<GuestAddress>,
}

/// An address of a guest interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAddress {
    pub address: String,
    /// `ipv4` or `ipv6`, as the agent says.
    pub family: String,
    pub prefix: u8,
}

/// The system a guest agent reports. An agent may answer with nothing: every
/// field is then `None`, which still tells the agent is there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestOsInfo {
    pub id: Option<String>,
    pub name: Option<String>,
    pub pretty_name: Option<String>,
    pub version: Option<String>,
    pub version_id: Option<String>,
    pub kernel_release: Option<String>,
    pub machine: Option<String>,
}

/// An LXC container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub vmid: u64,
    pub name: String,
    pub status: String,
    pub cpus: u64,
    /// In bytes.
    pub max_memory_bytes: u64,
    /// Size of the root disk, in bytes.
    pub max_disk_bytes: u64,
    pub tags: Vec<String>,
    /// `None` when unknown: the container is not running, or the call failed.
    pub interfaces: Option<Vec<ContainerInterface>>,
    /// The network cards of the configuration (`netN`). `None` when unknown:
    /// the container is not running (it has no interface to put a VLAN on),
    /// or its configuration could not be read.
    pub nics: Option<GuestNics>,
}

impl Container {
    /// Only a running container has interfaces to read.
    pub fn is_running(&self) -> bool {
        self.status == RUNNING
    }
}

/// A network interface of a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInterface {
    pub name: String,
    pub mac: Option<String>,
    /// IPv4 address with its prefix length (`192.0.2.10/24`).
    pub inet: Option<String>,
    /// IPv6 address with its prefix length.
    pub inet6: Option<String>,
}
