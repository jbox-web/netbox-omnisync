//! Proxmox VE source.
//!
//! The reading half: [`ProxmoxClient`] logs in and reads, [`collect()`] returns
//! what a cluster holds as plain data ([`ProxmoxCluster`]). The translating
//! half: [`desired`] turns that data into the NetBox objects the source asks
//! for, without any I/O.

pub mod client;
pub mod collect;
pub mod model;
pub mod neighbors;
pub mod translate;

pub use client::{ClientError, Credentials, ProxmoxClient, ProxmoxClientBuilder};
pub use collect::{CollectError, SUPPORTED_MAJORS, collect};
pub use model::{
    Container, ContainerInterface, Disk, DiskBus, GuestAddress, GuestInterface, GuestNic, GuestNics, GuestOsInfo, Node,
    NodeNetwork, NodeVlan, ProxmoxCluster, ProxmoxVersion, Vm,
};
pub use translate::{NoReverseDns, ReverseDns, Settings, SettingsError, Translation, desired};
