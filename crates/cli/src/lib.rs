//! The netbox-omnisync command: orchestration of a run and command line.

pub mod check;
pub mod cli;
pub mod collector;
pub mod config;
pub mod digest;
pub mod dns;
pub mod host;
pub mod hypervisors;
pub mod journal;
pub mod network;
pub mod raphinerie;
pub mod select;

/// The fake vCenter of the VMware crate, serving the recorded answers of a
/// real one: the end-to-end tests of the command line read the same fixtures.
#[cfg(test)]
#[path = "../../vmware/tests/common/mod.rs"]
mod vcenter;

/// The fake BMC of the Redfish crate, serving the recorded answers of real
/// ones, and the fake Proxmox VE of its crate: the end-to-end tests of the
/// command line read the same fixtures.
#[cfg(test)]
#[path = "../../redfish/tests/common/mod.rs"]
mod fake_bmc;

#[cfg(test)]
#[path = "../../proxmox/tests/common/mod.rs"]
mod fake_pve;
