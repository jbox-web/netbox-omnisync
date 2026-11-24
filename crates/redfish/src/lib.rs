//! The BMC of a server (Dell iDRAC, HPE iLO), read through Redfish, read-only.
//!
//! A hypervisor does not always know the hardware it runs on: the API of
//! Proxmox VE gives neither the model nor the serial of a node. Its BMC does.
//! This source completes a device NetBox already holds with its manufacturer,
//! its device type and its serial number, and nothing else: it never creates
//! a device, never deletes anything, never touches an interface or an address.
//!
//! [`client`] sends a closed list of `GET` requests, [`mod@collect`] reads one BMC
//! into plain data ([`model`]), and [`translate`] turns it into what the
//! reconciliation takes. `tests/fixtures/README.md` says what was observed on
//! real BMCs, and what never was.

pub mod client;
pub mod collect;
pub mod model;
pub mod translate;

pub use client::{Call, ClientError, Credentials, RedfishClient};
pub use collect::{CollectError, collect};
pub use model::{Bmc, Manager, System};
