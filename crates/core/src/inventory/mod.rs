//! What is shared by the hypervisor sources (Proxmox VE, VMware vSphere): the
//! object graph a source asks for, the identity of each object in NetBox, and
//! the pure reconciliation that turns the two into changes.

pub mod custom_fields;
pub mod dns;
pub mod guard;
pub mod hardware;
pub mod identity;
pub mod model;
pub mod reconcile;
