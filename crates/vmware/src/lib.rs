//! VMware vSphere source: a vCenter read through its SOAP API (`vim25`) for
//! the inventory, and through its REST API for the tags. Read-only.
//!
//! The reading half: [`client`] logs in and reads, [`collect`] returns what a
//! vCenter holds as plain data ([`model`]). The translating half:
//! [`translate`] turns that data into the NetBox objects the source asks for,
//! without any I/O.

pub mod client;
pub mod collect;
pub mod model;
pub mod soap;
pub mod translate;
pub mod xml;
