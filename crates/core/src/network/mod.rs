//! What is shared by the network sources (switches, routers, firewalls): the
//! normalised view of a device, the NetBox side of it, and the rules that turn
//! one into changes on the other.

pub mod cables;
pub mod collect;
pub mod descriptions;
pub mod diff;
pub mod dot1q;
pub mod hosts;
pub mod inventory;
pub mod model;
pub mod names;
pub mod stack;
pub mod state;
pub mod vlans;
