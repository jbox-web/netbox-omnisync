//! Cisco IOS and NX-OS source.

pub mod collect;
pub mod commands;
/// The known hosts file is shared by every SSH source: it lives in `omnisync-ssh`.
pub use omnisync_ssh::known_hosts;
pub mod parsers;
pub mod runner;
pub mod transport;
