//! NetBox REST client and readers of the NetBox state.

pub mod apply;
pub mod client;
pub mod inventory_apply;
pub mod inventory_state;
pub mod reporting;
pub mod state;
pub mod testing;
pub mod version;

pub use client::{NetboxClient, NetboxClientBuilder};
pub use reporting::ReportingGateway;
pub use state::StateError;
