//! Integration tests against a real NetBox, of the release `NETBOX_VERSION`
//! names (`mise run dev:test-integration`; CI runs each supported release).
//!
//! Every test is `#[ignore]`d: `cargo test --workspace` needs no Docker and
//! reports them as ignored; the mise task starts the stack of
//! `docker-compose.yml`, runs them with `--ignored` and destroys the stack.
//!
//! What they prove that the unit tests cannot: that what the tool writes is
//! accepted by NetBox, and read back in a form the tool takes for what it
//! wrote, so that a second run changes nothing.

#[path = "../../../redfish/tests/common/mod.rs"]
mod fake_bmc;
/// The fake vCenter of the VMware crate and the fake BMCs of the Redfish
/// crate, serving the recorded answers of real ones.
#[path = "../../../vmware/tests/common/mod.rs"]
mod fake_vcenter;
mod hypervisors;
mod network;
mod support;
mod version;
