//! The release of the NetBox under test, as the tool reads it.

use std::env;

use omnisync_netbox::version::{Dialect, NetboxVersion};

use crate::support::Netbox;

/// The NetBox of the stack says its release in `/api/status/`, and it is one
/// this build supports: the very release `NETBOX_VERSION` started.
#[tokio::test]
#[ignore = "needs the NetBox Docker stack: mise run dev:test-integration"]
async fn the_release_of_the_netbox_under_test_is_read_and_supported() {
    let netbox = Netbox::empty().await;
    let version = netbox.client.netbox_version().await.expect("the release of NetBox");
    // The image is named `vX.Y.Z` (v4.5.10 by default); NetBox says `X.Y.Z`.
    let image = env::var("NETBOX_VERSION").unwrap_or_else(|_| "v4.5.10".to_owned());
    let started = image.trim_start_matches('v');
    let release = version.split('-').next().unwrap_or_default();
    assert_eq!(release, started, "NetBox says {version}, the stack started {image}");
    assert!(Dialect::of(&version).is_some(), "{version} is not a supported release");
}
