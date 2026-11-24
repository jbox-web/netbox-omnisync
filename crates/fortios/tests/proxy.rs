//! The proxy of the environment, in a test file of its own: it changes the
//! environment of its process, which no other test may be reading meanwhile.

mod common;

use common::Firewall;
use omnisync_fortios::api::STATUS;

#[test]
fn proxy_of_the_environment_is_not_used() {
    // Through a proxy the certificate would not be pinned: the firewall is reached directly.
    // SAFETY: the only test of this process, and no other thread exists yet.
    #[expect(unsafe_code, reason = "the environment of the process can only be set this way")]
    unsafe {
        for variable in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
            std::env::set_var(variable, "http://127.0.0.1:9");
        }
        for variable in ["NO_PROXY", "no_proxy"] {
            std::env::remove_var(variable);
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime");
    runtime.block_on(async {
        let firewall = Firewall::start().await;
        let client = firewall.client(&firewall.fingerprint);
        client.login().await.expect("the firewall is reached directly");
        client.run(STATUS).await.expect("the read is answered");
        assert_eq!(firewall.seen("GET"), ["/api/v2/monitor/system/status"]);
    });
}
