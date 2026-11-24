//! The proxy of the environment, in a test file of its own: it changes the
//! environment of its process, which no other test may be reading meanwhile.

mod common;

use common::{client, vcenter};
use omnisync_vmware::collect::collect;

#[test]
fn proxy_of_the_environment_is_not_used() {
    // Through a proxy of the environment the account would leave for another
    // host, and with validate_certs = false nothing would check that host.
    // SAFETY: the only test of this process, and no other thread exists yet.
    #[expect(unsafe_code, reason = "the environment of the process can only be set this way")]
    unsafe {
        for variable in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
            std::env::set_var(variable, "http://127.0.0.1:9");
        }
        for variable in ["NO_PROXY", "no_proxy"] {
            std::env::remove_var(variable);
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime");
    runtime.block_on(async {
        let server = vcenter("6.7").await;
        collect(&client(&server)).await.expect("the vCenter is reached directly");
    });
}
