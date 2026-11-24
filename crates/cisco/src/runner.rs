//! What the collection of a switch needs from its transport: run one command,
//! get its output.

use std::future::Future;

pub use omnisync_core::network::collect::CollectionError;

/// Runs the show commands of one switch; implemented by the SSH transport and
/// by the fakes of the tests.
pub trait CommandRunner {
    /// The output of one command, or why the switch could not answer it.
    fn run(&mut self, command: &str) -> impl Future<Output = Result<String, CollectionError>> + Send;
}
