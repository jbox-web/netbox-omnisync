//! The netbox-omnisync binary: hands the process (arguments, environment,
//! streams, Ctrl-C) to `omnisync_cli::cli::run` and exits with its code.

use std::future::pending;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use omnisync_cli::cli::{self, EXIT_ERROR, Production, Terminal};
use omnisync_core::network::inventory::Environ;

/// The stderr of the process, as a handle the progress can keep a copy of.
#[derive(Debug, Clone, Copy)]
struct ProcessStderr;

impl Write for ProcessStderr {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        io::stderr().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

/// Completes at the first Ctrl-C.
async fn interrupted() {
    // Without a signal handler the run simply cannot be interrupted this way:
    // it must not be taken for an interrupt.
    if tokio::signal::ctrl_c().await.is_err() {
        pending::<()>().await;
    }
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            // A stderr that cannot be written to leaves the exit code to tell.
            let _ = writeln!(io::stderr(), "error: cannot start: {error}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    // A variable that is not Unicode cannot be one the tool reads: left out
    // rather than a reason to stop.
    let environ: Environ = std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let mut terminal = Terminal {
        stdout: io::stdout(),
        stderr: ProcessStderr,
        stdout_is_terminal: io::stdout().is_terminal(),
        stderr_is_terminal: io::stderr().is_terminal(),
    };
    let code = runtime.block_on(cli::run(std::env::args_os(), &environ, &mut terminal, &Production, interrupted()));
    // An interrupted run must not wait for what is still in flight in the
    // background (a name resolution) before the process exits.
    runtime.shutdown_background();
    ExitCode::from(code)
}
