//! Parsers of what the devices print: one module per platform.

pub mod ios;
pub mod nipper;
pub mod nxos;

/// A command output could not be turned into data: the switch is skipped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The output of `command` is not what its parser understands.
    #[error("{command}: {reason}")]
    Command { command: &'static str, reason: String },
    /// The page is not a configuration report.
    #[error("not a Nipper Cisco switch report ({0})")]
    Report(String),
}

impl ParseError {
    pub(crate) fn command(command: &'static str, reason: impl Into<String>) -> Self {
        ParseError::Command { command, reason: reason.into() }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::ParseError;

    pub const NXOS_I2: &str = "nxos_i2";
    pub const NXOS_I4: &str = "nxos_i4";
    pub const IOS: &str = "ios";
    pub const NIPPER: &str = "nipper";

    fn read(directory: &str, file: &str) -> String {
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(directory).join(file);
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    }

    /// Return the recorded output of `command`, named like the probe files.
    pub fn fixture_text(directory: &str, command: &str) -> String {
        let name: String = command.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
        read(directory, &format!("{name}.txt"))
    }

    /// Return the HTML of a recorded Nipper report excerpt, e.g. `fplab1-sw001`.
    pub fn nipper_report(name: &str) -> String {
        read(NIPPER, &format!("{name}.html"))
    }

    /// The first half of `text`: an output cut short.
    pub fn halved(text: &str) -> String {
        text.chars().take(text.chars().count() / 2).collect()
    }

    /// The command and the reason of a failure that names its command.
    pub fn failure<T: std::fmt::Debug>(result: Result<T, ParseError>) -> (&'static str, String) {
        match result.expect_err("a parse failure") {
            ParseError::Command { command, reason } => (command, reason),
            other => panic!("not a command failure: {other}"),
        }
    }
}
