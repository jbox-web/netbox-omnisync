//! The completion scripts, run by the shells against the real binary.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_netbox-omnisync");

/// A folder holding the script `completions <shell>` printed.
struct Bench {
    directory: tempfile::TempDir,
}

impl Bench {
    fn new(shell: &str) -> Self {
        let bench = Bench { directory: tempfile::tempdir().unwrap() };
        let script = Command::new(BIN).args(["completions", shell]).output().unwrap();
        assert!(script.status.success(), "{}", String::from_utf8_lossy(&script.stderr));
        assert!(script.stderr.is_empty(), "{}", String::from_utf8_lossy(&script.stderr));
        std::fs::write(bench.script(), script.stdout).unwrap();
        bench
    }

    fn script(&self) -> PathBuf {
        self.directory.path().join("script")
    }
}

fn has(program: &str) -> bool {
    Command::new(program).arg("-c").arg("true").status().is_ok_and(|status| status.success())
}

/// What the function bash registered for the binary offers for `words`, the
/// last one being the word under the cursor, sorted.
fn bash_complete(bench: &Bench, words: &[&str]) -> Vec<String> {
    let quoted: Vec<String> = words.iter().map(|word| format!("'{word}'")).collect();
    let code = format!(
        "source '{}'\nCOMP_WORDS=(netbox-omnisync {})\nCOMP_CWORD={}\nCOMP_LINE=\"${{COMP_WORDS[*]}}\"\n\
         complete=\"$(complete -p netbox-omnisync)\"\nfunction=\"${{complete#*-F }}\"\n\
         \"${{function%% *}}\" netbox-omnisync \"${{COMP_WORDS[COMP_CWORD]}}\" \"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\
         printf '%s\\n' \"${{COMPREPLY[@]}}\"",
        bench.script().display(),
        quoted.join(" "),
        words.len()
    );
    let out = Command::new("bash").args(["--norc", "--noprofile", "-c", &code]).output().unwrap();
    assert!(out.status.success(), "bash: {}", String::from_utf8_lossy(&out.stderr));
    let mut offered: Vec<String> =
        String::from_utf8(out.stdout).unwrap().lines().filter(|line| !line.is_empty()).map(str::to_owned).collect();
    offered.sort();
    offered
}

#[test]
fn bash_offers_the_commands() {
    let bench = Bench::new("bash");
    // The commands, and the two flags that work without one.
    assert_eq!(
        bash_complete(&bench, &[""]),
        ["--help", "--version", "-V", "-h", "check", "completions", "digest", "help", "licenses", "sync", "version"]
    );
    assert_eq!(bash_complete(&bench, &["li"]), ["licenses"]);
    // Not in the help, not in the completion either.
    assert_eq!(bash_complete(&bench, &["--r"]), Vec::<String>::new());
    for shell in ["bash", "zsh"] {
        let script = std::fs::read_to_string(Bench::new(shell).script()).unwrap();
        assert!(!script.to_lowercase().contains("raphinerie"), "{shell} tells the hidden flag");
    }
}

#[test]
fn bash_offers_the_options_of_a_sync_and_the_values_of_its_filters() {
    let bench = Bench::new("bash");
    assert_eq!(bash_complete(&bench, &["sync", "--d"]), ["--dry-run"]);
    assert_eq!(bash_complete(&bench, &["sync", "--p"]), ["--prune"]);
    // Not on the one screen of the help, and offered all the same: it is an option of a sync.
    assert_eq!(bash_complete(&bench, &["sync", "--r"]), ["--runner"]);
    assert_eq!(bash_complete(&bench, &["sync", "--kind", ""]), ["bmc", "firewall", "hypervisor", "router", "switch"]);
    assert_eq!(bash_complete(&bench, &["sync", "-k", "s"]), ["switch"]);
    assert_eq!(bash_complete(&bench, &["sync", "--type", "n"]), ["nipper", "nxos"]);
    assert_eq!(bash_complete(&bench, &["completions", "b"]), ["bash"]);
    assert_eq!(bash_complete(&bench, &["completions", "z"]), ["zsh"]);
}

#[test]
fn bash_offers_the_options_of_a_check_and_of_a_digest() {
    let bench = Bench::new("bash");
    assert_eq!(bash_complete(&bench, &["check", "--"]), ["--help", "--ignore-warning", "--journal", "--max-age"]);
    assert_eq!(bash_complete(&bench, &["digest", "--s"]), ["--sendmail", "--since"]);
    assert_eq!(bash_complete(&bench, &["digest", "--t"]), ["--to"]);
}

#[test]
fn bash_offers_files_for_the_configuration() {
    let bench = Bench::new("bash");
    let prefix = format!("{}/scr", bench.directory.path().display());
    let script = [bench.script().display().to_string()];
    assert_eq!(bash_complete(&bench, &["sync", "--config", &prefix]), script);
    assert_eq!(bash_complete(&bench, &["digest", "--config", &prefix]), script);
    assert_eq!(bash_complete(&bench, &["check", "--journal", &prefix]), script);
}

#[test]
fn the_scripts_are_valid_shell_and_name_the_binary() {
    for shell in ["bash", "zsh"] {
        if !has(shell) {
            eprintln!("{shell} is not installed: its script is not checked");
            continue;
        }
        let bench = Bench::new(shell);
        let out = Command::new(shell).arg("-n").arg(bench.script()).output().unwrap();
        assert!(out.status.success(), "{shell}: {}", String::from_utf8_lossy(&out.stderr));
    }
    // zsh loads a completion by its first line.
    let script = std::fs::read_to_string(Bench::new("zsh").script()).unwrap();
    assert_eq!(script.lines().next(), Some("#compdef netbox-omnisync"));
    for value in ["hypervisor", "fortios", "--dry-run", "licenses"] {
        assert!(script.contains(value), "{value} is not in the zsh script");
    }
}

#[test]
fn a_shell_that_is_not_supported_is_a_usage_error() {
    let out = Command::new(BIN).args(["completions", "fish"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("error: invalid value 'fish'"));
}
