//! The command line: arguments, the lock of a run, and the wiring of a run from
//! the configuration to the exit code.
//!
//! The tool writes to NetBox unless `--dry-run` is given. Everything is behind
//! [`run`], which takes the arguments, the environment and the two streams
//! instead of reading the process: the tests need neither a process nor a
//! network.

use std::ffi::OsString;
use std::fmt::Display;
use std::fs::{self, File, TryLockError};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::time::{Duration, Instant};

use clap::builder::StyledStr;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use jiff::{SignedDuration, ZonedDateTime};
use omnisync_core::network::inventory::Environ;
use omnisync_core::progress::{BarProgress, LogProgress, NullProgress, Progress};
use omnisync_core::report::{render, render_quiet, use_colour};
use omnisync_core::{Gateway, GatewayError, Outcome};
use omnisync_netbox::NetboxClient;
use omnisync_netbox::inventory_apply::DryRun;
use omnisync_netbox::version::{Admitted, NetboxVersion, admit};

use crate::check::{self, MaxAge, State};
use crate::collector::{CollectorError, NetworkCollector};
use crate::config::{self, Config, Hypervisor, Netbox};
use crate::digest::{self, Page};
use crate::host;
use crate::hypervisors::{self, Apis, NodeAccess, Reader};
use crate::journal;
use crate::network::{self, Collector, Options};
use crate::raphinerie;
use crate::select::{self, Candidate, Filter, Host, SourceKind, SourceType};
use omnisync_ssh::known_hosts::KnownHosts;

/// Nothing to do, or everything written.
pub const EXIT_OK: u8 = 0;
/// An error: the configuration, a source, NetBox, or another run in progress.
pub const EXIT_ERROR: u8 = 1;
/// Changes found by a dry run.
pub const EXIT_CHANGES: u8 = 2;
/// Interrupted by Ctrl-C: what a shell reports for SIGINT (128 + 2).
pub const EXIT_INTERRUPTED: u8 = 130;

/// The lock file of a run, in the temporary directory.
pub const LOCK_NAME: &str = "netbox-omnisync.lock";

/// What an interrupted run says, as the Python tool did.
pub const INTERRUPTED: &str = "interrupted; writes already made stay in Netbox, the next run starts from there";

/// What `--raphinerie` says: raw sources in, a clean inventory out.
pub const RAPHINERIE: &str = "raphinerie de données brutes depuis 1974";

/// The plant itself: four chimneys over the river, and what floats between them.
const PLANT: &str = r"                         ,--.
                        ( oo)~
                         `--'
     ||     ||                         ||     ||
     ||     ||                         ||     ||
     ||     ||                         ||     ||
     ||     ||                         ||     ||
    _||_   _||_                       _||_   _||_
   |    |_|    |_____________________|    |_|    |
   | || | | || | ||  ||  ||  ||  ||  | || | | || |
   | || | | || | ||  ||  ||  ||  ||  | || | | || |
   | || |_| || |_||__||__||__||__||__| || |_| || |
   |____|_|____|_____________________|____|_|____|
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~";

/// The colours of the help: headings in bold, what is typed in cyan as in the
/// progress bar, what is replaced in plain cyan.
const STYLES: Styles = Styles::styled()
    .header(AnsiColor::White.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::White.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

/// The first commands to try, and the exit codes, the 2 of a dry run being
/// the one that surprises: the end of every help.
fn examples() -> String {
    let (heading, command) = (STYLES.get_header(), STYLES.get_literal());
    let examples = [
        ("netbox-omnisync sync --dry-run", "What would change, every source"),
        ("netbox-omnisync sync -n -k hypervisor", "The same, hypervisors only"),
        ("netbox-omnisync sync -n -k switch -k router", "A filter given twice widens"),
        ("netbox-omnisync sync -s pve01.lab01", "Sync one source"),
    ];
    let codes = [
        ("0", "Nothing to do, or everything written"),
        ("1", "An error: command line, configuration, a source, NetBox"),
        ("2", "--dry-run found changes"),
        ("130", "Interrupted by Ctrl-C: what was written stays"),
    ];
    let mut text = format!("{heading}Examples:{heading:#}\n");
    for (example, meaning) in examples {
        text.push_str(&format!("  {command}{example:<45}{command:#}{meaning}\n"));
    }
    text.push_str(&format!("\n{heading}Exit codes:{heading:#}\n"));
    for (code, meaning) in codes {
        text.push_str(&format!("  {command}{code:>3}{command:#}  {meaning}\n"));
    }
    text
}

/// The help of the tool, shown when no command is given: what it is, its
/// commands, the options of a sync by what they are for, then how to start.
/// One screen says it all: `check` and `digest`, which read the journal of
/// the syncs, tell their options in their own help.
fn tool_help() -> StyledStr {
    let (heading, command) = (STYLES.get_header(), STYLES.get_literal());
    let commands = [
        ("sync", "Sync the sources into NetBox"),
        ("check", "Tell Icinga the state of each source, from the journal"),
        ("digest", "Mail what the runs of a period changed, from the journal"),
        ("version", "Show the version"),
        ("licenses", "Show the licences of the tool and of what it embeds"),
        ("completions", "Print the completion script of bash or zsh"),
        ("help", "Show this help"),
    ];
    // The two lines that say what the tool is stick to the usage: a 80×24
    // terminal must show the options of a sync without scrolling.
    let mut text = String::from(
        "{name} {version} \u{2014} {about}\n\
         Writes to NetBox unless --dry-run is given: start with a dry run.\n\
         {usage-heading} {usage}\n\n",
    );
    text.push_str(&format!("{heading}Commands:{heading:#}\n"));
    for (name, meaning) in commands {
        text.push_str(&format!("  {command}{name:<13}{command:#}{meaning}\n"));
    }
    // The options of a sync, as its own help lists them, but `--help` (this
    // is the help, and the `help` command is listed above) and `--runner`,
    // which no everyday run takes: a 80×24 terminal has no line left for it.
    let sync = <Args as clap::Args>::augment_args(clap::Command::new("sync"))
        .mut_arg("help", |help| help.hide(true))
        .mut_arg("runner", |runner| runner.hide(true))
        .styles(STYLES)
        .disable_help_flag(true)
        .help_template("{all-args}")
        .render_help();
    text.push_str(&format!("\n{}\n{}", sync.ansi(), examples()));
    StyledStr::from(text)
}

/// The command line: a command, and nothing is done without one.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "netbox-omnisync",
    version,
    about = "sync hypervisors and network devices into NetBox",
    long_about = None,
    override_usage = "netbox-omnisync <COMMAND>",
    help_template = tool_help(),
    styles = STYLES
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Not in the help: what the tool does, in one word of the house.
    #[arg(long, hide = true)]
    pub raphinerie: bool,
}

/// What the tool is asked to do. `help` is clap's own command.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Sync the sources into NetBox
    #[command(
        disable_help_flag = true,
        help_template = "{usage-heading} {usage}\n\n{all-args}{after-help}",
        after_help = StyledStr::from(examples())
    )]
    Sync(Args),

    /// Tell Icinga the state of each source, from the journal
    #[command(after_help = CHECK)]
    Check(CheckArgs),

    /// Mail what the runs of a period changed, from the journal
    #[command(after_help = DIGEST)]
    Digest(DigestArgs),

    /// Show the version
    Version,

    /// Show the licences of the tool and of what it embeds
    Licenses,

    /// Print the completion script of bash or zsh
    #[command(after_help = COMPLETIONS)]
    Completions {
        #[arg(value_enum, value_name = "SHELL")]
        shell: Shell,
    },
}

/// How Icinga calls `check`, and what its codes say, in its help.
const CHECK: &str = "\
Every source of the configuration must have succeeded within the maximum age
of its kind: those of the host of the journal alone, when the configuration
says which host runs each source (runner). A warning of the last run of a
source is a WARNING, unless --ignore-warning matches it.

Example:
  netbox-omnisync check --journal ~/.local/state/netbox-omnisync/journal.jsonl \\
    --max-age hypervisor=15m --max-age bmc=26h --max-age switch=26h \\
    --max-age router=26h --max-age firewall=26h

Exit codes (Nagios):
  0  OK        Every source succeeded recently
  1  WARNING   The last run of a source failed, its last success is recent
  2  CRITICAL  A source has no success within its maximum age
  3  UNKNOWN   The journal cannot be read, a kind has no --max-age, a usage error";

/// What `digest` sends, in its help.
const DIGEST: &str = "\
Nothing is printed nor sent when the period has no change and no error. A run
is in the period it ended in. 24h is 24 hours: on the days the clock changes,
a daily cron line on local time leaves out, or mails twice, an hour of runs.

Example:
  netbox-omnisync digest --since 24h --to noc@example.net";

/// The options of `check`.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct CheckArgs {
    /// The journal of the runs
    #[arg(long, value_name = "FILE", required = true)]
    pub journal: PathBuf,

    /// The oldest the last success of a kind may be (15m, 26h, 2d); repeatable
    #[arg(long = "max-age", value_name = "KIND=DURATION", value_parser = check::parse_max_age, required = true)]
    pub max_age: Vec<MaxAge>,

    /// A warning a run says by design, left out of the state; repeatable
    #[arg(long = "ignore-warning", value_name = "REGEX", value_parser = check::parse_ignored)]
    pub ignore_warning: Vec<check::Ignored>,
}

/// The options of `digest`.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct DigestArgs {
    /// Configuration file: the journal and the URL of NetBox
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    pub config: PathBuf,

    /// The period: the runs that ended within it (24h, 7d)
    #[arg(long, value_name = "DURATION", value_parser = check::parse_duration, required = true)]
    pub since: SignedDuration,

    /// Send the mail to this address; repeatable. Without it, print the message
    #[arg(long, value_name = "ADDRESS", value_parser = address)]
    pub to: Vec<String>,

    /// What the mail is handed to, as `sendmail -t -oi`
    #[arg(long, value_name = "PATH", default_value = "/usr/sbin/sendmail")]
    pub sendmail: PathBuf,
}

/// An address of `--to`: it goes into the `To` header, which a line break
/// would end and a comma would split.
fn address(text: &str) -> Result<String, String> {
    if text.is_empty() || text.contains(',') || text.chars().any(char::is_control) {
        return Err("an address, without a comma nor a line break".to_owned());
    }
    Ok(text.to_owned())
}

/// Where the script goes, said by the help of `completions`.
const COMPLETIONS: &str = "\
Install:
  netbox-omnisync completions zsh > \"${fpath[1]}/_netbox-omnisync\"
  netbox-omnisync completions bash > \\
    ~/.local/share/bash-completion/completions/netbox-omnisync";

/// The shells a completion script is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
}

/// The completion script of `shell`: the commands, the options of each, the
/// values of the filters and the files of `--config`, all from the command
/// line as it is defined here.
pub fn completions(shell: Shell) -> Vec<u8> {
    let generator = match shell {
        Shell::Bash => clap_complete::Shell::Bash,
        Shell::Zsh => clap_complete::Shell::Zsh,
    };
    // The commands alone, without the flag the help does not tell either:
    // the generators list a hidden option like any other.
    let mut command = Command::augment_subcommands(clap::Command::new(NAME).version(env!("CARGO_PKG_VERSION")));
    let mut script = Vec::new();
    clap_complete::generate(generator, &mut command, NAME, &mut script);
    // The bash generator names the function of a command of `netbox-omnisync`
    // in one way where it looks it up and in another where it defines it, so
    // that nothing is offered after a command: one name for both.
    let script = String::from_utf8_lossy(&script).replace("netbox__subcmd__omnisync", "netbox__omnisync");
    script.into_bytes()
}

/// The name of the binary, as the completion scripts register it.
const NAME: &str = "netbox-omnisync";

/// The third-party notices `cargo about` generated, embedded by a release
/// build; empty in any other build (see `build.rs`).
const NOTICES: &str = include_str!(concat!(env!("OUT_DIR"), "/notices.txt"));

/// What `licenses` prints: the licence of the tool, both texts in full since
/// the binary travels without the repository, then the `notices` of the
/// third-party code it embeds, or that this build embeds none.
pub fn licenses(version: &str, notices: &str) -> String {
    let rule = "=".repeat(80);
    let mut text = format!("netbox-omnisync {version}, licensed under MIT OR Apache-2.0, at your option.\n");
    for (name, licence) in [
        ("MIT License", include_str!("../../../LICENSE-MIT")),
        ("Apache License 2.0", include_str!("../../../LICENSE-APACHE")),
    ] {
        text.push_str(&format!("\n{rule}\nnetbox-omnisync: {name}\n{rule}\n\n{}\n", licence.trim_end()));
    }
    text.push_str(&format!("\n{rule}\n\n"));
    if notices.trim().is_empty() {
        text.push_str(
            "The third-party notices are not embedded in this build: a release carries them (THIRD-PARTY-NOTICES.txt).\n",
        );
    } else {
        text.push_str(notices);
    }
    text
}

/// The options of a sync. They show in the help in the order and under the
/// headings they have here.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct Args {
    /// Only hypervisor, bmc, switch, router, firewall
    #[arg(short, long, value_enum, value_name = "KIND", hide_possible_values = true, help_heading = "Sync sources")]
    pub kind: Vec<SourceKind>,

    /// Only vmware, proxmox, redfish, ios, nxos, nipper, fortios
    #[arg(
        short,
        long = "type",
        value_enum,
        value_name = "TYPE",
        hide_possible_values = true,
        help_heading = "Sync sources"
    )]
    pub r#type: Vec<SourceType>,

    /// Only the source of this name
    #[arg(short, long, value_name = "NAME", help_heading = "Sync sources")]
    pub source: Vec<String>,

    /// With --dry-run: as this host of runners, not as this machine
    #[arg(long, value_name = "HOST", help_heading = "Sync sources")]
    pub runner: Option<String>,

    /// Report what would change, write nothing
    #[arg(short = 'n', long, help_heading = "Sync options")]
    pub dry_run: bool,

    /// Also delete what a network source no longer has
    #[arg(long, help_heading = "Sync options")]
    pub prune: bool,

    /// Print nothing when there is nothing to report
    #[arg(short, long, help_heading = "Sync options")]
    pub quiet: bool,

    /// Configuration file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml", help_heading = "Sync options")]
    pub config: PathBuf,

    /// Show this help
    #[arg(short, long, action = ArgAction::Help, help_heading = "Sync options")]
    help: Option<bool>,
}

impl Args {
    /// The selection the arguments ask for.
    pub fn filter(&self) -> Filter {
        Filter { kinds: self.kind.clone(), types: self.r#type.clone(), names: self.source.clone() }
    }
}

/// The two streams of the process, and whether each is a terminal.
///
/// The report goes to `stdout`, alone; the progress and the errors go to
/// `stderr`, which the progress keeps a handle of.
pub struct Terminal<O, E> {
    pub stdout: O,
    pub stderr: E,
    pub stdout_is_terminal: bool,
    pub stderr_is_terminal: bool,
}

/// What a run talks to: NetBox, and the devices read over the network.
///
/// The real tool uses [`Production`]; the tests hand in fakes, so that the
/// whole wiring runs without a network.
pub trait Backend {
    type Gateway: Gateway + DryRun + NetboxVersion;
    type Collector: Collector;
    type Reader: Reader;

    /// The NetBox client of the run; in a dry run it must refuse every write.
    fn gateway(&self, netbox: &Netbox, dry_run: bool) -> Result<Self::Gateway, GatewayError>;

    /// What reads the network sources that are not read from a report file.
    fn collector(&self, environ: &Environ) -> Result<Self::Collector, CollectorError>;

    /// What reads the hypervisor sources.
    fn reader(&self, environ: &Environ) -> Self::Reader;

    /// The time and the time zone of the host: when a run starts, what
    /// `check` and `digest` measure the journal against.
    fn now(&self) -> ZonedDateTime {
        ZonedDateTime::now()
    }

    /// The name of the host, which the digest says it was sent from.
    fn hostname(&self) -> String {
        host::hostname()
    }

    /// The full name of the host (`hostname -f`), by which a run knows its
    /// sources in a file that says which host launches each; why the system
    /// gives none otherwise. Only asked for such a file.
    fn fqdn(&self) -> Result<String, String> {
        host::full_name()
    }

    /// Hand `message` to `<sendmail> -t -oi`; the message of the failure otherwise.
    fn send_mail(&self, sendmail: &Path, message: &[u8]) -> Result<(), String> {
        digest::send(sendmail, message)
    }
}

/// The real NetBox and the real devices.
#[derive(Debug, Clone, Copy, Default)]
pub struct Production;

impl Backend for Production {
    type Gateway = NetboxClient;
    type Collector = NetworkCollector;
    type Reader = Apis;

    fn gateway(&self, netbox: &Netbox, dry_run: bool) -> Result<NetboxClient, GatewayError> {
        // A run is refused before it gets here without its token; a client
        // is never built with an empty one all the same.
        let token = netbox.token.held().map_err(|missing| GatewayError::Request(missing.to_string()))?;
        let mut builder =
            NetboxClient::builder(&netbox.url, token.expose()).dry_run(dry_run).validate_certs(netbox.validate_certs);
        if let Some(timeout) = netbox.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(ca_file) = &netbox.ca_file {
            builder = builder.ca_file(ca_file);
        }
        builder.build()
    }

    fn collector(&self, environ: &Environ) -> Result<NetworkCollector, CollectorError> {
        NetworkCollector::from_environ(environ)
    }

    fn reader(&self, environ: &Environ) -> Apis {
        // The nodes of a Proxmox are logged into as the switches are: the
        // same known hosts file, the same agent.
        let nodes = NetworkCollector::from_environ(environ).ok().map(|collector| NodeAccess {
            known_hosts: KnownHosts::new(collector.known_hosts().to_owned()),
            agent_socket: collector.agent_socket().map(Path::to_owned),
            timeout: collector.timeout(),
        });
        Apis::with_nodes(nodes)
    }
}

/// The exit code of a finished run: an error wins, then changes left unwritten
/// by a dry run.
pub fn exit_code(outcome: &Outcome, dry_run: bool) -> u8 {
    if !outcome.errors.is_empty() {
        EXIT_ERROR
    } else if dry_run && !outcome.changes.is_empty() {
        EXIT_CHANGES
    } else {
        EXIT_OK
    }
}

/// Colours on a terminal only, and never when `NO_COLOR` is set and not empty.
pub fn colour(environ: &Environ, is_terminal: bool) -> bool {
    use_colour(environ.get("NO_COLOR").is_some_and(|value| !value.is_empty()), is_terminal)
}

/// The lock file of a run: in the state directory of the user, as the known
/// hosts, `$XDG_STATE_HOME/netbox-omnisync`, `~/.local/state/netbox-omnisync`
/// without it. Not in `TMPDIR`: a cron job and an interactive shell have
/// different ones, and would not exclude each other; nor in `/tmp`, where
/// another user could take its place.
pub fn lock_file(environ: &Environ) -> Result<PathBuf, String> {
    Ok(state_directory(environ, "the lock file")?.join(LOCK_NAME))
}

/// The state directory of the tool for the user: `$XDG_STATE_HOME/netbox-omnisync`,
/// `~/.local/state/netbox-omnisync` without it. `what` names what is looked for
/// in the refusal.
fn state_directory(environ: &Environ, what: &str) -> Result<PathBuf, String> {
    let set = |name: &str| environ.get(name).filter(|value| !value.is_empty());
    let state = match (set("XDG_STATE_HOME"), set("HOME")) {
        (Some(state), _) => PathBuf::from(state),
        (None, Some(home)) => Path::new(home).join(".local").join("state"),
        (None, None) => return Err(format!("cannot locate {what}: set HOME or XDG_STATE_HOME")),
    };
    Ok(state.join("netbox-omnisync"))
}

/// The journal of the runs: the one the configuration names (`journal`), or
/// `journal.jsonl` next to the lock file, in the same private directory.
pub fn journal_file(config: &Config, environ: &Environ) -> Result<PathBuf, String> {
    match &config.journal {
        Some(path) => Ok(path.clone()),
        None => Ok(state_directory(environ, "the journal")?.join(journal::NAME)),
    }
}

/// How the progress of a run is shown.
pub enum Shown<E: Write + Send> {
    /// A live bar, drawn on the terminal.
    Bar(BarProgress),
    /// One timestamped line per step, for cron and pipes.
    Lines(LogProgress<E>),
    /// Nothing: a quiet run off a terminal tells its report alone.
    Silent(NullProgress),
}

impl<E: Write + Send> Shown<E> {
    pub fn progress(&self) -> &dyn Progress {
        match self {
            Shown::Bar(bar) => bar,
            Shown::Lines(lines) => lines,
            Shown::Silent(silent) => silent,
        }
    }
}

/// A live bar on a terminal; one line per step on `stream` otherwise, and
/// nothing when the run is quiet: cron mails whatever a job writes.
pub fn make_progress<E: Write + Send>(stream: E, is_terminal: bool, quiet: bool) -> Shown<E> {
    if is_terminal {
        // The bar draws on the terminal itself, which `stream` is a handle of.
        Shown::Bar(BarProgress::new())
    } else if quiet {
        Shown::Silent(NullProgress)
    } else {
        Shown::Lines(LogProgress::new(stream))
    }
}

/// Print an error on stderr; the exit code of an error.
fn fail(stderr: &mut impl Write, message: impl Display) -> u8 {
    // A stderr that cannot be written to leaves the exit code to tell.
    let _ = writeln!(stderr, "error: {message}");
    EXIT_ERROR
}

/// ` (PID 4242, started …)` from the lock file, or nothing if it cannot be read.
fn holder(path: &Path) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return String::new();
    };
    match text.split_whitespace().collect::<Vec<_>>().as_slice() {
        [pid, started] => format!(" (PID {pid}, started {started})"),
        _ => String::new(),
    }
}

/// Take the lock of a run, held until the returned file is dropped; the
/// message of the refusal otherwise.
///
/// One run at a time: two runs overlapping would both create the same objects.
fn take_lock(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    let shown = path.display();
    // A private directory, created for the user alone: nobody else can put a
    // file or a link in the place of the lock.
    let directory = path.parent().unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|error| format!("cannot create the directory of the lock file {}: {error}", directory.display()))?;
    let metadata = fs::metadata(directory).map_err(|error| format!("cannot open the lock file {shown}: {error}"))?;
    if metadata.permissions().mode() & 0o022 != 0 {
        // SAFETY: geteuid has no precondition and cannot fail.
        #[expect(unsafe_code, reason = "the effective user is only known to libc")]
        let user = unsafe { libc::geteuid() };
        // Only a directory of the user is made private again: one of somebody
        // else may already hold what they put there.
        if metadata.uid() != user {
            return Err(format!(
                "the directory of the lock file {} belongs to another user and is writable by others",
                directory.display()
            ));
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!("cannot make the directory of the lock file {} private: {error}", directory.display())
        })?;
    }
    // Never through a link: the lock is truncated below.
    let mut lock = File::options()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open the lock file {shown}: {error}"))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(format!("another run{} holds {shown}", holder(path))),
        Err(TryLockError::Error(error)) => return Err(format!("cannot lock {shown}: {error}")),
    }
    // Who holds the lock, for the refusal message of a concurrent run. The lock
    // is held whether or not this can be written: the refusal then names nobody.
    let started = ZonedDateTime::now().datetime().strftime("%Y-%m-%dT%H:%M:%S");
    let _ =
        lock.set_len(0).and_then(|()| writeln!(lock, "{} {started}", std::process::id())).and_then(|()| lock.flush());
    Ok(lock)
}

/// Add what a second part of the run produced to the outcome of the first.
fn merge(outcome: &mut Outcome, other: Outcome) {
    outcome.changes.extend(other.changes);
    outcome.warnings.extend(other.warnings);
    outcome.errors.extend(other.errors);
    outcome.applied += other.applied;
}

/// The hypervisors and the BMC sources among the selected sources, in the order of the file.
fn selected_hypervisors<'c>(config: &'c Config, selected: &[&Candidate]) -> Vec<&'c Hypervisor> {
    let chosen = |source: &&Hypervisor| {
        selected.iter().any(|candidate| candidate.kind.is_inventory() && candidate.name == source.name)
    };
    config.hypervisors.iter().filter(chosen).collect()
}

/// The host the run is among those of the file (`runners`): the full name of
/// the machine, or the one `--runner` names for a dry run; None for a file
/// one host runs, which asks the system for no name. Whether the file lists
/// that host is the selection's to say.
///
/// A run that writes is always the one of its machine: its journal then only
/// ever names one host, the one whose sources `check` judges.
fn runner<B: Backend>(args: &Args, config: &Config, backend: &B) -> Result<Option<String>, String> {
    if args.runner.is_some() && !args.dry_run {
        return Err("--runner is only taken with --dry-run: a run that writes is the one of its machine".to_owned());
    }
    match (&args.runner, config.runners.is_empty()) {
        (Some(_), true) => Err("--runner names a host of runners, and the configuration lists none: one host runs \
                                every source"
            .to_owned()),
        (None, true) => Ok(None),
        (Some(name), false) => Ok(Some(name.clone())),
        (None, false) => match backend.fqdn() {
            Ok(name) => Ok(Some(name)),
            Err(error) => Err(format!("cannot tell which host of runners this one is: {error}")),
        },
    }
}

/// One run, the lock held: from the configuration to the exit code.
async fn execute<B, O, E>(args: &Args, environ: &Environ, terminal: &mut Terminal<O, E>, backend: &B) -> u8
where
    B: Backend,
    O: Write,
    E: Write + Send + Clone,
{
    // Everything that can be refused without contacting anything is, first.
    let config = match config::load(&args.config, environ) {
        Ok(config) => config,
        Err(error) => return fail(&mut terminal.stderr, error),
    };
    let candidates = select::candidates(&config.inventory, &config.hypervisors, &config.runners);
    // A file several hosts share says which one launches each source: the run
    // is the one of its host, and the filters choose among its sources.
    let runner = match runner(args, &config, backend) {
        Ok(runner) => runner,
        Err(refusal) => return fail(&mut terminal.stderr, refusal),
    };
    let host = runner.as_deref().map(|name| Host { name, runners: config.runners.hosts() });
    let selected = match select::select(&args.filter(), &candidates, host.as_ref()) {
        Ok(selected) => selected,
        Err(error) => return fail(&mut terminal.stderr, error),
    };
    // The file is the same on every host, the secrets are not: a run needs
    // the ones of the sources it selected, and no other. All of them are
    // asked for at once, before NetBox or any source is contacted.
    // What the cards of the hosts hear is only read by a run that reads switches too.
    let neighbours = !select::network_names(&selected).is_empty();
    if let Err(error) = config.require(|name| selected.iter().any(|candidate| candidate.name == name), neighbours) {
        return fail(&mut terminal.stderr, error);
    }
    // From here on NetBox is contacted: whatever ends the run is journaled,
    // a refusal of NetBox included, so that the monitoring sees it. A dry run
    // writes nothing anywhere.
    let journal = if args.dry_run {
        None
    } else {
        match journal_file(&config, environ) {
            Ok(path) => Some(path),
            Err(refusal) => return fail(&mut terminal.stderr, refusal),
        }
    };
    let started_at = backend.now();
    let started = Instant::now();
    let (outcome, code) = match sync_sources(args, environ, &config, &selected, terminal, backend).await {
        Ok(mut outcome) => {
            outcome.seconds = Some(started.elapsed().as_secs_f64());
            let code = report(args, environ, terminal, &outcome);
            (outcome, code)
        }
        Err(refusal) => {
            let code = fail(&mut terminal.stderr, &refusal);
            let seconds = Some(started.elapsed().as_secs_f64());
            (Outcome { errors: vec![refusal], seconds, ..Outcome::default() }, code)
        }
    };
    if let Some(path) = journal {
        let entry = journal::Entry {
            version: journal::VERSION,
            started: journal::stamp(&started_at),
            seconds: outcome.seconds.unwrap_or_default(),
            runner,
            configured: candidates
                .iter()
                .map(|candidate| journal::Configured {
                    name: candidate.name.clone(),
                    kind: candidate.kind.as_str().to_owned(),
                    runner: candidate.runner.clone(),
                })
                .collect(),
            selected: selected.iter().map(|candidate| candidate.name.clone()).collect(),
            changes: outcome.changes,
            applied: outcome.applied,
            warnings: outcome.warnings,
            errors: outcome.errors,
        };
        // The writes are made: a run whose journal is lost must not look like
        // a success, nor a sound source to the monitoring.
        if let Err(error) = journal::append(&path, &entry, backend.now().timestamp()) {
            return fail(&mut terminal.stderr, error);
        }
    }
    code
}

/// Print the report of a finished run; the exit code of the run.
fn report<O: Write, E: Write>(args: &Args, environ: &Environ, terminal: &mut Terminal<O, E>, outcome: &Outcome) -> u8 {
    let colour = colour(environ, terminal.stdout_is_terminal);
    let report = if args.quiet { render_quiet(outcome, colour) } else { Some(render(outcome, colour)) };
    if let Some(report) = report
        && let Err(error) = writeln!(terminal.stdout, "{report}").and_then(|()| terminal.stdout.flush())
    {
        // The writes are made: a report lost must at least not look like a success.
        return fail(&mut terminal.stderr, format!("cannot write the report: {error}"));
    }
    exit_code(outcome, args.dry_run)
}

/// The selected sources run against NetBox: the outcome of the run, or why
/// NetBox (or what reads the devices) refused it before any source was read.
async fn sync_sources<B, O, E>(
    args: &Args,
    environ: &Environ,
    config: &Config,
    selected: &[&Candidate],
    terminal: &Terminal<O, E>,
    backend: &B,
) -> Result<Outcome, String>
where
    B: Backend,
    E: Write + Send + Clone,
{
    let hypervisors = selected_hypervisors(config, selected);
    let network = select::network_names(selected);
    let gateway = backend.gateway(&config.netbox, args.dry_run).map_err(|error| error.to_string())?;
    // A release of NetBox this build was not tested with may take what is
    // written in another shape, or ignore it: it is refused before any source
    // is read, unless the file says to warn.
    let untested = match gateway.netbox_version().await {
        Err(error) => return Err(format!("cannot read the release of NetBox: {error}")),
        Ok(version) => match admit(&version, config.netbox.unsupported_version) {
            Err(refusal) => return Err(refusal.to_string()),
            Ok(Admitted::Supported(_)) => None,
            Ok(Admitted::Unsupported(warning)) => Some(warning),
        },
    };
    // Every write is checked against the schema of NetBox, which NetBox builds
    // when asked, slowly once it has just started: read now, with a bound of
    // its own, a failure stops the run before anything is read or written.
    if let Err(error) = gateway.load_schema().await {
        return Err(format!("cannot read the schema of NetBox: {error}"));
    }
    // No network source selected: no network run at all. An empty selection
    // handed to it would mean every source.
    let collector =
        if network.is_empty() { None } else { Some(backend.collector(environ).map_err(|error| error.to_string())?) };

    // stderr only: stdout keeps the report alone.
    let shown = make_progress(terminal.stderr.clone(), terminal.stderr_is_terminal, args.quiet);
    // The hypervisors first: the network sources then find their hosts in NetBox.
    let reader = backend.reader(environ);
    let priority = &config.netbox.source_priority;
    let groups = &config.vlan_groups;
    // What the cards of the hosts hear is only asked when switches are read:
    // it is told to their cable step, and to nothing else.
    let scope = hypervisors::Scope { vlan_groups: groups, neighbours: collector.is_some() };
    let (mut outcome, heard) = hypervisors::run_hearing(
        &config.hypervisors,
        &hypervisors,
        priority,
        &scope,
        &gateway,
        &reader,
        shown.progress(),
    )
    .await;
    if let Some(collector) = &collector {
        let options = Options {
            apply: !args.dry_run,
            prune: args.prune,
            only: network,
            vlan_groups: config.vlan_groups.clone(),
            heard,
        };
        let synced = network::run(&config.inventory, &gateway, collector, &options, shown.progress()).await;
        merge(&mut outcome, synced);
    }
    // First among the warnings: it bears on every change of the report.
    if let Some(warning) = untested {
        outcome.warnings.insert(0, warning);
    }
    Ok(outcome)
}

/// What the arguments could not be parsed into: the help or the version asked
/// for (stdout, code 0), or a usage error (stderr, code 1).
///
/// A usage error is an error like any other: it must not exit with 2, the
/// code a dry run gives when it finds changes.
fn usage<O: Write, E: Write>(error: &clap::Error, environ: &Environ, terminal: &mut Terminal<O, E>) -> u8 {
    let text = error.render();
    if error.use_stderr() {
        let _ = write!(terminal.stderr, "{text}");
        EXIT_ERROR
    } else {
        // The help has its colours on a terminal that takes them, like the report.
        let written = if colour(environ, terminal.stdout_is_terminal) {
            write!(terminal.stdout, "{}", text.ansi())
        } else {
            write!(terminal.stdout, "{text}")
        };
        let _ = written.and_then(|()| terminal.stdout.flush());
        EXIT_OK
    }
}

/// A usage error of clap in one line: its first paragraph, without `error: `.
fn usage_line(error: &clap::Error) -> String {
    let text = error.render().to_string();
    let first = text.split("\n\n").next().unwrap_or_default();
    let words: Vec<&str> = first.split_whitespace().collect();
    words.join(" ").trim_start_matches("error: ").to_owned()
}

/// Print what a check says; its exit code.
fn report_check<O: Write, E: Write>(terminal: &mut Terminal<O, E>, verdict: &check::Verdict) -> u8 {
    match write!(terminal.stdout, "{}", verdict.text).and_then(|()| terminal.stdout.flush()) {
        Ok(()) => verdict.state.code(),
        // What Icinga cannot read, it cannot take for OK either.
        Err(_) => State::Unknown.code(),
    }
}

/// `check`: the state of each source in the journal, at the time of the host.
fn run_check<B: Backend, O: Write, E: Write>(args: &CheckArgs, terminal: &mut Terminal<O, E>, backend: &B) -> u8 {
    let verdict = match journal::read(&args.journal) {
        Ok(entries) => check::evaluate(&entries, &args.max_age, &args.ignore_warning, backend.now().timestamp()),
        Err(error) => check::unknown(&format!("cannot read the journal {}: {error}", args.journal.display())),
    };
    report_check(terminal, &verdict)
}

/// `digest`: the mail of the runs of the period, printed or handed to sendmail.
///
/// The configuration is loaded as a run loads it, but no secret is asked
/// for: it only gives the journal and the URL of NetBox.
fn run_digest<B: Backend, O: Write, E: Write>(
    args: &DigestArgs,
    environ: &Environ,
    terminal: &mut Terminal<O, E>,
    backend: &B,
) -> u8 {
    let config = match config::load(&args.config, environ) {
        Ok(config) => config,
        Err(error) => return fail(&mut terminal.stderr, error),
    };
    let path = match journal_file(&config, environ) {
        Ok(path) => path,
        Err(refusal) => return fail(&mut terminal.stderr, refusal),
    };
    let entries = match journal::read(&path) {
        Ok(entries) => entries,
        Err(error) => {
            return fail(&mut terminal.stderr, format!("cannot read the journal {}: {error}", path.display()));
        }
    };
    let now = backend.now();
    let digest = digest::collect(&entries, args.since, now.timestamp());
    // Nothing to tell: no mail, and nothing for cron to mail either.
    if digest.is_empty() {
        return EXIT_OK;
    }
    let hostname = backend.hostname();
    let page = Page {
        time_zone: now.time_zone(),
        netbox_url: &config.netbox.url,
        version: env!("CARGO_PKG_VERSION"),
        hostname: &hostname,
    };
    let message = digest::message(&args.to, &digest.subject(), &digest.text(now.time_zone()), &digest.html(&page));
    if args.to.is_empty() {
        return match write!(terminal.stdout, "{message}").and_then(|()| terminal.stdout.flush()) {
            Ok(()) => EXIT_OK,
            Err(error) => fail(&mut terminal.stderr, format!("cannot write the message: {error}")),
        };
    }
    match backend.send_mail(&args.sendmail, message.as_bytes()) {
        Ok(()) => EXIT_OK,
        Err(refusal) => fail(&mut terminal.stderr, refusal),
    }
}

/// Run the tool: parse `argv` (the program name first), take the lock, run the
/// selected sources and print the report; the exit code of the process.
///
/// `interrupt` completes when the run must stop (Ctrl-C): the run is dropped
/// where it is, nothing more is written, and the code is 130.
pub async fn run<B, O, E>(
    argv: impl IntoIterator<Item = OsString>,
    environ: &Environ,
    terminal: &mut Terminal<O, E>,
    backend: &B,
    interrupt: impl Future<Output = ()>,
) -> u8
where
    B: Backend,
    O: Write,
    E: Write + Send + Clone,
{
    let argv: Vec<OsString> = argv.into_iter().collect();
    let cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        // Icinga reads stdout and the code: a check it was given wrong is
        // UNKNOWN, in the form of its line.
        Err(error) if error.use_stderr() && argv.get(1).is_some_and(|command| command == "check") => {
            return report_check(terminal, &check::unknown(&usage_line(&error)));
        }
        Err(error) => return usage(&error, environ, terminal),
    };
    // Says its line and nothing else: no configuration, no lock, no source.
    if cli.raphinerie {
        // On a terminal that takes colours and is large enough, the animation;
        // elsewhere, the drawing in plain text.
        let size = colour(environ, terminal.stdout_is_terminal).then(|| console::Term::stdout().size());
        match size.and_then(|(rows, columns)| raphinerie::fit(usize::from(columns), usize::from(rows))) {
            Some((columns, rows)) => {
                let delay = Duration::from_secs(1) / raphinerie::FRAME_RATE;
                tokio::select! {
                    () = raphinerie::play(&mut terminal.stdout, columns, rows, raphinerie::FRAMES, delay) => {}
                    // Ctrl-C: the cursor was hidden, and is owed back.
                    () = interrupt => raphinerie::show_cursor(&mut terminal.stdout),
                }
            }
            None => {
                let _ = writeln!(terminal.stdout, "{PLANT}");
            }
        }
        let line = format!("netbox-omnisync {} — {RAPHINERIE}", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(terminal.stdout, "{line}").and_then(|()| terminal.stdout.flush());
        return EXIT_OK;
    }
    let args = match cli.command {
        Some(Command::Sync(args)) => args,
        // Neither takes the lock: the journal is replaced in one rename, and
        // a run that holds the lock for long must not keep them waiting.
        Some(Command::Check(args)) => return run_check(&args, terminal, backend),
        Some(Command::Digest(args)) => return run_digest(&args, environ, terminal, backend),
        Some(Command::Version) => {
            let line = format!("netbox-omnisync {}", env!("CARGO_PKG_VERSION"));
            let _ = writeln!(terminal.stdout, "{line}").and_then(|()| terminal.stdout.flush());
            return EXIT_OK;
        }
        Some(Command::Completions { shell }) => {
            let _ = terminal.stdout.write_all(&completions(shell)).and_then(|()| terminal.stdout.flush());
            return EXIT_OK;
        }
        Some(Command::Licenses) => {
            let text = licenses(env!("CARGO_PKG_VERSION"), NOTICES);
            // A reader that stops early (`| head`) is no error.
            let _ = write!(terminal.stdout, "{text}").and_then(|()| terminal.stdout.flush());
            return EXIT_OK;
        }
        // Nothing is done without a command: the help, as the error it is for
        // a caller that forgot `sync`.
        None => {
            let help = Cli::command().render_help();
            let _ = if colour(environ, terminal.stderr_is_terminal) {
                write!(terminal.stderr, "{}", help.ansi())
            } else {
                write!(terminal.stderr, "{help}")
            };
            return EXIT_ERROR;
        }
    };
    let path = match lock_file(environ) {
        Ok(path) => path,
        Err(refusal) => return fail(&mut terminal.stderr, refusal),
    };
    let _lock = match take_lock(&path) {
        Ok(lock) => lock,
        Err(refusal) => return fail(&mut terminal.stderr, refusal),
    };
    let mut stderr = terminal.stderr.clone();
    let finished = {
        let work = pin!(execute(&args, environ, terminal, backend));
        tokio::select! {
            code = work => Some(code),
            () = interrupt => None,
        }
        // The run is dropped here, with its collections, its NetBox request in
        // flight and its progress: nothing more is written.
    };
    // Ctrl-C: a message rather than a run cut without a word, and the code of
    // a shell for SIGINT.
    finished.unwrap_or_else(|| {
        let _ = writeln!(stderr, "error: {INTERRUPTED}");
        EXIT_INTERRUPTED
    })
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use omnisync_core::inventory::model::{Desired, Identity, Kind, VrfKey};
    use omnisync_core::network::collect::CollectionError;
    use omnisync_core::network::inventory::{Secret, Source, Wanted};
    use omnisync_core::network::model::DeviceState;
    use omnisync_core::{Action, Change, Filters, Row};
    use omnisync_netbox::testing::FakeGateway;
    use omnisync_netbox::version::UnsupportedVersion;
    use regex::Regex;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::sync::Notify;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    use super::*;
    use crate::config::HypervisorType;
    use crate::dns::ReverseLookups;
    use crate::dns::testing::{FakeDns, Reply};
    use crate::hypervisors::Reading;
    use crate::network::CommandLog;
    use crate::vcenter;

    const CONFIG: &str = "[netbox]\nurl = \"https://netbox.example\"\n\n[ssh]\nusername = \"sync\"\nauth = \"agent\"\n\n\
                          [[sources]]\nname = \"nexus01.lab01\"\nkind = \"switch\"\nhost = \"192.0.2.239\"\ntype = \"nxos\"\n";
    const FIREWALL: &str = "\n[[sources]]\nname = \"fw01.lab01\"\nkind = \"firewall\"\nhost = \"192.0.2.1\"\n\
                            type = \"fortios\"\ntls_fingerprint = \"abababababababababababababababababababababababababababababababab\"\n";
    const HYPERVISOR: &str =
        "\n[[sources]]\nname = \"pve01.lab01\"\nkind = \"hypervisor\"\nhost = \"192.0.2.10\"\ntype = \"proxmox\"\n";
    const FIREWALL_ENV: [(&str, &str); 2] =
        [("FIREWALL_FW01_LAB01_USERNAME", "readonly"), ("FIREWALL_FW01_LAB01_PASSWORD", "pw-forti")];
    const HYPERVISOR_ENV: [(&str, &str); 1] = [("PVE01_LAB01_TOKEN", "pve-secret")];
    const NOT_IMPLEMENTED: &str = "pve01.lab01: proxmox sources are not implemented in this build";

    /// A stream the test reads back, shared with the progress of the run.
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A stdout that cannot be written to: a closed pipe.
    struct Closed;

    impl Write for Closed {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The fake NetBox of a test, handed to the run and kept by the test.
    struct Handle(Arc<FakeGateway>, bool);

    impl DryRun for Handle {
        fn dry_run(&self) -> bool {
            self.1
        }
    }

    impl NetboxVersion for Handle {
        async fn netbox_version(&self) -> Result<String, GatewayError> {
            self.0.netbox_version().await
        }

        async fn load_schema(&self) -> Result<(), GatewayError> {
            self.0.load_schema().await
        }
    }

    /// Answers for the hypervisors: what the test scripted, or the refusal of
    /// a build that cannot read them.
    struct Scripted(Option<Reading>, Vec<(String, Reading)>);

    impl Reader for Scripted {
        async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
            if let Some((_, reading)) = self.1.iter().find(|(name, _)| *name == source.name) {
                return Ok(reading.clone());
            }
            self.0.clone().ok_or(format!("{} sources are not implemented in this build", source.r#type.as_str()))
        }
    }

    /// A Proxmox cluster named pve-lab, as pve01.lab01 reports it.
    fn pve_lab() -> Reading {
        let source = "pve01.lab01";
        let kind = Desired::new(Kind::ClusterType, Identity::named("Proxmox"), source)
            .field("name", "Proxmox")
            .create_only("slug", "proxmox");
        let cluster = Desired::new(Kind::Cluster, Identity::named("pve-lab"), source)
            .field("name", "pve-lab")
            .reference("type", Kind::ClusterType, Identity::named("Proxmox"));
        Reading { objects: vec![kind, cluster], ..Reading::default() }
    }

    impl Gateway for Handle {
        async fn list(&self, endpoint: &str, filters: &Filters) -> Result<Vec<Row>, GatewayError> {
            self.0.list(endpoint, filters).await
        }

        async fn check_write(
            &self,
            write: omnisync_core::Write,
            endpoint: &str,
            fields: &[String],
        ) -> Result<(), GatewayError> {
            self.0.check_write(write, endpoint, fields).await
        }

        async fn create(&self, endpoint: &str, payload: &Row) -> Result<Row, GatewayError> {
            self.0.create(endpoint, payload).await
        }

        async fn update(&self, endpoint: &str, id: u64, payload: &Row) -> Result<(), GatewayError> {
            self.0.update(endpoint, id, payload).await
        }

        async fn delete(&self, endpoint: &str, id: u64) -> Result<(), GatewayError> {
            self.0.delete(endpoint, id).await
        }
    }

    /// Answers for the devices: a Nexus whose serial is SN1, anything else unreachable.
    struct Probe {
        asked: Arc<Mutex<Vec<String>>>,
        stuck: Option<Arc<Notify>>,
    }

    impl Collector for Probe {
        async fn collect(&self, source: &Source, _commands: &CommandLog<'_>) -> Result<DeviceState, CollectionError> {
            self.asked.lock().unwrap().push(source.name.clone());
            if let Some(stuck) = &self.stuck {
                stuck.notify_one();
                pending::<()>().await;
            }
            if source.r#type == "nxos" {
                Ok(DeviceState { serial: Some("SN1".to_owned()), ..DeviceState::default() })
            } else {
                Err(CollectionError("unreachable".to_owned()))
            }
        }
    }

    /// A NetBox holding nexus01.lab01, and devices that answer without a network.
    struct Lab {
        netbox: Arc<FakeGateway>,
        device: u64,
        /// The sources a collection was asked for, in order.
        asked: Arc<Mutex<Vec<String>>>,
        /// The mode each NetBox client was asked in.
        dry_runs: Mutex<Vec<bool>>,
        /// The lock file, read when the NetBox client is built: during the run.
        lock: Option<PathBuf>,
        lock_seen: Mutex<Vec<String>>,
        /// Set: the collection signals it started, then never ends.
        stuck: Option<Arc<Notify>>,
        /// What the hypervisor sources report; None when they cannot be read.
        hypervisor: Option<Reading>,
        /// What the hypervisor sources named here report, each its own.
        readings: Vec<(String, Reading)>,
        /// The mails a digest sent: the sendmail it named, and the message.
        mails: Mutex<Vec<(PathBuf, String)>>,
        /// Set: sendmail fails with this message.
        mail_refusal: Option<String>,
        /// What the system says the full name of the host is; None: asking for it fails the test.
        full_name: Option<Result<String, String>>,
    }

    /// The clock of a lab: 2026-11-20T08:00:00+01:00.
    fn lab_now() -> ZonedDateTime {
        let moment: jiff::Timestamp = "2026-11-20T07:00:00Z".parse().unwrap();
        moment.to_zoned_datetime(jiff::tz::TimeZone::fixed(jiff::tz::offset(1)))
    }

    impl Lab {
        /// NetBox records `serial` for nexus01.lab01; the device answers SN1.
        fn new(serial: &str) -> Self {
            let netbox = FakeGateway::new();
            let device = netbox.add("dcim.devices", json!({"name": "nexus01.lab01", "site": 12, "serial": serial}));
            Lab {
                netbox: Arc::new(netbox),
                device,
                asked: Arc::default(),
                dry_runs: Mutex::default(),
                lock: None,
                lock_seen: Mutex::default(),
                stuck: None,
                hypervisor: None,
                readings: Vec::new(),
                mails: Mutex::default(),
                mail_refusal: None,
                full_name: None,
            }
        }

        /// The same lab, on the host the system names `full_name`.
        fn on(mut self, full_name: &str) -> Self {
            self.full_name = Some(Ok(full_name.to_owned()));
            self
        }

        fn serial(&self) -> String {
            self.netbox.row("dcim.devices", self.device).unwrap()["serial"].as_str().unwrap().to_owned()
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }

        fn dry_runs(&self) -> Vec<bool> {
            self.dry_runs.lock().unwrap().clone()
        }
    }

    impl Backend for Lab {
        type Gateway = Handle;
        type Collector = Probe;
        type Reader = Scripted;

        fn gateway(&self, _netbox: &Netbox, dry_run: bool) -> Result<Handle, GatewayError> {
            self.dry_runs.lock().unwrap().push(dry_run);
            if let Some(lock) = &self.lock {
                self.lock_seen.lock().unwrap().push(fs::read_to_string(lock).unwrap());
            }
            Ok(Handle(Arc::clone(&self.netbox), dry_run))
        }

        fn collector(&self, _environ: &Environ) -> Result<Probe, CollectorError> {
            Ok(Probe { asked: Arc::clone(&self.asked), stuck: self.stuck.clone() })
        }

        fn reader(&self, _environ: &Environ) -> Scripted {
            Scripted(self.hypervisor.clone(), self.readings.clone())
        }

        fn now(&self) -> ZonedDateTime {
            lab_now()
        }

        fn hostname(&self) -> String {
            "sync01.lab01".to_owned()
        }

        fn fqdn(&self) -> Result<String, String> {
            self.full_name.clone().expect("the name of the host must not be asked for")
        }

        fn send_mail(&self, sendmail: &Path, message: &[u8]) -> Result<(), String> {
            self.mails.lock().unwrap().push((sendmail.to_owned(), String::from_utf8(message.to_vec()).unwrap()));
            self.mail_refusal.clone().map_or(Ok(()), Err)
        }
    }

    /// Nothing may be contacted: asking for NetBox or for a device fails the test.
    struct Untouchable;

    impl Backend for Untouchable {
        type Gateway = Handle;
        type Collector = Probe;
        type Reader = Scripted;

        fn gateway(&self, _netbox: &Netbox, _dry_run: bool) -> Result<Handle, GatewayError> {
            panic!("nothing must be contacted")
        }

        fn collector(&self, _environ: &Environ) -> Result<Probe, CollectorError> {
            panic!("nothing must be contacted")
        }

        fn reader(&self, _environ: &Environ) -> Scripted {
            panic!("nothing must be contacted")
        }

        fn fqdn(&self) -> Result<String, String> {
            panic!("the name of the host must not be asked for")
        }
    }

    /// Nothing may be contacted either, on a host whose system says this of its full name.
    struct UntouchableOn(Result<&'static str, &'static str>);

    impl Backend for UntouchableOn {
        type Gateway = Handle;
        type Collector = Probe;
        type Reader = Scripted;

        fn gateway(&self, _netbox: &Netbox, _dry_run: bool) -> Result<Handle, GatewayError> {
            panic!("nothing must be contacted")
        }

        fn collector(&self, _environ: &Environ) -> Result<Probe, CollectorError> {
            panic!("nothing must be contacted")
        }

        fn reader(&self, _environ: &Environ) -> Scripted {
            panic!("nothing must be contacted")
        }

        fn fqdn(&self) -> Result<String, String> {
            self.0.map(str::to_owned).map_err(str::to_owned)
        }
    }

    struct Ran {
        code: u8,
        stdout: String,
        stderr: String,
    }

    /// A configuration file and a temporary directory holding the lock of the run.
    struct Bench {
        directory: TempDir,
        config: PathBuf,
        environ: Vec<(String, String)>,
        stdout_is_terminal: bool,
        stderr_is_terminal: bool,
    }

    impl Bench {
        fn new(config: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.toml");
            fs::write(&path, config).unwrap();
            let home = directory.path().to_str().unwrap().to_owned();
            let environ = vec![("NETBOX_TOKEN".to_owned(), "token-value".to_owned()), ("HOME".to_owned(), home)];
            Bench { directory, config: path, environ, stdout_is_terminal: false, stderr_is_terminal: false }
        }

        fn with(mut self, pairs: &[(&str, &str)]) -> Self {
            self.environ.retain(|(name, _)| !pairs.iter().any(|(other, _)| other == name));
            self.environ.extend(pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())));
            self
        }

        fn without(mut self, name: &str) -> Self {
            self.environ.retain(|(other, _)| other != name);
            self
        }

        /// The lock of a run of this bench, in its private state directory.
        fn lock(&self) -> PathBuf {
            let directory = self.directory.path().join(".local/state/netbox-omnisync");
            fs::DirBuilder::new().recursive(true).mode(0o700).create(&directory).unwrap();
            directory.join("netbox-omnisync.lock")
        }

        /// The default journal of a run of this bench, next to its lock.
        fn journal(&self) -> PathBuf {
            self.directory.path().join(".local/state/netbox-omnisync/journal.jsonl")
        }

        /// The entries of the default journal, as JSON, without their duration
        /// (which is the time the test took), after checking it is one.
        fn journaled(&self) -> Vec<serde_json::Value> {
            let text = fs::read_to_string(self.journal()).unwrap();
            text.lines()
                .map(|line| {
                    let mut entry: serde_json::Value = serde_json::from_str(line).unwrap();
                    let seconds = entry.as_object_mut().unwrap().remove("seconds").unwrap();
                    assert!(seconds.as_f64().is_some_and(|seconds| (0.0..60.0).contains(&seconds)), "{seconds}");
                    entry
                })
                .collect()
        }

        fn argv(&self, args: &[&str]) -> Vec<OsString> {
            let config = self.config.to_str().unwrap();
            ["netbox-omnisync", "sync", "--config", config].iter().chain(args).map(OsString::from).collect()
        }

        /// The tool with `args` alone: no `sync`, no configuration given.
        async fn run_raw<B: Backend>(&self, backend: &B, args: &[&str]) -> Ran {
            let (stdout, stderr) = (Buffer::default(), Buffer::default());
            let mut terminal = Terminal {
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                stdout_is_terminal: self.stdout_is_terminal,
                stderr_is_terminal: self.stderr_is_terminal,
            };
            let argv = ["netbox-omnisync"].iter().chain(args).map(OsString::from);
            let code = run(argv, &self.environ(), &mut terminal, backend, pending()).await;
            Ran { code, stdout: stdout.text(), stderr: stderr.text() }
        }

        fn environ(&self) -> Environ {
            self.environ.iter().cloned().collect()
        }

        async fn run<B: Backend>(&self, backend: &B, args: &[&str]) -> Ran {
            self.run_until(backend, args, pending()).await
        }

        async fn run_until<B: Backend>(&self, backend: &B, args: &[&str], interrupt: impl Future<Output = ()>) -> Ran {
            let (stdout, stderr) = (Buffer::default(), Buffer::default());
            let mut terminal = Terminal {
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                stdout_is_terminal: self.stdout_is_terminal,
                stderr_is_terminal: self.stderr_is_terminal,
            };
            let code = run(self.argv(args), &self.environ(), &mut terminal, backend, interrupt).await;
            Ran { code, stdout: stdout.text(), stderr: stderr.text() }
        }
    }

    fn env(pairs: &[(&str, &str)]) -> Environ {
        pairs.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    fn parse(args: &[&str]) -> Args {
        match Cli::try_parse_from(["netbox-omnisync", "sync"].iter().chain(args)).unwrap().command {
            Some(Command::Sync(args)) => args,
            other => panic!("not a sync: {other:?}"),
        }
    }

    fn change() -> Change {
        Change::new("serial", Action::Update, "d", "d").fields([("serial", "x")]).id(1)
    }

    fn outcome(changes: Vec<Change>, warnings: &[&str], errors: &[&str], applied: usize) -> Outcome {
        Outcome {
            changes,
            warnings: warnings.iter().map(|text| (*text).to_owned()).collect(),
            errors: errors.iter().map(|text| (*text).to_owned()).collect(),
            applied,
            seconds: None,
        }
    }

    // The cases of the Python tool, `apply` turned into its opposite.
    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&outcome(vec![], &[], &[], 0), true), 0);
        assert_eq!(exit_code(&outcome(vec![change()], &[], &[], 0), true), 2);
        assert_eq!(exit_code(&outcome(vec![change()], &[], &[], 1), false), 0);
        assert_eq!(exit_code(&outcome(vec![change()], &[], &["boom"], 0), false), 1);
        assert_eq!(exit_code(&outcome(vec![], &["w"], &[], 0), true), 0);
    }

    #[test]
    fn an_error_wins_over_the_changes_of_a_dry_run() {
        assert_eq!(exit_code(&outcome(vec![change()], &[], &["boom"], 0), true), 1);
        assert_eq!(exit_code(&outcome(vec![], &[], &["boom"], 0), true), 1);
    }

    #[test]
    fn changes_never_exit_2_outside_a_dry_run() {
        assert_eq!(exit_code(&outcome(vec![change()], &[], &[], 0), false), 0);
        assert_eq!(exit_code(&outcome(vec![change(), change()], &["w"], &[], 2), false), 0);
    }

    #[test]
    fn the_arguments_default_to_a_full_writing_run() {
        let args = parse(&[]);
        assert_eq!(args.config, Path::new("config.toml"));
        assert_eq!((args.dry_run, args.prune, args.quiet), (false, false, false));
        assert!(args.filter().is_empty());
    }

    #[test]
    fn the_filters_are_repeatable_and_combinable() {
        let args = parse(&[
            "--kind",
            "switch",
            "--kind",
            "router",
            "--type",
            "ios",
            "--type",
            "nxos",
            "--source",
            "a",
            "--source",
            "b",
            "--dry-run",
            "--prune",
            "--quiet",
            "--config",
            "/etc/omnisync/config.toml",
        ]);
        assert_eq!(
            args.filter(),
            Filter {
                kinds: vec![SourceKind::Switch, SourceKind::Router],
                types: vec![SourceType::Ios, SourceType::Nxos],
                names: vec!["a".to_owned(), "b".to_owned()],
            }
        );
        assert_eq!((args.dry_run, args.prune, args.quiet), (true, true, true));
        assert_eq!(args.config, Path::new("/etc/omnisync/config.toml"));
    }

    #[test]
    fn every_kind_and_type_of_the_decisions_is_accepted() {
        let kinds = parse(&["--kind", "hypervisor", "--kind", "switch", "--kind", "router", "--kind", "firewall"]).kind;
        assert_eq!(kinds, [SourceKind::Hypervisor, SourceKind::Switch, SourceKind::Router, SourceKind::Firewall]);
        let types = ["vmware", "proxmox", "ios", "nxos", "nipper", "fortios"];
        let args: Vec<&str> = types.iter().flat_map(|name| ["--type", name]).collect();
        let parsed: Vec<&str> = parse(&args).r#type.iter().map(|r#type| r#type.as_str()).collect();
        assert_eq!(parsed, types);
    }

    #[test]
    fn the_apply_flag_of_the_python_tool_is_gone() {
        assert!(Cli::try_parse_from(["netbox-omnisync", "sync", "--apply"]).is_err());
        assert!(Cli::try_parse_from(["netbox-omnisync", "sync", "--device", "nexus01.lab01"]).is_err());
    }

    #[test]
    fn colour_only_on_a_terminal_without_no_color() {
        assert!(colour(&env(&[]), true));
        assert!(!colour(&env(&[("NO_COLOR", "1")]), true));
        assert!(!colour(&env(&[]), false));
        // no-color.org: an empty NO_COLOR is not set.
        assert!(colour(&env(&[("NO_COLOR", "")]), true));
    }

    #[test]
    fn progress_is_a_bar_on_a_terminal_and_lines_elsewhere() {
        assert!(matches!(make_progress(Buffer::default(), true, false), Shown::Bar(_)));
        assert!(matches!(make_progress(Buffer::default(), false, false), Shown::Lines(_)));
        // Quiet only silences what is not a terminal: someone watching still sees the bar.
        assert!(matches!(make_progress(Buffer::default(), true, true), Shown::Bar(_)));
        assert!(matches!(make_progress(Buffer::default(), false, true), Shown::Silent(_)));
    }

    // In the state directory of the user, as the known hosts: the same for a
    // cron job and an interactive shell, whatever their TMPDIR, and private.
    #[test]
    fn the_lock_file_is_in_the_state_directory_whatever_tmpdir() {
        let lock = |pairs: &[(&str, &str)]| lock_file(&env(pairs));
        assert_eq!(
            lock(&[("HOME", "/h"), ("TMPDIR", "/var/tmp/x")]),
            Ok(PathBuf::from("/h/.local/state/netbox-omnisync/netbox-omnisync.lock"))
        );
        assert_eq!(
            lock(&[("HOME", "/h"), ("XDG_STATE_HOME", "/s")]),
            Ok(PathBuf::from("/s/netbox-omnisync/netbox-omnisync.lock"))
        );
        assert_eq!(
            lock(&[("HOME", "/h"), ("XDG_STATE_HOME", "")]),
            Ok(PathBuf::from("/h/.local/state/netbox-omnisync/netbox-omnisync.lock"))
        );
        assert_eq!(
            lock(&[("TMPDIR", "/tmp")]),
            Err("cannot locate the lock file: set HOME or XDG_STATE_HOME".to_owned())
        );
    }

    // Created private: another user can neither take the place of the lock nor
    // point it at a file of this one through a symbolic link.
    #[tokio::test]
    async fn the_lock_lives_in_a_private_directory_and_is_never_a_link() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        let directory = bench.directory.path().join(".local/state/netbox-omnisync");
        assert_eq!(fs::metadata(&directory).unwrap().permissions().mode() & 0o777, 0o700);

        let target = bench.directory.path().join("precious");
        fs::write(&target, "keep me").unwrap();
        fs::remove_file(bench.lock()).unwrap();
        std::os::unix::fs::symlink(&target, bench.lock()).unwrap();
        let ran = bench.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        assert!(
            ran.stderr.starts_with(&format!("error: cannot open the lock file {}: ", bench.lock().display())),
            "{}",
            ran.stderr
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep me");

        // A directory of the user that others can write to (a umask, a copy) is
        // made private again rather than refused: the user owns it.
        fs::remove_file(bench.lock()).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert_eq!(fs::metadata(&directory).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[tokio::test]
    async fn a_missing_secret_returns_1_before_anything_is_contacted() {
        let bench = Bench::new(&CONFIG.replace("auth = \"agent\"", "auth = \"password\"")).without("NETBOX_TOKEN");
        let ran = bench.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stderr.contains("SWITCH_NEXUS01_LAB01_PASSWORD"), "{}", ran.stderr);
        assert!(ran.stderr.starts_with("error: missing environment variables: NETBOX_TOKEN, "), "{}", ran.stderr);
        assert_eq!(ran.stdout, "");
    }

    #[tokio::test]
    async fn a_second_run_is_refused_while_one_is_running() {
        let bench = Bench::new(CONFIG);
        let lock = bench.lock();
        let held = File::options().create(true).append(true).open(&lock).unwrap();
        held.try_lock().unwrap();
        let ran = bench.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        assert_eq!(ran.stderr, format!("error: another run holds {}\n", lock.display()));
    }

    #[tokio::test]
    async fn the_refusal_names_the_run_holding_the_lock() {
        let bench = Bench::new(CONFIG);
        let lock = bench.lock();
        let mut held = File::options().create(true).append(true).open(&lock).unwrap();
        held.try_lock().unwrap();
        held.write_all(b"4242 2026-09-30T20:31:02\n").unwrap();
        held.flush().unwrap();
        let ran = bench.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        assert_eq!(
            ran.stderr,
            format!("error: another run (PID 4242, started 2026-09-30T20:31:02) holds {}\n", lock.display())
        );
    }

    #[tokio::test]
    async fn a_running_run_records_itself_in_the_lock() {
        let bench = Bench::new(CONFIG);
        fs::write(bench.lock(), "999 2026-01-01T00:00:00\n").unwrap();
        let lab = Lab { lock: Some(bench.lock()), ..Lab::new("SN1") };
        assert_eq!(bench.run(&lab, &[]).await.code, 0);
        let seen = lab.lock_seen.lock().unwrap().clone();
        let expected = Regex::new(&format!(r"^{} \d{{4}}-\d\d-\d\dT\d\d:\d\d:\d\d\n$", std::process::id())).unwrap();
        assert_eq!(seen.len(), 1);
        assert!(expected.is_match(&seen[0]), "{seen:?}");
    }

    #[tokio::test]
    async fn the_lock_is_released_when_the_run_ends() {
        let bench = Bench::new(CONFIG);
        let lab = Lab::new("SN1");
        assert_eq!(bench.run(&lab, &[]).await.code, 0);
        let lock = File::options().append(true).open(bench.lock()).unwrap();
        assert!(lock.try_lock().is_ok());
    }

    // The Python tool ended in a traceback there.
    #[tokio::test]
    async fn a_lock_file_that_cannot_be_opened_is_an_error() {
        let bench = Bench::new(CONFIG);
        // A state directory under a file cannot be created.
        let file = bench.directory.path().join("a-file");
        fs::write(&file, "").unwrap();
        let bench = bench.with(&[("XDG_STATE_HOME", file.to_str().unwrap())]);
        let ran = bench.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        let expected =
            format!("error: cannot create the directory of the lock file {}: ", file.join("netbox-omnisync").display());
        assert!(ran.stderr.starts_with(&expected), "{}", ran.stderr);
    }

    #[tokio::test]
    async fn ctrl_c_exits_130_with_a_message() {
        let bench = Bench::new(CONFIG);
        let started = Arc::new(Notify::new());
        let lab = Lab { stuck: Some(Arc::clone(&started)), ..Lab::new("") };
        let ran = bench.run_until(&lab, &[], async { started.notified().await }).await;
        // 130 = 128 + SIGINT, what a shell reports for a command stopped by Ctrl-C.
        assert_eq!(ran.code, 130);
        assert_eq!(
            ran.stderr.lines().last(),
            Some("error: interrupted; writes already made stay in Netbox, the next run starts from there")
        );
        assert_eq!(ran.stdout, "");
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
        // The lock is released: the next run starts.
        let lock = File::options().append(true).open(bench.lock()).unwrap();
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn progress_goes_to_stderr_and_the_report_to_stdout() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert_eq!(ran.code, 0);
        assert!(ran.stderr.contains("collected nexus01.lab01 (1/1)"), "{}", ran.stderr);
        assert!(!ran.stdout.contains("collect"), "{}", ran.stdout);
        assert!(ran.stdout.contains("Nothing to do"), "{}", ran.stdout);
        assert!(ran.stdout.ends_with('\n'));
    }

    #[tokio::test]
    async fn on_a_terminal_no_progress_line_is_written() {
        let bench = Bench { stderr_is_terminal: true, ..Bench::new(CONFIG) };
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    }

    // NetBox changes the shape of its objects from one minor release to the
    // next and ignores a field it does not know on write: a release this build
    // was not tested with is refused before any source is read, unless the
    // file says to warn, and then the report says it.
    #[tokio::test]
    async fn a_netbox_release_this_build_was_not_tested_with_is_refused_unless_told_to_warn() {
        let lab = Lab::new("SN1");
        lab.netbox.set_version("4.8.0");
        let ran = Bench::new(CONFIG).run(&lab, &[]).await;
        assert_eq!(ran.code, 1);
        assert_eq!(
            ran.stderr,
            "error: NetBox 4.8.0 is not a release this build was tested with (4.5, 4.6, 4.7): nothing was read \
             nor written (netbox.unsupported_version = \"warn\" runs it anyway)\n"
        );
        assert_eq!(lab.asked(), [] as [&str; 0]);
        assert_eq!(lab.netbox.writes(), []);

        let warned = CONFIG.replace("[netbox]\n", "[netbox]\nunsupported_version = \"warn\"\n");
        let ran = Bench::new(&warned).run(&lab, &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
        assert!(
            ran.stdout.contains(
                "NetBox 4.8.0 is not a release this build was tested with (4.5, 4.6, 4.7): the run went on, \
                 as netbox.unsupported_version says"
            ),
            "{}",
            ran.stdout
        );
        // A supported release is said nothing of.
        lab.netbox.set_version("4.7.5");
        let ran = Bench::new(CONFIG).run(&lab, &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert!(!ran.stdout.contains("tested with"), "{}", ran.stdout);
    }

    #[tokio::test]
    async fn a_dry_run_reports_the_changes_and_writes_nothing() {
        let bench = Bench::new(CONFIG);
        let lab = Lab::new("");
        let ran = bench.run(&lab, &["--dry-run"]).await;
        assert_eq!(ran.code, 2);
        assert!(ran.stdout.contains("serial: '' → 'SN1'"), "{}", ran.stdout);
        assert_eq!(lab.netbox.writes(), []);
        assert_eq!(lab.serial(), "");
        // The NetBox client itself is asked to refuse the writes.
        assert_eq!(lab.dry_runs(), [true]);
    }

    // What `check` and `digest` read: one line per run that contacted NetBox,
    // with every source of the file, the selected ones, what changed and what
    // failed. The NetBox id of a change is not part of it.
    #[tokio::test]
    async fn a_run_appends_one_entry_to_the_journal() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV);
        let lab = Lab::new("");
        let ran = bench.run(&lab, &[]).await;
        assert_eq!(ran.code, 1, "{}", ran.stderr);
        assert_eq!(lab.serial(), "SN1");
        let journaled = bench.journaled();
        assert_eq!(journaled.len(), 1);
        let mut entry = journaled[0].clone();
        let changes = entry.as_object_mut().unwrap().remove("changes").unwrap();
        assert_eq!(
            entry,
            json!({
                "version": 1,
                "started": "2026-11-20T08:00:00+01:00",
                "configured": [{"name": "nexus01.lab01", "kind": "switch"}, {"name": "pve01.lab01", "kind": "hypervisor"}],
                "selected": ["nexus01.lab01", "pve01.lab01"],
                "applied": 1,
                "warnings": [],
                "errors": [NOT_IMPLEMENTED],
            })
        );
        let [change] = changes.as_array().unwrap().as_slice() else { panic!("one change: {changes}") };
        assert_eq!(change["device"], "nexus01.lab01");
        assert_eq!(change["action"], "update");
        assert_eq!(change["fields"], json!({"serial": "SN1"}));
        assert_eq!(change["before"], json!({"serial": ""}));
        assert_eq!(change.get("id"), None);
        assert_eq!(fs::metadata(bench.journal()).unwrap().permissions().mode() & 0o777, 0o644);

        // The next run adds its line after it, with what it selected.
        let ran = bench.run(&lab, &["--kind", "switch"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        let journaled = bench.journaled();
        assert_eq!(journaled.len(), 2);
        assert_eq!(journaled[1]["selected"], json!(["nexus01.lab01"]));
        assert_eq!(journaled[1]["configured"], journaled[0]["configured"]);
        assert_eq!(journaled[1]["changes"], json!([]));
    }

    #[tokio::test]
    async fn a_run_of_a_file_several_hosts_share_journals_its_host_and_the_one_of_each_source() {
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN0") }.on(SAT01);
        let bench = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV);
        assert_eq!(bench.run(&lab, &[]).await.code, 0);
        let journaled = bench.journaled();
        assert_eq!(journaled.len(), 1);
        assert_eq!(journaled[0]["runner"], json!("sat01.lab02"));
        // Every source of the file, each with the host that launches it: the check of a host judges its own.
        assert_eq!(
            journaled[0]["configured"],
            json!([
                {"name": "nexus01.lab01", "kind": "switch", "runner": "sync01.lab01"},
                {"name": "pve01.lab01", "kind": "hypervisor", "runner": "sat01.lab02"}
            ])
        );
        assert_eq!(journaled[0]["selected"], json!(["pve01.lab01"]));
        // A dry run as another host writes no line: the journal only ever names its machine.
        let ran = bench.run(&lab, &["--dry-run", "--runner", SYNC01]).await;
        assert_eq!(ran.code, 2, "{}", ran.stderr);
        assert_eq!(bench.journaled().len(), 1);
    }

    #[tokio::test]
    async fn a_dry_run_writes_nothing_in_the_journal() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Lab::new(""), &["--dry-run"]).await;
        assert_eq!(ran.code, 2, "{}", ran.stderr);
        assert!(!bench.journal().exists());
    }

    // A run refused before it contacts anything is the operator's to see at
    // once (cron mails its line): neither the configuration nor the lock is a
    // run of the sources.
    #[tokio::test]
    async fn a_run_refused_before_netbox_is_contacted_writes_nothing_in_the_journal() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}"));
        let ran = bench.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stderr.starts_with("error: missing environment variables: PVE01_LAB01_TOKEN"), "{}", ran.stderr);
        let ran = bench.run(&Untouchable, &["--source", "nope"]).await;
        assert_eq!(ran.code, 1);
        let held = File::options().create(true).append(true).open(bench.lock()).unwrap();
        held.try_lock().unwrap();
        let bench = bench.with(&HYPERVISOR_ENV);
        let ran = bench.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stderr.starts_with("error: another run (PID "), "{}", ran.stderr);
        assert!(!bench.journal().exists());
    }

    // Past the secrets, a run that NetBox stops (its release, its schema) is a
    // failed run of every selected source: the monitoring must see it.
    #[tokio::test]
    async fn a_run_netbox_refuses_is_journaled_as_failed() {
        let lab = Lab::new("SN1");
        lab.netbox.set_version("4.8.0");
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&lab, &[]).await;
        assert_eq!(ran.code, 1);
        let refusal = "NetBox 4.8.0 is not a release this build was tested with (4.5, 4.6, 4.7): nothing was read \
                       nor written (netbox.unsupported_version = \"warn\" runs it anyway)";
        assert_eq!(ran.stderr, format!("error: {refusal}\n"));
        assert_eq!(
            bench.journaled(),
            [json!({
                "version": 1,
                "started": "2026-11-20T08:00:00+01:00",
                "configured": [{"name": "nexus01.lab01", "kind": "switch"}],
                "selected": ["nexus01.lab01"],
                "changes": [],
                "applied": 0,
                "warnings": [],
                "errors": [refusal],
            })]
        );
    }

    #[tokio::test]
    async fn the_journal_is_where_the_configuration_says() {
        let bench = Bench::new(&format!("journal = \"runs/journal.jsonl\"\n{CONFIG}"));
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        let journal = bench.directory.path().join("runs/journal.jsonl");
        assert_eq!(fs::read_to_string(&journal).unwrap().lines().count(), 1);
        assert!(!bench.journal().exists());
    }

    // The writes are made: a run whose journal is lost must not look like a
    // success, and its report is still printed.
    #[tokio::test]
    async fn a_journal_that_cannot_be_written_fails_the_run_naming_it() {
        let bench = Bench::new(CONFIG);
        // A directory under a file cannot be created.
        let file = bench.directory.path().join("a-file");
        fs::write(&file, "").unwrap();
        fs::write(&bench.config, format!("journal = \"{}/journal.jsonl\"\n{CONFIG}", file.display())).unwrap();
        let lab = Lab::new("");
        // Quiet: stderr holds nothing but the error, the report a change.
        let ran = bench.run(&lab, &["--quiet"]).await;
        assert_eq!(ran.code, 1);
        let named = format!("error: cannot write the journal {}/journal.jsonl: ", file.display());
        assert!(ran.stderr.starts_with(&named), "{}", ran.stderr);
        assert!(ran.stdout.contains("serial: '' → 'SN1'"), "{}", ran.stdout);
        assert_eq!(lab.serial(), "SN1");
    }

    /// A run of nexus01.lab01 that started at `started`, took 12 s, made
    /// `changes` and said `errors`.
    fn switch_run(started: &str, changes: Vec<Change>, errors: &[&str]) -> journal::Entry {
        journal::Entry {
            version: 1,
            started: started.to_owned(),
            seconds: 12.0,
            runner: None,
            configured: vec![journal::Configured {
                name: "nexus01.lab01".to_owned(),
                kind: "switch".to_owned(),
                runner: None,
            }],
            selected: vec!["nexus01.lab01".to_owned()],
            changes: changes.into_iter().map(|change| Change { id: None, ..change }).collect(),
            applied: 0,
            warnings: vec![],
            errors: errors.iter().map(|error| (*error).to_owned()).collect(),
        }
    }

    /// Write `entries` as the default journal of `bench`.
    fn write_journal(bench: &Bench, entries: &[journal::Entry]) -> PathBuf {
        let path = bench.journal();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let lines: Vec<String> = entries.iter().map(|entry| serde_json::to_string(entry).unwrap()).collect();
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        path
    }

    // The clock of the lab is 08:00: the run of 07:55 ended at 07:55:12.
    #[tokio::test]
    async fn the_check_tells_the_state_of_the_sources_by_its_line_and_its_code() {
        let bench = Bench::new(CONFIG);
        let journal = write_journal(&bench, &[switch_run("2026-11-20T07:55:00+01:00", vec![], &[])]);
        let journal = journal.to_str().unwrap();
        let ran = bench.run_raw(&Lab::new("SN1"), &["check", "--journal", journal, "--max-age", "switch=26h"]).await;
        assert_eq!(
            (ran.code, ran.stdout.as_str(), ran.stderr.as_str()),
            (0, "NETBOX-OMNISYNC OK - 1 source synced | sources=1 failed=0 stale=0 warnings=0\n", "")
        );
        let ran = bench.run_raw(&Lab::new("SN1"), &["check", "--journal", journal, "--max-age", "switch=1m"]).await;
        assert_eq!(
            (ran.code, ran.stdout.as_str()),
            (
                2,
                "NETBOX-OMNISYNC CRITICAL - nexus01.lab01: no success for 4m | sources=1 failed=0 stale=1 warnings=0\n\
                 nexus01.lab01: no success for 4m\n"
            )
        );
        // A check never waits for a run, nor contacts anything.
        assert!(!bench.lock().exists());
    }

    #[tokio::test]
    async fn a_check_without_its_journal_is_unknown() {
        let bench = Bench::new(CONFIG);
        let journal = bench.journal();
        let args = ["check", "--journal", journal.to_str().unwrap(), "--max-age", "switch=26h"];
        let ran = bench.run_raw(&Lab::new("SN1"), &args).await;
        assert_eq!(ran.code, 3);
        assert_eq!(
            ran.stdout,
            format!(
                "NETBOX-OMNISYNC UNKNOWN - cannot read the journal {}: No such file or directory (os error 2)\n",
                journal.display()
            )
        );
    }

    // Icinga reads stdout and the code: a command line it was given wrong is
    // UNKNOWN, not the 1 of a WARNING, nor the 2 of a CRITICAL.
    #[tokio::test]
    async fn a_usage_error_of_the_check_is_unknown_on_stdout() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run_raw(&Lab::new("SN1"), &["check", "--journal", "j", "--max-age", "switch=1y"]).await;
        assert_eq!(
            (ran.code, ran.stdout.as_str(), ran.stderr.as_str()),
            (
                3,
                "NETBOX-OMNISYNC UNKNOWN - invalid value 'switch=1y' for '--max-age <KIND=DURATION>': \
                 invalid duration '1y': a whole number above 0 and s, m, h or d (15m, 26h, 2d)\n",
                ""
            )
        );
        for args in [&["check"][..], &["check", "--journal", "j"], &["check", "--frobnicate"]] {
            let ran = bench.run_raw(&Lab::new("SN1"), args).await;
            assert_eq!((ran.code, ran.stderr.as_str()), (3, ""), "{args:?}");
            assert!(ran.stdout.starts_with("NETBOX-OMNISYNC UNKNOWN - "), "{}", ran.stdout);
            assert_eq!(ran.stdout.lines().count(), 1, "{}", ran.stdout);
        }
        let help = bench.run_raw(&Lab::new("SN1"), &["check", "--help"]).await;
        assert_eq!(help.code, 0);
        assert!(help.stdout.contains("--max-age <KIND=DURATION>"), "{}", help.stdout);
        // Which sources a host answers for, when the file is shared.
        let judged = "Every source of the configuration must have succeeded within the maximum age\n\
                      of its kind: those of the host of the journal alone, when the configuration\n\
                      says which host runs each source (runner).";
        assert!(help.stdout.contains(judged), "{}", help.stdout);
    }

    fn changed_serial() -> Change {
        Change::new("device", Action::Update, "nexus01.lab01", "nexus01.lab01")
            .fields([("serial", "SN1")])
            .before([("serial", "")])
    }

    /// The text and the HTML of a message the digest wrote.
    fn decoded(message: &str) -> Vec<String> {
        message
            .split("--=_netbox-omnisync-digest")
            .skip(1)
            .filter(|part| !part.starts_with("--"))
            .map(|part| {
                let data: String = part.split_once("\n\n").unwrap().1.lines().collect();
                String::from_utf8(data_encoding::BASE64.decode(data.as_bytes()).unwrap()).unwrap()
            })
            .collect()
    }

    // The digest needs no secret: it reads the file and the journal, and
    // contacts nothing but sendmail.
    #[tokio::test]
    async fn without_an_address_the_digest_prints_its_message() {
        let bench = Bench::new(CONFIG).without("NETBOX_TOKEN");
        write_journal(&bench, &[switch_run("2026-11-20T07:55:00+01:00", vec![changed_serial()], &[])]);
        let config = bench.config.to_str().unwrap().to_owned();
        let lab = Lab::new("SN1");
        let ran = bench.run_raw(&lab, &["digest", "--config", &config, "--since", "24h"]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
        assert!(
            ran.stdout.starts_with("Subject: [netbox-omnisync] 1 change in the last 24 h\nMIME-Version: 1.0\n"),
            "{}",
            ran.stdout
        );
        let [text, html]: [String; 2] = decoded(&ran.stdout).try_into().unwrap();
        assert!(text.contains("  ~ device nexus01.lab01\n      serial: '' → 'SN1'\n"), "{text}");
        assert!(html.contains("href=\"https://netbox.example/core/changelog/?time_after=2026-11-19T07:00:00Z\""));
        assert!(html.contains(&format!("Sent by netbox-omnisync {} on sync01.lab01", env!("CARGO_PKG_VERSION"))));
        assert_eq!(lab.mails.lock().unwrap().len(), 0);
        assert!(!bench.lock().exists());
    }

    #[tokio::test]
    async fn with_addresses_the_digest_hands_its_message_to_sendmail() {
        let bench = Bench::new(CONFIG);
        write_journal(&bench, &[switch_run("2026-11-20T07:55:00+01:00", vec![], &["nexus01.lab01: unreachable"])]);
        let config = bench.config.to_str().unwrap().to_owned();
        let lab = Lab::new("SN1");
        let args = ["digest", "-c", &config, "--since", "24h", "--to", "noc@example.net", "--to", "ops@example.net"];
        let ran = bench.run_raw(&lab, &args).await;
        assert_eq!((ran.code, ran.stdout.as_str(), ran.stderr.as_str()), (0, "", ""));
        let mails = lab.mails.lock().unwrap().clone();
        let [(sendmail, message)] = mails.as_slice() else { panic!("one mail: {mails:?}") };
        assert_eq!(sendmail, Path::new("/usr/sbin/sendmail"));
        assert!(
            message.starts_with(
                "To: noc@example.net, ops@example.net\nSubject: [netbox-omnisync] 1 error in the last 24 h\n"
            ),
            "{message}"
        );

        let lab = Lab {
            mail_refusal: Some("/opt/sendmail could not send the mail: exit status: 75".to_owned()),
            ..Lab::new("SN1")
        };
        let args =
            ["digest", "-c", &config, "--since", "24h", "--to", "noc@example.net", "--sendmail", "/opt/sendmail"];
        let ran = bench.run_raw(&lab, &args).await;
        assert_eq!(
            (ran.code, ran.stdout.as_str(), ran.stderr.as_str()),
            (1, "", "error: /opt/sendmail could not send the mail: exit status: 75\n")
        );
        assert_eq!(lab.mails.lock().unwrap()[0].0, Path::new("/opt/sendmail"));
    }

    // Nothing to tell: no mail, and nothing for cron to mail either.
    #[tokio::test]
    async fn a_period_without_a_change_nor_an_error_sends_nothing() {
        let bench = Bench::new(CONFIG);
        let mut quiet = switch_run("2026-11-20T07:55:00+01:00", vec![], &[]);
        quiet.warnings = vec!["nexus01.lab01: a permanent warning".to_owned()];
        // Before the period: 25 hours ago.
        let old = switch_run("2026-11-19T07:00:00+01:00", vec![changed_serial()], &["nexus01.lab01: x"]);
        write_journal(&bench, &[old, quiet]);
        let config = bench.config.to_str().unwrap().to_owned();
        let lab = Lab::new("SN1");
        let ran = bench.run_raw(&lab, &["digest", "-c", &config, "--since", "24h", "--to", "noc@example.net"]).await;
        assert_eq!((ran.code, ran.stdout.as_str(), ran.stderr.as_str()), (0, "", ""));
        assert_eq!(lab.mails.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_digest_without_its_journal_or_with_a_wrong_address_is_an_error() {
        let bench = Bench::new(CONFIG);
        let config = bench.config.to_str().unwrap().to_owned();
        let ran = bench.run_raw(&Lab::new("SN1"), &["digest", "-c", &config, "--since", "24h"]).await;
        assert_eq!(ran.code, 1);
        assert_eq!(
            ran.stderr,
            format!(
                "error: cannot read the journal {}: No such file or directory (os error 2)\n",
                bench.journal().display()
            )
        );
        let ran = bench
            .run_raw(&Lab::new("SN1"), &["digest", "-c", &config, "--since", "24h", "--to", "a@b\nBcc: x@y"])
            .await;
        assert_eq!(ran.code, 1);
        assert!(ran.stderr.starts_with("error: invalid value 'a@b\nBcc: x@y' for '--to <ADDRESS>'"), "{}", ran.stderr);
        let ran = bench.run_raw(&Lab::new("SN1"), &["digest", "-c", &config]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stderr.contains("--since <DURATION>"), "{}", ran.stderr);
    }

    #[tokio::test]
    async fn without_dry_run_the_changes_are_written() {
        let bench = Bench::new(CONFIG);
        let lab = Lab::new("");
        let ran = bench.run(&lab, &[]).await;
        assert_eq!(ran.code, 0);
        assert!(ran.stdout.contains("serial: '' → 'SN1'"), "{}", ran.stdout);
        assert_eq!(lab.serial(), "SN1");
        assert_eq!(lab.dry_runs(), [false]);
    }

    #[tokio::test]
    async fn nothing_to_do_exits_0_in_both_modes() {
        let bench = Bench::new(CONFIG);
        let lab = Lab::new("SN1");
        assert_eq!(bench.run(&lab, &["--dry-run"]).await.code, 0);
        assert_eq!(bench.run(&lab, &[]).await.code, 0);
        assert_eq!(lab.netbox.writes(), []);
    }

    #[tokio::test]
    async fn the_hidden_flag_says_its_line_and_touches_nothing() {
        let bench = Bench::new(CONFIG);
        // Nothing is loaded, locked or contacted: the backend panics if asked.
        let ran = bench.run_raw(&Untouchable, &["--raphinerie"]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
        let lines: Vec<&str> = ran.stdout.lines().collect();
        // A plant with four chimneys, four rows of them, over the river, and a pig afloat between.
        let chimneys = "     ||     ||                         ||     ||";
        assert_eq!(lines.iter().filter(|line| **line == chimneys).count(), 4, "{}", ran.stdout);
        assert_eq!(lines[1], "                        ( oo)~");
        assert_eq!(lines[13], "  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        let line = format!("netbox-omnisync {} — raphinerie de données brutes depuis 1974", env!("CARGO_PKG_VERSION"));
        assert_eq!(lines.last().copied(), Some(line.as_str()));
        assert_eq!(lines.len(), 15);
        // Off a terminal, no colour code: the drawing is plain text.
        assert!(!ran.stdout.contains('\u{1b}'), "{}", ran.stdout);
        assert!(!bench.lock().exists());
        // Hidden: the help does not tell.
        let help = bench.run_raw(&Untouchable, &["help"]).await;
        assert_eq!(help.code, 0);
        assert!(!help.stdout.to_lowercase().contains("raphinerie"), "{}", help.stdout);
    }

    #[tokio::test]
    async fn quiet_prints_nothing_when_there_is_nothing_to_say() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Lab::new("SN1"), &["--quiet"]).await;
        assert_eq!((ran.code, ran.stdout.as_str()), (0, ""));
        let ran = bench.run(&Lab::new("SN1"), &["--quiet", "--dry-run"]).await;
        assert_eq!((ran.code, ran.stdout.as_str()), (0, ""));
    }

    #[tokio::test]
    async fn quiet_writes_no_progress_line_cron_would_mail() {
        // Off a terminal the progress is one line per step on stderr, and cron
        // mails whatever a job writes: with --quiet a run tells its report alone.
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Lab::new("SN1"), &["--quiet"]).await;
        assert_eq!((ran.code, ran.stdout.as_str(), ran.stderr.as_str()), (0, "", ""));
        // Something to say: it is in the report, on stdout.
        let ran = bench.run(&Lab::new(""), &["--quiet", "--dry-run"]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (2, ""));
        assert!(ran.stdout.contains("serial"), "{}", ran.stdout);
        // Without --quiet the steps are told.
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert!(ran.stderr.contains("done in"), "{}", ran.stderr);
    }

    #[tokio::test]
    async fn quiet_still_prints_the_report_of_a_run_that_has_something_to_say() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Lab::new(""), &["--quiet", "--dry-run"]).await;
        assert_eq!(ran.code, 2);
        assert!(ran.stdout.contains("serial: '' → 'SN1'"), "{}", ran.stdout);
        let ran = bench.run(&Lab::new(""), &["--quiet"]).await;
        assert_eq!(ran.code, 0);
        assert!(ran.stdout.contains("serial: '' → 'SN1'"), "{}", ran.stdout);
        // An error is something to say.
        let bench = Bench::new(&format!("{CONFIG}{FIREWALL}")).with(&FIREWALL_ENV);
        let ran = bench.run(&Lab::new("SN1"), &["--quiet"]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stdout.contains("fw01.lab01: unreachable"), "{}", ran.stdout);
    }

    #[tokio::test]
    async fn an_unknown_source_is_an_error_before_anything_is_contacted() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Untouchable, &["--source", "nexus09.lab01"]).await;
        assert_eq!(ran.code, 1);
        assert_eq!(ran.stderr, "error: unknown source(s): nexus09.lab01\n");
        assert_eq!(ran.stdout, "");
    }

    #[tokio::test]
    async fn filters_that_match_nothing_are_an_error_before_anything_is_contacted() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run(&Untouchable, &["--kind", "firewall"]).await;
        assert_eq!(ran.code, 1);
        assert_eq!(ran.stderr, "error: no source matches --kind firewall\n");
    }

    #[tokio::test]
    async fn only_the_selected_sources_run() {
        let bench = Bench::new(&format!("{CONFIG}{FIREWALL}")).with(&FIREWALL_ENV);
        let lab = Lab::new("SN1");
        assert_eq!(bench.run(&lab, &["--kind", "switch"]).await.code, 0);
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
        let lab = Lab::new("SN1");
        assert_eq!(bench.run(&lab, &["--type", "fortios"]).await.code, 1);
        assert_eq!(lab.asked(), ["fw01.lab01"]);
        let lab = Lab::new("SN1");
        assert_eq!(bench.run(&lab, &["--source", "nexus01.lab01"]).await.code, 0);
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
        let lab = Lab::new("SN1");
        assert_eq!(bench.run(&lab, &[]).await.code, 1);
        let mut asked = lab.asked();
        asked.sort();
        assert_eq!(asked, ["fw01.lab01", "nexus01.lab01"]);
    }

    #[tokio::test]
    async fn a_selected_hypervisor_is_an_error_of_this_build() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV);
        let lab = Lab::new("SN1");
        let ran = bench.run(&lab, &[]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stderr.contains(&format!("error: {NOT_IMPLEMENTED}\n")), "{}", ran.stderr);
        assert!(ran.stdout.contains(&format!("Errors (1)\n  {NOT_IMPLEMENTED}\n")), "{}", ran.stdout);
        // The network sources of the same run are synced all the same.
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
    }

    #[tokio::test]
    async fn a_selected_hypervisor_is_read_and_written_to_netbox() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV);
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN1") };
        let ran = bench.run(&lab, &["--kind", "hypervisor"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        let cluster = lab.netbox.find("virtualization.clusters", "name", &json!("pve-lab")).expect("cluster written");
        // Owned by the tool and by its source.
        let tag = |name: &str| lab.netbox.find("extras.tags", "name", &json!(name)).expect("tag written");
        let tags = lab.netbox.row("virtualization.clusters", cluster).unwrap()["tags"].clone();
        assert_eq!(tags, json!([tag("netbox-omnisync"), tag("source-pve01lab01")]));
        assert!(ran.stdout.contains("pve-lab"), "{}", ran.stdout);
    }

    #[tokio::test]
    async fn a_dry_run_reports_a_hypervisor_and_writes_nothing() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV);
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN1") };
        let ran = bench.run(&lab, &["--kind", "hypervisor", "--dry-run"]).await;
        assert_eq!(ran.code, 2, "{}", ran.stderr);
        assert!(ran.stdout.contains("pve-lab"), "{}", ran.stdout);
        assert_eq!(lab.netbox.writes(), []);
    }

    #[tokio::test]
    async fn a_hypervisor_left_out_of_a_run_keeps_its_tag_on_what_it_shares() {
        the_source_left_out_keeps_its_tag_on_what_it_shares(&[("PVE02_LAB01_TOKEN", "pve-secret")]).await;
    }

    // The host that launches pve01.lab01 holds no secret of pve02.lab01: the
    // file still tells it that source exists, and its tag is not a leftover.
    #[tokio::test]
    async fn a_hypervisor_left_out_of_a_run_keeps_its_tag_on_what_it_shares_without_its_secrets() {
        the_source_left_out_keeps_its_tag_on_what_it_shares(&[]).await;
    }

    /// Runs pve01.lab01 alone on a NetBox where pve02.lab01 holds the cluster
    /// type both report, with `secrets_of_the_other` as the variables of pve02.lab01.
    async fn the_source_left_out_keeps_its_tag_on_what_it_shares(secrets_of_the_other: &[(&str, &str)]) {
        let second =
            "\n[[sources]]\nname = \"pve02.lab01\"\nkind = \"hypervisor\"\nhost = \"192.0.2.11\"\ntype = \"proxmox\"\n";
        let bench =
            Bench::new(&format!("{CONFIG}{HYPERVISOR}{second}")).with(&HYPERVISOR_ENV).with(secrets_of_the_other);
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN1") };
        // The cluster type both sources report, held so far by pve02.lab01 alone.
        let tool = lab.netbox.add("extras.tags", json!({"name": "netbox-omnisync", "slug": "netbox-omnisync"}));
        let other = lab.netbox.add("extras.tags", json!({"name": "source-pve02lab01", "slug": "source-pve02lab01"}));
        let shared = lab
            .netbox
            .add("virtualization.cluster_types", json!({"name": "Proxmox", "slug": "proxmox", "tags": [tool, other]}));
        let ran = bench.run(&lab, &["--source", "pve01.lab01"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        let own = lab.netbox.find("extras.tags", "name", &json!("source-pve01lab01")).expect("tag written");
        let tags = lab.netbox.row("virtualization.cluster_types", shared).unwrap()["tags"].clone();
        let mut held: Vec<u64> = tags.as_array().unwrap().iter().map(|tag| tag.as_u64().unwrap()).collect();
        held.sort_unstable();
        let mut expected = vec![tool, other, own];
        expected.sort_unstable();
        // A tag of a source this configuration does not know would be taken for a leftover and removed.
        assert_eq!(held, expected);
    }

    /// One source of each kind of secret: a Proxmox and a vCenter (a token, or
    /// a user and its password), a BMC entry (a user and its password), a
    /// switch read with a password, and a firewall (its own account).
    fn every_kind_of_source() -> String {
        let switch = CONFIG.replace("auth = \"agent\"", "auth = \"password\"");
        let vcenter =
            "\n[[sources]]\nname = \"vc01.lab01\"\nkind = \"hypervisor\"\nhost = \"192.0.2.20\"\ntype = \"vmware\"\n";
        let bmc = "\n[[sources]]\nname = \"idrac.lab01\"\nkind = \"bmc\"\ntype = \"redfish\"\n\
                   bmcs = { \"pve01.lab01\" = \"drac-pve01.lab01\" }\n";
        format!("{switch}{HYPERVISOR}{vcenter}{bmc}{FIREWALL}")
    }

    const SWITCH_ENV: [(&str, &str); 1] = [("SWITCH_NEXUS01_LAB01_PASSWORD", "pw-nexus")];
    const VCENTER_ACCOUNT: [(&str, &str); 2] = [("VC01_LAB01_USERNAME", "sync"), ("VC01_LAB01_PASSWORD", "pw-vc")];
    const BMC_ENV: [(&str, &str); 2] = [("IDRAC_LAB01_USERNAME", "root"), ("IDRAC_LAB01_PASSWORD", "pw-idrac")];

    #[tokio::test]
    async fn a_run_needs_the_secrets_of_the_sources_it_selected_and_no_other() {
        let file = every_kind_of_source();
        // The Proxmox alone, with its token alone: read and written.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN1") };
        let ran = Bench::new(&file).with(&HYPERVISOR_ENV).run(&lab, &["--source", "pve01.lab01"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert!(lab.netbox.find("virtualization.clusters", "name", &json!("pve-lab")).is_some());
        assert_eq!(lab.asked(), [] as [&str; 0]);
        // The vCenter and the BMCs: selected by type and by kind, each reaches its reader.
        let lab = Lab::new("SN1");
        let ran = Bench::new(&file).with(&VCENTER_ACCOUNT).run(&lab, &["--type", "vmware"]).await;
        // The refusal of the reader, then the end of the run.
        let refusal = "error: vc01.lab01: vmware sources are not implemented in this build\n";
        assert!(ran.stderr.contains(refusal), "{}", ran.stderr);
        let ran = Bench::new(&file).with(&BMC_ENV).run(&lab, &["--kind", "bmc"]).await;
        let refusal = "error: idrac.lab01: redfish sources are not implemented in this build\n";
        assert!(ran.stderr.contains(refusal), "{}", ran.stderr);
        // The switch, with its own password.
        let lab = Lab::new("SN1");
        let ran = Bench::new(&file).with(&SWITCH_ENV).run(&lab, &["--kind", "switch"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
        // The firewall, with its account: it is asked (and does not answer, in this lab).
        let lab = Lab::new("SN1");
        let ran = Bench::new(&file).with(&FIREWALL_ENV).run(&lab, &["--type", "fortios"]).await;
        assert!(ran.stderr.contains(" error: fw01.lab01: unreachable\n"), "{}", ran.stderr);
        assert!(!ran.stderr.contains("missing environment variables"), "{}", ran.stderr);
        assert_eq!(lab.asked(), ["fw01.lab01"]);
    }

    #[tokio::test]
    async fn the_password_shared_by_the_switches_is_only_needed_by_a_run_that_selects_one() {
        let file = every_kind_of_source();
        // Enough for the switch, which has no password of its own here.
        let lab = Lab::new("SN1");
        let bench = Bench::new(&file).with(&[("SWITCH_PASSWORD", "pw-shared")]);
        assert_eq!(bench.run(&lab, &["--source", "nexus01.lab01"]).await.code, 0);
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
        // Not asked of a run that selects no switch.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN1") };
        let ran = Bench::new(&file).with(&HYPERVISOR_ENV).run(&lab, &["--type", "proxmox"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
    }

    #[tokio::test]
    async fn a_selected_source_without_its_secret_stops_the_run_before_anything_is_contacted() {
        let file = every_kind_of_source();
        // The two hypervisors selected, the secret of one of them held.
        let ran = Bench::new(&file).with(&HYPERVISOR_ENV).run(&Untouchable, &["--kind", "hypervisor"]).await;
        assert_eq!(
            ran.stderr,
            "error: missing environment variables: \
             VC01_LAB01_TOKEN (or VC01_LAB01_USERNAME and VC01_LAB01_PASSWORD)\n"
        );
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
        // Every missing variable of the selected sources, at once, and of no other.
        let ran = Bench::new(&file).run(&Untouchable, &["--source", "nexus01.lab01", "--source", "fw01.lab01"]).await;
        assert_eq!(
            ran.stderr,
            "error: missing environment variables: FIREWALL_FW01_LAB01_PASSWORD, FIREWALL_FW01_LAB01_USERNAME, \
             SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD\n"
        );
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
        // Half an account is not an account.
        let ran = Bench::new(&file).with(&BMC_ENV[..1]).run(&Untouchable, &["--kind", "bmc"]).await;
        assert_eq!(ran.stderr, "error: missing environment variables: IDRAC_LAB01_PASSWORD\n");
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
    }

    #[tokio::test]
    async fn a_run_without_filter_needs_every_secret() {
        let ran = Bench::new(&every_kind_of_source()).with(&HYPERVISOR_ENV).run(&Untouchable, &[]).await;
        assert_eq!(
            ran.stderr,
            "error: missing environment variables: FIREWALL_FW01_LAB01_PASSWORD, FIREWALL_FW01_LAB01_USERNAME, \
             IDRAC_LAB01_PASSWORD, IDRAC_LAB01_USERNAME, SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD, \
             VC01_LAB01_TOKEN (or VC01_LAB01_USERNAME and VC01_LAB01_PASSWORD)\n"
        );
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
    }

    const SYNC01: &str = "sync01.lab01";
    const SAT01: &str = "sat01.lab02";
    const NOT_A_RUNNER: &str = "is not one of runners (sync01.lab01, sat01.lab02): it runs no source of this file";

    /// `file` shared by two hosts: the list of both at its top, and each of
    /// its sources launched by the satellite when `on_the_satellite` names
    /// it, by the central server otherwise.
    fn shared(file: &str, on_the_satellite: &[&str]) -> String {
        let mut text = format!("runners = [\"{SYNC01}\", \"{SAT01}\"]\n");
        for line in file.lines() {
            text.push_str(line);
            text.push('\n');
            if let Some(name) = line.strip_prefix("name = \"").and_then(|rest| rest.strip_suffix('"')) {
                let host = if on_the_satellite.contains(&name) { SAT01 } else { SYNC01 };
                text.push_str(&format!("runner = \"{host}\"\n"));
            }
        }
        text
    }

    /// The switch on the central server, the Proxmox on the satellite.
    fn two_hosts() -> String {
        shared(&format!("{CONFIG}{HYPERVISOR}"), &["pve01.lab01"])
    }

    fn cluster_written(lab: &Lab) -> bool {
        lab.netbox.find("virtualization.clusters", "name", &json!("pve-lab")).is_some()
    }

    #[tokio::test]
    async fn a_run_launches_the_sources_of_its_host_alone() {
        // The satellite: its Proxmox, with its token alone, and the switch is not asked.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN0") }.on(SAT01);
        let ran = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV).run(&lab, &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert!(cluster_written(&lab));
        assert_eq!((lab.asked(), lab.serial().as_str()), (vec![], "SN0"));
        // The central server: the switch, and nothing of the Proxmox.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN0") }.on(SYNC01);
        let ran = Bench::new(&two_hosts()).run(&lab, &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert_eq!((lab.asked(), lab.serial().as_str()), (vec!["nexus01.lab01".to_owned()], "SN1"));
        assert!(!cluster_written(&lab));
        // A filter chooses among the sources of the host, and never reaches those of another.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN0") }.on(SAT01);
        let bench = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV);
        let ran = bench.run(&lab, &["--kind", "switch"]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (1, "error: no source of sat01.lab02 matches --kind switch\n"));
        let ran = bench.run(&lab, &["--source", "nexus01.lab01"]).await;
        let refusal = "error: not run by sat01.lab02: nexus01.lab01 (run by sync01.lab01)\n";
        assert_eq!((ran.code, ran.stderr.as_str()), (1, refusal));
        assert_eq!((lab.asked(), lab.dry_runs()), (vec![], vec![]));
    }

    /// The prefix two Proxmox report, as `source` describes it.
    fn prefix_of(source: &str) -> (String, Reading) {
        let prefix = Desired::new(Kind::Prefix, Identity::prefix("192.168.10.0/24", VrfKey::Unknown), source)
            .field("prefix", "192.168.10.0/24")
            .field("description", source)
            .ensure_only();
        (source.to_owned(), Reading { objects: vec![prefix], ..Reading::default() })
    }

    #[tokio::test]
    async fn two_hosts_that_report_the_same_object_never_write_it_back_and_forth() {
        // pve01.lab01, ranked first, on the central server; pve02.lab02 on the satellite.
        let second =
            "\n[[sources]]\nname = \"pve02.lab02\"\nkind = \"hypervisor\"\nhost = \"192.0.2.11\"\ntype = \"proxmox\"\n";
        let ranked = CONFIG.replacen(
            "url = \"https://netbox.example\"\n",
            "url = \"https://netbox.example\"\nsource_priority = [\"pve01.lab01\", \"pve02.lab02\"]\n",
            1,
        );
        let file = shared(&format!("{ranked}{HYPERVISOR}{second}"), &["pve02.lab02"]);
        let central = Bench::new(&file).with(&HYPERVISOR_ENV);
        let satellite = Bench::new(&file).with(&[("PVE02_LAB02_TOKEN", "pve-secret")]);
        let readings = vec![prefix_of("pve01.lab01"), prefix_of("pve02.lab02")];
        let on_central = Lab { readings: readings.clone(), ..Lab::new("SN0") }.on(SYNC01);
        let on_satellite = Lab { netbox: Arc::clone(&on_central.netbox), readings, ..Lab::new("SN0") }.on(SAT01);
        let netbox = &on_central.netbox;
        let description = || {
            let prefix = netbox.find("ipam.prefixes", "prefix", &json!("192.168.10.0/24")).expect("prefix written");
            netbox.row("ipam.prefixes", prefix).unwrap()["description"].clone()
        };
        let hypervisors = ["--kind", "hypervisor"];

        // The first run of each host: the satellite creates the prefix, the central server takes it.
        let ran = satellite.run(&on_satellite, &hypervisors).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert_eq!(description(), json!("pve02.lab02"));
        let ran = central.run(&on_central, &hypervisors).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert_eq!(description(), json!("pve01.lab01"));

        // From then on, whoever runs writes nothing.
        let written = netbox.writes().len();
        for _ in 0..2 {
            let ran = satellite.run(&on_satellite, &hypervisors).await;
            assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
            let ran = central.run(&on_central, &hypervisors).await;
            assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        }
        assert_eq!(netbox.writes().len(), written);
        assert_eq!(description(), json!("pve01.lab01"));
    }

    #[tokio::test]
    async fn a_run_on_a_host_that_is_no_runner_is_refused_before_anything_is_contacted() {
        // A machine renamed, or rebuilt under another name: it must not stop launching its sources in silence.
        let bench = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV);
        for args in [&[][..], &["--kind", "hypervisor"], &["--dry-run"]] {
            let ran = bench.run(&UntouchableOn(Ok("sync02.lab01")), args).await;
            assert_eq!(ran.stderr, format!("error: sync02.lab01 {NOT_A_RUNNER}\n"), "{args:?}");
            assert_eq!((ran.code, ran.stdout.as_str()), (1, ""), "{args:?}");
        }
        assert!(!bench.journal().exists());
    }

    #[tokio::test]
    async fn a_run_on_a_host_without_a_full_name_is_refused() {
        let bench = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV);
        let unnamed = UntouchableOn(Err("the system gives no full name to sat01: Name or service not known"));
        let ran = bench.run(&unnamed, &[]).await;
        assert_eq!(
            ran.stderr,
            "error: cannot tell which host of runners this one is: the system gives no full name to sat01: \
             Name or service not known\n"
        );
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
        assert!(!bench.journal().exists());
    }

    #[tokio::test]
    async fn the_short_name_of_a_runner_is_not_its_name() {
        // A system that only knows the short name gives it as the full one: two
        // writings of a host would be two hosts.
        let bench = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV);
        let ran = bench.run(&UntouchableOn(Ok("sat01")), &[]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (1, format!("error: sat01 {NOT_A_RUNNER}\n").as_str()));
        let ran = bench.run(&UntouchableOn(Ok("sat01.lab02.example.net")), &[]).await;
        assert_eq!(ran.stderr, format!("error: sat01.lab02.example.net {NOT_A_RUNNER}\n"));
    }

    #[tokio::test]
    async fn the_runner_option_replaces_the_name_of_the_host() {
        // The name of the machine is not even asked for: a lab that is asked fails the test.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN0") };
        let bench = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV);
        let ran = bench.run(&lab, &["--dry-run", "--runner", SAT01]).await;
        // The sources of that host, and theirs alone: the cluster the Proxmox reports would be created.
        assert_eq!(ran.code, 2, "{}", ran.stderr);
        assert!(ran.stdout.contains("pve-lab"), "{}", ran.stdout);
        assert_eq!(lab.asked(), [] as [&str; 0]);
        assert_eq!(lab.netbox.writes(), []);
        // A name the file does not list is refused as the one of a machine is.
        let ran = bench.run(&Untouchable, &["--dry-run", "--runner", "sat02.lab03"]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (1, format!("error: sat02.lab03 {NOT_A_RUNNER}\n").as_str()));
    }

    #[tokio::test]
    async fn the_runner_option_is_refused_without_a_list_of_runners() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV);
        let ran = bench.run(&Untouchable, &["--dry-run", "--runner", SYNC01]).await;
        assert_eq!(
            ran.stderr,
            "error: --runner names a host of runners, and the configuration lists none: one host runs every source\n"
        );
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
    }

    // A journal is the one of a machine: a run that wrote under the name of
    // another host would have the check of this one judge the sources of the
    // other, and say OK over its own.
    #[tokio::test]
    async fn the_runner_option_is_only_taken_by_a_dry_run() {
        let bench = Bench::new(&two_hosts()).with(&HYPERVISOR_ENV);
        for args in [&["--runner", SAT01][..], &["--runner", SYNC01, "--kind", "switch"]] {
            let ran = bench.run(&Untouchable, args).await;
            assert_eq!(
                ran.stderr,
                "error: --runner is only taken with --dry-run: a run that writes is the one of its machine\n",
                "{args:?}"
            );
            assert_eq!((ran.code, ran.stdout.as_str()), (1, ""), "{args:?}");
        }
        assert!(!bench.journal().exists());
    }

    #[tokio::test]
    async fn a_file_without_runners_never_asks_for_the_name_of_the_host() {
        // A file one host runs depends on no name resolution: a lab that is asked fails the test.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN0") };
        let ran = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV).run(&lab, &[]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert!(cluster_written(&lab));
        assert_eq!(lab.asked(), ["nexus01.lab01"]);
    }

    #[tokio::test]
    async fn a_run_needs_the_secrets_of_the_sources_of_its_host_alone() {
        // The Proxmox and the BMCs on the satellite; the switch, the vCenter and the firewall on the central server.
        let file = shared(&every_kind_of_source(), &["pve01.lab01", "idrac.lab01"]);
        // The satellite without any of its secrets: its own, and no other.
        let ran = Bench::new(&file).run(&UntouchableOn(Ok(SAT01)), &[]).await;
        assert_eq!(
            ran.stderr,
            "error: missing environment variables: IDRAC_LAB01_PASSWORD, IDRAC_LAB01_USERNAME, \
             PVE01_LAB01_TOKEN (or PVE01_LAB01_USERNAME and PVE01_LAB01_PASSWORD)\n"
        );
        // The central server, likewise.
        let ran = Bench::new(&file).run(&UntouchableOn(Ok(SYNC01)), &[]).await;
        assert_eq!(
            ran.stderr,
            "error: missing environment variables: FIREWALL_FW01_LAB01_PASSWORD, FIREWALL_FW01_LAB01_USERNAME, \
             SWITCH_NEXUS01_LAB01_PASSWORD or SWITCH_PASSWORD, \
             VC01_LAB01_TOKEN (or VC01_LAB01_USERNAME and VC01_LAB01_PASSWORD)\n"
        );
        // With the token of its Proxmox alone, the satellite reads it: a filter still narrows the secrets asked for.
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN0") }.on(SAT01);
        let ran = Bench::new(&file).with(&HYPERVISOR_ENV).run(&lab, &["--kind", "hypervisor"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        assert!(cluster_written(&lab));
        assert_eq!(lab.asked(), [] as [&str; 0]);
    }

    #[tokio::test]
    async fn the_netbox_token_is_needed_whatever_the_selection() {
        let bench = Bench::new(&every_kind_of_source()).with(&HYPERVISOR_ENV).without("NETBOX_TOKEN");
        let ran = bench.run(&Untouchable, &["--source", "pve01.lab01"]).await;
        assert_eq!(ran.stderr, "error: missing environment variables: NETBOX_TOKEN\n");
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
        // Told with the variables of the selected sources, in one message.
        let ran = bench.run(&Untouchable, &["--kind", "bmc"]).await;
        assert_eq!(
            ran.stderr,
            "error: missing environment variables: IDRAC_LAB01_PASSWORD, IDRAC_LAB01_USERNAME, NETBOX_TOKEN\n"
        );
    }

    #[tokio::test]
    async fn an_invalid_entry_is_refused_even_when_its_source_is_left_out() {
        let file = every_kind_of_source();
        let bench = |text: &str| Bench::new(text).with(&HYPERVISOR_ENV);
        // A hypervisor entry: a key that does not exist.
        let typo = file.replace("host = \"192.0.2.20\"\n", "host = \"192.0.2.20\"\nprunne = false\n");
        let refused = bench(&typo);
        let ran = refused.run(&Untouchable, &["--source", "pve01.lab01"]).await;
        let at = refused.config.display();
        assert_eq!(ran.stderr, format!("error: {at}: source entry 3 (vc01.lab01): unknown key 'prunne'\n"));
        assert_eq!(ran.code, 1);
        // A BMC entry: an address that is not one.
        let refused = bench(&file.replace("drac-pve01.lab01", "root@drac-pve01.lab01"));
        let ran = refused.run(&Untouchable, &["--source", "pve01.lab01"]).await;
        let at = refused.config.display();
        assert_eq!(
            ran.stderr,
            format!(
                "error: {at}: source entry 4 (idrac.lab01): \
                 the BMC of device 'pve01.lab01' must be a host name or an IPv4 address\n"
            )
        );
        // A firewall: a fingerprint that is not one.
        let short = file.replace("tls_fingerprint = \"abab", "tls_fingerprint = \"ab");
        let ran = bench(&short).run(&Untouchable, &["--source", "pve01.lab01"]).await;
        assert_eq!(
            ran.stderr,
            "error: fw01.lab01: tls_fingerprint must be the SHA-256 of the certificate \
             (64 hexadecimal digits, colons allowed)\n"
        );
        // A switch: a neighbour pattern that is not a regular expression of this tool.
        let pattern = file.replace("type = \"nxos\"\n", "type = \"nxos\"\nneighbor_pattern = \"^(?P<port>.+)$\"\n");
        let ran = bench(&pattern).run(&Untouchable, &["--source", "pve01.lab01"]).await;
        assert_eq!(ran.stderr, "error: nexus01.lab01: neighbor_pattern needs a named group 'host'\n");
    }

    // The variables are named, what the others hold never is: neither in the
    // refusal of a run, nor in the report of one that leaves sources out.
    #[tokio::test]
    async fn the_secrets_a_host_holds_are_never_printed_when_others_are_missing() {
        let file = every_kind_of_source();
        let held = [("NETBOX_TOKEN", "sentinel-token"), ("PVE01_LAB01_TOKEN", "sentinel-pve")];
        let half = [("VC01_LAB01_PASSWORD", "sentinel-vc"), ("FIREWALL_FW01_LAB01_PASSWORD", "sentinel-forti")];
        let bench = Bench::new(&file).with(&held).with(&half);
        let refused = bench.run(&Untouchable, &[]).await;
        assert_eq!(refused.code, 1);
        let lab = Lab { hypervisor: Some(pve_lab()), ..Lab::new("SN1") };
        let ran = bench.run(&lab, &["--source", "pve01.lab01"]).await;
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        let printed = format!("{}{}{}{}", refused.stdout, refused.stderr, ran.stdout, ran.stderr);
        for value in ["sentinel-token", "sentinel-pve", "sentinel-vc", "sentinel-forti"] {
            assert!(!printed.contains(value), "{value} is printed");
        }
    }

    #[tokio::test]
    async fn selecting_the_hypervisors_alone_never_runs_the_network_sources() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV);
        let lab = Lab::new("");
        let ran = bench.run(&lab, &["--kind", "hypervisor"]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stdout.contains(NOT_IMPLEMENTED), "{}", ran.stdout);
        assert_eq!(lab.asked(), [] as [&str; 0]);
        assert_eq!(lab.netbox.writes(), []);
    }

    #[tokio::test]
    async fn leaving_the_hypervisors_out_is_not_an_error() {
        let bench = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&HYPERVISOR_ENV);
        let ran = bench.run(&Lab::new("SN1"), &["--kind", "switch"]).await;
        assert_eq!(ran.code, 0);
        assert!(!ran.stdout.contains("not implemented"), "{}", ran.stdout);
    }

    #[tokio::test]
    async fn prune_deletes_what_the_device_no_longer_has() {
        let bench = Bench::new(CONFIG);
        let lab = Lab::new("SN1");
        let gone =
            lab.netbox.add("dcim.interfaces", json!({"device": lab.device, "name": "Ethernet9/9", "type": "other"}));
        assert_eq!(bench.run(&lab, &[]).await.code, 0);
        assert!(lab.netbox.row("dcim.interfaces", gone).is_some());
        assert_eq!(bench.run(&lab, &["--prune", "--dry-run"]).await.code, 2);
        assert!(lab.netbox.row("dcim.interfaces", gone).is_some());
        assert_eq!(bench.run(&lab, &["--prune"]).await.code, 0);
        assert_eq!(lab.netbox.row("dcim.interfaces", gone), None);
    }

    #[tokio::test]
    async fn the_report_is_coloured_on_a_terminal_only() {
        let bench = Bench { stdout_is_terminal: true, ..Bench::new(CONFIG) };
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert!(ran.stdout.contains("\x1b[1m"), "{:?}", ran.stdout);
        let bench = Bench { stdout_is_terminal: true, ..Bench::new(CONFIG) }.with(&[("NO_COLOR", "1")]);
        let ran = bench.run(&Lab::new("SN1"), &[]).await;
        assert!(!ran.stdout.contains('\x1b'), "{:?}", ran.stdout);
        let ran = Bench::new(CONFIG).run(&Lab::new("SN1"), &[]).await;
        assert!(!ran.stdout.contains('\x1b'), "{:?}", ran.stdout);
    }

    // The Python tool exited 2 there, the code of "changes found".
    #[tokio::test]
    async fn a_usage_error_exits_1_not_the_code_of_changes() {
        let bench = Bench::new(CONFIG);
        for args in [&["--frobnicate"][..], &["--kind", "toaster"], &["--apply"], &["--source"]] {
            let ran = bench.run(&Untouchable, args).await;
            assert_eq!(ran.code, 1, "{args:?}");
            assert!(ran.stderr.starts_with("error: "), "{}", ran.stderr);
            assert!(ran.stderr.contains(args[0]), "{}", ran.stderr);
            assert_eq!(ran.stdout, "");
        }
    }

    #[tokio::test]
    async fn without_a_command_the_help_is_shown_and_nothing_runs() {
        let bench = Bench::new(CONFIG);
        // Nothing is loaded, locked or contacted: the backend panics if asked.
        let ran = bench.run_raw(&Untouchable, &[]).await;
        // An error for a caller that forgot the command: a cron job must not pass for a sync.
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
        assert!(ran.stderr.contains("Usage: netbox-omnisync <COMMAND>"), "{}", ran.stderr);
        assert!(!bench.lock().exists());
        // The help asked for is the same text, on stdout, and no error.
        let help = bench.run_raw(&Untouchable, &["help"]).await;
        assert_eq!((help.code, help.stderr.as_str()), (0, ""));
        assert_eq!(help.stdout, ran.stderr);
        for flag in ["--help", "-h"] {
            assert_eq!(bench.run_raw(&Untouchable, &[flag]).await.stdout, help.stdout, "{flag}");
        }
    }

    #[tokio::test]
    async fn the_options_of_a_sync_without_the_command_are_refused() {
        // The form of before the commands: it must not sync, nor pass for a help.
        let bench = Bench::new(CONFIG);
        let ran = bench.run_raw(&Untouchable, &["--dry-run"]).await;
        assert_eq!((ran.code, ran.stdout.as_str()), (1, ""));
        assert!(ran.stderr.starts_with("error: unexpected argument '--dry-run' found"), "{}", ran.stderr);
        assert!(!bench.lock().exists());
    }

    #[tokio::test]
    async fn the_version_command_prints_the_version() {
        let bench = Bench::new(CONFIG);
        for form in ["version", "--version", "-V"] {
            let ran = bench.run_raw(&Untouchable, &[form]).await;
            assert_eq!(
                (ran.code, ran.stdout.as_str(), ran.stderr.as_str()),
                (0, "netbox-omnisync 0.5.0\n", ""),
                "{form}"
            );
        }
        // No lock: a run in progress does not hide the version.
        assert!(!bench.lock().exists());
    }

    #[tokio::test]
    async fn the_licenses_command_prints_the_licence_of_the_tool_and_touches_nothing() {
        let bench = Bench::new(CONFIG);
        // Nothing is loaded, locked or contacted: the backend panics if asked.
        let ran = bench.run_raw(&Untouchable, &["licenses"]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
        let mut lines = ran.stdout.lines();
        assert_eq!(lines.next(), Some("netbox-omnisync 0.5.0, licensed under MIT OR Apache-2.0, at your option."));
        // Both texts, in full: the binary travels without the repository.
        assert!(ran.stdout.contains("Permission is hereby granted, free of charge"), "{}", ran.stdout);
        assert!(ran.stdout.contains("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"), "{}", ran.stdout);
        assert!(!bench.lock().exists());
    }

    #[test]
    fn the_licenses_end_with_the_third_party_notices_a_release_embeds() {
        let notices = "netbox-omnisync includes the following third-party software.\n- MIT License: 2 crate(s)\n";
        let text = licenses("0.1.0", notices);
        assert!(text.ends_with(notices), "{text}");
        assert!(!text.contains("not embedded"), "{text}");
    }

    #[test]
    fn a_build_without_the_notices_says_so() {
        // `cargo build` embeds none: only a release build generates them.
        let text = licenses("0.1.0", "");
        let last = text.lines().last().expect("a last line");
        assert_eq!(
            last,
            "The third-party notices are not embedded in this build: a release carries them (THIRD-PARTY-NOTICES.txt)."
        );
    }

    #[tokio::test]
    async fn the_help_fits_one_screen_and_says_how_to_start() {
        let bench = Bench::new(CONFIG);
        let help = bench.run_raw(&Untouchable, &["help"]).await.stdout;
        // The commands, the options of a sync by what they are for, then how
        // to start and what the code means.
        let headings: Vec<&str> = help.lines().filter(|line| line.ends_with(':') && !line.starts_with(' ')).collect();
        assert_eq!(headings, ["Commands:", "Sync sources:", "Sync options:", "Examples:", "Exit codes:"], "{help}");
        for command in ["  sync ", "  check ", "  digest ", "  version ", "  licenses ", "  completions ", "  help "] {
            assert!(help.contains(command), "{command}\n{help}");
        }
        for flag in
            ["--config <FILE>", "--kind <KIND>", "--type <TYPE>", "--source <NAME>", "--dry-run", "--prune", "--quiet"]
        {
            assert!(help.contains(flag), "{flag} is not in the help");
        }
        // The one screen has no line for the option of a host that is not itself: the help of a sync tells it.
        assert!(!help.contains("--runner"), "{help}");
        // The values a filter takes are on its line.
        assert!(help.contains("hypervisor, bmc, switch, router, firewall"), "{help}");
        assert!(help.contains("vmware, proxmox, redfish, ios, nxos, nipper, fortios"), "{help}");
        // The first thing to try, and the code that surprises.
        assert!(help.contains("netbox-omnisync sync --dry-run"), "{help}");
        assert!(help.contains("  2  --dry-run found changes"), "{help}");
        // A 80×24 terminal shows the options without scrolling, and folds no line.
        let widest = help.lines().map(|line| line.chars().count()).max().unwrap_or(0);
        assert!(widest <= 80, "a line of {widest} columns\n{help}");
        let examples = help.lines().position(|line| line == "Examples:").expect("the examples");
        assert!(examples <= 24, "the options end at line {examples}\n{help}");
        // Not a terminal: no escape sequence.
        assert!(!help.contains('\u{1b}'), "{help}");
    }

    #[tokio::test]
    async fn the_help_of_a_sync_shows_its_options() {
        let bench = Bench::new(CONFIG);
        let ran = bench.run_raw(&Untouchable, &["sync", "--help"]).await;
        assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
        assert!(ran.stdout.contains("Usage: netbox-omnisync sync [OPTIONS]"), "{}", ran.stdout);
        assert!(ran.stdout.contains("-n, --dry-run"), "{}", ran.stdout);
        // The option no everyday run takes is told here, with the filters it goes with.
        let runner =
            "      --runner <HOST>  With --dry-run: as this host of runners, not as this machine\n\nSync options:";
        assert!(ran.stdout.contains(runner), "{}", ran.stdout);
        assert_eq!(bench.run_raw(&Untouchable, &["help", "sync"]).await.stdout, ran.stdout);
    }

    #[tokio::test]
    async fn the_help_is_coloured_on_a_terminal_that_takes_colours() {
        let mut bench = Bench::new(CONFIG);
        bench.stdout_is_terminal = true;
        let help = bench.run_raw(&Untouchable, &["help"]).await.stdout;
        assert!(help.contains("\u{1b}["), "{help}");
        let bench = bench.with(&[("NO_COLOR", "1")]);
        let help = bench.run_raw(&Untouchable, &["help"]).await.stdout;
        assert!(!help.contains('\u{1b}'), "{help}");
    }

    #[test]
    fn the_common_flags_have_a_short_form() {
        let long = parse(&[
            "--dry-run",
            "--quiet",
            "--config",
            "lab.toml",
            "--kind",
            "switch",
            "--type",
            "nxos",
            "--source",
            "nexus01.lab01",
        ]);
        let short = parse(&["-n", "-q", "-c", "lab.toml", "-k", "switch", "-t", "nxos", "-s", "nexus01.lab01"]);
        assert_eq!(short, long);
        assert!(long.dry_run && long.quiet);
    }

    #[tokio::test]
    async fn a_report_that_cannot_be_written_is_an_error() {
        let bench = Bench::new(CONFIG);
        let lab = Lab::new("");
        let stderr = Buffer::default();
        let mut terminal =
            Terminal { stdout: Closed, stderr: stderr.clone(), stdout_is_terminal: false, stderr_is_terminal: false };
        let code = run(bench.argv(&[]), &bench.environ(), &mut terminal, &lab, pending()).await;
        assert_eq!(code, 1);
        assert!(stderr.text().contains("error: cannot write the report: "), "{}", stderr.text());
        // The run itself went through.
        assert_eq!(lab.serial(), "SN1");
    }

    #[tokio::test]
    async fn no_secret_is_ever_printed() {
        let secrets = [
            ("NETBOX_TOKEN", "token-value"),
            ("PVE01_LAB01_PASSWORD", "pve-password"),
            ("PVE01_LAB01_TOKEN", "pve-secret"),
        ];
        let values = ["token-value", "pve-password", "pve-secret", "pw-forti"];
        // A configuration error, an error of this build, and a run that works.
        let refused = Bench::new(&format!("{CONFIG}{HYPERVISOR}")).with(&secrets);
        let ran = refused.run(&Untouchable, &[]).await;
        assert_eq!(ran.code, 1);
        assert_eq!(
            ran.stderr,
            format!(
                "error: {}: source entry 2 (pve01.lab01): set PVE01_LAB01_PASSWORD or PVE01_LAB01_TOKEN, not both\n",
                refused.config.display()
            )
        );
        let mut printed = format!("{}{}", ran.stdout, ran.stderr);
        let unbuilt = Bench::new(&format!("{CONFIG}{HYPERVISOR}{FIREWALL}")).with(&secrets[..2]).with(&FIREWALL_ENV);
        let unbuilt = unbuilt.with(&[("PVE01_LAB01_USERNAME", "sync@pve")]);
        let ran = unbuilt.run(&Lab::new(""), &[]).await;
        assert_eq!(ran.code, 1);
        printed.push_str(&ran.stdout);
        printed.push_str(&ran.stderr);
        for value in values {
            assert!(!printed.contains(value), "{value} is printed");
        }
    }

    /// The real clients of NetBox and of a hypervisor, the latter pointed at
    /// a fake one that does not speak TLS; devices that answer without a network.
    struct Wired {
        /// The URL of the fake Proxmox or vCenter.
        hypervisor: String,
    }

    /// The configuration of a test whose NetBox is the mock `server`, which
    /// answers `/api/status/` as NetBox 4.7.5 does, and an empty schema.
    async fn netbox_at(server: &MockServer, config: &str) -> String {
        let status = json!({"netbox-version": "4.7.5"});
        Mock::given(method("GET"))
            .and(path("/api/status/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(status))
            .mount(server)
            .await;
        // A schema with no operation: enough for a run that stops before writing.
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"paths": {}})))
            .mount(server)
            .await;
        config.replace("https://netbox.example", &server.uri())
    }

    /// Reads a hypervisor as the tool does, at another URL, with the real reverse DNS lookups.
    struct OverHttp(String, ReverseLookups);

    impl Reader for OverHttp {
        async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
            self.read_hearing(source, false).await
        }

        async fn read_hearing(&self, source: &Hypervisor, neighbours: bool) -> Result<Reading, String> {
            match source.r#type {
                HypervisorType::Proxmox => hypervisors::read_proxmox_at(source, &self.0, &self.1).await,
                HypervisorType::Vmware => {
                    hypervisors::read_vmware_hearing_at(source, &self.0, &self.1, neighbours).await
                }
                HypervisorType::Redfish => hypervisors::read_redfish_at(source, &|_| self.0.clone()).await,
            }
        }

        fn warnings(&self) -> Vec<String> {
            self.1.warning().into_iter().collect()
        }
    }

    impl Backend for Wired {
        type Gateway = NetboxClient;
        type Collector = Probe;
        type Reader = OverHttp;

        fn gateway(&self, netbox: &Netbox, dry_run: bool) -> Result<NetboxClient, GatewayError> {
            Production.gateway(netbox, dry_run)
        }

        fn collector(&self, _environ: &Environ) -> Result<Probe, CollectorError> {
            Ok(Probe { asked: Arc::default(), stuck: None })
        }

        fn reader(&self, _environ: &Environ) -> OverHttp {
            OverHttp(self.hypervisor.clone(), ReverseLookups::system())
        }
    }

    /// The fake NetBox of a [`Lab`], and a vCenter read as the tool reads one, at another URL.
    struct Vsphere {
        lab: Lab,
        vcenter: String,
    }

    impl Backend for Vsphere {
        type Gateway = Handle;
        type Collector = Probe;
        type Reader = OverHttp;

        fn gateway(&self, netbox: &Netbox, dry_run: bool) -> Result<Handle, GatewayError> {
            self.lab.gateway(netbox, dry_run)
        }

        fn collector(&self, environ: &Environ) -> Result<Probe, CollectorError> {
            self.lab.collector(environ)
        }

        fn reader(&self, _environ: &Environ) -> OverHttp {
            OverHttp(self.vcenter.clone(), ReverseLookups::system())
        }
    }

    /// A vCenter entry with the settings of production, under made-up names;
    /// the fixtures were anonymised into 198.18.0.0/15.
    fn vcenter_entry(port: u16) -> String {
        format!(
            "\n[[sources]]\nname = \"vc01.lab01\"\nkind = \"hypervisor\"\ntype = \"vmware\"\nhost = \"127.0.0.1\"\n\
             port = {port}\nvalidate_certs = false\nsite = \"Harbor\"\ntenant = \"Example Tenant\"\n\
             host_role = \"Hypervisor ESX\"\nvm_role = \"Virtual Machine ESX\"\n\
             permitted_subnets = [\"198.18.0.0/15\"]\n"
        )
    }

    const VCENTER_ENV: [(&str, &str); 2] =
        [("VC01_LAB01_USERNAME", "0perator-never-shown@vsphere.local"), ("VC01_LAB01_PASSWORD", "s3ntinel pass&word<")];

    #[tokio::test]
    async fn a_vcenter_is_synced_end_to_end_and_a_second_run_finds_nothing_to_change() {
        // The recorded answers of a vCenter 6.7: 6 hosts, 166 machines, 28 tags.
        let server = vcenter::vcenter("6.7").await;
        let bench = Bench::new(&format!("{CONFIG}{}", vcenter_entry(server.address().port()))).with(&VCENTER_ENV);
        let backend = Vsphere { lab: Lab::new("SN1"), vcenter: server.uri() };
        let ran = bench.run(&backend, &["--type", "vmware"]).await;
        // The two homonyms left out are warnings, not errors.
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert!(ran.stdout.contains("skipping vm vm041.lab.example (vm-5366)"), "{}", ran.stdout);
        let netbox = &backend.lab.netbox;
        let id = |endpoint: &str, field: &str, value: &str| {
            netbox.find(endpoint, field, &json!(value)).unwrap_or_else(|| panic!("{endpoint} {value} written"))
        };
        // host-10: `esx04.lab.example`, a PowerEdge FC430 whose `SerialNumberTag` is ID00016.
        let device = netbox.row("dcim.devices", id("dcim.devices", "name", "esx04.lab.example")).unwrap();
        assert_eq!(device["serial"], json!("ID00016"));
        assert_eq!(device["device_type"], json!(id("dcim.device_types", "model", "PowerEdge FC430")));
        assert_eq!(device["site"], json!(id("dcim.sites", "name", "Harbor")));
        assert_eq!(device["role"], json!(id("dcim.device_roles", "name", "Hypervisor ESX")));
        // Its vmk0 holds 198.18.0.36/24, on the port group `Management Network`: its primary address.
        assert_eq!(device["primary_ip4"], json!(id("ipam.ip_addresses", "address", "198.18.0.36/24")));
        // vm-342: `vm076.lab.example` carries the vSphere tag `service-rabbit`, and is owned by the tool
        // and by its source.
        let machine = id("virtualization.virtual_machines", "name", "vm076.lab.example");
        let machine = netbox.row("virtualization.virtual_machines", machine).unwrap();
        let mut tags: Vec<u64> = machine["tags"].as_array().unwrap().iter().map(|tag| tag.as_u64().unwrap()).collect();
        tags.sort_unstable();
        let mut expected =
            ["netbox-omnisync", "source-vc01lab01", "service-rabbit"].map(|name| id("extras.tags", "name", name));
        expected.sort_unstable();
        assert_eq!(tags, expected);
        assert_eq!(machine["device"], json!(id("dcim.devices", "name", "esx04.lab.example")));
        assert_eq!(machine["tenant"], json!(id("tenancy.tenants", "name", "Example Tenant")));
        // The account left with the login, and was printed nowhere.
        let printed = format!("{}{}", ran.stdout, ran.stderr);
        assert!(!printed.contains("0perator") && !printed.contains("s3ntinel"), "{printed}");

        // The same vCenter again: nothing differs, which a dry run tells by its exit code.
        let writes = netbox.writes().len();
        let again = bench.run(&backend, &["--type", "vmware", "--dry-run"]).await;
        assert_eq!(again.code, 0, "{}{}", again.stdout, again.stderr);
        assert_eq!(netbox.writes().len(), writes);
        // The switch of the same file was left out by the filter.
        assert_eq!(backend.lab.asked(), Vec::<String>::new());
    }

    /// The `QueryNetworkHint` requests a vCenter received.
    async fn hints_asked(server: &MockServer) -> usize {
        let requests = server.received_requests().await.unwrap();
        requests
            .iter()
            .filter(|request| String::from_utf8_lossy(&request.body).contains("<vim25:QueryNetworkHint>"))
            .count()
    }

    #[tokio::test]
    async fn a_run_of_the_hypervisors_alone_never_asks_for_the_hints() {
        let server = vcenter::vcenter("6.7").await;
        let bench = Bench::new(&format!("{CONFIG}{}", vcenter_entry(server.address().port()))).with(&VCENTER_ENV);
        let backend = Vsphere { lab: Lab::new("SN1"), vcenter: server.uri() };
        let ran = bench.run(&backend, &["--kind", "hypervisor", "--dry-run"]).await;
        assert!(ran.code == 0 || ran.code == 2, "{}{}", ran.stdout, ran.stderr);
        assert_eq!(hints_asked(&server).await, 0);
        // With the switches, each of the six hosts is asked what its cards hear.
        let ran = bench.run(&backend, &["--kind", "hypervisor", "--kind", "switch", "--dry-run"]).await;
        assert!(ran.code == 0 || ran.code == 2, "{}{}", ran.stdout, ran.stderr);
        assert_eq!(hints_asked(&server).await, 6);
        assert_eq!(backend.lab.asked(), ["nexus01.lab01"]);
    }

    // The BMC sources, end to end

    /// A local URL nothing listens on.
    const UNREACHABLE: &str = "http://127.0.0.1:1";

    /// Reads each source as the tool does, at the URL of its fake: a Proxmox
    /// VE or a vCenter, and one BMC per address. A BMC that has no fake is unreachable.
    struct Routed {
        hypervisor: String,
        lookups: ReverseLookups,
        bmcs: std::collections::BTreeMap<String, String>,
    }

    impl Reader for Routed {
        async fn read(&self, source: &Hypervisor) -> Result<Reading, String> {
            let bmc = |host: &str| self.bmcs.get(host).cloned().unwrap_or_else(|| UNREACHABLE.to_owned());
            match source.r#type {
                HypervisorType::Proxmox => hypervisors::read_proxmox_at(source, &self.hypervisor, &self.lookups).await,
                HypervisorType::Vmware => hypervisors::read_vmware_at(source, &self.hypervisor, &self.lookups).await,
                HypervisorType::Redfish => hypervisors::read_redfish_at(source, &bmc).await,
            }
        }

        fn warnings(&self) -> Vec<String> {
            self.lookups.warning().into_iter().collect()
        }
    }

    /// The fake NetBox of a [`Lab`], with a hypervisor (a Proxmox VE, or a vCenter) and BMCs
    /// served from their fixtures.
    struct ServerRoom {
        lab: Lab,
        hypervisor: MockServer,
        /// Address of a BMC, as the configuration names it -> its fake.
        bmcs: Vec<(&'static str, MockServer)>,
    }

    impl ServerRoom {
        /// The Proxmox VE 9.2 fixture (nodes `pve01` and `pve02`) and a BMC per address, each
        /// answering from the fixture of a family.
        async fn new<const N: usize>(bmcs: [(&'static str, &str); N]) -> Self {
            let proxmox = crate::fake_pve::serve(crate::fake_pve::fixture("9.2")).await;
            let mut served = Vec::new();
            for (host, family) in bmcs {
                served.push((host, crate::fake_bmc::bmc(family).await));
            }
            ServerRoom::around(proxmox, served)
        }

        /// A room around a hypervisor and BMCs that are already served.
        fn around(hypervisor: MockServer, bmcs: Vec<(&'static str, MockServer)>) -> Self {
            let lab = Lab::new("SN1");
            ServerRoom { lab, hypervisor, bmcs }
        }

        /// The configuration of the room: the switch of [`CONFIG`], the Proxmox VE and the BMCs
        /// of `devices`, named after the convention; `netbox` is added to the `[netbox]` block.
        fn bench(&self, netbox: &str, devices: &[&str]) -> Bench {
            let config = CONFIG.replacen(
                "url = \"https://netbox.example\"\n",
                &format!("url = \"https://netbox.example\"\n{netbox}"),
                1,
            );
            let listed: Vec<String> = devices.iter().map(|device| format!("\"{device}\"")).collect();
            let sources = format!(
                "\n[[sources]]\nname = \"pve.lab01\"\nkind = \"hypervisor\"\ntype = \"proxmox\"\nhost = \"127.0.0.1\"\n\
                 port = {}\nsite = \"Paris\"\ndomain = \"lab01\"\n\
                 \n[[sources]]\nname = \"bmc.lab01\"\nkind = \"bmc\"\ntype = \"redfish\"\nvalidate_certs = false\n\
                 devices = [{}]\nbmc_pattern = \"drac-{{name}}\"\n",
                self.hypervisor.address().port(),
                listed.join(", ")
            );
            Bench::new(&format!("{config}{sources}")).with(&[
                ("PVE_LAB01_USERNAME", "sync@pve"),
                ("PVE_LAB01_PASSWORD", "the-password"),
                ("BMC_LAB01_USERNAME", crate::fake_bmc::USER),
                ("BMC_LAB01_PASSWORD", crate::fake_bmc::PASSWORD),
            ])
        }

        /// How many requests the BMCs received, all together.
        async fn bmc_requests(&self) -> usize {
            let mut requests = 0;
            for (_, server) in &self.bmcs {
                requests += server.received_requests().await.unwrap().len();
            }
            requests
        }

        fn device(&self, name: &str) -> u64 {
            self.lab.netbox.find("dcim.devices", "name", &json!(name)).unwrap_or_else(|| panic!("device {name}"))
        }

        /// The model of the device type and the serial NetBox holds for a device.
        fn hardware(&self, name: &str) -> (String, String) {
            let row = self.lab.netbox.row("dcim.devices", self.device(name)).unwrap();
            let device_type = self.lab.netbox.row("dcim.device_types", row["device_type"].as_u64().unwrap()).unwrap();
            let serial = row.get("serial").and_then(|serial| serial.as_str()).unwrap_or_default();
            (device_type["model"].as_str().unwrap().to_owned(), serial.to_owned())
        }

        /// Documents, by hand, the MAC address of a card of a device: an interface nobody owns.
        fn document_mac(&self, device: &str, mac: &str) {
            let fields = json!({"device": self.device(device), "name": "mgmt0", "type": "other"});
            let interface = self.lab.netbox.add("dcim.interfaces", fields);
            let assigned =
                json!({"mac_address": mac, "assigned_object_type": "dcim.interface", "assigned_object_id": interface});
            self.lab.netbox.add("dcim.mac_addresses", assigned);
        }

        /// A server made by hand, with the type and the serial given, and the MAC address of one card.
        fn add_server(&self, name: &str, model: &str, serial: &str, mac: &str) {
            let netbox = &self.lab.netbox;
            let maker = netbox.add("dcim.manufacturers", json!({"name": format!("Maker of {name}"), "slug": name}));
            let device_type =
                netbox.add("dcim.device_types", json!({"model": model, "slug": name, "manufacturer": maker}));
            netbox.add("dcim.devices", json!({"name": name, "site": 12, "device_type": device_type, "serial": serial}));
            self.document_mac(name, mac);
        }
    }

    impl Backend for ServerRoom {
        type Gateway = Handle;
        type Collector = Probe;
        type Reader = Routed;

        fn gateway(&self, netbox: &Netbox, dry_run: bool) -> Result<Handle, GatewayError> {
            self.lab.gateway(netbox, dry_run)
        }

        fn collector(&self, environ: &Environ) -> Result<Probe, CollectorError> {
            self.lab.collector(environ)
        }

        fn reader(&self, _environ: &Environ) -> Routed {
            let bmcs = self.bmcs.iter().map(|(host, server)| ((*host).to_owned(), server.uri())).collect();
            Routed { hypervisor: self.hypervisor.uri(), lookups: ReverseLookups::system(), bmcs }
        }
    }

    /// A Proxmox VE source and a BMC source report the same two hosts: each host ends with the
    /// device type and the serial its BMC gives, and no later run moves anything, whoever runs.
    async fn the_bmcs_complete_the_hosts_of_a_proxmox(netbox_block: &str) {
        // idrac8-2.86.86.86: "Model": "PowerEdge R630", "SKU": "878X8Z3", cards "02:00:00:00:00:0E" …
        // ilo4-2.82: "Model": "ProLiant DL360 Gen9", "SerialNumber": "CBQ260112M",
        //            "HostMACAddress": ["02:00:00:00:00:1e", …], "HostName": "corp-siteb-pve02"
        let room =
            ServerRoom::new([("drac-pve01.lab01", "idrac8-2.86.86.86"), ("drac-pve02.lab01", "ilo4-2.82")]).await;
        let bench = room.bench(netbox_block, &["pve01.lab01", "pve02.lab01"]);

        // The hypervisors alone, as every five minutes: the hosts are created, with what Proxmox knows.
        let ran = bench.run(&room, &["--kind", "hypervisor"]).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert_eq!(room.hardware("pve01.lab01"), ("Generic Model".to_owned(), String::new()));
        assert_eq!(room.hardware("pve02.lab01"), ("Generic Model".to_owned(), String::new()));
        // No BMC was read.
        assert_eq!(room.bmc_requests().await, 0);

        // The BMCs alone: NetBox holds no MAC address of these hosts yet, so nothing proves which
        // server each BMC manages, and nothing is written.
        let writes = room.lab.netbox.writes().len();
        let ran = bench.run(&room, &["--kind", "bmc"]).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert!(
            ran.stdout.contains(
                "bmc.lab01: device pve01.lab01: NetBox holds no MAC address on its interfaces yet: BMC \
                 drac-pve01.lab01 cannot be checked against it; nothing is written for it"
            ),
            "{}",
            ran.stdout
        );
        assert_eq!(room.lab.netbox.writes().len(), writes);
        assert!(room.bmc_requests().await > 0);

        // Somebody documents one card of each host, in a letter case of his own.
        room.document_mac("pve01.lab01", "02:00:00:00:00:0e");
        room.document_mac("pve02.lab01", "02:00:00:00:00:1F");

        // Every source at once.
        let ran = bench.run(&room, &[]).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert_eq!(room.hardware("pve01.lab01"), ("PowerEdge R630".to_owned(), "878X8Z3".to_owned()));
        assert_eq!(room.hardware("pve02.lab01"), ("ProLiant DL360 Gen9".to_owned(), "CBQ260112M".to_owned()));
        // The two sources never disagreed: Proxmox only has a fallback for the device type.
        assert!(!ran.stdout.contains("reported differently"), "{}", ran.stdout);
        // The host name the iLO was told is a warning, not a refusal.
        assert!(
            ran.stdout.contains(
                "bmc.lab01: device pve02.lab01: BMC drac-pve02.lab01 says its server is named corp-siteb-pve02"
            ),
            "{}",
            ran.stdout
        );
        // The hosts stay the hypervisor's: the BMC source put its tag on what it created, not on them.
        let tag = |name: &str| room.lab.netbox.find("extras.tags", "name", &json!(name)).expect("tag written");
        let tags = room.lab.netbox.row("dcim.devices", room.device("pve01.lab01")).unwrap()["tags"].clone();
        assert_eq!(tags, json!([tag("netbox-omnisync"), tag("source-pvelab01")]));
        let r630 = room.lab.netbox.find("dcim.device_types", "model", &json!("PowerEdge R630")).unwrap();
        let tags = room.lab.netbox.row("dcim.device_types", r630).unwrap()["tags"].clone();
        assert_eq!(tags, json!([tag("netbox-omnisync"), tag("source-bmclab01")]));
        // The account of the BMCs was printed nowhere.
        let printed = format!("{}{}", ran.stdout, ran.stderr);
        assert!(!printed.contains("0perator") && !printed.contains("s3ntinel"), "{printed}");

        // Then every combination again: nothing differs, which a dry run tells by its exit code.
        let writes = room.lab.netbox.writes().len();
        for filters in
            [&[][..], &["--kind", "hypervisor"], &["--kind", "bmc"], &["--kind", "hypervisor", "--kind", "bmc"]]
        {
            let mut args = filters.to_vec();
            args.push("--dry-run");
            let again = bench.run(&room, &args).await;
            assert_eq!(again.code, 0, "{filters:?}: {}{}", again.stdout, again.stderr);
            let again = bench.run(&room, filters).await;
            assert_eq!(again.code, 0, "{filters:?}: {}{}", again.stdout, again.stderr);
            assert_eq!(room.lab.netbox.writes().len(), writes, "{filters:?}");
        }
        assert_eq!(room.hardware("pve01.lab01"), ("PowerEdge R630".to_owned(), "878X8Z3".to_owned()));
        assert_eq!(room.hardware("pve02.lab01"), ("ProLiant DL360 Gen9".to_owned(), "CBQ260112M".to_owned()));
    }

    #[tokio::test]
    async fn a_proxmox_and_its_bmcs_settle_on_the_hardware_of_the_bmc_without_source_priority() {
        the_bmcs_complete_the_hosts_of_a_proxmox("").await;
    }

    #[tokio::test]
    async fn a_proxmox_and_its_bmcs_settle_on_the_hardware_of_the_bmc_whichever_source_is_ranked_first() {
        the_bmcs_complete_the_hosts_of_a_proxmox("source_priority = [\"pve.lab01\", \"bmc.lab01\"]\n").await;
        the_bmcs_complete_the_hosts_of_a_proxmox("source_priority = [\"bmc.lab01\", \"pve.lab01\"]\n").await;
    }

    /// The vCenter 6.7 fixture and the BMC of its host `esx04.lab.example`, which answers what
    /// the iDRAC 8 of a blade of the same model answered, with `service_tag` as its service tag.
    ///
    /// The two recordings were anonymised apart: nothing ties the serial of the one to the
    /// service tag of the other, so the test sets it.
    async fn vcenter_room(service_tag: &str) -> ServerRoom {
        // idrac8-2.83.83.83: "Manufacturer": "Dell Inc.", "Model": "PowerEdge FC430", "SKU": "8RQZLZ7"
        let mut answers = crate::fake_bmc::fixture("idrac8-2.83.83.83");
        let system = answers.get_mut("/redfish/v1/Systems/System.Embedded.1").expect("the system");
        assert_eq!(system.1["SKU"], json!("8RQZLZ7"));
        system.1["SKU"] = json!(service_tag);
        let bmc = crate::fake_bmc::serve(answers).await;
        ServerRoom::around(vcenter::vcenter("6.7").await, vec![("drac-esx04.lab.example", bmc)])
    }

    /// The vCenter of [`vcenter_entry`] and the BMC of one of its hosts.
    fn vcenter_bench(room: &ServerRoom, netbox_block: &str) -> Bench {
        let config = CONFIG.replacen(
            "url = \"https://netbox.example\"\n",
            &format!("url = \"https://netbox.example\"\n{netbox_block}"),
            1,
        );
        let bmcs = "\n[[sources]]\nname = \"bmc.lab01\"\nkind = \"bmc\"\ntype = \"redfish\"\nvalidate_certs = false\n\
                    devices = [\"esx04.lab.example\"]\nbmc_pattern = \"drac-{name}\"\n";
        Bench::new(&format!("{config}{}{bmcs}", vcenter_entry(room.hypervisor.address().port())))
            .with(&VCENTER_ENV)
            .with(&[("BMC_LAB01_USERNAME", crate::fake_bmc::USER), ("BMC_LAB01_PASSWORD", crate::fake_bmc::PASSWORD)])
    }

    #[tokio::test]
    async fn a_vcenter_and_the_bmc_of_its_host_name_the_same_hardware_and_say_nothing() {
        // host-10 of the vCenter: `esx04.lab.example`, <vendor>Dell Inc.</vendor><model>PowerEdge FC430</model>,
        // identifier `ServiceTag`: ID00016. The BMC gives the same service tag in `SKU`.
        let room = vcenter_room("ID00016").await;
        let bench = vcenter_bench(&room, "");
        let ran = bench.run(&room, &["--type", "vmware"]).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert_eq!(room.hardware("esx04.lab.example"), ("PowerEdge FC430".to_owned(), "ID00016".to_owned()));
        // NIC.Embedded.1-1-1 of the BMC: "MACAddress": "02:00:00:00:00:09"; documented by hand on the host.
        room.document_mac("esx04.lab.example", "02:00:00:00:00:09");

        let ran = bench.run(&room, &["--kind", "hypervisor", "--kind", "bmc"]).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        // One manufacturer and one device type for both sources, and no difference between them.
        assert!(!ran.stdout.contains("reported differently"), "{}", ran.stdout);
        assert_eq!(room.hardware("esx04.lab.example"), ("PowerEdge FC430".to_owned(), "ID00016".to_owned()));
        // `Dell Inc.` was written as `Dell` by the vCenter, and never a second time under another name.
        let netbox = &room.lab.netbox;
        assert!(netbox.find("dcim.manufacturers", "name", &json!("Dell Inc.")).is_none());
        let dell = netbox.find("dcim.manufacturers", "name", &json!("Dell")).expect("manufacturer written");
        let fc430 = netbox.find("dcim.device_types", "model", &json!("PowerEdge FC430")).expect("type written");
        // The BMC source needs both and says so with its tag, next to the vCenter's: neither is
        // deleted under the device the day the vCenter stops reporting that model.
        let tag = |name: &str| netbox.find("extras.tags", "name", &json!(name)).expect("tag written");
        let mut expected = ["netbox-omnisync", "source-vc01lab01", "source-bmclab01"].map(tag);
        expected.sort_unstable();
        for (endpoint, id) in [("dcim.manufacturers", dell), ("dcim.device_types", fc430)] {
            let tags = netbox.row(endpoint, id).unwrap()["tags"].clone();
            let mut held: Vec<u64> = tags.as_array().unwrap().iter().map(|tag| tag.as_u64().unwrap()).collect();
            held.sort_unstable();
            assert_eq!(held, expected, "{endpoint}");
        }
        // The host itself stays the vCenter's.
        let tags = netbox.row("dcim.devices", room.device("esx04.lab.example")).unwrap()["tags"].clone();
        assert!(!tags.as_array().unwrap().contains(&json!(tag("source-bmclab01"))), "{tags}");

        // Then nothing moves, whoever runs.
        let writes = room.lab.netbox.writes().len();
        for filters in [&["--kind", "hypervisor", "--kind", "bmc"][..], &["--type", "vmware"], &["--kind", "bmc"]] {
            let again = bench.run(&room, filters).await;
            assert_eq!(again.code, 0, "{filters:?}: {}{}", again.stdout, again.stderr);
            assert_eq!(room.lab.netbox.writes().len(), writes, "{filters:?}");
        }
    }

    #[tokio::test]
    async fn a_vcenter_and_a_bmc_that_differ_on_a_serial_leave_the_one_of_the_bmc() {
        // The vCenter says ID00016 (`ServiceTag` of host-10); the BMC says another service tag.
        // Whatever the ranking, the BMC tells the hardware of a device it documents.
        for ranking in [
            "source_priority = [\"vc01.lab01\", \"bmc.lab01\"]\n",
            "source_priority = [\"bmc.lab01\", \"vc01.lab01\"]\n",
            "",
        ] {
            let room = vcenter_room("OTHER01").await;
            let bench = vcenter_bench(&room, ranking);
            assert_eq!(bench.run(&room, &["--type", "vmware"]).await.code, 0);
            room.document_mac("esx04.lab.example", "02:00:00:00:00:09");
            let ran = bench.run(&room, &["--kind", "hypervisor", "--kind", "bmc"]).await;
            assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
            // Not a disagreement to arbitrate: the vCenter only fills what is empty.
            assert!(!ran.stdout.contains("reported differently"), "{ranking}: {}", ran.stdout);
            assert_eq!(
                room.hardware("esx04.lab.example"),
                ("PowerEdge FC430".to_owned(), "OTHER01".to_owned()),
                "{ranking}"
            );
            // The vCenter alone, as every five minutes, then both again: nothing is written back.
            let writes = room.lab.netbox.writes().len();
            assert_eq!(bench.run(&room, &["--type", "vmware"]).await.code, 0);
            assert_eq!(bench.run(&room, &["--kind", "hypervisor", "--kind", "bmc"]).await.code, 0);
            assert_eq!(room.lab.netbox.writes().len(), writes, "{ranking}");
        }
    }

    #[tokio::test]
    async fn a_run_of_the_bmcs_alone_creates_no_custom_field() {
        let room = ServerRoom::new([("drac-pve01.lab01", "idrac8-2.83.83.83")]).await;
        // NIC.Embedded.1-1-1 of the BMC: "MACAddress": "02:00:00:00:00:09"; documented by hand on the server.
        room.add_server("pve01.lab01", "By hand", "", "02:00:00:00:00:09");
        let bench = room.bench("", &["pve01.lab01"]);
        let ran = bench.run(&room, &["--kind", "bmc"]).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        // The BMC completed its device: "Model": "PowerEdge FC430", "SKU": "8RQZLZ7".
        assert_eq!(room.hardware("pve01.lab01"), ("PowerEdge FC430".to_owned(), "8RQZLZ7".to_owned()));
        // A BMC fills no custom field: none is defined for it.
        for name in ["source", "source_id", "host_cpu_cores", "host_memory", "arp_entry"] {
            assert!(room.lab.netbox.find("extras.custom_fields", "name", &json!(name)).is_none(), "{name}");
        }
    }

    #[tokio::test]
    async fn only_a_run_that_asks_for_the_bmcs_reads_them() {
        let room = ServerRoom::new([("drac-pve01.lab01", "idrac8-2.83.83.83")]).await;
        let bench = room.bench("", &["pve01.lab01"]);
        // The hypervisors, by kind or by type, and the network sources: no BMC is contacted.
        for filters in
            [&["--kind", "hypervisor"][..], &["--type", "proxmox"], &["--kind", "switch"], &["--source", "pve.lab01"]]
        {
            let ran = bench.run(&room, filters).await;
            assert_eq!(ran.code, 0, "{filters:?}: {}{}", ran.stdout, ran.stderr);
            assert_eq!(room.bmc_requests().await, 0, "{filters:?}");
        }
        // By its kind, its type, its name, or without filter: the BMC is read each time. The
        // recording of idrac8-2.83.83.83 is seven answers (the_collection_only_ever_reads…).
        let mut expected = 0;
        for filters in [&["--kind", "bmc"][..], &["--type", "redfish"], &["--source", "bmc.lab01"], &[]] {
            let ran = bench.run(&room, filters).await;
            assert_eq!(ran.code, 0, "{filters:?}: {}{}", ran.stdout, ran.stderr);
            expected += 7;
            assert_eq!(room.bmc_requests().await, expected, "{filters:?}");
        }
        // Selected alone, it runs neither the hypervisors nor the network sources.
        let proxmox_requests = room.hypervisor.received_requests().await.unwrap().len();
        let asked = room.lab.asked().len();
        assert_eq!(bench.run(&room, &["--kind", "bmc"]).await.code, 0);
        assert_eq!(room.hypervisor.received_requests().await.unwrap().len(), proxmox_requests);
        assert_eq!(room.lab.asked().len(), asked);
    }

    #[tokio::test]
    async fn a_missing_device_a_wrong_bmc_and_a_failed_bmc_leave_the_others_and_netbox_alone() {
        // Four devices are listed. NetBox holds three of them, made by hand with the MAC address
        // of one card each; `pve03.lab01` is not in NetBox.
        //   pve01: its BMC is the idrac8-2.86.86.86 recording, whose first card is 02:00:00:00:00:0E.
        //   pve02: the address configured for it answers with the idrac9-7.00.00.174 recording
        //          (cards 02:00:00:00:00:15 to …:18), none of which is the card NetBox holds.
        //   pve03: its BMC answers (ilo4-2.82-blank-serial), and the device does not exist.
        //   pve04: its BMC is unreachable.
        let room = ServerRoom::new([
            ("drac-pve01.lab01", "idrac8-2.86.86.86"),
            ("drac-pve02.lab01", "idrac9-7.00.00.174"),
            ("drac-pve03.lab01", "ilo4-2.82-blank-serial"),
        ])
        .await;
        room.add_server("pve01.lab01", "Unknown", "", "02:00:00:00:00:0E");
        room.add_server("pve02.lab01", "Chosen by hand", "KEEP-02", "02:00:00:00:00:AA");
        room.add_server("pve04.lab01", "PowerEdge R640", "KEEP-04", "02:00:00:00:00:BB");
        let bench = room.bench("", &["pve01.lab01", "pve02.lab01", "pve03.lab01", "pve04.lab01"]);
        let ran = bench.run(&room, &["--kind", "bmc"]).await;
        // The BMC that could not be read is an error of the run.
        assert_eq!(ran.code, 1, "{}{}", ran.stdout, ran.stderr);
        let failed = "error: bmc.lab01: redfish drac-pve04.lab01:443: GET /redfish/v1/: ";
        assert!(ran.stderr.contains(failed), "{}", ran.stderr);
        assert!(ran.stdout.contains("Errors (1)\n"), "{}", ran.stdout);
        // The device whose BMC answered and was proven is completed.
        assert_eq!(room.hardware("pve01.lab01"), ("PowerEdge R630".to_owned(), "878X8Z3".to_owned()));
        // The wrong BMC and the missing device are warnings, naming the device and the BMC.
        for warning in [
            "bmc.lab01: device pve02.lab01: none of the 4 MAC address(es) BMC drac-pve02.lab01 reports is on its 1 \
             NetBox interface address(es): wrong BMC for this device?; nothing is written for it",
            "bmc.lab01: device pve03.lab01: not in NetBox; BMC drac-pve03.lab01 is left out (a device is never \
             created from its BMC); nothing is written for it",
        ] {
            assert!(ran.stdout.contains(warning), "{warning}\n{}", ran.stdout);
        }
        // What NetBox held for the others is as it was.
        assert_eq!(room.hardware("pve02.lab01"), ("Chosen by hand".to_owned(), "KEEP-02".to_owned()));
        assert_eq!(room.hardware("pve04.lab01"), ("PowerEdge R640".to_owned(), "KEEP-04".to_owned()));
        assert!(room.lab.netbox.find("dcim.devices", "name", &json!("pve03.lab01")).is_none());
        // Neither the R640 the wrong BMC describes nor the ProLiant of the missing device was made.
        let types = |model: &str| room.lab.netbox.find("dcim.device_types", "slug", &json!(model));
        assert_eq!((types("poweredge-r640"), types("proliant-dl360-gen9")), (None, None));
        assert!(types("poweredge-r630").is_some());
        let printed = format!("{}{}", ran.stdout, ran.stderr);
        assert!(!printed.contains("0perator") && !printed.contains("s3ntinel"), "{printed}");

        // The same run again: the error is still there, and nothing more is written.
        let writes = room.lab.netbox.writes().len();
        let again = bench.run(&room, &["--kind", "bmc"]).await;
        assert_eq!(again.code, 1);
        assert_eq!(room.lab.netbox.writes().len(), writes);
    }

    #[tokio::test]
    async fn the_addresses_of_a_vcenter_get_their_dns_names_end_to_end_when_the_entry_asks_for_it() {
        let server = vcenter::vcenter("6.7").await;
        // A DNS server that knows two of the addresses of the vCenter, and answers NXDOMAIN for the others.
        let dns = FakeDns::serving([
            // vmk0 of esx04.lab.example: 198.18.0.36.
            ("36.0.18.198.in-addr.arpa.", Reply::Names(vec!["ESX04.Lab.Example."])),
            // `Network adapter 1` of vm076.lab.example: 198.18.2.160. Two records, as a round robin gives them.
            ("160.2.18.198.in-addr.arpa.", Reply::Names(vec!["vm076.lab.example.", "rabbit.lab.example."])),
        ])
        .await;
        let entry = format!(
            "{}dns_name_lookup = true\ndns_servers = [\"{}\"]\n",
            vcenter_entry(server.address().port()),
            dns.address
        );
        let bench = Bench::new(&format!("{CONFIG}{entry}")).with(&VCENTER_ENV);
        let backend = Vsphere { lab: Lab::new("SN1"), vcenter: server.uri() };
        let ran = bench.run(&backend, &["--type", "vmware"]).await;
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        // No lookup failed: an address without record is an answer.
        assert!(!ran.stdout.contains("reverse DNS"), "{}", ran.stdout);
        let netbox = &backend.lab.netbox;
        let name = |address: &str| {
            let id = netbox.find("ipam.ip_addresses", "address", &json!(address)).expect("the address");
            netbox.row("ipam.ip_addresses", id).unwrap().get("dns_name").cloned()
        };
        // Without its final dot, in lower case; of two records the first in alphabetical order.
        assert_eq!(name("198.18.0.36/24"), Some(json!("esx04.lab.example")));
        assert_eq!(name("198.18.2.160/24"), Some(json!("rabbit.lab.example")));
        // vmk1 of the same host, 198.18.1.36, has no record: no name was written for it.
        assert_eq!(name("198.18.1.36/27"), None);
        // Each address was asked once.
        let asked = dns.asked();
        assert_eq!(asked["36.0.18.198.in-addr.arpa."], 1);
        assert_eq!(asked.values().copied().max(), Some(1));

        // The same vCenter and the same DNS again: nothing differs, which a dry run tells by its exit code.
        let writes = netbox.writes().len();
        let again = bench.run(&backend, &["--type", "vmware", "--dry-run"]).await;
        assert_eq!(again.code, 0, "{}{}", again.stdout, again.stderr);
        assert_eq!(netbox.writes().len(), writes);
    }

    #[tokio::test]
    async fn a_dns_server_that_does_not_answer_fails_nothing_and_is_one_warning() {
        let server = vcenter::vcenter("6.7").await;
        // A local port nothing listens on.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let nowhere = socket.local_addr().unwrap();
        drop(socket);
        let entry = format!(
            "{}dns_name_lookup = true\ndns_servers = [\"{nowhere}\"]\n",
            vcenter_entry(server.address().port())
        );
        let bench = Bench::new(&format!("{CONFIG}{entry}")).with(&VCENTER_ENV);
        let backend = Vsphere { lab: Lab::new("SN1"), vcenter: server.uri() };
        let started = std::time::Instant::now();
        let ran = bench.run(&backend, &["--type", "vmware"]).await;
        // The run succeeds, and the dead resolver cost its budget at most (15 s, and the lookups then in flight).
        assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
        assert!(started.elapsed() < Duration::from_secs(19), "{:?}", started.elapsed());
        let lines: Vec<&str> = ran.stdout.lines().filter(|line| line.contains("reverse DNS")).collect();
        let [line] = lines.as_slice() else {
            panic!("one line about the lookups, not {lines:?}");
        };
        assert!(line.ends_with("the DNS names NetBox holds for these addresses are kept"), "{line}");
        assert!(line.len() < 320, "{line}");
        // The addresses are written all the same, without name.
        let netbox = &backend.lab.netbox;
        let id = netbox.find("ipam.ip_addresses", "address", &json!("198.18.0.36/24")).expect("the address");
        assert_eq!(netbox.row("ipam.ip_addresses", id).unwrap().get("dns_name"), None);
    }

    #[tokio::test]
    async fn a_vcenter_that_refuses_the_login_shows_its_type_and_host_never_the_account() {
        let (user, password) = VCENTER_ENV.map(|(_, value)| value).into();
        // The password as the XML body of the login carries it.
        let password_xml = "s3ntinel pass&amp;word&lt;";
        let server = MockServer::start().await;
        // A vCenter, or a proxy, that refuses the login and repeats what it received.
        let refusal = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope \
             xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><soapenv:Body><soapenv:Fault>\
             <faultcode>ServerFaultCode</faultcode><faultstring>Cannot complete login of {user} with \
             {password_xml} due to an incorrect user name or password.</faultstring><detail>\
             <InvalidLoginFault xmlns=\"urn:vim25\" xsi:type=\"InvalidLogin\"></InvalidLoginFault></detail>\
             </soapenv:Fault></soapenv:Body></soapenv:Envelope>"
        );
        vcenter::mount_soap(&server, "<vim25:Login>", vcenter::xml(500, &refusal), 1).await;
        vcenter::mount_inventory(&server, "6.7").await;
        vcenter::mount_tags(&server, "6.7").await;
        let port = server.address().port();
        let bench =
            Bench::new(&netbox_at(&server, &format!("{CONFIG}{}", vcenter_entry(port))).await).with(&VCENTER_ENV);
        let ran = bench.run(&Wired { hypervisor: server.uri() }, &["--kind", "hypervisor"]).await;
        assert_eq!(ran.code, 1);
        // The source, its type and its host; the account is masked where it was quoted.
        let line = format!(
            "vc01.lab01: vmware 127.0.0.1:{port}: Login: InvalidLogin: Cannot complete login of *** with *** due \
             to an incorrect user name or password."
        );
        assert!(ran.stderr.contains(&format!("error: {line}\n")), "{}", ran.stderr);
        assert!(ran.stdout.contains(&format!("Errors (1)\n  {line}\n")), "{}", ran.stdout);
        let printed = format!("{}{}", ran.stdout, ran.stderr);
        for value in [user, password, password_xml, "0perator", "s3ntinel"] {
            assert!(!printed.contains(value), "{value} is printed: {printed}");
        }
        // The account did leave with the login: the assertions above are not vacuous.
        let sent = server.received_requests().await.unwrap();
        let login = sent.iter().find(|request| String::from_utf8_lossy(&request.body).contains("<vim25:Login>"));
        let body = String::from_utf8_lossy(&login.expect("a login").body).into_owned();
        assert!(body.contains(user) && body.contains(password_xml), "{body}");
    }

    #[tokio::test]
    async fn a_hypervisor_that_refuses_the_login_shows_neither_the_user_nor_the_password() {
        // The account as given, then as the form of the login carries it.
        let (user, user_form) = ("0perator-never-shown@pve", "0perator-never-shown%40pve");
        let (password, password_form) = ("s3ntinel pass&word/+", "s3ntinel+pass%26word%2F%2B");
        // A Proxmox, or a proxy, that refuses the login and quotes what it received.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/access/ticket"))
            .respond_with(|request: &wiremock::Request| {
                let quoted = format!("authentication failure: {}", String::from_utf8_lossy(&request.body));
                ResponseTemplate::new(401).set_body_json(json!({"data": null, "message": quoted}))
            })
            .mount(&server)
            .await;
        let port = server.address().port();
        let hypervisor = format!(
            "\n[[sources]]\nname = \"pve01.lab01\"\nkind = \"hypervisor\"\nhost = \"127.0.0.1\"\nport = {port}\n\
             type = \"proxmox\"\nsite = \"Paris\"\n"
        );
        let bench = Bench::new(&netbox_at(&server, &format!("{CONFIG}{hypervisor}")).await)
            .with(&[("PVE01_LAB01_USERNAME", user), ("PVE01_LAB01_PASSWORD", password)]);
        let ran = bench.run(&Wired { hypervisor: server.uri() }, &["--kind", "hypervisor"]).await;
        assert_eq!(ran.code, 1);
        // The source, its type and its host; the account is masked where it was quoted.
        let line = format!(
            "pve01.lab01: proxmox 127.0.0.1:{port}: POST /access/ticket answered 401: \
             authentication failure: username=***&password=***"
        );
        assert!(ran.stderr.contains(&format!("error: {line}\n")), "{}", ran.stderr);
        assert!(ran.stdout.contains(&format!("Errors (1)\n  {line}\n")), "{}", ran.stdout);
        let printed = format!("{}{}", ran.stdout, ran.stderr);
        for value in [user, user_form, "0perator", password, password_form, "s3ntinel"] {
            assert!(!printed.contains(value), "{value} is printed: {printed}");
        }
        // The account did leave with the login: the assertions above are not vacuous.
        let sent = server.received_requests().await.unwrap();
        let login = sent.iter().find(|request| request.url.path() == "/api2/json/access/ticket").expect("a login");
        assert_eq!(String::from_utf8_lossy(&login.body), format!("username={user_form}&password={password_form}"));
    }

    #[tokio::test]
    async fn a_netbox_that_cannot_be_reached_is_named_with_its_host_never_its_token() {
        // A local port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        let token = "s3ntinel-token-never-shown";
        let config = CONFIG.replace("https://netbox.example", &format!("http://{closed}"));
        let bench = Bench::new(&config).with(&[("NETBOX_TOKEN", token)]);
        let ran = bench.run(&Wired { hypervisor: String::new() }, &[]).await;
        assert_eq!(ran.code, 1);
        // Its release is asked before anything else: the run stops there, without a report.
        let named = format!("error: cannot read the release of NetBox: NetBox {closed}: GET /api/status/: ");
        assert!(ran.stderr.starts_with(&named), "{}", ran.stderr);
        assert_eq!(ran.stdout, "");
        let printed = format!("{}{}", ran.stdout, ran.stderr);
        assert!(!printed.contains("s3ntinel"), "{printed}");
    }

    #[tokio::test]
    async fn a_netbox_that_cannot_give_its_schema_stops_the_run_before_any_source_is_read() {
        // Every write is checked against the schema: read at the first write,
        // a NetBox too slow to give it would fail the run half way through.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(500).set_body_string("schema generation failed"))
            .with_priority(1)
            .mount(&server)
            .await;
        let hypervisor = MockServer::start().await;
        let port = hypervisor.address().port();
        let bench =
            Bench::new(&netbox_at(&server, &format!("{CONFIG}{}", vcenter_entry(port))).await).with(&VCENTER_ENV);
        let ran = bench.run(&Wired { hypervisor: hypervisor.uri() }, &["--kind", "hypervisor"]).await;
        assert_eq!(ran.code, 1);
        assert!(ran.stderr.starts_with("error: cannot read the schema of NetBox: "), "{}", ran.stderr);
        assert_eq!(ran.stdout, "");
        assert_eq!(hypervisor.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_real_client_of_a_dry_run_refuses_every_write() {
        let server = MockServer::start().await;
        let netbox = Netbox {
            url: server.uri(),
            token: Wanted::Held(Secret::new("token-value")),
            timeout: Some(Duration::from_secs(5)),
            validate_certs: true,
            ca_file: None,
            source_priority: Vec::new(),
            unsupported_version: UnsupportedVersion::Refuse,
        };
        let client = Production.gateway(&netbox, true).unwrap();
        let payload: Row = serde_json::from_value(json!({"name": "nexus01.lab01"})).unwrap();
        let refusal =
            |method: &str| GatewayError::DryRun { method: method.to_owned(), endpoint: "dcim.devices".to_owned() };
        assert_eq!(client.create("dcim.devices", &payload).await, Err(refusal("POST")));
        assert_eq!(client.update("dcim.devices", 7, &payload).await, Err(refusal("PATCH")));
        assert_eq!(client.delete("dcim.devices", 7).await, Err(refusal("DELETE")));
        // Nothing reached NetBox.
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_real_client_writes_outside_a_dry_run() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/dcim/devices/"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 7, "name": "nexus01.lab01"})))
            .mount(&server)
            .await;
        // The schema the fields of a write are checked against: a device takes a name.
        let body = json!({"oneOf": [{"$ref": "#/components/schemas/WritableDeviceRequest"}]});
        let schema = json!({
            "paths": {"/api/dcim/devices/": {"post": {"requestBody": {"content": {"application/json": {"schema": body}}}}}},
            "components": {"schemas": {"WritableDeviceRequest": {"properties": {"name": {"type": "string"}}}}}
        });
        Mock::given(method("GET"))
            .and(path("/api/schema/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(schema))
            .mount(&server)
            .await;
        let netbox = Netbox {
            url: server.uri(),
            token: Wanted::Held(Secret::new("token-value")),
            timeout: None,
            validate_certs: true,
            ca_file: None,
            source_priority: Vec::new(),
            unsupported_version: UnsupportedVersion::Refuse,
        };
        let client = Production.gateway(&netbox, false).unwrap();
        let payload: Row = serde_json::from_value(json!({"name": "nexus01.lab01"})).unwrap();
        let created = client.create("dcim.devices", &payload).await.unwrap();
        assert_eq!(created["id"], json!(7));
        let sent = server.received_requests().await.unwrap();
        assert_eq!(sent.iter().filter(|request| request.method.as_str() == "POST").count(), 1);
    }

    #[test]
    fn the_real_client_takes_the_settings_of_the_netbox_block() {
        let netbox = |timeout: Option<Duration>, ca_file: Option<PathBuf>| Netbox {
            url: "https://netbox.example.net".to_owned(),
            token: Wanted::Held(Secret::new("token-value")),
            timeout,
            validate_certs: true,
            ca_file,
            source_priority: Vec::new(),
            unsupported_version: UnsupportedVersion::Refuse,
        };
        let client = Production.gateway(&netbox(Some(Duration::from_secs(30)), None), false).unwrap();
        assert_eq!(client.timeout(), Duration::from_secs(30));
        let client = Production.gateway(&netbox(None, None), false).unwrap();
        assert_eq!(client.timeout(), omnisync_netbox::client::DEFAULT_TIMEOUT);
        // The CA file is read when the client is built: a missing one is refused.
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent.pem");
        let error = Production.gateway(&netbox(None, Some(absent.clone())), false).unwrap_err().to_string();
        assert!(error.starts_with(&format!("CA file {}: ", absent.display())), "{error}");
    }

    // The run is refused before it asks for a client; the client itself
    // never takes an empty token for one.
    #[test]
    fn the_real_client_is_never_built_without_the_token() {
        let netbox = Netbox {
            url: "https://netbox.example.net".to_owned(),
            token: Wanted::Missing(vec!["NETBOX_TOKEN".to_owned()]),
            timeout: None,
            validate_certs: true,
            ca_file: None,
            source_priority: Vec::new(),
            unsupported_version: UnsupportedVersion::Refuse,
        };
        let error = Production.gateway(&netbox, false).unwrap_err().to_string();
        assert_eq!(error, "missing environment variables: NETBOX_TOKEN");
    }

    #[tokio::test]
    async fn a_netbox_client_that_cannot_be_built_is_an_error() {
        let bench = Bench::new(&CONFIG.replace("https://netbox.example", "ftp://netbox.example"));
        let stderr = Buffer::default();
        let mut terminal = Terminal {
            stdout: Buffer::default(),
            stderr: stderr.clone(),
            stdout_is_terminal: false,
            stderr_is_terminal: false,
        };
        let code = run(bench.argv(&[]), &bench.environ(), &mut terminal, &Production, pending()).await;
        assert_eq!(code, 1);
        assert_eq!(stderr.text(), "error: NetBox URL \"ftp://netbox.example\": not an http or https URL\n");
    }

    #[tokio::test]
    async fn a_collector_that_cannot_be_set_up_is_an_error_before_anything_is_contacted() {
        let bench = Bench::new(CONFIG).without("HOME");
        let stderr = Buffer::default();
        let mut terminal = Terminal {
            stdout: Buffer::default(),
            stderr: stderr.clone(),
            stdout_is_terminal: false,
            stderr_is_terminal: false,
        };
        let code = run(bench.argv(&[]), &bench.environ(), &mut terminal, &Production, pending()).await;
        assert_eq!(code, 1);
        assert_eq!(stderr.text(), "error: cannot locate the lock file: set HOME or XDG_STATE_HOME\n");
    }
}
