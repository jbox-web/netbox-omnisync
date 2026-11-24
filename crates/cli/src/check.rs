//! `netbox-omnisync check`: the state of each source from the journal of the
//! runs, as a Nagios plugin tells it (Icinga runs it).
//!
//! One status line on stdout, `NETBOX-OMNISYNC <STATE> - <summary> | <perfdata>`,
//! then a line per source that is not OK with the errors of its last failed
//! run, then the warnings that stand and those `--ignore-warning` leaves out;
//! the exit code is the state: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
//!
//! The sources checked are those the last entry says the configuration has:
//! a source that no run selects any more is never forgotten. When the file is
//! shared by several hosts (`runner`), they are those it gives to the host of
//! that last run: the journal is the one of a host, which answers for what it
//! launches, and the other hosts for the rest. The check reads the journal
//! alone, neither the configuration nor the name of the host. Each must have
//! succeeded within the maximum age of its kind (`--max-age`), or the check
//! is CRITICAL; a source whose last run failed while its last success is
//! still recent enough is a WARNING. So is a warning of the last run of any
//! source: something the runs keep failing to write, told at once rather
//! than in the next daily digest, and over as soon as a run no longer says it.
//! A warning a run says by design is named with `--ignore-warning`: it would
//! otherwise keep the check at WARNING for good.

use std::fmt;

use jiff::{SignedDuration, Timestamp};
use omnisync_core::report::printable;
use regex::Regex;

use crate::journal::{Configured, Entry};
use crate::select::SourceKind;

/// The state of a check, as Nagios defines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    Ok,
    Warning,
    Critical,
    Unknown,
}

impl State {
    /// The exit code of the plugin.
    pub fn code(self) -> u8 {
        match self {
            State::Ok => 0,
            State::Warning => 1,
            State::Critical => 2,
            State::Unknown => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            State::Ok => "OK",
            State::Warning => "WARNING",
            State::Critical => "CRITICAL",
            State::Unknown => "UNKNOWN",
        }
    }
}

/// How old the last success of the sources of a kind may be: `--max-age KIND=DURATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxAge {
    pub kind: SourceKind,
    pub age: SignedDuration,
}

impl fmt::Display for MaxAge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.kind.as_str(), age(self.age))
    }
}

/// A duration as the command line takes it: a whole positive number and its
/// unit, `s`, `m`, `h` or `d` (`15m`, `26h`, `2d`).
pub fn parse_duration(text: &str) -> Result<SignedDuration, String> {
    let refused = || format!("invalid duration '{text}': a whole number above 0 and s, m, h or d (15m, 26h, 2d)");
    let split = text.len().checked_sub(1).filter(|_| text.is_char_boundary(text.len() - 1)).ok_or_else(refused)?;
    let (number, unit) = text.split_at(split);
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refused());
    }
    let number: i64 = number.parse().map_err(|_| refused())?;
    let seconds = match unit {
        "s" => Some(number),
        "m" => number.checked_mul(60),
        "h" => number.checked_mul(3600),
        "d" => number.checked_mul(86_400),
        _ => None,
    };
    match seconds {
        Some(seconds) if seconds > 0 => Ok(SignedDuration::from_secs(seconds)),
        _ => Err(refused()),
    }
}

/// `KIND=DURATION`, the value of `--max-age`.
pub fn parse_max_age(text: &str) -> Result<MaxAge, String> {
    let Some((kind, duration)) = text.split_once('=') else {
        return Err(format!("invalid max age '{text}': KIND=DURATION"));
    };
    let kinds = [SourceKind::Hypervisor, SourceKind::Bmc, SourceKind::Switch, SourceKind::Router, SourceKind::Firewall];
    let Some(kind) = kinds.into_iter().find(|known| known.as_str() == kind) else {
        return Err(format!("invalid kind '{kind}': hypervisor, bmc, switch, router or firewall"));
    };
    Ok(MaxAge { kind, age: parse_duration(duration)? })
}

/// A warning to leave out of the state, the value of `--ignore-warning`: a
/// regular expression a warning matches anywhere in its text. Two are the
/// same when they are written the same.
#[derive(Debug, Clone)]
pub struct Ignored(Regex);

impl Ignored {
    fn matches(&self, warning: &str) -> bool {
        self.0.is_match(warning)
    }
}

impl PartialEq for Ignored {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for Ignored {}

pub fn parse_ignored(text: &str) -> Result<Ignored, String> {
    Regex::new(text).map(Ignored).map_err(|error| format!("invalid regular expression '{text}': {error}"))
}

/// A duration to the minute, as the summary tells an age: `45s`, `12m`,
/// `2h 05m`, `3d 04h`.
pub fn age(duration: SignedDuration) -> String {
    let seconds = duration.as_secs().max(0);
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        3600..86_400 => format!("{}h {:02}m", seconds / 3600, seconds % 3600 / 60),
        _ => format!("{}d {:02}h", seconds / 86_400, seconds % 86_400 / 3600),
    }
}

/// A text as a line of the output may hold it: escaped as the report escapes
/// it, and without the `|` that would start the performance data.
fn shown(text: &str) -> String {
    printable(text).replace('|', "/")
}

/// The texts of `said` (the errors or the warnings of `entry`) that are about
/// `name`, one of the sources it selected: those that start with its name and
/// `: `, and those that name no selected source, which are about the run.
fn about<'e>(entry: &Entry, said: &'e [String], name: &str) -> Vec<&'e str> {
    let names = |text: &str, source: &str| text.strip_prefix(source).is_some_and(|rest| rest.starts_with(": "));
    said.iter()
        .map(String::as_str)
        .filter(|text| names(text, name) || !entry.selected.iter().any(|source| names(text, source)))
        .collect()
}

/// The errors of `entry` that are the failure of `name`.
fn failures<'e>(entry: &'e Entry, name: &str) -> Vec<&'e str> {
    about(entry, &entry.errors, name)
}

/// What the journal says of one source.
struct Source<'e> {
    name: &'e str,
    state: State,
    /// Why it is not OK.
    problem: String,
    /// The errors of its last failed run.
    errors: Vec<&'e str>,
    failed: bool,
    stale: bool,
}

/// The state of `name` in `entries`, against `max_age`, at `now`.
fn source<'e>(entries: &'e [Entry], name: &'e str, max_age: SignedDuration, now: Timestamp) -> Source<'e> {
    let runs: Vec<&Entry> =
        entries.iter().filter(|entry| entry.selected.iter().any(|selected| selected == name)).collect();
    let failed_in = |entry: &Entry| !failures(entry, name).is_empty();
    let failed = runs.last().is_some_and(|entry| failed_in(entry));
    let errors =
        runs.iter().rev().find(|entry| failed_in(entry)).map(|entry| failures(entry, name)).unwrap_or_default();
    let success = runs.iter().rev().filter(|entry| !failed_in(entry)).find_map(|entry| entry.ended_at());
    let (state, problem, stale) = match success {
        None => (State::Critical, "no success in the journal".to_owned(), true),
        Some(ended) if now.duration_since(ended) > max_age => {
            (State::Critical, format!("no success for {}", age(now.duration_since(ended))), true)
        }
        Some(_) if failed => (State::Warning, "last run failed".to_owned(), false),
        Some(_) => (State::Ok, String::new(), false),
    };
    Source { name, state, problem, errors, failed, stale }
}

/// The warnings that stand: those the last run of each of `sources` said of
/// it (that name it, or no selected source), each once, in the order of the
/// sources then of the run. A source read once a night keeps the warnings of
/// its run until the next one, whatever the more frequent runs of the others
/// say; a warning that names a source is taken back by the next run of that
/// source alone.
fn standing_warnings<'e>(entries: &'e [Entry], sources: &[&str]) -> Vec<&'e str> {
    let mut warnings: Vec<&str> = Vec::new();
    for name in sources {
        let last = entries.iter().rev().find(|entry| entry.selected.iter().any(|selected| selected == name));
        for warning in last.map(|entry| about(entry, &entry.warnings, name)).unwrap_or_default() {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    warnings
}

/// What the plugin prints, and its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub state: State,
    /// The status line and the long output, each line ending with a newline.
    pub text: String,
}

/// An UNKNOWN that says why: the journal cannot be read, the command line is
/// wrong.
pub fn unknown(message: &str) -> Verdict {
    Verdict { state: State::Unknown, text: format!("NETBOX-OMNISYNC UNKNOWN - {}\n", shown(message)) }
}

/// The sources of the configuration `last` tells that its host is to answer
/// for: all of them when one host runs every source (no `runner`), those the
/// file gives to the host of that run otherwise. One no host is said to
/// launch, which the tool never writes, is judged: it is nobody else's.
fn judged(last: &Entry) -> Vec<&Configured> {
    let own = |configured: &&Configured| match (&last.runner, &configured.runner) {
        (Some(host), Some(runner)) => host == runner,
        (None, _) | (_, None) => true,
    };
    last.configured.iter().filter(own).collect()
}

/// The state of the sources the last of `entries` says are configured and
/// launched by its host, at `now`, against `max_ages` (the last one given for
/// a kind wins). A warning one of `ignored` matches is listed apart and
/// changes nothing.
///
/// A source whose kind has no maximum age makes the check UNKNOWN before
/// anything else is looked at: the check is incomplete, and saying OK for
/// the others would hide the gap.
pub fn evaluate(entries: &[Entry], max_ages: &[MaxAge], ignored: &[Ignored], now: Timestamp) -> Verdict {
    let Some(last) = entries.last() else {
        return unknown("no run in the journal");
    };
    let judged = judged(last);
    // A host the file gives no source to is refused before it runs: an entry
    // that says so was not written by a run, and checks nothing.
    if let (Some(host), true) = (&last.runner, judged.is_empty()) {
        return unknown(&format!("the last run names no source of {host}"));
    }
    let max_age = |kind: &str| max_ages.iter().rev().find(|max| max.kind.as_str() == kind).map(|max| max.age);
    // The kinds without a maximum age, each with its sources, in the order of the file.
    let mut missing: Vec<(&str, Vec<&str>)> = Vec::new();
    for configured in judged.iter().filter(|configured| max_age(&configured.kind).is_none()) {
        match missing.iter_mut().find(|(kind, _)| *kind == configured.kind) {
            Some((_, names)) => names.push(&configured.name),
            None => missing.push((&configured.kind, vec![&configured.name])),
        }
    }
    if !missing.is_empty() {
        let kinds: Vec<String> = missing.iter().map(|(kind, names)| format!("{kind} ({})", names.join(", "))).collect();
        return unknown(&format!("no --max-age for {}", kinds.join(", ")));
    }
    let mut sources: Vec<Source<'_>> = judged
        .iter()
        .map(|configured| source(entries, &configured.name, max_age(&configured.kind).unwrap_or_default(), now))
        .collect();
    let names: Vec<&str> = judged.iter().map(|configured| configured.name.as_str()).collect();
    let (ignored, warnings): (Vec<&str>, Vec<&str>) = standing_warnings(entries, &names)
        .into_iter()
        .partition(|warning| ignored.iter().any(|pattern| pattern.matches(warning)));
    // The worst first, each state in the order of the file.
    sources.sort_by_key(|source| std::cmp::Reverse(source.state));
    let worst = sources.first().map_or(State::Ok, |source| source.state);
    // A warning is a write the runs keep failing to make: told at once, never
    // over a worse state.
    let state = if warnings.is_empty() { worst } else { worst.max(State::Warning) };
    let failed = sources.iter().filter(|source| source.failed).count();
    let stale = sources.iter().filter(|source| source.stale).count();
    let not_ok: Vec<&Source<'_>> = sources.iter().filter(|source| source.state != State::Ok).collect();
    let mut problems: Vec<String> =
        not_ok.iter().map(|source| format!("{}: {}", shown(source.name), source.problem)).collect();
    if !warnings.is_empty() {
        let plural = if warnings.len() == 1 { "" } else { "s" };
        problems.push(format!("{} warning{plural}", warnings.len()));
    }
    let summary = if problems.is_empty() {
        let plural = if sources.len() == 1 { "" } else { "s" };
        format!("{} source{plural} synced", sources.len())
    } else {
        problems.join(", ")
    };
    let mut text = format!(
        "NETBOX-OMNISYNC {} - {summary} | sources={} failed={failed} stale={stale} warnings={}\n",
        state.as_str(),
        sources.len(),
        warnings.len()
    );
    for source in not_ok {
        text.push_str(&format!("{}: {}\n", shown(source.name), source.problem));
        for error in &source.errors {
            text.push_str(&format!("  {}\n", shown(error)));
        }
    }
    for (title, listed) in [("warnings of the last runs", &warnings), ("ignored warnings", &ignored)] {
        if !listed.is_empty() {
            text.push_str(&format!("{title}:\n"));
            for warning in listed {
                text.push_str(&format!("  {}\n", shown(warning)));
            }
        }
    }
    Verdict { state, text }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-20T08:00:00+01:00.
    fn now() -> Timestamp {
        "2026-11-20T07:00:00Z".parse().unwrap()
    }

    fn fleet() -> Vec<Configured> {
        [("pve01.lab01", "hypervisor"), ("pve02.lab02", "hypervisor"), ("bmc.lab01", "bmc")]
            .iter()
            .map(|(name, kind)| Configured { name: (*name).to_owned(), kind: (*kind).to_owned(), runner: None })
            .collect()
    }

    /// A run of the fleet that started at `started` (UTC), took 30 s, and
    /// selected `selected`, with `errors`.
    fn run(started: &str, selected: &[&str], errors: &[&str]) -> Entry {
        Entry {
            version: 1,
            started: format!("2026-11-20T{started}+01:00"),
            seconds: 30.0,
            runner: None,
            configured: fleet(),
            selected: selected.iter().map(|name| (*name).to_owned()).collect(),
            changes: vec![],
            applied: 0,
            warnings: vec![],
            errors: errors.iter().map(|error| (*error).to_owned()).collect(),
        }
    }

    fn ages() -> Vec<MaxAge> {
        vec![
            MaxAge { kind: SourceKind::Hypervisor, age: SignedDuration::from_mins(15) },
            MaxAge { kind: SourceKind::Bmc, age: SignedDuration::from_hours(26) },
        ]
    }

    const HYPERVISORS: [&str; 2] = ["pve01.lab01", "pve02.lab02"];

    /// The BMCs, read at 04:47.
    fn bmc_run() -> Entry {
        run("04:47:00", &["bmc.lab01"], &[])
    }

    #[test]
    fn a_duration_is_a_whole_number_and_its_unit() {
        assert_eq!(parse_duration("45s"), Ok(SignedDuration::from_secs(45)));
        assert_eq!(parse_duration("15m"), Ok(SignedDuration::from_mins(15)));
        assert_eq!(parse_duration("26h"), Ok(SignedDuration::from_hours(26)));
        assert_eq!(parse_duration("2d"), Ok(SignedDuration::from_hours(48)));
        for wrong in ["15", "m", "1.5h", "0m", "-5m", "15M", "15 m", "15min", ""] {
            assert_eq!(
                parse_duration(wrong),
                Err(format!("invalid duration '{wrong}': a whole number above 0 and s, m, h or d (15m, 26h, 2d)")),
                "{wrong}"
            );
        }
    }

    #[test]
    fn a_max_age_is_a_kind_and_a_duration() {
        assert_eq!(
            parse_max_age("hypervisor=15m"),
            Ok(MaxAge { kind: SourceKind::Hypervisor, age: SignedDuration::from_mins(15) })
        );
        assert_eq!(parse_max_age("bmc=26h").map(|max| max.to_string()), Ok("bmc=1d 02h".to_owned()));
        assert_eq!(
            parse_max_age("toaster=15m"),
            Err("invalid kind 'toaster': hypervisor, bmc, switch, router or firewall".to_owned())
        );
        assert_eq!(parse_max_age("hypervisor"), Err("invalid max age 'hypervisor': KIND=DURATION".to_owned()));
        assert_eq!(
            parse_max_age("switch=1y"),
            Err("invalid duration '1y': a whole number above 0 and s, m, h or d (15m, 26h, 2d)".to_owned())
        );
    }

    #[test]
    fn an_age_is_told_to_the_minute() {
        assert_eq!(age(SignedDuration::from_secs(45)), "45s");
        assert_eq!(age(SignedDuration::from_secs(12 * 60 + 59)), "12m");
        assert_eq!(age(SignedDuration::from_secs(2 * 3600 + 5 * 60 + 30)), "2h 05m");
        assert_eq!(age(SignedDuration::from_secs(3 * 86400 + 4 * 3600 + 59 * 60)), "3d 04h");
    }

    #[test]
    fn sources_that_all_succeeded_recently_are_ok() {
        let entries = [bmc_run(), run("07:50:00", &HYPERVISORS, &[]), run("07:55:00", &HYPERVISORS, &[])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Ok);
        assert_eq!(verdict.text, "NETBOX-OMNISYNC OK - 3 sources synced | sources=3 failed=0 stale=0 warnings=0\n");
    }

    // pve02.lab02 last succeeded in the run of 05:50, which ended at 05:50:30:
    // 2 h 09 min 30 s before 08:00, more than 15 minutes.
    #[test]
    fn a_source_without_a_success_within_its_max_age_is_critical() {
        let entries = [
            bmc_run(),
            run("05:50:00", &HYPERVISORS, &[]),
            run("07:55:00", &HYPERVISORS, &["pve02.lab02: connect: Connection refused"]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Critical);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - pve02.lab02: no success for 2h 09m | sources=3 failed=1 stale=1 warnings=0\n\
             pve02.lab02: no success for 2h 09m\n  \
             pve02.lab02: connect: Connection refused\n"
        );
    }

    // The run of 07:55 failed for pve01.lab01; its success of 07:50 ended at
    // 07:50:30, 9 min 30 s before 08:00: within 15 minutes.
    #[test]
    fn a_source_whose_last_run_failed_but_succeeded_recently_is_a_warning() {
        let entries = [
            bmc_run(),
            run("07:50:00", &HYPERVISORS, &[]),
            run("07:55:00", &HYPERVISORS, &["pve01.lab01: timeout", "pve01.lab01: node pve03 is offline"]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Warning);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - pve01.lab01: last run failed | sources=3 failed=1 stale=0 warnings=0\n\
             pve01.lab01: last run failed\n  \
             pve01.lab01: timeout\n  \
             pve01.lab01: node pve03 is offline\n"
        );
    }

    #[test]
    fn a_source_that_never_succeeded_is_critical_and_the_worst_come_first() {
        let entries = [
            run("07:50:00", &HYPERVISORS, &[]),
            run("07:55:00", &HYPERVISORS, &["pve01.lab01: timeout"]),
            run("07:56:00", &["bmc.lab01"], &["bmc.lab01: drac-pve01.lab01: refused"]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Critical);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - bmc.lab01: no success in the journal, pve01.lab01: last run failed \
             | sources=3 failed=2 stale=1 warnings=0\n\
             bmc.lab01: no success in the journal\n  \
             bmc.lab01: drac-pve01.lab01: refused\n\
             pve01.lab01: last run failed\n  \
             pve01.lab01: timeout\n"
        );
    }

    // A source the configuration has and no run ever selected is not a gap:
    // it is a source that never succeeded.
    #[test]
    fn a_configured_source_no_run_selected_is_critical() {
        let entries = [run("07:55:00", &HYPERVISORS, &[])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Critical);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - bmc.lab01: no success in the journal | sources=3 failed=0 stale=1 warnings=0\n\
             bmc.lab01: no success in the journal\n"
        );
    }

    // An error that names a selected source is that source's; one that names
    // none of them (NetBox refused the run, or a source that was not
    // selected) is the failure of every selected source.
    #[test]
    fn an_error_fails_the_source_it_names_or_every_selected_one() {
        let named = [bmc_run(), run("07:50:00", &HYPERVISORS, &[]), run("07:55:00", &HYPERVISORS, &["pve02.lab02: x"])];
        let verdict = evaluate(&named, &ages(), &[], now());
        assert!(
            verdict.text.starts_with("NETBOX-OMNISYNC WARNING - pve02.lab02: last run failed |"),
            "{}",
            verdict.text
        );

        let netbox = "cannot read the schema of NetBox: 502 Bad Gateway";
        let refused = [bmc_run(), run("07:50:00", &HYPERVISORS, &[]), run("07:55:00", &HYPERVISORS, &[netbox])];
        let verdict = evaluate(&refused, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - pve01.lab01: last run failed, pve02.lab02: last run failed \
             | sources=3 failed=2 stale=0 warnings=0\n\
             pve01.lab01: last run failed\n  \
             cannot read the schema of NetBox: 502 Bad Gateway\n\
             pve02.lab02: last run failed\n  \
             cannot read the schema of NetBox: 502 Bad Gateway\n"
        );

        // bmc.lab01 is not selected by the hypervisor run: its name does not
        // make the error its own, nor spare the selected ones.
        let foreign = [bmc_run(), run("07:50:00", &HYPERVISORS, &[]), run("07:55:00", &HYPERVISORS, &["bmc.lab01: x"])];
        let verdict = evaluate(&foreign, &ages(), &[], now());
        assert!(
            verdict
                .text
                .starts_with("NETBOX-OMNISYNC WARNING - pve01.lab01: last run failed, pve02.lab02: last run failed |"),
            "{}",
            verdict.text
        );
    }

    // A member of a stack fails under the name of its source, then its own:
    // the failure is the stack's, not the one of every source of the run.
    #[test]
    fn the_error_of_a_member_of_a_stack_fails_its_source_alone() {
        let configured = vec![
            Configured { name: "2960-stack.lab01".to_owned(), kind: "switch".to_owned(), runner: None },
            Configured { name: "nexus01.lab01".to_owned(), kind: "switch".to_owned(), runner: None },
        ];
        let network = |started: &str, errors: &[&str]| Entry {
            configured: configured.clone(),
            ..run(started, &["2960-stack.lab01", "nexus01.lab01"], errors)
        };
        let member = "2960-stack.lab01: 2960-stack02.lab01: unknown field description on dcim.interfaces";
        let entries = [network("07:00:00", &[]), network("07:55:00", &[member])];
        let switches = [MaxAge { kind: SourceKind::Switch, age: SignedDuration::from_hours(26) }];
        let verdict = evaluate(&entries, &switches, &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 2960-stack.lab01: last run failed | sources=2 failed=1 stale=0 warnings=0\n\
             2960-stack.lab01: last run failed\n  \
             2960-stack.lab01: 2960-stack02.lab01: unknown field description on dcim.interfaces\n"
        );
    }

    /// `run`, with `warnings`.
    fn warned(started: &str, selected: &[&str], warnings: &[&str]) -> Entry {
        Entry {
            warnings: warnings.iter().map(|warning| (*warning).to_owned()).collect(),
            ..run(started, selected, &[])
        }
    }

    const SHARED: &str = "ip 192.0.2.72/24 of web02.lab01: also assigned to web01.lab01; not created";
    const SKIPPED: &str = "vm web02.lab01: primary_ip4 refers to ip 192.0.2.72/24, which is skipped";

    // A warning is something the run could not do: the next run says it
    // again until someone acts, so it is told at once, not in tomorrow's mail.
    #[test]
    fn the_warnings_of_the_last_run_of_a_source_make_the_check_a_warning() {
        let entries =
            [bmc_run(), run("07:50:00", &HYPERVISORS, &[]), warned("07:55:00", &HYPERVISORS, &[SHARED, SKIPPED])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Warning);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 2 warnings | sources=3 failed=0 stale=0 warnings=2\n\
             warnings of the last runs:\n  \
             ip 192.0.2.72/24 of web02.lab01: also assigned to web01.lab01; not created\n  \
             vm web02.lab01: primary_ip4 refers to ip 192.0.2.72/24, which is skipped\n"
        );
    }

    #[test]
    fn a_warning_ends_with_the_first_run_that_no_longer_says_it() {
        let entries = [bmc_run(), warned("07:50:00", &HYPERVISORS, &[SHARED]), run("07:55:00", &HYPERVISORS, &[])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Ok);
        assert_eq!(verdict.text, "NETBOX-OMNISYNC OK - 3 sources synced | sources=3 failed=0 stale=0 warnings=0\n");
    }

    // The BMCs are read once a night: what their run said stands until the
    // next one, whatever the runs of the hypervisors say in between.
    #[test]
    fn a_warning_of_a_source_read_once_a_night_lasts_until_its_next_run() {
        let bmc = "bmc.lab01: drac-pve02.lab01 reports no MAC address NetBox holds";
        let entries = [
            warned("04:47:00", &["bmc.lab01"], &[bmc]),
            run("07:50:00", &HYPERVISORS, &[]),
            run("07:55:00", &HYPERVISORS, &[]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Warning);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 1 warning | sources=3 failed=0 stale=0 warnings=1\n\
             warnings of the last runs:\n  \
             bmc.lab01: drac-pve02.lab01 reports no MAC address NetBox holds\n"
        );
    }

    const EVERY_SOURCE: [&str; 3] = ["pve01.lab01", "pve02.lab02", "bmc.lab01"];

    // A warning names the source it is about, as an error does: the run of
    // 04:47 read every source, but only the hypervisor it names can take it
    // back, and the hypervisors were read again since without it. What it
    // says of the BMC stands until the BMC is read again.
    #[test]
    fn a_warning_that_names_its_source_ends_with_the_next_run_of_that_source() {
        let hypervisor = "pve01.lab01: ip 192.0.2.72/24 of web02.lab01: also assigned to web01.lab01; not created";
        let bmc = "bmc.lab01: drac-pve02.lab01 reports no MAC address NetBox holds";
        let entries = [
            warned("04:47:00", &EVERY_SOURCE, &[hypervisor, bmc]),
            run("07:50:00", &HYPERVISORS, &[]),
            run("07:55:00", &HYPERVISORS, &[]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 1 warning | sources=3 failed=0 stale=0 warnings=1\n\
             warnings of the last runs:\n  \
             bmc.lab01: drac-pve02.lab01 reports no MAC address NetBox holds\n"
        );
    }

    // A warning that names no source selected by its run is the run's (the
    // release of NetBox, the reverse lookups): it stands for every source of
    // that run, here until the BMC, read by it, is read again.
    #[test]
    fn a_warning_that_names_no_source_stands_for_every_source_of_its_run() {
        let release = "NetBox 4.8.0 is a release this build was not tested with";
        let entries = [
            warned("04:47:00", &EVERY_SOURCE, &[release]),
            run("07:50:00", &HYPERVISORS, &[]),
            run("07:55:00", &HYPERVISORS, &[]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 1 warning | sources=3 failed=0 stale=0 warnings=1\n\
             warnings of the last runs:\n  \
             NetBox 4.8.0 is a release this build was not tested with\n"
        );
    }

    // Both hypervisors were selected by the run that said it: it is listed
    // once, and the warning of the BMC run after it.
    #[test]
    fn a_warning_said_for_several_sources_is_listed_once() {
        let bmc = "bmc.lab01: drac-pve02.lab01 reports no MAC address NetBox holds";
        let entries = [warned("04:47:00", &["bmc.lab01"], &[bmc]), warned("07:55:00", &HYPERVISORS, &[SHARED])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 2 warnings | sources=3 failed=0 stale=0 warnings=2\n\
             warnings of the last runs:\n  \
             ip 192.0.2.72/24 of web02.lab01: also assigned to web01.lab01; not created\n  \
             bmc.lab01: drac-pve02.lab01 reports no MAC address NetBox holds\n"
        );
    }

    // A warning never hides a worse state: the sources come first, the
    // warnings after them.
    #[test]
    fn the_warnings_come_after_the_sources_that_are_not_ok() {
        let mut last = warned("07:55:00", &HYPERVISORS, &[SHARED]);
        last.errors = vec!["pve02.lab02: connect: Connection refused".to_owned()];
        let entries = [run("05:50:00", &HYPERVISORS, &[]), last];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Critical);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - pve02.lab02: no success for 2h 09m, bmc.lab01: no success in the journal, \
             1 warning | sources=3 failed=1 stale=2 warnings=1\n\
             pve02.lab02: no success for 2h 09m\n  \
             pve02.lab02: connect: Connection refused\n\
             bmc.lab01: no success in the journal\n\
             warnings of the last runs:\n  \
             ip 192.0.2.72/24 of web02.lab01: also assigned to web01.lab01; not created\n"
        );
    }

    #[test]
    fn a_warning_cannot_break_the_output() {
        let entries = [bmc_run(), warned("07:55:00", &HYPERVISORS, &["vm a|b\u{1b}[2J"])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 1 warning | sources=3 failed=0 stale=0 warnings=1\n\
             warnings of the last runs:\n  \
             vm a/b\\u{1b}[2J\n"
        );
    }

    // A warning a run says by design (a source priority that settles a
    // field, a release of NetBox run with `unsupported_version = "warn"`)
    // would keep the check at WARNING for good, and acknowledging the service
    // would hide a run that fails: the operator names the ones that are known.
    #[test]
    fn a_warning_the_operator_ignores_does_not_change_the_state() {
        let priority = "vm web01: reported differently by vc01 and bmc.lab01; vc01 wins (source priority)";
        let entries = [bmc_run(), warned("07:55:00", &HYPERVISORS, &[priority, SHARED])];
        let ignored = [parse_ignored(r"\(source priority\)$").unwrap()];
        let verdict = evaluate(&entries, &ages(), &ignored, now());
        assert_eq!(verdict.state, State::Warning);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 1 warning | sources=3 failed=0 stale=0 warnings=1\n\
             warnings of the last runs:\n  \
             ip 192.0.2.72/24 of web02.lab01: also assigned to web01.lab01; not created\n\
             ignored warnings:\n  \
             vm web01: reported differently by vc01 and bmc.lab01; vc01 wins (source priority)\n"
        );
        let all = [parse_ignored("source priority").unwrap(), parse_ignored("^ip ").unwrap()];
        let verdict = evaluate(&entries, &ages(), &all, now());
        assert_eq!(verdict.state, State::Ok);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC OK - 3 sources synced | sources=3 failed=0 stale=0 warnings=0\n\
             ignored warnings:\n  \
             vm web01: reported differently by vc01 and bmc.lab01; vc01 wins (source priority)\n  \
             ip 192.0.2.72/24 of web02.lab01: also assigned to web01.lab01; not created\n"
        );
    }

    #[test]
    fn an_ignored_warning_is_a_regular_expression() {
        assert!(parse_ignored("wins \\(source priority\\)").is_ok());
        let refused = parse_ignored("(unclosed").unwrap_err();
        assert!(refused.starts_with("invalid regular expression '(unclosed': "), "{refused}");
    }

    // No silent gap: a kind without a maximum age is a check to complete.
    #[test]
    fn a_source_whose_kind_has_no_max_age_is_unknown() {
        let entries = [bmc_run(), run("07:55:00", &HYPERVISORS, &[])];
        let verdict = evaluate(&entries, &ages()[..1], &[], now());
        assert_eq!(verdict.state, State::Unknown);
        assert_eq!(verdict.text, "NETBOX-OMNISYNC UNKNOWN - no --max-age for bmc (bmc.lab01)\n");
    }

    const SYNC01: &str = "sync01.lab01";
    const SAT01: &str = "sat01.lab02";

    /// `run`, by `host`, of a file two hosts share: the satellite launches
    /// pve02.lab02, the central server pve01.lab01 and the BMCs.
    fn run_on(host: &str, started: &str, selected: &[&str], errors: &[&str]) -> Entry {
        let mut entry = run(started, selected, errors);
        entry.runner = Some(host.to_owned());
        for configured in &mut entry.configured {
            let runner = if configured.name == "pve02.lab02" { SAT01 } else { SYNC01 };
            configured.runner = Some(runner.to_owned());
        }
        entry
    }

    // The journal is the one of a host: the sources another host launches
    // have no run in it, and are that host's to check.
    #[test]
    fn a_source_of_another_host_is_not_judged() {
        let entries =
            [run_on(SAT01, "07:50:00", &["pve02.lab02"], &[]), run_on(SAT01, "07:55:00", &["pve02.lab02"], &[])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            (verdict.state, verdict.text.as_str()),
            (State::Ok, "NETBOX-OMNISYNC OK - 1 source synced | sources=1 failed=0 stale=0 warnings=0\n")
        );
        // The central server, from its own journal: its two sources, and not the one of the satellite.
        let entries = [
            run_on(SYNC01, "04:47:00", &["bmc.lab01"], &[]),
            run_on(SYNC01, "07:55:00", &["pve01.lab01"], &["pve01.lab01: unreachable"]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - pve01.lab01: no success in the journal | sources=2 failed=1 stale=1 warnings=0\n\
             pve01.lab01: no success in the journal\n  pve01.lab01: unreachable\n"
        );
    }

    // The invariant holds for each host: what it launches and never selected is a gap.
    #[test]
    fn a_source_of_the_host_no_run_selected_is_critical() {
        let entries = [run_on(SYNC01, "07:55:00", &["pve01.lab01"], &[])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(verdict.state, State::Critical);
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - bmc.lab01: no success in the journal | sources=2 failed=0 stale=1 warnings=0\n\
             bmc.lab01: no success in the journal\n"
        );
    }

    // The command of Icinga is the same on every host: a kind this host
    // launches no source of needs no age here, and one it launches still does.
    #[test]
    fn a_kind_only_another_host_runs_needs_no_max_age() {
        let hypervisors = &ages()[..1];
        let entries = [run_on(SAT01, "07:55:00", &["pve02.lab02"], &[])];
        assert_eq!(evaluate(&entries, hypervisors, &[], now()).state, State::Ok);
        let entries = [run_on(SYNC01, "07:55:00", &["pve01.lab01"], &[])];
        let verdict = evaluate(&entries, hypervisors, &[], now());
        assert_eq!(verdict.text, "NETBOX-OMNISYNC UNKNOWN - no --max-age for bmc (bmc.lab01)\n");
    }

    // A host that launched every source before the file was shared keeps
    // their runs in its journal for a week: what they warned of is no longer its to tell.
    #[test]
    fn the_warnings_of_the_sources_of_another_host_do_not_stand() {
        let before = warned("07:50:00", &["pve01.lab01", "pve02.lab02", "bmc.lab01"], &["pve01.lab01: w1", SHARED]);
        let entries = [before, run_on(SAT01, "07:55:00", &["pve02.lab02"], &[])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            (verdict.state, verdict.text.as_str()),
            (State::Ok, "NETBOX-OMNISYNC OK - 1 source synced | sources=1 failed=0 stale=0 warnings=0\n")
        );
        // Those of its own source still do.
        let mut warning = run_on(SAT01, "07:55:00", &["pve02.lab02"], &[]);
        warning.warnings = vec!["pve02.lab02: w2".to_owned()];
        let entries = [warned("07:50:00", &["pve01.lab01"], &["pve01.lab01: w1"]), warning];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - 1 warning | sources=1 failed=0 stale=0 warnings=1\n\
             warnings of the last runs:\n  pve02.lab02: w2\n"
        );
    }

    #[test]
    fn a_journal_without_runner_judges_every_source() {
        // A file one host runs, as before: the two sources no run selected are its gaps.
        let entries = [run("07:55:00", &["pve02.lab02"], &[])];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - pve01.lab01: no success in the journal, bmc.lab01: no success in the journal \
             | sources=3 failed=0 stale=2 warnings=0\n\
             pve01.lab01: no success in the journal\nbmc.lab01: no success in the journal\n"
        );
        // The last run decides: runs of a host of a shared file, then one of a file that is no longer shared.
        let entries = [run_on(SAT01, "07:50:00", &["pve02.lab02"], &[]), run("07:55:00", &["pve02.lab02"], &[])];
        assert_eq!(evaluate(&entries, &ages(), &[], now()).text, verdict.text);
    }

    // What the tool never writes, and must not read as "nothing to check":
    // a source no host is said to launch is judged, a host without a source is not OK.
    #[test]
    fn a_run_of_a_host_never_says_ok_over_a_source_nobody_is_said_to_launch() {
        let mut entry = run_on(SAT01, "07:55:00", &["pve02.lab02"], &[]);
        entry.configured[0].runner = None;
        let verdict = evaluate(&[entry], &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC CRITICAL - pve01.lab01: no success in the journal | sources=2 failed=0 stale=1 warnings=0\n\
             pve01.lab01: no success in the journal\n"
        );
        let stranger = run_on("sat02.lab03", "07:55:00", &["pve02.lab02"], &[]);
        let verdict = evaluate(&[stranger], &ages(), &[], now());
        assert_eq!(
            (verdict.state, verdict.text.as_str()),
            (State::Unknown, "NETBOX-OMNISYNC UNKNOWN - the last run names no source of sat02.lab03\n")
        );
    }

    #[test]
    fn a_journal_without_an_entry_is_unknown() {
        let verdict = evaluate(&[], &ages(), &[], now());
        assert_eq!(verdict.state, State::Unknown);
        assert_eq!(verdict.text, "NETBOX-OMNISYNC UNKNOWN - no run in the journal\n");
        assert_eq!(unknown("cannot read x").text, "NETBOX-OMNISYNC UNKNOWN - cannot read x\n");
    }

    // A `|` starts the performance data for Icinga; a control character
    // reaches the notification as is.
    #[test]
    fn what_a_source_says_cannot_break_the_output() {
        let entries = [
            bmc_run(),
            run("07:50:00", &HYPERVISORS, &[]),
            run("07:55:00", &HYPERVISORS, &["pve01.lab01: a|b\u{1b}[2J"]),
        ];
        let verdict = evaluate(&entries, &ages(), &[], now());
        assert_eq!(
            verdict.text,
            "NETBOX-OMNISYNC WARNING - pve01.lab01: last run failed | sources=3 failed=1 stale=0 warnings=0\n\
             pve01.lab01: last run failed\n  \
             pve01.lab01: a/b\\u{1b}[2J\n"
        );
    }

    #[test]
    fn the_exit_code_is_the_state() {
        let codes: Vec<u8> = [State::Ok, State::Warning, State::Critical, State::Unknown].map(State::code).to_vec();
        assert_eq!(codes, [0, 1, 2, 3]);
    }
}
