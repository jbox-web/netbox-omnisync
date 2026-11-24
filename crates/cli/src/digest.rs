//! `netbox-omnisync digest`: one mail of what the runs of a period changed
//! and what failed, read from the journal of the runs, instead of a cron mail
//! per run.
//!
//! The message is a `multipart/alternative`: the text report of the period,
//! and the same in HTML, laid out as a notification of Icinga (a card on a
//! grey page, a coloured accent, the details in a table, the output in a dark
//! box), with inline styles and tables only, which is what mail clients keep.
//! Both parts are base64, so that no line of a name or of an error can break
//! the message. It is handed to `sendmail -t -oi`, which adds `From` and
//! `Date`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};
use omnisync_core::report::{field_lines, printable, render, sections_of};
use omnisync_core::{Action, Change, Outcome};

use crate::journal::Entry;

/// The changes the HTML part shows at most; the text part shows them all.
pub const MAX_CHANGES: usize = 300;

/// The boundary of the parts. A base64 line never holds `=` but at its end,
/// nor `_`: the boundary cannot occur in a part.
const BOUNDARY: &str = "=_netbox-omnisync-digest";

/// A change, with the start of the run that made it.
#[derive(Debug, Clone, PartialEq)]
pub struct Dated<'e> {
    pub at: Timestamp,
    pub change: &'e Change,
}

/// A warning or an error of the period, and the number of runs that said it:
/// a source that fails all day fails in 288 runs, and is one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counted {
    pub text: String,
    pub runs: usize,
}

/// What the runs of a period did.
#[derive(Debug, Clone, PartialEq)]
pub struct Digest<'e> {
    pub from: Timestamp,
    pub to: Timestamp,
    /// The runs that ended in the period.
    pub runs: usize,
    /// The sources these runs selected.
    pub sources: usize,
    /// Every change, in the order the runs made them.
    pub changes: Vec<Dated<'e>>,
    pub warnings: Vec<Counted>,
    pub errors: Vec<Counted>,
    /// The changes written to NetBox.
    pub applied: usize,
}

/// What the HTML part says besides the digest.
#[derive(Debug, Clone)]
pub struct Page<'a> {
    /// The time zone the times are shown in: the one of the host.
    pub time_zone: &'a TimeZone,
    /// The URL of NetBox, for the link to its changelog.
    pub netbox_url: &'a str,
    pub version: &'a str,
    pub hostname: &'a str,
}

/// The colours of the card: what was written, what changed, what failed.
const GREEN: &str = "#16a34a";
const RED: &str = "#dc2626";
const GREY: &str = "#6b7280";
const DARK: &str = "#111827";
const MONOSPACE: &str = "Menlo,Consolas,'Courier New',monospace";

/// The warnings or the errors of `runs`, each once, in the order they were
/// first said, with the number of runs that said it.
fn counted<'e>(runs: &[&'e Entry], said: impl Fn(&'e Entry) -> &'e [String]) -> Vec<Counted> {
    let mut counted: Vec<Counted> = Vec::new();
    for run in runs {
        let mut seen: Vec<&str> = Vec::new();
        for text in said(run) {
            if seen.contains(&text.as_str()) {
                continue;
            }
            seen.push(text);
            match counted.iter_mut().find(|known| known.text == *text) {
                Some(known) => known.runs += 1,
                None => counted.push(Counted { text: text.clone(), runs: 1 }),
            }
        }
    }
    counted
}

/// The runs of `entries` that ended within `since` before `now`: after its
/// start, up to `now` included.
///
/// An entry is written when its run ends: a run that started before the
/// period and ended in it was in no earlier digest. Two digests of back to
/// back periods never take the same run, nor leave one out.
pub fn collect(entries: &[Entry], since: SignedDuration, now: Timestamp) -> Digest<'_> {
    let from = now.checked_sub(since).unwrap_or(now);
    let runs: Vec<&Entry> =
        entries.iter().filter(|entry| entry.ended_at().is_some_and(|ended| from < ended && ended <= now)).collect();
    let mut sources: Vec<&str> = runs.iter().flat_map(|run| run.selected.iter().map(String::as_str)).collect();
    sources.sort_unstable();
    sources.dedup();
    let changes = runs
        .iter()
        .filter_map(|run| Some((run.started_at()?, run)))
        .flat_map(|(at, run)| run.changes.iter().map(move |change| Dated { at, change }))
        .collect();
    Digest {
        from,
        to: now,
        runs: runs.len(),
        sources: sources.len(),
        changes,
        warnings: counted(&runs, |run| &run.warnings),
        errors: counted(&runs, |run| &run.errors),
        applied: runs.iter().map(|run| run.applied).sum(),
    }
}

/// `count` of `word`, in the plural but for one.
fn plural(count: usize, word: &str) -> String {
    if count == 1 { format!("1 {word}") } else { format!("{count} {word}s") }
}

/// A period as the subject says it: `24 h`, `90 min`, `45 s`.
fn period_length(duration: SignedDuration) -> String {
    let seconds = duration.as_secs();
    if seconds % 3600 == 0 {
        format!("{} h", seconds / 3600)
    } else if seconds % 60 == 0 {
        format!("{} min", seconds / 60)
    } else {
        format!("{seconds} s")
    }
}

/// A warning or an error as the digest lists it, with the runs that said it.
fn counted_line(counted: &Counted) -> String {
    if counted.runs > 1 { format!("{} (in {} runs)", counted.text, counted.runs) } else { counted.text.clone() }
}

/// A text of a source as HTML may hold it: escaped as the report escapes it,
/// then every character that is markup made an entity.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in printable(text).chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(character),
        }
    }
    out
}

/// The pill of an action: its mark and its verb, its background and its text colour.
fn pill(action: Action) -> (&'static str, &'static str, &'static str) {
    match action {
        Action::Create => ("+ create", "#dcfce7", "#166534"),
        Action::Update => ("~ update", "#fef3c7", "#92400e"),
        Action::Delete => ("\u{2212} delete", "#fee2e2", "#991b1b"),
    }
}

impl Digest<'_> {
    /// Nothing changed and nothing failed: no mail.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.errors.is_empty()
    }

    /// What the period holds: `2 changes, 1 error`.
    fn counts(&self) -> String {
        let mut parts = Vec::new();
        if !self.changes.is_empty() {
            parts.push(plural(self.changes.len(), "change"));
        }
        if !self.errors.is_empty() {
            parts.push(plural(self.errors.len(), "error"));
        }
        if parts.is_empty() { "nothing".to_owned() } else { parts.join(", ") }
    }

    /// The subject of the mail, in ASCII.
    pub fn subject(&self) -> String {
        format!("[netbox-omnisync] {} in the last {}", self.counts(), period_length(self.to.duration_since(self.from)))
    }

    /// The period in `time_zone`, to the minute: `2026-11-19 08:00 +01:00 → 2026-11-20 08:00 +01:00`.
    fn period(&self, time_zone: &TimeZone) -> String {
        let local =
            |moment: Timestamp| moment.to_zoned_datetime(time_zone.clone()).strftime("%Y-%m-%d %H:%M %:z").to_string();
        format!("{} \u{2192} {}", local(self.from), local(self.to))
    }

    /// The text part: the period, then the report of its runs.
    pub fn text(&self, time_zone: &TimeZone) -> String {
        let outcome = Outcome {
            changes: self.changes.iter().map(|dated| dated.change.clone()).collect(),
            warnings: self.warnings.iter().map(counted_line).collect(),
            errors: self.errors.iter().map(counted_line).collect(),
            applied: self.applied,
            seconds: None,
        };
        format!(
            "Period: {}\nRuns: {}\nSources: {}\n{}\n",
            self.period(time_zone),
            self.runs,
            self.sources,
            render(&outcome, false)
        )
    }

    /// One row of the HTML part per change, under the title of its section.
    fn change_rows(&self, time_zone: &TimeZone) -> String {
        let shown = &self.changes[..self.changes.len().min(MAX_CHANGES)];
        let mut rows = String::new();
        for (title, changes) in sections_of(shown, |dated| dated.change) {
            rows.push_str(&format!(
                "<tr><td style=\"padding:16px 0 4px 0;font-size:13px;font-weight:bold;\
                 border-bottom:1px solid #e5e7eb;\">{}</td></tr>\n",
                escape(title)
            ));
            for dated in changes {
                let change = dated.change;
                let time = dated.at.to_zoned_datetime(time_zone.clone()).strftime("%H:%M").to_string();
                let (label, background, colour) = pill(change.action);
                let mut fields = String::new();
                for line in field_lines(change) {
                    let after = format!("<span style=\"color:{GREEN};\">{}</span>", escape(&line.after));
                    let value = match &line.before {
                        Some(before) => {
                            format!("<span style=\"color:{RED};\">{}</span> \u{2192} {after}", escape(before))
                        }
                        None => after,
                    };
                    fields.push_str(&format!(
                        "<div style=\"font-family:{MONOSPACE};font-size:12px;color:#374151;padding:2px 0 0 52px;\">\
                         {}: {value}</div>",
                        escape(line.name)
                    ));
                }
                rows.push_str(&format!(
                    "<tr><td style=\"padding:6px 0;font-size:13px;border-bottom:1px solid #f3f4f6;\">\
                     <span style=\"color:#9ca3af;font-family:{MONOSPACE};font-size:12px;\">{time}</span> \
                     <span style=\"display:inline-block;padding:1px 8px;border-radius:999px;background:{background};\
                     color:{colour};font-size:11px;font-weight:bold;\">{label}</span> \
                     <strong>{}</strong> {}{fields}</td></tr>\n",
                    escape(&change.kind),
                    escape(&change.key)
                ));
            }
        }
        if self.changes.len() > MAX_CHANGES {
            let more = self.changes.len() - MAX_CHANGES;
            rows.push_str(&format!(
                "<tr><td style=\"padding:8px 0;font-size:13px;color:{GREY};\">\u{2026} and {} \
                 (see the changelog)</td></tr>\n",
                plural(more, "more change")
            ));
        }
        rows
    }

    /// The warnings and the errors, as the dark output box shows them; None without any.
    fn output(&self) -> Option<String> {
        let mut blocks = Vec::new();
        for (title, said) in [("Errors", &self.errors), ("Warnings", &self.warnings)] {
            if !said.is_empty() {
                let lines: Vec<String> =
                    said.iter().map(|counted| format!("  {}", escape(&counted_line(counted)))).collect();
                blocks.push(format!("{title} ({})\n{}", said.len(), lines.join("\n")));
            }
        }
        (!blocks.is_empty()).then(|| blocks.join("\n\n"))
    }

    /// The HTML part.
    pub fn html(&self, page: &Page<'_>) -> String {
        let failed = !self.errors.is_empty();
        let (accent, badge) = if failed { (RED, "ERRORS") } else { (GREEN, "CHANGES") };
        let label = |name: &str| {
            format!(
                "<td style=\"padding:4px 12px 4px 0;color:{GREY};font-size:11px;text-transform:uppercase;\
                 letter-spacing:1px;width:90px;vertical-align:top;\">{name}</td>"
            )
        };
        let value = |text: &str| format!("<td style=\"padding:4px 0;font-size:13px;\">{text}</td>");
        let details = format!(
            "<tr>{}{}</tr>\n<tr>{}{}</tr>\n<tr>{}{}</tr>\n",
            label("Period"),
            value(&escape(&self.period(page.time_zone))),
            label("Runs"),
            value(&self.runs.to_string()),
            label("Sources"),
            value(&self.sources.to_string()),
        );
        let output = self.output().map_or(String::new(), |output| {
            format!(
                "<tr><td style=\"padding:16px 24px 0 24px;\"><pre style=\"margin:0;padding:12px;background:{DARK};\
                 color:#e5e7eb;border-radius:6px;font-family:{MONOSPACE};font-size:12px;white-space:pre-wrap;\
                 word-break:break-word;\">{output}</pre></td></tr>\n"
            )
        });
        // To the second: the changelog of NetBox filters on it.
        let start = Timestamp::from_second(self.from.as_second()).unwrap_or(self.from);
        let changelog = format!("{}/core/changelog/?time_after={start}", page.netbox_url.trim_end_matches('/'));
        format!(
            "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{subject}</title></head>\n\
             <body style=\"margin:0;padding:0;background:#f3f4f6;\">\n\
             <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
             style=\"background:#f3f4f6;padding:24px 8px;\"><tr><td align=\"center\">\n\
             <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
             style=\"max-width:600px;background:#ffffff;border-radius:8px;border-top:4px solid {accent};\
             font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;color:{DARK};\">\n\
             <tr><td style=\"padding:16px 24px 0 24px;\"><table role=\"presentation\" width=\"100%\" \
             cellpadding=\"0\" cellspacing=\"0\"><tr>\
             <td style=\"font-weight:bold;font-size:14px;\">netbox-omnisync</td>\
             <td align=\"right\" style=\"font-size:11px;color:{GREY};letter-spacing:1px;\
             font-variant:small-caps;\">NETBOX SYNC</td></tr></table></td></tr>\n\
             <tr><td style=\"padding:16px 24px 0 24px;font-size:28px;font-weight:bold;\">{title}</td></tr>\n\
             <tr><td style=\"padding:8px 24px 0 24px;\"><span style=\"display:inline-block;padding:2px 10px;\
             border-radius:999px;background:{accent};color:#ffffff;font-size:11px;font-weight:bold;\
             letter-spacing:1px;\">{badge}</span></td></tr>\n\
             <tr><td style=\"padding:16px 24px 0 24px;\"><table role=\"presentation\" cellpadding=\"0\" \
             cellspacing=\"0\">\n{details}</table></td></tr>\n\
             <tr><td style=\"padding:8px 24px 0 24px;\"><table role=\"presentation\" width=\"100%\" \
             cellpadding=\"0\" cellspacing=\"0\">\n{rows}</table></td></tr>\n\
             {output}\
             <tr><td style=\"padding:24px 24px 8px 24px;\"><a href=\"{href}\" style=\"display:inline-block;\
             color:#ffffff;background:{DARK};text-decoration:none;padding:10px 18px;border-radius:6px;\
             font-size:14px;font-weight:bold;\">Open the NetBox changelog \u{2192}</a></td></tr>\n\
             <tr><td style=\"padding:16px 24px;font-size:11px;color:#9ca3af;\">Sent by netbox-omnisync \
             {version} on {hostname}</td></tr>\n\
             </table>\n</td></tr></table>\n</body></html>\n",
            subject = escape(&self.subject()),
            title = escape(&self.counts()),
            rows = self.change_rows(page.time_zone),
            href = escape(&changelog),
            version = escape(page.version),
            hostname = escape(page.hostname),
        )
    }
}

/// `bytes` in base64, in lines of 76 characters.
fn base64_lines(bytes: &[u8]) -> String {
    let encoded = data_encoding::BASE64.encode(bytes);
    // Base64 is ASCII: every 76 bytes are 76 characters.
    let lines: Vec<&str> = encoded.as_bytes().chunks(76).filter_map(|line| std::str::from_utf8(line).ok()).collect();
    lines.join("\n")
}

/// The message handed to sendmail: the headers, then both parts in base64.
/// No `To` without an address.
pub fn message(to: &[String], subject: &str, text: &str, html: &str) -> String {
    let mut message = String::new();
    if !to.is_empty() {
        message.push_str(&format!("To: {}\n", to.join(", ")));
    }
    message.push_str(&format!(
        "Subject: {subject}\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"{BOUNDARY}\"\n\n"
    ));
    for (subtype, body) in [("plain", text), ("html", html)] {
        message.push_str(&format!(
            "--{BOUNDARY}\nContent-Type: text/{subtype}; charset=utf-8\nContent-Transfer-Encoding: base64\n\n{}\n",
            base64_lines(body.as_bytes())
        ));
    }
    message.push_str(&format!("--{BOUNDARY}--\n"));
    message
}

/// Hand `message` to `<sendmail> -t -oi`: the recipients are read from its
/// `To`, and a line made of a dot does not end it.
pub fn send(sendmail: &Path, message: &[u8]) -> Result<(), String> {
    let shown = sendmail.display();
    let mut child = Command::new(sendmail)
        .args(["-t", "-oi"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start {shown}: {error}"))?;
    // Closed once written: sendmail reads to the end of its input.
    let written = child.stdin.take().map(|mut stdin| stdin.write_all(message));
    let status = child.wait().map_err(|error| format!("cannot wait for {shown}: {error}"))?;
    if !status.success() {
        return Err(format!("{shown} could not send the mail: {status}"));
    }
    match written {
        Some(Err(error)) => Err(format!("cannot hand the mail to {shown}: {error}")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use data_encoding::BASE64;
    use serde_json::json;

    use super::*;
    use crate::journal::Configured;

    /// 2026-11-20T08:00:00+01:00.
    fn now() -> Timestamp {
        "2026-11-20T07:00:00Z".parse().unwrap()
    }

    fn paris() -> TimeZone {
        TimeZone::fixed(jiff::tz::offset(1))
    }

    fn day() -> SignedDuration {
        SignedDuration::from_hours(24)
    }

    fn run(started: &str, selected: &[&str], changes: Vec<Change>) -> Entry {
        Entry {
            version: 1,
            started: started.to_owned(),
            seconds: 12.0,
            runner: None,
            configured: vec![Configured {
                name: "pve01.lab01".to_owned(),
                kind: "hypervisor".to_owned(),
                runner: None,
            }],
            selected: selected.iter().map(|name| (*name).to_owned()).collect(),
            changes,
            applied: 0,
            warnings: vec![],
            errors: vec![],
        }
    }

    fn description() -> Change {
        Change::new("interface", Action::Update, "nexus01.lab01", "Ethernet1/7")
            .fields([("description", json!("uplink"))])
            .before([("description", json!(""))])
    }

    fn web01() -> Change {
        Change::new("vm", Action::Create, "web01", "web01").fields([("name", json!("web01")), ("vcpus", json!(2))])
    }

    /// A day of runs: one just before it, then three within it.
    fn journal() -> Vec<Entry> {
        let before = run("2026-11-19T07:59:00+01:00", &["nexus01.lab01"], vec![description()]);
        let switch = Entry { applied: 1, ..run("2026-11-19T09:00:00+01:00", &["nexus01.lab01"], vec![description()]) };
        let quiet =
            Entry { warnings: vec!["w".to_owned()], ..run("2026-11-20T07:50:00+01:00", &["pve01.lab01"], vec![]) };
        let failed = Entry {
            warnings: vec!["w".to_owned()],
            errors: vec!["pve01.lab01: timeout".to_owned()],
            ..run("2026-11-20T07:55:00+01:00", &["pve01.lab01", "nexus01.lab01"], vec![web01()])
        };
        vec![before, switch, quiet, failed]
    }

    fn page() -> (TimeZone, String) {
        (paris(), "https://netbox.example.net/".to_owned())
    }

    fn html(digest: &Digest<'_>) -> String {
        let (time_zone, url) = page();
        digest.html(&Page { time_zone: &time_zone, netbox_url: &url, version: "9.9.9", hostname: "sync01.lab01" })
    }

    /// The decoded parts of a message: its headers, the text, the HTML.
    fn parts(message: &str) -> (String, String, String) {
        let (headers, body) = message.split_once("\n\n").unwrap();
        let mut decoded = Vec::new();
        for part in body.split(&format!("--{BOUNDARY}")).skip(1) {
            if part.starts_with("--") {
                break;
            }
            let (_, data) = part.trim_start_matches('\n').split_once("\n\n").unwrap();
            for line in data.lines() {
                assert!(line.len() <= 76, "{line}");
            }
            let joined: String = data.lines().collect();
            decoded.push(String::from_utf8(BASE64.decode(joined.as_bytes()).unwrap()).unwrap());
        }
        let [text, html]: [String; 2] = decoded.try_into().unwrap();
        (headers.to_owned(), text, html)
    }

    #[test]
    fn the_digest_takes_the_runs_that_started_within_the_period() {
        let journal = journal();
        let digest = collect(&journal, day(), now());
        assert_eq!(digest.from, "2026-11-19T07:00:00Z".parse::<Timestamp>().unwrap());
        assert_eq!(digest.to, now());
        assert_eq!((digest.runs, digest.sources, digest.applied), (3, 2, 1));
        let changes: Vec<(String, &Change)> =
            digest.changes.iter().map(|dated| (dated.at.to_string(), dated.change)).collect();
        assert_eq!(
            changes,
            [("2026-11-19T08:00:00Z".to_owned(), &description()), ("2026-11-20T06:55:00Z".to_owned(), &web01())]
        );
        assert_eq!(digest.warnings, [Counted { text: "w".to_owned(), runs: 2 }]);
        assert_eq!(digest.errors, [Counted { text: "pve01.lab01: timeout".to_owned(), runs: 1 }]);
        assert!(!digest.is_empty());
    }

    // An entry is written when its run ends: a run that started before the
    // period and ended in it was in no earlier digest, and belongs to this one.
    // The window starts at 2026-11-19T08:00:00+01:00; each run takes 12 s.
    #[test]
    fn a_run_belongs_to_the_period_it_ended_in() {
        let ended_inside = run("2026-11-19T07:59:55+01:00", &["pve01.lab01"], vec![web01()]);
        let ended_before = run("2026-11-19T07:59:40+01:00", &["nexus01.lab01"], vec![description()]);
        let journal = [ended_before, ended_inside];
        let digest = collect(&journal, day(), now());
        assert_eq!(digest.runs, 1);
        let changes: Vec<&Change> = digest.changes.iter().map(|dated| dated.change).collect();
        assert_eq!(changes, [&web01()]);
    }

    // The warnings alone are no reason for a mail: some are permanent.
    #[test]
    fn a_period_without_a_change_nor_an_error_is_empty() {
        let journal = journal();
        assert!(collect(&journal[2..3], day(), now()).is_empty());
        assert!(collect(&journal[..1], day(), now()).is_empty());
        assert!(collect(&[], day(), now()).is_empty());
    }

    #[test]
    fn the_subject_counts_the_changes_and_the_errors_of_the_period() {
        let journal = journal();
        assert_eq!(collect(&journal, day(), now()).subject(), "[netbox-omnisync] 2 changes, 1 error in the last 24 h");
        let switch = &journal[1..2];
        assert_eq!(collect(switch, day(), now()).subject(), "[netbox-omnisync] 1 change in the last 24 h");
        let failing = Entry { errors: vec!["a: x".to_owned(), "b: y".to_owned()], ..journal[2].clone() };
        let failing = [failing];
        let digest = collect(&failing, SignedDuration::from_mins(90), now());
        assert_eq!(digest.subject(), "[netbox-omnisync] 2 errors in the last 90 min");
        assert_eq!(
            collect(&failing, SignedDuration::from_hours(48), now()).subject(),
            "[netbox-omnisync] 2 errors in the last 48 h"
        );
    }

    #[test]
    fn the_text_part_is_the_report_of_the_period() {
        let journal = journal();
        let text = collect(&journal, day(), now()).text(&paris());
        assert_eq!(
            text,
            "Period: 2026-11-19 08:00 +01:00 → 2026-11-20 08:00 +01:00\n\
             Runs: 3\n\
             Sources: 2\n\
             \n\
             nexus01.lab01\n  \
             ~ interface Ethernet1/7\n      \
             description: '' → 'uplink'\n\
             \n\
             web01\n  \
             + vm web01\n      \
             vcpus: 2\n\
             \n\
             Warnings (1)\n  \
             w (in 2 runs)\n\
             \n\
             Errors (1)\n  \
             pve01.lab01: timeout\n\
             \n\
             2 change(s): 1 create, 1 update, 0 delete · 1 warning(s) · 1 error(s) · 1 applied\n"
        );
    }

    #[test]
    fn the_message_carries_both_parts_in_base64_under_its_headers() {
        let journal = journal();
        let digest = collect(&journal, day(), now());
        let (text, html) = (digest.text(&paris()), html(&digest));
        let to = ["noc@example.net".to_owned(), "ops@example.net".to_owned()];
        let message = message(&to, &digest.subject(), &text, &html);
        let (headers, decoded_text, decoded_html) = parts(&message);
        assert_eq!(
            headers,
            "To: noc@example.net, ops@example.net\n\
             Subject: [netbox-omnisync] 2 changes, 1 error in the last 24 h\n\
             MIME-Version: 1.0\n\
             Content-Type: multipart/alternative; boundary=\"=_netbox-omnisync-digest\""
        );
        assert_eq!((decoded_text, decoded_html), (text, html));
        assert!(message.contains(
            "--=_netbox-omnisync-digest\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n"
        ));
        assert!(message.contains(
            "--=_netbox-omnisync-digest\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\n"
        ));
        assert!(message.ends_with("\n--=_netbox-omnisync-digest--\n"), "{message}");
        // Every line of base64 is full but the last of each part.
        let long = message.lines().filter(|line| line.len() == 76).count();
        assert!(long > 2, "{message}");
        // Without an address, the message has no recipient to name.
        let unsent = super::message(&[], "s", "t", "h");
        assert!(unsent.starts_with("Subject: s\nMIME-Version: 1.0\n"), "{unsent}");
    }

    #[test]
    fn the_html_part_is_a_card_of_the_period() {
        let journal = journal();
        let html = html(&collect(&journal, day(), now()));
        for fragment in [
            "<title>[netbox-omnisync] 2 changes, 1 error in the last 24 h</title>",
            "background:#f3f4f6",
            "max-width:600px",
            // Errors: the accent and the badge are red.
            "border-top:4px solid #dc2626",
            ">ERRORS</span>",
            ">netbox-omnisync</td>",
            ">NETBOX SYNC</td>",
            ">2 changes, 1 error</td>",
            ">Period</td>",
            ">2026-11-19 08:00 +01:00 → 2026-11-20 08:00 +01:00</td>",
            ">Runs</td>",
            ">3</td>",
            ">Sources</td>",
            ">2</td>",
            ">nexus01.lab01</td>",
            ">09:00</span>",
            ">~ update</span>",
            "<strong>interface</strong> Ethernet1/7",
            "description: <span style=\"color:#dc2626;\">&#39;&#39;</span> → <span style=\"color:#16a34a;\">&#39;uplink&#39;</span>",
            ">web01</td>",
            ">07:55</span>",
            ">+ create</span>",
            "<strong>vm</strong> web01",
            "vcpus: <span style=\"color:#16a34a;\">2</span>",
            "background:#111827",
            "Errors (1)\n  pve01.lab01: timeout\n\nWarnings (1)\n  w (in 2 runs)",
            "href=\"https://netbox.example.net/core/changelog/?time_after=2026-11-19T07:00:00Z\"",
            ">Open the NetBox changelog →</a>",
            "Sent by netbox-omnisync 9.9.9 on sync01.lab01",
        ] {
            assert!(html.contains(fragment), "{fragment}\n{html}");
        }
        assert!(!html.contains("<style"), "{html}");
    }

    #[test]
    fn changes_alone_make_a_green_card() {
        let journal = journal();
        let html = html(&collect(&journal[1..2], day(), now()));
        for fragment in ["border-top:4px solid #16a34a", ">CHANGES</span>", ">1 change</td>"] {
            assert!(html.contains(fragment), "{fragment}\n{html}");
        }
        assert!(!html.contains("#111827;color"), "no output box without warning nor error\n{html}");
    }

    #[test]
    fn a_deletion_is_a_red_pill() {
        let gone = Change::new("interface", Action::Delete, "nexus01.lab01", "Ethernet1/9");
        let journal = [run("2026-11-20T07:00:00+01:00", &["nexus01.lab01"], vec![gone])];
        let html = html(&collect(&journal, day(), now()));
        assert!(html.contains(">\u{2212} delete</span>"), "{html}");
        assert!(html.contains("<strong>interface</strong> Ethernet1/9"), "{html}");
    }

    // A name comes from a source: it must never become markup in the mail.
    #[test]
    fn every_text_of_a_source_is_escaped() {
        let hostile = Change::new("vm", Action::Create, "<script>alert(1)</script>", "<b>&\"x\"</b>")
            .fields([("comments", json!("<img src=x onerror=alert(1)>"))]);
        let mut entry = run("2026-11-20T07:00:00+01:00", &["pve01.lab01"], vec![hostile]);
        entry.errors = vec!["pve01.lab01: <script>".to_owned()];
        let journal = [entry];
        let html = html(&collect(&journal, day(), now()));
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("<img"), "{html}");
        assert!(!html.contains("<b>"), "{html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{html}");
        assert!(html.contains("&lt;b&gt;&amp;&quot;x&quot;&lt;/b&gt;"), "{html}");
        assert!(html.contains("pve01.lab01: &lt;script&gt;"), "{html}");
    }

    #[test]
    fn a_field_changed_several_times_shows_each_change_with_its_time() {
        let mtu = |from: i64, to: i64| {
            Change::new("interface", Action::Update, "nexus01.lab01", "Ethernet1/7")
                .fields([("mtu", json!(to))])
                .before([("mtu", json!(from))])
        };
        let journal = [
            run("2026-11-20T07:00:00+01:00", &["nexus01.lab01"], vec![mtu(1500, 9216)]),
            run("2026-11-20T07:05:00+01:00", &["nexus01.lab01"], vec![mtu(9216, 1500)]),
        ];
        let html = html(&collect(&journal, day(), now()));
        let first = html.find(">07:00</span>").expect("the first change");
        let second = html.find(">07:05</span>").expect("the second change");
        assert!(first < second, "{html}");
        let between = &html[first..second];
        assert!(
            between.contains("<span style=\"color:#dc2626;\">1500</span> → <span style=\"color:#16a34a;\">9216</span>")
        );
        assert!(
            html[second..]
                .contains("<span style=\"color:#dc2626;\">9216</span> → <span style=\"color:#16a34a;\">1500</span>")
        );
    }

    #[test]
    fn the_html_part_shows_the_first_300_changes_and_counts_the_others() {
        let changes: Vec<Change> =
            (0..302).map(|vid| Change::new("vlan", Action::Create, "", &vid.to_string())).collect();
        let journal = [run("2026-11-20T07:00:00+01:00", &["nexus01.lab01"], changes)];
        let digest = collect(&journal, day(), now());
        let html = html(&digest);
        assert_eq!(html.matches(">+ create</span>").count(), 300);
        assert!(html.contains("<strong>vlan</strong> 299<"), "{html}");
        assert!(!html.contains("<strong>vlan</strong> 300<"), "{html}");
        assert!(html.contains("… and 2 more changes (see the changelog)"), "{html}");
        // The text part has them all.
        assert_eq!(digest.text(&paris()).matches("+ vlan ").count(), 302);
        let one_more: Vec<Change> =
            (0..301).map(|vid| Change::new("vlan", Action::Create, "", &vid.to_string())).collect();
        let journal = [run("2026-11-20T07:00:00+01:00", &["nexus01.lab01"], one_more)];
        assert!(html_of(&journal).contains("… and 1 more change (see the changelog)"));
    }

    fn html_of(journal: &[Entry]) -> String {
        html(&collect(journal, day(), now()))
    }

    /// A sendmail of a test: a script that records its arguments and what it
    /// is handed, then exits with `code`.
    fn sendmail(directory: &Path, code: u8) -> std::path::PathBuf {
        let path = directory.join("sendmail");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{0}/arguments\"\ncat > \"{0}/message\"\nexit {code}\n",
            directory.display()
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn the_message_is_handed_to_sendmail_which_reads_the_recipients_in_it() {
        let directory = tempfile::tempdir().unwrap();
        let sendmail = sendmail(directory.path(), 0);
        send(&sendmail, b"To: noc@example.net\n\nbody\n").unwrap();
        assert_eq!(fs::read_to_string(directory.path().join("arguments")).unwrap(), "-t\n-oi\n");
        assert_eq!(fs::read_to_string(directory.path().join("message")).unwrap(), "To: noc@example.net\n\nbody\n");
    }

    #[test]
    fn a_sendmail_that_fails_or_cannot_start_is_an_error_naming_it() {
        let directory = tempfile::tempdir().unwrap();
        let failing = sendmail(directory.path(), 75);
        assert_eq!(
            send(&failing, b"To: noc@example.net\n\nbody\n"),
            Err(format!("{} could not send the mail: exit status: 75", failing.display()))
        );
        let missing = directory.path().join("nowhere/sendmail");
        let error = send(&missing, b"x").unwrap_err();
        assert!(error.starts_with(&format!("cannot start {}: ", missing.display())), "{error}");
    }
}
