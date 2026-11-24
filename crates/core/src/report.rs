//! Human-readable report of a run: grouped by section, one field per line.

use std::fmt::Write;

use serde_json::Value;

use crate::change::{Action, Change};
use crate::outcome::Outcome;

/// ANSI colours.
const BOLD: &str = "1";
const RED: &str = "31";
const YELLOW: &str = "33";
const GREEN: &str = "32";

/// The mark that opens the header of a change.
fn symbol(action: Action) -> &'static str {
    match action {
        Action::Create => "+",
        Action::Update => "~",
        Action::Delete => "-",
    }
}

/// ANSI colours: green create, yellow update, red delete.
fn action_colour(action: Action) -> &'static str {
    match action {
        Action::Create => GREEN,
        Action::Update => YELLOW,
        Action::Delete => RED,
    }
}

fn paint(text: &str, code: &str, colour: bool) -> String {
    if colour { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
}

/// Whether Python's `str.isprintable` holds for `character`, which decides
/// between the character itself and an escape in a `repr`.
///
/// Approximation: controls and the usual separators and format characters are
/// covered, not the whole Unicode database (unassigned and private-use code
/// points pass for printable).
fn is_printable(character: char) -> bool {
    !(character.is_control()
        || matches!(
            character,
            '\u{a0}'
                | '\u{ad}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200f}'
                | '\u{2028}'..='\u{202f}'
                | '\u{205f}'..='\u{2064}'
                | '\u{3000}'
                | '\u{feff}'
        ))
}

/// A string as Python's `repr` prints it: in single quotes, or in double
/// quotes when it holds a single quote and no double one.
fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if character == quote => {
                out.push('\\');
                out.push(character);
            }
            _ if is_printable(character) => out.push(character),
            _ => {
                let code = u32::from(character);
                // Writing to a String cannot fail.
                let _ = match code {
                    0..=0xff => write!(out, "\\x{code:02x}"),
                    0x100..=0xffff => write!(out, "\\u{code:04x}"),
                    _ => write!(out, "\\U{code:08x}"),
                };
            }
        }
    }
    out.push(quote);
    out
}

/// A number as Python's `repr` prints it. Only the exponent differs from what
/// serde_json prints: Python signs it and gives it two digits (`1e+16`, `1e-07`).
fn repr_number(number: &serde_json::Number) -> String {
    let text = number.to_string();
    let Some((mantissa, exponent)) = text.split_once('e') else {
        return text;
    };
    let (sign, digits) = match exponent.strip_prefix('-') {
        Some(digits) => ('-', digits),
        None => ('+', exponent.strip_prefix('+').unwrap_or(exponent)),
    };
    format!("{mantissa}e{sign}{digits:0>2}")
}

/// A field value as Python's `repr` prints it. A list stands for the tuple the
/// Python diff carries: `(10, 20)`, `(10,)`, `()`.
fn repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => repr_number(number),
        Value::String(text) => repr_str(text),
        Value::Array(items) => match items.as_slice() {
            [only] => format!("({},)", repr(only)),
            _ => format!("({})", items.iter().map(repr).collect::<Vec<_>>().join(", ")),
        },
        Value::Object(entries) => {
            let entries: Vec<String> =
                entries.iter().map(|(key, value)| format!("{}: {}", repr_str(key), repr(value))).collect();
            format!("{{{}}}", entries.join(", "))
        }
    }
}

/// A created object's empty fields say nothing: only the set ones are listed.
fn shown(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => true,
    }
}

/// A line of what a change shows under its header: an updated field with
/// its value before and after, or a field a creation sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLine<'c> {
    pub name: &'c str,
    /// The value before, as Python's `repr` prints it; None for a creation.
    pub before: Option<String>,
    /// The value written, as Python's `repr` prints it.
    pub after: String,
}

/// What `change` shows under its header, field by field: every updated field
/// with its value before and after; the fields a creation sets, but its empty
/// ones and a name that repeats the header; nothing for a cable (its key
/// names both ends) nor for a deletion. The text report and the HTML digest
/// both show these, so that they never tell a change differently.
pub fn field_lines(change: &Change) -> Vec<FieldLine<'_>> {
    if change.kind == "cable" || change.action == Action::Delete {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for (key, value) in &change.fields {
        if change.action == Action::Update {
            let before = repr(change.before.get(key).unwrap_or(&Value::Null));
            lines.push(FieldLine { name: key, before: Some(before), after: repr(value) });
        }
        // An interface's name repeats the header; a VLAN's name does not.
        else if !(key == "name" && value.as_str() == Some(change.key.as_str())) && shown(value) {
            lines.push(FieldLine { name: key, before: None, after: repr(value) });
        }
    }
    lines
}

fn change_lines(change: &Change, colour: bool) -> Vec<String> {
    let header = format!("{} {} {}", symbol(change.action), change.kind, printable(&change.key));
    let mut lines = vec![format!("  {}", paint(&header, action_colour(change.action), colour))];
    for line in field_lines(change) {
        match line.before {
            Some(before) => {
                let (before, after) = (paint(&before, RED, colour), paint(&line.after, GREEN, colour));
                lines.push(format!("      {}: {before} → {after}", line.name));
            }
            None => lines.push(format!("      {}: {}", line.name, line.after)),
        }
    }
    lines
}

/// The sections of the report: the VLANs, then one section per device in the
/// order of its first change, then the cables.
fn sections(changes: &[Change]) -> Vec<(&str, Vec<&Change>)> {
    sections_of(changes, |change| change)
}

/// The sections of the report over any `items` that each carry a change,
/// which `change` reaches: the VLANs, then one section per device in the
/// order of its first change, then the cables; within a section, the order of
/// `items`. The digest of several runs groups its changes this way, each with
/// the time of its run.
pub fn sections_of<T>(items: &[T], change: impl Fn(&T) -> &Change) -> Vec<(&str, Vec<&T>)> {
    let vlans: Vec<&T> = items.iter().filter(|item| change(item).kind == "vlan").collect();
    let cables: Vec<&T> = items.iter().filter(|item| change(item).kind == "cable").collect();
    let mut devices: Vec<(&str, Vec<&T>)> = Vec::new();
    for item in items.iter().filter(|item| change(item).kind != "vlan" && change(item).kind != "cable") {
        let device = change(item).device.as_str();
        match devices.iter_mut().find(|(name, _)| *name == device) {
            Some((_, of_device)) => of_device.push(item),
            None => devices.push((device, vec![item])),
        }
    }
    let mut sections = Vec::new();
    if !vlans.is_empty() {
        sections.push(("VLANs", vlans));
    }
    sections.append(&mut devices);
    if !cables.is_empty() {
        sections.push(("Cables", cables));
    }
    sections
}

/// A duration to the second, rounded half to even as Python's `round` does.
fn duration(seconds: f64) -> String {
    // A float-to-integer cast saturates, and a run does not last 2^63 seconds.
    let total = seconds.round_ties_even() as i64;
    let (minutes, rest) = (total.div_euclid(60), total.rem_euclid(60));
    if minutes == 0 { format!("{rest} s") } else { format!("{minutes} min {rest} s") }
}

fn summary(outcome: &Outcome) -> String {
    let warnings = format!("{} warning(s)", outcome.warnings.len());
    let errors = format!("{} error(s)", outcome.errors.len());
    let applied = format!("{} applied", outcome.applied);
    let mut parts = Vec::new();
    if outcome.changes.is_empty() && outcome.errors.is_empty() {
        parts.push("Nothing to do: NetBox matches the sources".to_owned());
        if !outcome.warnings.is_empty() {
            parts.push(warnings);
        }
        parts.push(applied);
    } else {
        let counts: Vec<String> = [Action::Create, Action::Update, Action::Delete]
            .into_iter()
            .map(|action| {
                let count = outcome.changes.iter().filter(|change| change.action == action).count();
                format!("{count} {action}")
            })
            .collect();
        parts.push(format!("{} change(s): {}", outcome.changes.len(), counts.join(", ")));
        parts.extend([warnings, errors, applied]);
    }
    if let Some(seconds) = outcome.seconds {
        parts.push(format!("done in {}", duration(seconds)));
    }
    parts.join(" · ")
}

/// A text as a line of the report may show it: what a field value escapes (a
/// control character of an escape sequence sent in an LLDP system name, a
/// format character that reverses a VM name) written `\u{1b}`, never handed
/// to the terminal or the cron mail.
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if !is_printable(character) {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(character)));
        } else {
            out.push(character);
        }
    }
    out
}

/// Renders the report of a run: one block per section, then the warnings, the
/// errors and the summary line.
pub fn render(outcome: &Outcome, colour: bool) -> String {
    let mut blocks: Vec<Vec<String>> = Vec::new();
    for (title, changes) in sections(&outcome.changes) {
        let mut lines = vec![paint(&printable(title), BOLD, colour)];
        for change in changes {
            lines.append(&mut change_lines(change, colour));
        }
        blocks.push(lines);
    }
    if !outcome.warnings.is_empty() {
        let mut lines = vec![paint(&format!("Warnings ({})", outcome.warnings.len()), YELLOW, colour)];
        lines.extend(outcome.warnings.iter().map(|warning| format!("  {}", printable(warning))));
        blocks.push(lines);
    }
    if !outcome.errors.is_empty() {
        let mut lines = vec![paint(&format!("Errors ({})", outcome.errors.len()), RED, colour)];
        lines.extend(outcome.errors.iter().map(|error| format!("  {}", printable(error))));
        blocks.push(lines);
    }
    blocks.push(vec![paint(&summary(outcome), BOLD, colour)]);
    // Opening blank line: the report follows the command line once the progress
    // bar is cleared, and its first section must not stick to it.
    let blocks: Vec<String> = blocks.iter().map(|lines| lines.join("\n")).collect();
    format!("\n{}", blocks.join("\n\n"))
}

/// The report for a run that must stay silent when it has nothing to say:
/// `None` when the outcome has no change, no warning and no error (cron then
/// prints nothing, hence sends no mail), the full report otherwise.
pub fn render_quiet(outcome: &Outcome, colour: bool) -> Option<String> {
    if outcome.changes.is_empty() && outcome.warnings.is_empty() && outcome.errors.is_empty() {
        return None;
    }
    Some(render(outcome, colour))
}

/// Colours on a terminal only, and never when NO_COLOR is set (no-color.org).
///
/// `no_color_set` is true when the variable is present **and not empty**: an
/// empty `NO_COLOR` counts as unset.
pub fn use_colour(no_color_set: bool, is_terminal: bool) -> bool {
    is_terminal && !no_color_set
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // A name comes from the network (an LLDP system name, a VM name): a
    // control character in it would reach the terminal or the cron mail as is.
    #[test]
    fn a_control_character_from_the_network_is_shown_escaped() {
        let forged = "sw01\u{1b}]52;c;aGk=\u{7}";
        let outcome = Outcome {
            changes: vec![Change::new("interface", Action::Delete, forged, forged)],
            warnings: vec![format!("nexus01.lab01: neighbour {forged} unknown")],
            errors: vec![format!("{forged}: refused")],
            ..Outcome::default()
        };
        let text = render(&outcome, false);
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'), "{text:?}");
        assert!(text.contains("nexus01.lab01: neighbour sw01\\u{1b}]52;c;aGk=\\u{7} unknown"), "{text}");
        assert!(text.contains("sw01\\u{1b}]52;c;aGk=\\u{7}: refused"), "{text}");
    }

    // A format character is no control, yet U+202E reverses what follows it
    // on the screen: `vm-\u{202e}gpj.exe` reads `vm-exe.jpg`. What a field
    // value would escape, a line of the report escapes as well.
    #[test]
    fn a_character_that_changes_how_a_line_reads_is_shown_escaped() {
        let forged = "vm-\u{202e}gpj.exe\u{200b}";
        let outcome = Outcome { warnings: vec![format!("{forged} unknown")], ..Outcome::default() };
        let text = render(&outcome, false);
        assert!(text.contains("vm-\\u{202e}gpj.exe\\u{200b} unknown"), "{text:?}");
    }

    fn outcome() -> Outcome {
        Outcome {
            changes: vec![
                Change::new("vlan", Action::Create, "", "2800").fields([
                    ("site", json!(12)),
                    ("vid", json!(2800)),
                    ("name", json!("Admin")),
                ]),
                Change::new("vlan", Action::Update, "", "26")
                    .fields([("name", "PPE")])
                    .before([("name", "VLAN2600-PPE")])
                    .id(81),
                Change::new("interface", Action::Update, "nexus01.lab01", "Ethernet1/7")
                    .fields([("description", json!("cartman")), ("enabled", json!(true))])
                    .before([("description", json!("")), ("enabled", json!(false))])
                    .id(3),
                Change::new("interface", Action::Create, "nexus01.lab01", "mgmt0").fields([
                    ("name", json!("mgmt0")),
                    ("type", json!("1000base-t")),
                    ("enabled", json!(true)),
                    ("description", json!("")),
                    ("lag", Value::Null),
                    ("tagged_vlans", json!([])),
                    ("mac", json!("FC:5B:39:8D:17:C0")),
                ]),
                Change::new("ip", Action::Delete, "nexus01.lab01", "10.9.9.9/24").id(5),
                Change::new("cable", Action::Create, "", "nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48")
                    .fields([("a_device", "nexus01.lab01")]),
            ],
            warnings: vec!["VLAN 5: something".to_owned()],
            errors: vec!["nexus03.lab01: SSH to 192.0.2.242 failed: NetmikoTimeoutException".to_owned()],
            applied: 0,
            seconds: None,
        }
    }

    /// An outcome whose only change is an update of one field, to look at how a
    /// value is printed on both sides of the arrow.
    fn update_of(before: Value, after: Value) -> Outcome {
        Outcome {
            changes: vec![
                Change::new("interface", Action::Update, "sw", "Ethernet1/1")
                    .fields([("field", after)])
                    .before([("field", before)]),
            ],
            ..Outcome::default()
        }
    }

    /// The field line of `update_of`: the third line after the opening blank one.
    fn field_line(outcome: &Outcome) -> String {
        render(outcome, false).lines().nth(3).expect("an update prints its field line").to_owned()
    }

    #[test]
    fn render_groups_changes_one_field_per_line() {
        let expected = [
            "",
            "VLANs",
            "  + vlan 2800",
            "      name: 'Admin'",
            "      site: 12",
            "      vid: 2800",
            "  ~ vlan 26",
            "      name: 'VLAN2600-PPE' → 'PPE'",
            "",
            "nexus01.lab01",
            "  ~ interface Ethernet1/7",
            "      description: '' → 'cartman'",
            "      enabled: False → True",
            "  + interface mgmt0",
            "      enabled: True",
            "      mac: 'FC:5B:39:8D:17:C0'",
            "      type: '1000base-t'",
            "  - ip 10.9.9.9/24",
            "",
            "Cables",
            "  + cable nexus01.lab01:Ethernet1/48 <-> nexus02.lab01:Ethernet1/48",
            "",
            "Warnings (1)",
            "  VLAN 5: something",
            "",
            "Errors (1)",
            "  nexus03.lab01: SSH to 192.0.2.242 failed: NetmikoTimeoutException",
            "",
            "6 change(s): 3 create, 2 update, 1 delete · 1 warning(s) · 1 error(s) · 0 applied",
        ]
        .join("\n");
        assert_eq!(render(&outcome(), false), expected);
    }

    #[test]
    fn render_colours_only_when_asked() {
        let plain = render(&outcome(), false);
        let coloured = render(&outcome(), true);
        assert!(!plain.contains("\x1b["));
        assert!(coloured.contains("\x1b[32m+ vlan 2800\x1b[0m"));
        assert!(coloured.contains("\x1b[33m~ vlan 26\x1b[0m"));
        assert!(coloured.contains("\x1b[31m- ip 10.9.9.9/24\x1b[0m"));
    }

    #[test]
    fn render_colours_titles_values_and_summary() {
        let coloured = render(&outcome(), true);
        assert!(coloured.starts_with("\n\x1b[1mVLANs\x1b[0m\n  \x1b[32m+ vlan 2800\x1b[0m\n      name: 'Admin'\n"));
        assert!(coloured.contains("\n\n\x1b[1mnexus01.lab01\x1b[0m\n"));
        assert!(coloured.contains("\n      description: \x1b[31m''\x1b[0m → \x1b[32m'cartman'\x1b[0m\n"));
        assert!(coloured.contains("\n\n\x1b[33mWarnings (1)\x1b[0m\n  VLAN 5: something\n"));
        assert!(coloured.contains("\n\n\x1b[31mErrors (1)\x1b[0m\n  nexus03.lab01: SSH to"));
        assert!(coloured.ends_with(
            "\n\n\x1b[1m6 change(s): 3 create, 2 update, 1 delete · 1 warning(s) · 1 error(s) · 0 applied\x1b[0m"
        ));
    }

    #[test]
    fn render_nothing_to_do() {
        assert_eq!(render(&Outcome::default(), false), "\nNothing to do: NetBox matches the sources · 0 applied");
    }

    #[test]
    fn report_is_set_apart_from_what_precedes_it() {
        // Printed right after the command line (`[app:sync] $ ...`) once the progress
        // bar is cleared: an opening blank line keeps its first section apart.
        let only_warnings = Outcome {
            warnings: vec!["nexus01.lab01: 2 neighbours announce no name (...)".to_owned()],
            ..Outcome::default()
        };
        let rendered = render(&only_warnings, false);
        let first: Vec<&str> = rendered.lines().take(2).collect();
        assert_eq!(first, ["", "Warnings (1)"]);
    }

    #[test]
    fn summary_ends_with_the_run_duration() {
        let last = |outcome: &Outcome| render(outcome, false).lines().last().expect("a summary line").to_owned();
        assert_eq!(
            last(&Outcome { seconds: Some(42.4), ..Outcome::default() }),
            "Nothing to do: NetBox matches the sources · 0 applied · done in 42 s"
        );
        assert_eq!(
            last(&Outcome { seconds: Some(97.6), ..Outcome::default() }),
            "Nothing to do: NetBox matches the sources · 0 applied · done in 1 min 38 s"
        );
        assert!(last(&outcome()).ends_with("· 0 applied"));
    }

    #[test]
    fn duration_rounds_half_to_even_like_python() {
        let last = |seconds: f64| {
            let outcome = Outcome { seconds: Some(seconds), ..Outcome::default() };
            render(&outcome, false).lines().last().expect("a summary line").to_owned()
        };
        // Python: round(2.5) == 2, round(3.5) == 4, divmod(60, 60) == (1, 0).
        assert_eq!(last(2.5), "Nothing to do: NetBox matches the sources · 0 applied · done in 2 s");
        assert_eq!(last(3.5), "Nothing to do: NetBox matches the sources · 0 applied · done in 4 s");
        assert_eq!(last(59.6), "Nothing to do: NetBox matches the sources · 0 applied · done in 1 min 0 s");
        assert_eq!(last(0.0), "Nothing to do: NetBox matches the sources · 0 applied · done in 0 s");
    }

    #[test]
    fn summary_counts_warnings_of_a_run_with_nothing_to_do() {
        let outcome = Outcome { warnings: vec!["a".to_owned(), "b".to_owned()], applied: 0, ..Outcome::default() };
        assert_eq!(
            render(&outcome, false),
            "\nWarnings (2)\n  a\n  b\n\nNothing to do: NetBox matches the sources · 2 warning(s) · 0 applied"
        );
    }

    #[test]
    fn summary_of_a_run_with_errors_only_counts_everything() {
        let outcome = Outcome { errors: vec!["boom".to_owned()], seconds: Some(61.0), ..Outcome::default() };
        assert_eq!(
            render(&outcome, false),
            "\nErrors (1)\n  boom\n\n\
             0 change(s): 0 create, 0 update, 0 delete · 0 warning(s) · 1 error(s) · 0 applied · done in 1 min 1 s"
        );
    }

    #[test]
    fn summary_reports_what_was_applied() {
        let outcome = Outcome {
            changes: vec![Change::new("ip", Action::Delete, "sw", "10.0.0.1/24").id(7)],
            applied: 1,
            ..Outcome::default()
        };
        assert_eq!(
            render(&outcome, false),
            "\nsw\n  - ip 10.0.0.1/24\n\n1 change(s): 0 create, 0 update, 1 delete · 0 warning(s) · 0 error(s) · 1 applied"
        );
    }

    #[test]
    fn devices_keep_the_order_of_their_first_change() {
        let outcome = Outcome {
            changes: vec![
                Change::new("ip", Action::Delete, "zulu", "10.0.0.1/24"),
                Change::new("ip", Action::Delete, "alpha", "10.0.0.2/24"),
                Change::new("cable", Action::Delete, "", "a:1 <-> b:1"),
                Change::new("ip", Action::Delete, "zulu", "10.0.0.3/24"),
                Change::new("vlan", Action::Delete, "", "7"),
            ],
            ..Outcome::default()
        };
        let expected = [
            "",
            "VLANs",
            "  - vlan 7",
            "",
            "zulu",
            "  - ip 10.0.0.1/24",
            "  - ip 10.0.0.3/24",
            "",
            "alpha",
            "  - ip 10.0.0.2/24",
            "",
            "Cables",
            "  - cable a:1 <-> b:1",
            "",
            "5 change(s): 0 create, 0 update, 5 delete · 0 warning(s) · 0 error(s) · 0 applied",
        ]
        .join("\n");
        assert_eq!(render(&outcome, false), expected);
    }

    #[test]
    fn a_created_vlan_keeps_its_name_but_an_interface_does_not_repeat_it() {
        let outcome = Outcome {
            changes: vec![
                Change::new("vlan", Action::Create, "", "Admin").fields([("name", json!("Admin")), ("vid", json!(5))]),
                Change::new("interface", Action::Create, "sw", "5").fields([("name", json!(5)), ("mtu", json!(0))]),
            ],
            ..Outcome::default()
        };
        // `name` equal to the key is dropped whatever the kind; the number 5 is
        // not the string '5', and 0 and False are values, not empty fields.
        let expected = [
            "",
            "VLANs",
            "  + vlan Admin",
            "      vid: 5",
            "",
            "sw",
            "  + interface 5",
            "      mtu: 0",
            "      name: 5",
            "",
            "2 change(s): 2 create, 0 update, 0 delete · 0 warning(s) · 0 error(s) · 0 applied",
        ]
        .join("\n");
        assert_eq!(render(&outcome, false), expected);
    }

    #[test]
    fn an_update_shows_none_for_a_field_without_previous_value() {
        let outcome = Outcome {
            changes: vec![Change::new("interface", Action::Update, "sw", "Ethernet1/1").fields([("mtu", 9216)])],
            ..Outcome::default()
        };
        assert_eq!(field_line(&outcome), "      mtu: None → 9216");
    }

    #[test]
    fn an_update_shows_empty_values_on_both_sides() {
        assert_eq!(field_line(&update_of(json!([10, 20]), json!([]))), "      field: (10, 20) → ()");
        assert_eq!(field_line(&update_of(json!("x"), Value::Null)), "      field: 'x' → None");
    }

    #[test]
    fn a_list_prints_as_a_python_tuple() {
        assert_eq!(field_line(&update_of(json!([]), json!([10]))), "      field: () → (10,)");
        assert_eq!(field_line(&update_of(json!([10]), json!([10, 20, 30]))), "      field: (10,) → (10, 20, 30)");
        assert_eq!(
            field_line(&update_of(json!(["a"]), json!([["b", 1], null]))),
            "      field: ('a',) → (('b', 1), None)"
        );
    }

    #[test]
    fn a_string_prints_as_its_python_repr() {
        assert_eq!(field_line(&update_of(json!("plain"), json!("it's"))), r#"      field: 'plain' → "it's""#);
        assert_eq!(
            field_line(&update_of(json!(r#"say "hi""#), json!(r#"it's "both""#))),
            r#"      field: 'say "hi"' → 'it\'s "both"'"#
        );
        assert_eq!(field_line(&update_of(json!("a\\b"), json!("a\nb\tc\rd"))), r"      field: 'a\\b' → 'a\nb\tc\rd'");
        assert_eq!(
            field_line(&update_of(json!("\u{1b}[0m"), json!("\u{7f}\u{0}"))),
            r"      field: '\x1b[0m' → '\x7f\x00'"
        );
        assert_eq!(field_line(&update_of(json!("é → ·"), json!("a\u{a0}b"))), r"      field: 'é → ·' → 'a\xa0b'");
    }

    #[test]
    fn a_number_prints_bare() {
        assert_eq!(
            field_line(&update_of(json!(-3), json!(18446744073709551615u64))),
            "      field: -3 → 18446744073709551615"
        );
        assert_eq!(field_line(&update_of(json!(1.0), json!(1.5))), "      field: 1.0 → 1.5");
        assert_eq!(field_line(&update_of(json!(1e16), json!(1e-7))), "      field: 1e+16 → 1e-07");
        assert_eq!(field_line(&update_of(json!(1.5e300), json!(-2.5e-10))), "      field: 1.5e+300 → -2.5e-10");
    }

    #[test]
    fn an_object_prints_as_a_python_dict() {
        assert_eq!(
            field_line(&update_of(json!({}), json!({"a": 1, "b": [true, null]}))),
            "      field: {} → {'a': 1, 'b': (True, None)}"
        );
    }

    #[test]
    fn a_created_object_lists_an_empty_dict_but_no_empty_tuple() {
        let outcome = Outcome {
            changes: vec![Change::new("vm", Action::Create, "vm01", "vm01").fields([
                ("custom_fields", json!({})),
                ("tags", json!([])),
                ("comments", json!("")),
                ("cluster", Value::Null),
                ("enabled", json!(false)),
            ])],
            ..Outcome::default()
        };
        // Python: `value not in (None, "", ())` hides None, '' and (); {} and False stay.
        let expected = [
            "",
            "vm01",
            "  + vm vm01",
            "      custom_fields: {}",
            "      enabled: False",
            "",
            "1 change(s): 1 create, 0 update, 0 delete · 0 warning(s) · 0 error(s) · 0 applied",
        ]
        .join("\n");
        assert_eq!(render(&outcome, false), expected);
    }

    #[test]
    fn a_cable_never_lists_its_fields() {
        let outcome = Outcome {
            changes: vec![
                Change::new("cable", Action::Update, "", "a:1 <-> b:1")
                    .fields([("status", "connected")])
                    .before([("status", "planned")]),
            ],
            ..Outcome::default()
        };
        assert_eq!(
            render(&outcome, false),
            "\nCables\n  ~ cable a:1 <-> b:1\n\n1 change(s): 0 create, 1 update, 0 delete · 0 warning(s) · 0 error(s) · 0 applied"
        );
    }

    #[test]
    fn render_quiet_says_nothing_when_there_is_nothing_to_say() {
        assert_eq!(render_quiet(&Outcome::default(), false), None);
        assert_eq!(render_quiet(&Outcome { applied: 3, seconds: Some(12.0), ..Outcome::default() }, true), None);
    }

    #[test]
    fn render_quiet_reports_a_change_a_warning_or_an_error() {
        let change =
            Outcome { changes: vec![Change::new("ip", Action::Delete, "sw", "10.0.0.1/24")], ..Outcome::default() };
        assert_eq!(
            render_quiet(&change, false).as_deref(),
            Some(
                "\nsw\n  - ip 10.0.0.1/24\n\n\
                 1 change(s): 0 create, 0 update, 1 delete · 0 warning(s) · 0 error(s) · 0 applied"
            )
        );
        let warning = Outcome { warnings: vec!["careful".to_owned()], ..Outcome::default() };
        assert_eq!(
            render_quiet(&warning, false).as_deref(),
            Some("\nWarnings (1)\n  careful\n\nNothing to do: NetBox matches the sources · 1 warning(s) · 0 applied")
        );
        let error = Outcome { errors: vec!["boom".to_owned()], ..Outcome::default() };
        assert_eq!(
            render_quiet(&error, true).as_deref(),
            Some(
                "\n\x1b[31mErrors (1)\x1b[0m\n  boom\n\n\
                 \x1b[1m0 change(s): 0 create, 0 update, 0 delete · 0 warning(s) · 1 error(s) · 0 applied\x1b[0m"
            )
        );
    }

    #[test]
    fn colour_only_on_a_terminal_without_no_color() {
        assert!(use_colour(false, true));
        assert!(!use_colour(true, true));
        assert!(!use_colour(false, false));
        assert!(!use_colour(true, false));
    }
}
