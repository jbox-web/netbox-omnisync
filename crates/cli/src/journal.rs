//! The journal of the runs: one JSON line per sync that wrote to NetBox (or
//! tried to), read by `check` (the state of each source, for Icinga) and by
//! `digest` (the mail of a day of changes).
//!
//! A run appends its line while it holds the lock, so that two writers never
//! meet; readers may read at any time, so every append rewrites the file into
//! a temporary file of the same directory, renamed over it: a reader sees the
//! file before or after, never half of it. The same rewrite drops the entries
//! older than [`RETENTION`]. A line that does not parse is kept as it is, and
//! skipped by the readers: nothing is destroyed that is not understood (a line
//! of a later schema, a line an operator edited).

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use jiff::{SignedDuration, Timestamp, ZonedDateTime};
use omnisync_core::Change;
use serde::{Deserialize, Serialize};

/// The schema of an entry; a line of another version is not read. The keys a
/// file several hosts share adds (`runner`) are optional ones of this version:
/// another version would have a new binary skip the days of lines a host
/// already wrote, and find no success for a source read once a night.
pub const VERSION: u32 = 1;

/// The file of the journal in the state directory, when the configuration
/// does not name one.
pub const NAME: &str = "journal.jsonl";

/// How long an entry is kept: a week and a day, so that a digest of the last
/// seven days always finds its first one.
pub const RETENTION: SignedDuration = SignedDuration::from_hours(8 * 24);

/// The mode of a journal this tool creates: the user of the monitoring reads
/// it. It holds names of objects and addresses, never a secret.
const FILE_MODE: u32 = 0o644;

/// The mode of the directory of a journal when this tool creates it: the user
/// of the monitoring must reach the file.
const DIRECTORY_MODE: u32 = 0o755;

/// A source of the configuration, as the journal records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Configured {
    pub name: String,
    /// What `SourceKind::as_str` says: `hypervisor`, `bmc`, `switch`…
    pub kind: String,
    /// The host the file says launches it (`runner`); absent from the line
    /// when one host runs every source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
}

/// One run, as a line of the journal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// [`VERSION`].
    pub version: u32,
    /// When the run started to contact NetBox, RFC 3339 with the offset of
    /// the host ([`stamp`]).
    pub started: String,
    /// How long it took from then.
    pub seconds: f64,
    /// The host the run was, among those of the file (`runners`): `check`
    /// judges its sources alone. Absent from the line when one host runs
    /// every source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
    /// Every source of the configuration, selected or not: what `check` must
    /// find a recent success for.
    pub configured: Vec<Configured>,
    /// The names of the sources this run selected.
    pub selected: Vec<String>,
    pub changes: Vec<Change>,
    /// Number of changes written to NetBox.
    pub applied: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl Entry {
    /// When the run started; None when `started` is not a timestamp.
    pub fn started_at(&self) -> Option<Timestamp> {
        self.started.parse().ok()
    }

    /// When the run ended: its start and its duration.
    pub fn ended_at(&self) -> Option<Timestamp> {
        let duration = SignedDuration::try_from_secs_f64(self.seconds).ok()?;
        self.started_at()?.checked_add(duration).ok()
    }
}

/// A moment as an entry records it: RFC 3339 to the second, with the offset
/// of its time zone (`2026-11-20T07:51:55+01:00`).
pub fn stamp(moment: &ZonedDateTime) -> String {
    let second = moment.timestamp().as_second();
    // A second of a timestamp is always a timestamp.
    let truncated = Timestamp::from_second(second).unwrap_or(moment.timestamp());
    truncated.display_with_offset(moment.offset()).to_string()
}

/// The entry a line holds; None for a line that is not one of [`VERSION`]
/// with a readable start.
pub fn parse(line: &str) -> Option<Entry> {
    let entry: Entry = serde_json::from_str(line).ok()?;
    (entry.version == VERSION && entry.started_at().is_some()).then_some(entry)
}

/// The lines of the bytes of a journal, without their `\n`: a line need not
/// be UTF-8 to be a line, and is kept or skipped as such.
fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty())
}

/// The entry a line of bytes holds; None for one that is not UTF-8 or not an entry.
fn parse_bytes(line: &[u8]) -> Option<Entry> {
    parse(std::str::from_utf8(line).ok()?)
}

/// The entries of the journal at `path`, in the order they were written, the
/// lines that are not entries left out.
pub fn read(path: &Path) -> io::Result<Vec<Entry>> {
    Ok(lines(&fs::read(path)?).filter_map(parse_bytes).collect())
}

/// Whether a line of the journal is to be kept by an append at `now`: an
/// entry younger than [`RETENTION`], or anything that is not an entry but a
/// blank line.
fn kept(line: &[u8], now: Timestamp) -> bool {
    if line.iter().all(u8::is_ascii_whitespace) {
        return false;
    }
    let oldest = now.checked_sub(RETENTION).unwrap_or(now);
    match parse_bytes(line).and_then(|entry| entry.started_at()) {
        Some(started) => started >= oldest,
        None => true,
    }
}

/// Write `bytes` with `mode` into a file next to `path`, then rename it over
/// `path` and make the rename durable. The temporary file is removed when
/// anything fails.
///
/// Its name is the one of the process: a file a killed run left under the
/// same PID is truncated, not a reason to stop. The directory belongs to the
/// writer; the file is never opened through a link all the same.
fn replace(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let temporary = directory.join(format!(".{name}.{}.tmp", std::process::id()));
    let opened =
        File::options().write(true).create(true).truncate(true).custom_flags(libc::O_NOFOLLOW).open(&temporary);
    let Ok(mut file) = opened else {
        // A link in its place is not removed: it is not ours.
        return opened.map(|_| ());
    };
    let written = file
        .write_all(bytes)
        // The umask is not the reader's business: the mode is set as said.
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(mode)))
        .and_then(|()| file.sync_all());
    let renamed = written.and_then(|()| fs::rename(&temporary, path));
    if renamed.is_err() {
        // Nothing to add when it cannot be removed: the error above is the one to tell.
        let _ = fs::remove_file(&temporary);
    }
    // The rename is written to the disk with the directory.
    renamed.and_then(|()| File::open(directory)?.sync_all())
}

/// Append `entry` to the journal at `path`, dropping the entries that started
/// more than [`RETENTION`] before `now`; the message of the failure, naming
/// the file, otherwise.
///
/// The directory is created, readable by all, when it is missing: the
/// default one, next to the lock, already exists and stays private (the
/// monitoring then reads it as the user of the runs); one the configuration
/// names is the operator's choice. A new file is readable by all. A rewrite
/// is a new file renamed over the old one: it keeps the mode of the file it
/// replaces, but takes the owner and the group of the writer, so a group the
/// operator gave the file (for a mode `0640`) is lost at the next run. A
/// journal another user reads stays readable by all (`0644`).
pub fn append(path: &Path, entry: &Entry, now: Timestamp) -> Result<(), String> {
    let failed = |error: io::Error| format!("cannot write the journal {}: {error}", path.display());
    let directory = path.parent().unwrap_or(Path::new("."));
    if !directory.as_os_str().is_empty() && !directory.exists() {
        fs::DirBuilder::new().recursive(true).mode(DIRECTORY_MODE).create(directory).map_err(failed)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE)).map_err(failed)?;
    }
    let (old, mode) = match fs::read(path) {
        Ok(old) => (old, fs::metadata(path).map_err(failed)?.permissions().mode() & 0o7777),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (Vec::new(), FILE_MODE),
        Err(error) => return Err(failed(error)),
    };
    let line = serde_json::to_string(entry).map_err(|error| failed(io::Error::other(error)))?;
    let mut rewritten = Vec::with_capacity(old.len() + line.len() + 1);
    for kept in lines(&old).filter(|old| kept(old, now)) {
        rewritten.extend_from_slice(kept);
        rewritten.push(b'\n');
    }
    rewritten.extend_from_slice(line.as_bytes());
    rewritten.push(b'\n');
    replace(path, &rewritten, mode).map_err(failed)
}

#[cfg(test)]
mod tests {
    use omnisync_core::Action;
    use serde_json::json;

    use super::*;

    /// 2026-11-20T08:00:00+01:00.
    fn now() -> Timestamp {
        "2026-11-20T07:00:00Z".parse().unwrap()
    }

    fn entry(started: &str) -> Entry {
        Entry {
            version: 1,
            started: started.to_owned(),
            seconds: 2.5,
            runner: None,
            configured: vec![Configured {
                name: "pve01.lab01".to_owned(),
                kind: "hypervisor".to_owned(),
                runner: None,
            }],
            selected: vec!["pve01.lab01".to_owned()],
            changes: vec![],
            applied: 0,
            warnings: vec![],
            errors: vec![],
        }
    }

    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path).unwrap().lines().map(str::to_owned).collect()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    // The schema the monitoring and the digest read: a rename is a new version.
    #[test]
    fn an_entry_is_one_json_line_of_the_schema_of_version_1() {
        let change = Change::new("serial", Action::Update, "nexus01.lab01", "nexus01.lab01")
            .fields([("serial", json!("SN1"))])
            .before([("serial", json!(""))])
            .id(7);
        let entry = Entry {
            changes: vec![change],
            applied: 1,
            warnings: vec!["w".to_owned()],
            errors: vec!["pve01.lab01: refused".to_owned()],
            ..entry("2026-11-20T07:51:55+01:00")
        };
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            "{\"version\":1,\"started\":\"2026-11-20T07:51:55+01:00\",\"seconds\":2.5,\
             \"configured\":[{\"name\":\"pve01.lab01\",\"kind\":\"hypervisor\"}],\"selected\":[\"pve01.lab01\"],\
             \"changes\":[{\"kind\":\"serial\",\"action\":\"update\",\"device\":\"nexus01.lab01\",\
             \"key\":\"nexus01.lab01\",\"fields\":{\"serial\":\"SN1\"},\"before\":{\"serial\":\"\"}}],\
             \"applied\":1,\"warnings\":[\"w\"],\"errors\":[\"pve01.lab01: refused\"]}"
        );
    }

    /// The same entry, of a run of sat01.lab02 on a file two hosts share.
    fn shared_entry(started: &str) -> Entry {
        let configured = |name: &str, kind: &str, host: &str| Configured {
            name: name.to_owned(),
            kind: kind.to_owned(),
            runner: Some(host.to_owned()),
        };
        Entry {
            runner: Some("sat01.lab02".to_owned()),
            configured: vec![
                configured("pve01.lab01", "hypervisor", "sat01.lab02"),
                configured("nexus01.lab01", "switch", "sync01.lab01"),
            ],
            ..entry(started)
        }
    }

    // Who launched the run, and who launches each source: what `check` needs
    // to judge the sources of its host alone. Two keys more, the same version.
    #[test]
    fn an_entry_names_its_runner_and_the_runner_of_each_source() {
        assert_eq!(
            serde_json::to_string(&shared_entry("2026-11-20T07:51:55+01:00")).unwrap(),
            "{\"version\":1,\"started\":\"2026-11-20T07:51:55+01:00\",\"seconds\":2.5,\"runner\":\"sat01.lab02\",\
             \"configured\":[{\"name\":\"pve01.lab01\",\"kind\":\"hypervisor\",\"runner\":\"sat01.lab02\"},\
             {\"name\":\"nexus01.lab01\",\"kind\":\"switch\",\"runner\":\"sync01.lab01\"}],\
             \"selected\":[\"pve01.lab01\"],\"changes\":[],\"applied\":0,\"warnings\":[],\"errors\":[]}"
        );
        let line = serde_json::to_string(&shared_entry("2026-11-20T07:51:55+01:00")).unwrap();
        assert_eq!(parse(&line), Some(shared_entry("2026-11-20T07:51:55+01:00")));
    }

    // A file one host runs: not a byte of its journal changes.
    #[test]
    fn an_entry_without_runner_is_written_as_before() {
        assert_eq!(
            serde_json::to_string(&entry("2026-11-20T07:51:55+01:00")).unwrap(),
            "{\"version\":1,\"started\":\"2026-11-20T07:51:55+01:00\",\"seconds\":2.5,\
             \"configured\":[{\"name\":\"pve01.lab01\",\"kind\":\"hypervisor\"}],\"selected\":[\"pve01.lab01\"],\
             \"changes\":[],\"applied\":0,\"warnings\":[],\"errors\":[]}"
        );
    }

    // The eight days of lines a host already wrote: read as they are, of a
    // file one host runs.
    #[test]
    fn a_line_written_before_the_runners_is_still_read() {
        let line = "{\"version\":1,\"started\":\"2026-11-20T07:51:55+01:00\",\"seconds\":2.5,\
                    \"configured\":[{\"name\":\"pve01.lab01\",\"kind\":\"hypervisor\"}],\
                    \"selected\":[\"pve01.lab01\"],\"changes\":[],\"applied\":0,\"warnings\":[],\"errors\":[]}";
        let read = parse(line).expect("an entry");
        assert_eq!(read, entry("2026-11-20T07:51:55+01:00"));
        assert_eq!((read.runner, read.configured[0].runner.clone()), (None, None));
    }

    #[test]
    fn a_moment_is_stamped_to_the_second_with_its_offset() {
        let moment: Timestamp = "2026-11-20T06:51:55.987654Z".parse().unwrap();
        let paris = moment.to_zoned_datetime(jiff::tz::TimeZone::fixed(jiff::tz::offset(1)));
        assert_eq!(stamp(&paris), "2026-11-20T07:51:55+01:00");
        let entry = entry(&stamp(&paris));
        assert_eq!(entry.started_at(), Some("2026-11-20T06:51:55Z".parse().unwrap()));
        assert_eq!(entry.ended_at(), Some("2026-11-20T06:51:57.5Z".parse().unwrap()));
    }

    #[test]
    fn a_line_is_an_entry_only_of_version_1_with_a_readable_start() {
        let line = serde_json::to_string(&entry("2026-11-20T07:51:55+01:00")).unwrap();
        assert_eq!(parse(&line), Some(entry("2026-11-20T07:51:55+01:00")));
        let later = line.replace("\"version\":1", "\"version\":2");
        assert_eq!(parse(&later), None);
        let unreadable = line.replace("2026-11-20T07:51:55+01:00", "yesterday");
        assert_eq!(parse(&unreadable), None);
        assert_eq!(parse("{\"version\":1}"), None);
        assert_eq!(parse("not json"), None);
    }

    #[test]
    fn the_first_append_creates_the_file_and_its_directory_readable_by_all() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("var/netbox-omnisync/journal.jsonl");
        append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        assert_eq!(lines(&path), [serde_json::to_string(&entry("2026-11-20T07:59:00+01:00")).unwrap()]);
        assert_eq!(mode(&path), 0o644);
        assert_eq!(mode(path.parent().unwrap()), 0o755);
    }

    // The default journal lives next to the lock, whose directory is private:
    // an append never opens it.
    #[test]
    fn a_directory_that_exists_keeps_its_mode() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        append(&state.join(NAME), &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        assert_eq!(mode(&state), 0o700);
    }

    #[test]
    fn an_append_drops_the_entries_older_than_eight_days_and_keeps_the_others() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        // Now is 2026-11-20T08:00:00+01:00: eight days before is 2026-11-12T08:00:00+01:00.
        for started in ["2026-11-12T07:59:59+01:00", "2026-11-12T08:00:00+01:00", "2026-11-19T23:00:00+01:00"] {
            append(&path, &entry(started), now()).unwrap();
        }
        append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        let kept: Vec<String> = read(&path).unwrap().into_iter().map(|entry| entry.started).collect();
        assert_eq!(kept, ["2026-11-12T08:00:00+01:00", "2026-11-19T23:00:00+01:00", "2026-11-20T07:59:00+01:00"]);
    }

    // Never destroy what is not understood: a line of a later version, or one
    // an operator edited, stays where it is; the readers skip it.
    #[test]
    fn a_line_that_does_not_parse_is_kept_and_skipped_by_the_readers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        fs::write(&path, "{\"version\":2,\"started\":\"2020-01-01T00:00:00Z\"}\n\ngarbage\n").unwrap();
        append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        assert_eq!(
            lines(&path),
            [
                "{\"version\":2,\"started\":\"2020-01-01T00:00:00Z\"}".to_owned(),
                "garbage".to_owned(),
                serde_json::to_string(&entry("2026-11-20T07:59:00+01:00")).unwrap(),
            ]
        );
        assert_eq!(read(&path).unwrap(), [entry("2026-11-20T07:59:00+01:00")]);
    }

    // One byte that is not UTF-8 is a line not understood like any other:
    // kept as it is, byte for byte, and skipped by the readers. It must not
    // fail every sync, nor leave the check UNKNOWN for good.
    #[test]
    fn a_line_that_is_not_utf8_is_kept_byte_for_byte_and_skipped_by_the_readers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        let first = serde_json::to_string(&entry("2026-11-20T07:58:00+01:00")).unwrap();
        let mut text = b"caf\xe9 \xff\n".to_vec();
        text.extend_from_slice(first.as_bytes());
        text.push(b'\n');
        fs::write(&path, &text).unwrap();
        append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        let second = serde_json::to_string(&entry("2026-11-20T07:59:00+01:00")).unwrap();
        let mut expected = text.clone();
        expected.extend_from_slice(second.as_bytes());
        expected.push(b'\n');
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert_eq!(read(&path).unwrap(), [entry("2026-11-20T07:58:00+01:00"), entry("2026-11-20T07:59:00+01:00")]);
    }

    // A run killed during its rewrite leaves its temporary file; a later run
    // that gets the same PID must not be stopped by it.
    #[test]
    fn a_temporary_file_a_killed_run_left_does_not_stop_the_next_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        let leftover = directory.path().join(format!(".{NAME}.{}.tmp", std::process::id()));
        fs::write(&leftover, "half of a journal").unwrap();
        append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        assert_eq!(read(&path).unwrap(), [entry("2026-11-20T07:59:00+01:00")]);
        assert!(!leftover.exists());
    }

    // The temporary file is never written through a link: what it points at
    // is left alone, and the journal with it.
    #[test]
    fn the_temporary_file_is_never_written_through_a_link() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        let target = directory.path().join("precious");
        fs::write(&target, "keep me").unwrap();
        let temporary = directory.path().join(format!(".{NAME}.{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&target, &temporary).unwrap();
        let error = append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap_err();
        assert!(error.starts_with(&format!("cannot write the journal {}: ", path.display())), "{error}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep me");
        assert!(!path.exists());
    }

    #[test]
    fn a_line_cut_short_by_a_crash_does_not_glue_to_the_next_entry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        fs::write(&path, "{\"version\":1,\"sta").unwrap();
        append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        assert_eq!(read(&path).unwrap(), [entry("2026-11-20T07:59:00+01:00")]);
    }

    #[test]
    fn the_rewrite_keeps_the_mode_the_operator_gave_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        append(&path, &entry("2026-11-20T07:58:00+01:00"), now()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap();
        assert_eq!(mode(&path), 0o640);
        assert_eq!(read(&path).unwrap().len(), 2);
    }

    // A reader sees the file before the append or after it, never half of it:
    // the rewrite is a file of the same directory, renamed over the journal.
    // When it cannot be made, the journal is left as it was, and no temporary
    // file is left behind.
    #[test]
    fn a_journal_that_cannot_be_rewritten_is_left_as_it_was() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(NAME);
        append(&path, &entry("2026-11-20T07:58:00+01:00"), now()).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let error = append(&path, &entry("2026-11-20T07:59:00+01:00"), now()).unwrap_err();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(error.starts_with(&format!("cannot write the journal {}: ", path.display())), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        let names: Vec<_> = fs::read_dir(directory.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(names, [NAME]);
    }

    #[test]
    fn a_journal_that_does_not_exist_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let error = read(&directory.path().join(NAME)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
