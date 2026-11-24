//! Where a run is: a live bar on a terminal, one line per step otherwise.
//!
//! Progress goes to stderr only: stdout keeps the report alone, unchanged.

use std::io::Write;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use jiff::ZonedDateTime;
use jiff::civil::DateTime;

/// What a run reports of its advancement. Sources are collected concurrently:
/// every operation takes `&self` and an implementation is `Send + Sync`.
pub trait Progress: Send + Sync {
    /// Start, with the number of units of work expected.
    fn begin(&self, total: u64);

    /// The number of units became known more precisely.
    fn resize(&self, total: u64);

    /// A stage starts: a switch collection, a device write, the cables.
    fn step(&self, label: &str);

    /// The unit running now, e.g. one show command.
    fn doing(&self, label: &str);

    /// One unit of work is done, within `lane` when given.
    fn advance(&self, lane: Option<&str>);

    /// A switch starts its collection, in parallel with others: its own row.
    fn lane_start(&self, lane: &str, total: u64);

    /// The command that switch runs now.
    fn lane_doing(&self, lane: &str, label: &str);

    /// That switch is done: its row goes.
    fn lane_end(&self, lane: &str);

    /// Something to keep in sight: a failed switch or device.
    fn note(&self, text: &str);

    /// The run is over.
    fn end(&self);
}

/// Shows nothing: the default of a run, and the tests'.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullProgress;

impl Progress for NullProgress {
    fn begin(&self, _total: u64) {}

    fn resize(&self, _total: u64) {}

    fn step(&self, _label: &str) {}

    fn doing(&self, _label: &str) {}

    fn advance(&self, _lane: Option<&str>) {}

    fn lane_start(&self, _lane: &str, _total: u64) {}

    fn lane_doing(&self, _lane: &str, _label: &str) {}

    fn lane_end(&self, _lane: &str) {}

    fn note(&self, _text: &str) {}

    fn end(&self) {}
}

/// Local wall-clock time, for the timestamp of a line.
type Now = Box<dyn Fn() -> DateTime + Send + Sync>;

/// Time elapsed since an arbitrary fixed origin, for the duration of the run.
type Monotonic = Box<dyn Fn() -> Duration + Send + Sync>;

/// What `LogProgress` mutates: the stream, and when the run began.
struct LogState<W> {
    stream: W,
    started: Duration,
}

/// One timestamped line per step and per note, for cron and pipes.
///
/// Individual commands are not logged: a mail per run must stay short.
pub struct LogProgress<W: Write + Send> {
    state: Mutex<LogState<W>>,
    now: Now,
    monotonic: Monotonic,
}

impl<W: Write + Send> LogProgress<W> {
    /// Writes to `stream`, stamped with the local time of the machine.
    pub fn new(stream: W) -> Self {
        let origin = Instant::now();
        LogProgress::with_clock(stream, || ZonedDateTime::now().datetime(), move || origin.elapsed())
    }

    /// Same, with both clocks injected: `now` stamps each line, `monotonic`
    /// measures the run (two readings: at `begin`, then at `end`).
    pub fn with_clock(
        stream: W,
        now: impl Fn() -> DateTime + Send + Sync + 'static,
        monotonic: impl Fn() -> Duration + Send + Sync + 'static,
    ) -> Self {
        LogProgress {
            state: Mutex::new(LogState { stream, started: Duration::ZERO }),
            now: Box::new(now),
            monotonic: Box::new(monotonic),
        }
    }

    /// The state, even after a thread panicked while holding it: a line lost
    /// then is no reason to lose the following ones.
    fn state(&self) -> MutexGuard<'_, LogState<W>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn line(&self, text: &str) {
        // Stamped under the lock: two lines written at once come out in the
        // order of their stamps.
        let mut state = self.state();
        let stamp = (self.now)().strftime("%Y-%m-%dT%H:%M:%S");
        // A stream that cannot be written to (closed pipe) must not stop the
        // run: progress is a courtesy, the report is what matters.
        let _ = writeln!(state.stream, "{stamp} {text}").and_then(|()| state.stream.flush());
    }
}

impl<W: Write + Send> Progress for LogProgress<W> {
    fn begin(&self, _total: u64) {
        let started = (self.monotonic)();
        self.state().started = started;
    }

    fn resize(&self, _total: u64) {}

    fn step(&self, label: &str) {
        self.line(label);
    }

    fn doing(&self, _label: &str) {}

    fn advance(&self, _lane: Option<&str>) {}

    fn lane_start(&self, _lane: &str, _total: u64) {}

    fn lane_doing(&self, _lane: &str, _label: &str) {}

    fn lane_end(&self, _lane: &str) {}

    fn note(&self, text: &str) {
        self.line(text);
    }

    fn end(&self) {
        let now = (self.monotonic)();
        let started = self.state().started;
        // Rounded half to even, as Python's `round` does.
        let seconds = now.saturating_sub(started).as_secs_f64().round_ties_even();
        self.line(&format!("done in {seconds:.0} s"));
    }
}

/// What `BarProgress` mutates: the row of the run, and one row per lane, in
/// the order the lanes started.
#[derive(Default)]
struct BarState {
    task: Option<ProgressBar>,
    lanes: Vec<(String, ProgressBar)>,
}

impl BarState {
    fn lane(&self, lane: &str) -> Option<&ProgressBar> {
        self.lanes.iter().find(|(name, _)| name == lane).map(|(_, row)| row)
    }

    fn take_lane(&mut self, lane: &str) -> Option<ProgressBar> {
        let index = self.lanes.iter().position(|(name, _)| name == lane)?;
        Some(self.lanes.remove(index).1)
    }
}

/// What a row of the bar stands for: the run, or one source read alongside others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Run,
    Lane,
}

/// The bar: done, the head of what is done, to do. One thin line whose colour
/// tells the two sides apart.
const BAR: &str = "━╸━";

/// The frames of the spinner, the last one shown by a finished row.
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "];

/// How often a row on a terminal is redrawn while nothing happens.
const REDRAW: Duration = Duration::from_millis(100);

/// A live bar: stage, done/total, percentage, elapsed time, running unit.
///
/// Notes print above the bar and stay; the bar itself is cleared at the end so
/// that only the report remains.
pub struct BarProgress {
    bars: MultiProgress,
    state: Mutex<BarState>,
}

impl BarProgress {
    /// A bar drawn on stderr.
    pub fn new() -> Self {
        BarProgress::with_draw_target(ProgressDrawTarget::stderr())
    }

    /// A bar drawn on `target`; a hidden one draws nothing but keeps its rows.
    pub fn with_draw_target(target: ProgressDrawTarget) -> Self {
        BarProgress { bars: MultiProgress::with_draw_target(target), state: Mutex::new(BarState::default()) }
    }

    /// The state, even after a thread panicked while holding it.
    fn state(&self) -> MutexGuard<'_, BarState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new row at the bottom. The row of the run shows its stage, a bar,
    /// done/total, the percentage, the elapsed time and the running unit; so
    /// does a lane of several units, in a shorter bar. A lane of one unit has
    /// nothing to fill: it shows its elapsed time only.
    ///
    /// The running unit takes what is left of the line and is cut there, so
    /// that a narrow terminal does not fold a row in two. On a terminal the
    /// row is also redrawn on a timer: the spinner and the clock keep moving
    /// while a slow request is awaited, and a run that waits does not look
    /// hung.
    fn row(&self, kind: RowKind, description: &str, total: u64) -> ProgressBar {
        let template = match (kind, total) {
            (RowKind::Run, _) => {
                "{spinner:.cyan} {prefix:.bold} {bar:24.cyan/238} {pos:>3}/{len} {percent:>3}% {elapsed:.dim} {wide_msg:.dim}"
            }
            (RowKind::Lane, 0 | 1) => "{spinner:.cyan} {prefix} {elapsed:.dim} {wide_msg:.dim}",
            (RowKind::Lane, _) => "{spinner:.cyan} {prefix} {bar:16.cyan/238} {pos:>3}/{len} {wide_msg:.dim}",
        };
        let style = ProgressStyle::with_template(template)
            .expect("the templates are constants whose keys indicatif knows")
            .progress_chars(BAR)
            .tick_strings(SPINNER);
        let row = self.bars.add(ProgressBar::new(total).with_style(style));
        row.set_prefix(description.to_owned());
        if !self.bars.is_hidden() {
            row.enable_steady_tick(REDRAW);
        }
        row
    }

    /// The rows on screen now, as plain text: one line per row, the run first
    /// then each lane, as `<stage> <done>/<total> <running unit>` (an empty
    /// stage or unit is left out).
    pub fn frame(&self) -> String {
        let state = self.state();
        let mut frame = String::new();
        for row in state.task.iter().chain(state.lanes.iter().map(|(_, row)| row)) {
            let count = format!("{}/{}", row.position(), row.length().unwrap_or(0));
            let fields = [row.prefix(), count, row.message()];
            let fields: Vec<&str> = fields.iter().map(String::as_str).filter(|field| !field.is_empty()).collect();
            frame.push_str(&fields.join(" "));
            frame.push('\n');
        }
        frame
    }
}

impl Drop for BarProgress {
    /// A run that is cut short (Ctrl-C) never reaches [`Progress::end`]: its
    /// rows are taken off the screen here, their timers stopped first so that
    /// none redraws a row once it is cleared. What is written next starts on
    /// an empty line.
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        let rows = state.lanes.drain(..).map(|(_, row)| row).chain(state.task.take());
        for row in rows {
            row.disable_steady_tick();
            row.finish_and_clear();
            self.bars.remove(&row);
        }
        // A terminal that cannot be written to must not stop the run.
        let _ = self.bars.clear();
    }
}

impl Default for BarProgress {
    fn default() -> Self {
        BarProgress::new()
    }
}

impl Progress for BarProgress {
    fn begin(&self, total: u64) {
        let row = self.row(RowKind::Run, "", total);
        row.tick();
        // A run that begins twice keeps one row only.
        if let Some(previous) = self.state().task.replace(row) {
            previous.finish_and_clear();
            self.bars.remove(&previous);
        }
    }

    fn resize(&self, total: u64) {
        if let Some(task) = &self.state().task {
            task.set_length(total);
        }
    }

    fn step(&self, label: &str) {
        if let Some(task) = &self.state().task {
            task.set_prefix(label.to_owned());
            task.set_message("");
        }
    }

    fn doing(&self, label: &str) {
        if let Some(task) = &self.state().task {
            task.set_message(label.to_owned());
        }
    }

    fn advance(&self, lane: Option<&str>) {
        let state = self.state();
        if let Some(row) = lane.and_then(|lane| state.lane(lane)) {
            row.inc(1);
        }
        if let Some(task) = &state.task {
            task.inc(1);
        }
    }

    fn lane_start(&self, lane: &str, total: u64) {
        let row = self.row(RowKind::Lane, &format!("  {lane}"), total);
        row.tick();
        let mut state = self.state();
        // A lane that starts twice keeps one row only.
        if let Some(previous) = state.take_lane(lane) {
            previous.finish_and_clear();
            self.bars.remove(&previous);
        }
        state.lanes.push((lane.to_owned(), row));
    }

    fn lane_doing(&self, lane: &str, label: &str) {
        if let Some(row) = self.state().lane(lane) {
            row.set_message(label.to_owned());
        }
    }

    fn lane_end(&self, lane: &str) {
        if let Some(row) = self.state().take_lane(lane) {
            row.finish_and_clear();
            self.bars.remove(&row);
        }
    }

    fn note(&self, text: &str) {
        // A terminal that cannot be written to must not stop the run.
        let _ = self.bars.println(text);
    }

    fn end(&self) {
        let state = self.state();
        // Rows leave the display without being finished: finishing a row would
        // move it to its total, and the count of a run cut short would lie.
        for row in state.lanes.iter().map(|(_, row)| row).chain(state.task.iter()) {
            self.bars.remove(row);
        }
        // A terminal that cannot be written to must not stop the run.
        let _ = self.bars.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use jiff::civil::datetime;

    use super::*;

    /// A stream the test keeps a handle on once the progress owns it.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A monotonic clock that returns the given readings, in seconds, in turn.
    fn ticks(seconds: Vec<f64>) -> impl Fn() -> Duration + Send + Sync + 'static {
        let readings = Mutex::new(seconds.into_iter());
        move || Duration::from_secs_f64(readings.lock().unwrap().next().expect("one more reading of the clock"))
    }

    fn drive(progress: &dyn Progress) {
        progress.begin(4);
        progress.step("collect nexus01.lab01 (1/2)");
        progress.doing("nexus01.lab01 · show interface | json");
        progress.advance(None);
        progress.note("nexus02.lab01: SSH to 192.0.2.240 failed: NetmikoTimeoutException");
        progress.resize(3);
        progress.step("cables");
        progress.advance(None);
        progress.end();
    }

    #[test]
    fn null_progress_accepts_every_call() {
        drive(&NullProgress);
    }

    #[test]
    fn log_progress_writes_one_line_per_step_and_note() {
        let stream = Shared::default();
        let progress =
            LogProgress::with_clock(stream.clone(), || datetime(2026, 9, 30, 19, 2, 11, 0), ticks(vec![100.0, 242.4]));
        drive(&progress);
        assert_eq!(
            stream.text(),
            "2026-09-30T19:02:11 collect nexus01.lab01 (1/2)\n\
             2026-09-30T19:02:11 nexus02.lab01: SSH to 192.0.2.240 failed: NetmikoTimeoutException\n\
             2026-09-30T19:02:11 cables\n\
             2026-09-30T19:02:11 done in 142 s\n"
        );
    }

    #[test]
    fn log_progress_stamps_to_the_second() {
        let stream = Shared::default();
        let progress =
            LogProgress::with_clock(stream.clone(), || datetime(2026, 1, 2, 3, 4, 5, 999_999_999), ticks(vec![]));
        progress.step("VLANs");
        // Python: `isoformat(timespec="seconds")` truncates, it does not round.
        assert_eq!(stream.text(), "2026-01-02T03:04:05 VLANs\n");
    }

    #[test]
    fn log_progress_rounds_the_duration_half_to_even_like_python() {
        let stream = Shared::default();
        let progress = LogProgress::with_clock(
            stream.clone(),
            || datetime(2026, 9, 30, 19, 2, 11, 0),
            ticks(vec![10.0, 12.5, 13.5]),
        );
        progress.begin(1);
        progress.end();
        progress.end();
        // Python: round(2.5) == 2, round(3.5) == 4.
        assert_eq!(stream.text(), "2026-09-30T19:02:11 done in 2 s\n2026-09-30T19:02:11 done in 4 s\n");
    }

    #[test]
    fn log_progress_stamps_with_the_local_clock_by_default() {
        let stream = Shared::default();
        let progress = LogProgress::new(stream.clone());
        progress.begin(1);
        progress.step("VLANs");
        progress.end();
        let text = stream.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let stamp = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} (.*)$").unwrap();
        assert_eq!(&stamp.captures(lines[0]).expect("a stamped line")[1], "VLANs");
        assert_eq!(&stamp.captures(lines[1]).expect("a stamped line")[1], "done in 0 s");
    }

    #[test]
    fn bar_progress_shows_the_current_unit_and_keeps_notes() {
        let progress = BarProgress::with_draw_target(ProgressDrawTarget::hidden());
        progress.begin(4);
        progress.step("collect nexus01.lab01 (1/2)");
        progress.doing("nexus01.lab01 · show interface | json");
        let rendered = progress.frame();
        assert!(rendered.contains("collect nexus01.lab01 (1/2)"));
        assert!(rendered.contains("nexus01.lab01 · show interface | json"));
        assert!(rendered.contains("0/4"));
        progress.advance(None);
        assert!(progress.frame().contains("1/4"));
        progress.note("nexus02.lab01: SSH to 192.0.2.240 failed");
        progress.end();
    }

    #[test]
    fn bar_progress_follows_a_whole_run() {
        let progress = BarProgress::with_draw_target(ProgressDrawTarget::hidden());
        drive(&progress);
        // 2 units done out of the 3 the run was resized to; a new step clears
        // the running unit of the previous one.
        assert_eq!(progress.frame(), "cables 2/3\n");
    }

    /// Waits for `text` on `screen`: a terminal is redrawn at most a few
    /// times a second, so a row just changed may not be drawn yet. Two seconds
    /// at most, twenty redraws of the steady tick.
    fn drawn(screen: &indicatif::InMemoryTerm, text: &str) -> bool {
        for _ in 0..100 {
            if screen.contents().contains(text) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn a_bar_dropped_before_its_end_leaves_nothing_on_screen() {
        // Ctrl-C drops the run where it is, its progress with it: the rows
        // must go, or the message that follows is written at their end.
        let screen = indicatif::InMemoryTerm::new(10, 80);
        let progress = BarProgress::with_draw_target(ProgressDrawTarget::term_like(Box::new(screen.clone())));
        progress.begin(3);
        progress.step("read 2 source(s)");
        progress.lane_start("pve-a", 1);
        assert!(drawn(&screen, "read 2 source(s)"), "{}", screen.contents());
        assert!(drawn(&screen, "pve-a"), "{}", screen.contents());
        drop(progress);
        assert_eq!(screen.contents(), "");
        // The same before any source has its row: the run alone is on screen.
        let progress = BarProgress::with_draw_target(ProgressDrawTarget::term_like(Box::new(screen.clone())));
        progress.begin(31);
        progress.step("read 9 source(s)");
        assert!(drawn(&screen, "read 9 source(s)"), "{}", screen.contents());
        drop(progress);
        assert_eq!(screen.contents(), "");
    }

    #[test]
    fn bar_progress_shows_one_row_per_switch_being_collected() {
        let progress = BarProgress::with_draw_target(ProgressDrawTarget::hidden());
        progress.begin(20);
        progress.step("collect (0/2)");
        progress.lane_start("nexus01.lab01", 9);
        progress.lane_start("nexus03.lab01", 9);
        progress.lane_doing("nexus01.lab01", "show vlan brief | json");
        progress.lane_doing("nexus03.lab01", "show inventory | json");
        progress.advance(Some("nexus01.lab01"));
        let frame = progress.frame();
        assert!(frame.contains("nexus01.lab01") && frame.contains("show vlan brief | json"));
        assert!(frame.contains("nexus03.lab01") && frame.contains("show inventory | json"));
        assert!(frame.contains("1/9") && frame.contains("1/20"));
        assert_eq!(
            frame,
            "collect (0/2) 1/20\n  nexus01.lab01 1/9 show vlan brief | json\n  nexus03.lab01 0/9 show inventory | json\n"
        );
        progress.lane_end("nexus01.lab01");
        assert!(!progress.frame().contains("nexus01.lab01"));
        progress.end();
    }

    #[test]
    fn bar_progress_ignores_an_unknown_lane_and_calls_before_begin() {
        let progress = BarProgress::with_draw_target(ProgressDrawTarget::hidden());
        progress.resize(3);
        progress.step("early");
        progress.doing("early");
        progress.advance(None);
        assert_eq!(progress.frame(), "");
        progress.begin(2);
        progress.lane_doing("ghost", "show version");
        progress.lane_end("ghost");
        // An unknown lane still counts as one unit of the run.
        progress.advance(Some("ghost"));
        assert_eq!(progress.frame(), "1/2\n");
    }

    #[test]
    fn bar_progress_counts_units_done_concurrently() {
        let progress = BarProgress::with_draw_target(ProgressDrawTarget::hidden());
        progress.begin(8);
        progress.step("collect 4 switch(es)");
        std::thread::scope(|scope| {
            for lane in ["sw1", "sw2", "sw3", "sw4"] {
                let progress: &dyn Progress = &progress;
                scope.spawn(move || {
                    progress.lane_start(lane, 2);
                    progress.lane_doing(lane, "show version");
                    progress.advance(Some(lane));
                    progress.advance(Some(lane));
                    progress.lane_end(lane);
                });
            }
        });
        // 4 lanes × 2 units, every lane gone.
        assert_eq!(progress.frame(), "collect 4 switch(es) 8/8\n");
    }

    #[test]
    fn log_and_null_progress_ignore_lanes() {
        let stream = Shared::default();
        let log = LogProgress::new(stream.clone());
        let progresses: [&dyn Progress; 2] = [&log, &NullProgress];
        for progress in progresses {
            progress.lane_start("nexus01.lab01", 9);
            progress.lane_doing("nexus01.lab01", "show vlan brief | json");
            progress.advance(Some("nexus01.lab01"));
            progress.lane_end("nexus01.lab01");
        }
        assert_eq!(stream.text(), "");
    }

    #[test]
    fn every_progress_is_shared_between_threads() {
        fn shared<T: Send + Sync>() {}
        shared::<NullProgress>();
        shared::<LogProgress<io::Stderr>>();
        shared::<LogProgress<Vec<u8>>>();
        shared::<BarProgress>();
        shared::<Box<dyn Progress>>();
    }
}
