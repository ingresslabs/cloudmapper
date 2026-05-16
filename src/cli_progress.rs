use std::env;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const DISPLAY_DELAY: Duration = Duration::from_millis(1200);
const FRAME_INTERVAL: Duration = Duration::from_millis(90);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(25);

const STAGES: &[&str] = &[
    "discovering cloud state",
    "normalizing resources",
    "linking relationships",
    "writing map database",
];

pub struct IngestAnimation {
    enabled: bool,
    label: String,
    db_path: PathBuf,
    started_at: Instant,
    stop: Arc<AtomicBool>,
    stage: Arc<Mutex<String>>,
    handle: Option<JoinHandle<()>>,
}

impl IngestAnimation {
    pub fn start(label: impl Into<String>, db_path: impl AsRef<Path>) -> Self {
        let label = label.into();
        let db_path = db_path.as_ref().to_path_buf();
        let enabled = should_animate();
        let stop = Arc::new(AtomicBool::new(false));
        let stage = Arc::new(Mutex::new(STAGES[0].to_string()));
        let handle = enabled.then(|| {
            let stop = Arc::clone(&stop);
            let stage = Arc::clone(&stage);
            let label = label.clone();
            let color = color_enabled();
            thread::spawn(move || animate(stop, stage, label, color))
        });

        Self {
            enabled,
            label,
            db_path,
            started_at: Instant::now(),
            stop,
            stage,
            handle,
        }
    }

    pub fn stage(&self, value: impl Into<String>) {
        if let Ok(mut stage) = self.stage.lock() {
            *stage = value.into();
        }
    }

    pub fn finish(mut self, detail: impl AsRef<str>) {
        self.stop_thread();
        if self.enabled {
            let _ = writeln!(
                io::stderr(),
                "\r\x1b[2Kdone {} -> {} in {} ({})",
                self.label,
                self.db_path.display(),
                elapsed(self.started_at),
                detail.as_ref()
            );
        }
        self.enabled = false;
    }

    pub fn fail(mut self) {
        self.stop_thread();
        self.enabled = false;
    }

    fn stop_thread(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for IngestAnimation {
    fn drop(&mut self) {
        self.stop_thread();
        if self.enabled {
            let _ = write!(io::stderr(), "\r\x1b[2K");
            let _ = io::stderr().flush();
        }
    }
}

fn animate(stop: Arc<AtomicBool>, stage: Arc<Mutex<String>>, label: String, color: bool) {
    let started_at = Instant::now();
    if !wait_for_display_delay(&stop, started_at) {
        return;
    }

    let mut tick = 0usize;
    while !stop.load(Ordering::Relaxed) {
        let frame = FRAMES[tick % FRAMES.len()];
        let stage = stage
            .lock()
            .map(|stage| stage.clone())
            .unwrap_or_else(|_| STAGES[(tick / 4) % STAGES.len()].to_string());
        let _ = write!(
            io::stderr(),
            "\r\x1b[2K{}",
            render_line(frame, &label, &stage, elapsed(started_at), color)
        );
        let _ = io::stderr().flush();
        tick = tick.wrapping_add(1);
        thread::sleep(FRAME_INTERVAL);
    }
    let _ = write!(io::stderr(), "\r\x1b[2K");
    let _ = io::stderr().flush();
}

fn wait_for_display_delay(stop: &AtomicBool, started_at: Instant) -> bool {
    while started_at.elapsed() < DISPLAY_DELAY {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        thread::sleep(STOP_POLL_INTERVAL);
    }
    !stop.load(Ordering::Relaxed)
}

fn should_animate() -> bool {
    io::stderr().is_terminal() && env::var("TERM").map_or(true, |term| term != "dumb")
}

fn color_enabled() -> bool {
    should_animate() && env::var_os("NO_COLOR").is_none()
}

fn render_line(frame: &str, label: &str, stage: &str, elapsed: String, color: bool) -> String {
    if !color {
        return format!("{frame} {label}: {stage} {elapsed}");
    }
    format!(
        "\x1b[36m{frame}\x1b[0m \x1b[1m{label}\x1b[0m: \x1b[2m{stage}\x1b[0m \x1b[2m{elapsed}\x1b[0m"
    )
}

fn elapsed(started_at: Instant) -> String {
    let elapsed = started_at.elapsed();
    let seconds = elapsed.as_secs();
    if seconds >= 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}.{:01}s", elapsed.subsec_millis() / 100)
    }
}

#[cfg(test)]
mod tests {
    use super::render_line;

    #[test]
    fn renders_short_plain_progress_line() {
        let line = render_line(
            ">",
            "aws",
            "discovering AWS resources",
            "1.2s".to_string(),
            false,
        );

        assert_eq!(line, "> aws: discovering AWS resources 1.2s");
        assert!(!line.contains("cloudmapper ingest"));
        assert!(!line.contains("map.db"));
    }
}
