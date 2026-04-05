use crate::core::{
    BatchReport, BatchResult, DepotError, ErrorCode, Outcome, OutcomeSeverity, TransferProgress,
};
use crate::protocol::ListEntry;
use crate::transport::{HandshakeError, TransportError};
use std::env;
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Client,
    Server,
}

const ANSI_RED: &str = "\x1b[31m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RESET: &str = "\x1b[0m";

pub struct ClientConsole {
    progress: ProgressRenderer,
    color_enabled: bool,
}

impl ClientConsole {
    pub fn new() -> Self {
        Self {
            progress: ProgressRenderer::new(),
            color_enabled: io::stdout().is_terminal() || io::stderr().is_terminal(),
        }
    }

    pub fn print_status_line(&mut self, line: &str) -> io::Result<()> {
        self.progress.clear()?;
        writeln!(
            io::stdout(),
            "{}",
            colorize_tag(line, ANSI_GREEN, self.color_enabled)
        )
    }

    pub fn print_plain_line(&mut self, line: &str) -> io::Result<()> {
        self.progress.clear()?;
        writeln!(io::stdout(), "{line}")
    }

    pub fn print_error_line(&mut self, line: &str) -> io::Result<()> {
        self.progress.clear()?;
        writeln!(
            io::stderr(),
            "{}",
            colorize_tag(line, ANSI_RED, self.color_enabled)
        )
    }

    pub fn draw_progress(&mut self, progress: &TransferProgress) -> io::Result<()> {
        self.progress.draw(progress)
    }

    pub fn clear_progress(&mut self) -> io::Result<()> {
        self.progress.clear()
    }
}

struct ProgressRenderer {
    is_tty: bool,
    last_line_width: usize,
    last_percent: Option<u8>,
    last_draw: Option<Instant>,
}

impl ProgressRenderer {
    fn new() -> Self {
        Self {
            is_tty: io::stdout().is_terminal(),
            last_line_width: 0,
            last_percent: None,
            last_draw: None,
        }
    }

    fn clear(&mut self) -> io::Result<()> {
        if !self.is_tty || self.last_line_width == 0 {
            self.last_line_width = 0;
            self.last_percent = None;
            self.last_draw = None;
            return Ok(());
        }
        let cols = terminal_columns();
        clear_wrapped_rows(cols, self.last_line_width)?;
        self.last_line_width = 0;
        self.last_percent = None;
        self.last_draw = None;
        Ok(())
    }

    fn draw(&mut self, progress: &TransferProgress) -> io::Result<()> {
        if !self.is_tty {
            return Ok(());
        }

        let percent = progress
            .total_bytes
            .filter(|total| *total > 0)
            .map(|total| ((progress.done_bytes as f64 / total as f64) * 100.0) as u8);
        let now = Instant::now();
        if self.last_percent == percent
            && self
                .last_draw
                .is_some_and(|last| now.duration_since(last) < Duration::from_millis(100))
        {
            return Ok(());
        }

        let cols = terminal_columns();
        let line = render_progress_line(progress, cols);
        if self.last_line_width > 0 {
            clear_wrapped_rows(cols, self.last_line_width)?;
        }

        write!(io::stdout(), "{line}")?;
        io::stdout().flush()?;
        self.last_line_width = visible_width(&line);
        self.last_percent = percent;
        self.last_draw = Some(now);
        Ok(())
    }
}

pub fn render_error(error: &DepotError, audience: Audience) -> String {
    let mut rendered = format!(
        "[{}] {}",
        error.code.name(),
        message_text(error.code, audience)
    );
    if let Some(message) = &error.message {
        if !message.is_empty() {
            rendered.push_str(": ");
            rendered.push_str(message);
        }
    }
    rendered
}

pub fn render_handshake_error(error: &HandshakeError, audience: Audience) -> String {
    match error {
        HandshakeError::Remote(code) => render_error(&DepotError::code_only(*code), audience),
        HandshakeError::VersionMismatch { expected, actual } => render_error(
            &DepotError::new(
                ErrorCode::Compat,
                format!("protocol version mismatch: expected {expected}, got {actual}"),
            ),
            audience,
        ),
        HandshakeError::MissingFeature(name) => render_error(
            &DepotError::new(
                ErrorCode::Compat,
                format!("required feature missing: {name}"),
            ),
            audience,
        ),
        HandshakeError::Authentication(message) => {
            render_error(&DepotError::new(ErrorCode::Auth, *message), audience)
        }
        HandshakeError::EnrollmentRequired => render_error(
            &DepotError::new(
                ErrorCode::Auth,
                "client pairing is required before this request can continue",
            ),
            audience,
        ),
        HandshakeError::Codec(_) | HandshakeError::BadState(_) => render_error(
            &DepotError::new(ErrorCode::Protocol, "invalid handshake message from peer"),
            audience,
        ),
        HandshakeError::Crypto(_) => render_error(
            &DepotError::new(
                ErrorCode::Protocol,
                "cryptographic handshake verification failed",
            ),
            audience,
        ),
        HandshakeError::Io(_) => render_error(
            &DepotError::new(ErrorCode::Closed, "connection closed during handshake"),
            audience,
        ),
    }
}

pub fn render_transport_error(error: &TransportError, audience: Audience) -> String {
    match error {
        TransportError::ConnectionClosed => {
            render_error(&DepotError::code_only(ErrorCode::Closed), audience)
        }
        TransportError::Timeout => {
            render_error(&DepotError::code_only(ErrorCode::Timeout), audience)
        }
        TransportError::AuthenticationFailed => render_error(
            &DepotError::new(
                ErrorCode::Protocol,
                "encrypted record authentication failed",
            ),
            audience,
        ),
        TransportError::InvalidRecordLength(_) | TransportError::Codec(_) => render_error(
            &DepotError::new(ErrorCode::Protocol, "invalid protocol frame from peer"),
            audience,
        ),
        TransportError::Crypto(_) => render_error(
            &DepotError::new(
                ErrorCode::Protocol,
                "failed to process encrypted protocol record",
            ),
            audience,
        ),
        TransportError::Io(error) => render_error(
            &DepotError::new(ErrorCode::Closed, error.to_string()),
            audience,
        ),
    }
}

pub fn render_status(tag: &str, message: &str) -> String {
    format!("[{tag}] {message}")
}

pub fn render_server_listening(
    address: &str,
    root: &str,
    sandboxed: bool,
    allow_overwrite: bool,
) -> String {
    render_status(
        "listening",
        &format!(
            "{address} root={root} sandbox={} overwrite={}",
            if sandboxed { "on" } else { "off" },
            if allow_overwrite { "on" } else { "off" }
        ),
    )
}

pub fn render_list_entry(entry: &ListEntry) -> String {
    if entry.is_dir {
        format!(
            "[dir] {} ({})",
            entry.relative_path.as_str(),
            format_bytes(entry.file_size)
        )
    } else {
        format!(
            "{} ({})",
            entry.relative_path.as_str(),
            format_bytes(entry.file_size)
        )
    }
}

pub fn render_batch_result(operation: &str, result: &BatchResult) -> String {
    match operation {
        "export" => render_transfer_summary(
            result.sent_files,
            result.sent_bytes,
            result.skipped,
            result.failed,
        ),
        "import" => render_transfer_summary(
            result.received_files,
            result.received_bytes,
            result.skipped,
            result.failed,
        ),
        _ => format!(
            "[transferred] sent={} received={} skipped={} failed={}",
            result.sent_files + result.received_files,
            format_bytes(result.sent_bytes + result.received_bytes),
            result.skipped,
            result.failed
        ),
    }
}

pub fn render_batch_report(operation: &str, report: &BatchReport) -> Vec<String> {
    let mut lines = Vec::new();
    for outcome in &report.outcomes {
        lines.push(render_outcome(outcome));
    }
    lines.push(render_batch_result(operation, &report.result));
    lines
}

pub fn render_outcome(outcome: &Outcome) -> String {
    let code = outcome.code.unwrap_or(ErrorCode::Unknown);
    let path = outcome.path.as_deref().unwrap_or("");
    match outcome.severity {
        OutcomeSeverity::Skipped => render_status("skip", path),
        OutcomeSeverity::ItemError | OutcomeSeverity::Fatal => {
            render_error(&DepotError::new(code, path), Audience::Client)
        }
        OutcomeSeverity::Success => render_status("done", path),
    }
}

fn render_progress_line(progress: &TransferProgress, columns: usize) -> String {
    let rate = if progress.elapsed.is_zero() {
        0.0
    } else {
        progress.done_bytes as f64 / progress.elapsed.as_secs_f64()
    };
    let rate_str = format!("{}/s", format_bytes(rate.max(0.0) as u64));
    let mut suffix = match progress.total_bytes {
        Some(total) if total > 0 => {
            let percent = ((progress.done_bytes as f64 / total as f64) * 100.0) as u8;
            format!(
                " {percent}% ({}/{}, {rate_str})",
                format_bytes(progress.done_bytes),
                format_bytes(total)
            )
        }
        _ => format!(" ({}, {rate_str})", format_bytes(progress.done_bytes)),
    };

    if let Some(total) = progress
        .total_bytes
        .filter(|total| *total > progress.done_bytes)
    {
        if rate > 0.0 {
            let remaining = (total - progress.done_bytes) as f64 / rate;
            suffix.push_str(", ETA ");
            suffix.push_str(&format_eta(Duration::from_secs(remaining as u64)));
        }
    }

    let base = format!("{} ", progress.action.tag());
    let max_name_width = columns.saturating_sub(visible_width(&base) + visible_width(&suffix));
    let name = shorten_visible(&sanitize_for_terminal(&progress.name), max_name_width);
    format!("{base}{name}{suffix}")
}

fn format_eta(duration: Duration) -> String {
    let secs = duration.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

fn terminal_columns() -> usize {
    env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.max(40))
        .unwrap_or(80)
}

fn clear_wrapped_rows(columns: usize, previous_width: usize) -> io::Result<()> {
    let rows = previous_width.max(1).div_ceil(columns.max(1));
    write!(io::stdout(), "\r")?;
    for index in 0..rows {
        write!(io::stdout(), "\x1b[2K")?;
        if index + 1 < rows {
            write!(io::stdout(), "\x1b[1A\r")?;
        }
    }
    io::stdout().flush()
}

fn colorize_tag(line: &str, color: &str, enabled: bool) -> String {
    if !enabled {
        return line.to_owned();
    }
    let Some(left) = line.find('[') else {
        return line.to_owned();
    };
    let Some(right_rel) = line[left + 1..].find(']') else {
        return line.to_owned();
    };
    let right = left + 1 + right_rel;
    let mut rendered = String::with_capacity(line.len() + color.len() + ANSI_RESET.len());
    rendered.push_str(&line[..left + 1]);
    rendered.push_str(color);
    rendered.push_str(&line[left + 1..right]);
    rendered.push_str(ANSI_RESET);
    rendered.push_str(&line[right..]);
    rendered
}

fn sanitize_for_terminal(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect()
}

fn visible_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn shorten_visible(text: &str, max_width: usize) -> String {
    if visible_width(text) <= max_width {
        return text.to_owned();
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }

    let chars: Vec<char> = text.chars().collect();
    let left_target = (max_width - 3) / 2;
    let right_target = max_width - 3 - left_target;

    let mut left = String::new();
    let mut width = 0usize;
    for ch in &chars {
        let w = UnicodeWidthChar::width(*ch).unwrap_or(0);
        if width + w > left_target {
            break;
        }
        left.push(*ch);
        width += w;
    }

    let mut right_chars = Vec::new();
    let mut width = 0usize;
    for ch in chars.iter().rev() {
        let w = UnicodeWidthChar::width(*ch).unwrap_or(0);
        if width + w > right_target {
            break;
        }
        right_chars.push(*ch);
        width += w;
    }
    right_chars.reverse();
    let right: String = right_chars.into_iter().collect();

    format!("{left}...{right}")
}

fn render_transfer_summary(files: u64, bytes: u64, skipped: u64, failed: u64) -> String {
    let mut rendered = format!("[transferred] {} file(s), {}", files, format_bytes(bytes));
    if skipped > 0 {
        rendered.push_str(&format!(", skipped {skipped}"));
    }
    if failed > 0 {
        rendered.push_str(&format!(", failed {failed}"));
    }
    rendered
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn message_text(code: ErrorCode, audience: Audience) -> &'static str {
    match audience {
        Audience::Client => match code {
            ErrorCode::Exists => "file exists",
            ErrorCode::Filter => "skipped by filter",
            ErrorCode::NoSpace => "no space left",
            ErrorCode::Perms => "permission denied",
            ErrorCode::Absolute => "absolute remote path not allowed",
            ErrorCode::UnsafePath => "unsafe path",
            ErrorCode::BadPath => "bad path",
            ErrorCode::BadPayload => "bad payload",
            ErrorCode::OpenFail => "open failed",
            ErrorCode::WriteFail => "write failed",
            ErrorCode::ReadFail => "read failed",
            ErrorCode::NotFound => "item not found",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Checksum => "checksum mismatch",
            ErrorCode::Closed => "connection closed unexpectedly",
            ErrorCode::Connect => "couldn't connect to server",
            ErrorCode::Protocol => "protocol error",
            ErrorCode::CommitFail => "commit failed on server",
            ErrorCode::Conflict => "conflicting destination",
            ErrorCode::BadRemote => "invalid remote spec",
            ErrorCode::Config => "server misconfigured",
            ErrorCode::Compat => "incompatible client/server",
            ErrorCode::Auth => "authentication required or failed",
            ErrorCode::Unknown => "error",
        },
        Audience::Server => match code {
            ErrorCode::Exists => "refusing overwrite",
            ErrorCode::Filter => "filtered",
            ErrorCode::NoSpace => "disk full",
            ErrorCode::Perms => "access denied",
            ErrorCode::Absolute => "absolute remote path not allowed",
            ErrorCode::UnsafePath => "unsafe path rejected",
            ErrorCode::BadPath => "bad path",
            ErrorCode::BadPayload => "bad payload",
            ErrorCode::OpenFail => "open failed",
            ErrorCode::WriteFail => "write failed",
            ErrorCode::ReadFail => "read failed",
            ErrorCode::NotFound => "not found",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Checksum => "checksum mismatch",
            ErrorCode::Closed => "peer closed connection",
            ErrorCode::Connect => "client connection error",
            ErrorCode::Protocol => "protocol violation",
            ErrorCode::CommitFail => "commit failed",
            ErrorCode::Conflict => "conflict",
            ErrorCode::BadRemote => "bad remote spec",
            ErrorCode::Config => "server configuration error",
            ErrorCode::Compat => "feature/version mismatch",
            ErrorCode::Auth => "client authentication error",
            ErrorCode::Unknown => "unknown",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BatchReport, DepotError, ErrorCode, Operation, Outcome, RemotePath};
    use crate::transport::{HandshakeError, TransportError};

    #[test]
    fn renders_absolute_remote_path_errors_for_clients() {
        let error = DepotError::new(ErrorCode::Absolute, "/home/xioren/test");
        let rendered = render_error(&error, Audience::Client);
        assert!(rendered.contains("absolute remote path not allowed"));
        assert!(rendered.contains("/home/xioren/test"));
    }

    #[test]
    fn renders_directory_entries_with_trailing_slash() {
        let rendered = render_list_entry(&ListEntry {
            relative_path: RemotePath::new("movies"),
            file_size: 0,
            is_dir: true,
        });
        assert_eq!(rendered, "[dir] movies (0 B)");
    }

    #[test]
    fn renders_human_batch_sizes() {
        let rendered = render_batch_result(
            "export",
            &BatchResult {
                sent_files: 2,
                sent_bytes: 1536,
                ..BatchResult::default()
            },
        );
        assert!(rendered.contains("1.50 KiB"));
        assert!(!rendered.contains("skipped 0"));
        assert!(!rendered.contains("failed 0"));
    }

    #[test]
    fn renders_server_listening_status() {
        let rendered = render_server_listening("127.0.0.1:60006", "/srv/media", true, false);
        assert!(rendered.contains("sandbox=on"));
        assert!(rendered.contains("overwrite=off"));
    }

    #[test]
    fn renders_batch_report_with_outcomes_first() {
        let rendered = render_batch_report(
            "import",
            &BatchReport {
                result: BatchResult {
                    failed: 1,
                    ..BatchResult::default()
                },
                outcomes: vec![Outcome {
                    operation: Operation::Import,
                    severity: OutcomeSeverity::ItemError,
                    code: Some(ErrorCode::Absolute),
                    path: Some("/tmp/file".to_owned()),
                }],
            },
        );
        assert!(rendered[0].contains("[absolute]"));
        assert!(rendered[1].contains("[transferred]"));
    }

    #[test]
    fn renders_transport_protocol_failures_helpfully() {
        let rendered =
            render_transport_error(&TransportError::InvalidRecordLength(2), Audience::Client);
        assert!(rendered.contains("[protocol]"));
        assert!(rendered.contains("invalid protocol frame from peer"));
        assert!(!rendered.contains("invalid record length"));
    }

    #[test]
    fn renders_enrollment_required_helpfully() {
        let rendered =
            render_handshake_error(&HandshakeError::EnrollmentRequired, Audience::Client);
        assert!(rendered.contains("[auth]"));
        assert!(rendered.contains("client pairing is required"));
    }

    #[test]
    fn colorizes_only_tag_text() {
        let rendered = colorize_tag("[done] file.txt (1 B)", ANSI_GREEN, true);
        assert!(rendered.starts_with("[\u{1b}[32mdone\u{1b}[0m]"));
        assert!(rendered.ends_with("file.txt (1 B)"));
    }

    #[test]
    fn renders_progress_line_with_rate_and_eta() {
        let rendered = render_progress_line(
            &TransferProgress {
                action: crate::core::TransferProgressAction::Downloading,
                name: "archive.tar".to_owned(),
                done_bytes: 1024 * 1024,
                total_bytes: Some(2 * 1024 * 1024),
                elapsed: Duration::from_secs(2),
            },
            120,
        );
        assert!(rendered.contains("[downloading]"));
        assert!(rendered.contains("50%"));
        assert!(rendered.contains("512.00 KiB/s"));
        assert!(rendered.contains("ETA 00:02"));
    }
}
