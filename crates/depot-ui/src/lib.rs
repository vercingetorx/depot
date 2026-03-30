use depot_core::{BatchReport, BatchResult, DepotError, ErrorCode, Outcome, OutcomeSeverity};
use depot_protocol::ListEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Client,
    Server,
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

pub fn render_status(tag: &str, message: &str) -> String {
    format!("[{tag}] {message}")
}

pub fn render_server_listening(
    address: &str,
    root: &str,
    sandboxed: bool,
    require_client_auth: bool,
    allow_overwrite: bool,
) -> String {
    render_status(
        "listening",
        &format!(
            "{address} root={root} sandbox={} client_auth={} overwrite={}",
            if sandboxed { "on" } else { "off" },
            if require_client_auth { "required" } else { "off" },
            if allow_overwrite { "on" } else { "off" }
        ),
    )
}

pub fn render_keygen_result(secret_path: &str, public_path: &str) -> String {
    render_status(
        "generated",
        &format!("secret={secret_path} public={public_path}"),
    )
}

pub fn render_list_entry(entry: &ListEntry) -> String {
    if entry.is_dir {
        format!("{}/", entry.relative_path.as_str())
    } else {
        entry.relative_path.as_str().to_owned()
    }
}

pub fn render_batch_result(operation: &str, result: &BatchResult) -> String {
    match operation {
        "export" => format!(
            "[transferred] {} file(s), {}, {} skipped, {} failed",
            result.sent_files,
            format_bytes(result.sent_bytes),
            result.skipped,
            result.failed
        ),
        "import" => format!(
            "[transferred] {} file(s), {}, {} skipped, {} failed",
            result.received_files,
            format_bytes(result.received_bytes),
            result.skipped,
            result.failed
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
        OutcomeSeverity::Skipped => render_error(&DepotError::new(code, path), Audience::Client),
        OutcomeSeverity::ItemError | OutcomeSeverity::Fatal => {
            render_error(&DepotError::new(code, path), Audience::Client)
        }
        OutcomeSeverity::Success => render_status("ok", path),
    }
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
    use depot_core::{BatchReport, DepotError, ErrorCode, Operation, Outcome, RemotePath};

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
        assert_eq!(rendered, "movies/");
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
    }

    #[test]
    fn renders_server_listening_status() {
        let rendered =
            render_server_listening("127.0.0.1:60006", "/srv/media", true, false, false);
        assert!(rendered.contains("sandbox=on"));
        assert!(rendered.contains("client_auth=off"));
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
}
