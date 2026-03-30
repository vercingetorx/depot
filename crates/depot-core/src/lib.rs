use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err("invalid log level"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxPolicy {
    Enforced,
    Disabled,
}

impl SandboxPolicy {
    pub fn is_enforced(self) -> bool {
        matches!(self, Self::Enforced)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemotePath(String);

impl RemotePath {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for RemotePath {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for RemotePath {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for RemotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRoot(PathBuf);

impl ServerRoot {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortablePermission {
    UserRead,
    UserWrite,
    UserExec,
    GroupRead,
    GroupWrite,
    GroupExec,
    OtherRead,
    OtherWrite,
    OtherExec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortablePermissions(u16);

impl PortablePermissions {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn insert(&mut self, permission: PortablePermission) {
        self.0 |= 1 << (permission as u16);
    }

    pub fn contains(self, permission: PortablePermission) -> bool {
        (self.0 & (1 << (permission as u16))) != 0
    }

    pub fn bits(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOptions {
    pub listen: String,
    pub port: u16,
    pub root: Option<PathBuf>,
    pub sandbox: SandboxPolicy,
    pub allow_overwrite: bool,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportPlan {
    pub endpoint: Endpoint,
    pub sources: Vec<PathBuf>,
    pub destination: Option<RemotePath>,
    pub include_top: bool,
    pub skip_existing: bool,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPlan {
    pub endpoint: Endpoint,
    pub sources: Vec<RemotePath>,
    pub destination: Option<PathBuf>,
    pub include_top: bool,
    pub skip_existing: bool,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPlan {
    pub endpoint: Endpoint,
    pub path: Option<RemotePath>,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Serve(ServeOptions),
    Export(ExportPlan),
    Import(ImportPlan),
    List(ListPlan),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Serve,
    Export,
    Import,
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferProgressAction {
    Uploading,
    Downloading,
}

impl TransferProgressAction {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Uploading => "[uploading]",
            Self::Downloading => "[downloading]",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferProgress {
    pub action: TransferProgressAction,
    pub name: String,
    pub done_bytes: u64,
    pub total_bytes: Option<u64>,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Unknown,
    Exists,
    Filter,
    NoSpace,
    Perms,
    Absolute,
    UnsafePath,
    BadPath,
    BadPayload,
    OpenFail,
    WriteFail,
    ReadFail,
    NotFound,
    Timeout,
    Checksum,
    Closed,
    Connect,
    Protocol,
    CommitFail,
    Conflict,
    BadRemote,
    Config,
    Compat,
    Auth,
}

impl ErrorCode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Exists => "exists",
            Self::Filter => "filter",
            Self::NoSpace => "no-space",
            Self::Perms => "perms",
            Self::Absolute => "absolute",
            Self::UnsafePath => "unsafe-path",
            Self::BadPath => "bad-path",
            Self::BadPayload => "bad-payload",
            Self::OpenFail => "open-fail",
            Self::WriteFail => "write-fail",
            Self::ReadFail => "read-fail",
            Self::NotFound => "not-found",
            Self::Timeout => "timeout",
            Self::Checksum => "checksum",
            Self::Closed => "closed",
            Self::Connect => "connect",
            Self::Protocol => "protocol",
            Self::CommitFail => "commit-fail",
            Self::Conflict => "conflict",
            Self::BadRemote => "bad-remote",
            Self::Config => "server-config",
            Self::Compat => "compat",
            Self::Auth => "auth",
        }
    }

    pub fn is_session_fatal(self) -> bool {
        matches!(
            self,
            Self::Closed
                | Self::Timeout
                | Self::Protocol
                | Self::Compat
                | Self::Auth
                | Self::Config
                | Self::Connect
        )
    }

    pub fn is_local_fatal(self) -> bool {
        matches!(
            self,
            Self::NoSpace | Self::Perms | Self::OpenFail | Self::WriteFail | Self::ReadFail
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepotError {
    pub code: ErrorCode,
    pub message: Option<String>,
}

impl DepotError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            code,
            message: if message.is_empty() {
                None
            } else {
                Some(message)
            },
        }
    }

    pub fn code_only(code: ErrorCode) -> Self {
        Self {
            code,
            message: None,
        }
    }
}

impl fmt::Display for DepotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(message) => write!(f, "[{}] {}", self.code.name(), message),
            None => write!(f, "[{}]", self.code.name()),
        }
    }
}

impl std::error::Error for DepotError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeSeverity {
    Success,
    Skipped,
    ItemError,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub operation: Operation,
    pub severity: OutcomeSeverity,
    pub code: Option<ErrorCode>,
    pub path: Option<String>,
}

impl Outcome {
    pub fn should_abort_batch(&self) -> bool {
        self.severity == OutcomeSeverity::Fatal
    }
}

pub fn classify_outcome_severity(code: ErrorCode) -> OutcomeSeverity {
    if code == ErrorCode::Unknown {
        return OutcomeSeverity::Fatal;
    }
    if matches!(code, ErrorCode::Exists | ErrorCode::Filter) {
        return OutcomeSeverity::Skipped;
    }
    if code.is_session_fatal() || code.is_local_fatal() {
        return OutcomeSeverity::Fatal;
    }
    if matches!(
        code,
        ErrorCode::Exists
            | ErrorCode::NotFound
            | ErrorCode::BadPath
            | ErrorCode::UnsafePath
            | ErrorCode::Absolute
            | ErrorCode::Checksum
            | ErrorCode::Filter
    ) {
        return OutcomeSeverity::ItemError;
    }
    OutcomeSeverity::Fatal
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BatchResult {
    pub sent_files: u64,
    pub sent_bytes: u64,
    pub received_files: u64,
    pub received_bytes: u64,
    pub skipped: u64,
    pub failed: u64,
    pub fatal_abort: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BatchReport {
    pub result: BatchResult,
    pub outcomes: Vec<Outcome>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_log_levels() {
        assert_eq!("debug".parse::<LogLevel>(), Ok(LogLevel::Debug));
        assert_eq!("warning".parse::<LogLevel>(), Ok(LogLevel::Warn));
        assert!("loud".parse::<LogLevel>().is_err());
    }

    #[test]
    fn classifies_fatal_errors() {
        assert!(ErrorCode::Timeout.is_session_fatal());
        assert!(ErrorCode::OpenFail.is_local_fatal());
        assert!(!ErrorCode::NotFound.is_session_fatal());
    }
}
