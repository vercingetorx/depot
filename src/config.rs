use crate::core::{Endpoint, LogLevel, SandboxPolicy};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server: ServerDefaults,
    pub client: ClientDefaults,
    pub servers: HashMap<String, Endpoint>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerDefaults::default(),
            client: ClientDefaults::default(),
            servers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerDefaults {
    pub listen: String,
    pub port: u16,
    pub sandbox: SandboxPolicy,
}

impl Default for ServerDefaults {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".to_owned(),
            port: 60006,
            sandbox: SandboxPolicy::Enforced,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDefaults {
    pub server: Option<String>,
    pub log_level: LogLevel,
}

impl Default for ClientDefaults {
    fn default() -> Self {
        Self {
            server: None,
            log_level: LogLevel::Info,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    ParseToml(String),
    Read(std::io::Error),
    InvalidLogLevel(String),
    MissingClientDefaultServer,
    MissingClientTarget,
    UnknownNamedServer(String),
    NamedServerMissingHost(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseToml(err) => write!(f, "failed to parse config: {err}"),
            Self::Read(err) => write!(f, "failed to read config: {err}"),
            Self::InvalidLogLevel(value) => write!(f, "invalid log level: {value}"),
            Self::MissingClientDefaultServer => {
                write!(f, "named servers are configured but client.server is not set")
            }
            Self::MissingClientTarget => {
                write!(
                    f,
                    "no server selected; set client.server in config or use --server or --host"
                )
            }
            Self::UnknownNamedServer(name) => {
                write!(f, "unknown named server: {name}")
            }
            Self::NamedServerMissingHost(name) => {
                write!(f, "named server {name} is missing host")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    server: RawServerDefaults,
    #[serde(default)]
    client: RawClientDefaults,
    #[serde(default)]
    servers: HashMap<String, RawNamedServer>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerDefaults {
    listen: Option<String>,
    port: Option<u16>,
    sandbox: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientDefaults {
    server: Option<String>,
    log: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNamedServer {
    host: Option<String>,
    port: Option<u16>,
}

impl Config {
    pub fn parse_toml(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input)
            .map_err(|err| ConfigError::ParseToml(format_toml_error(input, &err)))?;
        let mut config = Self::default();

        if let Some(listen) = raw.server.listen {
            config.server.listen = listen;
        }
        if let Some(port) = raw.server.port {
            config.server.port = port;
        }
        if let Some(sandbox) = raw.server.sandbox {
            config.server.sandbox = if sandbox {
                SandboxPolicy::Enforced
            } else {
                SandboxPolicy::Disabled
            };
        }
        config.client.server = raw.client.server;
        if let Some(log) = raw.client.log {
            config.client.log_level = log
                .parse()
                .map_err(|_| ConfigError::InvalidLogLevel(log.clone()))?;
        }
        for (name, raw_server) in raw.servers {
            let host = raw_server
                .host
                .ok_or_else(|| ConfigError::NamedServerMissingHost(name.clone()))?;
            let port = raw_server.port.unwrap_or(60006);
            config.servers.insert(name, Endpoint::new(host, port));
        }
        if !config.servers.is_empty() && config.client.server.is_none() {
            return Err(ConfigError::MissingClientDefaultServer);
        }
        if let Some(name) = &config.client.server
            && !config.servers.contains_key(name)
        {
            return Err(ConfigError::UnknownNamedServer(name.clone()));
        }
        Ok(config)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
        Self::parse_toml(&content)
    }
}

fn format_toml_error(input: &str, error: &toml::de::Error) -> String {
    let mut rendered = error.to_string();
    if let Some(span) = error.span() {
        let (line_no, column_no, line_text) = line_details(input, span.start);
        if let Some(hint) = value_hint(line_text) {
            rendered.push_str(&format!(
                " at line {}, column {}: {}",
                line_no, column_no, hint
            ));
        }
    }
    rendered
}

fn line_details(input: &str, offset: usize) -> (usize, usize, &str) {
    let mut line_no = 1usize;
    let mut line_start = 0usize;
    for (idx, ch) in input.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line_no += 1;
            line_start = idx + 1;
        }
    }

    let line_end = input[line_start..]
        .find('\n')
        .map(|rel| line_start + rel)
        .unwrap_or(input.len());
    let column_no = input[line_start..offset].chars().count() + 1;
    (line_no, column_no, &input[line_start..line_end])
}

fn value_hint(line_text: &str) -> Option<&'static str> {
    let (_, rhs) = line_text.split_once('=')?;
    let value = rhs.trim();
    if value.is_empty() || value.starts_with('"') || value.starts_with('\'') {
        return None;
    }
    if value.chars().all(|ch| ch.is_ascii_digit() || ch == '.') && value.contains('.') {
        return Some(
            "values like host addresses must be quoted strings, for example host = \"192.168.68.11\"",
        );
    }
    None
}

pub fn config_dir() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) => PathBuf::from(value).join("depot"),
        None => PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join(".config")
            .join("depot"),
    }
}

pub fn config_path() -> PathBuf {
    config_dir().join("depot.conf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_v3_aligned() {
        let config = Config::default();
        assert_eq!(config.server.listen, "0.0.0.0");
        assert_eq!(config.client.log_level, LogLevel::Info);
        assert!(config.client.server.is_none());
        assert!(config.servers.is_empty());
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = Config::parse_toml(
            r#"
            [server]
            base = "/tmp"
            "#,
        )
        .unwrap_err();

        match err {
            ConfigError::ParseToml(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn parse_errors_hint_for_unquoted_host_strings() {
        let err = Config::parse_toml(
            r#"
            [servers.home]
            host = 192.168.68.11
            "#,
        )
        .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("failed to parse config:"));
        assert!(rendered.contains("quoted strings"));
        assert!(rendered.contains("host = \"192.168.68.11\""));
    }

    #[test]
    fn parses_named_servers_and_default_server() {
        let config = Config::parse_toml(
            r#"
            [client]
            server = "home"

            [servers.home]
            host = "storage.lan"

            [servers.vps]
            host = "files.example.com"
            port = 61000
            "#,
        )
        .unwrap();

        assert_eq!(config.client.server.as_deref(), Some("home"));
        assert_eq!(config.servers["home"].host, "storage.lan");
        assert_eq!(config.servers["home"].port, 60006);
        assert_eq!(config.servers["vps"].host, "files.example.com");
        assert_eq!(config.servers["vps"].port, 61000);
    }

    #[test]
    fn rejects_named_servers_without_default_selection() {
        let err = Config::parse_toml(
            r#"
            [servers.home]
            host = "storage.lan"
            "#,
        )
        .unwrap_err();

        assert!(matches!(err, ConfigError::MissingClientDefaultServer));
    }

    #[test]
    fn rejects_unknown_default_named_server() {
        let err = Config::parse_toml(
            r#"
            [client]
            server = "vps"

            [servers.home]
            host = "storage.lan"
            "#,
        )
        .unwrap_err();

        assert!(matches!(err, ConfigError::UnknownNamedServer(name) if name == "vps"));
    }
}
