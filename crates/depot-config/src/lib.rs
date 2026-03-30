use depot_core::{Endpoint, LogLevel, SandboxPolicy};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server: ServerDefaults,
    pub client: ClientDefaults,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerDefaults::default(),
            client: ClientDefaults::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerDefaults {
    pub listen: String,
    pub port: u16,
    pub sandbox: SandboxPolicy,
    pub psk: Option<String>,
    pub require_client_auth: bool,
}

impl Default for ServerDefaults {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".to_owned(),
            port: 60006,
            sandbox: SandboxPolicy::Enforced,
            psk: None,
            require_client_auth: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDefaults {
    pub endpoint: Endpoint,
    pub log_level: LogLevel,
    pub psk: Option<String>,
}

impl Default for ClientDefaults {
    fn default() -> Self {
        Self {
            endpoint: Endpoint::new("localhost", 60006),
            log_level: LogLevel::Info,
            psk: None,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    ParseToml(toml::de::Error),
    Read(std::io::Error),
    InvalidLogLevel(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseToml(err) => write!(f, "failed to parse config: {err}"),
            Self::Read(err) => write!(f, "failed to read config: {err}"),
            Self::InvalidLogLevel(value) => write!(f, "invalid log level: {value}"),
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
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerDefaults {
    listen: Option<String>,
    port: Option<u16>,
    sandbox: Option<bool>,
    psk: Option<String>,
    require_client_auth: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientDefaults {
    host: Option<String>,
    port: Option<u16>,
    log: Option<String>,
    psk: Option<String>,
}

impl Config {
    pub fn parse_toml(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input).map_err(ConfigError::ParseToml)?;
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
        config.server.psk = raw.server.psk.filter(|value| !value.is_empty());
        if let Some(require_client_auth) = raw.server.require_client_auth {
            config.server.require_client_auth = require_client_auth;
        }

        if let Some(host) = raw.client.host {
            config.client.endpoint.host = host;
        }
        if let Some(port) = raw.client.port {
            config.client.endpoint.port = port;
        }
        if let Some(log) = raw.client.log {
            config.client.log_level = log
                .parse()
                .map_err(|_| ConfigError::InvalidLogLevel(log.clone()))?;
        }
        config.client.psk = raw.client.psk.filter(|value| !value.is_empty());

        Ok(config)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
        Self::parse_toml(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_v3_aligned() {
        let config = Config::default();
        assert_eq!(config.server.listen, "0.0.0.0");
        assert_eq!(config.client.endpoint.host, "localhost");
        assert_eq!(config.client.log_level, LogLevel::Info);
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
}
