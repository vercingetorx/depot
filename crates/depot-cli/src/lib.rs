use clap::{Args, Parser, Subcommand};
use depot_app::{App, AppError};
use depot_config::{Config, ConfigError};
use depot_core::{
    Command, Endpoint, ExportPlan, ImportPlan, ListPlan, RemotePath, SandboxPolicy, ServeOptions,
};
use depot_crypto::latebra::signature::{MlDsa87PublicKey, MlDsa87SecretKey};
use depot_crypto::{CryptoError, HandshakeCryptoProvider, LatebraCrypto, SigningIdentity};
use depot_ui::{
    Audience, render_batch_report, render_error, render_keygen_result, render_list_entry,
    render_server_listening,
};
use std::path::PathBuf;
use tokio::net::TcpListener;

#[derive(Debug, Clone, Parser)]
#[command(name = "depot")]
#[command(about = "secure file transfer")]
pub struct Cli {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    Serve(ServeArgs),
    Export(ExportArgs),
    Import(ImportArgs),
    Ls(ListArgs),
    Keygen(KeygenArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    #[arg(long, default_value = "")]
    pub listen: String,
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    #[arg(long)]
    pub root: Option<PathBuf>,
    #[arg(long)]
    pub no_sandbox: bool,
    #[arg(long)]
    pub allow_overwrite: bool,
    #[arg(long, default_value = "info")]
    pub log: String,
    #[arg(long)]
    pub identity_file: PathBuf,
    #[arg(long)]
    pub require_client_auth: bool,
    #[arg(long = "trust-client-pubkey-file")]
    pub trusted_client_pubkey_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    #[arg()]
    pub sources: Vec<PathBuf>,
    #[arg(long, default_value = "")]
    pub host: String,
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    #[arg(long)]
    pub dest: Option<String>,
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub skip_existing: bool,
    #[arg(long, default_value = "info")]
    pub log: String,
    #[arg(long)]
    pub server_pubkey_file: PathBuf,
    #[arg(long)]
    pub client_identity_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ImportArgs {
    #[arg()]
    pub sources: Vec<String>,
    #[arg(long, default_value = "")]
    pub host: String,
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    #[arg(long)]
    pub dest: Option<PathBuf>,
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub skip_existing: bool,
    #[arg(long, default_value = "info")]
    pub log: String,
    #[arg(long)]
    pub server_pubkey_file: PathBuf,
    #[arg(long)]
    pub client_identity_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    #[arg()]
    pub path: Option<String>,
    #[arg(long, default_value = "")]
    pub host: String,
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    #[arg(long, default_value = "info")]
    pub log: String,
    #[arg(long)]
    pub server_pubkey_file: PathBuf,
    #[arg(long)]
    pub client_identity_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub secret_out: PathBuf,
    #[arg(long)]
    pub public_out: PathBuf,
}

#[derive(Debug)]
pub enum CliError {
    InvalidLogLevel(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLogLevel(value) => write!(f, "invalid log level: {value}"),
        }
    }
}

impl std::error::Error for CliError {}

#[derive(Debug)]
pub enum RunError {
    Cli(CliError),
    Config(ConfigError),
    Io(std::io::Error),
    Crypto(CryptoError),
    App(AppError),
    BatchFailed(String),
    MissingTrustedClients,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cli(error) => write!(f, "{error}"),
            Self::Config(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::App(error) => write!(f, "{error}"),
            Self::BatchFailed(message) => write!(f, "{message}"),
            Self::MissingTrustedClients => {
                f.write_str("client authentication requires at least one trusted client public key")
            }
        }
    }
}

impl std::error::Error for RunError {}

impl From<CliError> for RunError {
    fn from(value: CliError) -> Self {
        Self::Cli(value)
    }
}

impl From<ConfigError> for RunError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<std::io::Error> for RunError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<CryptoError> for RunError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<AppError> for RunError {
    fn from(value: AppError) -> Self {
        Self::App(value)
    }
}

impl TryFrom<&Commands> for Command {
    type Error = CliError;

    fn try_from(command: &Commands) -> Result<Self, Self::Error> {
        match command {
            Commands::Serve(args) => Ok(Command::Serve(ServeOptions {
                listen: args.listen.clone(),
                port: args.port,
                root: args.root.clone(),
                sandbox: if args.no_sandbox {
                    SandboxPolicy::Disabled
                } else {
                    SandboxPolicy::Enforced
                },
                allow_overwrite: args.allow_overwrite,
                log_level: args
                    .log
                    .parse()
                    .map_err(|_| CliError::InvalidLogLevel(args.log.clone()))?,
            })),
            Commands::Export(args) => Ok(Command::Export(ExportPlan {
                endpoint: Endpoint::new(args.host.clone(), args.port),
                sources: if args.all && args.sources.is_empty() {
                    vec![PathBuf::from(".")]
                } else {
                    args.sources.clone()
                },
                destination: args.dest.clone().map(RemotePath::new),
                include_top: !args.all,
                skip_existing: args.skip_existing,
                log_level: args
                    .log
                    .parse()
                    .map_err(|_| CliError::InvalidLogLevel(args.log.clone()))?,
            })),
            Commands::Import(args) => Ok(Command::Import(ImportPlan {
                endpoint: Endpoint::new(args.host.clone(), args.port),
                sources: if args.all && args.sources.is_empty() {
                    vec![RemotePath::new(".")]
                } else {
                    args.sources.iter().cloned().map(RemotePath::new).collect()
                },
                destination: args.dest.clone(),
                include_top: !args.all,
                skip_existing: args.skip_existing,
                log_level: args
                    .log
                    .parse()
                    .map_err(|_| CliError::InvalidLogLevel(args.log.clone()))?,
            })),
            Commands::Ls(args) => Ok(Command::List(ListPlan {
                endpoint: Endpoint::new(args.host.clone(), args.port),
                path: args.path.clone().map(RemotePath::new),
                log_level: args
                    .log
                    .parse()
                    .map_err(|_| CliError::InvalidLogLevel(args.log.clone()))?,
            })),
            Commands::Keygen(_) => unreachable!("keygen is not a depot-core command"),
        }
    }
}

pub async fn run(cli: Cli) -> Result<(), RunError> {
    match &cli.command {
        Commands::Keygen(args) => {
            run_keygen(args)?;
            Ok(())
        }
        command => {
            let config = load_config(cli.config.as_ref())?;
            let app = App::new(config);
            match command {
                Commands::Serve(args) => run_serve(&app, args).await,
                Commands::Export(args) => run_export(&app, args).await,
                Commands::Import(args) => run_import(&app, args).await,
                Commands::Ls(args) => run_list(&app, args).await,
                Commands::Keygen(_) => unreachable!(),
            }
        }
    }
}

fn load_config(path: Option<&PathBuf>) -> Result<Config, RunError> {
    match path {
        Some(path) => Ok(Config::from_path(path)?),
        None => Ok(Config::default()),
    }
}

async fn run_serve(app: &App, args: &ServeArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Serve(args.clone()))?);
    let Command::Serve(options) = command else {
        unreachable!()
    };

    let current_dir = std::env::current_dir()?;
    let root = app.resolved_server_root(options.root.clone(), current_dir);
    let root = app.canonical_server_root(root.as_path())?;
    let identity = load_signing_identity(&args.identity_file)?;
    let require_client_auth = args.require_client_auth || app.config().server.require_client_auth;
    let trusted_client_identities = load_public_keys(&args.trusted_client_pubkey_files)?;
    if require_client_auth && trusted_client_identities.is_empty() {
        return Err(RunError::MissingTrustedClients);
    }

    let runtime = app.default_server_runtime_options(
        root.clone(),
        identity,
        options.sandbox,
        options.allow_overwrite,
        require_client_auth,
        trusted_client_identities,
    );

    let listener = TcpListener::bind((options.listen.as_str(), options.port)).await?;
    let local_addr = listener.local_addr()?;
    println!(
        "{}",
        render_server_listening(
            &local_addr.to_string(),
            &root.as_path().display().to_string(),
            options.sandbox.is_enforced(),
            require_client_auth,
            options.allow_overwrite,
        )
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let server_app = app.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = server_app.serve_connection(stream, &runtime).await {
                eprintln!("{}", render_app_error(&error, Audience::Server));
            }
        });
    }
}

async fn run_export(app: &App, args: &ExportArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Export(args.clone()))?);
    let Command::Export(plan) = command else {
        unreachable!()
    };

    let options = load_client_runtime_options(
        app,
        &args.server_pubkey_file,
        args.client_identity_file.as_ref(),
    )?;
    let result = app.export(plan, options).await?;
    finish_batch("export", result)
}

async fn run_import(app: &App, args: &ImportArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Import(args.clone()))?);
    let Command::Import(plan) = command else {
        unreachable!()
    };

    let options = load_client_runtime_options(
        app,
        &args.server_pubkey_file,
        args.client_identity_file.as_ref(),
    )?;
    let result = app.import(plan, options).await?;
    finish_batch("import", result)
}

async fn run_list(app: &App, args: &ListArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Ls(args.clone()))?);
    let Command::List(plan) = command else {
        unreachable!()
    };

    let options = load_client_runtime_options(
        app,
        &args.server_pubkey_file,
        args.client_identity_file.as_ref(),
    )?;
    let entries = app.list(plan, options).await?;
    for entry in entries {
        println!("{}", render_list_entry(&entry));
    }
    Ok(())
}

fn run_keygen(args: &KeygenArgs) -> Result<(), RunError> {
    let crypto = LatebraCrypto;
    let identity = crypto.generate_signing_identity()?;
    write_file(&args.secret_out, identity.secret_key.as_bytes())?;
    write_file(&args.public_out, identity.public_key.as_bytes())?;
    println!(
        "{}",
        render_keygen_result(
            &args.secret_out.display().to_string(),
            &args.public_out.display().to_string(),
        )
    );
    Ok(())
}

fn load_client_runtime_options(
    app: &App,
    server_pubkey_file: &PathBuf,
    client_identity_file: Option<&PathBuf>,
) -> Result<depot_app::ClientRuntimeOptions, RunError> {
    let expected_server_identity = load_public_key(server_pubkey_file)?;
    let mut options = app.default_client_runtime_options(expected_server_identity);
    options.client_identity = client_identity_file
        .map(load_signing_identity)
        .transpose()?;
    Ok(options)
}

fn load_signing_identity(path: &PathBuf) -> Result<SigningIdentity, RunError> {
    let crypto = LatebraCrypto;
    let secret_bytes = std::fs::read(path)?;
    let secret_key: MlDsa87SecretKey = crypto.parse_signing_secret_key(&secret_bytes)?;
    let public_key = crypto.derive_signing_public_key(&secret_key)?;
    Ok(SigningIdentity {
        public_key,
        secret_key,
    })
}

fn load_public_key(path: &PathBuf) -> Result<MlDsa87PublicKey, RunError> {
    let crypto = LatebraCrypto;
    let bytes = std::fs::read(path)?;
    Ok(crypto.parse_signing_public_key(&bytes)?)
}

fn load_public_keys(paths: &[PathBuf]) -> Result<Vec<MlDsa87PublicKey>, RunError> {
    paths.iter().map(load_public_key).collect()
}

fn write_file(path: &PathBuf, bytes: &[u8]) -> Result<(), RunError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

fn render_app_error(error: &AppError, audience: Audience) -> String {
    match error {
        AppError::Depot(error) => render_error(error, audience),
        _ => error.to_string(),
    }
}

fn finish_batch(operation: &str, report: depot_core::BatchReport) -> Result<(), RunError> {
    let rendered = render_batch_report(operation, &report);
    if report.result.failed > 0 || report.result.fatal_abort {
        return Err(RunError::BatchFailed(rendered.join("\n")));
    }

    for line in rendered {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_export_all_as_current_directory() {
        let cli = Cli::parse_from([
            "depot",
            "export",
            "--all",
            "--server-pubkey-file",
            "server.pub",
        ]);
        let command = Command::try_from(&cli.command).unwrap();
        match command {
            Command::Export(plan) => {
                assert_eq!(plan.sources, vec![PathBuf::from(".")]);
                assert!(!plan.include_top);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_keygen_command() {
        let cli = Cli::parse_from([
            "depot",
            "keygen",
            "--secret-out",
            "server.key",
            "--public-out",
            "server.pub",
        ]);
        match cli.command {
            Commands::Keygen(args) => {
                assert_eq!(args.secret_out, PathBuf::from("server.key"));
                assert_eq!(args.public_out, PathBuf::from("server.pub"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
