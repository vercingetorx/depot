use clap::{Args, Parser, Subcommand};
use depot_app::{App, AppError};
use depot_config::{Config, ConfigError, config_dir, config_path};
use depot_core::{
    BatchReport, Command, Endpoint, ExportPlan, ImportPlan, ListPlan, RemotePath, SandboxPolicy,
    ServeOptions,
};
use depot_crypto::latebra::signature::MlDsa87PublicKey;
use depot_crypto::{CryptoError, HandshakeCryptoProvider, LatebraCrypto, SigningIdentity};
use depot_transport::{ClientTrustProvider, HandshakeError};
use depot_ui::{
    Audience, ClientConsole, render_batch_result, render_error, render_handshake_error,
    render_list_entry, render_outcome, render_server_listening, render_transport_error,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Parser)]
#[command(name = "depot")]
#[command(about = "secure file transfer")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    Serve(ServeArgs),
    Export(ExportArgs),
    Import(ImportArgs),
    Ls(ListArgs),
    Config(ConfigArgs),
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
    pub key_pass: Option<String>,
    #[arg(long)]
    pub key_pass_file: Option<PathBuf>,
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
    #[arg(long = "no-skip", alias = "noskip", default_value_t = false)]
    pub no_skip: bool,
    #[arg(skip = true)]
    pub skip_existing: bool,
    #[arg(long, default_value = "info")]
    pub log: String,
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
    #[arg(long = "no-skip", alias = "noskip", default_value_t = false)]
    pub no_skip: bool,
    #[arg(skip = true)]
    pub skip_existing: bool,
    #[arg(long, default_value = "info")]
    pub log: String,
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
}

#[derive(Debug, Clone, Args)]
pub struct ConfigArgs {
    #[arg(long)]
    pub init: bool,
    #[arg(long)]
    pub force: bool,
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
    MissingServerPassphrase,
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
            Self::MissingServerPassphrase => {
                f.write_str("No server key found; --key-pass or --key-pass-file is required to generate an encrypted key")
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

struct PendingEnrollment {
    token: String,
    expires_at: Instant,
}

struct ClientTrustState {
    trusted: HashSet<Vec<u8>>,
    pending: HashMap<Vec<u8>, PendingEnrollment>,
}

struct ClientTrustStore {
    trust_dir: PathBuf,
    state: Mutex<ClientTrustState>,
}

impl ClientTrustStore {
    const ENROLLMENT_TTL: Duration = Duration::from_secs(5 * 60);

    fn load() -> Result<Arc<Self>, RunError> {
        let trust_dir = config_dir().join("trust").join("clients");
        std::fs::create_dir_all(&trust_dir)?;

        let crypto = LatebraCrypto;
        let mut trusted = HashSet::new();
        let mut entries = std::fs::read_dir(&trust_dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("pk") {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let key = crypto.parse_signing_public_key(&bytes)?;
            trusted.insert(key.as_bytes().to_vec());
        }

        Ok(Arc::new(Self {
            trust_dir,
            state: Mutex::new(ClientTrustState {
                trusted,
                pending: HashMap::new(),
            }),
        }))
    }

    fn cleanup_expired(state: &mut ClientTrustState) {
        let now = Instant::now();
        state.pending.retain(|_, pending| pending.expires_at > now);
    }

    fn fingerprint(public_key: &MlDsa87PublicKey) -> String {
        use depot_crypto::latebra::hash::Blake3;

        let mut hash = Blake3::new();
        hash.update(public_key.as_bytes());
        let digest = hash.finalize();
        let mut fingerprint = String::with_capacity(16);
        for byte in &digest.as_bytes()[..8] {
            use std::fmt::Write;
            let _ = write!(fingerprint, "{byte:02x}");
        }
        fingerprint
    }

    fn new_token() -> Result<String, HandshakeError> {
        let mut bytes = [0u8; 6];
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(HandshakeError::Io)?;
        let mut token = String::with_capacity(14);
        for (index, byte) in bytes.iter().enumerate() {
            use std::fmt::Write;
            if index > 0 && index % 2 == 0 {
                token.push('-');
            }
            let _ = write!(token, "{byte:02X}");
        }
        Ok(token)
    }
}

impl ClientTrustProvider for ClientTrustStore {
    fn is_trusted(&self, public_key: &MlDsa87PublicKey) -> Result<bool, HandshakeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| HandshakeError::BadState("client trust store poisoned"))?;
        Ok(state.trusted.contains(public_key.as_bytes().as_slice()))
    }

    fn begin_enrollment(
        &self,
        public_key: &MlDsa87PublicKey,
        session_label: &str,
    ) -> Result<(), HandshakeError> {
        let fingerprint = Self::fingerprint(public_key);
        let mut state = self
            .state
            .lock()
            .map_err(|_| HandshakeError::BadState("client trust store poisoned"))?;
        Self::cleanup_expired(&mut state);
        let token = match state.pending.get(public_key.as_bytes().as_slice()) {
            Some(pending) => pending.token.clone(),
            None => {
                let token = Self::new_token()?;
                state.pending.insert(
                    public_key.as_bytes().to_vec(),
                    PendingEnrollment {
                        token: token.clone(),
                        expires_at: Instant::now() + Self::ENROLLMENT_TTL,
                    },
                );
                token
            }
        };
        eprintln!(
            "[{}] {}",
            session_label,
            depot_ui::render_status(
                "pairing",
                &format!("approve client {fingerprint} with token {token}"),
            )
        );
        Ok(())
    }

    fn try_enroll(
        &self,
        public_key: &MlDsa87PublicKey,
        token: &str,
        session_label: &str,
    ) -> Result<bool, HandshakeError> {
        let key_bytes = public_key.as_bytes().to_vec();
        let mut state = self
            .state
            .lock()
            .map_err(|_| HandshakeError::BadState("client trust store poisoned"))?;
        Self::cleanup_expired(&mut state);

        let Some(pending) = state.pending.get(&key_bytes) else {
            return Ok(false);
        };
        if pending.token != token {
            return Ok(false);
        }

        let fingerprint = Self::fingerprint(public_key);
        let path = self.trust_dir.join(format!("{fingerprint}.pk"));
        std::fs::write(&path, &key_bytes).map_err(HandshakeError::Io)?;
        state.pending.remove(&key_bytes);
        state.trusted.insert(key_bytes);
        eprintln!(
            "[{}] {}",
            session_label,
            depot_ui::render_status("paired", &format!("trusted client {fingerprint}")),
        );
        Ok(true)
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
                skip_existing: !args.no_skip,
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
                skip_existing: !args.no_skip,
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
            Commands::Config(_) => unreachable!("config is not a depot-core command"),
        }
    }
}

pub async fn run(cli: Cli) -> Result<(), RunError> {
    match &cli.command {
        Commands::Config(args) => run_config(args),
        command => {
            let config = load_config()?;
            let app = App::new(config);
            match command {
                Commands::Serve(args) => run_serve(&app, args).await,
                Commands::Export(args) => run_export(&app, args).await,
                Commands::Import(args) => run_import(&app, args).await,
                Commands::Ls(args) => run_list(&app, args).await,
                Commands::Config(_) => unreachable!(),
            }
        }
    }
}

fn load_config() -> Result<Config, RunError> {
    let path = config_path();
    if path.exists() {
        Ok(Config::from_path(path)?)
    } else {
        Ok(Config::default())
    }
}

fn run_config(args: &ConfigArgs) -> Result<(), RunError> {
    if !args.init {
        return Err(RunError::Io(std::io::Error::other(
            "config subcommand requires --init",
        )));
    }

    let config = Config::default();
    let path = config_path();
    let parent = path.parent().expect("config path has parent");
    std::fs::create_dir_all(parent)?;
    if path.exists() && !args.force {
        println!("Config already exists: {}", path.display());
        println!("Use --force to overwrite.");
        return Ok(());
    }

    let template = format!(
        "# depot configuration\n\n[server]\n# listen = 0.0.0.0\n# port = 60006\nsandbox = true\n\n[client]\n# host = {}\n# port = {}\n# log = info\n",
        config.client.endpoint.host, config.client.endpoint.port
    );
    std::fs::write(&path, template)?;
    println!("Wrote config: {}", path.display());
    Ok(())
}

async fn run_serve(app: &App, args: &ServeArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Serve(args.clone()))?);
    let Command::Serve(options) = command else {
        unreachable!()
    };

    let current_dir = std::env::current_dir()?;
    let root = app.resolved_server_root(options.root.clone(), current_dir);
    let root = app.canonical_server_root(root.as_path())?;
    let passphrase = resolve_server_passphrase(args)?;
    let identity = ensure_server_identity(passphrase.as_deref())?;
    let client_trust = ClientTrustStore::load()?;

    let runtime = app.default_server_runtime_options(
        root.clone(),
        identity,
        options.sandbox,
        options.allow_overwrite,
        client_trust,
    );

    let listener = TcpListener::bind((options.listen.as_str(), options.port)).await?;
    let local_addr = listener.local_addr()?;
    println!(
        "{}",
        render_server_listening(
            &local_addr.to_string(),
            &root.as_path().display().to_string(),
            options.sandbox.is_enforced(),
            options.allow_overwrite,
        )
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let session_id = new_session_id()?;
        eprintln!(
            "[{}] {}",
            session_id,
            depot_ui::render_status("connected", "client connected")
        );
        let server_app = app.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = server_app
                .serve_connection(stream, &runtime, &session_id)
                .await
            {
                eprintln!(
                    "[{}] {}",
                    session_id,
                    render_app_error(&error, Audience::Server)
                );
            }
        });
    }
}

async fn run_export(app: &App, args: &ExportArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Export(args.clone()))?);
    let Command::Export(plan) = command else {
        unreachable!()
    };

    let console = RefCell::new(ClientConsole::new());
    let response = run_client_with_pairing_retry(|token| {
        let options = client_runtime_options(&plan.endpoint, token)?;
        let plan = plan.clone();
        let console = &console;
        Ok(async move {
            app.export_over_io_with_progress(
                tokio::net::TcpStream::connect((plan.endpoint.host.as_str(), plan.endpoint.port))
                    .await
                    .map_err(AppError::from)?,
                plan,
                options,
                |outcome| {
                    let line = render_outcome(outcome);
                    let mut console = console.borrow_mut();
                    match outcome.severity {
                        depot_core::OutcomeSeverity::ItemError
                        | depot_core::OutcomeSeverity::Fatal => {
                            let _ = console.print_error_line(&line);
                        }
                        depot_core::OutcomeSeverity::Success
                        | depot_core::OutcomeSeverity::Skipped => {
                            let _ = console.print_status_line(&line);
                        }
                    }
                },
                |progress| {
                    let _ = console.borrow_mut().draw_progress(progress);
                },
            )
            .await
            .map_err(RunError::from)
        })
    })
    .await;
    match response {
        Ok(response) => finish_batch_with_console("export", response.value, &console),
        Err(error) => {
            let _ = console.borrow_mut().clear_progress();
            Err(error)
        }
    }
}

async fn run_import(app: &App, args: &ImportArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Import(args.clone()))?);
    let Command::Import(plan) = command else {
        unreachable!()
    };

    let console = RefCell::new(ClientConsole::new());
    let response = run_client_with_pairing_retry(|token| {
        let options = client_runtime_options(&plan.endpoint, token)?;
        let plan = plan.clone();
        let console = &console;
        Ok(async move {
            app.import_over_io_with_progress(
                tokio::net::TcpStream::connect((plan.endpoint.host.as_str(), plan.endpoint.port))
                    .await
                    .map_err(AppError::from)?,
                plan,
                options,
                |outcome| {
                    let line = render_outcome(outcome);
                    let mut console = console.borrow_mut();
                    match outcome.severity {
                        depot_core::OutcomeSeverity::ItemError
                        | depot_core::OutcomeSeverity::Fatal => {
                            let _ = console.print_error_line(&line);
                        }
                        depot_core::OutcomeSeverity::Success
                        | depot_core::OutcomeSeverity::Skipped => {
                            let _ = console.print_status_line(&line);
                        }
                    }
                },
                |progress| {
                    let _ = console.borrow_mut().draw_progress(progress);
                },
            )
            .await
            .map_err(RunError::from)
        })
    })
    .await;
    match response {
        Ok(response) => finish_batch_with_console("import", response.value, &console),
        Err(error) => {
            let _ = console.borrow_mut().clear_progress();
            Err(error)
        }
    }
}

async fn run_list(app: &App, args: &ListArgs) -> Result<(), RunError> {
    let command = app.apply_client_defaults(Command::try_from(&Commands::Ls(args.clone()))?);
    let Command::List(plan) = command else {
        unreachable!()
    };

    let mut console = ClientConsole::new();
    let response = run_client_with_pairing_retry(|token| {
        let options = client_runtime_options(&plan.endpoint, token)?;
        let plan = plan.clone();
        Ok(async move { app.list(plan, options).await.map_err(RunError::from) })
    })
    .await?;
    for entry in response.value {
        console.print_plain_line(&render_list_entry(&entry))?;
    }
    Ok(())
}

fn client_runtime_options(
    endpoint: &Endpoint,
    enrollment_token: Option<String>,
) -> Result<depot_app::ClientRuntimeOptions, RunError> {
    let config = load_config()?;
    let app = App::new(config);
    let remote_id = remote_id(endpoint);
    let pinned = load_pinned_server_identity(&remote_id)?;
    Ok(app.default_client_runtime_options(
        pinned,
        ensure_client_identity()?,
        Some(pin_path(&remote_id)?),
        enrollment_token,
    ))
}

fn resolve_server_passphrase(args: &ServeArgs) -> Result<Option<String>, RunError> {
    if let Some(pass) = &args.key_pass {
        return Ok(Some(pass.clone()));
    }
    if let Some(path) = &args.key_pass_file {
        return Ok(Some(std::fs::read_to_string(path)?.trim().to_owned()));
    }
    Ok(None)
}

fn ensure_server_identity(passphrase: Option<&str>) -> Result<SigningIdentity, RunError> {
    let crypto = LatebraCrypto;
    let id_dir = config_dir().join("id");
    std::fs::create_dir_all(&id_dir)?;
    let public_path = id_dir.join("server_dilithium.pk");
    let secret_path = id_dir.join("server_dilithium.sk");

    if public_path.exists() && secret_path.exists() {
        let public_bytes = std::fs::read(&public_path)?;
        let public_key = crypto.parse_signing_public_key(&public_bytes)?;
        let secret_bytes = std::fs::read(&secret_path)?;
        let passphrase = passphrase.ok_or(RunError::Io(std::io::Error::other(
            "Encrypted server key requires --key-pass or --key-pass-file on server",
        )))?;
        let decrypted = crypto.decrypt_secret(&secret_bytes, passphrase.as_bytes())?;
        let secret_key = crypto.parse_signing_secret_key(&decrypted)?;
        return Ok(SigningIdentity {
            public_key,
            secret_key,
        });
    }

    let passphrase = passphrase.ok_or(RunError::MissingServerPassphrase)?;
    let identity = crypto.generate_signing_identity()?;
    std::fs::write(&public_path, identity.public_key.as_bytes())?;
    let encrypted = crypto.encrypt_secret(identity.secret_key.as_bytes(), passphrase.as_bytes())?;
    std::fs::write(&secret_path, encrypted.as_bytes())?;
    Ok(identity)
}

fn ensure_client_identity() -> Result<SigningIdentity, RunError> {
    let crypto = LatebraCrypto;
    let id_dir = config_dir().join("id");
    std::fs::create_dir_all(&id_dir)?;
    let public_path = id_dir.join("client_dilithium.pk");
    let secret_path = id_dir.join("client_dilithium.sk");

    if public_path.exists() && secret_path.exists() {
        let public_bytes = std::fs::read(&public_path)?;
        let secret_bytes = std::fs::read(&secret_path)?;
        return Ok(SigningIdentity {
            public_key: crypto.parse_signing_public_key(&public_bytes)?,
            secret_key: crypto.parse_signing_secret_key(&secret_bytes)?,
        });
    }

    let identity = crypto.generate_signing_identity()?;
    std::fs::write(&public_path, identity.public_key.as_bytes())?;
    std::fs::write(&secret_path, identity.secret_key.as_bytes())?;
    Ok(identity)
}

fn remote_id(endpoint: &Endpoint) -> String {
    format!("{}:{}", endpoint.host, endpoint.port)
}

fn load_pinned_server_identity(remote_id: &str) -> Result<Option<MlDsa87PublicKey>, RunError> {
    let path = pin_path(remote_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let crypto = LatebraCrypto;
    let bytes = std::fs::read(path)?;
    Ok(Some(crypto.parse_signing_public_key(&bytes)?))
}

fn pin_path(remote_id: &str) -> Result<PathBuf, RunError> {
    let trust_dir = config_dir().join("trust");
    std::fs::create_dir_all(&trust_dir)?;
    Ok(trust_dir.join(format!("{remote_id}.pk")))
}

fn new_session_id() -> Result<String, RunError> {
    let mut bytes = [0u8; 8];
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut session_id = String::with_capacity(16);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(session_id, "{byte:02x}");
    }
    Ok(session_id)
}

fn render_app_error(error: &AppError, audience: Audience) -> String {
    match error {
        AppError::Depot(error) => render_error(error, audience),
        AppError::Handshake(error) => render_handshake_error(error, audience),
        AppError::Transport(error) => render_transport_error(error, audience),
        _ => error.to_string(),
    }
}

fn finish_batch_with_console(
    operation: &str,
    report: BatchReport,
    console: &RefCell<ClientConsole>,
) -> Result<(), RunError> {
    let summary = render_batch_result(operation, &report.result);
    console.borrow_mut().print_status_line(&summary)?;
    if report.result.failed > 0 || report.result.fatal_abort {
        return Err(RunError::BatchFailed(summary));
    }
    Ok(())
}

async fn run_client_with_pairing_retry<T, F, Fut>(mut operation: F) -> Result<T, RunError>
where
    F: FnMut(Option<String>) -> Result<Fut, RunError>,
    Fut: Future<Output = Result<T, RunError>>,
{
    let mut enrollment_token = None;
    loop {
        match operation(enrollment_token.clone())?.await {
            Ok(value) => return Ok(value),
            Err(RunError::App(AppError::Handshake(HandshakeError::EnrollmentRequired))) => {
                enrollment_token = Some(prompt_for_enrollment_token()?);
            }
            Err(error) => return Err(error),
        }
    }
}

fn prompt_for_enrollment_token() -> Result<String, RunError> {
    eprint!("Pairing required. Enter one-time server token: ");
    io::stderr().flush()?;
    let mut token = String::new();
    io::stdin().read_line(&mut token)?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(RunError::Io(std::io::Error::other(
            "pairing token is required",
        )));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_export_all_as_current_directory() {
        let cli = Cli::parse_from(["depot", "export", "--all"]);
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
    fn parses_serve_key_pass() {
        let cli = Cli::parse_from(["depot", "serve", "--key-pass", "secret"]);
        match cli.command {
            Commands::Serve(args) => assert_eq!(args.key_pass.as_deref(), Some("secret")),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_export_no_skip_aliases() {
        let cli = Cli::parse_from(["depot", "export", "--no-skip", "file.txt"]);
        let command = Command::try_from(&cli.command).unwrap();
        match command {
            Command::Export(plan) => assert!(!plan.skip_existing),
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::parse_from(["depot", "export", "--noskip", "file.txt"]);
        let command = Command::try_from(&cli.command).unwrap();
        match command {
            Command::Export(plan) => assert!(!plan.skip_existing),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_import_no_skip_aliases() {
        let cli = Cli::parse_from(["depot", "import", "--no-skip", "file.txt"]);
        let command = Command::try_from(&cli.command).unwrap();
        match command {
            Command::Import(plan) => assert!(!plan.skip_existing),
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::parse_from(["depot", "import", "--noskip", "file.txt"]);
        let command = Command::try_from(&cli.command).unwrap();
        match command {
            Command::Import(plan) => assert!(!plan.skip_existing),
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
