use crate::config::{Config, ConfigError};
use crate::core::{
    BatchReport, Command, DepotError, Endpoint, ErrorCode, ExportPlan, ImportPlan, ListPlan,
    Operation, Outcome, OutcomeSeverity, PortablePermission, PortablePermissions, RemotePath,
    SandboxPolicy, ServeOptions, ServerRoot, TransferProgress, TransferProgressAction,
    classify_outcome_severity,
};
use crate::crypto::{Blake3, CryptoError, DepotCrypto, MlDsa87PublicKey, SigningIdentity};
use crate::fs::{ensure_server_root, resolve_remote_path};
use crate::protocol::{
    FileMetadata, ListEntry, PathOpenPayload, RecordType, UploadOpenPayload, decode_error_payload,
    decode_list_chunk, decode_path_open, decode_path_param, decode_upload_open,
    encode_error_payload, encode_list_chunk, encode_path_open, encode_path_param,
    encode_upload_open,
};
use crate::transport::{
    ClientHandshakeOptions, ClientTrustProvider, HandshakeError, SecureChannel,
    ServerHandshakeOptions, TransportConfig, TransportError,
    client_handshake_with_identity_handler, server_handshake,
};
use filetime::{FileTime, set_file_mtime};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::{self, File};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIST_CHUNK_LIMIT: usize = 64 * 1024;
const FILE_CHUNK_SIZE: usize = 1024 * 1024;
const DIGEST_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct App {
    config: Config,
}

#[derive(Clone)]
pub struct ServerRuntimeOptions {
    pub root: ServerRoot,
    pub identity: SigningIdentity,
    pub sandbox: SandboxPolicy,
    pub allow_overwrite: bool,
    pub client_trust: Arc<dyn ClientTrustProvider>,
}

#[derive(Clone)]
pub struct ClientRuntimeOptions {
    pub expected_server_identity: Option<MlDsa87PublicKey>,
    pub client_identity: SigningIdentity,
    pub tofu_pin_path: Option<PathBuf>,
    pub enrollment_token: Option<String>,
}

#[derive(Clone)]
pub struct ClientResponse<T> {
    pub value: T,
    pub server_identity: MlDsa87PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportJob {
    local_path: PathBuf,
    remote_path: RemotePath,
}

struct UploadState {
    destination_path: PathBuf,
    partial_path: PathBuf,
    file: File,
    hasher: Blake3,
    modification_time_unix: u64,
    permissions: PortablePermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DownloadItem {
    relative_path: RemotePath,
    resolved_path: PathBuf,
    metadata: FileMetadata,
}

struct DownloadState {
    destination_path: PathBuf,
    partial_path: PathBuf,
    file: File,
    hasher: Blake3,
    expected_size: u64,
    received_size: u64,
    modification_time_unix: u64,
    permissions: PortablePermissions,
}

#[derive(Debug)]
pub enum AppError {
    Config(ConfigError),
    Io(std::io::Error),
    Crypto(CryptoError),
    Handshake(HandshakeError),
    Transport(TransportError),
    Depot(DepotError),
    Codec(crate::protocol::CodecError),
    InvalidUtf8Path(PathBuf),
    InvalidLocalSource(PathBuf),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Handshake(error) => write!(f, "{error}"),
            Self::Transport(error) => write!(f, "{error}"),
            Self::Depot(error) => write!(f, "{error}"),
            Self::Codec(error) => write!(f, "{error}"),
            Self::InvalidUtf8Path(path) => write!(f, "path is not valid utf-8: {}", path.display()),
            Self::InvalidLocalSource(path) => write!(f, "invalid local source: {}", path.display()),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ConfigError> for AppError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<CryptoError> for AppError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<HandshakeError> for AppError {
    fn from(value: HandshakeError) -> Self {
        Self::Handshake(value)
    }
}

impl From<TransportError> for AppError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<DepotError> for AppError {
    fn from(value: DepotError) -> Self {
        Self::Depot(value)
    }
}

impl From<crate::protocol::CodecError> for AppError {
    fn from(value: crate::protocol::CodecError) -> Self {
        Self::Codec(value)
    }
}

impl App {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn resolved_server_root(
        &self,
        root_override: Option<PathBuf>,
        current_dir: PathBuf,
    ) -> ServerRoot {
        ServerRoot::new(root_override.unwrap_or(current_dir))
    }

    pub fn apply_client_defaults(&self, command: Command) -> Result<Command, AppError> {
        Ok(match command {
            Command::Serve(options) => Command::Serve(self.apply_serve_defaults(options)),
            Command::Export(plan) => Command::Export(self.apply_export_defaults(plan)?),
            Command::Import(plan) => Command::Import(self.apply_import_defaults(plan)?),
            Command::List(plan) => Command::List(self.apply_list_defaults(plan)?),
        })
    }

    pub fn canonical_server_root(&self, path: impl AsRef<Path>) -> Result<ServerRoot, AppError> {
        Ok(ensure_server_root(path)?)
    }

    pub fn default_server_runtime_options(
        &self,
        root: ServerRoot,
        identity: SigningIdentity,
        sandbox: SandboxPolicy,
        allow_overwrite: bool,
        client_trust: Arc<dyn ClientTrustProvider>,
    ) -> ServerRuntimeOptions {
        ServerRuntimeOptions {
            root,
            identity,
            sandbox,
            allow_overwrite,
            client_trust,
        }
    }

    pub fn default_client_runtime_options(
        &self,
        expected_server_identity: Option<MlDsa87PublicKey>,
        client_identity: SigningIdentity,
        tofu_pin_path: Option<PathBuf>,
        enrollment_token: Option<String>,
    ) -> ClientRuntimeOptions {
        ClientRuntimeOptions {
            expected_server_identity,
            client_identity,
            tofu_pin_path,
            enrollment_token,
        }
    }

    pub async fn list(
        &self,
        plan: ListPlan,
        options: ClientRuntimeOptions,
    ) -> Result<ClientResponse<Vec<ListEntry>>, AppError> {
        let endpoint = self.defaulted_endpoint(plan.endpoint)?;
        let stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
        let path = plan.path.unwrap_or_else(|| RemotePath::new("."));
        self.list_over_io(stream, path, options).await
    }

    pub async fn list_over_io<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
        remote_path: RemotePath,
        options: ClientRuntimeOptions,
    ) -> Result<ClientResponse<Vec<ListEntry>>, AppError> {
        let (mut channel, server_identity): (SecureChannel<IO, DepotCrypto>, MlDsa87PublicKey) =
            self.establish_client_channel(io, options).await?;
        channel
            .send_record(RecordType::ListOpen, &encode_path_param(&remote_path))
            .await?;

        let mut entries = Vec::new();
        loop {
            let frame = self.recv_client_record(&mut channel).await?;
            match frame.record_type {
                RecordType::ListChunk => entries.extend(decode_list_chunk(&frame.payload)?),
                RecordType::ListDone => break,
                RecordType::ErrorRec => {
                    let code = decode_error_payload(&frame.payload)?;
                    return Err(AppError::Depot(DepotError::new(code, remote_path.as_str())));
                }
                _ => {
                    return Err(AppError::Depot(DepotError::new(
                        ErrorCode::Protocol,
                        format!("unexpected record type {:?}", frame.record_type),
                    )));
                }
            }
        }

        Ok(ClientResponse {
            value: entries,
            server_identity,
        })
    }

    pub async fn export(
        &self,
        plan: ExportPlan,
        options: ClientRuntimeOptions,
    ) -> Result<ClientResponse<BatchReport>, AppError> {
        let endpoint = self.defaulted_endpoint(plan.endpoint.clone())?;
        let stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
        self.export_over_io_with_progress(stream, plan, options, |_| {}, |_| {})
            .await
    }

    pub async fn export_over_io<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
        plan: ExportPlan,
        options: ClientRuntimeOptions,
    ) -> Result<ClientResponse<BatchReport>, AppError> {
        self.export_over_io_with_progress(io, plan, options, |_| {}, |_| {})
            .await
    }

    pub async fn export_over_io_with_progress<IO, OF, PF>(
        &self,
        io: IO,
        plan: ExportPlan,
        options: ClientRuntimeOptions,
        mut on_outcome: OF,
        mut on_progress: PF,
    ) -> Result<ClientResponse<BatchReport>, AppError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        OF: FnMut(&Outcome),
        PF: FnMut(&TransferProgress),
    {
        let (mut channel, server_identity) = self.establish_client_channel(io, options).await?;
        let jobs = self.collect_export_jobs(&plan)?;
        let mut report = BatchReport::default();

        for job in jobs {
            match self.upload_job(&mut channel, &job, &mut on_progress).await {
                Ok(sent_bytes) => {
                    report.result.sent_files += 1;
                    report.result.sent_bytes += sent_bytes;
                    push_outcome(
                        &mut report,
                        Outcome {
                            operation: Operation::Export,
                            severity: OutcomeSeverity::Success,
                            code: None,
                            path: Some(format!(
                                "{} ({})",
                                job.local_path.display(),
                                format_bytes(sent_bytes)
                            )),
                        },
                        &mut on_outcome,
                    );
                }
                Err(AppError::Depot(error))
                    if error.code == ErrorCode::Exists && plan.skip_existing =>
                {
                    report.result.skipped += 1;
                    push_outcome(
                        &mut report,
                        Outcome {
                            operation: Operation::Export,
                            severity: OutcomeSeverity::Skipped,
                            code: Some(error.code),
                            path: Some(format!("existing {}", job.local_path.display())),
                        },
                        &mut on_outcome,
                    );
                }
                Err(AppError::Depot(error)) if !error.code.is_session_fatal() => {
                    report.result.failed += 1;
                    push_outcome(
                        &mut report,
                        item_outcome(
                            Operation::Export,
                            OutcomeSeverity::ItemError,
                            error.code,
                            Some(job.remote_path.as_str().to_owned()),
                        ),
                        &mut on_outcome,
                    );
                }
                Err(AppError::Depot(error)) => {
                    report.result.fatal_abort = true;
                    push_outcome(
                        &mut report,
                        item_outcome(
                            Operation::Export,
                            classify_outcome_severity(error.code),
                            error.code,
                            Some(job.remote_path.as_str().to_owned()),
                        ),
                        &mut on_outcome,
                    );
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        Ok(ClientResponse {
            value: report,
            server_identity,
        })
    }

    pub async fn import(
        &self,
        plan: ImportPlan,
        options: ClientRuntimeOptions,
    ) -> Result<ClientResponse<BatchReport>, AppError> {
        let endpoint = self.defaulted_endpoint(plan.endpoint.clone())?;
        let stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
        self.import_over_io_with_progress(stream, plan, options, |_| {}, |_| {})
            .await
    }

    pub async fn import_over_io<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
        plan: ImportPlan,
        options: ClientRuntimeOptions,
    ) -> Result<ClientResponse<BatchReport>, AppError> {
        self.import_over_io_with_progress(io, plan, options, |_| {}, |_| {})
            .await
    }

    pub async fn import_over_io_with_progress<IO, OF, PF>(
        &self,
        io: IO,
        plan: ImportPlan,
        options: ClientRuntimeOptions,
        mut on_outcome: OF,
        mut on_progress: PF,
    ) -> Result<ClientResponse<BatchReport>, AppError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        OF: FnMut(&Outcome),
        PF: FnMut(&TransferProgress),
    {
        let (mut channel, server_identity) = self.establish_client_channel(io, options).await?;
        let destination_root = plan
            .destination
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let mut report = BatchReport::default();

        for source in &plan.sources {
            match self
                .download_source(
                    &mut channel,
                    source,
                    &destination_root,
                    plan.include_top,
                    plan.skip_existing,
                    &mut report,
                    &mut on_outcome,
                    &mut on_progress,
                )
                .await
            {
                Ok(()) => {}
                Err(AppError::Depot(error)) if !error.code.is_session_fatal() => {
                    report.result.failed += 1;
                    push_outcome(
                        &mut report,
                        item_outcome(
                            Operation::Import,
                            OutcomeSeverity::ItemError,
                            error.code,
                            Some(source.as_str().to_owned()),
                        ),
                        &mut on_outcome,
                    );
                }
                Err(AppError::Depot(error)) => {
                    report.result.fatal_abort = true;
                    push_outcome(
                        &mut report,
                        item_outcome(
                            Operation::Import,
                            classify_outcome_severity(error.code),
                            error.code,
                            Some(source.as_str().to_owned()),
                        ),
                        &mut on_outcome,
                    );
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        Ok(ClientResponse {
            value: report,
            server_identity,
        })
    }

    pub async fn serve_once(
        &self,
        listener: &TcpListener,
        options: &ServerRuntimeOptions,
    ) -> Result<(), AppError> {
        let (stream, _) = listener.accept().await?;
        self.serve_connection(stream, options, "test-session").await
    }

    pub async fn serve_connection<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
        options: &ServerRuntimeOptions,
        session_id: &str,
    ) -> Result<(), AppError> {
        let handshake = server_handshake(
            io,
            DepotCrypto,
            ServerHandshakeOptions {
                server_identity: options.identity.clone(),
                client_trust: options.client_trust.clone(),
                session_label: session_id.to_owned(),
                sandbox: options.sandbox,
            },
            TransportConfig::default(),
        )
        .await?;

        log_server_status(session_id, "handshake", "handshake complete");
        let result = self
            .run_server_loop(handshake.channel, options, session_id)
            .await;
        match &result {
            Ok(()) => log_server_status(session_id, "disconnected", "client disconnected"),
            Err(AppError::Transport(TransportError::Timeout)) => {
                log_server_error(
                    session_id,
                    "[timeout] timeout: session timeout; closing connection",
                );
                log_server_status(session_id, "disconnected", "client disconnected");
            }
            Err(error) => {
                log_server_error(session_id, &error.to_string());
                log_server_status(session_id, "disconnected", "client disconnected");
            }
        }
        result
    }

    async fn establish_client_channel<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
        options: ClientRuntimeOptions,
    ) -> Result<
        (
            SecureChannel<IO, DepotCrypto>,
            MlDsa87PublicKey,
        ),
        AppError,
    > {
        let pin_path = options.tofu_pin_path.clone();
        let handshake = client_handshake_with_identity_handler(
            io,
            DepotCrypto,
            ClientHandshakeOptions {
                expected_server_identity: options.expected_server_identity,
                client_identity: options.client_identity,
                enrollment_token: options.enrollment_token,
            },
            TransportConfig::default(),
            move |server_identity: &MlDsa87PublicKey| {
                if let Some(pin_path) = &pin_path {
                    if !pin_path.exists() {
                        if let Some(parent) = pin_path.parent() {
                            std::fs::create_dir_all(parent).map_err(HandshakeError::Io)?;
                        }
                        std::fs::write(pin_path, server_identity.as_ref())
                            .map_err(HandshakeError::Io)?;
                    }
                }
                Ok(())
            },
        )
        .await?;
        Ok((handshake.channel, handshake.summary.server_identity))
    }

    async fn run_server_loop<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut channel: SecureChannel<IO, DepotCrypto>,
        options: &ServerRuntimeOptions,
        session_id: &str,
    ) -> Result<(), AppError> {
        let mut upload_state: Option<UploadState> = None;

        loop {
            let frame = match channel.recv_record().await {
                Ok(frame) => frame,
                Err(TransportError::ConnectionClosed) => break,
                Err(TransportError::Timeout) => {
                    return Err(AppError::Transport(TransportError::Timeout));
                }
                Err(error) => return Err(error.into()),
            };

            match frame.record_type {
                RecordType::ListOpen => {
                    if upload_state.is_some() {
                        return self
                            .send_protocol_error(&mut channel, "list during upload")
                            .await;
                    }
                    match self
                        .handle_list_request(&mut channel, &frame.payload, options, session_id)
                        .await
                    {
                        Ok(()) => {}
                        Err(AppError::Depot(error)) => {
                            channel
                                .send_record(
                                    RecordType::ErrorRec,
                                    &encode_error_payload(error.code),
                                )
                                .await?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                RecordType::UploadOpen => {
                    if upload_state.is_some() {
                        return self
                            .send_protocol_error(&mut channel, "nested upload open")
                            .await;
                    }
                    let next_state = self
                        .handle_upload_open(&mut channel, &frame.payload, options, session_id)
                        .await?;
                    upload_state = next_state;
                }
                RecordType::FileData => {
                    let state = upload_state.as_mut().ok_or_else(|| {
                        AppError::Depot(DepotError::new(
                            ErrorCode::Protocol,
                            "file data without open upload",
                        ))
                    })?;
                    self.handle_upload_data(state, &frame.payload).await?;
                }
                RecordType::FileClose => {
                    let state = upload_state.take().ok_or_else(|| {
                        AppError::Depot(DepotError::new(
                            ErrorCode::Protocol,
                            "file close without open upload",
                        ))
                    })?;
                    self.handle_upload_commit(
                        &mut channel,
                        state,
                        &frame.payload,
                        options,
                        session_id,
                    )
                    .await?;
                }
                RecordType::DownloadOpen => {
                    if upload_state.is_some() {
                        return self
                            .send_protocol_error(&mut channel, "download during upload")
                            .await;
                    }
                    match self
                        .handle_download_request(&mut channel, &frame.payload, options, session_id)
                        .await
                    {
                        Ok(()) => {}
                        Err(AppError::Depot(error)) => {
                            channel
                                .send_record(
                                    RecordType::ErrorRec,
                                    &encode_error_payload(error.code),
                                )
                                .await?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                _ => {
                    return self
                        .send_protocol_error(
                            &mut channel,
                            &format!("unexpected record type {:?}", frame.record_type),
                        )
                        .await;
                }
            }
        }

        if let Some(mut state) = upload_state.take() {
            let _ = state.file.flush().await;
            drop(state.file);
            let _ = fs::remove_file(&state.partial_path).await;
        }
        Ok(())
    }

    async fn handle_list_request<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        payload: &[u8],
        options: &ServerRuntimeOptions,
        session_id: &str,
    ) -> Result<(), AppError> {
        let (requested, next_offset) = decode_path_param(payload, 0)?;
        if next_offset != payload.len() {
            return Err(AppError::Depot(DepotError::code_only(
                ErrorCode::BadPayload,
            )));
        }
        if requested.is_empty() {
            return Err(AppError::Depot(DepotError::code_only(ErrorCode::BadPath)));
        }

        let resolved = resolve_remote_path(&options.root, &requested, options.sandbox)?;
        let metadata = std::fs::metadata(&resolved.resolved).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::Depot(DepotError::new(ErrorCode::NotFound, requested.as_str()))
            } else {
                AppError::Depot(DepotError::new(
                    ErrorCode::OpenFail,
                    format!("{}: {error}", requested.as_str()),
                ))
            }
        })?;

        if metadata.is_file() {
            let relative_path =
                single_file_list_path(&options.root, &resolved.resolved, &requested)?;
            channel
                .send_record(
                    RecordType::ListChunk,
                    &encode_list_chunk(&[ListEntry {
                        relative_path,
                        file_size: metadata.len(),
                        is_dir: false,
                    }]),
                )
                .await?;
            channel.send_record(RecordType::ListDone, &[]).await?;
            log_server_status(session_id, "list-file", &format!("{}", requested.as_str()));
            return Ok(());
        }

        if !metadata.is_dir() {
            return Err(AppError::Depot(DepotError::new(
                ErrorCode::BadPath,
                requested.as_str(),
            )));
        }

        let mut chunk = Vec::new();
        for entry in std::fs::read_dir(&resolved.resolved)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let name = entry.file_name();
            let name = name
                .into_string()
                .map_err(|_| AppError::InvalidUtf8Path(entry.path()))?;
            let list_entry = ListEntry {
                relative_path: RemotePath::new(name),
                file_size: if file_type.is_dir() {
                    0
                } else {
                    entry.metadata()?.len()
                },
                is_dir: file_type.is_dir(),
            };
            let encoded = crate::protocol::encode_list_item(&list_entry);
            if !chunk.is_empty() && chunk.len() + encoded.len() > LIST_CHUNK_LIMIT {
                channel.send_record(RecordType::ListChunk, &chunk).await?;
                chunk.clear();
            }
            chunk.extend_from_slice(&encoded);
        }

        if !chunk.is_empty() {
            channel.send_record(RecordType::ListChunk, &chunk).await?;
        }
        channel.send_record(RecordType::ListDone, &[]).await?;
        log_server_status(
            session_id,
            "list-complete",
            &format!(
                "{} ({} entries)",
                requested.as_str(),
                std::fs::read_dir(&resolved.resolved)?.count()
            ),
        );
        Ok(())
    }

    async fn handle_upload_open<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        payload: &[u8],
        options: &ServerRuntimeOptions,
        session_id: &str,
    ) -> Result<Option<UploadState>, AppError> {
        let upload = decode_upload_open(payload)?;
        if upload.relative_path.is_empty() {
            channel
                .send_record(
                    RecordType::UploadFail,
                    &encode_error_payload(ErrorCode::BadPath),
                )
                .await?;
            return Ok(None);
        }

        let resolved =
            match resolve_remote_path(&options.root, &upload.relative_path, options.sandbox) {
                Ok(resolved) => resolved,
                Err(error) => {
                    channel
                        .send_record(RecordType::UploadFail, &encode_error_payload(error.code))
                        .await?;
                    return Ok(None);
                }
            };

        if fs::metadata(&resolved.resolved).await.is_ok() && !options.allow_overwrite {
            channel
                .send_record(
                    RecordType::UploadFail,
                    &encode_error_payload(ErrorCode::Exists),
                )
                .await?;
            return Ok(None);
        }

        let parent = resolved
            .resolved
            .parent()
            .ok_or_else(|| AppError::Depot(DepotError::code_only(ErrorCode::BadPath)))?;
        fs::create_dir_all(parent).await?;

        let partial_path = part_path(&resolved.resolved);
        let file = File::create(&partial_path).await?;
        let hasher = Blake3::new();

        log_server_status(
            session_id,
            "upload-start",
            &format!("upload start: {}", upload.relative_path.as_str()),
        );
        channel.propose_rekey_and_await().await?;
        channel.send_record(RecordType::UploadOk, &[]).await?;
        Ok(Some(UploadState {
            destination_path: resolved.resolved,
            partial_path,
            file,
            hasher,
            modification_time_unix: upload.modification_time_unix,
            permissions: upload.permissions,
        }))
    }

    async fn handle_upload_data(
        &self,
        state: &mut UploadState,
        payload: &[u8],
    ) -> Result<(), AppError> {
        if !payload.is_empty() {
            state.file.write_all(payload).await?;
            state.hasher.update(payload);
        }
        Ok(())
    }

    async fn handle_upload_commit<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        mut state: UploadState,
        payload: &[u8],
        options: &ServerRuntimeOptions,
        session_id: &str,
    ) -> Result<(), AppError> {
        state.file.flush().await?;
        drop(state.file);

        if payload.len() != DIGEST_LEN {
            let _ = fs::remove_file(&state.partial_path).await;
            channel
                .send_record(
                    RecordType::ErrorRec,
                    &encode_error_payload(ErrorCode::Checksum),
                )
                .await?;
            return Ok(());
        }

        let digest = state.hasher.finalize();
        if digest.as_bytes() != payload {
            let _ = fs::remove_file(&state.partial_path).await;
            channel
                .send_record(
                    RecordType::ErrorRec,
                    &encode_error_payload(ErrorCode::Checksum),
                )
                .await?;
            return Ok(());
        }

        if fs::metadata(&state.destination_path).await.is_ok() {
            if options.allow_overwrite {
                let _ = fs::remove_file(&state.destination_path).await;
            } else {
                let _ = fs::remove_file(&state.partial_path).await;
                channel
                    .send_record(
                        RecordType::ErrorRec,
                        &encode_error_payload(ErrorCode::Exists),
                    )
                    .await?;
                return Ok(());
            }
        }

        fs::rename(&state.partial_path, &state.destination_path).await?;
        apply_uploaded_metadata(
            &state.destination_path,
            state.modification_time_unix,
            state.permissions,
        )?;
        log_server_status(
            session_id,
            "upload-complete",
            &state.destination_path.display().to_string(),
        );
        channel.propose_rekey_and_await().await?;
        channel.send_record(RecordType::UploadDone, &[]).await?;
        Ok(())
    }

    async fn upload_job<IO, PF>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        job: &ExportJob,
        on_progress: &mut PF,
    ) -> Result<u64, AppError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        PF: FnMut(&TransferProgress),
    {
        let start = Instant::now();
        let metadata = fs::metadata(&job.local_path).await?;
        if !metadata.is_file() {
            return Err(AppError::InvalidLocalSource(job.local_path.clone()));
        }

        let modification_time_unix = unix_mtime(&metadata)?;
        let permissions = permissions_from_std(metadata.permissions());
        let open_payload = encode_upload_open(&UploadOpenPayload {
            relative_path: job.remote_path.clone(),
            modification_time_unix,
            permissions,
        });
        channel
            .send_record(RecordType::UploadOpen, &open_payload)
            .await?;

        let open_reply = self.recv_client_record(channel).await?;
        match open_reply.record_type {
            RecordType::UploadOk => {}
            RecordType::UploadFail => {
                let code = decode_error_payload(&open_reply.payload)?;
                return Err(AppError::Depot(DepotError::new(
                    code,
                    job.remote_path.as_str(),
                )));
            }
            _ => {
                return Err(AppError::Depot(DepotError::new(
                    ErrorCode::Protocol,
                    format!("unexpected record type {:?}", open_reply.record_type),
                )));
            }
        }

        let mut file = File::open(&job.local_path).await?;
        let mut buffer = vec![0u8; FILE_CHUNK_SIZE];
        let mut sent_bytes = 0u64;
        let mut hasher = Blake3::new();

        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            hasher.update(chunk);
            channel.send_record(RecordType::FileData, chunk).await?;
            sent_bytes += read as u64;
            on_progress(&TransferProgress {
                action: TransferProgressAction::Uploading,
                name: file_name_display(&job.local_path),
                done_bytes: sent_bytes,
                total_bytes: Some(metadata.len()),
                elapsed: start.elapsed(),
            });
        }

        channel
            .send_record(RecordType::FileClose, hasher.finalize().as_bytes())
            .await?;

        let commit_reply = self.recv_client_record(channel).await?;
        match commit_reply.record_type {
            RecordType::UploadDone => Ok(sent_bytes),
            RecordType::ErrorRec => {
                let code = decode_error_payload(&commit_reply.payload)?;
                Err(AppError::Depot(DepotError::new(
                    code,
                    job.remote_path.as_str(),
                )))
            }
            _ => Err(AppError::Depot(DepotError::new(
                ErrorCode::Protocol,
                format!("unexpected record type {:?}", commit_reply.record_type),
            ))),
        }
    }

    async fn download_source<IO, OF, PF>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        source: &RemotePath,
        destination_root: &Path,
        include_top: bool,
        skip_existing: bool,
        report: &mut BatchReport,
        on_outcome: &mut OF,
        on_progress: &mut PF,
    ) -> Result<(), AppError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        OF: FnMut(&Outcome),
        PF: FnMut(&TransferProgress),
    {
        channel
            .send_record(RecordType::DownloadOpen, &encode_path_param(source))
            .await?;
        let mut pending_exists: Option<String> = None;

        loop {
            let frame = self.recv_client_record(channel).await?;
            match frame.record_type {
                RecordType::PathOpen => {
                    let path_open = decode_path_open(&frame.payload)?;
                    match self.prepare_download_state(
                        source,
                        destination_root,
                        include_top,
                        skip_existing,
                        &path_open,
                    )? {
                        DownloadAction::Skip => {
                            channel
                                .send_record(
                                    RecordType::PathSkip,
                                    &encode_error_payload(ErrorCode::Exists),
                                )
                                .await?;
                            report.result.skipped += 1;
                            push_outcome(
                                report,
                                Outcome {
                                    operation: Operation::Import,
                                    severity: OutcomeSeverity::Skipped,
                                    code: Some(ErrorCode::Exists),
                                    path: Some(format!(
                                        "path exists {} ({})",
                                        local_destination_for_download(
                                            source,
                                            destination_root,
                                            include_top,
                                            &path_open.relative_path,
                                        )
                                        .display(),
                                        format_bytes(path_open.metadata.file_size)
                                    )),
                                },
                                on_outcome,
                            );
                        }
                        DownloadAction::Conflict(path) => {
                            channel
                                .send_record(
                                    RecordType::PathSkip,
                                    &encode_error_payload(ErrorCode::Exists),
                                )
                                .await?;
                            report.result.skipped += 1;
                            pending_exists = Some(path.display().to_string());
                        }
                        DownloadAction::Receive(state) => {
                            channel.send_record(RecordType::PathAccept, &[]).await?;
                            let (received_bytes, destination_path) = self
                                .receive_download_file(channel, state, on_progress)
                                .await?;
                            report.result.received_files += 1;
                            report.result.received_bytes += received_bytes;
                            push_outcome(
                                report,
                                Outcome {
                                    operation: Operation::Import,
                                    severity: OutcomeSeverity::Success,
                                    code: None,
                                    path: Some(format!(
                                        "{} ({})",
                                        destination_path.display(),
                                        format_bytes(received_bytes)
                                    )),
                                },
                                on_outcome,
                            );
                        }
                    }
                }
                RecordType::DownloadDone => {
                    if let Some(path) = pending_exists {
                        return Err(AppError::Depot(DepotError::new(ErrorCode::Exists, path)));
                    }
                    return Ok(());
                }
                RecordType::ErrorRec => {
                    let code = decode_error_payload(&frame.payload)?;
                    return Err(AppError::Depot(DepotError::new(code, source.as_str())));
                }
                _ => {
                    return Err(AppError::Depot(DepotError::new(
                        ErrorCode::Protocol,
                        format!("unexpected record type {:?}", frame.record_type),
                    )));
                }
            }
        }
    }

    fn prepare_download_state(
        &self,
        source: &RemotePath,
        destination_root: &Path,
        include_top: bool,
        skip_existing: bool,
        path_open: &PathOpenPayload,
    ) -> Result<DownloadAction, AppError> {
        let destination_path = local_destination_for_download(
            source,
            destination_root,
            include_top,
            &path_open.relative_path,
        );

        if destination_path.exists() && skip_existing {
            return Ok(DownloadAction::Skip);
        }
        if destination_path.exists() {
            return Ok(DownloadAction::Conflict(destination_path));
        }

        let parent = destination_path
            .parent()
            .ok_or_else(|| AppError::Depot(DepotError::code_only(ErrorCode::BadPath)))?;
        std::fs::create_dir_all(parent).map_err(AppError::Io)?;

        let partial_path = part_path(&destination_path);
        let file = std::fs::File::create(&partial_path)
            .map(tokio::fs::File::from_std)
            .map_err(map_open_error)?;
        let hasher = Blake3::new();

        Ok(DownloadAction::Receive(DownloadState {
            destination_path,
            partial_path,
            file,
            hasher,
            expected_size: path_open.metadata.file_size,
            received_size: 0,
            modification_time_unix: path_open.metadata.modification_time_unix,
            permissions: path_open.metadata.permissions,
        }))
    }

    async fn receive_download_file<IO, PF>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        mut state: DownloadState,
        on_progress: &mut PF,
    ) -> Result<(u64, PathBuf), AppError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        PF: FnMut(&TransferProgress),
    {
        let start = Instant::now();
        let display_name = file_name_display(&state.destination_path);
        loop {
            let frame = match self.recv_client_record(channel).await {
                Ok(frame) => frame,
                Err(error) => {
                    let _ = state.file.flush().await;
                    drop(state.file);
                    let _ = fs::remove_file(&state.partial_path).await;
                    return Err(error);
                }
            };
            match frame.record_type {
                RecordType::FileData => {
                    state
                        .file
                        .write_all(&frame.payload)
                        .await
                        .map_err(map_write_error)?;
                    state.hasher.update(&frame.payload);
                    state.received_size += frame.payload.len() as u64;
                    on_progress(&TransferProgress {
                        action: TransferProgressAction::Downloading,
                        name: display_name.clone(),
                        done_bytes: state.received_size,
                        total_bytes: Some(state.expected_size),
                        elapsed: start.elapsed(),
                    });
                }
                RecordType::FileClose => {
                    return self.commit_download_file(state, &frame.payload).await;
                }
                RecordType::ErrorRec => {
                    let code = decode_error_payload(&frame.payload)?;
                    let _ = state.file.flush().await;
                    drop(state.file);
                    let _ = fs::remove_file(&state.partial_path).await;
                    return Err(AppError::Depot(DepotError::new(
                        code,
                        state.destination_path.display().to_string(),
                    )));
                }
                _ => {
                    return Err(AppError::Depot(DepotError::new(
                        ErrorCode::Protocol,
                        format!("unexpected record type {:?}", frame.record_type),
                    )));
                }
            }
        }
    }

    async fn commit_download_file(
        &self,
        state: DownloadState,
        payload: &[u8],
    ) -> Result<(u64, PathBuf), AppError> {
        let DownloadState {
            destination_path,
            partial_path,
            mut file,
            hasher,
            expected_size,
            received_size,
            modification_time_unix,
            permissions,
        } = state;

        file.flush().await.map_err(map_write_error)?;
        drop(file);

        if payload.len() != DIGEST_LEN || received_size != expected_size {
            let _ = fs::remove_file(&partial_path).await;
            return Err(AppError::Depot(DepotError::code_only(ErrorCode::Checksum)));
        }

        let digest = hasher.finalize();
        if digest.as_bytes() != payload {
            let _ = fs::remove_file(&partial_path).await;
            return Err(AppError::Depot(DepotError::code_only(ErrorCode::Checksum)));
        }

        std::fs::rename(&partial_path, &destination_path).map_err(map_commit_error)?;
        apply_uploaded_metadata(&destination_path, modification_time_unix, permissions)?;
        Ok((received_size, destination_path))
    }

    async fn handle_download_request<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        payload: &[u8],
        options: &ServerRuntimeOptions,
        session_id: &str,
    ) -> Result<(), AppError> {
        let (requested, next_offset) = decode_path_param(payload, 0)?;
        if next_offset != payload.len() {
            return Err(AppError::Depot(DepotError::code_only(
                ErrorCode::BadPayload,
            )));
        }
        if requested.is_empty() {
            return Err(AppError::Depot(DepotError::code_only(ErrorCode::BadPath)));
        }

        let files = self.collect_download_request(&requested, options)?;
        log_server_status(session_id, "download-request", requested.as_str());
        for item in &files {
            channel.propose_rekey_and_await().await?;
            channel
                .send_record(
                    RecordType::PathOpen,
                    &encode_path_open(&PathOpenPayload {
                        relative_path: item.relative_path.clone(),
                        metadata: item.metadata,
                    }),
                )
                .await?;

            let reply = channel.recv_record().await?;
            match reply.record_type {
                RecordType::PathAccept => {
                    self.stream_download_item(channel, item, session_id).await?;
                }
                RecordType::PathSkip => continue,
                RecordType::ErrorRec => {
                    let code = decode_error_payload(&reply.payload)?;
                    return Err(AppError::Depot(DepotError::new(
                        code,
                        item.relative_path.as_str(),
                    )));
                }
                _ => {
                    return Err(AppError::Depot(DepotError::new(
                        ErrorCode::Protocol,
                        format!("unexpected record type {:?}", reply.record_type),
                    )));
                }
            }
        }

        channel.send_record(RecordType::DownloadDone, &[]).await?;
        log_server_status(
            session_id,
            "download-complete",
            &format!("{} ({} files)", requested.as_str(), files.len()),
        );
        Ok(())
    }

    fn collect_download_request(
        &self,
        requested: &RemotePath,
        options: &ServerRuntimeOptions,
    ) -> Result<Vec<DownloadItem>, AppError> {
        let resolved = resolve_remote_path(&options.root, requested, options.sandbox)?;
        let metadata = std::fs::metadata(&resolved.resolved).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::Depot(DepotError::new(ErrorCode::NotFound, requested.as_str()))
            } else {
                AppError::Depot(DepotError::new(
                    ErrorCode::OpenFail,
                    format!("{}: {error}", requested.as_str()),
                ))
            }
        })?;

        let files = if metadata.is_file() {
            vec![DownloadItem {
                relative_path: RemotePath::new(remote_basename(&resolved.resolved)?),
                resolved_path: resolved.resolved,
                metadata: file_metadata_from_std(&metadata)?,
            }]
        } else if metadata.is_dir() {
            let mut files = Vec::new();
            collect_download_directory_items(&resolved.resolved, &resolved.resolved, &mut files)?;
            files
        } else {
            return Err(AppError::Depot(DepotError::new(
                ErrorCode::BadPath,
                requested.as_str(),
            )));
        };

        Ok(files)
    }

    async fn stream_download_item<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        item: &DownloadItem,
        session_id: &str,
    ) -> Result<(), AppError> {
        let mut file = File::open(&item.resolved_path)
            .await
            .map_err(map_open_error)?;
        let mut hasher = Blake3::new();
        let mut buffer = vec![0u8; FILE_CHUNK_SIZE];
        let mut sent_size = 0u64;

        loop {
            let read = file.read(&mut buffer).await.map_err(map_read_error)?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            hasher.update(chunk);
            channel.send_record(RecordType::FileData, chunk).await?;
            sent_size += read as u64;
        }

        if sent_size != item.metadata.file_size {
            return Err(AppError::Depot(DepotError::code_only(ErrorCode::ReadFail)));
        }

        channel
            .send_record(RecordType::FileClose, hasher.finalize().as_bytes())
            .await?;
        log_server_status(session_id, "send-complete", item.relative_path.as_str());
        Ok(())
    }

    fn collect_export_jobs(&self, plan: &ExportPlan) -> Result<Vec<ExportJob>, AppError> {
        let mut jobs = Vec::new();

        for source in &plan.sources {
            let metadata = std::fs::metadata(source).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    AppError::InvalidLocalSource(source.clone())
                } else {
                    AppError::Io(error)
                }
            })?;

            if metadata.is_file() {
                jobs.push(ExportJob {
                    local_path: source.clone(),
                    remote_path: join_remote_destination(
                        plan.destination.as_ref(),
                        &remote_basename(source)?,
                    ),
                });
                continue;
            }

            if metadata.is_dir() {
                let top = if plan.include_top {
                    Some(remote_basename(source)?)
                } else {
                    None
                };
                collect_directory_jobs(
                    source,
                    source,
                    plan.destination.as_ref(),
                    plan.include_top,
                    top.as_deref().unwrap_or(""),
                    &mut jobs,
                )?;
                continue;
            }

            return Err(AppError::InvalidLocalSource(source.clone()));
        }

        jobs.sort_by(|left, right| left.remote_path.as_str().cmp(right.remote_path.as_str()));
        Ok(jobs)
    }

    async fn send_protocol_error<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
        message: &str,
    ) -> Result<(), AppError> {
        channel
            .send_record(
                RecordType::ErrorRec,
                &encode_error_payload(ErrorCode::Protocol),
            )
            .await?;
        Err(AppError::Depot(DepotError::new(
            ErrorCode::Protocol,
            message.to_owned(),
        )))
    }

    async fn recv_client_record<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        channel: &mut SecureChannel<IO, DepotCrypto>,
    ) -> Result<crate::protocol::Frame, AppError> {
        loop {
            let frame = channel.recv_record().await?;
            match frame.record_type {
                RecordType::RekeyReq => {
                    channel.handle_rekey_request(&frame.payload).await?;
                }
                RecordType::RekeyAck => {
                    return Err(AppError::Depot(DepotError::new(
                        ErrorCode::Protocol,
                        "unexpected rekey ack",
                    )));
                }
                _ => return Ok(frame),
            }
        }
    }

    fn apply_serve_defaults(&self, mut options: ServeOptions) -> ServeOptions {
        if options.listen.is_empty() {
            options.listen = self.config.server.listen.clone();
        }
        if options.port == 0 {
            options.port = self.config.server.port;
        }
        options
    }

    fn apply_export_defaults(&self, mut plan: ExportPlan) -> Result<ExportPlan, AppError> {
        plan.endpoint = self.defaulted_endpoint(plan.endpoint)?;
        Ok(plan)
    }

    fn apply_import_defaults(&self, mut plan: ImportPlan) -> Result<ImportPlan, AppError> {
        plan.endpoint = self.defaulted_endpoint(plan.endpoint)?;
        Ok(plan)
    }

    fn apply_list_defaults(&self, mut plan: ListPlan) -> Result<ListPlan, AppError> {
        plan.endpoint = self.defaulted_endpoint(plan.endpoint)?;
        Ok(plan)
    }

    fn defaulted_endpoint(&self, endpoint: Endpoint) -> Result<Endpoint, AppError> {
        let selected_server = endpoint
            .server
            .clone()
            .or_else(|| self.config.client.server.clone());
        let default = if let Some(name) = &selected_server {
            self.config
                .servers
                .get(name)
                .cloned()
                .ok_or_else(|| ConfigError::UnknownNamedServer(name.clone()))?
        } else {
            Endpoint::new("", 60006)
        };
        let host = if endpoint.host.is_empty() {
            default.host
        } else {
            endpoint.host
        };
        if host.is_empty() {
            return Err(ConfigError::MissingClientTarget.into());
        }
        Ok(Endpoint {
            server: selected_server,
            host,
            port: if endpoint.port == 0 {
                default.port
            } else {
                endpoint.port
            },
        })
    }
}

fn collect_directory_jobs(
    root: &Path,
    current: &Path,
    destination: Option<&RemotePath>,
    include_top: bool,
    top_name: &str,
    jobs: &mut Vec<ExportJob>,
) -> Result<(), AppError> {
    let mut entries = std::fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_directory_jobs(root, &path, destination, include_top, top_name, jobs)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| AppError::InvalidLocalSource(path.clone()))?;
            let relative = path_to_remote_string(relative)?;
            let remote = if include_top {
                join_remote_destination(destination, &join_remote_path(top_name, &relative))
            } else {
                join_remote_destination(destination, &relative)
            };
            jobs.push(ExportJob {
                local_path: path,
                remote_path: remote,
            });
        }
    }

    Ok(())
}

fn collect_download_directory_items(
    root: &Path,
    current: &Path,
    items: &mut Vec<DownloadItem>,
) -> Result<(), AppError> {
    let mut entries = std::fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_download_directory_items(root, &path, items)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| AppError::InvalidLocalSource(path.clone()))?;
            items.push(DownloadItem {
                relative_path: RemotePath::new(path_to_remote_string(relative)?),
                resolved_path: path,
                metadata: file_metadata_from_std(&metadata)?,
            });
        }
    }

    Ok(())
}

fn file_metadata_from_std(metadata: &std::fs::Metadata) -> Result<FileMetadata, AppError> {
    Ok(FileMetadata {
        file_size: metadata.len(),
        modification_time_unix: unix_mtime(metadata)?,
        permissions: permissions_from_std(metadata.permissions()),
    })
}

fn single_file_list_path(
    root: &ServerRoot,
    resolved: &Path,
    requested: &RemotePath,
) -> Result<RemotePath, AppError> {
    let root = root.as_path();
    let relative = resolved
        .strip_prefix(root)
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|_| PathBuf::from(requested.as_str()));
    let text = relative
        .to_str()
        .ok_or_else(|| AppError::InvalidUtf8Path(relative.clone()))?;
    Ok(RemotePath::new(
        text.replace(std::path::MAIN_SEPARATOR, "/"),
    ))
}

fn remote_basename(path: &Path) -> Result<String, AppError> {
    let name = path
        .file_name()
        .map(|name| name.to_owned())
        .or_else(|| {
            std::fs::canonicalize(path)
                .ok()
                .and_then(|canonical| canonical.file_name().map(|name| name.to_owned()))
        })
        .ok_or_else(|| AppError::InvalidLocalSource(path.to_path_buf()))?;
    let name = name
        .to_str()
        .ok_or_else(|| AppError::InvalidUtf8Path(path.to_path_buf()))?;
    Ok(name.to_owned())
}

fn file_name_display(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn path_to_remote_string(path: &Path) -> Result<String, AppError> {
    let text = path
        .to_str()
        .ok_or_else(|| AppError::InvalidUtf8Path(path.to_path_buf()))?;
    Ok(text.replace(std::path::MAIN_SEPARATOR, "/"))
}

fn join_remote_destination(destination: Option<&RemotePath>, leaf: &str) -> RemotePath {
    match destination {
        Some(base) if !base.is_empty() && base.as_str() != "." => {
            RemotePath::new(join_remote_path(base.as_str(), leaf))
        }
        _ => RemotePath::new(leaf),
    }
}

fn join_remote_path(base: &str, leaf: &str) -> String {
    if base.is_empty() || base == "." {
        return leaf.to_owned();
    }
    if leaf.is_empty() || leaf == "." {
        return base.to_owned();
    }
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        leaf.trim_start_matches('/')
    )
}

fn local_destination_for_download(
    source: &RemotePath,
    destination_root: &Path,
    include_top: bool,
    relative_path: &RemotePath,
) -> PathBuf {
    if !destination_root.is_dir() {
        return destination_root.to_path_buf();
    }

    let source_path = Path::new(source.as_str());
    let source_basename = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| *name != ".");

    let relative = PathBuf::from(relative_path.as_str());
    if include_top {
        match source_basename {
            Some(top) if top != relative_path.as_str() => destination_root.join(top).join(relative),
            _ => destination_root.join(relative),
        }
    } else {
        destination_root.join(relative)
    }
}

fn part_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .expect("part path requires file name")
        .to_string_lossy();
    path.with_file_name(format!("{name}.part"))
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

fn unix_mtime(metadata: &std::fs::Metadata) -> Result<u64, AppError> {
    let modified = metadata.modified()?;
    let unix = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| AppError::Io(std::io::Error::other(error)))?;
    Ok(unix.as_secs())
}

fn apply_uploaded_metadata(
    path: &Path,
    modification_time_unix: u64,
    permissions: PortablePermissions,
) -> Result<(), AppError> {
    let mtime = FileTime::from_unix_time(modification_time_unix as i64, 0);
    set_file_mtime(path, mtime).map_err(AppError::Io)?;
    let std_permissions = permissions_to_std(permissions);
    std::fs::set_permissions(path, std_permissions).map_err(AppError::Io)?;
    Ok(())
}

fn map_open_error(error: std::io::Error) -> AppError {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::Perms,
        _ => ErrorCode::OpenFail,
    };
    AppError::Depot(DepotError::new(code, error.to_string()))
}

fn map_read_error(error: std::io::Error) -> AppError {
    let code = match error.kind() {
        std::io::ErrorKind::PermissionDenied => ErrorCode::Perms,
        _ => ErrorCode::ReadFail,
    };
    AppError::Depot(DepotError::new(code, error.to_string()))
}

fn map_write_error(error: std::io::Error) -> AppError {
    let code = match error.kind() {
        std::io::ErrorKind::PermissionDenied => ErrorCode::Perms,
        std::io::ErrorKind::WriteZero => ErrorCode::WriteFail,
        std::io::ErrorKind::OutOfMemory => ErrorCode::NoSpace,
        _ => ErrorCode::WriteFail,
    };
    AppError::Depot(DepotError::new(code, error.to_string()))
}

fn map_commit_error(error: std::io::Error) -> AppError {
    let code = match error.kind() {
        std::io::ErrorKind::PermissionDenied => ErrorCode::Perms,
        std::io::ErrorKind::AlreadyExists => ErrorCode::Exists,
        _ => ErrorCode::CommitFail,
    };
    AppError::Depot(DepotError::new(code, error.to_string()))
}

fn log_server_status(session_id: &str, tag: &str, message: &str) {
    eprintln!("[{session_id}] [{tag}] {message}");
}

fn log_server_error(session_id: &str, message: &str) {
    eprintln!("[{session_id}] {message}");
}

enum DownloadAction {
    Skip,
    Conflict(PathBuf),
    Receive(DownloadState),
}

fn item_outcome(
    operation: Operation,
    severity: OutcomeSeverity,
    code: ErrorCode,
    path: Option<String>,
) -> Outcome {
    Outcome {
        operation,
        severity,
        code: Some(code),
        path,
    }
}

fn push_outcome<F>(report: &mut BatchReport, outcome: Outcome, on_outcome: &mut F)
where
    F: FnMut(&Outcome),
{
    on_outcome(&outcome);
    report.outcomes.push(outcome);
}

fn permissions_from_std(permissions: std::fs::Permissions) -> PortablePermissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut portable = PortablePermissions::empty();
        let mode = permissions.mode();
        if mode & 0o400 != 0 {
            portable.insert(PortablePermission::UserRead);
        }
        if mode & 0o200 != 0 {
            portable.insert(PortablePermission::UserWrite);
        }
        if mode & 0o100 != 0 {
            portable.insert(PortablePermission::UserExec);
        }
        if mode & 0o040 != 0 {
            portable.insert(PortablePermission::GroupRead);
        }
        if mode & 0o020 != 0 {
            portable.insert(PortablePermission::GroupWrite);
        }
        if mode & 0o010 != 0 {
            portable.insert(PortablePermission::GroupExec);
        }
        if mode & 0o004 != 0 {
            portable.insert(PortablePermission::OtherRead);
        }
        if mode & 0o002 != 0 {
            portable.insert(PortablePermission::OtherWrite);
        }
        if mode & 0o001 != 0 {
            portable.insert(PortablePermission::OtherExec);
        }
        portable
    }
    #[cfg(not(unix))]
    {
        let mut portable = PortablePermissions::empty();
        portable.insert(PortablePermission::UserRead);
        portable.insert(PortablePermission::GroupRead);
        portable.insert(PortablePermission::OtherRead);
        if !permissions.readonly() {
            portable.insert(PortablePermission::UserWrite);
            portable.insert(PortablePermission::GroupWrite);
            portable.insert(PortablePermission::OtherWrite);
        }
        portable
    }
}

fn permissions_to_std(permissions: PortablePermissions) -> std::fs::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut mode = 0u32;
        if permissions.contains(PortablePermission::UserRead) {
            mode |= 0o400;
        }
        if permissions.contains(PortablePermission::UserWrite) {
            mode |= 0o200;
        }
        if permissions.contains(PortablePermission::UserExec) {
            mode |= 0o100;
        }
        if permissions.contains(PortablePermission::GroupRead) {
            mode |= 0o040;
        }
        if permissions.contains(PortablePermission::GroupWrite) {
            mode |= 0o020;
        }
        if permissions.contains(PortablePermission::GroupExec) {
            mode |= 0o010;
        }
        if permissions.contains(PortablePermission::OtherRead) {
            mode |= 0o004;
        }
        if permissions.contains(PortablePermission::OtherWrite) {
            mode |= 0o002;
        }
        if permissions.contains(PortablePermission::OtherExec) {
            mode |= 0o001;
        }
        std::fs::Permissions::from_mode(mode)
    }
    #[cfg(not(unix))]
    {
        let readonly = !permissions.contains(PortablePermission::UserWrite);
        let mut perms = std::fs::metadata(".")
            .map(|metadata| metadata.permissions())
            .unwrap_or_else(|_| std::fs::Permissions::readonly());
        perms.set_readonly(readonly);
        perms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::LogLevel;
    use crate::crypto::HandshakeCryptoProvider;
    use crate::transport::ClientTrustProvider;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[derive(Default)]
    struct TestTrustStore {
        trusted: Mutex<HashSet<Vec<u8>>>,
    }

    impl TestTrustStore {
        fn with_trusted(public_key: &MlDsa87PublicKey) -> Arc<Self> {
            let mut trusted = HashSet::new();
            trusted.insert(public_key.as_ref().to_vec());
            Arc::new(Self {
                trusted: Mutex::new(trusted),
            })
        }
    }

    impl ClientTrustProvider for TestTrustStore {
        fn is_trusted(
            &self,
            public_key: &MlDsa87PublicKey,
        ) -> Result<bool, HandshakeError> {
            Ok(self
                .trusted
                .lock()
                .unwrap()
                .contains(public_key.as_slice()))
        }

        fn begin_enrollment(
            &self,
            _public_key: &MlDsa87PublicKey,
            _session_label: &str,
        ) -> Result<(), HandshakeError> {
            Err(HandshakeError::BadState(
                "unexpected enrollment in trusted app test",
            ))
        }

        fn try_enroll(
            &self,
            _public_key: &MlDsa87PublicKey,
            _token: &str,
            _session_label: &str,
        ) -> Result<bool, HandshakeError> {
            Err(HandshakeError::BadState(
                "unexpected enrollment in trusted app test",
            ))
        }
    }

    #[test]
    fn resolves_named_server_from_config_default() {
        let config = Config::parse_toml(
            r#"
            [client]
            server = "home"

            [servers.home]
            host = "storage.lan"
            port = 61000
            "#,
        )
        .unwrap();
        let app = App::new(config);

        let command = app
            .apply_client_defaults(Command::List(ListPlan {
                endpoint: Endpoint::new("", 0),
                path: None,
                log_level: LogLevel::Info,
            }))
            .unwrap();

        match command {
            Command::List(plan) => {
                assert_eq!(plan.endpoint.server.as_deref(), Some("home"));
                assert_eq!(plan.endpoint.host, "storage.lan");
                assert_eq!(plan.endpoint.port, 61000);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn resolves_named_server_with_host_port_overrides() {
        let config = Config::parse_toml(
            r#"
            [client]
            server = "home"

            [servers.home]
            host = "storage.lan"
            port = 60006
            "#,
        )
        .unwrap();
        let app = App::new(config);

        let command = app
            .apply_client_defaults(Command::List(ListPlan {
                endpoint: Endpoint::new("override.example.com", 62000)
                    .with_server(Some("home".to_owned())),
                path: None,
                log_level: LogLevel::Info,
            }))
            .unwrap();

        match command {
            Command::List(plan) => {
                assert_eq!(plan.endpoint.server.as_deref(), Some("home"));
                assert_eq!(plan.endpoint.host, "override.example.com");
                assert_eq!(plan.endpoint.port, 62000);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn explicit_named_server_overrides_config_default_server() {
        let config = Config::parse_toml(
            r#"
            [client]
            server = "home"

            [servers.home]
            host = "storage.lan"
            port = 60006

            [servers.vps]
            host = "files.example.com"
            port = 61000
            "#,
        )
        .unwrap();
        let app = App::new(config);

        let command = app
            .apply_client_defaults(Command::List(ListPlan {
                endpoint: Endpoint::new("", 0).with_server(Some("vps".to_owned())),
                path: None,
                log_level: LogLevel::Info,
            }))
            .unwrap();

        match command {
            Command::List(plan) => {
                assert_eq!(plan.endpoint.server.as_deref(), Some("vps"));
                assert_eq!(plan.endpoint.host, "files.example.com");
                assert_eq!(plan.endpoint.port, 61000);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn missing_named_server_and_missing_host_is_an_error() {
        let app = App::new(Config::default());

        let error = app
            .apply_client_defaults(Command::List(ListPlan {
                endpoint: Endpoint::new("", 0),
                path: None,
                log_level: LogLevel::Info,
            }))
            .unwrap_err();

        assert!(matches!(error, AppError::Config(ConfigError::MissingClientTarget)));
    }

    #[tokio::test]
    async fn list_roundtrip_over_tcp_returns_directory_entries() {
        let root_dir = tempdir().unwrap();
        std::fs::create_dir(root_dir.path().join("movies")).unwrap();
        std::fs::write(root_dir.path().join("movies").join("a.txt"), b"hello").unwrap();
        std::fs::create_dir(root_dir.path().join("movies").join("extras")).unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let entries = app
            .list(
                ListPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    path: Some(RemotePath::new("movies")),
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let entries = entries.value;

        server_task.await.unwrap();

        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| {
            entry.relative_path.as_str() == "a.txt" && !entry.is_dir && entry.file_size == 5
        }));
        assert!(entries.iter().any(|entry| {
            entry.relative_path.as_str() == "extras" && entry.is_dir && entry.file_size == 0
        }));
    }

    #[tokio::test]
    async fn list_roundtrip_for_single_file_returns_requested_path() {
        let root_dir = tempdir().unwrap();
        std::fs::write(root_dir.path().join("movie.mkv"), b"123456").unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let entries = app
            .list(
                ListPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    path: Some(RemotePath::new("movie.mkv")),
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let entries = entries.value;

        server_task.await.unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relative_path.as_str(), "movie.mkv");
        assert_eq!(entries[0].file_size, 6);
        assert!(!entries[0].is_dir);
    }

    #[tokio::test]
    async fn export_roundtrip_uploads_file_over_tcp() {
        let root_dir = tempdir().unwrap();
        let local_dir = tempdir().unwrap();
        let local_file = local_dir.path().join("notes.txt");
        std::fs::write(&local_file, b"alpha").unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .export(
                ExportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![local_file.clone()],
                    destination: Some(RemotePath::new("incoming")),
                    include_top: true,
                    skip_existing: false,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let batch = batch.value;

        server_task.await.unwrap();

        assert_eq!(batch.result.sent_files, 1);
        assert_eq!(batch.result.sent_bytes, 5);
        assert_eq!(
            std::fs::read(root_dir.path().join("incoming").join("notes.txt")).unwrap(),
            b"alpha"
        );
    }

    #[tokio::test]
    async fn export_roundtrip_uploads_directory_tree() {
        let root_dir = tempdir().unwrap();
        let local_dir = tempdir().unwrap();
        let source_dir = local_dir.path().join("album");
        std::fs::create_dir(&source_dir).unwrap();
        std::fs::create_dir(source_dir.join("disc1")).unwrap();
        std::fs::write(source_dir.join("disc1").join("track1.flac"), b"t1").unwrap();
        std::fs::write(source_dir.join("cover.jpg"), b"jpg").unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .export(
                ExportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![source_dir.clone()],
                    destination: Some(RemotePath::new("music")),
                    include_top: true,
                    skip_existing: false,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let batch = batch.value;

        server_task.await.unwrap();

        assert_eq!(batch.result.sent_files, 2);
        assert_eq!(
            std::fs::read(root_dir.path().join("music/album/cover.jpg")).unwrap(),
            b"jpg"
        );
        assert_eq!(
            std::fs::read(root_dir.path().join("music/album/disc1/track1.flac")).unwrap(),
            b"t1"
        );
    }

    #[tokio::test]
    async fn export_roundtrip_all_style_directory_source_omits_top_level_wrapper() {
        let root_dir = tempdir().unwrap();
        let local_dir = tempdir().unwrap();
        let source_dir = local_dir.path().join("album");
        std::fs::create_dir(&source_dir).unwrap();
        std::fs::create_dir(source_dir.join("disc1")).unwrap();
        std::fs::write(source_dir.join("disc1").join("track1.flac"), b"t1").unwrap();
        std::fs::write(source_dir.join("cover.jpg"), b"jpg").unwrap();
        let all_style_source = source_dir.join(".");

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .export(
                ExportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![all_style_source],
                    destination: Some(RemotePath::new("music")),
                    include_top: false,
                    skip_existing: false,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let batch = batch.value;

        server_task.await.unwrap();

        assert_eq!(batch.result.sent_files, 2);
        assert_eq!(
            std::fs::read(root_dir.path().join("music/cover.jpg")).unwrap(),
            b"jpg"
        );
        assert_eq!(
            std::fs::read(root_dir.path().join("music/disc1/track1.flac")).unwrap(),
            b"t1"
        );
        assert!(!root_dir.path().join("music/album").exists());
    }

    #[tokio::test]
    async fn import_roundtrip_downloads_file_over_tcp() {
        let root_dir = tempdir().unwrap();
        std::fs::create_dir(root_dir.path().join("classics")).unwrap();
        std::fs::write(root_dir.path().join("classics").join("film.mkv"), b"film").unwrap();
        let local_dir = tempdir().unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .import(
                ImportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![RemotePath::new("classics/film.mkv")],
                    destination: Some(local_dir.path().to_path_buf()),
                    include_top: true,
                    skip_existing: false,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let batch = batch.value;

        server_task.await.unwrap();

        assert_eq!(batch.result.received_files, 1);
        assert_eq!(batch.result.received_bytes, 4);
        assert_eq!(
            std::fs::read(local_dir.path().join("film.mkv")).unwrap(),
            b"film"
        );
    }

    #[tokio::test]
    async fn import_roundtrip_downloads_directory_tree() {
        let root_dir = tempdir().unwrap();
        let remote_dir = root_dir.path().join("album");
        std::fs::create_dir(&remote_dir).unwrap();
        std::fs::create_dir(remote_dir.join("disc1")).unwrap();
        std::fs::write(remote_dir.join("cover.jpg"), b"jpg").unwrap();
        std::fs::write(remote_dir.join("disc1").join("track1.flac"), b"t1").unwrap();
        let local_dir = tempdir().unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .import(
                ImportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![RemotePath::new("album")],
                    destination: Some(local_dir.path().to_path_buf()),
                    include_top: true,
                    skip_existing: false,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let batch = batch.value;

        server_task.await.unwrap();

        assert_eq!(batch.result.received_files, 2);
        assert_eq!(
            std::fs::read(local_dir.path().join("album").join("cover.jpg")).unwrap(),
            b"jpg"
        );
        assert_eq!(
            std::fs::read(local_dir.path().join("album/disc1/track1.flac")).unwrap(),
            b"t1"
        );
    }

    #[tokio::test]
    async fn import_roundtrip_skips_existing_files() {
        let root_dir = tempdir().unwrap();
        let remote_dir = root_dir.path().join("set");
        std::fs::create_dir(&remote_dir).unwrap();
        std::fs::write(remote_dir.join("keep.txt"), b"new").unwrap();
        let local_dir = tempdir().unwrap();
        std::fs::create_dir(local_dir.path().join("set")).unwrap();
        std::fs::write(local_dir.path().join("set").join("keep.txt"), b"old").unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .import(
                ImportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![RemotePath::new("set")],
                    destination: Some(local_dir.path().to_path_buf()),
                    include_top: true,
                    skip_existing: true,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap();
        let batch = batch.value;

        server_task.await.unwrap();

        assert_eq!(batch.result.received_files, 0);
        assert_eq!(batch.result.skipped, 1);
        assert_eq!(
            std::fs::read(local_dir.path().join("set").join("keep.txt")).unwrap(),
            b"old"
        );
    }

    #[tokio::test]
    async fn import_existing_file_without_skip_fails_and_does_not_overwrite() {
        let root_dir = tempdir().unwrap();
        std::fs::write(root_dir.path().join("film.mkv"), b"new").unwrap();
        let local_dir = tempdir().unwrap();
        std::fs::write(local_dir.path().join("film.mkv"), b"old").unwrap();

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .import(
                ImportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![RemotePath::new("film.mkv")],
                    destination: Some(local_dir.path().to_path_buf()),
                    include_top: true,
                    skip_existing: false,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap()
            .value;

        server_task.await.unwrap();

        assert_eq!(batch.result.received_files, 0);
        assert_eq!(batch.result.skipped, 1);
        assert_eq!(batch.result.failed, 1);
        assert_eq!(
            std::fs::read(local_dir.path().join("film.mkv")).unwrap(),
            b"old"
        );
    }

    #[tokio::test]
    async fn import_single_file_can_target_explicit_file_path() {
        let root_dir = tempdir().unwrap();
        std::fs::write(root_dir.path().join("film.mkv"), b"film").unwrap();
        let local_dir = tempdir().unwrap();
        let local_target = local_dir.path().join("renamed.mkv");

        let app = App::new(Config::default());
        let root = app.canonical_server_root(root_dir.path()).unwrap();
        let identity = DepotCrypto.generate_signing_identity().unwrap();
        let expected_server_identity = identity.public_key.clone();
        let client_identity = DepotCrypto.generate_signing_identity().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_options = app.default_server_runtime_options(
            root,
            identity,
            SandboxPolicy::Enforced,
            false,
            TestTrustStore::with_trusted(&client_identity.public_key),
        );

        let server_app = app.clone();
        let server_task = tokio::spawn(async move {
            server_app
                .serve_once(&listener, &server_options)
                .await
                .unwrap();
        });

        let batch = app
            .import(
                ImportPlan {
                    endpoint: Endpoint::new(addr.ip().to_string(), addr.port()),
                    sources: vec![RemotePath::new("film.mkv")],
                    destination: Some(local_target.clone()),
                    include_top: true,
                    skip_existing: false,
                    log_level: LogLevel::Info,
                },
                app.default_client_runtime_options(
                    Some(expected_server_identity),
                    client_identity,
                    None,
                    None,
                ),
            )
            .await
            .unwrap()
            .value;

        server_task.await.unwrap();

        assert_eq!(batch.result.received_files, 1);
        assert_eq!(std::fs::read(local_target).unwrap(), b"film");
    }
}
