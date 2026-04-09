use crate::core::{ErrorCode, SandboxPolicy};
use crate::crypto::{
    CryptoError, CryptoProvider, HandshakeCryptoProvider, MlDsa87PublicKey, RekeyMaterial,
    SessionKeys, SigningIdentity, Transcript,
};
use crate::protocol::{
    ClientAuthPayload, ClientHello, ClientKemPayload, CodecError, EncodedHandshakeBlob, Frame,
    HandshakeBlob, HandshakeFeatures, HandshakeType, PROTOCOL_VERSION, RecordType, ServerHello,
    ServerIdentityPayload, ServerKemBindingPayload, decode_client_auth, decode_client_hello,
    decode_client_kem, decode_error_payload, decode_handshake_blob, decode_server_hello,
    decode_server_identity, decode_server_kem_binding, decode_uvar, encode_client_auth,
    encode_client_hello, encode_client_kem, encode_error_payload, encode_handshake_blob,
    encode_server_hello, encode_server_identity, encode_server_kem_binding, encode_uvar,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_REKEY_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveFailure {
    None,
    Closed,
    Format,
    Authentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionStats {
    pub sent_files: u64,
    pub sent_bytes: u64,
    pub received_files: u64,
    pub received_bytes: u64,
    pub skipped: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    pub io_timeout: Duration,
    pub rekey_interval: Duration,
    pub max_record_body_len: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            io_timeout: DEFAULT_IO_TIMEOUT,
            rekey_interval: DEFAULT_REKEY_INTERVAL,
            max_record_body_len: crate::protocol::MAX_RECORD_BODY_LEN,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureChannelState {
    pub role: ConnectionRole,
    pub sequence_tx: u64,
    pub sequence_rx: u64,
    pub epoch: u32,
    pub last_receive_failure: ReceiveFailure,
}

impl SecureChannelState {
    pub fn protocol_error_for_receive_failure(&self) -> Option<ErrorCode> {
        match self.last_receive_failure {
            ReceiveFailure::None => None,
            ReceiveFailure::Closed => Some(ErrorCode::Closed),
            ReceiveFailure::Format => Some(ErrorCode::BadPayload),
            ReceiveFailure::Authentication => Some(ErrorCode::Protocol),
        }
    }
}

#[derive(Clone)]
pub struct ClientHandshakeOptions {
    pub expected_server_identity: Option<MlDsa87PublicKey>,
    pub client_identity: SigningIdentity,
    pub enrollment_token: Option<String>,
}

pub trait ClientTrustProvider: Send + Sync {
    fn is_trusted(
        &self,
        public_key: &MlDsa87PublicKey,
    ) -> Result<bool, HandshakeError>;

    fn begin_enrollment(
        &self,
        public_key: &MlDsa87PublicKey,
        session_label: &str,
    ) -> Result<(), HandshakeError>;

    fn try_enroll(
        &self,
        public_key: &MlDsa87PublicKey,
        token: &str,
        session_label: &str,
    ) -> Result<bool, HandshakeError>;
}

#[derive(Clone)]
pub struct ServerHandshakeOptions {
    pub server_identity: SigningIdentity,
    pub client_trust: Arc<dyn ClientTrustProvider>,
    pub session_label: String,
    pub sandbox: SandboxPolicy,
}

#[derive(Clone)]
pub struct ClientHandshakeSummary {
    pub server_identity: MlDsa87PublicKey,
    pub server_sandbox: SandboxPolicy,
    pub features: HandshakeFeatures,
}

#[derive(Clone)]
pub struct ServerHandshakeSummary {
    pub client_identity: MlDsa87PublicKey,
    pub sandbox: SandboxPolicy,
    pub features: HandshakeFeatures,
}

pub struct ClientHandshakeResult<IO, C> {
    pub channel: SecureChannel<IO, C>,
    pub summary: ClientHandshakeSummary,
}

pub struct ServerHandshakeResult<IO, C> {
    pub channel: SecureChannel<IO, C>,
    pub summary: ServerHandshakeSummary,
}

#[derive(Debug)]
pub enum HandshakeError {
    Io(std::io::Error),
    Codec(CodecError),
    Crypto(CryptoError),
    Remote(ErrorCode),
    VersionMismatch { expected: u8, actual: u8 },
    MissingFeature(&'static str),
    Authentication(&'static str),
    EnrollmentRequired,
    BadState(&'static str),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Codec(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Remote(code) => write!(f, "remote handshake failed: {}", code.name()),
            Self::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "protocol version mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MissingFeature(name) => write!(f, "required feature missing: {name}"),
            Self::Authentication(message) => f.write_str(message),
            Self::EnrollmentRequired => f.write_str("client enrollment required"),
            Self::BadState(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<std::io::Error> for HandshakeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<CodecError> for HandshakeError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<CryptoError> for HandshakeError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Codec(CodecError),
    Crypto(CryptoError),
    InvalidRecordLength(usize),
    ConnectionClosed,
    Timeout,
    AuthenticationFailed,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Codec(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::InvalidRecordLength(length) => write!(f, "invalid record length: {length}"),
            Self::ConnectionClosed => f.write_str("connection closed"),
            Self::Timeout => f.write_str("session timed out"),
            Self::AuthenticationFailed => f.write_str("record authentication failed"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<CodecError> for TransportError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<CryptoError> for TransportError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

pub struct SecureChannel<IO, C> {
    io: IO,
    crypto: C,
    keys: SessionKeys,
    config: TransportConfig,
    state: SecureChannelState,
    last_activity: Instant,
    last_rekey: Instant,
}

impl<IO, C> SecureChannel<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: CryptoProvider<Error = CryptoError>,
{
    pub fn new(
        io: IO,
        crypto: C,
        keys: SessionKeys,
        role: ConnectionRole,
        config: TransportConfig,
    ) -> Self {
        Self {
            io,
            crypto,
            keys,
            config,
            state: SecureChannelState {
                role,
                sequence_tx: 0,
                sequence_rx: 0,
                epoch: 0,
                last_receive_failure: ReceiveFailure::None,
            },
            last_activity: Instant::now(),
            last_rekey: Instant::now(),
        }
    }

    pub fn state(&self) -> &SecureChannelState {
        &self.state
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn should_propose_rekey(&self) -> bool {
        self.last_rekey.elapsed() > self.config.rekey_interval
    }

    pub fn into_inner(self) -> IO {
        self.io
    }

    pub async fn send_record(
        &mut self,
        record_type: RecordType,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        let aad = associated_data(record_type, self.state.sequence_tx, self.state.epoch);
        let nonce = build_nonce(&self.keys.tx_nonce_prefix, self.state.sequence_tx);
        let (ciphertext, tag) = self.crypto.seal(&self.keys.tx_key, &nonce, payload, &aad)?;

        let body_len = 1 + ciphertext.len() + tag.len();
        if body_len > self.config.max_record_body_len {
            return Err(TransportError::InvalidRecordLength(body_len));
        }

        let mut frame = encode_uvar(body_len as u64);
        frame.push(record_type as u8);
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&tag);

        self.write_all_timeout(&frame).await?;
        self.flush_timeout().await?;

        self.state.sequence_tx += 1;
        self.last_activity = Instant::now();
        Ok(())
    }

    pub async fn recv_record(&mut self) -> Result<Frame, TransportError> {
        let body_len = self.read_len_prefix().await?;
        if body_len < 17 || body_len > self.config.max_record_body_len {
            self.state.last_receive_failure = ReceiveFailure::Format;
            return Err(TransportError::InvalidRecordLength(body_len));
        }

        let mut body = vec![0u8; body_len];
        self.read_exact_timeout(&mut body).await.map_err(|error| {
            self.state.last_receive_failure = match error {
                TransportError::ConnectionClosed => ReceiveFailure::Closed,
                TransportError::Timeout => ReceiveFailure::Closed,
                _ => ReceiveFailure::Format,
            };
            error
        })?;

        let record_type = RecordType::try_from(body[0])
            .map_err(|_| TransportError::Codec(CodecError::InvalidRecordType(body[0])))?;
        let tag_offset = body.len() - 16;
        let tag = slice_to_array_16(&body[tag_offset..])?;
        let ciphertext = &body[1..tag_offset];
        let aad = associated_data(record_type, self.state.sequence_rx, self.state.epoch);
        let nonce = build_nonce(&self.keys.rx_nonce_prefix, self.state.sequence_rx);

        let plaintext = match self
            .crypto
            .open(&self.keys.rx_key, &nonce, ciphertext, &aad, &tag)
        {
            Ok(plaintext) => plaintext,
            Err(CryptoError::Aead) => {
                self.state.last_receive_failure = ReceiveFailure::Authentication;
                return Err(TransportError::AuthenticationFailed);
            }
            Err(error) => {
                self.state.last_receive_failure = ReceiveFailure::Format;
                return Err(TransportError::Crypto(error));
            }
        };

        self.state.sequence_rx += 1;
        self.state.last_receive_failure = ReceiveFailure::None;
        self.last_activity = Instant::now();

        Ok(Frame {
            record_type,
            payload: plaintext,
        })
    }

    pub fn apply_rekey(&mut self, material: RekeyMaterial) {
        self.keys.tx_key = material.tx_key;
        self.keys.rx_key = material.rx_key;
        self.keys.tx_nonce_prefix = material.tx_nonce_prefix;
        self.keys.rx_nonce_prefix = material.rx_nonce_prefix;
        self.state.epoch = material.epoch;
        self.state.sequence_tx = 0;
        self.state.sequence_rx = 0;
        self.last_activity = Instant::now();
        self.last_rekey = Instant::now();
    }

    pub async fn handle_rekey_request(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let epoch_bytes: [u8; 4] = payload
            .try_into()
            .map_err(|_| TransportError::Codec(CodecError::Truncated))?;
        let epoch = u32::from_le_bytes(epoch_bytes);
        let material = self.crypto.derive_rekey(
            &self.keys.traffic_secret,
            epoch,
            self.state.role == ConnectionRole::Client,
        )?;
        self.send_record(RecordType::RekeyAck, &epoch_bytes).await?;
        self.apply_rekey(material);
        Ok(())
    }

    pub async fn propose_rekey_and_await(&mut self) -> Result<(), TransportError> {
        if !self.should_propose_rekey() {
            return Ok(());
        }

        let next_epoch = self.state.epoch.wrapping_add(1);
        let epoch_bytes = next_epoch.to_le_bytes();
        let material = self.crypto.derive_rekey(
            &self.keys.traffic_secret,
            next_epoch,
            self.state.role == ConnectionRole::Client,
        )?;
        self.send_record(RecordType::RekeyReq, &epoch_bytes).await?;

        let frame = self.recv_record().await?;
        match frame.record_type {
            RecordType::RekeyAck if frame.payload == epoch_bytes => {
                self.apply_rekey(material);
                Ok(())
            }
            _ => Err(TransportError::Codec(CodecError::InvalidHandshakePayload(
                "expected rekey ack",
            ))),
        }
    }

    async fn read_len_prefix(&mut self) -> Result<usize, TransportError> {
        let mut buffer = Vec::with_capacity(10);
        loop {
            let mut byte = [0u8; 1];
            match self.read_exact_timeout(&mut byte).await {
                Ok(_) => {
                    buffer.push(byte[0]);
                    match decode_uvar(&buffer) {
                        Ok((value, used)) if used == buffer.len() => {
                            return usize::try_from(value)
                                .map_err(|_| TransportError::InvalidRecordLength(usize::MAX));
                        }
                        Ok(_) => {}
                        Err(CodecError::Truncated) => {}
                        Err(error) => {
                            self.state.last_receive_failure = ReceiveFailure::Format;
                            return Err(TransportError::Codec(error));
                        }
                    }
                    if buffer.len() > 10 {
                        self.state.last_receive_failure = ReceiveFailure::Format;
                        return Err(TransportError::Codec(CodecError::InvalidVarint));
                    }
                }
                Err(TransportError::ConnectionClosed) => {
                    self.state.last_receive_failure = ReceiveFailure::Closed;
                    return Err(TransportError::ConnectionClosed);
                }
                Err(TransportError::Timeout) => {
                    self.state.last_receive_failure = ReceiveFailure::Closed;
                    return Err(TransportError::Timeout);
                }
                Err(error) => {
                    self.state.last_receive_failure = ReceiveFailure::Format;
                    return Err(error);
                }
            }
        }
    }

    fn remaining_io_timeout(&self) -> Result<Duration, TransportError> {
        let elapsed = self.last_activity.elapsed();
        if elapsed >= self.config.io_timeout {
            return Err(TransportError::Timeout);
        }
        Ok(self.config.io_timeout - elapsed)
    }

    async fn write_all_timeout(&mut self, buffer: &[u8]) -> Result<(), TransportError> {
        let timeout = self.remaining_io_timeout()?;
        match time::timeout(timeout, self.io.write_all(buffer)).await {
            Ok(result) => result.map_err(TransportError::Io),
            Err(_) => Err(TransportError::Timeout),
        }
    }

    async fn flush_timeout(&mut self) -> Result<(), TransportError> {
        let timeout = self.remaining_io_timeout()?;
        match time::timeout(timeout, self.io.flush()).await {
            Ok(result) => result.map_err(TransportError::Io),
            Err(_) => Err(TransportError::Timeout),
        }
    }

    async fn read_exact_timeout(&mut self, buffer: &mut [u8]) -> Result<(), TransportError> {
        let timeout = self.remaining_io_timeout()?;
        match time::timeout(timeout, self.io.read_exact(buffer)).await {
            Ok(result) => result.map(|_| ()).map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    TransportError::ConnectionClosed
                } else {
                    TransportError::Io(error)
                }
            }),
            Err(_) => Err(TransportError::Timeout),
        }
    }
}

pub async fn client_handshake<IO, C>(
    io: IO,
    crypto: C,
    options: ClientHandshakeOptions,
    config: TransportConfig,
) -> Result<ClientHandshakeResult<IO, C>, HandshakeError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: HandshakeCryptoProvider<Error = CryptoError>,
{
    client_handshake_with_identity_handler(io, crypto, options, config, |_| Ok(())).await
}

pub async fn client_handshake_with_identity_handler<IO, C, F>(
    io: IO,
    crypto: C,
    options: ClientHandshakeOptions,
    config: TransportConfig,
    on_server_identity: F,
) -> Result<ClientHandshakeResult<IO, C>, HandshakeError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: HandshakeCryptoProvider<Error = CryptoError>,
    F: FnOnce(&MlDsa87PublicKey) -> Result<(), HandshakeError>,
{
    let mut io = io;
    let mut transcript = Transcript::new();
    let required_features = HandshakeFeatures {
        download_ack_v1: true,
    };

    let client_hello = ClientHello {
        version: PROTOCOL_VERSION,
        features: required_features,
    };
    send_handshake_message(
        &mut io,
        &mut transcript,
        HandshakeType::ClientHello,
        encode_client_hello(&client_hello),
    )
    .await?;

    let server_hello_blob = recv_handshake_message(&mut io, &mut transcript).await?;
    let server_hello = expect_server_hello(server_hello_blob)?;
    validate_server_hello(&server_hello, &options, required_features)?;

    let server_identity_blob = recv_handshake_message(&mut io, &mut transcript).await?;
    let server_identity_payload = expect_server_identity(server_identity_blob)?;
    let server_identity = crypto.parse_signing_public_key(&server_identity_payload.public_key)?;
    if let Some(expected_server_identity) = &options.expected_server_identity {
        if server_identity.as_slice() != expected_server_identity.as_slice() {
            return Err(HandshakeError::Authentication(
                "server identity does not match expected key",
            ));
        }
    }
    on_server_identity(&server_identity)?;

    let server_kem_blob = recv_handshake_message(&mut io, &mut transcript).await?;
    let server_kem = expect_server_kem_binding(server_kem_blob)?;
    let kem_public_key = crypto.parse_kem_public_key(&server_kem.kem_public_key)?;
    let kem_signature = crypto.parse_signature(&server_kem.signature)?;
    crypto.verify_message(&server_identity, kem_public_key.as_ref(), &kem_signature)?;

    let envelope = crypto.encapsulate(&kem_public_key)?;
    send_handshake_message(
        &mut io,
        &mut transcript,
        HandshakeType::ClientKem,
        encode_client_kem(&ClientKemPayload {
            ciphertext: envelope.ciphertext.as_ref().to_vec(),
        })?,
    )
    .await?;

    let transcript_hash = transcript.finish()?;
    let keys =
        crypto.derive_handshake_session_keys(envelope.shared_secret, transcript_hash, true)?;

    let signature = crypto.sign_message(&options.client_identity.secret_key, &transcript_hash)?;
    send_handshake_message(
        &mut io,
        &mut transcript,
        HandshakeType::ClientAuth,
        encode_client_auth(&ClientAuthPayload {
            public_key: options.client_identity.public_key.as_ref().to_vec(),
            signature: signature.as_ref().to_vec(),
            enrollment_token: options.enrollment_token,
        })?,
    )
    .await?;

    let completion_blob = recv_handshake_message(&mut io, &mut transcript).await?;
    match completion_blob.message_type {
        HandshakeType::Complete => {}
        HandshakeType::EnrollmentRequired => return Err(HandshakeError::EnrollmentRequired),
        HandshakeType::Failure => {
            return Err(HandshakeError::Remote(decode_error_payload(
                &completion_blob.payload,
            )?));
        }
        _ => return Err(HandshakeError::BadState("expected handshake completion")),
    }

    let channel = SecureChannel::new(io, crypto, keys, ConnectionRole::Client, config);
    Ok(ClientHandshakeResult {
        channel,
        summary: ClientHandshakeSummary {
            server_identity,
            server_sandbox: if server_hello.sandboxed {
                SandboxPolicy::Enforced
            } else {
                SandboxPolicy::Disabled
            },
            features: server_hello.features,
        },
    })
}

pub async fn server_handshake<IO, C>(
    io: IO,
    crypto: C,
    options: ServerHandshakeOptions,
    config: TransportConfig,
) -> Result<ServerHandshakeResult<IO, C>, HandshakeError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: HandshakeCryptoProvider<Error = CryptoError>,
{
    let mut io = io;
    let mut transcript = Transcript::new();
    let required_features = HandshakeFeatures {
        download_ack_v1: true,
    };

    let client_hello_blob = recv_handshake_message(&mut io, &mut transcript).await?;
    let client_hello = match expect_client_hello(client_hello_blob) {
        Ok(hello) => hello,
        Err(error) => {
            send_handshake_error(&mut io, error_code_for_handshake_error(&error)).await?;
            return Err(error);
        }
    };
    if let Err(error) = validate_client_hello(&client_hello, &options, required_features) {
        send_handshake_error(&mut io, error_code_for_handshake_error(&error)).await?;
        return Err(error);
    }

    let server_hello = ServerHello {
        version: PROTOCOL_VERSION,
        sandboxed: options.sandbox.is_enforced(),
        features: required_features,
    };
    send_handshake_message(
        &mut io,
        &mut transcript,
        HandshakeType::ServerHello,
        encode_server_hello(&server_hello),
    )
    .await?;

    send_handshake_message(
        &mut io,
        &mut transcript,
        HandshakeType::ServerIdentity,
        encode_server_identity(&ServerIdentityPayload {
            public_key: options.server_identity.public_key.as_ref().to_vec(),
        })?,
    )
    .await?;

    let kem_keypair = crypto.generate_kem_keypair()?;
    let kem_signature = crypto.sign_message(
        &options.server_identity.secret_key,
        kem_keypair.public_key.as_ref(),
    )?;
    send_handshake_message(
        &mut io,
        &mut transcript,
        HandshakeType::ServerKemBinding,
        encode_server_kem_binding(&ServerKemBindingPayload {
            kem_public_key: kem_keypair.public_key.as_ref().to_vec(),
            signature: kem_signature.as_ref().to_vec(),
        })?,
    )
    .await?;

    let client_kem_blob = recv_handshake_message(&mut io, &mut transcript).await?;
    let client_kem = match expect_client_kem(client_kem_blob) {
        Ok(payload) => payload,
        Err(error) => {
            send_handshake_error(&mut io, error_code_for_handshake_error(&error)).await?;
            return Err(error);
        }
    };
    let ciphertext = crypto.parse_kem_ciphertext(&client_kem.ciphertext)?;
    let shared_secret = crypto.decapsulate(&kem_keypair.secret_key, &ciphertext)?;

    let transcript_hash = transcript.finish()?;
    let keys = crypto.derive_handshake_session_keys(shared_secret, transcript_hash, false)?;

    let client_auth_blob = recv_handshake_message(&mut io, &mut transcript).await?;
    let client_auth = match verify_client_auth(&crypto, &transcript_hash, client_auth_blob) {
        Ok(payload) => payload,
        Err(error) => {
            send_handshake_error(&mut io, error_code_for_handshake_error(&error)).await?;
            return Err(error);
        }
    };
    let client_identity = crypto.parse_signing_public_key(&client_auth.public_key)?;

    let trusted = options.client_trust.is_trusted(&client_identity)?;
    if !trusted {
        let enrolled = match client_auth.enrollment_token.as_deref() {
            Some(token) => {
                options
                    .client_trust
                    .try_enroll(&client_identity, token, &options.session_label)?
            }
            None => false,
        };
        if !enrolled {
            options
                .client_trust
                .begin_enrollment(&client_identity, &options.session_label)?;
            send_handshake_message(
                &mut io,
                &mut transcript,
                HandshakeType::EnrollmentRequired,
                Vec::new(),
            )
            .await?;
            return Err(HandshakeError::EnrollmentRequired);
        }
    }

    send_handshake_message(
        &mut io,
        &mut transcript,
        HandshakeType::Complete,
        Vec::new(),
    )
    .await?;

    let channel = SecureChannel::new(io, crypto, keys, ConnectionRole::Server, config);
    Ok(ServerHandshakeResult {
        channel,
        summary: ServerHandshakeSummary {
            client_identity,
            sandbox: options.sandbox,
            features: server_hello.features,
        },
    })
}

pub fn build_nonce(prefix: &[u8; 16], sequence: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

pub fn associated_data(record_type: RecordType, sequence: u64, epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 10 + 5);
    aad.push(record_type as u8);
    aad.extend_from_slice(&encode_uvar(sequence));
    aad.extend_from_slice(&encode_uvar(epoch as u64));
    aad
}

async fn send_handshake_message<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    transcript: &mut Transcript,
    message_type: HandshakeType,
    payload: Vec<u8>,
) -> Result<(), HandshakeError> {
    let encoded = encode_handshake_blob(&HandshakeBlob {
        message_type,
        payload,
    });
    io.write_all(&encoded).await?;
    io.flush().await?;
    transcript.append(&encoded);
    Ok(())
}

async fn send_handshake_error<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    code: ErrorCode,
) -> Result<(), HandshakeError> {
    let encoded = encode_handshake_blob(&HandshakeBlob {
        message_type: HandshakeType::Failure,
        payload: encode_error_payload(code).to_vec(),
    });
    io.write_all(&encoded).await?;
    io.flush().await?;
    Ok(())
}

async fn recv_handshake_message<IO: AsyncRead + Unpin>(
    io: &mut IO,
    transcript: &mut Transcript,
) -> Result<EncodedHandshakeBlob, HandshakeError> {
    let encoded = read_handshake_blob(io).await?;
    let decoded = decode_handshake_blob(&encoded)?;
    if decoded.message_type != HandshakeType::Failure {
        transcript.append(&decoded.encoded);
    }
    Ok(decoded)
}

async fn read_handshake_blob<IO: AsyncRead + Unpin>(
    io: &mut IO,
) -> Result<Vec<u8>, HandshakeError> {
    let mut header = Vec::with_capacity(10);
    let body_len = loop {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte).await?;
        header.push(byte[0]);
        match decode_uvar(&header) {
            Ok((value, used)) if used == header.len() => break value as usize,
            Ok(_) => {}
            Err(CodecError::Truncated) => {}
            Err(error) => return Err(HandshakeError::Codec(error)),
        }
        if header.len() > 10 {
            return Err(HandshakeError::Codec(CodecError::InvalidVarint));
        }
    };

    if body_len == 0 || body_len > crate::protocol::MAX_HANDSHAKE_BLOB_LEN {
        return Err(HandshakeError::Codec(
            CodecError::InvalidHandshakeBlobLength(body_len),
        ));
    }

    let mut body = vec![0u8; body_len];
    io.read_exact(&mut body).await?;

    header.extend_from_slice(&body);
    Ok(header)
}

fn expect_client_hello(blob: EncodedHandshakeBlob) -> Result<ClientHello, HandshakeError> {
    match blob.message_type {
        HandshakeType::ClientHello => Ok(decode_client_hello(&blob.payload)?),
        HandshakeType::Failure => Err(HandshakeError::Remote(decode_error_payload(&blob.payload)?)),
        _ => Err(HandshakeError::BadState("expected client hello")),
    }
}

fn expect_server_hello(blob: EncodedHandshakeBlob) -> Result<ServerHello, HandshakeError> {
    match blob.message_type {
        HandshakeType::ServerHello => Ok(decode_server_hello(&blob.payload)?),
        HandshakeType::Failure => Err(HandshakeError::Remote(decode_error_payload(&blob.payload)?)),
        _ => Err(HandshakeError::BadState("expected server hello")),
    }
}

fn expect_server_identity(
    blob: EncodedHandshakeBlob,
) -> Result<ServerIdentityPayload, HandshakeError> {
    match blob.message_type {
        HandshakeType::ServerIdentity => Ok(decode_server_identity(&blob.payload)?),
        HandshakeType::Failure => Err(HandshakeError::Remote(decode_error_payload(&blob.payload)?)),
        _ => Err(HandshakeError::BadState("expected server identity")),
    }
}

fn expect_server_kem_binding(
    blob: EncodedHandshakeBlob,
) -> Result<ServerKemBindingPayload, HandshakeError> {
    match blob.message_type {
        HandshakeType::ServerKemBinding => Ok(decode_server_kem_binding(&blob.payload)?),
        HandshakeType::Failure => Err(HandshakeError::Remote(decode_error_payload(&blob.payload)?)),
        _ => Err(HandshakeError::BadState("expected server kem binding")),
    }
}

fn expect_client_kem(blob: EncodedHandshakeBlob) -> Result<ClientKemPayload, HandshakeError> {
    match blob.message_type {
        HandshakeType::ClientKem => Ok(decode_client_kem(&blob.payload)?),
        HandshakeType::Failure => Err(HandshakeError::Remote(decode_error_payload(&blob.payload)?)),
        _ => Err(HandshakeError::BadState("expected client kem")),
    }
}

fn verify_client_auth<C: HandshakeCryptoProvider<Error = CryptoError>>(
    crypto: &C,
    transcript_hash: &[u8; 64],
    blob: EncodedHandshakeBlob,
) -> Result<ClientAuthPayload, HandshakeError> {
    let payload = match blob.message_type {
        HandshakeType::ClientAuth => decode_client_auth(&blob.payload)?,
        HandshakeType::Failure => {
            return Err(HandshakeError::Remote(decode_error_payload(&blob.payload)?));
        }
        _ => return Err(HandshakeError::BadState("expected client auth")),
    };

    let client_key = crypto.parse_signing_public_key(&payload.public_key)?;
    let signature = crypto.parse_signature(&payload.signature)?;
    crypto.verify_message(&client_key, transcript_hash, &signature)?;
    Ok(payload)
}

fn validate_server_hello(
    server_hello: &ServerHello,
    _options: &ClientHandshakeOptions,
    required_features: HandshakeFeatures,
) -> Result<(), HandshakeError> {
    if server_hello.version != PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            actual: server_hello.version,
        });
    }
    if !server_hello.features.is_compatible_with(required_features) {
        return Err(HandshakeError::MissingFeature("download_ack_v1"));
    }
    Ok(())
}

fn validate_client_hello(
    client_hello: &ClientHello,
    _options: &ServerHandshakeOptions,
    required_features: HandshakeFeatures,
) -> Result<(), HandshakeError> {
    if client_hello.version != PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            actual: client_hello.version,
        });
    }
    if !client_hello.features.is_compatible_with(required_features) {
        return Err(HandshakeError::MissingFeature("download_ack_v1"));
    }
    Ok(())
}

fn error_code_for_handshake_error(error: &HandshakeError) -> ErrorCode {
    match error {
        HandshakeError::Remote(code) => *code,
        HandshakeError::VersionMismatch { .. } => ErrorCode::Compat,
        HandshakeError::MissingFeature(_) => ErrorCode::Compat,
        HandshakeError::Authentication(_) => ErrorCode::Auth,
        HandshakeError::EnrollmentRequired => ErrorCode::Auth,
        HandshakeError::Codec(_) | HandshakeError::BadState(_) => ErrorCode::BadPayload,
        HandshakeError::Crypto(_) => ErrorCode::Protocol,
        HandshakeError::Io(_) => ErrorCode::Closed,
    }
}

fn slice_to_array_16(input: &[u8]) -> Result<[u8; 16], TransportError> {
    input
        .try_into()
        .map_err(|_| TransportError::Codec(CodecError::Truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DepotCrypto;
    use crate::crypto::{ML_DSA_87_PUBLIC_KEY_LEN, ML_KEM_1024_CIPHERTEXT_LEN};
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use tokio::io::duplex;

    #[derive(Default)]
    struct TestTrustProvider {
        trusted: Mutex<HashSet<Vec<u8>>>,
        pending: Mutex<HashMap<Vec<u8>, String>>,
    }

    impl TestTrustProvider {
        fn with_trusted(public_key: &MlDsa87PublicKey) -> Arc<Self> {
            let mut trusted = HashSet::new();
            trusted.insert(public_key.as_ref().to_vec());
            Arc::new(Self {
                trusted: Mutex::new(trusted),
                pending: Mutex::new(HashMap::new()),
            })
        }

        fn pending_token(
            &self,
            public_key: &MlDsa87PublicKey,
        ) -> Option<String> {
            self.pending
                .lock()
                .unwrap()
                .get(public_key.as_slice())
                .cloned()
        }
    }

    impl ClientTrustProvider for TestTrustProvider {
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
            public_key: &MlDsa87PublicKey,
            _session_label: &str,
        ) -> Result<(), HandshakeError> {
            self.pending
                .lock()
                .unwrap()
                .insert(public_key.as_ref().to_vec(), "TOKEN123".to_owned());
            Ok(())
        }

        fn try_enroll(
            &self,
            public_key: &MlDsa87PublicKey,
            token: &str,
            _session_label: &str,
        ) -> Result<bool, HandshakeError> {
            let key = public_key.as_ref().to_vec();
            let mut pending = self.pending.lock().unwrap();
            if pending.get(&key).is_some_and(|expected| expected == token) {
                pending.remove(&key);
                self.trusted.lock().unwrap().insert(key);
                return Ok(true);
            }
            Ok(false)
        }
    }

    #[tokio::test]
    async fn secure_channel_roundtrip_works() {
        let crypto = DepotCrypto;
        let keys = crypto
            .derive_handshake_session_keys([9u8; 32], [7u8; 64], true)
            .unwrap();
        let inverse = SessionKeys {
            tx_key: keys.rx_key,
            rx_key: keys.tx_key,
            tx_nonce_prefix: keys.rx_nonce_prefix,
            rx_nonce_prefix: keys.tx_nonce_prefix,
            traffic_secret: keys.traffic_secret,
        };

        let (left, right) = duplex(4096);
        let mut client = SecureChannel::new(
            left,
            crypto,
            keys,
            ConnectionRole::Client,
            TransportConfig::default(),
        );
        let mut server = SecureChannel::new(
            right,
            DepotCrypto,
            inverse,
            ConnectionRole::Server,
            TransportConfig::default(),
        );

        client
            .send_record(RecordType::UploadOpen, b"hello")
            .await
            .unwrap();
        let frame = server.recv_record().await.unwrap();
        assert_eq!(frame.record_type, RecordType::UploadOpen);
        assert_eq!(frame.payload, b"hello");
    }

    #[tokio::test]
    async fn detects_authentication_failures() {
        let crypto = DepotCrypto;
        let client_keys = crypto
            .derive_handshake_session_keys([1u8; 32], [2u8; 64], true)
            .unwrap();
        let mut wrong_server_keys = crypto
            .derive_handshake_session_keys([3u8; 32], [2u8; 64], false)
            .unwrap();
        wrong_server_keys.tx_key = client_keys.rx_key;
        wrong_server_keys.tx_nonce_prefix = client_keys.rx_nonce_prefix;

        let (left, right) = duplex(4096);
        let mut client = SecureChannel::new(
            left,
            crypto,
            client_keys,
            ConnectionRole::Client,
            TransportConfig::default(),
        );
        let mut server = SecureChannel::new(
            right,
            DepotCrypto,
            wrong_server_keys,
            ConnectionRole::Server,
            TransportConfig::default(),
        );

        client
            .send_record(RecordType::FileData, b"tamper")
            .await
            .unwrap();
        let error = server.recv_record().await.unwrap_err();
        assert!(matches!(error, TransportError::AuthenticationFailed));
        assert_eq!(
            server.state().last_receive_failure,
            ReceiveFailure::Authentication
        );
    }

    #[tokio::test]
    async fn full_handshake_establishes_secure_channel() {
        let crypto = DepotCrypto;
        let server_identity = crypto.generate_signing_identity().unwrap();
        let expected_server_identity = server_identity.public_key.clone();
        let client_identity = crypto.generate_signing_identity().unwrap();
        let trusted_client = client_identity.public_key.clone();
        let (left, right) = duplex(32768);

        let server_task = tokio::spawn(async move {
            server_handshake(
                right,
                DepotCrypto,
                ServerHandshakeOptions {
                    server_identity,
                    client_trust: TestTrustProvider::with_trusted(&trusted_client),
                    session_label: "test-session".to_owned(),
                    sandbox: SandboxPolicy::Enforced,
                },
                TransportConfig::default(),
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            client_handshake(
                left,
                DepotCrypto,
                ClientHandshakeOptions {
                    expected_server_identity: Some(expected_server_identity),
                    client_identity,
                    enrollment_token: None,
                },
                TransportConfig::default(),
            )
            .await
        });

        let mut server = server_task.await.unwrap().unwrap();
        let mut client = client_task.await.unwrap().unwrap();

        client
            .channel
            .send_record(RecordType::ListOpen, b".")
            .await
            .unwrap();
        let frame = server.channel.recv_record().await.unwrap();
        assert_eq!(frame.record_type, RecordType::ListOpen);
        assert_eq!(frame.payload, b".");
        assert_eq!(client.summary.server_sandbox, SandboxPolicy::Enforced);
        assert_eq!(
            server.summary.client_identity.as_ref().len(),
            ML_DSA_87_PUBLIC_KEY_LEN
        );
    }

    #[tokio::test]
    async fn full_handshake_with_client_auth_works() {
        let crypto = DepotCrypto;
        let server_identity = crypto.generate_signing_identity().unwrap();
        let expected_server_identity = server_identity.public_key.clone();
        let client_identity = crypto.generate_signing_identity().unwrap();
        let trusted_client = client_identity.public_key.clone();
        let (left, right) = duplex(32768);

        let server_task = tokio::spawn(async move {
            server_handshake(
                right,
                DepotCrypto,
                ServerHandshakeOptions {
                    server_identity,
                    client_trust: TestTrustProvider::with_trusted(&trusted_client),
                    session_label: "test-session".to_owned(),
                    sandbox: SandboxPolicy::Disabled,
                },
                TransportConfig::default(),
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            client_handshake(
                left,
                DepotCrypto,
                ClientHandshakeOptions {
                    expected_server_identity: Some(expected_server_identity),
                    client_identity,
                    enrollment_token: None,
                },
                TransportConfig::default(),
            )
            .await
        });

        let server = server_task.await.unwrap().unwrap();
        let client = client_task.await.unwrap().unwrap();

        assert_eq!(client.summary.server_sandbox, SandboxPolicy::Disabled);
        assert_eq!(
            server.summary.client_identity.as_ref().len(),
            ML_DSA_87_PUBLIC_KEY_LEN
        );
    }

    #[tokio::test]
    async fn proposed_rekey_is_acknowledged_and_activates_new_epoch() {
        let crypto = DepotCrypto;
        let keys = crypto
            .derive_handshake_session_keys([9u8; 32], [7u8; 64], true)
            .unwrap();
        let inverse = SessionKeys {
            tx_key: keys.rx_key,
            rx_key: keys.tx_key,
            tx_nonce_prefix: keys.rx_nonce_prefix,
            rx_nonce_prefix: keys.tx_nonce_prefix,
            traffic_secret: keys.traffic_secret,
        };
        let config = TransportConfig {
            rekey_interval: Duration::from_millis(1),
            ..TransportConfig::default()
        };

        let (left, right) = duplex(4096);
        let mut client =
            SecureChannel::new(left, crypto, keys, ConnectionRole::Client, config.clone());
        let mut server = SecureChannel::new(
            right,
            DepotCrypto,
            inverse,
            ConnectionRole::Server,
            config,
        );

        tokio::time::sleep(Duration::from_millis(5)).await;

        let server_task = tokio::spawn(async move {
            server.propose_rekey_and_await().await.unwrap();
            server
                .send_record(RecordType::ListDone, b"post-rekey")
                .await
                .unwrap();
            server
        });

        let rekey = client.recv_record().await.unwrap();
        assert_eq!(rekey.record_type, RecordType::RekeyReq);
        client.handle_rekey_request(&rekey.payload).await.unwrap();

        let post_rekey = client.recv_record().await.unwrap();
        assert_eq!(post_rekey.record_type, RecordType::ListDone);
        assert_eq!(post_rekey.payload, b"post-rekey");
        assert_eq!(client.state().epoch, 1);

        let server = server_task.await.unwrap();
        assert_eq!(server.state().epoch, 1);
    }

    #[tokio::test]
    async fn idle_timeout_surfaces_as_transport_timeout() {
        let crypto = DepotCrypto;
        let keys = crypto
            .derive_handshake_session_keys([9u8; 32], [7u8; 64], true)
            .unwrap();
        let config = TransportConfig {
            io_timeout: Duration::from_millis(10),
            ..TransportConfig::default()
        };
        let (left, _right) = duplex(1024);
        let mut client = SecureChannel::new(left, crypto, keys, ConnectionRole::Client, config);

        tokio::time::sleep(Duration::from_millis(20)).await;
        let error = client
            .send_record(RecordType::ListOpen, b".")
            .await
            .unwrap_err();
        assert!(matches!(error, TransportError::Timeout));
    }

    #[tokio::test]
    async fn rejects_server_identity_mismatch() {
        let crypto = DepotCrypto;
        let server_identity = crypto.generate_signing_identity().unwrap();
        let wrong_server_identity = crypto.generate_signing_identity().unwrap();
        let client_identity = crypto.generate_signing_identity().unwrap();
        let trusted_client = client_identity.public_key.clone();
        let (left, right) = duplex(32768);

        let server_task = tokio::spawn(async move {
            server_handshake(
                right,
                DepotCrypto,
                ServerHandshakeOptions {
                    server_identity,
                    client_trust: TestTrustProvider::with_trusted(&trusted_client),
                    session_label: "test-session".to_owned(),
                    sandbox: SandboxPolicy::Enforced,
                },
                TransportConfig::default(),
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            client_handshake(
                left,
                DepotCrypto,
                ClientHandshakeOptions {
                    expected_server_identity: Some(wrong_server_identity.public_key),
                    client_identity,
                    enrollment_token: None,
                },
                TransportConfig::default(),
            )
            .await
        });

        let client_result = client_task.await.unwrap();
        let client_error = match client_result {
            Ok(_) => panic!("client handshake unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(
            client_error,
            HandshakeError::Authentication("server identity does not match expected key")
        ));

        let server_result = server_task.await.unwrap();
        let server_error = match server_result {
            Ok(_) => panic!("server handshake unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(
            server_error,
            HandshakeError::Io(_) | HandshakeError::Remote(ErrorCode::Closed)
        ));
    }

    #[test]
    fn handshake_ciphertext_size_matches_protocol() {
        assert_eq!(ML_KEM_1024_CIPHERTEXT_LEN, 1568);
    }

    #[tokio::test]
    async fn unknown_client_requires_enrollment_then_accepts_token() {
        let crypto = DepotCrypto;
        let server_identity = crypto.generate_signing_identity().unwrap();
        let expected_server_identity = server_identity.public_key.clone();
        let client_identity = crypto.generate_signing_identity().unwrap();
        let retry_client_identity = client_identity.clone();
        let client_public = client_identity.public_key.clone();
        let trust = Arc::new(TestTrustProvider::default());
        let (left, right) = duplex(32768);

        let server_trust = trust.clone();
        let server_task = tokio::spawn(async move {
            server_handshake(
                right,
                DepotCrypto,
                ServerHandshakeOptions {
                    server_identity,
                    client_trust: server_trust,
                    session_label: "pair-session".to_owned(),
                    sandbox: SandboxPolicy::Enforced,
                },
                TransportConfig::default(),
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            client_handshake(
                left,
                DepotCrypto,
                ClientHandshakeOptions {
                    expected_server_identity: Some(expected_server_identity),
                    client_identity,
                    enrollment_token: None,
                },
                TransportConfig::default(),
            )
            .await
        });

        let client_error = match client_task.await.unwrap() {
            Ok(_) => panic!("client handshake unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(client_error, HandshakeError::EnrollmentRequired));
        let server_error = match server_task.await.unwrap() {
            Ok(_) => panic!("server handshake unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(server_error, HandshakeError::EnrollmentRequired));

        let token = trust.pending_token(&client_public).unwrap();

        let server_identity = crypto.generate_signing_identity().unwrap();
        let expected_server_identity = server_identity.public_key.clone();
        let (left, right) = duplex(32768);
        let server_trust = trust.clone();
        let server_task = tokio::spawn(async move {
            server_handshake(
                right,
                DepotCrypto,
                ServerHandshakeOptions {
                    server_identity,
                    client_trust: server_trust,
                    session_label: "pair-session".to_owned(),
                    sandbox: SandboxPolicy::Enforced,
                },
                TransportConfig::default(),
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            client_handshake(
                left,
                DepotCrypto,
                ClientHandshakeOptions {
                    expected_server_identity: Some(expected_server_identity),
                    client_identity: retry_client_identity,
                    enrollment_token: Some(token),
                },
                TransportConfig::default(),
            )
            .await
        });

        let server = server_task.await.unwrap().unwrap();
        let client = client_task.await.unwrap().unwrap();
        assert_eq!(client.summary.server_sandbox, SandboxPolicy::Enforced);
        assert_eq!(
            server.summary.client_identity.as_ref().len(),
            ML_DSA_87_PUBLIC_KEY_LEN
        );
    }
}
