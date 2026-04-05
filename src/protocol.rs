use bytes::{BufMut, BytesMut};
use crate::core::{ErrorCode, PortablePermission, PortablePermissions, RemotePath};
use std::convert::TryFrom;

pub const MAX_RECORD_BODY_LEN: usize = 16 * 1024 * 1024;
pub const MAX_HANDSHAKE_BLOB_LEN: usize = 1024 * 1024;
pub const PROTOCOL_VERSION: u8 = 3;
pub const FEATURE_DOWNLOAD_ACK_V1: u64 = 1 << 0;
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;
pub const ML_KEM_1024_PUBLIC_KEY_LEN: usize = 1568;
pub const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;
pub const MAX_ENROLLMENT_TOKEN_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    FileData = 0x11,
    FileClose = 0x12,
    ErrorRec = 0x13,
    PathOpen = 0x21,
    PathAccept = 0x22,
    PathSkip = 0x23,
    UploadOpen = 0x30,
    UploadOk = 0x31,
    UploadFail = 0x32,
    UploadDone = 0x33,
    DownloadOpen = 0x40,
    DownloadDone = 0x41,
    ListOpen = 0x50,
    ListChunk = 0x51,
    ListDone = 0x52,
    RekeyReq = 0x60,
    RekeyAck = 0x61,
}

impl TryFrom<u8> for RecordType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x11 => Self::FileData,
            0x12 => Self::FileClose,
            0x13 => Self::ErrorRec,
            0x21 => Self::PathOpen,
            0x22 => Self::PathAccept,
            0x23 => Self::PathSkip,
            0x30 => Self::UploadOpen,
            0x31 => Self::UploadOk,
            0x32 => Self::UploadFail,
            0x33 => Self::UploadDone,
            0x40 => Self::DownloadOpen,
            0x41 => Self::DownloadDone,
            0x50 => Self::ListOpen,
            0x51 => Self::ListChunk,
            0x52 => Self::ListDone,
            0x60 => Self::RekeyReq,
            0x61 => Self::RekeyAck,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 0x00,
    ServerIdentity = 0x01,
    ServerKemBinding = 0x02,
    ClientKem = 0x03,
    ServerHello = 0x04,
    ClientAuth = 0x05,
    Failure = 0x06,
    EnrollmentRequired = 0x07,
    Complete = 0x08,
}

impl TryFrom<u8> for HandshakeType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => Self::ClientHello,
            0x01 => Self::ServerIdentity,
            0x02 => Self::ServerKemBinding,
            0x03 => Self::ClientKem,
            0x04 => Self::ServerHello,
            0x05 => Self::ClientAuth,
            0x06 => Self::Failure,
            0x07 => Self::EnrollmentRequired,
            0x08 => Self::Complete,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HandshakeFeatures {
    pub download_ack_v1: bool,
}

impl HandshakeFeatures {
    pub fn is_compatible_with(self, required: Self) -> bool {
        (!required.download_ack_v1) || self.download_ack_v1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u8,
    pub features: HandshakeFeatures,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u8,
    pub sandboxed: bool,
    pub features: HandshakeFeatures,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentityPayload {
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKemBindingPayload {
    pub kem_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKemPayload {
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthPayload {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub enrollment_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeBlob {
    pub message_type: HandshakeType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedHandshakeBlob {
    pub message_type: HandshakeType,
    pub payload: Vec<u8>,
    pub encoded: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub record_type: RecordType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMetadata {
    pub file_size: u64,
    pub modification_time_unix: u64,
    pub permissions: PortablePermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathOpenPayload {
    pub relative_path: RemotePath,
    pub metadata: FileMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadOpenPayload {
    pub relative_path: RemotePath,
    pub modification_time_unix: u64,
    pub permissions: PortablePermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub relative_path: RemotePath,
    pub file_size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    InvalidVarint,
    Truncated,
    InvalidRecordType(u8),
    InvalidHandshakeType(u8),
    InvalidPermission(u8),
    InvalidHandshakeBlobLength(usize),
    InvalidHandshakePayload(&'static str),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVarint => f.write_str("invalid varint"),
            Self::Truncated => f.write_str("truncated payload"),
            Self::InvalidRecordType(value) => write!(f, "invalid record type {value:#x}"),
            Self::InvalidHandshakeType(value) => write!(f, "invalid handshake type {value:#x}"),
            Self::InvalidPermission(value) => write!(f, "invalid permission ordinal {value}"),
            Self::InvalidHandshakeBlobLength(value) => {
                write!(f, "invalid handshake blob length {value}")
            }
            Self::InvalidHandshakePayload(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CodecError {}

pub fn is_valid_record_body_len(value: usize) -> bool {
    value <= MAX_RECORD_BODY_LEN
}

pub fn is_valid_handshake_blob_len(value: usize) -> bool {
    value > 0 && value <= MAX_HANDSHAKE_BLOB_LEN
}

pub fn encode_uvar(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            output.push(low);
            break;
        }
        output.push(low | 0x80);
    }
    output
}

pub fn decode_uvar(input: &[u8]) -> Result<(u64, usize), CodecError> {
    let mut shift = 0u32;
    let mut value = 0u64;

    for (index, byte) in input.iter().copied().enumerate() {
        let chunk = (byte & 0x7f) as u64;
        value |= chunk << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(CodecError::InvalidVarint);
        }
    }

    Err(CodecError::Truncated)
}

pub fn encode_error_payload(code: ErrorCode) -> [u8; 1] {
    [code as u8]
}

pub fn decode_error_payload(payload: &[u8]) -> Result<ErrorCode, CodecError> {
    if payload.len() != 1 {
        return Err(CodecError::Truncated);
    }

    Ok(match payload[0] {
        0 => ErrorCode::Unknown,
        1 => ErrorCode::Exists,
        2 => ErrorCode::Filter,
        3 => ErrorCode::NoSpace,
        4 => ErrorCode::Perms,
        5 => ErrorCode::Absolute,
        6 => ErrorCode::UnsafePath,
        7 => ErrorCode::BadPath,
        8 => ErrorCode::BadPayload,
        9 => ErrorCode::OpenFail,
        10 => ErrorCode::WriteFail,
        11 => ErrorCode::ReadFail,
        12 => ErrorCode::NotFound,
        13 => ErrorCode::Timeout,
        14 => ErrorCode::Checksum,
        15 => ErrorCode::Closed,
        16 => ErrorCode::Connect,
        17 => ErrorCode::Protocol,
        18 => ErrorCode::CommitFail,
        19 => ErrorCode::Conflict,
        20 => ErrorCode::BadRemote,
        21 => ErrorCode::Config,
        22 => ErrorCode::Compat,
        23 => ErrorCode::Auth,
        _ => ErrorCode::Unknown,
    })
}

pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(1 + frame.payload.len());
    body.put_u8(frame.record_type as u8);
    body.extend_from_slice(&frame.payload);

    let mut encoded = encode_uvar(body.len() as u64);
    encoded.extend_from_slice(&body);
    encoded
}

pub fn encode_handshake_blob(blob: &HandshakeBlob) -> Vec<u8> {
    let mut body = BytesMut::with_capacity(1 + blob.payload.len());
    body.put_u8(blob.message_type as u8);
    body.extend_from_slice(&blob.payload);

    let mut encoded = encode_uvar(body.len() as u64);
    encoded.extend_from_slice(&body);
    encoded
}

pub fn decode_handshake_blob(encoded: &[u8]) -> Result<EncodedHandshakeBlob, CodecError> {
    let (body_len, header_len) = decode_uvar(encoded)?;
    let body_len = body_len as usize;
    if !is_valid_handshake_blob_len(body_len) {
        return Err(CodecError::InvalidHandshakeBlobLength(body_len));
    }
    if encoded.len() != header_len + body_len {
        return Err(CodecError::Truncated);
    }
    let body = &encoded[header_len..];
    let message_type =
        HandshakeType::try_from(body[0]).map_err(|_| CodecError::InvalidHandshakeType(body[0]))?;

    Ok(EncodedHandshakeBlob {
        message_type,
        payload: body[1..].to_vec(),
        encoded: encoded.to_vec(),
    })
}

pub fn encode_client_hello(hello: &ClientHello) -> Vec<u8> {
    vec![hello.version, 0, encode_features(hello.features) as u8]
}

pub fn decode_client_hello(payload: &[u8]) -> Result<ClientHello, CodecError> {
    if payload.len() != 3 {
        return Err(CodecError::InvalidHandshakePayload(
            "client hello payload has invalid size",
        ));
    }

    Ok(ClientHello {
        version: payload[0],
        features: decode_features(payload[2] as u64),
    })
}

pub fn encode_server_hello(hello: &ServerHello) -> Vec<u8> {
    let mut flags = 0u8;
    if hello.sandboxed {
        flags |= 1 << 0;
    }

    vec![hello.version, flags, encode_features(hello.features) as u8]
}

pub fn decode_server_hello(payload: &[u8]) -> Result<ServerHello, CodecError> {
    if payload.len() != 3 {
        return Err(CodecError::InvalidHandshakePayload(
            "server hello payload has invalid size",
        ));
    }

    Ok(ServerHello {
        version: payload[0],
        sandboxed: payload[1] & (1 << 0) != 0,
        features: decode_features(payload[2] as u64),
    })
}

pub fn encode_server_identity(payload: &ServerIdentityPayload) -> Result<Vec<u8>, CodecError> {
    if payload.public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "server identity public key has invalid size",
        ));
    }
    Ok(payload.public_key.clone())
}

pub fn decode_server_identity(payload: &[u8]) -> Result<ServerIdentityPayload, CodecError> {
    if payload.len() != ML_DSA_87_PUBLIC_KEY_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "server identity payload has invalid size",
        ));
    }

    Ok(ServerIdentityPayload {
        public_key: payload.to_vec(),
    })
}

pub fn encode_server_kem_binding(payload: &ServerKemBindingPayload) -> Result<Vec<u8>, CodecError> {
    if payload.kem_public_key.len() != ML_KEM_1024_PUBLIC_KEY_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "server kem public key has invalid size",
        ));
    }
    if payload.signature.len() != ML_DSA_87_SIGNATURE_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "server kem signature has invalid size",
        ));
    }

    let mut encoded = Vec::with_capacity(payload.kem_public_key.len() + payload.signature.len());
    encoded.extend_from_slice(&payload.kem_public_key);
    encoded.extend_from_slice(&payload.signature);
    Ok(encoded)
}

pub fn decode_server_kem_binding(payload: &[u8]) -> Result<ServerKemBindingPayload, CodecError> {
    if payload.len() != ML_KEM_1024_PUBLIC_KEY_LEN + ML_DSA_87_SIGNATURE_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "server kem binding payload has invalid size",
        ));
    }

    Ok(ServerKemBindingPayload {
        kem_public_key: payload[..ML_KEM_1024_PUBLIC_KEY_LEN].to_vec(),
        signature: payload[ML_KEM_1024_PUBLIC_KEY_LEN..].to_vec(),
    })
}

pub fn encode_client_kem(payload: &ClientKemPayload) -> Result<Vec<u8>, CodecError> {
    if payload.ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "client kem ciphertext has invalid size",
        ));
    }
    Ok(payload.ciphertext.clone())
}

pub fn decode_client_kem(payload: &[u8]) -> Result<ClientKemPayload, CodecError> {
    if payload.len() != ML_KEM_1024_CIPHERTEXT_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "client kem payload has invalid size",
        ));
    }

    Ok(ClientKemPayload {
        ciphertext: payload.to_vec(),
    })
}

pub fn encode_client_auth(payload: &ClientAuthPayload) -> Result<Vec<u8>, CodecError> {
    if payload.public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "client auth public key has invalid size",
        ));
    }
    if payload.signature.len() != ML_DSA_87_SIGNATURE_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "client auth signature has invalid size",
        ));
    }

    let token_bytes = payload
        .enrollment_token
        .as_ref()
        .map(|value| value.as_bytes())
        .unwrap_or_default();
    if token_bytes.len() > MAX_ENROLLMENT_TOKEN_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "client auth enrollment token is too long",
        ));
    }

    let mut encoded = Vec::with_capacity(
        payload.public_key.len()
            + payload.signature.len()
            + encode_uvar(token_bytes.len() as u64).len()
            + token_bytes.len(),
    );
    encoded.extend_from_slice(&payload.public_key);
    encoded.extend_from_slice(&payload.signature);
    encoded.extend_from_slice(&encode_uvar(token_bytes.len() as u64));
    encoded.extend_from_slice(token_bytes);
    Ok(encoded)
}

pub fn decode_client_auth(payload: &[u8]) -> Result<ClientAuthPayload, CodecError> {
    if payload.len() < ML_DSA_87_PUBLIC_KEY_LEN + ML_DSA_87_SIGNATURE_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "client auth payload has invalid size",
        ));
    }

    let token_offset = ML_DSA_87_PUBLIC_KEY_LEN + ML_DSA_87_SIGNATURE_LEN;
    let (token_len, used) = decode_uvar(&payload[token_offset..])?;
    let token_len = usize::try_from(token_len)
        .map_err(|_| CodecError::InvalidHandshakePayload("client auth token length overflow"))?;
    if token_len > MAX_ENROLLMENT_TOKEN_LEN {
        return Err(CodecError::InvalidHandshakePayload(
            "client auth enrollment token is too long",
        ));
    }
    let token_start = token_offset + used;
    let token_end = token_start + token_len;
    if token_end != payload.len() {
        return Err(CodecError::InvalidHandshakePayload(
            "client auth payload has trailing data",
        ));
    }
    let enrollment_token = if token_len == 0 {
        None
    } else {
        Some(
            std::str::from_utf8(&payload[token_start..token_end])
                .map_err(|_| {
                    CodecError::InvalidHandshakePayload(
                        "client auth enrollment token is not valid utf-8",
                    )
                })?
                .to_owned(),
        )
    };

    Ok(ClientAuthPayload {
        public_key: payload[..ML_DSA_87_PUBLIC_KEY_LEN].to_vec(),
        signature: payload[ML_DSA_87_PUBLIC_KEY_LEN..token_offset].to_vec(),
        enrollment_token,
    })
}

pub fn encode_path_open(payload: &PathOpenPayload) -> Vec<u8> {
    let mut encoded = encode_uvar(payload.relative_path.as_str().len() as u64);
    encoded.extend_from_slice(payload.relative_path.as_str().as_bytes());
    encoded.extend_from_slice(&encode_uvar(payload.metadata.file_size));
    encoded.extend_from_slice(&encode_uvar(payload.metadata.modification_time_unix));

    let mut permission_bytes = Vec::new();
    for permission in [
        PortablePermission::UserRead,
        PortablePermission::UserWrite,
        PortablePermission::UserExec,
        PortablePermission::GroupRead,
        PortablePermission::GroupWrite,
        PortablePermission::GroupExec,
        PortablePermission::OtherRead,
        PortablePermission::OtherWrite,
        PortablePermission::OtherExec,
    ] {
        if payload.metadata.permissions.contains(permission) {
            permission_bytes.push(permission as u8);
        }
    }

    encoded.extend_from_slice(&encode_uvar(permission_bytes.len() as u64));
    encoded.extend_from_slice(&permission_bytes);
    encoded
}

pub fn encode_upload_open(payload: &UploadOpenPayload) -> Vec<u8> {
    let mut encoded = encode_path_param(&payload.relative_path);
    encoded.extend_from_slice(&encode_uvar(payload.modification_time_unix));

    let mut permission_bytes = Vec::new();
    for permission in [
        PortablePermission::UserRead,
        PortablePermission::UserWrite,
        PortablePermission::UserExec,
        PortablePermission::GroupRead,
        PortablePermission::GroupWrite,
        PortablePermission::GroupExec,
        PortablePermission::OtherRead,
        PortablePermission::OtherWrite,
        PortablePermission::OtherExec,
    ] {
        if payload.permissions.contains(permission) {
            permission_bytes.push(permission as u8);
        }
    }

    encoded.extend_from_slice(&encode_uvar(permission_bytes.len() as u64));
    encoded.extend_from_slice(&permission_bytes);
    encoded
}

pub fn encode_path_param(path: &RemotePath) -> Vec<u8> {
    let mut encoded = encode_uvar(path.as_str().len() as u64);
    encoded.extend_from_slice(path.as_str().as_bytes());
    encoded
}

pub fn decode_path_param(payload: &[u8], offset: usize) -> Result<(RemotePath, usize), CodecError> {
    let (path_len, next_offset) = decode_uvar(&payload[offset..])?;
    let path_len = path_len as usize;
    let start = offset + next_offset;
    let end = start + path_len;
    if payload.len() < end {
        return Err(CodecError::Truncated);
    }
    let path = std::str::from_utf8(&payload[start..end]).map_err(|_| CodecError::Truncated)?;
    Ok((RemotePath::new(path), end))
}

pub fn decode_path_open(payload: &[u8]) -> Result<PathOpenPayload, CodecError> {
    let (path_len, mut offset) = decode_uvar(payload)?;
    let path_len = path_len as usize;
    if payload.len() < offset + path_len {
        return Err(CodecError::Truncated);
    }

    let relative_path = std::str::from_utf8(&payload[offset..offset + path_len])
        .map_err(|_| CodecError::Truncated)?;
    offset += path_len;

    let (file_size, next) = decode_uvar(&payload[offset..])?;
    offset += next;
    let (modification_time_unix, next) = decode_uvar(&payload[offset..])?;
    offset += next;
    let (permission_count, next) = decode_uvar(&payload[offset..])?;
    offset += next;
    let permission_count = permission_count as usize;

    if payload.len() < offset + permission_count {
        return Err(CodecError::Truncated);
    }

    let mut permissions = PortablePermissions::empty();
    for ordinal in &payload[offset..offset + permission_count] {
        match *ordinal {
            0 => permissions.insert(PortablePermission::UserRead),
            1 => permissions.insert(PortablePermission::UserWrite),
            2 => permissions.insert(PortablePermission::UserExec),
            3 => permissions.insert(PortablePermission::GroupRead),
            4 => permissions.insert(PortablePermission::GroupWrite),
            5 => permissions.insert(PortablePermission::GroupExec),
            6 => permissions.insert(PortablePermission::OtherRead),
            7 => permissions.insert(PortablePermission::OtherWrite),
            8 => permissions.insert(PortablePermission::OtherExec),
            other => return Err(CodecError::InvalidPermission(other)),
        }
    }

    Ok(PathOpenPayload {
        relative_path: RemotePath::new(relative_path),
        metadata: FileMetadata {
            file_size,
            modification_time_unix,
            permissions,
        },
    })
}

pub fn decode_upload_open(payload: &[u8]) -> Result<UploadOpenPayload, CodecError> {
    let (relative_path, mut offset) = decode_path_param(payload, 0)?;
    let (modification_time_unix, next_offset) = decode_uvar(&payload[offset..])?;
    offset += next_offset;
    let (permission_count, next_offset) = decode_uvar(&payload[offset..])?;
    offset += next_offset;
    let permission_count = permission_count as usize;

    if payload.len() < offset + permission_count {
        return Err(CodecError::Truncated);
    }

    let mut permissions = PortablePermissions::empty();
    for ordinal in &payload[offset..offset + permission_count] {
        match *ordinal {
            0 => permissions.insert(PortablePermission::UserRead),
            1 => permissions.insert(PortablePermission::UserWrite),
            2 => permissions.insert(PortablePermission::UserExec),
            3 => permissions.insert(PortablePermission::GroupRead),
            4 => permissions.insert(PortablePermission::GroupWrite),
            5 => permissions.insert(PortablePermission::GroupExec),
            6 => permissions.insert(PortablePermission::OtherRead),
            7 => permissions.insert(PortablePermission::OtherWrite),
            8 => permissions.insert(PortablePermission::OtherExec),
            other => return Err(CodecError::InvalidPermission(other)),
        }
    }

    Ok(UploadOpenPayload {
        relative_path,
        modification_time_unix,
        permissions,
    })
}

pub fn encode_list_item(entry: &ListEntry) -> Vec<u8> {
    let mut encoded = encode_path_param(&entry.relative_path);
    encoded.extend_from_slice(&encode_uvar(entry.file_size));
    encoded.push(if entry.is_dir { 1 } else { 0 });
    encoded
}

pub fn encode_list_chunk(entries: &[ListEntry]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for entry in entries {
        encoded.extend_from_slice(&encode_list_item(entry));
    }
    encoded
}

pub fn decode_list_chunk(payload: &[u8]) -> Result<Vec<ListEntry>, CodecError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < payload.len() {
        let (relative_path, next_offset) = decode_path_param(payload, offset)?;
        if next_offset >= payload.len() {
            return Err(CodecError::Truncated);
        }
        let (file_size, next_size_offset) = decode_uvar(&payload[next_offset..])?;
        let kind_offset = next_offset + next_size_offset;
        if kind_offset >= payload.len() {
            return Err(CodecError::Truncated);
        }

        entries.push(ListEntry {
            relative_path,
            file_size,
            is_dir: payload[kind_offset] == 1,
        });
        offset = kind_offset + 1;
    }

    Ok(entries)
}

fn encode_features(features: HandshakeFeatures) -> u64 {
    let mut flags = 0u64;
    if features.download_ack_v1 {
        flags |= FEATURE_DOWNLOAD_ACK_V1;
    }
    flags
}

fn decode_features(flags: u64) -> HandshakeFeatures {
    HandshakeFeatures {
        download_ack_v1: flags & FEATURE_DOWNLOAD_ACK_V1 != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_blob_roundtrip_works() {
        let encoded = encode_handshake_blob(&HandshakeBlob {
            message_type: HandshakeType::ClientHello,
            payload: encode_client_hello(&ClientHello {
                version: PROTOCOL_VERSION,
                features: HandshakeFeatures {
                    download_ack_v1: true,
                },
            }),
        });

        let decoded = decode_handshake_blob(&encoded).unwrap();
        assert_eq!(decoded.encoded, encoded);
        assert_eq!(decoded.message_type, HandshakeType::ClientHello);
        assert_eq!(
            decode_client_hello(&decoded.payload).unwrap(),
            ClientHello {
                version: PROTOCOL_VERSION,
                features: HandshakeFeatures {
                    download_ack_v1: true,
                },
            }
        );
    }

    #[test]
    fn server_kem_binding_roundtrip_works() {
        let payload = ServerKemBindingPayload {
            kem_public_key: vec![1u8; ML_KEM_1024_PUBLIC_KEY_LEN],
            signature: vec![2u8; ML_DSA_87_SIGNATURE_LEN],
        };

        let encoded = encode_server_kem_binding(&payload).unwrap();
        let decoded = decode_server_kem_binding(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn client_auth_payload_roundtrip_works() {
        let payload = ClientAuthPayload {
            public_key: vec![3u8; ML_DSA_87_PUBLIC_KEY_LEN],
            signature: vec![4u8; ML_DSA_87_SIGNATURE_LEN],
            enrollment_token: Some("ABCD-EF12".to_owned()),
        };

        let encoded = encode_client_auth(&payload).unwrap();
        let decoded = decode_client_auth(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn list_chunk_roundtrip_works() {
        let entries = vec![
            ListEntry {
                relative_path: RemotePath::new("movie.mkv"),
                file_size: 123,
                is_dir: false,
            },
            ListEntry {
                relative_path: RemotePath::new("extras"),
                file_size: 0,
                is_dir: true,
            },
        ];

        let encoded = encode_list_chunk(&entries);
        let decoded = decode_list_chunk(&encoded).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn upload_open_roundtrip_works() {
        let mut permissions = PortablePermissions::empty();
        permissions.insert(PortablePermission::UserRead);
        permissions.insert(PortablePermission::UserWrite);
        let payload = UploadOpenPayload {
            relative_path: RemotePath::new("incoming/file.txt"),
            modification_time_unix: 1_717_171_717,
            permissions,
        };

        let encoded = encode_upload_open(&payload);
        let decoded = decode_upload_open(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
