use latebra::aead::{
    SealedXChaCha20Poly1305Message, XChaCha20Poly1305Tag, open_with_xchacha20_poly1305,
    seal_with_xchacha20_poly1305,
};
use latebra::hash::Blake3;
use latebra::kdf::{Argon2, Argon2Mode, Argon2Parameters};
use latebra::kem::{
    MlKem1024, MlKem1024Ciphertext, MlKem1024Envelope, MlKem1024KeyPair, MlKem1024PublicKey,
    MlKem1024SecretKey, generate_ml_kem_1024_keypair,
};
use latebra::signature::{
    MlDsa87, MlDsa87KeyPair, MlDsa87PublicKey, MlDsa87SecretKey, MlDsa87Signature,
    generate_ml_dsa_87_keypair,
};

pub use latebra;

const TRAFFIC_SECRET_INFO: &[u8] = b"depot/traffic-secret";
const C2S_KEY_INFO: &[u8] = b"depot/session/c2s/key";
const C2S_NONCE_INFO: &[u8] = b"depot/session/c2s/nonce";
const S2C_KEY_INFO: &[u8] = b"depot/session/s2c/key";
const S2C_NONCE_INFO: &[u8] = b"depot/session/s2c/nonce";
const REKEY_C2S_INFO: &[u8] = b"depot/session/rekey/c2s";
const REKEY_S2C_INFO: &[u8] = b"depot/session/rekey/s2c";
const DPK1_MAGIC: &[u8; 4] = b"DPK1";
const DPK1_SALT_LEN: usize = 16;
const DPK1_NONCE_LEN: usize = 24;
const DPK1_TAG_LEN: usize = 16;
const ARGON2_LIVE_TIME_COST: u32 = 3;
const ARGON2_LIVE_MEMORY_KIB: u32 = 131072;
const ARGON2_LIVE_LANES: u32 = 1;
const ARGON2_DPK1_TIME_COST: u32 = 4;
const ARGON2_DPK1_MEMORY_KIB: u32 = 262144;
const ARGON2_DPK1_LANES: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    pub tx_nonce_prefix: [u8; 16],
    pub rx_nonce_prefix: [u8; 16],
    pub traffic_secret: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyMaterial {
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    pub tx_nonce_prefix: [u8; 16],
    pub rx_nonce_prefix: [u8; 16],
    pub epoch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn append(&mut self, data: impl AsRef<[u8]>) {
        let data = data.as_ref();
        self.bytes
            .extend_from_slice(&(data.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(data);
    }

    pub fn finish(&self) -> Result<[u8; 64], CryptoError> {
        let mut hasher = Blake3::new();
        hasher.update(&self.bytes);
        let mut output = [0u8; 64];
        hasher.finalize_xof().squeeze_into(&mut output);
        Ok(output)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningIdentity {
    pub public_key: MlDsa87PublicKey,
    pub secret_key: MlDsa87SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemKeypair {
    pub public_key: MlKem1024PublicKey,
    pub secret_key: MlKem1024SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemEnvelope {
    pub ciphertext: MlKem1024Ciphertext,
    pub shared_secret: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedSecret {
    bytes: Vec<u8>,
}

impl EncryptedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug)]
pub enum CryptoError {
    Latebra(latebra::LatebraError),
    InvalidLength { expected: usize, actual: usize },
    InvalidEncryptedSecret,
    Random(std::io::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Latebra(error) => write!(f, "{error}"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected}, got {actual}")
            }
            Self::InvalidEncryptedSecret => f.write_str("invalid encrypted secret"),
            Self::Random(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<latebra::LatebraError> for CryptoError {
    fn from(value: latebra::LatebraError) -> Self {
        Self::Latebra(value)
    }
}

pub trait CryptoProvider {
    type Error: std::error::Error + Send + Sync + 'static;

    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        payload: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), Self::Error>;

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Self::Error>;

    fn derive_rekey(
        &self,
        traffic_secret: &[u8; 32],
        epoch: u32,
        outbound_is_client_to_server: bool,
    ) -> Result<RekeyMaterial, Self::Error>;
}

pub trait HandshakeCryptoProvider: CryptoProvider<Error = CryptoError> {
    fn parse_signing_secret_key(&self, bytes: &[u8]) -> Result<MlDsa87SecretKey, CryptoError>;
    fn parse_signing_public_key(&self, bytes: &[u8]) -> Result<MlDsa87PublicKey, CryptoError>;
    fn derive_signing_public_key(
        &self,
        secret_key: &MlDsa87SecretKey,
    ) -> Result<MlDsa87PublicKey, CryptoError>;
    fn parse_signature(&self, bytes: &[u8]) -> Result<MlDsa87Signature, CryptoError>;
    fn parse_kem_public_key(&self, bytes: &[u8]) -> Result<MlKem1024PublicKey, CryptoError>;
    fn parse_kem_ciphertext(&self, bytes: &[u8]) -> Result<MlKem1024Ciphertext, CryptoError>;
    fn generate_signing_identity(&self) -> Result<SigningIdentity, CryptoError>;
    fn generate_kem_keypair(&self) -> Result<KemKeypair, CryptoError>;
    fn sign_message(
        &self,
        secret_key: &MlDsa87SecretKey,
        message: &[u8],
    ) -> Result<MlDsa87Signature, CryptoError>;
    fn verify_message(
        &self,
        public_key: &MlDsa87PublicKey,
        message: &[u8],
        signature: &MlDsa87Signature,
    ) -> Result<(), CryptoError>;
    fn encapsulate(&self, public_key: &MlKem1024PublicKey) -> Result<KemEnvelope, CryptoError>;
    fn decapsulate(
        &self,
        secret_key: &MlKem1024SecretKey,
        ciphertext: &MlKem1024Ciphertext,
    ) -> Result<[u8; 32], CryptoError>;
    fn derive_handshake_session_keys(
        &self,
        shared_secret: [u8; 32],
        transcript_hash: [u8; 64],
        outbound_is_client_to_server: bool,
    ) -> Result<SessionKeys, CryptoError>;
    fn encrypt_secret(
        &self,
        plaintext: &[u8],
        passphrase: &[u8],
    ) -> Result<EncryptedSecret, CryptoError>;
    fn decrypt_secret(&self, encrypted: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LatebraCrypto;

impl LatebraCrypto {
    pub fn parse_signing_secret_key(&self, bytes: &[u8]) -> Result<MlDsa87SecretKey, CryptoError> {
        let bytes = to_array_4896(bytes)?;
        Ok(MlDsa87SecretKey::new(bytes))
    }

    pub fn parse_signing_public_key(&self, bytes: &[u8]) -> Result<MlDsa87PublicKey, CryptoError> {
        let bytes = to_array_2592(bytes)?;
        Ok(MlDsa87PublicKey::new(bytes))
    }

    pub fn derive_signing_public_key(
        &self,
        secret_key: &MlDsa87SecretKey,
    ) -> Result<MlDsa87PublicKey, CryptoError> {
        MlDsa87::derive_public_key(secret_key.clone()).map_err(CryptoError::Latebra)
    }

    pub fn parse_signature(&self, bytes: &[u8]) -> Result<MlDsa87Signature, CryptoError> {
        let bytes = to_array_4627(bytes)?;
        Ok(MlDsa87Signature::new(bytes))
    }

    pub fn parse_kem_public_key(&self, bytes: &[u8]) -> Result<MlKem1024PublicKey, CryptoError> {
        MlKem1024PublicKey::from_slice(bytes).map_err(CryptoError::Latebra)
    }

    pub fn parse_kem_ciphertext(&self, bytes: &[u8]) -> Result<MlKem1024Ciphertext, CryptoError> {
        MlKem1024Ciphertext::from_slice(bytes).map_err(CryptoError::Latebra)
    }

    pub fn encrypt_secret(
        &self,
        plaintext: &[u8],
        passphrase: &[u8],
    ) -> Result<EncryptedSecret, CryptoError> {
        let mut salt = [0u8; DPK1_SALT_LEN];
        fill_random_bytes(&mut salt)?;
        let mut nonce = [0u8; DPK1_NONCE_LEN];
        fill_random_bytes(&mut nonce)?;
        let key = dpk1_key(passphrase, &salt)?;
        let sealed = seal_with_xchacha20_poly1305(&key, &nonce, DPK1_MAGIC, plaintext)
            .map_err(CryptoError::Latebra)?;

        let mut bytes = Vec::with_capacity(
            4 + 4 + DPK1_SALT_LEN + DPK1_NONCE_LEN + plaintext.len() + DPK1_TAG_LEN,
        );
        bytes.extend_from_slice(DPK1_MAGIC);
        bytes.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&sealed.ciphertext);
        bytes.extend_from_slice(sealed.tag.as_bytes());
        Ok(EncryptedSecret { bytes })
    }

    pub fn decrypt_secret(
        &self,
        encrypted: &[u8],
        passphrase: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if encrypted.len() < 4 + 4 + DPK1_SALT_LEN + DPK1_NONCE_LEN + DPK1_TAG_LEN {
            return Err(CryptoError::InvalidEncryptedSecret);
        }
        if &encrypted[..4] != DPK1_MAGIC {
            return Err(CryptoError::InvalidEncryptedSecret);
        }
        let expected_len = u32::from_le_bytes(
            encrypted[4..8]
                .try_into()
                .map_err(|_| CryptoError::InvalidEncryptedSecret)?,
        ) as usize;
        let salt_start = 8;
        let nonce_start = salt_start + DPK1_SALT_LEN;
        let ciphertext_start = nonce_start + DPK1_NONCE_LEN;
        let ciphertext_end = ciphertext_start + expected_len;
        let tag_end = ciphertext_end + DPK1_TAG_LEN;
        if encrypted.len() != tag_end {
            return Err(CryptoError::InvalidEncryptedSecret);
        }

        let salt: [u8; DPK1_SALT_LEN] = encrypted[salt_start..nonce_start]
            .try_into()
            .map_err(|_| CryptoError::InvalidEncryptedSecret)?;
        let nonce: [u8; DPK1_NONCE_LEN] = encrypted[nonce_start..ciphertext_start]
            .try_into()
            .map_err(|_| CryptoError::InvalidEncryptedSecret)?;
        let key = dpk1_key(passphrase, &salt)?;
        let sealed = SealedXChaCha20Poly1305Message {
            ciphertext: encrypted[ciphertext_start..ciphertext_end].to_vec(),
            tag: XChaCha20Poly1305Tag::new(
                encrypted[ciphertext_end..tag_end]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidEncryptedSecret)?,
            ),
        };
        open_with_xchacha20_poly1305(&key, &nonce, DPK1_MAGIC, &sealed)
            .map_err(CryptoError::Latebra)
    }
}

impl HandshakeCryptoProvider for LatebraCrypto {
    fn parse_signing_secret_key(&self, bytes: &[u8]) -> Result<MlDsa87SecretKey, CryptoError> {
        Self::parse_signing_secret_key(self, bytes)
    }

    fn parse_signing_public_key(&self, bytes: &[u8]) -> Result<MlDsa87PublicKey, CryptoError> {
        Self::parse_signing_public_key(self, bytes)
    }

    fn derive_signing_public_key(
        &self,
        secret_key: &MlDsa87SecretKey,
    ) -> Result<MlDsa87PublicKey, CryptoError> {
        Self::derive_signing_public_key(self, secret_key)
    }

    fn parse_signature(&self, bytes: &[u8]) -> Result<MlDsa87Signature, CryptoError> {
        Self::parse_signature(self, bytes)
    }

    fn parse_kem_public_key(&self, bytes: &[u8]) -> Result<MlKem1024PublicKey, CryptoError> {
        Self::parse_kem_public_key(self, bytes)
    }

    fn parse_kem_ciphertext(&self, bytes: &[u8]) -> Result<MlKem1024Ciphertext, CryptoError> {
        Self::parse_kem_ciphertext(self, bytes)
    }

    fn generate_signing_identity(&self) -> Result<SigningIdentity, CryptoError> {
        let MlDsa87KeyPair {
            public_key,
            secret_key,
        } = generate_ml_dsa_87_keypair().map_err(CryptoError::Latebra)?;
        Ok(SigningIdentity {
            public_key,
            secret_key,
        })
    }

    fn generate_kem_keypair(&self) -> Result<KemKeypair, CryptoError> {
        let MlKem1024KeyPair {
            public_key,
            secret_key,
        } = generate_ml_kem_1024_keypair().map_err(CryptoError::Latebra)?;
        Ok(KemKeypair {
            public_key,
            secret_key,
        })
    }

    fn sign_message(
        &self,
        secret_key: &MlDsa87SecretKey,
        message: &[u8],
    ) -> Result<MlDsa87Signature, CryptoError> {
        latebra::signature::sign_message_with_ml_dsa_87(secret_key.as_bytes(), message)
            .map_err(CryptoError::Latebra)
    }

    fn verify_message(
        &self,
        public_key: &MlDsa87PublicKey,
        message: &[u8],
        signature: &MlDsa87Signature,
    ) -> Result<(), CryptoError> {
        latebra::signature::verify_message_with_ml_dsa_87(
            public_key.as_bytes(),
            message,
            signature.as_bytes(),
        )
        .map_err(CryptoError::Latebra)
    }

    fn encapsulate(&self, public_key: &MlKem1024PublicKey) -> Result<KemEnvelope, CryptoError> {
        let MlKem1024Envelope {
            ciphertext,
            shared_secret,
        } = MlKem1024::encapsulate(public_key.clone()).map_err(CryptoError::Latebra)?;

        Ok(KemEnvelope {
            ciphertext,
            shared_secret: shared_secret.into_bytes(),
        })
    }

    fn decapsulate(
        &self,
        secret_key: &MlKem1024SecretKey,
        ciphertext: &MlKem1024Ciphertext,
    ) -> Result<[u8; 32], CryptoError> {
        Ok(
            MlKem1024::decapsulate(secret_key.clone(), ciphertext.clone())
                .map_err(CryptoError::Latebra)?
                .into_bytes(),
        )
    }

    fn derive_handshake_session_keys(
        &self,
        shared_secret: [u8; 32],
        transcript_hash: [u8; 64],
        outbound_is_client_to_server: bool,
    ) -> Result<SessionKeys, CryptoError> {
        let traffic_secret = argon2_domain_kdf(
            &shared_secret,
            &transcript_hash,
            TRAFFIC_SECRET_INFO,
            32,
            argon2_live_parameters(32)?,
        )?;

        let c2s_key = argon2_domain_kdf(
            &traffic_secret,
            &transcript_hash,
            C2S_KEY_INFO,
            32,
            argon2_live_parameters(32)?,
        )?;
        let c2s_nonce = argon2_domain_kdf(
            &traffic_secret,
            &transcript_hash,
            C2S_NONCE_INFO,
            16,
            argon2_live_parameters(16)?,
        )?;
        let s2c_key = argon2_domain_kdf(
            &traffic_secret,
            &transcript_hash,
            S2C_KEY_INFO,
            32,
            argon2_live_parameters(32)?,
        )?;
        let s2c_nonce = argon2_domain_kdf(
            &traffic_secret,
            &transcript_hash,
            S2C_NONCE_INFO,
            16,
            argon2_live_parameters(16)?,
        )?;

        let (tx_key, tx_nonce_prefix, rx_key, rx_nonce_prefix) = if outbound_is_client_to_server {
            (
                to_array_32(&c2s_key)?,
                to_array_16(&c2s_nonce)?,
                to_array_32(&s2c_key)?,
                to_array_16(&s2c_nonce)?,
            )
        } else {
            (
                to_array_32(&s2c_key)?,
                to_array_16(&s2c_nonce)?,
                to_array_32(&c2s_key)?,
                to_array_16(&c2s_nonce)?,
            )
        };

        Ok(SessionKeys {
            tx_key,
            rx_key,
            tx_nonce_prefix,
            rx_nonce_prefix,
            traffic_secret,
        })
    }

    fn encrypt_secret(
        &self,
        plaintext: &[u8],
        passphrase: &[u8],
    ) -> Result<EncryptedSecret, CryptoError> {
        Self::encrypt_secret(self, plaintext, passphrase)
    }

    fn decrypt_secret(&self, encrypted: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Self::decrypt_secret(self, encrypted, passphrase)
    }
}

impl CryptoProvider for LatebraCrypto {
    type Error = CryptoError;

    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        payload: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), Self::Error> {
        let sealed = seal_with_xchacha20_poly1305(key, nonce, associated_data, payload)
            .map_err(CryptoError::Latebra)?;
        Ok((sealed.ciphertext, sealed.tag.into_bytes()))
    }

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Self::Error> {
        let sealed = SealedXChaCha20Poly1305Message {
            ciphertext: ciphertext.to_vec(),
            tag: XChaCha20Poly1305Tag::new(*tag),
        };
        open_with_xchacha20_poly1305(key, nonce, associated_data, &sealed)
            .map_err(CryptoError::Latebra)
    }

    fn derive_rekey(
        &self,
        traffic_secret: &[u8; 32],
        epoch: u32,
        outbound_is_client_to_server: bool,
    ) -> Result<RekeyMaterial, Self::Error> {
        let epoch_bytes = epoch.to_le_bytes();
        let c2s = argon2_domain_kdf(
            traffic_secret,
            &epoch_bytes,
            REKEY_C2S_INFO,
            48,
            argon2_live_parameters(48)?,
        )?;
        let s2c = argon2_domain_kdf(
            traffic_secret,
            &epoch_bytes,
            REKEY_S2C_INFO,
            48,
            argon2_live_parameters(48)?,
        )?;

        let (tx_material, rx_material) = if outbound_is_client_to_server {
            (&c2s, &s2c)
        } else {
            (&s2c, &c2s)
        };

        Ok(RekeyMaterial {
            tx_key: to_array_32(&tx_material[..32])?,
            rx_key: to_array_32(&rx_material[..32])?,
            tx_nonce_prefix: to_array_16(&tx_material[32..48])?,
            rx_nonce_prefix: to_array_16(&rx_material[32..48])?,
            epoch,
        })
    }
}

fn dpk1_key(passphrase: &[u8], salt: &[u8; DPK1_SALT_LEN]) -> Result<[u8; 32], CryptoError> {
    let parameters = Argon2Parameters::new(
        Argon2Mode::Argon2id,
        ARGON2_DPK1_TIME_COST,
        ARGON2_DPK1_MEMORY_KIB,
        ARGON2_DPK1_LANES,
        32,
    )
        .map_err(CryptoError::Latebra)?;
    let digest =
        Argon2::hash_password(passphrase, salt, parameters).map_err(CryptoError::Latebra)?;
    to_array_32(digest.as_bytes())
}

fn argon2_live_parameters(output_len: u32) -> Result<Argon2Parameters, CryptoError> {
    Argon2Parameters::new(
        Argon2Mode::Argon2id,
        ARGON2_LIVE_TIME_COST,
        ARGON2_LIVE_MEMORY_KIB,
        ARGON2_LIVE_LANES,
        output_len,
    )
    .map_err(CryptoError::Latebra)
}

fn argon2_domain_kdf(
    key_material: &[u8],
    salt_material: &[u8],
    label: &[u8],
    output_len: usize,
    parameters: Argon2Parameters,
) -> Result<Vec<u8>, CryptoError> {
    let mut salt_hasher = Blake3::new();
    salt_hasher.update(b"depot/argon2/salt");
    salt_hasher.update(label);
    salt_hasher.update(salt_material);
    let mut salt = [0u8; DPK1_SALT_LEN];
    salt_hasher.finalize_xof().squeeze_into(&mut salt);

    let mut password = Vec::with_capacity(key_material.len() + label.len());
    password.extend_from_slice(key_material);
    password.extend_from_slice(label);

    let digest = Argon2::hash_password(&password, &salt, parameters).map_err(CryptoError::Latebra)?;
    if digest.as_bytes().len() != output_len {
        return Err(CryptoError::InvalidLength {
            expected: output_len,
            actual: digest.as_bytes().len(),
        });
    }
    Ok(digest.as_bytes().to_vec())
}

fn fill_random_bytes(bytes: &mut [u8]) -> Result<(), CryptoError> {
    let mut file = std::fs::File::open("/dev/urandom").map_err(CryptoError::Random)?;
    use std::io::Read;
    file.read_exact(bytes).map_err(CryptoError::Random)
}

fn to_array_16(input: &[u8]) -> Result<[u8; 16], CryptoError> {
    input.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: 16,
        actual: input.len(),
    })
}

fn to_array_4896(input: &[u8]) -> Result<[u8; 4896], CryptoError> {
    input.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: 4896,
        actual: input.len(),
    })
}

fn to_array_32(input: &[u8]) -> Result<[u8; 32], CryptoError> {
    input.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: 32,
        actual: input.len(),
    })
}

fn to_array_2592(input: &[u8]) -> Result<[u8; 2592], CryptoError> {
    input.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: 2592,
        actual: input.len(),
    })
}

fn to_array_4627(input: &[u8]) -> Result<[u8; 4627], CryptoError> {
    input.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: 4627,
        actual: input.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_hashes_stably() {
        let mut transcript = Transcript::new();
        transcript.append("client-hello");
        transcript.append("server-hello");

        let digest_a = transcript.finish().unwrap();
        let digest_b = transcript.finish().unwrap();
        assert_eq!(digest_a, digest_b);
    }

    #[test]
    fn handshake_session_key_derivation_is_directional() {
        let crypto = LatebraCrypto;
        let transcript = [7u8; 64];
        let shared_secret = [9u8; 32];

        let client = crypto
            .derive_handshake_session_keys(shared_secret, transcript, true)
            .unwrap();
        let server = crypto
            .derive_handshake_session_keys(shared_secret, transcript, false)
            .unwrap();

        assert_eq!(client.tx_key, server.rx_key);
        assert_eq!(client.rx_key, server.tx_key);
        assert_eq!(client.tx_nonce_prefix, server.rx_nonce_prefix);
        assert_eq!(client.rx_nonce_prefix, server.tx_nonce_prefix);
        assert_eq!(client.traffic_secret, server.traffic_secret);
    }

    #[test]
    fn aead_roundtrip_works() {
        let crypto = LatebraCrypto;
        let key = [3u8; 32];
        let nonce = [4u8; 24];
        let aad = b"record";
        let payload = b"hello";

        let (ciphertext, tag) = crypto.seal(&key, &nonce, payload, aad).unwrap();
        let opened = crypto.open(&key, &nonce, &ciphertext, aad, &tag).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn signature_and_kem_bindings_work() {
        let crypto = LatebraCrypto;
        let identity = crypto.generate_signing_identity().unwrap();
        let kem = crypto.generate_kem_keypair().unwrap();
        let signature = crypto
            .sign_message(&identity.secret_key, kem.public_key.as_bytes())
            .unwrap();

        crypto
            .verify_message(&identity.public_key, kem.public_key.as_bytes(), &signature)
            .unwrap();

        let envelope = crypto.encapsulate(&kem.public_key).unwrap();
        let shared_secret = crypto
            .decapsulate(&kem.secret_key, &envelope.ciphertext)
            .unwrap();
        assert_eq!(shared_secret, envelope.shared_secret);
    }
}
