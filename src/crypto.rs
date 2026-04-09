use argon2::{Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version};
use chacha20poly1305::{
    Key, Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use libcrux_ml_dsa::{
    KEY_GENERATION_RANDOMNESS_SIZE as ML_DSA_KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE as ML_DSA_SIGNING_RANDOMNESS_SIZE, SigningError, VerificationError,
    ml_dsa_87::{
        MLDSA87KeyPair, MLDSA87Signature, MLDSA87SigningKey, MLDSA87VerificationKey,
        generate_key_pair as generate_ml_dsa_87_key_pair, sign as sign_ml_dsa_87,
        verify as verify_ml_dsa_87,
    },
};
use libcrux_ml_kem::{
    KEY_GENERATION_SEED_SIZE as ML_KEM_1024_KEY_GENERATION_SEED_SIZE,
    SHARED_SECRET_SIZE as ML_KEM_1024_SHARED_SECRET_SIZE,
    mlkem1024::{
        MlKem1024Ciphertext, MlKem1024KeyPair, MlKem1024PrivateKey as MlKem1024SecretKey,
        MlKem1024PublicKey, decapsulate as decapsulate_ml_kem_1024,
        encapsulate as encapsulate_ml_kem_1024, generate_key_pair as generate_ml_kem_1024_key_pair,
    },
};

pub use blake3::Hasher as Blake3;
pub type MlDsa87PublicKey = MLDSA87VerificationKey;
pub type MlDsa87SecretKey = MLDSA87SigningKey;
pub type MlDsa87Signature = MLDSA87Signature;

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

pub const ML_DSA_87_SECRET_KEY_LEN: usize = MlDsa87SecretKey::len();
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = MlDsa87PublicKey::len();
pub const ML_DSA_87_SIGNATURE_LEN: usize = MlDsa87Signature::len();
pub const ML_KEM_1024_PUBLIC_KEY_LEN: usize = MlKem1024PublicKey::len();
pub const ML_KEM_1024_CIPHERTEXT_LEN: usize = MlKem1024Ciphertext::len();

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
        hasher.finalize_xof().fill(&mut output);
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

#[derive(Clone)]
pub struct SigningIdentity {
    pub public_key: MlDsa87PublicKey,
    pub secret_key: MlDsa87SecretKey,
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningIdentity")
            .field("public_key_len", &self.public_key.as_ref().len())
            .field("secret_key_len", &self.secret_key.as_ref().len())
            .finish()
    }
}

impl PartialEq for SigningIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.public_key.as_ref() == other.public_key.as_ref()
            && self.secret_key.as_ref() == other.secret_key.as_ref()
    }
}

impl Eq for SigningIdentity {}

#[derive(Clone)]
pub struct KemKeypair {
    pub public_key: MlKem1024PublicKey,
    pub secret_key: MlKem1024SecretKey,
}

#[derive(Clone)]
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
    MlDsaSigning(SigningError),
    MlDsaVerification(VerificationError),
    Argon2(argon2::Error),
    Aead,
    InvalidLength { expected: usize, actual: usize },
    InvalidEncryptedSecret,
    Random(std::io::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MlDsaSigning(error) => write!(f, "{error:?}"),
            Self::MlDsaVerification(error) => write!(f, "{error:?}"),
            Self::Argon2(error) => write!(f, "{error}"),
            Self::Aead => f.write_str("authenticated encryption failed"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected}, got {actual}")
            }
            Self::InvalidEncryptedSecret => f.write_str("invalid encrypted secret"),
            Self::Random(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<argon2::Error> for CryptoError {
    fn from(value: argon2::Error) -> Self {
        Self::Argon2(value)
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
pub struct DepotCrypto;

impl DepotCrypto {
    pub fn parse_signing_secret_key(&self, bytes: &[u8]) -> Result<MlDsa87SecretKey, CryptoError> {
        Ok(MlDsa87SecretKey::new(to_array_4896(bytes)?))
    }

    pub fn parse_signing_public_key(&self, bytes: &[u8]) -> Result<MlDsa87PublicKey, CryptoError> {
        Ok(MlDsa87PublicKey::new(to_array_2592(bytes)?))
    }

    pub fn parse_signature(&self, bytes: &[u8]) -> Result<MlDsa87Signature, CryptoError> {
        Ok(MlDsa87Signature::new(to_array_4627(bytes)?))
    }

    pub fn parse_kem_public_key(&self, bytes: &[u8]) -> Result<MlKem1024PublicKey, CryptoError> {
        bytes.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: ML_KEM_1024_PUBLIC_KEY_LEN,
            actual: bytes.len(),
        })
    }

    pub fn parse_kem_ciphertext(&self, bytes: &[u8]) -> Result<MlKem1024Ciphertext, CryptoError> {
        bytes.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: ML_KEM_1024_CIPHERTEXT_LEN,
            actual: bytes.len(),
        })
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
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), DPK1_MAGIC, &mut ciphertext)
            .map_err(|_| CryptoError::Aead)?;

        let mut bytes = Vec::with_capacity(
            4 + 4 + DPK1_SALT_LEN + DPK1_NONCE_LEN + plaintext.len() + DPK1_TAG_LEN,
        );
        bytes.extend_from_slice(DPK1_MAGIC);
        bytes.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        bytes.extend_from_slice(tag.as_slice());
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
        let tag = Tag::from_slice(&encrypted[ciphertext_end..tag_end]);
        let mut plaintext = encrypted[ciphertext_start..ciphertext_end].to_vec();
        let key = dpk1_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                DPK1_MAGIC,
                &mut plaintext,
                tag,
            )
            .map_err(|_| CryptoError::Aead)?;
        Ok(plaintext)
    }
}

impl HandshakeCryptoProvider for DepotCrypto {
    fn parse_signing_secret_key(&self, bytes: &[u8]) -> Result<MlDsa87SecretKey, CryptoError> {
        Self::parse_signing_secret_key(self, bytes)
    }

    fn parse_signing_public_key(&self, bytes: &[u8]) -> Result<MlDsa87PublicKey, CryptoError> {
        Self::parse_signing_public_key(self, bytes)
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
        let mut randomness = [0u8; ML_DSA_KEY_GENERATION_RANDOMNESS_SIZE];
        fill_random_bytes(&mut randomness)?;
        let MLDSA87KeyPair {
            verification_key,
            signing_key,
        } = generate_ml_dsa_87_key_pair(randomness);
        Ok(SigningIdentity {
            public_key: verification_key,
            secret_key: signing_key,
        })
    }

    fn generate_kem_keypair(&self) -> Result<KemKeypair, CryptoError> {
        let mut randomness = [0u8; ML_KEM_1024_KEY_GENERATION_SEED_SIZE];
        fill_random_bytes(&mut randomness)?;
        let keypair: MlKem1024KeyPair = generate_ml_kem_1024_key_pair(randomness);
        Ok(KemKeypair {
            public_key: keypair.public_key().clone(),
            secret_key: keypair.private_key().clone(),
        })
    }

    fn sign_message(
        &self,
        secret_key: &MlDsa87SecretKey,
        message: &[u8],
    ) -> Result<MlDsa87Signature, CryptoError> {
        let mut randomness = [0u8; ML_DSA_SIGNING_RANDOMNESS_SIZE];
        fill_random_bytes(&mut randomness)?;
        sign_ml_dsa_87(secret_key, message, b"", randomness).map_err(CryptoError::MlDsaSigning)
    }

    fn verify_message(
        &self,
        public_key: &MlDsa87PublicKey,
        message: &[u8],
        signature: &MlDsa87Signature,
    ) -> Result<(), CryptoError> {
        verify_ml_dsa_87(public_key, message, b"", signature)
            .map_err(CryptoError::MlDsaVerification)
    }

    fn encapsulate(&self, public_key: &MlKem1024PublicKey) -> Result<KemEnvelope, CryptoError> {
        let mut randomness = [0u8; ML_KEM_1024_SHARED_SECRET_SIZE];
        fill_random_bytes(&mut randomness)?;
        let (ciphertext, shared_secret) = encapsulate_ml_kem_1024(public_key, randomness);
        Ok(KemEnvelope {
            ciphertext,
            shared_secret,
        })
    }

    fn decapsulate(
        &self,
        secret_key: &MlKem1024SecretKey,
        ciphertext: &MlKem1024Ciphertext,
    ) -> Result<[u8; 32], CryptoError> {
        let shared_secret = decapsulate_ml_kem_1024(secret_key, ciphertext);
        Ok(shared_secret)
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
        let traffic_secret = to_array_32(&traffic_secret)?;

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

impl CryptoProvider for DepotCrypto {
    type Error = CryptoError;

    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        payload: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), Self::Error> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let mut ciphertext = payload.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(nonce),
                associated_data,
                &mut ciphertext,
            )
            .map_err(|_| CryptoError::Aead)?;
        Ok((ciphertext, *tag.as_ref()))
    }

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Self::Error> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let mut plaintext = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
                associated_data,
                &mut plaintext,
                Tag::from_slice(tag),
            )
            .map_err(|_| CryptoError::Aead)?;
        Ok(plaintext)
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
    let params = Argon2Params::new(
        ARGON2_DPK1_MEMORY_KIB,
        ARGON2_DPK1_TIME_COST,
        ARGON2_DPK1_LANES,
        Some(32),
    )?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2.hash_password_into(passphrase, salt, &mut output)?;
    Ok(output)
}

fn argon2_live_parameters(output_len: usize) -> Result<Argon2Params, CryptoError> {
    Argon2Params::new(
        ARGON2_LIVE_MEMORY_KIB,
        ARGON2_LIVE_TIME_COST,
        ARGON2_LIVE_LANES,
        Some(output_len),
    )
    .map_err(CryptoError::Argon2)
}

fn argon2_domain_kdf(
    key_material: &[u8],
    salt_material: &[u8],
    label: &[u8],
    output_len: usize,
    parameters: Argon2Params,
) -> Result<Vec<u8>, CryptoError> {
    let mut salt_hasher = Blake3::new();
    salt_hasher.update(b"depot/argon2/salt");
    salt_hasher.update(label);
    salt_hasher.update(salt_material);
    let mut salt = [0u8; DPK1_SALT_LEN];
    salt_hasher.finalize_xof().fill(&mut salt);

    let mut password = Vec::with_capacity(key_material.len() + label.len());
    password.extend_from_slice(key_material);
    password.extend_from_slice(label);

    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, parameters);
    let mut output = vec![0u8; output_len];
    argon2.hash_password_into(&password, &salt, &mut output)?;
    Ok(output)
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
        let crypto = DepotCrypto;
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
        let crypto = DepotCrypto;
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
        let crypto = DepotCrypto;
        let identity = crypto.generate_signing_identity().unwrap();
        let kem = crypto.generate_kem_keypair().unwrap();
        let signature = crypto
            .sign_message(&identity.secret_key, kem.public_key.as_ref())
            .unwrap();

        crypto
            .verify_message(&identity.public_key, kem.public_key.as_ref(), &signature)
            .unwrap();

        let envelope = crypto.encapsulate(&kem.public_key).unwrap();
        let shared_secret = crypto
            .decapsulate(&kem.secret_key, &envelope.ciphertext)
            .unwrap();
        assert_eq!(shared_secret, envelope.shared_secret);
    }
}
