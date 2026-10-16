//! Encrypted wallet keystore: argon2id key derivation + AES-256-GCM sealing.
//!
//! The 32-byte secret scalar *is* the wallet, so this module exists for exactly
//! one reason: the keystore file must never contain it. A password plus a
//! per-wallet random salt are stretched into a 256-bit key by **argon2id**, and
//! that key seals the secret under **AES-256-GCM**. The GCM authentication tag
//! does double duty — it detects any edit to the file, and it proves the password
//! was correct, because a wrong password derives a key that cannot open the
//! ciphertext.
//!
//! The sealed bytes are additionally bound to the wallet's public identity through
//! the AEAD *associated data*. A ciphertext lifted out of Alice's file and pasted
//! into Bob's therefore fails to open, which rules out keystore splicing and
//! replaying an old envelope beside a newer one.
//!
//! This replaces the reference prototype's plaintext seed file (a direct theft
//! vector) and its ChaCha20-Poly1305 envelope with the AES-256-GCM + argon2id
//! construction the ZeroCoin security requirements call for. Zero custom
//! cryptography: derivation is `argon2`, sealing is `aes-gcm`, randomness is the
//! operating-system CSPRNG.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The secret this envelope holds: a secp256k1 scalar.
pub const SECRET_LEN: usize = 32;
/// AES-256 key length.
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KDF_NAME: &str = "argon2id";
pub const CIPHER_NAME: &str = "aes-256-gcm";
pub const KEYSTORE_VERSION: u32 = 1;

/// Default argon2id cost: ~19 MiB and 2 passes, which puts a single password
/// guess at a fraction of a second on a laptop while making a stolen file an
/// expensive dictionary search. These are the OWASP-recommended interactive-login
/// parameters, tuned down slightly so tests stay fast.
pub const DEFAULT_M_COST: u32 = 19_456;
pub const DEFAULT_T_COST: u32 = 2;
pub const DEFAULT_P_COST: u32 = 1;

/// Upper bounds on the cost parameters stored *in the file*. Whoever supplied the
/// file supplied these, so opening an untrusted keystore must not hand an attacker
/// a memory or CPU bomb.
const MAX_M_COST: u32 = 1 << 21; // 2 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeystoreError {
    #[error("no operating-system randomness source available")]
    RandomSourceUnavailable,
    #[error("keystore password must not be empty")]
    EmptyPassword,
    #[error("unsupported key derivation function '{0}'")]
    UnsupportedKdf(String),
    #[error("unsupported cipher '{0}'")]
    UnsupportedCipher(String),
    #[error("unsupported keystore version {0}")]
    UnsupportedVersion(u32),
    #[error("keystore key-derivation parameters are out of range")]
    BadKdfParams,
    #[error("keystore file is malformed: {0}")]
    Malformed(String),
    #[error("encryption of the keystore failed")]
    SealingFailed,
    #[error("wrong password, or the keystore file was changed after it was written")]
    WrongPassword,
}

/// Everything a keystore file stores instead of a secret. Each field is either
/// public or useless without the password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    pub version: u32,
    pub kdf: String,
    pub cipher: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// Seal `secret` under `password`. `aad` is the wallet's public identity, bound
/// into the GCM tag so the envelope cannot be moved between wallets.
pub fn seal(
    secret: &[u8; SECRET_LEN],
    password: &str,
    aad: &[u8],
) -> Result<SealedSecret, KeystoreError> {
    seal_with_params(
        secret,
        password,
        aad,
        DEFAULT_M_COST,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )
}

/// Seal with explicit argon2id cost parameters. Exposed so a wallet can raise the
/// cost on a machine that can afford it, and so tests can lower it.
pub fn seal_with_params(
    secret: &[u8; SECRET_LEN],
    password: &str,
    aad: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<SealedSecret, KeystoreError> {
    if password.is_empty() {
        return Err(KeystoreError::EmptyPassword);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut salt)
        .map_err(|_| KeystoreError::RandomSourceUnavailable)?;
    OsRng.try_fill_bytes(&mut nonce)
        .map_err(|_| KeystoreError::RandomSourceUnavailable)?;

    let mut key = derive_key(password, &salt, m_cost, t_cost, p_cost)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| KeystoreError::SealingFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret.as_slice(),
                aad,
            },
        )
        .map_err(|_| KeystoreError::SealingFailed)?;
    key.zeroize();

    Ok(SealedSecret {
        version: KEYSTORE_VERSION,
        kdf: KDF_NAME.to_string(),
        cipher: CIPHER_NAME.to_string(),
        m_cost,
        t_cost,
        p_cost,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// Recover the secret. Only the correct password, an unmodified envelope, and the
/// identity the envelope was bound to will return anything at all.
pub fn open(
    sealed: &SealedSecret,
    password: &str,
    aad: &[u8],
) -> Result<[u8; SECRET_LEN], KeystoreError> {
    if sealed.version != KEYSTORE_VERSION {
        return Err(KeystoreError::UnsupportedVersion(sealed.version));
    }
    if sealed.kdf != KDF_NAME {
        return Err(KeystoreError::UnsupportedKdf(sealed.kdf.clone()));
    }
    if sealed.cipher != CIPHER_NAME {
        return Err(KeystoreError::UnsupportedCipher(sealed.cipher.clone()));
    }
    if sealed.m_cost == 0
        || sealed.m_cost > MAX_M_COST
        || sealed.t_cost == 0
        || sealed.t_cost > MAX_T_COST
        || sealed.p_cost == 0
        || sealed.p_cost > MAX_P_COST
    {
        return Err(KeystoreError::BadKdfParams);
    }

    let salt = hex::decode(&sealed.salt_hex).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
    if salt.len() != SALT_LEN {
        return Err(KeystoreError::Malformed("salt is not 16 bytes".into()));
    }
    let nonce =
        hex::decode(&sealed.nonce_hex).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
    if nonce.len() != NONCE_LEN {
        return Err(KeystoreError::Malformed("nonce is not 12 bytes".into()));
    }
    let ciphertext =
        hex::decode(&sealed.ciphertext_hex).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
    // A GCM ciphertext is at least as long as the 16-byte tag; anything shorter
    // cannot possibly decrypt to a 32-byte secret.
    if ciphertext.len() < 16 + SECRET_LEN {
        return Err(KeystoreError::Malformed(
            "ciphertext is shorter than a sealed secret".into(),
        ));
    }

    let mut key = derive_key(password, &salt, sealed.m_cost, sealed.t_cost, sealed.p_cost)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| KeystoreError::BadKdfParams)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| KeystoreError::WrongPassword)?;
    key.zeroize();

    if plaintext.len() != SECRET_LEN {
        return Err(KeystoreError::Malformed(
            "decrypted secret is not a 32-byte scalar".into(),
        ));
    }
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

/// Derive a 256-bit AES key from a password and salt with argon2id.
fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; KEY_LEN], KeystoreError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|_| KeystoreError::BadKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| KeystoreError::BadKdfParams)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Low cost keeps the test suite fast while exercising the same code path.
    const TEST_M: u32 = 4_096;
    const TEST_T: u32 = 1;
    const TEST_P: u32 = 1;

    fn seal_test(secret: &[u8; 32], password: &str, aad: &[u8]) -> SealedSecret {
        seal_with_params(secret, password, aad, TEST_M, TEST_T, TEST_P).expect("seals")
    }

    #[test]
    fn seal_open_roundtrip() {
        let secret = [42u8; SECRET_LEN];
        let aad = b"wallet-alice";
        let sealed = seal_test(&secret, "correct horse", aad);
        let recovered = open(&sealed, "correct horse", aad).expect("opens");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn wrong_password_fails() {
        let secret = [7u8; SECRET_LEN];
        let sealed = seal_test(&secret, "right", b"id");
        assert_eq!(
            open(&sealed, "wrong", b"id").err(),
            Some(KeystoreError::WrongPassword)
        );
    }

    #[test]
    fn wrong_identity_fails() {
        let secret = [7u8; SECRET_LEN];
        let sealed = seal_test(&secret, "pw", b"alice");
        // The AAD binds the envelope to an identity: Bob cannot open Alice's file.
        assert_eq!(
            open(&sealed, "pw", b"bob").err(),
            Some(KeystoreError::WrongPassword)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let secret = [7u8; SECRET_LEN];
        let mut sealed = seal_test(&secret, "pw", b"id");
        // Flip a byte of the ciphertext; the GCM tag must reject it.
        let mut bytes = hex::decode(&sealed.ciphertext_hex).unwrap();
        bytes[0] ^= 0xff;
        sealed.ciphertext_hex = hex::encode(bytes);
        assert_eq!(
            open(&sealed, "pw", b"id").err(),
            Some(KeystoreError::WrongPassword)
        );
    }

    #[test]
    fn empty_password_rejected() {
        let secret = [1u8; SECRET_LEN];
        assert_eq!(
            seal(&secret, "", b"id").err(),
            Some(KeystoreError::EmptyPassword)
        );
    }

    #[test]
    fn file_never_contains_the_secret() {
        let secret = [0xab; SECRET_LEN];
        let sealed = seal_test(&secret, "pw", b"id");
        let json = serde_json::to_string(&sealed).unwrap();
        // Neither the raw bytes nor their hex may appear anywhere in the file.
        assert!(!json.contains(&hex::encode(secret)));
        assert!(json.contains(CIPHER_NAME) && json.contains(KDF_NAME));
    }

    #[test]
    fn rejects_absurd_kdf_params_on_open() {
        let secret = [3u8; SECRET_LEN];
        let mut sealed = seal_test(&secret, "pw", b"id");
        sealed.m_cost = MAX_M_COST + 1;
        assert_eq!(open(&sealed, "pw", b"id").err(), Some(KeystoreError::BadKdfParams));
    }

    #[test]
    fn two_seals_of_the_same_secret_differ() {
        let secret = [9u8; SECRET_LEN];
        let a = seal_test(&secret, "pw", b"id");
        let b = seal_test(&secret, "pw", b"id");
        // Fresh random salt and nonce each time: no deterministic fingerprint.
        assert_ne!(a.ciphertext_hex, b.ciphertext_hex);
    }
}
