//! Cryptographic primitives.
//!
//! ZeroCoin uses only battle-tested RustCrypto primitives: SHA-256/SHA-256d and
//! RIPEMD-160 for hashing, secp256k1 ECDSA for signatures (`k256`), AES-256-GCM
//! plus argon2id for the wallet keystore, and HMAC-SHA256 for frame
//! authentication. There is no hand-rolled cryptography anywhere in this crate.

pub mod hash;
pub mod secp256k1;
pub mod keystore;

pub use hash::{hash160, sha256, sha256d, Hash160, Hash256};
pub use secp256k1::{PrivateKey, PublicKey, Signature, ECDSA};
