//! The wallet: an encrypted key, its address, and the logic to spend its coins.
//!
//! A ZeroCoin wallet is a single secp256k1 key whose 32-byte scalar is **never**
//! stored in the clear. On disk lives a [`WalletFile`]: the public identity
//! (public key, address, chain id) plus a [`SealedSecret`] produced by
//! [`crate::crypto::keystore`] — argon2id-derived AES-256-GCM. Unlocking requires the
//! password; the sealed bytes are bound to this wallet's public identity through the
//! AEAD associated data, so an envelope copied between wallets will not open.
//!
//! ## Spending
//!
//! [`Wallet::send`] is the whole payment path. It decodes and network-checks the
//! destination address, unlocks the key, selects mature coins from the chain until
//! they cover `amount + fee`, builds a two-output P2PKH transaction (payment plus
//! change back to self), and signs every input under a chain-bound `SIGHASH_ALL`
//! sighash. Coin selection is deliberately simple — largest-first over spendable
//! coins — which is correct and adequate for a single-key devnet wallet; a production
//! wallet would add branch-and-bound and privacy-aware selection.
//!
//! This is a single-address wallet: [`Wallet::new_address`] returns the one address
//! the key controls. That keeps the model honest — there is exactly one secret, and
//! therefore exactly one receiving identity — rather than pretending to rotate keys
//! it does not track.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressError};
use crate::chain::{Chain, ChainError, CoinInfo};
use crate::crypto::keystore::{self, KeystoreError, SealedSecret};
use crate::crypto::secp256k1::{CryptoError, PrivateKey, PublicKey};
use crate::ledger::script::{p2pkh_script_pubkey, p2pkh_script_sig};
use crate::ledger::sighash::{signature_hash, SIGHASH_ALL};
use crate::ledger::transaction::{Transaction, TxIn, TxOut};
use crate::params::ChainParams;

/// The on-disk wallet format version.
pub const WALLET_VERSION: u32 = 1;
/// Domain tag folded into the keystore's associated data.
const WALLET_AAD_TAG: &[u8] = b"zerocoin-wallet/v1\0";

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("keystore error: {0}")]
    Keystore(#[from] KeystoreError),
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("address error: {0}")]
    Address(#[from] AddressError),
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("insufficient funds: need {needed} Fah but only {available} Fah is spendable")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("wallet file is already present at {0}")]
    AlreadyExists(PathBuf),
    #[error("no wallet file at {0}")]
    NotFound(PathBuf),
    #[error("wallet file is corrupt: {0}")]
    Corrupt(String),
    #[error("i/o error: {0}")]
    Io(String),
}

impl From<std::io::Error> for WalletError {
    fn from(error: std::io::Error) -> Self {
        WalletError::Io(error.to_string())
    }
}

/// The persisted wallet: public identity plus the sealed secret. Nothing here is
/// sensitive except through the password, and the secret is not present in the clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletFile {
    pub version: u32,
    pub chain_id: u32,
    pub public_key: PublicKey,
    pub address: String,
    pub sealed: SealedSecret,
}

/// An open wallet bound to a network. The secret stays sealed until [`Wallet::unlock`].
pub struct Wallet {
    params: ChainParams,
    file: WalletFile,
    path: Option<PathBuf>,
}

/// Build the associated data that binds a sealed secret to this wallet's identity.
fn wallet_aad(chain_id: u32, public_key: &PublicKey) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WALLET_AAD_TAG.len() + 4 + 33);
    aad.extend_from_slice(WALLET_AAD_TAG);
    aad.extend_from_slice(&chain_id.to_le_bytes());
    aad.extend_from_slice(&public_key.to_sec1());
    aad
}

impl Wallet {
    /// Create a new wallet with a fresh random key, seal it under `password`, and
    /// write it to `path`. Fails if the file already exists, so an existing wallet is
    /// never silently overwritten.
    pub fn create(params: ChainParams, path: impl AsRef<Path>, password: &str) -> Result<Self, WalletError> {
        let key = PrivateKey::random();
        Self::create_from_key(params, path, password, key)
    }

    /// Create a wallet from a specific key. Used by tests and by tooling that imports
    /// an existing secret; the secret is sealed immediately and never persisted raw.
    pub fn create_from_key(
        params: ChainParams,
        path: impl AsRef<Path>,
        password: &str,
        key: PrivateKey,
    ) -> Result<Self, WalletError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(WalletError::AlreadyExists(path));
        }
        let wallet = Self::from_key(params, Some(path), password, key, None)?;
        wallet.save()?;
        Ok(wallet)
    }

    /// Create with explicit argon2id cost parameters. A user machine can raise these;
    /// tests lower them to stay fast. The parameters are recorded in the file.
    pub fn create_with_kdf(
        params: ChainParams,
        path: impl AsRef<Path>,
        password: &str,
        key: PrivateKey,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Self, WalletError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(WalletError::AlreadyExists(path));
        }
        let wallet = Self::from_key(
            params,
            Some(path),
            password,
            key,
            Some((m_cost, t_cost, p_cost)),
        )?;
        wallet.save()?;
        Ok(wallet)
    }

    /// Load a wallet from disk. The secret remains sealed; call [`Wallet::unlock`] to
    /// use it. The stored chain id must match the network this wallet is opened on.
    pub fn load(params: ChainParams, path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(WalletError::NotFound(path));
        }
        let text = fs::read_to_string(&path)?;
        let file: WalletFile =
            serde_json::from_str(&text).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        if file.version != WALLET_VERSION {
            return Err(WalletError::Corrupt(format!(
                "unsupported wallet version {}",
                file.version
            )));
        }
        if file.chain_id != params.chain_id.0 {
            return Err(WalletError::Corrupt(format!(
                "wallet is for chain {:#x} but this node serves {:#x}",
                file.chain_id, params.chain_id.0
            )));
        }
        Ok(Wallet {
            params,
            file,
            path: Some(path),
        })
    }

    /// An in-memory wallet that is never persisted, for tests and ephemeral tools.
    pub fn ephemeral(
        params: ChainParams,
        password: &str,
        key: PrivateKey,
    ) -> Result<Self, WalletError> {
        Self::from_key(params, None, password, key, Some((4_096, 1, 1)))
    }

    fn from_key(
        params: ChainParams,
        path: Option<PathBuf>,
        password: &str,
        key: PrivateKey,
        kdf: Option<(u32, u32, u32)>,
    ) -> Result<Self, WalletError> {
        let public_key = key.public_key();
        let address = Address::from_public_key(params.base58_pubkey_prefix, &public_key).encode();
        let aad = wallet_aad(params.chain_id.0, &public_key);
        let sealed = match kdf {
            Some((m, t, p)) => keystore::seal_with_params(&key.to_bytes(), password, &aad, m, t, p)?,
            None => keystore::seal(&key.to_bytes(), password, &aad)?,
        };
        Ok(Wallet {
            params,
            file: WalletFile {
                version: WALLET_VERSION,
                chain_id: params.chain_id.0,
                public_key,
                address,
                sealed,
            },
            path,
        })
    }

    /// Write the wallet file atomically (sibling + rename), if it has a path.
    pub fn save(&self) -> Result<(), WalletError> {
        let Some(path) = &self.path else {
            return Ok(()); // ephemeral: nothing to persist
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let text = serde_json::to_string(&self.file).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let temp = path.with_extension("json.tmp");
        fs::write(&temp, text)?;
        fs::rename(&temp, path)?;
        Ok(())
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The wallet's public key, available without unlocking.
    pub fn public_key(&self) -> PublicKey {
        self.file.public_key
    }

    /// The wallet's receiving address on its network.
    pub fn new_address(&self) -> Address {
        Address::from_public_key(self.params.base58_pubkey_prefix, &self.file.public_key)
    }

    /// The wallet's address as a Base58Check string.
    pub fn address_string(&self) -> &str {
        &self.file.address
    }

    /// The public-key hash this wallet's coins pay to.
    pub fn pubkey_hash(&self) -> crate::crypto::hash::Hash160 {
        self.file.public_key.key_hash()
    }

    /// Recover the secret key with the password. A wrong password fails the GCM tag
    /// and yields [`KeystoreError::WrongPassword`].
    pub fn unlock(&self, password: &str) -> Result<PrivateKey, WalletError> {
        let aad = wallet_aad(self.file.chain_id, &self.file.public_key);
        let secret = keystore::open(&self.file.sealed, password, &aad)?;
        Ok(PrivateKey::from_bytes(secret)?)
    }

    /// The wallet's total confirmed balance (mature and immature) on `chain`.
    pub fn balance(&self, chain: &Chain) -> u64 {
        chain.balance_of_pubkey_hash(&self.pubkey_hash())
    }

    /// The balance that is mature enough to spend in the next block.
    pub fn spendable_balance(&self, chain: &Chain) -> u64 {
        chain.spendable_balance(&self.pubkey_hash())
    }

    /// Build and sign a payment of `amount` Fah to `to` (a Base58Check address on this
    /// network), paying `fee` Fah to the miner, selecting coins from `chain`.
    pub fn send(
        &self,
        password: &str,
        chain: &Chain,
        to: &str,
        amount: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        let destination =
            Address::decode_for_network(to, self.params.base58_pubkey_prefix)?;
        let key = self.unlock(password)?;
        self.build_signed_payment(&key, chain, &destination, amount, fee)
    }

    /// Build and sign a payment to an already-decoded address, using an
    /// already-unlocked key. Separated so callers can unlock once and send many times.
    pub fn build_signed_payment(
        &self,
        key: &PrivateKey,
        chain: &Chain,
        to: &Address,
        amount: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        let coins = chain.coins_for_pubkey_hash(&self.pubkey_hash());
        let target = amount.checked_add(fee).ok_or(WalletError::InsufficientFunds {
            needed: u64::MAX,
            available: 0,
        })?;
        let selected = select_coins(&coins, target)?;

        let own_script = p2pkh_script_pubkey(&self.pubkey_hash());
        let mut inputs = Vec::with_capacity(selected.len());
        let mut total_in: u64 = 0;
        for coin in &selected {
            inputs.push(TxIn {
                previous_output: coin.outpoint,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            });
            total_in = total_in.saturating_add(coin.value);
        }

        let mut outputs = vec![TxOut {
            value: amount,
            script_pubkey: p2pkh_script_pubkey(&to.pubkey_hash),
        }];
        // Return the surplus as change to ourselves; a zero change output is omitted.
        let change = total_in
            .checked_sub(amount)
            .and_then(|v| v.checked_sub(fee))
            .ok_or(WalletError::InsufficientFunds {
                needed: target,
                available: total_in,
            })?;
        if change > 0 {
            outputs.push(TxOut {
                value: change,
                script_pubkey: own_script.clone(),
            });
        }

        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs,
            lock_time: 0,
        };

        // Sign every input. All selected coins pay this wallet's key, so they share
        // one script_code; each signature commits to the whole transaction.
        let public_key = key.public_key();
        let sec1 = public_key.to_sec1();
        for index in 0..tx.inputs.len() {
            let digest = signature_hash(&tx, index, &own_script, chain.chain_id(), SIGHASH_ALL)
                .ok_or(WalletError::Corrupt("input index out of range".into()))?;
            let mut sig = key.sign(&digest)?.to_der().to_vec();
            sig.push(SIGHASH_ALL as u8);
            tx.inputs[index].script_sig = p2pkh_script_sig(&sig, &sec1);
        }
        Ok(tx)
    }
}

/// Greedy largest-first selection over mature coins until `target` is covered.
fn select_coins<'a>(coins: &'a [CoinInfo], target: u64) -> Result<Vec<&'a CoinInfo>, WalletError> {
    let mut mature: Vec<&CoinInfo> = coins.iter().filter(|c| c.spendable).collect();
    // Largest first minimizes the number of inputs (and therefore transaction size).
    mature.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for coin in mature {
        if total >= target {
            break;
        }
        selected.push(coin);
        total = total.saturating_add(coin.value);
    }
    if total < target {
        return Err(WalletError::InsufficientFunds {
            needed: target,
            available: total,
        });
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Low argon2id cost keeps the suite fast while exercising the real code path.
    const TEST_M: u32 = 4_096;
    const TEST_T: u32 = 1;
    const TEST_P: u32 = 1;

    fn regtest() -> ChainParams {
        ChainParams::regtest()
    }

    fn test_wallet(path: &Path) -> Wallet {
        Wallet::create_with_kdf(
            regtest(),
            path,
            "hunter2",
            PrivateKey::from_bytes([11u8; 32]).unwrap(),
            TEST_M,
            TEST_T,
            TEST_P,
        )
        .expect("creates")
    }

    /// Mine a funding block to `wallet`, then mature it over 100 blocks.
    fn funded_chain(wallet: &Wallet) -> Chain {
        let mut chain = Chain::in_memory(regtest()).unwrap();
        let mut now = crate::params::GENESIS_TIMESTAMP + 1_000;
        chain.mine_block(&wallet.public_key(), vec![], now).unwrap();
        for _ in 0..100 {
            now += 1;
            chain.mine_block(&wallet.public_key(), vec![], now).unwrap();
        }
        chain
    }

    #[test]
    fn wallet_file_never_contains_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let wallet = test_wallet(&path);
        let text = fs::read_to_string(&path).unwrap();
        // The raw scalar (or its hex) must never appear in the file.
        assert!(!text.contains(&hex::encode([11u8; 32])));
        assert!(text.contains(wallet.address_string()));
    }

    #[test]
    fn unlock_roundtrips_and_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = test_wallet(&dir.path().join("wallet.json"));
        let key = wallet.unlock("hunter2").expect("unlocks");
        assert_eq!(key.public_key(), wallet.public_key());
        assert!(matches!(
            wallet.unlock("wrong").err(),
            Some(WalletError::Keystore(KeystoreError::WrongPassword))
        ));
    }

    #[test]
    fn reload_from_disk_preserves_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let wallet = test_wallet(&path);
        let address = wallet.address_string().to_string();
        drop(wallet);
        let reloaded = Wallet::load(regtest(), &path).expect("loads");
        assert_eq!(reloaded.address_string(), address);
        assert_eq!(reloaded.unlock("hunter2").unwrap().public_key().to_sec1(), 
            reloaded.public_key().to_sec1());
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let _first = test_wallet(&path);
        let second = Wallet::create_with_kdf(
            regtest(),
            &path,
            "pw",
            PrivateKey::from_bytes([12u8; 32]).unwrap(),
            TEST_M,
            TEST_T,
            TEST_P,
        );
        assert!(matches!(second, Err(WalletError::AlreadyExists(_))));
    }

    #[test]
    fn address_is_network_bound() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = test_wallet(&dir.path().join("wallet.json"));
        // A regtest/devnet address (0x6f) does not start with the mainnet '1'.
        assert!(!wallet.address_string().starts_with('1'));
        // The same address decodes for this network and is rejected for mainnet.
        assert!(Address::decode_for_network(wallet.address_string(), 0x6f).is_ok());
        assert!(Address::decode_for_network(wallet.address_string(), 0x00).is_err());
    }

    #[test]
    fn send_builds_a_valid_signed_payment() {
        let dir = tempfile::tempdir().unwrap();
        let sender = test_wallet(&dir.path().join("sender.json"));
        let chain = funded_chain(&sender);

        // A fresh recipient wallet (ephemeral, no file needed to receive).
        let recipient = Wallet::ephemeral(
            regtest(),
            "pw",
            PrivateKey::from_bytes([77u8; 32]).unwrap(),
        )
        .unwrap();

        let amount = 250_000_000; // 2.5 ZRO
        let fee = 1_000;
        let tx = sender
            .send("hunter2", &chain, recipient.address_string(), amount, fee)
            .expect("builds and signs");

        // The chain's own validator accepts it and reports exactly the intended fee.
        assert_eq!(chain.validate_transaction(&tx).expect("valid"), fee);
        // The payment output pays the recipient the requested amount.
        assert!(tx
            .outputs
            .iter()
            .any(|o| o.value == amount
                && o.script_pubkey == p2pkh_script_pubkey(&recipient.pubkey_hash())));
    }

    #[test]
    fn send_rejects_insufficient_funds() {
        let dir = tempfile::tempdir().unwrap();
        let sender = test_wallet(&dir.path().join("sender.json"));
        let chain = funded_chain(&sender);
        let recipient = Wallet::ephemeral(regtest(), "pw", PrivateKey::random()).unwrap();
        // More than the entire matured supply this wallet holds.
        let result = sender.send(
            "hunter2",
            &chain,
            recipient.address_string(),
            u64::MAX / 2,
            1_000,
        );
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })));
    }

    #[test]
    fn send_rejects_immature_coins() {
        let dir = tempfile::tempdir().unwrap();
        let sender = test_wallet(&dir.path().join("sender.json"));
        // Mine only the funding block: the coinbase is far from mature.
        let mut chain = Chain::in_memory(regtest()).unwrap();
        let now = crate::params::GENESIS_TIMESTAMP + 1_000;
        chain.mine_block(&sender.public_key(), vec![], now).unwrap();
        let recipient = Wallet::ephemeral(regtest(), "pw", PrivateKey::random()).unwrap();
        // There is confirmed value but nothing spendable yet.
        assert!(sender.balance(&chain) > 0);
        assert_eq!(sender.spendable_balance(&chain), 0);
        let result = sender.send("hunter2", &chain, recipient.address_string(), 1_000_000, 100);
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })));
    }

    #[test]
    fn send_rejects_a_foreign_network_address() {
        let dir = tempfile::tempdir().unwrap();
        let sender = test_wallet(&dir.path().join("sender.json"));
        let chain = funded_chain(&sender);
        // A mainnet-prefixed address must be refused on regtest.
        let mainnet_addr =
            Address::from_public_key(0x00, &PrivateKey::random().public_key()).encode();
        let result = sender.send("hunter2", &chain, &mainnet_addr, 1_000_000, 100);
        assert!(matches!(result, Err(WalletError::Address(_))));
    }
}
