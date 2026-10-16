//! The shared wallet core: one in-process facade over the node state.
//!
//! # Why this exists
//!
//! The desktop wallet is a *front-end*: it drives a `zerocoind` process over
//! loopback JSON-RPC, spawning one when nothing is listening. That split works
//! on Windows/macOS/Linux, but it is not portable — Android and iOS sandboxed
//! applications cannot launch helper executables, and a mobile app has no
//! background daemon to attach to. The safest cross-platform answer is
//! therefore not a second node implementation, but the *same* node state
//! inside the application process.
//!
//! [`Session`] opens exactly what `Node::open` opens — the chain store and the
//! encrypted wallet file under a data directory — without binding any sockets
//! and without starting any threads. Every operation is dispatched through the
//! node's own `handle_rpc`, the single function that also serves the loopback
//! RPC server: the desktop transport and the session transport cannot drift
//! apart, because there is only one implementation of every operation (mining,
//! signing, mempool admission, wallet lifecycle).
//!
//! # Storage
//!
//! The caller chooses the data directory. Desktop code keeps using
//! `crate::datadir::default_datadir`; a mobile binding points the session at
//! its sandbox directory (see `crate::datadir::set_base_dir`). The wallet file
//! format, the argon2id parameters and the address derivation are shared with
//! `zerocoind`, so a wallet created by the desktop wallet opens in a session
//! and vice versa.
//!
//! # Honesty contract
//!
//! [`Session::send`] reports a txid only after the node has signed the
//! transaction, admitted it to the mempool and announced it to peers —
//! confirmation still requires a mined block, which [`Session::info`] lets a
//! UI track (height and mempool length). Nothing in this module ever
//! fabricates a balance, an address or a transaction.

use std::path::Path;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::node::{handle_rpc, Node, NodeConfig, NodeError, NodeState};
use crate::params::ChainParams;

/// Everything a session operation can fail with.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Opening the node state failed: i/o, a corrupt chain file, or a wallet
    /// file that does not belong to this network.
    #[error(transparent)]
    Node(#[from] NodeError),
    /// The node refused the operation. The message is the node's own — the
    /// exact string the loopback RPC would return — and is safe to show.
    #[error("{0}")]
    Rejected(String),
    /// A node result did not match the documented shape, which indicates a
    /// version mismatch between this library and the state that produced it.
    #[error("unexpected node response: {0}")]
    Malformed(String),
}

/// What the node knows about the wallet, without creating one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletStatus {
    /// Whether a wallet identity is loaded (on disk and in memory).
    pub present: bool,
    /// The wallet's receiving address when present.
    pub address: Option<String>,
}

/// A wallet's balance snapshot, in Fah (1 ZRO = 100,000,000 Fah).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// The address this balance belongs to.
    pub address: String,
    /// Every confirmed coin, mature or not.
    #[serde(rename = "confirmed")]
    pub confirmed_fah: u64,
    /// The balance mature enough to spend in the next block.
    #[serde(rename = "spendable")]
    pub spendable_fah: u64,
}

/// A snapshot of the chain and network this session is attached to.
///
/// A session never starts the P2P servers, so `peers` is always 0 and `height`
/// is the authoritative height of the local store — the session is always in
/// sync with itself. A UI that wants live peer counts runs a full node
/// alongside and reads *its* RPC, exactly like the desktop wallet does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInfo {
    pub network: String,
    pub chain_id: u32,
    pub height: u64,
    pub tip: String,
    pub difficulty_bits: u32,
    pub engine: String,
    pub utxo_count: u64,
    pub subsidy_issued: u64,
    pub state_root: String,
    pub mempool: u64,
    pub peers: u64,
}

/// An open wallet session: node state, no servers, no threads.
///
/// `Session` is `Send + Sync` and can be shared freely between a UI thread and
/// worker threads; every operation takes the same internal locks the node's own
/// RPC handlers take.
pub struct Session {
    state: Arc<NodeState>,
}

impl Session {
    /// Open (or create) the chain and wallet state for `params` under
    /// `data_dir`.
    ///
    /// Nothing is bound and nothing is spawned. A wallet file that exists is
    /// loaded (and stays locked behind its password); an absent wallet is
    /// *not* created — deliberate, so opening an application can never invent
    /// an identity with a password nobody chose. Callers use
    /// [`Session::wallet_status`] and then [`Session::create_wallet`],
    /// [`Session::import_secret`] or [`Session::import_keystore`], mirroring
    /// the desktop onboarding.
    pub fn open(params: ChainParams, data_dir: impl AsRef<Path>) -> Result<Self, SessionError> {
        let config = NodeConfig {
            params,
            data_dir: data_dir.as_ref().to_path_buf(),
            // Never used: a session does not start the servers. Kept as a
            // valid loopback address so the config stays well-formed.
            p2p_listen: "127.0.0.1:0".parse().expect("valid loopback address"),
            rpc_listen: None,
            seeds: Vec::new(),
            // An empty password guarantees no wallet is created on open even
            // when none exists yet; an existing wallet file is loaded anyway.
            wallet_password: String::new(),
        };
        let state = Node::open(&config)?;
        Ok(Session { state })
    }

    /// The single dispatch path: identical to the loopback RPC server's.
    fn handle(&self, method: &str, params: &Value) -> Result<Value, SessionError> {
        handle_rpc(&self.state, method, params).map_err(SessionError::Rejected)
    }

    fn typed<T: DeserializeOwned>(&self, method: &str, params: &Value) -> Result<T, SessionError> {
        let value = self.handle(method, params)?;
        serde_json::from_value(value).map_err(|error| SessionError::Malformed(error.to_string()))
    }

    /// Whether a wallet identity is present, and its address when it is.
    pub fn wallet_status(&self) -> Result<WalletStatus, SessionError> {
        self.typed("walletstatus", &json!({}))
    }

    /// Create a brand-new wallet, sealed under `password`. Returns its
    /// address. Refused when a wallet already exists — replacing an identity
    /// requires an explicit import.
    pub fn create_wallet(&self, password: &str) -> Result<String, SessionError> {
        let outcome: AddressOutcome =
            self.typed("createwallet", &json!({ "password": password }))?;
        Ok(outcome.address)
    }

    /// Import an identity from its raw 32-byte secp256k1 secret (64 hex
    /// characters), re-sealed under `password` on this machine. This is the
    /// recovery format the node's `importwallet` accepts — the same one the
    /// desktop tooling produces.
    pub fn import_secret(&self, password: &str, secret_hex: &str) -> Result<String, SessionError> {
        let outcome: AddressOutcome = self.typed(
            "importwallet",
            &json!({ "password": password, "secret": secret_hex }),
        )?;
        Ok(outcome.address)
    }

    /// Restore a wallet from its encrypted keystore (the exact bytes of a
    /// `wallet.json` backup). The password must open the keystore; on failure
    /// the previous wallet, if any, is left untouched.
    pub fn import_keystore(
        &self,
        password: &str,
        keystore_json: &str,
    ) -> Result<String, SessionError> {
        let outcome: AddressOutcome = self.typed(
            "importwallet",
            &json!({ "password": password, "keystore": keystore_json }),
        )?;
        Ok(outcome.address)
    }

    /// The wallet's receiving address. Refused when no wallet is loaded.
    pub fn address(&self) -> Result<String, SessionError> {
        let outcome: AddressOutcome = self.typed("getnewaddress", &json!({}))?;
        Ok(outcome.address)
    }

    /// Confirmed and spendable balance, in Fah.
    pub fn balance(&self) -> Result<Balance, SessionError> {
        self.typed("getbalance", &json!({}))
    }

    /// Network identity, height, tip, mempool and peer counts.
    pub fn info(&self) -> Result<ChainInfo, SessionError> {
        self.typed("getinfo", &json!({}))
    }

    /// Sign, admit and broadcast a payment of `amount_fah` to `to`, paying
    /// `fee_fah` to the miner. Returns the transaction id.
    ///
    /// The amount is validated here before anything is signed; the node then
    /// re-validates the address network, the coin maturity and the balance, so
    /// nothing is signed that the chain would reject. A returned txid means
    /// the transaction is in the mempool and announced — not yet confirmed.
    pub fn send(
        &self,
        password: &str,
        to: &str,
        amount_fah: u64,
        fee_fah: u64,
    ) -> Result<String, SessionError> {
        if amount_fah == 0 {
            return Err(SessionError::Rejected(
                "the amount must be greater than zero".to_string(),
            ));
        }
        let outcome: TxidOutcome = self.typed(
            "sendtoaddress",
            &json!({
                "address": to,
                "amount": amount_fah,
                "fee": fee_fah,
                "password": password,
            }),
        )?;
        Ok(outcome.txid)
    }

    /// Mine `blocks` new blocks, paying this session's wallet key, and return
    /// the resulting chain height. Each block claims the transactions waiting
    /// in the mempool, so payments sent through this session (or broadcast by
    /// it for peers) confirm the same way they do on the network.
    pub fn mine(&self, blocks: u64) -> Result<u64, SessionError> {
        let outcome: MinedOutcome = self.typed("generate", &json!({ "blocks": blocks }))?;
        Ok(outcome.height)
    }
}

/// The `address` field shared by `createwallet`, `importwallet` and
/// `getnewaddress` replies.
#[derive(Deserialize)]
struct AddressOutcome {
    address: String,
}

/// The `sendtoaddress` reply.
#[derive(Deserialize)]
struct TxidOutcome {
    txid: String,
}

/// The `generate` reply, of which the session surfaces the final height.
#[derive(Deserialize)]
struct MinedOutcome {
    height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::consensus::reward::block_subsidy;
    use crate::crypto::secp256k1::PrivateKey;
    use crate::storage::CHAIN_FILE;
    use crate::FAH_PER_ZRO;

    /// Unwrap a rejection, panicking (with the actual outcome) on anything
    /// else. Refusals are the interesting behaviour in half these tests.
    fn rejected<T: std::fmt::Debug>(result: Result<T, SessionError>) -> String {
        match result {
            Err(SessionError::Rejected(message)) => message,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    fn regtest() -> ChainParams {
        ChainParams::regtest()
    }

    fn open_session(dir: &tempfile::TempDir) -> Session {
        Session::open(regtest(), dir.path()).expect("opening a regtest session")
    }

    /// A recipient identity that never touches any session: a fresh key and
    /// the address derived from it, plus its raw secret for recovery tests.
    fn recipient(params: ChainParams) -> (PrivateKey, String) {
        let key = PrivateKey::random();
        let address = Address::from_public_key(params.base58_pubkey_prefix, &key.public_key());
        (key, address.encode())
    }

    #[test]
    fn a_wallet_is_created_explicitly_and_never_by_opening() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_session(&dir);

        // Opening state must never invent a wallet...
        let status = session.wallet_status().unwrap();
        assert!(!status.present);
        assert_eq!(status.address, None);
        assert!(rejected(session.address()).contains("no wallet loaded"));
        assert!(rejected(session.balance()).contains("no wallet loaded"));
        assert!(!dir.path().join("wallet.json").exists());

        // ...creating one is an explicit, password-protected act.
        let address = session.create_wallet("hunter2").unwrap();
        Address::decode_for_network(&address, regtest().base58_pubkey_prefix)
            .expect("the fresh address decodes on its own network");

        let status = session.wallet_status().unwrap();
        assert!(status.present);
        assert_eq!(status.address.as_deref(), Some(address.as_str()));
        assert_eq!(session.address().unwrap(), address);

        // A second create must not silently replace the identity.
        assert!(rejected(session.create_wallet("another-password")).contains("already present"));
        assert_eq!(session.address().unwrap(), address);
    }

    #[test]
    fn mined_rewards_show_as_confirmed_then_mature() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_session(&dir);
        session.create_wallet("hunter2").unwrap();

        assert_eq!(session.mine(1).unwrap(), 1);
        let balance = session.balance().unwrap();
        // The height-1 coinbase is confirmed but not yet mature: 100 blocks
        // must build on top of it before it can be spent.
        assert_eq!(balance.confirmed_fah, block_subsidy(1));
        assert_eq!(balance.spendable_fah, 0);

        assert_eq!(session.mine(100).unwrap(), 101);
        let balance = session.balance().unwrap();
        assert!(
            balance.spendable_fah >= block_subsidy(1),
            "the height-1 coinbase is mature at height 101"
        );
        assert!(
            balance.confirmed_fah > balance.spendable_fah,
            "later coinbases are confirmed but still immature"
        );
    }

    #[test]
    fn a_payment_signs_broadcasts_confirms_and_reaches_its_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_session(&dir);
        let sender_address = session.create_wallet("hunter2").unwrap();
        session.mine(101).unwrap();

        let (recipient_key, recipient_address) = recipient(regtest());
        assert_ne!(sender_address, recipient_address);

        let amount_fah = 2 * FAH_PER_ZRO;
        let txid = session
            .send("hunter2", &recipient_address, amount_fah, 1_000)
            .unwrap();
        assert_eq!(txid.len(), 64, "a txid is a 32-byte hex digest");
        assert!(txid.chars().all(|c| c.is_ascii_hexdigit()));

        // Signed and broadcast — but honestly reported as *not yet confirmed*:
        // the payment waits in the mempool until a block claims it.
        let info = session.info().unwrap();
        assert_eq!(info.mempool, 1);
        assert_eq!(info.height, 101);

        // The next block carries it; the mempool drains, and the recipient can
        // prove the value moved by restoring from the raw secret alone.
        assert_eq!(session.mine(1).unwrap(), 102);
        assert_eq!(session.info().unwrap().mempool, 0);

        // The recipient recovers on their own machine: import the raw secret
        // into a fresh data directory and sync the chain it needs (here: a
        // copy of this node's chain store — an empty chain of its own would
        // simply not contain the payment yet).
        let restored_dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            dir.path().join(CHAIN_FILE),
            restored_dir.path().join(CHAIN_FILE),
        )
        .expect("copying the chain store for the recipient");
        let restored = open_session(&restored_dir);
        assert!(
            !restored.wallet_status().unwrap().present,
            "the recipient's machine starts without a wallet"
        );
        let secret_hex = hex::encode(recipient_key.to_bytes());
        assert_eq!(
            restored.import_secret("restore-me", &secret_hex).unwrap(),
            recipient_address
        );
        let balance = restored.balance().unwrap();
        assert_eq!(balance.confirmed_fah, amount_fah);
        assert_eq!(
            balance.spendable_fah, amount_fah,
            "a received payment is spendable as soon as it is confirmed \
             (maturity applies to mined rewards, not to transfers)"
        );
    }

    #[test]
    fn invalid_payments_are_refused_before_anything_is_signed() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_session(&dir);
        let wallet_address = session.create_wallet("hunter2").unwrap();
        session.mine(101).unwrap();

        let (_, recipient_address) = recipient(regtest());

        // Zero is refused before the node ever sees the call.
        assert!(
            rejected(session.send("hunter2", &recipient_address, 0, 1_000))
                .contains("greater than zero")
        );

        // So are malformed and empty addresses.
        for bad in ["not-an-address", ""] {
            rejected(session.send("hunter2", bad, FAH_PER_ZRO, 1_000));
        }

        // And a valid address from another network (mainnet uses prefix 0x00,
        // regtest/devnet 0x6f).
        let mainnet = ChainParams::mainnet();
        let foreign = Address::from_public_key(
            mainnet.base58_pubkey_prefix,
            &PrivateKey::random().public_key(),
        );
        rejected(session.send("hunter2", &foreign.encode(), FAH_PER_ZRO, 1_000));

        // An amount larger than every coin we own fails coin selection.
        assert!(
            rejected(session.send("hunter2", &recipient_address, u64::MAX / 2, 1_000))
                .contains("insufficient funds")
        );

        // A wrong password fails at keystore unlock, after selection.
        assert!(
            rejected(session.send("wrong-password", &recipient_address, FAH_PER_ZRO, 1_000))
                .contains("payment failed")
        );

        // Nothing was signed, admitted or paid out along the way.
        assert_eq!(session.info().unwrap().mempool, 0);
        assert_eq!(session.address().unwrap(), wallet_address);
    }

    #[test]
    fn a_backup_restores_its_identity_and_a_wrong_password_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_session(&dir);
        let original_address = session.create_wallet("hunter2").unwrap();

        // The backup is literally the wallet file — the same artifact the
        // desktop Download Shield writes out.
        let keystore = std::fs::read_to_string(dir.path().join("wallet.json")).unwrap();

        // A machine that already holds a wallet: a bad import must leave it
        // exactly as it found it...
        let other_dir = tempfile::tempdir().unwrap();
        let other = open_session(&other_dir);
        let keep = other.create_wallet("other-password").unwrap();
        assert!(matches!(
            other.import_keystore("wrong-password", &keystore),
            Err(SessionError::Rejected(_))
        ));
        assert_eq!(other.address().unwrap(), keep);

        // ...while the right password restores the original identity, and it
        // survives a reopen from disk.
        assert_eq!(
            other.import_keystore("hunter2", &keystore).unwrap(),
            original_address
        );
        drop(other);
        let reopened = open_session(&other_dir);
        assert_eq!(reopened.address().unwrap(), original_address);
    }

    #[test]
    fn reopening_a_session_finds_the_same_chain_and_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let address = {
            let session = open_session(&dir);
            session.create_wallet("hunter2").unwrap();
            session.mine(3).unwrap();
            session.address().unwrap()
        };

        let reopened = open_session(&dir);
        let info = reopened.info().unwrap();
        assert_eq!(info.network, "regtest");
        assert_eq!(info.height, 3);
        assert_eq!(info.peers, 0, "a session never starts the P2P servers");
        let status = reopened.wallet_status().unwrap();
        assert!(status.present);
        assert_eq!(status.address.as_deref(), Some(address.as_str()));
    }

    #[test]
    fn a_session_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Session>();
    }
}
