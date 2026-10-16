//! Chain persistence.
//!
//! A node's authoritative state is the ordered list of blocks in its active chain
//! plus the UTXO set those blocks produce. [`ChainData`] is that state as one
//! serializable value; a [`Store`] reads and writes it.
//!
//! Two backends are provided behind the same trait:
//! - [`FileStore`] writes a single JSON document to a data directory, atomically
//!   (write a sibling, then rename), so a crash mid-write can never leave a
//!   half-written chain on disk. JSON keeps the file inspectable and dependency-free.
//! - [`MemoryStore`] holds the chain in RAM for tests and ephemeral nodes.
//!
//! A production node would swap [`FileStore`] for a real database (RocksDB and
//! friends) by implementing [`Store`]; nothing above this module would change, which
//! is the whole point of the trait. Persisting the entire chain per block is O(state)
//! and fine for a devnet; a database backend makes it incremental.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::consensus::block::Block;
use crate::ledger::utxo::UtxoSet;

/// The chain document's file name inside a node's data directory.
pub const CHAIN_FILE: &str = "chain.json";

/// The whole of a node's persisted consensus state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainData {
    /// The active chain, ordered by height; `blocks[0]` is genesis.
    pub blocks: Vec<Block>,
    /// The UTXO set those blocks produce.
    pub utxo: UtxoSet,
    /// Total subsidy issued so far, used to enforce the 21,000,000 ZRO cap.
    pub subsidy_issued: u64,
}

impl ChainData {
    pub fn empty() -> Self {
        ChainData {
            blocks: Vec::new(),
            utxo: UtxoSet::new(),
            subsidy_issued: 0,
        }
    }

    /// The height of the tip, or `None` if there is no chain yet.
    pub fn height(&self) -> Option<u64> {
        self.blocks.last().map(|b| b.header.height)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage i/o error: {0}")]
    Io(String),
    #[error("stored chain data is corrupt: {0}")]
    Corrupt(String),
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        StorageError::Io(error.to_string())
    }
}

/// A place a chain can be loaded from and saved to.
pub trait Store: Send + Sync {
    /// Load the persisted chain, or `None` if nothing has been written yet.
    fn load(&self) -> Result<Option<ChainData>, StorageError>;
    /// Persist the chain, atomically where the backend allows it.
    fn save(&self, data: &ChainData) -> Result<(), StorageError>;
}

/// A JSON document in a data directory.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileStore { dir: dir.into() }
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(CHAIN_FILE)
    }
}

impl Store for FileStore {
    fn load(&self) -> Result<Option<ChainData>, StorageError> {
        let path = self.path();
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path)?;
        let data: ChainData =
            serde_json::from_str(&text).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        Ok(Some(data))
    }

    fn save(&self, data: &ChainData) -> Result<(), StorageError> {
        fs::create_dir_all(&self.dir)?;
        let text = serde_json::to_string(data).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        // Write to a sibling, then rename over the real file. On every platform
        // `rename` is atomic within a directory, so a reader sees either the old
        // chain or the new one, never a torn file.
        let temp = self.dir.join(format!("{CHAIN_FILE}.tmp"));
        fs::write(&temp, text)?;
        fs::rename(&temp, self.path())?;
        Ok(())
    }
}

/// An in-memory chain, for tests and throwaway nodes.
#[derive(Default)]
pub struct MemoryStore {
    data: Mutex<Option<ChainData>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore::default()
    }
}

impl Store for MemoryStore {
    fn load(&self) -> Result<Option<ChainData>, StorageError> {
        Ok(self.data.lock().map_err(|_| StorageError::Corrupt("poisoned".into()))?.clone())
    }

    fn save(&self, data: &ChainData) -> Result<(), StorageError> {
        *self.data.lock().map_err(|_| StorageError::Corrupt("poisoned".into()))? = Some(data.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrips() {
        let store = MemoryStore::new();
        assert!(store.load().unwrap().is_none());
        let data = ChainData {
            blocks: vec![],
            utxo: UtxoSet::new(),
            subsidy_issued: 5_000_000_000,
        };
        store.save(&data).unwrap();
        let loaded = store.load().unwrap().expect("saved");
        assert_eq!(loaded.subsidy_issued, data.subsidy_issued);
    }

    #[test]
    fn file_store_roundtrips_and_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        assert!(store.load().unwrap().is_none());
        let data = ChainData {
            blocks: vec![],
            utxo: UtxoSet::new(),
            subsidy_issued: 42,
        };
        store.save(&data).unwrap();
        let loaded = store.load().unwrap().expect("saved");
        assert_eq!(loaded, data);
        // No temp file is left behind.
        assert!(!dir.path().join(format!("{CHAIN_FILE}.tmp")).exists());
    }

    #[test]
    fn empty_chain_has_no_height() {
        assert_eq!(ChainData::empty().height(), None);
    }

    #[test]
    fn file_store_roundtrips_a_nonempty_utxo_set() {
        // Regression: the UTXO set must survive JSON even though its keys are
        // structs, which serde cannot emit as bare JSON object keys.
        use crate::consensus::reward::{block_subsidy, coinbase_transaction};
        use crate::crypto::secp256k1::PrivateKey;

        let key = PrivateKey::from_bytes([21u8; 32]).unwrap().public_key();
        let mut utxo = UtxoSet::new();
        let cb = coinbase_transaction(1, &key, block_subsidy(1));
        utxo.apply_coinbase(&cb, 1);
        assert_eq!(utxo.len(), 1);

        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        let data = ChainData {
            blocks: Vec::new(),
            utxo: utxo.clone(),
            subsidy_issued: block_subsidy(1),
        };
        store.save(&data).expect("saves a non-empty UTXO set");
        let loaded = store.load().unwrap().expect("saved");
        assert_eq!(loaded.utxo, utxo);
        assert_eq!(loaded.utxo.state_root(), utxo.state_root());
    }
}
