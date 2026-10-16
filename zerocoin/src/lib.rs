//! ZeroCoin (ZRO): a fair-launch, zero-premine, ownerless cryptocurrency.
//!
//! The crate is layered so each tier depends only on those below it:
//! `crypto` → `ledger` → `consensus` → `network`, with `params`/`address`/`genesis`
//! binding the consensus rules to a specific network, and `storage`/`chain`/`mempool`
//! assembling them into node state. `node` ties it all together, and `pool` adds the
//! off-chain share accounting that lets low-end devices earn micro-rewards without
//! ever changing what the chain agrees on. `datadir` fixes *where* all of that
//! state lives on a consumer machine, so the wallet survives software updates, and
//! `session` exposes the same node state as a small in-process wallet API for
//! front-ends that cannot spawn a daemon (mobile), backed by the exact same
//! operation handlers as the loopback RPC. `gui` (behind the default `gui`
//! feature) is the Slint wallet front-end shared by the desktop binary and the
//! Android app.

pub mod crypto;
pub mod ledger;
pub mod consensus;
pub mod network;
pub mod params;
pub mod datadir;
pub mod address;
pub mod genesis;
pub mod storage;
pub mod chain;
pub mod mempool;
pub mod wallet;
pub mod pool;
pub mod node;
pub mod session;

// The wallet UI: a library module (not a binary) because it compiles two ways
// — linked into the desktop `zerocoin-gui` binary, and exported as this
// package's `cdylib` for Android, where the OS calls its `android_main`
// symbol instead of a Rust `main`.
#[cfg(feature = "gui")]
pub mod gui;

pub use params::ChainParams;

/// Fah per ZRO: the fixed 8-decimal precision, like satoshis per bitcoin.
pub const FAH_PER_ZRO: u64 = 100_000_000;
/// The four-byte magic that opens every P2P frame, tying a stream to this network.
pub const NETWORK_MAGIC: [u8; 4] = *b"ZRO\0";
