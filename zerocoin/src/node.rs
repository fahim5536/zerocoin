//! The node daemon: consensus state, an authenticated P2P fabric, and a local RPC.
//!
//! [`Node`] ties together everything below it. It owns the [`Chain`] (consensus
//! state), the [`Mempool`] (unconfirmed transactions), an optional [`Wallet`] (an
//! encrypted key used for mining payouts and payments), and a long-term
//! [`NodeIdentity`] (which signs P2P handshakes and is *not* a wallet key). Two
//! independent servers run on their own threads:
//!
//! - **P2P** — peers connect over TCP, run the mutual-authentication handshake
//!   ([`crate::network::handshake`]), and then exchange [`Message`]s inside
//!   encrypted, replay-protected frames ([`crate::network::frame`]). Transactions
//!   and blocks propagate by the classic Bitcoin `inv`/`getdata` gossip: a node
//!   announces what it has, a peer asks for what it lacks, and relays it onward.
//!   A node that is behind a peer also runs a header-first catch-up
//!   (`getheaders`/`headers`), so it can pull a whole missing range of blocks in
//!   order instead of only ever seeing the peer's newest block.
//! - **RPC** — a plaintext, length-prefixed JSON server bound to the loopback
//!   interface only. It is a *different trust boundary* from P2P: it is how the
//!   operator's own `zerocoin-cli` drives the node (mine, send, query), and it is
//!   never exposed to the network. Keeping it local and separate from the
//!   authenticated fabric is exactly how Bitcoin Core separates `bitcoind` from
//!   `bitcoin-cli`.
//!
//! Concurrency is plain `std::thread` plus `Mutex`, matching the rest of the crate:
//! consensus state is a single [`Chain`] guarded by one lock, so there is no
//! data-race surface and no async runtime to reason about.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::chain::{now_timestamp, Chain, ChainError};
use crate::consensus::block::{Block, BlockHeader, MAX_BLOCK_TRANSACTIONS};
use crate::consensus::difficulty::compact_to_target;
use crate::consensus::pow::DEFAULT_SHARE_EASINESS;
use crate::consensus::reward::{pool_coinbase_transaction, split_reward};
use crate::crypto::hash::{Hash160, Hash256};
use crate::crypto::secp256k1::PrivateKey;
use crate::ledger::script::p2pkh_script_pubkey;
use crate::ledger::transaction::Outpoint;
use crate::mempool::Mempool;
use crate::network::frame::SecureChannel;
use crate::network::handshake::{
    begin_handshake, finish_handshake, respond_to_hello, Hello, HelloBack, NodeIdentity,
    SessionKeys,
};
use crate::network::message::{
    Inventory, Message, SharePayload, VersionPayload, MAX_HEADERS, MAX_INV_ENTRIES,
    PROTOCOL_VERSION,
};
use crate::params::ChainParams;
use crate::pool::{
    share_target_for, validate_share_submission, PoolLedger, ShareError, FINDER_SHARE_WEIGHT,
};
use crate::storage::FileStore;
use crate::wallet::Wallet;

/// The largest length-prefixed handshake/RPC message accepted (8 MiB).
const MAX_LEN_PREFIXED: usize = 8 * 1024 * 1024;
/// How long the accept loops sleep between non-blocking polls.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// First pause before redialling a seed that refused or dropped us.
const SEED_RETRY_INITIAL: Duration = Duration::from_secs(1);
/// Ceiling for the seed redial backoff, so a permanently absent peer costs
/// one idle wake-up per half minute instead of a busy retry loop.
const SEED_RETRY_MAX: Duration = Duration::from_secs(30);
/// How many blocks one catch-up `GetData` requests. Bounded by the gossip list
/// limit ([`crate::network::message::MAX_INV_ENTRIES`]) so a peer never has to
/// reject our request as oversized, while still draining a long history quickly.
const SYNC_BATCH: usize = MAX_INV_ENTRIES;

/// Upper bound on the rows `wallethistory` answers with, newest first. The
/// wallet view slices this further; the cap here keeps the response bounded
/// for any client.
const HISTORY_ROW_LIMIT: usize = 250;

type PeerId = u64;
/// Each peer's outbound queue carries *plaintext* message bytes; the peer's writer
/// thread seals them into a frame, so every peer keeps its own sequence numbering.
type Outbox = Sender<Vec<u8>>;

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("wallet error: {0}")]
    Wallet(#[from] crate::wallet::WalletError),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("node has no wallet loaded")]
    NoWallet,
}

/// Environment variable holding a wallet password for non-interactive startup.
/// `zerocoind` reads it (only when `--password` is absent) to create or unlock a
/// wallet at boot; the desktop wallet *removes* it from the embedded daemon's
/// environment so that node always starts walletless and onboarding stays the
/// only path to a wallet. One definition here keeps the daemon that reads it and
/// the wallet that strips it from drifting apart.
pub const WALLET_PASSWORD_ENV: &str = "ZRO_WALLET_PASSWORD";

/// Everything a node needs to start.
pub struct NodeConfig {
    pub params: ChainParams,
    /// Data directory holding the chain store and the wallet file.
    pub data_dir: PathBuf,
    /// Address to accept P2P connections on. Use port 0 for an ephemeral port.
    pub p2p_listen: SocketAddr,
    /// Address for the loopback JSON-RPC server, or `None` to run without RPC.
    pub rpc_listen: Option<SocketAddr>,
    /// Peers to dial on startup.
    pub seeds: Vec<SocketAddr>,
    /// Password for the wallet file. A wallet file that already exists is loaded
    /// regardless; when the file is *absent*, a non-empty password creates a fresh
    /// wallet here, while an empty password leaves the node walletless so the
    /// wallet can be created or imported later through the RPC lifecycle
    /// (`createwallet` / `importwallet`) — the embedded desktop-wallet flow.
    pub wallet_password: String,
}

/// The consensus and networking state shared by every thread of one node.
pub struct NodeState {
    pub params: ChainParams,
    pub identity: NodeIdentity,
    pub chain: Mutex<Chain>,
    pub mempool: Mutex<Mempool>,
    pub wallet: Mutex<Option<Wallet>>,
    /// The data directory the node was opened with. The wallet lifecycle RPCs
    /// (`createwallet` / `importwallet`) materialise `wallet.json` here, in the
    /// OS user-directory location shared with `zerocoind`.
    pub wallet_path: PathBuf,
    /// Off-chain pool accounting: the share weight each contributor has earned toward
    /// the next block. Never consensus state — the chain only ever sees the split
    /// coinbase a coordinator mines from it (see [`crate::pool`]).
    pub pool: Mutex<PoolLedger>,
    /// Dial-back addresses this node has learned, served on `GetAddr`.
    pub known_addrs: Mutex<Vec<SocketAddr>>,
    /// Block headers a peer announced that extend our chain but whose blocks we
    /// have not requested yet, ordered by height. Keeping them lets catch-up fetch
    /// blocks strictly in order, since [`crate::chain::Chain::connect_block`] only
    /// accepts a block whose parent is the current tip.
    sync_queue: Mutex<VecDeque<BlockHeader>>,
    /// Height of the highest block catch-up has asked a peer for. Continuation
    /// waits until our tip reaches it, so a further range is requested only once
    /// the previous one has fully connected.
    sync_requested_height: AtomicU64,
    /// Set when a peer's `Headers` reply filled the whole list, hinting it likely
    /// holds more. Continuation is gated on this, and clears it as it acts, so a
    /// caught-up peer cannot start a request loop.
    sync_more_available: AtomicBool,
    peers: Mutex<HashMap<PeerId, Outbox>>,
    next_peer: AtomicU64,
    /// A random per-connection nonce echoed in `Version`; a peer that returns it is
    /// us, and the connection is dropped to avoid self-loops.
    pub self_nonce: u64,
    stop: AtomicBool,
}

impl NodeState {
    fn register_peer(&self, out: Outbox) -> PeerId {
        let id = self.next_peer.fetch_add(1, Ordering::SeqCst);
        self.peers.lock().unwrap().insert(id, out);
        id
    }

    fn drop_peer(&self, id: PeerId) {
        self.peers.lock().unwrap().remove(&id);
    }

    /// Send an encoded message to every peer except `exclude`.
    fn broadcast_except(&self, msg: &Message, exclude: Option<PeerId>) {
        let Ok(bytes) = msg.encode() else {
            return;
        };
        let peers = self.peers.lock().unwrap();
        for (id, out) in peers.iter() {
            if Some(*id) == exclude {
                continue;
            }
            // A full outbox means a slow peer; dropping one relay is harmless because
            // the peer will re-request via inv/getdata.
            let _ = out.send(bytes.clone());
        }
    }

    fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// Whether a shutdown has been requested (via the RPC `stop` method).
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Send one message to a single peer's outbox.
fn send_msg(out: &Outbox, msg: &Message) {
    if let Ok(bytes) = msg.encode() {
        let _ = out.send(bytes);
    }
}

/// A running node. Dropping it does not stop the threads; call [`RunningNode::stop`].
pub struct RunningNode {
    pub state: Arc<NodeState>,
    pub p2p_addr: SocketAddr,
    pub rpc_addr: Option<SocketAddr>,
    threads: Vec<JoinHandle<()>>,
}

impl RunningNode {
    /// Signal every server loop to shut down and wait for them to finish.
    pub fn stop(self) {
        self.state.stop.store(true, Ordering::SeqCst);
        for handle in self.threads {
            let _ = handle.join();
        }
    }
}

/// A node: the entry point for opening state and running the servers.
pub struct Node;

impl Node {
    /// Open (or create) the chain and wallet for `config` without starting servers.
    pub fn open(config: &NodeConfig) -> Result<Arc<NodeState>, NodeError> {
        std::fs::create_dir_all(&config.data_dir)?;
        let store = FileStore::new(&config.data_dir);
        let chain = Chain::open(config.params, Box::new(store))?;

        // The wallet is only materialised when one already exists on disk, or
        // when a startup password was supplied. A walletless node (empty
        // password, no file) serves the chain and exposes the lifecycle RPCs so
        // the operator — or the embedded GUI — can create or import a wallet
        // later. This is what makes the consumer onboarding possible: the
        // daemon must never invent a wallet with a password nobody chose.
        let wallet_path = config.data_dir.join("wallet.json");
        let wallet = if wallet_path.exists() {
            Some(Wallet::load(config.params, &wallet_path)?)
        } else if config.wallet_password.is_empty() {
            None
        } else {
            Some(Wallet::create(config.params, &wallet_path, &config.wallet_password)?)
        };

        let self_nonce = rand::random::<u64>();
        Ok(Arc::new(NodeState {
            params: config.params,
            identity: NodeIdentity::random(),
            chain: Mutex::new(chain),
            mempool: Mutex::new(Mempool::new()),
            wallet: Mutex::new(wallet),
            wallet_path: config.data_dir.clone(),
            pool: Mutex::new(PoolLedger::new()),
            known_addrs: Mutex::new(Vec::new()),
            sync_queue: Mutex::new(VecDeque::new()),
            sync_requested_height: AtomicU64::new(0),
            sync_more_available: AtomicBool::new(false),
            peers: Mutex::new(HashMap::new()),
            next_peer: AtomicU64::new(0),
            self_nonce,
            stop: AtomicBool::new(false),
        }))
    }

    /// Open the node and start the P2P and RPC servers, returning the running handle.
    pub fn spawn(config: &NodeConfig) -> Result<RunningNode, NodeError> {
        let state = Node::open(config)?;

        let p2p_listener = TcpListener::bind(config.p2p_listen)?;
        p2p_listener.set_nonblocking(true)?;
        let p2p_addr = p2p_listener.local_addr()?;

        let mut rpc_addr = None;
        let mut rpc_listener = None;
        if let Some(addr) = config.rpc_listen {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            rpc_addr = Some(listener.local_addr()?);
            rpc_listener = Some(listener);
        }

        let mut threads = Vec::new();

        // P2P accept loop.
        {
            let state = Arc::clone(&state);
            threads.push(std::thread::spawn(move || {
                p2p_accept_loop(state, p2p_listener);
            }));
        }

        // RPC accept loop.
        if let Some(listener) = rpc_listener {
            let state = Arc::clone(&state);
            threads.push(std::thread::spawn(move || {
                rpc_accept_loop(state, listener);
            }));
        }

        // Dial the seeds. Peer sessions are detached, exactly as the inbound
        // connections are: a live session blocks in `read_frame` until its socket
        // closes, so `stop()` must not try to join one — it only stops the accept and
        // RPC loops, which poll the stop flag. Peer threads exit when their socket
        // does (or when the process ends).
        //
        // Each seed gets a redial loop. A single attempt would mean a seed that
        // happens to be restarting when this node boots is lost for the whole
        // run, leaving the node with no route to the network and a chain height
        // frozen at whatever it had. Reconnecting is what makes catch-up
        // eventually happen rather than only if the timing was lucky.
        for seed in &config.seeds {
            let state = Arc::clone(&state);
            let seed = *seed;
            std::thread::spawn(move || {
                // First retry after a second, then 2s, 4s … capped at
                // `SEED_RETRY_MAX`. Sleeping before widening the delay keeps the
                // first retry prompt, which is what matters when a peer is only
                // a moment slower to boot than this node.
                let mut backoff = SEED_RETRY_INITIAL;
                while !state.is_stopped() {
                    if dial_peer(Arc::clone(&state), seed).is_ok() {
                        // The handshake completed, so the peer is real; a
                        // session that ends is worth re-establishing at once.
                        backoff = SEED_RETRY_INITIAL;
                        std::thread::sleep(backoff);
                        continue;
                    }
                    if state.is_stopped() {
                        break;
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(SEED_RETRY_MAX);
                }
            });
        }

        Ok(RunningNode {
            state,
            p2p_addr,
            rpc_addr,
            threads,
        })
    }

    /// Open and run the node, blocking until it is stopped from another thread.
    pub fn run(config: &NodeConfig) -> Result<(), NodeError> {
        let running = Node::spawn(config)?;
        while !running.state.is_stopped() {
            std::thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// P2P transport
// ---------------------------------------------------------------------------

fn p2p_accept_loop(state: Arc<NodeState>, listener: TcpListener) {
    while !state.is_stopped() {
        match listener.accept() {
            Ok((stream, addr)) => {
                let _ = stream.set_nonblocking(false);
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = serve_peer(state, stream, addr, false) {
                        tracing_debug(&format!("inbound peer {addr} ended: {e}"));
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(_) => break,
        }
    }
}

/// Dial an outbound peer and serve it once the handshake succeeds.
fn dial_peer(state: Arc<NodeState>, addr: SocketAddr) -> io::Result<()> {
    let stream = TcpStream::connect(addr)?;
    serve_peer(state, stream, addr, true)
}

/// Run the handshake on a fresh socket, then serve messages until it closes.
/// `initiator` is true for an outbound connection (we send `Hello` first).
fn serve_peer(
    state: Arc<NodeState>,
    mut stream: TcpStream,
    addr: SocketAddr,
    initiator: bool,
) -> io::Result<()> {
    let chain = state.params.chain_id.0;
    let keys: SessionKeys = if initiator {
        let (istate, hello) = begin_handshake(&state.identity, chain);
        send_len_json(&mut stream, &hello)?;
        let back: HelloBack = recv_len_json(&mut stream)?;
        finish_handshake(istate, &back).map_err(|e| io_other(&e.to_string()))?
    } else {
        let hello: Hello = recv_len_json(&mut stream)?;
        let (keys, back) =
            respond_to_hello(&state.identity, chain, &hello).map_err(|e| io_other(&e.to_string()))?;
        send_len_json(&mut stream, &back)?;
        keys
    };

    // Two clones of the socket and two channels built from the same keys: the writer
    // thread only ever seals (advancing send_seq), the reader only ever opens
    // (advancing recv_seq), so the counters stay correct on each side.
    let writer_stream = stream.try_clone()?;
    let writer_channel = keys.channel();
    let mut channel = keys.channel();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let peer_id = state.register_peer(tx.clone());

    let wstate = Arc::clone(&state);
    let writer = std::thread::spawn(move || {
        peer_writer(wstate, writer_stream, writer_channel, rx);
    });

    // Announce ourselves and exchange version/verack.
    let height = state.chain.lock().unwrap().height();
    send_msg(
        &tx,
        &Message::Version(VersionPayload {
            version: PROTOCOL_VERSION,
            chain,
            height,
            listen: Some(addr),
            nonce: state.self_nonce,
        }),
    );

    let result = peer_reader(Arc::clone(&state), peer_id, &mut stream, &mut channel, &tx);

    state.drop_peer(peer_id);
    // Dropping our `tx` closes the writer's channel once `result` returns.
    drop(tx);
    let _ = writer.join();
    result
}

/// The per-peer writer: seal queued plaintext messages into authenticated frames.
fn peer_writer(
    _state: Arc<NodeState>,
    mut stream: TcpStream,
    mut channel: SecureChannel,
    rx: Receiver<Vec<u8>>,
) {
    while let Ok(bytes) = rx.recv() {
        if channel.write_frame(&mut stream, &bytes).is_err() {
            break;
        }
    }
}

/// The per-peer reader: open frames, decode messages, and dispatch them.
fn peer_reader(
    state: Arc<NodeState>,
    peer_id: PeerId,
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    out: &Outbox,
) -> io::Result<()> {
    loop {
        if state.is_stopped() {
            return Ok(());
        }
        match channel.read_frame(stream) {
            Ok(Some(bytes)) => {
                let Ok(msg) = Message::decode(&bytes) else {
                    return Err(io_other("undecodable message"));
                };
                if msg.validate_limits().is_err() {
                    return Err(io_other("message over list bounds"));
                }
                handle_message(&state, peer_id, msg, out)?;
            }
            Ok(None) => return Ok(()), // clean EOF
            Err(e) => return Err(io_other(&format!("frame error: {e}"))),
        }
    }
}

/// What happened to a block announced by a peer.
enum BlockOutcome {
    /// The block was validated and appended; its identity is the new tip.
    Connected,
    /// The block failed ordinary validation; drop it silently, as before.
    Rejected,
    /// The block tried to spend an immature coinbase — a frozen launch invariant.
    /// It was dropped whole; the peer that served it must be disconnected.
    FrozenInvariantViolation,
}

/// Dispatch one authenticated message, replying on `out` and relaying as needed.
///
/// Returns `Err` when the peer must be disconnected: a malformed or hostile
/// message, or a block that violates a frozen consensus invariant (see
/// [`crate::consensus::immutability`]). Ordinary invalid blocks are dropped
/// silently, exactly as before.
fn handle_message(
    state: &Arc<NodeState>,
    peer_id: PeerId,
    msg: Message,
    out: &Outbox,
) -> io::Result<()> {
    match msg {
        Message::Version(payload) => {
            if payload.chain != state.params.chain_id.0 {
                return Ok(()); // wrong network: ignore, the connection will idle out
            }
            if payload.nonce == state.self_nonce {
                return Ok(()); // we dialed ourselves
            }
            let height = state.chain.lock().unwrap().height();
            send_msg(
                out,
                &Message::Verack {
                    version: PROTOCOL_VERSION,
                    height,
                },
            );
            if let Some(listen) = payload.listen {
                remember_addr(state, listen);
            }
            // Ask the peer what it knows and share our view of the tip.
            send_msg(out, &Message::GetAddr);
            let tip = state.chain.lock().unwrap().tip_hash();
            send_msg(
                out,
                &Message::Inv {
                    items: vec![Inventory::block(tip)],
                },
            );
            // If the peer is ahead of us, ask for the headers above our tip so we
            // catch up, rather than only ever requesting its newest block.
            if payload.height > height {
                request_headers(state, out);
            }
        }
        Message::Verack { height, .. } => {
            // The responder's `Verack` carries its height; if it is ahead, pull the
            // headers above our tip so this node catches up instead of idling.
            let ours = state.chain.lock().unwrap().height();
            if height > ours {
                request_headers(state, out);
            }
        }
        Message::Ping { nonce } => send_msg(out, &Message::Pong { nonce }),
        Message::Pong { .. } => {}
        Message::GetAddr => {
            let addresses = state.known_addrs.lock().unwrap().clone();
            send_msg(out, &Message::Addr { addresses });
        }
        Message::Addr { addresses } => {
            for addr in addresses {
                remember_addr(state, addr);
            }
        }
        Message::Inv { items } => {
            // Request anything advertised that we do not already have.
            let mut wanted = Vec::new();
            {
                let chain = state.chain.lock().unwrap();
                let mempool = state.mempool.lock().unwrap();
                for item in items {
                    let have = match item.kind {
                        crate::network::message::InvKind::Block => chain.holds_block(&item.hash),
                        crate::network::message::InvKind::Tx => mempool.contains(&item.hash),
                    };
                    if !have {
                        wanted.push(item);
                    }
                }
            }
            if !wanted.is_empty() {
                send_msg(out, &Message::GetData { items: wanted });
            }
        }
        Message::GetData { items } => {
            for item in items {
                match item.kind {
                    crate::network::message::InvKind::Block => {
                        if let Some(block) = block_by_hash(state, &item.hash) {
                            send_msg(out, &Message::Block {
                                block: Box::new(block),
                            });
                        }
                    }
                    crate::network::message::InvKind::Tx => {
                        let mempool = state.mempool.lock().unwrap();
                        if let Some(entry) = mempool.get(&item.hash) {
                            send_msg(out, &Message::Tx {
                                transaction: Box::new(entry.tx.clone()),
                            });
                        }
                    }
                }
            }
        }
        Message::Tx { transaction } => {
            let tx = *transaction;
            let txid = tx.txid();
            let accepted = {
                let chain = state.chain.lock().unwrap();
                let mut mempool = state.mempool.lock().unwrap();
                mempool.admit(tx, &chain).is_ok()
            };
            if accepted {
                // Relay the announcement to everyone but the sender.
                state.broadcast_except(
                    &Message::Inv {
                        items: vec![Inventory::tx(txid)],
                    },
                    Some(peer_id),
                );
            }
        }
        Message::Block { block } => {
            let block = *block;

            // A block that does not hang off our tip is not necessarily invalid:
            // most often it is a peer's newest block while our own chain is still
            // behind. Dropping it used to strand the node for good, because the
            // announcer only ever offers the tip of a mining run (see `generate`),
            // so the blocks in between were never offered again and the node sat at
            // its old height with a healthy peer count. Treat the gap as a sync
            // hint instead: ask for the headers above our tip and let the ordinary
            // catch-up path fetch the missing range in order — this block arrives
            // again as part of it.
            {
                let chain = state.chain.lock().unwrap();
                let id = block.id(state.params.build_engine().as_ref());
                if chain.holds_block(&id) {
                    return Ok(()); // duplicate or stale announcement
                }
                let extends_tip = block.header.height == chain.next_height()
                    && block.header.previous_hash == chain.tip_hash();
                if !extends_tip {
                    // Throttled by the catch-up watermark, which records the
                    // highest height already asked for: an unhelpful peer that
                    // keeps serving the same unconnectable block cannot make this
                    // node emit a header request per block forever.
                    let already_requested = state
                        .sync_requested_height
                        .load(Ordering::SeqCst)
                        >= block.header.height;
                    drop(chain);
                    if !already_requested {
                        request_headers(state, out);
                    }
                    return Ok(());
                }
            }

            let outcome = {
                let mut chain = state.chain.lock().unwrap();
                let now = now_timestamp();
                match chain.connect_block(block.clone(), now) {
                    Ok(_) => {
                        let mut mempool = state.mempool.lock().unwrap();
                        mempool.prune_confirmed(&block.transactions);
                        BlockOutcome::Connected
                    }
                    // Rule 2 trip-wire (coinbase maturity guard): the block is
                    // dropped whole — `connect_block` is atomic, so nothing was
                    // applied — and the peer that served it is disconnected by
                    // the reader loop below.
                    Err(ChainError::Utxo(e))
                        if crate::consensus::immutability::isolates_peer(&e) =>
                    {
                        BlockOutcome::FrozenInvariantViolation
                    }
                    Err(_) => BlockOutcome::Rejected,
                }
            };
            match outcome {
                BlockOutcome::Connected => {
                    // The block was just connected, so its identity is the new tip.
                    let tip = state.chain.lock().unwrap().tip_hash();
                    state.broadcast_except(
                        &Message::Inv {
                            items: vec![Inventory::block(tip)],
                        },
                        Some(peer_id),
                    );
                    // Keep catching up: fetch the next queued run, and — once all we
                    // requested has connected — ask the peer for a further range.
                    continue_sync(state, out);
                }
                BlockOutcome::Rejected => {}
                BlockOutcome::FrozenInvariantViolation => {
                    return Err(io_other(
                        "peer served a block spending an immature coinbase: \
                         block dropped, peer isolated",
                    ));
                }
            }
        }
        Message::GetHeaders { locator, .. } => {
            let chain = state.chain.lock().unwrap();
            // Find the first locator hash we hold and send headers above it.
            let start = locator
                .iter()
                .find_map(|h| height_of_hash(&chain, h))
                .unwrap_or(0);
            let headers = chain.headers_above(start, crate::network::message::MAX_HEADERS);
            send_msg(out, &Message::Headers { headers });
        }
        Message::Headers { headers } => {
            // A reply that filled the whole list means the peer truncated at the
            // limit and likely holds more; remember so continuation can ask again.
            state
                .sync_more_available
                .store(headers.len() >= MAX_HEADERS, Ordering::SeqCst);
            queue_headers(state, headers);
            pump_sync(state, out);
        }
        Message::Share(payload) => {
            // A low-end device submitted a partial proof of work. Validate it and, if
            // it holds, credit the miner's share weight. This mints nothing and touches
            // no consensus state; a bogus share costs one hash and is dropped.
            if let Err(e) = handle_share(state, &payload) {
                tracing_debug(&format!("rejected share from peer {peer_id}: {e}"));
            }
        }
    }
    Ok(())
}

/// Validate one submitted share and, if it is sound, credit the miner's share weight
/// in the pool ledger. Returns the share's proof-of-work hash on success.
///
/// The share must be for this network and for the height this node would mine *next*;
/// one for an already-passed height is stale and refused. Its proof is checked against
/// the share target derived from that height's block target, so accepting a share costs
/// exactly one hash and never touches the chain. The two locks are taken in turn, never
/// together, matching the order every other code path uses.
fn handle_share(state: &Arc<NodeState>, payload: &SharePayload) -> Result<Hash256, ShareError> {
    let (share_tgt, height) = {
        let chain = state.chain.lock().unwrap();
        let height = chain.next_height();
        let block_target = compact_to_target(chain.required_bits(height));
        (share_target_for(&state.params, &block_target), height)
    };
    let engine = state.params.build_engine();
    let hash = validate_share_submission(
        engine.as_ref(),
        &payload.header,
        state.params.chain_id,
        height,
        &share_tgt,
    )?;
    // The share is sound: credit one unit of weight to the miner's payout key.
    state
        .pool
        .lock()
        .unwrap()
        .record_share(payload.payout.key_hash());
    Ok(hash)
}

fn remember_addr(state: &NodeState, addr: SocketAddr) {
    let mut addrs = state.known_addrs.lock().unwrap();
    if !addrs.contains(&addr) {
        addrs.push(addr);
    }
}

fn block_by_hash(state: &NodeState, hash: &Hash256) -> Option<Block> {
    let chain = state.chain.lock().unwrap();
    for height in 0..=chain.height() {
        if chain.hash_at(height) == Some(*hash) {
            return chain.block_at(height).cloned();
        }
    }
    None
}

fn height_of_hash(chain: &Chain, hash: &Hash256) -> Option<u64> {
    for height in 0..=chain.height() {
        if chain.hash_at(height) == Some(*hash) {
            return Some(height);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Chain catch-up (header-first sync)
// ---------------------------------------------------------------------------

/// Ask a peer for the block headers above our tip. The locator is the chain's
/// exponentially-spaced ancestor list, so the peer can locate our fork point in
/// one round even across a long history and reply with everything we are missing.
fn request_headers(state: &Arc<NodeState>, out: &Outbox) {
    let locator = state.chain.lock().unwrap().locator();
    send_msg(
        out,
        &Message::GetHeaders {
            locator,
            stop: Hash256::ZERO,
        },
    );
}

/// Queue the headers a peer returned, ignoring any that are already on our chain
/// or already queued. [`crate::chain::Chain::headers_above`] yields ascending
/// heights, so the queue stays ordered; contiguity is enforced when blocks are
/// actually requested, so a header we cannot hang off our tip is never fetched.
fn queue_headers(state: &Arc<NodeState>, headers: Vec<BlockHeader>) {
    let tip_height = state.chain.lock().unwrap().height();
    let mut queue = state.sync_queue.lock().unwrap();
    for header in headers {
        if header.height <= tip_height {
            continue;
        }
        if queue.iter().any(|q| q.height == header.height) {
            continue;
        }
        queue.push_back(header);
    }
}

/// Request the next contiguous run of queued blocks, in ascending height order.
///
/// [`crate::chain::Chain::connect_block`] only accepts a block whose parent is the
/// current tip, and a peer serves a `GetData` in the order it was sent while the
/// per-peer stream preserves that order, so a run requested together connects one
/// block at a time. The queue is drained as requests go out, so a block is never
/// requested twice while its earlier siblings are still in flight.
fn pump_sync(state: &Arc<NodeState>, out: &Outbox) {
    let engine = state.params.build_engine();
    let mut requests: Vec<Inventory> = Vec::new();
    let mut highest = 0u64;
    {
        let (mut tip, mut next_height) = {
            let chain = state.chain.lock().unwrap();
            (chain.tip_hash(), chain.height().saturating_add(1))
        };
        let mut queue = state.sync_queue.lock().unwrap();
        while requests.len() < SYNC_BATCH {
            match queue.front() {
                Some(h) if h.height == next_height && h.previous_hash == tip => {
                    let id = h.pow_hash(engine.as_ref());
                    requests.push(Inventory::block(id));
                    tip = id;
                    highest = next_height;
                    next_height = next_height.saturating_add(1);
                    queue.pop_front();
                }
                _ => break,
            }
        }
    }
    if !requests.is_empty() {
        state.sync_requested_height.store(highest, Ordering::SeqCst);
        send_msg(out, &Message::GetData { items: requests });
    }
}

/// Carry catch-up one step after a block connects: request the next run of blocks
/// we already know about, and — only once everything requested so far has actually
/// connected — ask the peer for a further range if its last header reply was
/// truncated. A caught-up peer answers with an empty `Headers`, which leaves the
/// "more available" hint clear and ends the exchange.
fn continue_sync(state: &Arc<NodeState>, out: &Outbox) {
    pump_sync(state, out);
    let caught_up = {
        let chain = state.chain.lock().unwrap();
        chain.height() >= state.sync_requested_height.load(Ordering::SeqCst)
    };
    let queue_empty = state.sync_queue.lock().unwrap().is_empty();
    if caught_up && queue_empty && state.sync_more_available.swap(false, Ordering::SeqCst) {
        request_headers(state, out);
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed JSON codec (handshake messages and RPC)
// ---------------------------------------------------------------------------

fn send_len_json<W: Write, T: Serialize>(writer: &mut W, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| io_other(&e.to_string()))?;
    let len = (bytes.len() as u32).to_le_bytes();
    writer.write_all(&len)?;
    writer.write_all(&bytes)?;
    writer.flush()
}

fn recv_len_json<R: Read, T: serde::de::DeserializeOwned>(reader: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_LEN_PREFIXED {
        return Err(io_other("length-prefixed message too large"));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io_other(&e.to_string()))
}

fn io_other(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
}

// ---------------------------------------------------------------------------
// Loopback JSON-RPC
// ---------------------------------------------------------------------------

/// An RPC request: a method name and JSON parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// An RPC response: either a result or an error string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn rpc_accept_loop(state: Arc<NodeState>, listener: TcpListener) {
    while !state.is_stopped() {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let _ = serve_rpc(state, stream);
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(_) => break,
        }
    }
}

fn serve_rpc(state: Arc<NodeState>, mut stream: TcpStream) -> io::Result<()> {
    let request: RpcRequest = recv_len_json(&mut stream)?;
    let response = dispatch_rpc(&state, request);
    send_len_json(&mut stream, &response)?;
    stream.flush()
}

/// Adapt one [`RpcRequest`] to [`handle_rpc`] and wrap the outcome for the wire.
fn dispatch_rpc(state: &Arc<NodeState>, request: RpcRequest) -> RpcResponse {
    match handle_rpc(state, &request.method, &request.params) {
        Ok(result) => RpcResponse {
            result: Some(result),
            error: None,
        },
        Err(e) => RpcResponse {
            result: None,
            error: Some(e),
        },
    }
}

/// The wallet's transaction ledger: pending payments first, then confirmed
/// rows newest-first, capped at [`HISTORY_ROW_LIMIT`].
///
/// The history is rebuilt from the blocks on every call — there is no
/// secondary index that could drift from the chain. One forward walk from
/// genesis to the tip tracks which of the wallet's outputs each transaction
/// consumed (`owned`), so a spend is attributed to the transaction that made
/// it. A single-key wallet has exactly three row kinds:
///
/// - `mined`    — a coinbase paying this wallet (the reward).
/// - `sent`     — a transaction spending wallet coins; `amount` is the net
///   change (change minus spent, fee included) and `fee` the surplus the
///   inputs left over every output.
/// - `received` — a transaction paying this wallet without spending from it.
fn wallet_history(chain: &Chain, pkhash: &Hash160, mempool: &Mempool) -> Value {
    let script = p2pkh_script_pubkey(pkhash);
    let tip = chain.height();

    // Pending rows first. A pooled payment spends coins that are still in
    // the UTXO set (the spend is not confirmed), so a walk over mined blocks
    // alone would never attribute it; this pass books it as a sent row
    // until a block claims it.
    let mut rows = Vec::new();
    for txid in mempool.txids() {
        let Some(entry) = mempool.get(&txid) else {
            continue; // a prune raced the snapshot; the next call sees the new set
        };
        let tx = &entry.tx;
        let debit: u64 = tx
            .inputs
            .iter()
            .filter_map(|input| chain.utxo().get(&input.previous_output))
            .filter(|entry| entry.output.script_pubkey == script)
            .map(|entry| entry.output.value)
            .sum();
        let credit: u64 = tx
            .outputs
            .iter()
            .filter(|output| output.script_pubkey == script)
            .map(|output| output.value)
            .sum();
        if debit == 0 && credit == 0 {
            continue;
        }
        if debit > 0 {
            rows.push(history_row(
                txid.to_display_hex(),
                0,
                "sent",
                credit as i64 - debit as i64,
                entry.fee,
                0,
            ));
        } else {
            rows.push(history_row(
                txid.to_display_hex(),
                0,
                "received",
                credit as i64,
                0,
                0,
            ));
        }
    }

    // Confirmed rows: one walk in chain order keeps coin attribution exact.
    // `owned` holds the wallet's outputs created so far; the block that
    // spends one removes it, and the resulting debit belongs to that
    // transaction.
    let mut owned: HashMap<Outpoint, u64> = HashMap::new();
    let mut confirmed = Vec::new();
    for height in 1..=tip {
        let Some(block) = chain.block_at(height) else {
            continue;
        };
        for tx in &block.transactions {
            let txid = tx.txid();
            let mut debit = 0u64;
            for input in &tx.inputs {
                if let Some(value) = owned.remove(&input.previous_output) {
                    debit += value;
                }
            }
            let credit: u64 = tx
                .outputs
                .iter()
                .filter(|output| output.script_pubkey == script)
                .map(|output| output.value)
                .sum();
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.script_pubkey == script {
                    owned.insert(
                        Outpoint {
                            txid,
                            vout: vout as u32,
                        },
                        output.value,
                    );
                }
            }
            if debit == 0 && credit == 0 {
                continue;
            }
            let confirmations = tip - height + 1;
            if tx.is_coinbase() {
                confirmed.push(history_row(
                    txid.to_display_hex(),
                    height,
                    "mined",
                    credit as i64,
                    0,
                    confirmations,
                ));
            } else if debit > 0 {
                // The fee is what the wallet's inputs left over: every coin
                // they added, minus every output the transaction created.
                let paid: u64 = tx.outputs.iter().map(|output| output.value).sum();
                confirmed.push(history_row(
                    txid.to_display_hex(),
                    height,
                    "sent",
                    credit as i64 - debit as i64,
                    debit.saturating_sub(paid),
                    confirmations,
                ));
            } else {
                confirmed.push(history_row(
                    txid.to_display_hex(),
                    height,
                    "received",
                    credit as i64,
                    0,
                    confirmations,
                ));
            }
        }
    }
    confirmed.reverse();
    rows.extend(confirmed);
    rows.truncate(HISTORY_ROW_LIMIT);
    json!({ "history": rows })
}

/// One `wallethistory` row, in the shape [`crate::session::HistoryEntry`]
/// deserializes and the wallet view renders.
fn history_row(
    txid: String,
    height: u64,
    direction: &str,
    amount: i64,
    fee: u64,
    confirmations: u64,
) -> Value {
    json!({
        "txid": txid,
        "height": height,
        "direction": direction,
        "amount": amount,
        "fee": fee,
        "confirmations": confirmations,
    })
}

/// Route one RPC call. Every method is served from the node's own state.
///
/// This is the single implementation of the node's operations: the loopback
/// RPC server dispatches through it, and so does [`crate::session::Session`]
/// — the in-process wallet core used where no daemon can be spawned (mobile
/// sandboxes) — so no two transports can ever drift apart.
pub(crate) fn handle_rpc(state: &Arc<NodeState>, method: &str, params: &Value) -> Result<Value, String> {
    match method {
        "getinfo" => {
            let chain = state.chain.lock().unwrap();
            let status = chain.describe();
            let mempool_len = state.mempool.lock().unwrap().len();
            Ok(json!({
                "network": status.network,
                "chain_id": status.chain_id,
                "height": status.height,
                "tip": status.tip.to_display_hex(),
                "difficulty_bits": status.difficulty_bits,
                "engine": status.engine,
                "utxo_count": status.utxo_count,
                "subsidy_issued": status.subsidy_issued,
                "state_root": status.state_root.to_display_hex(),
                "mempool": mempool_len,
                "peers": state.peer_count(),
            }))
        }
        "getnewaddress" => {
            let wallet = state.wallet.lock().unwrap();
            let wallet = wallet.as_ref().ok_or("no wallet loaded")?;
            Ok(json!({ "address": wallet.address_string() }))
        }
        "getbalance" => {
            let wallet_guard = state.wallet.lock().unwrap();
            let wallet = wallet_guard.as_ref().ok_or("no wallet loaded")?;
            let chain = state.chain.lock().unwrap();
            Ok(json!({
                "address": wallet.address_string(),
                "confirmed": wallet.balance(&chain),
                "spendable": wallet.spendable_balance(&chain),
            }))
        }
        "generate" => {
            // Mine `blocks` new blocks, paying this node's wallet key. No unlock is
            // needed: a coinbase pays a public key, it is not a spend.
            let count = params
                .get("blocks")
                .and_then(Value::as_u64)
                .ok_or("generate requires {\"blocks\": N}")?;
            let payout = {
                let wallet_guard = state.wallet.lock().unwrap();
                let wallet = wallet_guard.as_ref().ok_or("no wallet loaded")?;
                wallet.public_key()
            };
            let finder = payout.key_hash();
            let mut hashes = Vec::new();
            let mut pooled = 0u64;
            for _ in 0..count {
                let now = now_timestamp();
                // Every block claims what our mempool is holding, so a payment
                // this node signed confirms instead of sitting forever. The
                // coinbase is a block transaction too, hence the minus one.
                let txs = state
                    .mempool
                    .lock()
                    .unwrap()
                    .take_for_block(MAX_BLOCK_TRANSACTIONS - 1);
                // Drain the pool first, then take the chain lock, so the two are never
                // held at once (the same order `handle_share` uses).
                let contributions = state.pool.lock().unwrap().drain();
                let (tip_hex, confirmed) = {
                    let mut chain = state.chain.lock().unwrap();
                    let block = if contributions.is_empty() {
                        chain
                            .mine_block(&payout, txs, now)
                            .map_err(|e| format!("mining failed: {e}"))?
                    } else {
                        let height = chain.next_height();
                        let reward = chain
                            .projected_reward(&txs)
                            .map_err(|e| format!("mining failed: {e}"))?;
                        // Credit the finder as though it submitted a whole block of
                        // shares, so it keeps the bulk while mobiles earn their slice.
                        let mut weights = contributions;
                        match weights.iter_mut().find(|(h, _)| *h == finder) {
                            Some((_, w)) => *w = w.saturating_add(FINDER_SHARE_WEIGHT),
                            None => weights.push((finder, FINDER_SHARE_WEIGHT)),
                        }
                        let payouts = split_reward(reward, &weights);
                        let coinbase = pool_coinbase_transaction(height, reward, &payouts);
                        let block = chain
                            .mine_block_with_coinbase(coinbase, txs, now)
                            .map_err(|e| format!("mining failed: {e}"))?;
                        pooled += 1;
                        block
                    };
                    (chain.tip_hash().to_display_hex(), block.transactions)
                };
                // The block is connected: drop everything it confirmed from the
                // mempool, and everything whose coins it consumed.
                state.mempool.lock().unwrap().prune_confirmed(&confirmed);
                hashes.push(tip_hex);
            }
            let (height, tip) = {
                let chain = state.chain.lock().unwrap();
                (chain.height(), chain.tip_hash())
            };
            // Announce the new tip so connected peers fetch it.
            state.broadcast_except(
                &Message::Inv {
                    items: vec![Inventory::block(tip)],
                },
                None,
            );
            Ok(json!({ "mined": count, "height": height, "tip": tip.to_display_hex(), "hashes": hashes, "pooled_blocks": pooled }))
        }
        "sendtoaddress" => {
            let address = params
                .get("address")
                .and_then(Value::as_str)
                .ok_or("sendtoaddress requires an address")?
                .to_string();
            let amount = params
                .get("amount")
                .and_then(Value::as_u64)
                .ok_or("sendtoaddress requires an amount in Fah")?;
            let fee = params.get("fee").and_then(Value::as_u64).unwrap_or(1_000);
            let password = params
                .get("password")
                .and_then(Value::as_str)
                .ok_or("sendtoaddress requires the wallet password")?;

            let tx = {
                let wallet_guard = state.wallet.lock().unwrap();
                let wallet = wallet_guard.as_ref().ok_or("no wallet loaded")?;
                let chain = state.chain.lock().unwrap();
                wallet
                    .send(password, &chain, &address, amount, fee)
                    .map_err(|e| format!("payment failed: {e}"))?
            };
            let txid = tx.txid();
            // Admit to our own mempool, then announce it to the network.
            {
                let chain = state.chain.lock().unwrap();
                let mut mempool = state.mempool.lock().unwrap();
                mempool
                    .admit(tx, &chain)
                    .map_err(|e| format!("mempool rejected payment: {e}"))?;
            }
            state.broadcast_except(
                &Message::Inv {
                    items: vec![Inventory::tx(txid)],
                },
                None,
            );
            Ok(json!({ "txid": txid.to_display_hex() }))
        }
        "getpoolinfo" => {
            // Snapshot the share target for the height we are mining, then read the
            // pool. The chain lock is released before the pool lock, as everywhere else.
            let (height, share_tgt) = {
                let chain = state.chain.lock().unwrap();
                let height = chain.next_height();
                let block_target = compact_to_target(chain.required_bits(height));
                (height, share_target_for(&state.params, &block_target).to_string())
            };
            let pool = state.pool.lock().unwrap();
            Ok(json!({
                "active": !pool.is_empty(),
                "contributors": pool.contributor_count(),
                "total_weight": pool.total_weight(),
                "mining_height": height,
                "share_easiness": DEFAULT_SHARE_EASINESS,
                "share_target": share_tgt,
                "finder_weight": FINDER_SHARE_WEIGHT,
            }))
        }
        "walletstatus" => {
            // Non-destructive identity probe. Answers "does this node hold a
            // wallet?" without ever creating one — the onboarding layer calls
            // this before showing the Welcome session, and the GUI poll loop
            // calls it to detect a wallet appearing under it.
            let wallet_guard = state.wallet.lock().unwrap();
            match wallet_guard.as_ref() {
                Some(wallet) => Ok(json!({
                    "present": true,
                    "address": wallet.address_string(),
                })),
                None => Ok(json!({
                    "present": false,
                    "address": Value::Null,
                })),
            }
        }
        "createwallet" => {
            // Create a fresh single-key wallet and persist it atomically. The
            // wallet file is sealed before the node keeps it in memory, so the
            // raw key never survives the call. Refuses to overwrite an existing
            // wallet — replacing an identity requires an explicit import.
            let password = params
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if password.is_empty() {
                return Err("createwallet requires a non-empty wallet password".to_string());
            }
            let path = state
                .wallet_path
                .join("wallet.json");
            let wallet = Wallet::create(state.params, &path, password)
                .map_err(|e| format!("creating the wallet failed: {e}"))?;
            let address = wallet.address_string().to_string();
            *state.wallet.lock().unwrap() = Some(wallet);
            Ok(json!({ "created": true, "address": address }))
        }
        "importwallet" => {
            // Import an existing identity. Two forms, one of which is required:
            //   secret     — 64 hex chars (32 bytes): the raw secp256k1 scalar.
            //                Re-sealed on this machine under the supplied
            //                password; the restored balance is visible as soon
            //                as the chain catches up.
            //   keystore   — the full encrypted wallet file (JSON). Its
            //                identity-bound AEAD tag means the supplied password
            //                is proven by opening it before anything is written.
            let password = params
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if password.is_empty() {
                return Err("importwallet requires the wallet password".to_string());
            }
            let secret_hex = params.get("secret").and_then(Value::as_str);
            let keystore_json = params.get("keystore").and_then(Value::as_str);

            if let Some(secret_hex) = secret_hex {
                let bytes = hex::decode(secret_hex.trim())
                    .map_err(|e| format!("secret is not valid hex: {e}"))?;
                let scalar: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "secret must be exactly 32 bytes (64 hex characters)".to_string())?;
                let key = PrivateKey::from_bytes(scalar)
                    .map_err(|e| format!("secret is not a secp256k1 scalar: {e}"))?;
                let path = state
                    .wallet_path
                    .join("wallet.json");
                let wallet = Wallet::create_from_key(state.params, &path, password, key)
                    .map_err(|e| format!("importing the secret failed: {e}"))?;
                let address = wallet.address_string().to_string();
                *state.wallet.lock().unwrap() = Some(wallet);
                Ok(json!({ "imported": true, "address": address, "source": "secret" }))
            } else if let Some(keystore_json) = keystore_json {
                // The keystore is validated by passing it through the same path
                // a restart would take: written to disk, then loaded with
                // `Wallet::load` (which enforces the wallet format and the
                // network's chain id) and finally unlocked, which proves the
                // password against the identity-bound AEAD tag. Only a keystore
                // that survives all three is kept; on any failure the original
                // file is restored. The import is a full identity swap, so it is
                // allowed to replace an existing wallet.
                let path = state.wallet_path.join("wallet.json");
                let backup = std::fs::read(&path).ok();
                let temp = path.with_extension("json.tmp");
                std::fs::write(&temp, keystore_json)
                    .map_err(|e| format!("writing the keystore to import: {e}"))?;
                std::fs::rename(&temp, &path)
                    .map_err(|e| format!("installing the keystore to import: {e}"))?;

                let loaded = Wallet::load(state.params, &path).and_then(|wallet| {
                    wallet.unlock(password)?;
                    Ok(wallet)
                });
                match loaded {
                    Ok(wallet) => {
                        let address = wallet.address_string().to_string();
                        *state.wallet.lock().unwrap() = Some(wallet);
                        Ok(json!({ "imported": true, "address": address, "source": "keystore" }))
                    }
                    Err(error) => {
                        // Put the previous state back; the import must leave
                        // the machine exactly as it found it when it fails.
                        match backup {
                            Some(previous) => {
                                let _ = std::fs::write(&temp, previous);
                                let _ = std::fs::rename(&temp, &path);
                            }
                            None => {
                                let _ = std::fs::remove_file(&path);
                            }
                        }
                        Err(format!(
                            "the keystore was rejected ({error}); the previous wallet, if any, is untouched"
                        ))
                    }
                }
            } else {
                Err("importwallet requires either a 'secret' scalar or a 'keystore' file".to_string())
            }
        }
        "wallethistory" => {
            // The wallet's ledger, derived from current state — no stored
            // index can drift from the chain. Lock order follows the other
            // handlers: wallet, then chain, then mempool.
            let wallet_guard = state.wallet.lock().unwrap();
            let wallet = wallet_guard.as_ref().ok_or("no wallet loaded")?;
            let pkhash = wallet.pubkey_hash();
            let chain = state.chain.lock().unwrap();
            let mempool = state.mempool.lock().unwrap();
            Ok(wallet_history(&chain, &pkhash, &mempool))
        }
        "getpeercount" => Ok(json!({ "peers": state.peer_count() })),
        "stop" => {
            state.stop.store(true, Ordering::SeqCst);
            Ok(json!({ "stopping": true }))
        }
        other => Err(format!("unknown method '{other}'")),
    }
}

/// A minimal RPC client used by `zerocoin-cli` and the integration tests.
pub fn rpc_call(addr: SocketAddr, method: &str, params: Value) -> io::Result<Value> {
    let mut stream = TcpStream::connect(addr)?;
    let request = RpcRequest {
        method: method.to_string(),
        params,
    };
    send_len_json(&mut stream, &request)?;
    let response: RpcResponse = recv_len_json(&mut stream)?;
    if let Some(error) = response.error {
        return Err(io_other(&error));
    }
    Ok(response.result.unwrap_or(Value::Null))
}

/// A tiny stderr logger. Kept dependency-free; a real deployment would use `log`.
fn tracing_debug(msg: &str) {
    if std::env::var("ZRO_DEBUG").is_ok() {
        eprintln!("[zerocoin] {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::block::BlockHeader;
    use crate::consensus::pow::mine;
    use crate::crypto::secp256k1::{PrivateKey, PublicKey};
    use std::time::Instant;

    fn regtest_config(dir: &std::path::Path, rpc: bool) -> NodeConfig {
        NodeConfig {
            params: ChainParams::regtest(),
            data_dir: dir.to_path_buf(),
            p2p_listen: "127.0.0.1:0".parse().unwrap(),
            rpc_listen: if rpc {
                Some("127.0.0.1:0".parse().unwrap())
            } else {
                None
            },
            seeds: Vec::new(),
            wallet_password: "test-password".to_string(),
        }
    }

    #[test]
    fn rpc_generate_mines_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let config = regtest_config(dir.path(), true);
        let node = Node::spawn(&config).expect("spawns");
        let rpc = node.rpc_addr.expect("rpc bound");

        let info = rpc_call(rpc, "getinfo", json!({})).expect("getinfo");
        assert_eq!(info["height"].as_u64(), Some(0), "starts at genesis");

        let result = rpc_call(rpc, "generate", json!({ "blocks": 5 })).expect("generate");
        assert_eq!(result["mined"].as_u64(), Some(5));
        assert_eq!(result["height"].as_u64(), Some(5));

        let info = rpc_call(rpc, "getinfo", json!({})).expect("getinfo");
        assert_eq!(info["height"].as_u64(), Some(5));

        node.stop();
    }

    #[test]
    fn rpc_reports_wallet_address_and_balance() {
        let dir = tempfile::tempdir().unwrap();
        let config = regtest_config(dir.path(), true);
        let node = Node::spawn(&config).expect("spawns");
        let rpc = node.rpc_addr.expect("rpc bound");

        let addr = rpc_call(rpc, "getnewaddress", json!({})).expect("address");
        assert!(addr["address"].as_str().is_some());

        // Mine to the wallet, then the balance reflects the subsidy.
        rpc_call(rpc, "generate", json!({ "blocks": 1 })).unwrap();
        let balance = rpc_call(rpc, "getbalance", json!({})).expect("balance");
        assert_eq!(
            balance["confirmed"].as_u64(),
            Some(crate::consensus::reward::block_subsidy(1))
        );
        // Immature: nothing is spendable yet.
        assert_eq!(balance["spendable"].as_u64(), Some(0));

        node.stop();
    }

    #[test]
    fn wallet_persists_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let config = regtest_config(dir.path(), true);
        let node = Node::spawn(&config).expect("spawns");
        let rpc = node.rpc_addr.expect("rpc bound");
        rpc_call(rpc, "generate", json!({ "blocks": 3 })).unwrap();
        let addr = rpc_call(rpc, "getnewaddress", json!({})).unwrap();
        node.stop();

        // Reopen the same data directory: the chain and wallet are recovered.
        let config2 = regtest_config(dir.path(), true);
        let node2 = Node::spawn(&config2).expect("respawns");
        let rpc2 = node2.rpc_addr.expect("rpc bound");
        let info = rpc_call(rpc2, "getinfo", json!({})).unwrap();
        assert_eq!(info["height"].as_u64(), Some(3));
        let addr2 = rpc_call(rpc2, "getnewaddress", json!({})).unwrap();
        assert_eq!(addr["address"], addr2["address"], "same wallet identity");
        // Both persisted artifacts are anchored to the one data directory: the
        // ledger under its pinned name (`chain.json`) and the encrypted wallet
        // (`wallet.json`) beside it. This is the `%APPDATA%\ZeroCoin\<network>`
        // anchor both `zerocoind` and `zerocoin-gui` resolve through
        // `zerocoin::datadir::default_datadir`.
        assert!(dir.path().join(crate::storage::CHAIN_FILE).is_file());
        assert!(dir.path().join("wallet.json").is_file());
        node2.stop();
    }

    /// Two regtest nodes: when one mines a block, the other fetches and connects it
    /// through inv/getdata gossip over the authenticated channel.
    #[test]
    fn a_mined_block_propagates_to_a_peer() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let config_a = regtest_config(dir_a.path(), true);
        let node_a = Node::spawn(&config_a).expect("spawns A");
        let rpc_a = node_a.rpc_addr.unwrap();

        let mut config_b = regtest_config(dir_b.path(), true);
        config_b.seeds = vec![node_a.p2p_addr];
        let node_b = Node::spawn(&config_b).expect("spawns B");
        let rpc_b = node_b.rpc_addr.unwrap();

        // Give the outbound dial time to complete the handshake.
        wait_until(Duration::from_secs(5), || {
            rpc_call(rpc_a, "getpeercount", json!({}))
                .map(|v| v["peers"].as_u64().unwrap_or(0) >= 1)
                .unwrap_or(false)
                && rpc_call(rpc_b, "getpeercount", json!({}))
                    .map(|v| v["peers"].as_u64().unwrap_or(0) >= 1)
                    .unwrap_or(false)
        });

        // Mine on A; B should learn the new tip through gossip.
        rpc_call(rpc_a, "generate", json!({ "blocks": 1 })).unwrap();
        let propagated = wait_until(Duration::from_secs(10), || {
            rpc_call(rpc_b, "getinfo", json!({}))
                .map(|v| v["height"].as_u64().unwrap_or(0) >= 1)
                .unwrap_or(false)
        });
        assert!(propagated, "node B did not reach height 1 via gossip");

        node_a.stop();
        node_b.stop();
    }

    /// A node that joins *after* the chain is already several blocks long must
    /// catch up to the peer's tip. This is the regression for header sync: without
    /// it the lagging node could only ever request the newest block, which
    /// `connect_block` rejects out of order, so it stalled one block behind forever.
    #[test]
    fn a_lagging_node_catches_up_across_several_blocks() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let config_a = regtest_config(dir_a.path(), true);
        let node_a = Node::spawn(&config_a).expect("spawns A");
        let rpc_a = node_a.rpc_addr.unwrap();

        // A gets several blocks ahead before B ever connects.
        rpc_call(rpc_a, "generate", json!({ "blocks": 6 })).unwrap();
        let ahead = rpc_call(rpc_a, "getinfo", json!({})).unwrap();
        assert_eq!(ahead["height"].as_u64(), Some(6));

        let mut config_b = regtest_config(dir_b.path(), true);
        config_b.seeds = vec![node_a.p2p_addr];
        let node_b = Node::spawn(&config_b).expect("spawns B");
        let rpc_b = node_b.rpc_addr.unwrap();

        // B starts at genesis and must climb all the way to A's tip, not just one
        // block, which is all inv/getdata alone would ever manage.
        let caught_up = wait_until(Duration::from_secs(20), || {
            rpc_call(rpc_b, "getinfo", json!({}))
                .map(|v| v["height"].as_u64().unwrap_or(0) >= 6)
                .unwrap_or(false)
        });
        assert!(
            caught_up,
            "node B did not catch up to height 6; header sync is not pulling the history"
        );

        // After catch-up the two nodes agree on the tip.
        let tip_a = rpc_call(rpc_a, "getinfo", json!({})).unwrap()["tip"].clone();
        let tip_b = rpc_call(rpc_b, "getinfo", json!({})).unwrap()["tip"].clone();
        assert_eq!(tip_a, tip_b, "the lagging node converged on the peer's tip");

        node_a.stop();
        node_b.stop();
    }

    /// A seed that is not listening yet must not be abandoned.
    ///
    /// The node is started first, pointed at an address with nothing behind it,
    /// and only later does the peer start listening there. A single-attempt dial
    /// gives up during that window and the node stays isolated for the rest of
    /// its life: no peers, no block gossip, and a chain height frozen at
    /// genesis. The redial loop is what turns that into an ordinary slow start.
    #[test]
    fn a_seed_that_appears_later_is_still_dialled() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        // Claim a port for A and release it, so the address is concrete but
        // genuinely empty while B boots.
        let seed_addr = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };

        let mut config_b = regtest_config(dir_b.path(), true);
        config_b.seeds = vec![seed_addr];
        let node_b = Node::spawn(&config_b).expect("spawns B");
        let rpc_b = node_b.rpc_addr.unwrap();

        // Let the first dial attempt fail against the empty port. B must come
        // up regardless — an unreachable seed is not a startup error.
        std::thread::sleep(Duration::from_millis(300));
        let peers_b = rpc_call(rpc_b, "getpeercount", json!({})).unwrap()["peers"]
            .as_u64()
            .unwrap_or(0);
        assert_eq!(peers_b, 0, "B cannot already have a peer: nothing is listening yet");

        // Now the peer appears at exactly the address B was given.
        let mut config_a = regtest_config(dir_a.path(), true);
        config_a.p2p_listen = seed_addr;
        let node_a = Node::spawn(&config_a).expect("spawns A");
        let rpc_a = node_a.rpc_addr.unwrap();
        assert_eq!(node_a.p2p_addr, seed_addr, "A bound the contested address");

        let reconnected = wait_until(Duration::from_secs(20), || {
            rpc_call(rpc_b, "getpeercount", json!({}))
                .map(|v| v["peers"].as_u64().unwrap_or(0) >= 1)
                .unwrap_or(false)
        });
        assert!(
            reconnected,
            "B never redialled its seed; a seed that starts late leaves the node isolated"
        );

        // The session B re-established must be a working one, not just a
        // counted socket: a block mined on A has to reach B.
        rpc_call(rpc_a, "generate", json!({ "blocks": 1 })).unwrap();
        let synced = wait_until(Duration::from_secs(15), || {
            rpc_call(rpc_b, "getinfo", json!({}))
                .map(|v| v["height"].as_u64().unwrap_or(0) >= 1)
                .unwrap_or(false)
        });
        assert!(synced, "B redialled but never received A's block");

        node_a.stop();
        node_b.stop();
    }

    /// A batch mined while the peer is already connected must reach it.
    ///
    /// This is the regression for a node that connected *before* the mining
    /// run started: it announced nothing to us at handshake time (our heights
    /// matched), and the miner then advertises only the tip of the whole run.
    /// That single block cannot connect without its ancestors, so a reader that
    /// simply dropped it left the chain frozen at genesis — a live peer, no
    /// error, and no progress. The fix is to treat an unconnectable block as a
    /// catch-up hint, which this test pins down.
    #[test]
    fn a_batch_mined_after_connecting_is_pulled_in_full() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let config_a = regtest_config(dir_a.path(), true);
        let node_a = Node::spawn(&config_a).expect("spawns A");
        let rpc_a = node_a.rpc_addr.unwrap();

        let mut config_b = regtest_config(dir_b.path(), true);
        config_b.seeds = vec![node_a.p2p_addr];
        let node_b = Node::spawn(&config_b).expect("spawns B");
        let rpc_b = node_b.rpc_addr.unwrap();

        // Both are at genesis: the handshake gives B no reason to ask for
        // headers, so everything B learns from here has to come from the
        // announcement of a block it cannot attach yet.
        let connected = wait_until(Duration::from_secs(10), || {
            rpc_call(rpc_b, "getpeercount", json!({}))
                .map(|v| v["peers"].as_u64().unwrap_or(0) >= 1)
                .unwrap_or(false)
        });
        assert!(connected, "B never established its session with A");
        assert_eq!(
            rpc_call(rpc_b, "getinfo", json!({})).unwrap()["height"].as_u64(),
            Some(0),
            "B must still be at genesis before A mines"
        );

        // One call, five blocks: the tip is announced once.
        rpc_call(rpc_a, "generate", json!({ "blocks": 5 })).unwrap();

        let caught_up = wait_until(Duration::from_secs(20), || {
            rpc_call(rpc_b, "getinfo", json!({}))
                .map(|v| v["height"].as_u64().unwrap_or(0) >= 5)
                .unwrap_or(false)
        });
        assert!(
            caught_up,
            "B kept a peer but never pulled the batch; an unconnectable block must trigger a header sync"
        );

        let tip_a = rpc_call(rpc_a, "getinfo", json!({})).unwrap()["tip"].clone();
        let tip_b = rpc_call(rpc_b, "getinfo", json!({})).unwrap()["tip"].clone();
        assert_eq!(tip_a, tip_b, "the two nodes agree on the tip after the batch");

        node_a.stop();
        node_b.stop();
    }

    /// Poll `cond` until it holds or the deadline passes; returns the last value.
    fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        loop {
            if cond() {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn node_identity_is_not_a_wallet_key() {
        let dir = tempfile::tempdir().unwrap();
        let config = regtest_config(dir.path(), false);
        let state = Node::open(&config).expect("opens");
        let identity = state.identity.public_key();
        let wallet_key = state
            .wallet
            .lock()
            .unwrap()
            .as_ref()
            .expect("wallet")
            .public_key();
        // The P2P signing identity and the payout key are independent.
        assert_ne!(identity.to_sec1(), wallet_key.to_sec1());
        let _ = PrivateKey::random();
    }

    /// Build a valid share for the height `state` would mine next, paid to `payout`.
    /// Regtest uses the trivial engine and the easiest target, so this mines instantly.
    fn make_share(state: &Arc<NodeState>, payout: PublicKey) -> SharePayload {
        let (height, bits, chain_id, prev, engine_id) = {
            let chain = state.chain.lock().unwrap();
            let height = chain.next_height();
            (
                height,
                chain.required_bits(height),
                state.params.chain_id.0,
                chain.tip_hash(),
                state.params.engine.id(),
            )
        };
        let engine = state.params.build_engine();
        let block_target = compact_to_target(bits);
        let share_tgt = share_target_for(&state.params, &block_target);
        let mut header = BlockHeader {
            version: crate::consensus::block::BLOCK_VERSION,
            chain: chain_id,
            height,
            previous_hash: prev,
            merkle_root: Hash256::ZERO,
            timestamp: now_timestamp(),
            difficulty_bits: bits,
            engine_id,
            nonce: 0,
        };
        let (nonce, _) =
            mine(engine.as_ref(), &header.preimage(), &share_tgt, 0).expect("share is easy");
        header.nonce = nonce;
        SharePayload { header, payout }
    }

    /// A mobile device submits a share, then the next mined block splits its subsidy
    /// so the mobile earns a micro-reward — while exactly one subsidy enters supply.
    #[test]
    fn a_submitted_share_earns_a_mobile_micro_reward() {
        let dir = tempfile::tempdir().unwrap();
        let config = regtest_config(dir.path(), true);
        let node = Node::spawn(&config).expect("spawns");
        let rpc = node.rpc_addr.expect("rpc bound");

        let mobile = PrivateKey::from_bytes([0x5Eu8; 32]).unwrap().public_key();
        let mobile_hash = mobile.key_hash();

        // Submit a share straight to the coordinator; it is validated and credited.
        let share = make_share(&node.state, mobile);
        assert!(
            handle_share(&node.state, &share).is_ok(),
            "a valid share is accepted"
        );

        let info = rpc_call(rpc, "getpoolinfo", json!({})).expect("getpoolinfo");
        assert_eq!(info["contributors"].as_u64(), Some(1));
        assert_eq!(info["total_weight"].as_u64(), Some(1));
        assert_eq!(info["active"].as_bool(), Some(true));

        // Mine one block: it must be a pooled block that splits the subsidy.
        let result = rpc_call(rpc, "generate", json!({ "blocks": 1 })).expect("generate");
        assert_eq!(result["pooled_blocks"].as_u64(), Some(1));

        let subsidy = crate::consensus::reward::block_subsidy(1);
        {
            let chain = node.state.chain.lock().unwrap();
            let mobile_balance = chain.balance_of_pubkey_hash(&mobile_hash);
            assert!(mobile_balance > 0, "the mobile earned a micro-reward");
            assert!(
                mobile_balance < subsidy / 1000,
                "but only a micro-reward next to the finder"
            );
            // Exactly one subsidy entered circulation: the split redistributed it, so
            // the 21,000,000 ZRO cap is untouched.
            assert_eq!(chain.subsidy_issued(), subsidy);
        }

        // Mining drained the pool.
        let info = rpc_call(rpc, "getpoolinfo", json!({})).expect("getpoolinfo");
        assert_eq!(info["contributors"].as_u64(), Some(0));

        node.stop();
    }

    /// A share for a height the pool is not mining is stale and is never credited.
    #[test]
    fn a_stale_share_is_rejected_and_not_credited() {
        let dir = tempfile::tempdir().unwrap();
        let config = regtest_config(dir.path(), true);
        let node = Node::spawn(&config).expect("spawns");
        let rpc = node.rpc_addr.expect("rpc bound");
        let mobile = PrivateKey::from_bytes([0x11u8; 32]).unwrap().public_key();

        let mut share = make_share(&node.state, mobile);
        share.header.height = 0; // the pool is mining height 1, so this is stale
        assert!(matches!(
            handle_share(&node.state, &share),
            Err(crate::pool::ShareError::StaleWork { .. })
        ));

        let info = rpc_call(rpc, "getpoolinfo", json!({})).expect("getpoolinfo");
        assert_eq!(info["contributors"].as_u64(), Some(0), "nothing was credited");

        node.stop();
    }
}
