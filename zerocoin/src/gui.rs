//! The ZeroCoin (ZRO) wallet — one Slint UI shared by the desktop
//! (`zerocoin-gui` binary) and the Android app (this library's `cdylib`).
//!
//! Like `zerocoin-cli`, this front-end holds no keys and no chain state of
//! its own. Every cryptography step — the argon2id keystore unlock, the
//! AES-256-GCM decryption of the wallet file, ECDSA signing, the mempool
//! admit and the broadcast that follow — runs inside a node. What differs
//! per platform is only *how* that node is reached (`Backend`):
//!
//! - **Desktop** talks to a `zerocoind` over the loopback JSON-RPC, calling
//!   the exact same `sendtoaddress` handler the CLI uses, over the same wire
//!   framing (a 4-byte little-endian length prefix followed by JSON). Unlike
//!   the CLI it is also *self-contained*: on launch it probes the network's
//!   default loopback endpoint and, when nothing is listening there, spawns a
//!   detached, windowless daemon of its own (`tokio::process::Command`, no
//!   console window, no password on the command line) pointed at the same
//!   per-user data directory resolved by `crate::datadir`. Deleting, moving
//!   or updating the wallet binaries therefore leaves the chain state, the
//!   balance and the encrypted wallet identity untouched under
//!   `%APPDATA%\ZeroCoin\<network>` (the platform equivalent elsewhere).
//! - **Android** cannot spawn a daemon, so it runs the node in-process
//!   through `crate::session::Session`, whose dispatch table is the exact
//!   same RPC surface the daemon serves. `android_main` pins the app sandbox
//!   directory via `crate::datadir::set_base_dir` before any state opens, so
//!   the chain and the keystore survive app updates the same way.
//!
//! Threading model: the Slint UI owns the main thread and must never block, so
//! every round-trip runs on a small dedicated Tokio runtime (two worker
//! threads; the session's blocking dispatch is confined to the runtime's
//! blocking pool). Results travel back with `Weak::upgrade_in_event_loop`,
//! which is the only safe way into a component from a foreign thread. One
//! background task keeps the window fed: it polls height / balances / peers
//! every couple of seconds and refreshes the transaction ledger whenever the
//! chain tip or the mempool moved (plus a slow fallback cadence). Buttons
//! dispatch their work as one-shot tasks — the UI thread itself only ever
//! moves strings, so the window stays responsive even while the node grinds
//! through argon2id on a slow machine. After `createwallet` succeeds, the
//! mandatory backup step must confirm a saved keystore before the dashboard
//! unlocks: the desktop opens the native save dialog on a dedicated thread
//! (via `rfd`), Android writes the byte copy into the app's private external
//! files directory, which is visible over USB.
//!
//! Desktop usage (devnet by default; starts its own node when none is
//! listening):
//! ```text
//! zerocoin-gui [--network mainnet|devnet|regtest] [--rpc HOST:PORT] [--no-spawn]
//! ```

slint::include_modules!();

#[cfg(not(target_os = "android"))]
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(not(target_os = "android"))]
use std::path::Path;
#[cfg(not(target_os = "android"))]
use std::process::Stdio;
#[cfg(target_os = "android")]
use std::sync::OnceLock;

use serde_json::{json, Value};
use slint::{ComponentHandle, ModelRc, Timer, VecModel, Weak};
use tokio::runtime::Handle;
use tokio::time::{sleep, timeout};
#[cfg(not(target_os = "android"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(target_os = "android"))]
use tokio::net::TcpStream;

#[cfg(not(target_os = "android"))]
use crate::node::{RpcRequest, RpcResponse};
use crate::params::ChainParams;
use crate::session::Session;
use crate::FAH_PER_ZRO;

/// The node's own wire limit (`MAX_LEN_PREFIXED` in `crate::node`). Only the
/// desktop RPC client frames bytes itself; the in-process session inherits
/// the same limit from the dispatch layer.
#[cfg(not(target_os = "android"))]
const MAX_LEN_PREFIXED: usize = 8 * 1024 * 1024;

/// Read-only polls must fail fast so the UI can show "offline" promptly.
const RPC_TIMEOUT: Duration = Duration::from_secs(4);

/// A send runs argon2id + AES-256-GCM inside the node; allow it to finish even
/// on slow hardware. This is a safety net, not an expected wait.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// Default miner fee, in Fah — the same default the node and CLI apply.
const DEFAULT_FEE_FAH: u64 = 1_000;

/// How often the height / balance / peer snapshot is refreshed.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How often the ledger is re-read even when nothing on-chain moved, so a
/// mempool change with a stable height cannot stay invisible.
const HISTORY_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// Upper bound on ledger rows handed to the UI model. The node caps its own
/// answer; this one keeps the model small on a 4 GB phone.
const HISTORY_UI_ROWS: usize = 100;

/// How long the "Copied" confirmation stays on the copy button.
const COPY_FEEDBACK: Duration = Duration::from_millis(1_400);

const COPY_OK_MESSAGE: &str = "Address copied to clipboard.";

/// The keystore file, relative to the data directory. Its existence is the
/// wallet's synchronous "identity present" answer at first paint; the node's
/// `walletstatus` stays authoritative afterwards, and the backup flow copies
/// this exact file.
const WALLET_FILE_NAME: &str = "wallet.json";

/// How long a probe of the RPC endpoint may take. Loopback connects resolve
/// instantly (accepted or refused); this only bounds the pathological case of
/// a firewall silently dropping the SYN.
#[cfg(not(target_os = "android"))]
const EMBEDDED_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// How long the embedded node gets to bind its RPC endpoint before the wallet
/// stops waiting and says so.
#[cfg(not(target_os = "android"))]
const EMBEDDED_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the controller re-probes while the embedded node boots.
#[cfg(not(target_os = "android"))]
const EMBEDDED_READY_POLL: Duration = Duration::from_millis(400);

/// Status-line note shown while the embedded node boots; the first successful
/// poll retracts it.
#[cfg(not(target_os = "android"))]
const EMBEDDED_BOOT_NOTE: &str = "Starting the embedded ZeroCoin node…";

/// Shown when the embedded node never bound its RPC endpoint.
#[cfg(not(target_os = "android"))]
const EMBEDDED_READY_FAILURE: &str =
    "The embedded node did not come up within 30 s — start zerocoind manually to see why.";

/// The status-line note Android shows when the in-process session fails to
/// answer; there is no daemon to start or restart, so it names no remedy.
#[cfg(target_os = "android")]
const ANDROID_OFFLINE_NOTE: &str =
    "The wallet session did not answer. It keeps retrying — if this persists, restart the app.";

#[cfg(not(target_os = "android"))]
const HELP_TEXT: &str = "\
zerocoin-gui — desktop wallet for ZeroCoin (ZRO)

USAGE:
  zerocoin-gui [--network NAME] [--rpc HOST:PORT] [--no-spawn]

OPTIONS:
  --network NAME   mainnet | devnet | regtest (default: devnet)
  --rpc HOST:PORT  node RPC address (default: 127.0.0.1:<network port>)
  --no-spawn       never start the embedded node; expect one to be running
  --help, -h       show this help

By default the wallet starts its own `zerocoind` when nothing is listening on
the network's default RPC port. Chain and wallet state live under the per-user
application directory, so they survive updates of these binaries. The wallet
never touches keys itself; every signature happens inside the node.";

/// Where the Download Shield saves a fresh wallet on Android: the app's
/// private external files directory, captured from the OS at startup because
/// the Slint callback that writes the file has no `AndroidApp` handle.
#[cfg(target_os = "android")]
static ANDROID_BACKUP_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Android entry point. The OS owns the event loop: the native activity calls
/// this symbol once the app starts (that is why the crate is also a `cdylib`
/// — Android has no Rust `main`). It pins the app's sandbox directory into
/// the shared resolver, initialises Slint's Android backend and then runs the
/// exact same wallet code path as the desktop binary — one UI, one core, no
/// fork.
#[cfg(target_os = "android")]
#[no_mangle]
pub fn android_main(app: slint::android::AndroidApp) {
    // The OS hands the app its writable directories; everything persistent
    // (chain store, keystore) must live under them, so bind the base before
    // any node state is opened. The external path is app-private external
    // storage — visible over USB, no permission required — and is preferred
    // for the backup copy; internal storage is the fallback.
    if let Some(sandbox) = app.internal_data_path() {
        crate::datadir::set_base_dir(sandbox);
    }
    if let Some(shared) = app.external_data_path().or_else(|| app.internal_data_path()) {
        let _ = ANDROID_BACKUP_DIR.set(shared);
    }

    if let Err(error) = slint::android::init(app) {
        eprintln!("zerocoin-gui: initialising the Android backend failed: {error}");
        return;
    }
    if let Err(error) = run_wallet() {
        eprintln!("zerocoin-gui: {error}");
    }
}

/// The wallet itself, shared by the desktop binary and `android_main`.
pub fn run_wallet() -> Result<(), String> {
    // Platform setup: `(network, backend, data_dir)` — how this process
    // reaches a node, and where its chain and keystore live.
    #[cfg(not(target_os = "android"))]
    let (network, backend, data_dir, auto_spawn) = {
        let (network, rpc_override, no_spawn) = match parse_args() {
            Ok(parsed) => parsed,
            Err(message) => {
                eprintln!("zerocoin-gui: {message}");
                std::process::exit(1);
            }
        };

        let params = match ChainParams::by_name(&network) {
            Some(params) => params,
            None => {
                eprintln!(
                    "zerocoin-gui: unknown network '{network}' (use mainnet, devnet or regtest)"
                );
                std::process::exit(1);
            }
        };
        // An explicit `--rpc` points at somebody else's node: never spawn one.
        let using_own_endpoint = rpc_override.is_none();
        let rpc_addr = rpc_override.unwrap_or_else(|| {
            format!("127.0.0.1:{}", params.default_rpc_port)
                .parse()
                .expect("valid loopback RPC address")
        });

        // One shared resolver with `zerocoind` (see `crate::datadir`): this
        // wallet and any daemon it spawns read the exact same per-user files —
        // %APPDATA%\ZeroCoin\<network> on Windows — so the balance and identity
        // survive updates, moves and reinstalls of the binaries.
        let data_dir = crate::datadir::default_datadir(params.name);
        let auto_spawn = using_own_endpoint && !no_spawn;
        (network, Backend::Rpc(rpc_addr), data_dir, auto_spawn)
    };

    #[cfg(target_os = "android")]
    let (network, backend, data_dir) = {
        // Android has no daemon to spawn: the node runs in-process through
        // `Session`, on the same chain rules and defaults as the desktop
        // wallet (devnet). `android_main` has already pinned the data
        // directory to the app sandbox.
        let params = ChainParams::devnet();
        let network = params.name.to_string();
        let data_dir = crate::datadir::default_datadir(params.name);
        std::fs::create_dir_all(&data_dir)
            .map_err(|error| format!("creating {}: {error}", data_dir.display()))?;
        let session = Session::open(params, &data_dir)
            .map_err(|error| format!("opening the wallet session: {error}"))?;
        (network, Backend::Session(Arc::new(session)), data_dir)
    };

    let ui = WalletWindow::new().map_err(|error| error.to_string())?;
    ui.set_network_name(display_network(&network).into());

    // First paint answers "does a wallet exist?" synchronously from the
    // keystore file itself, so a returning user never sees the welcome
    // screen flash; the poll loop's `walletstatus` stays authoritative and
    // corrects the view either way as soon as the node answers.
    ui.set_view_mode(if data_dir.join(WALLET_FILE_NAME).exists() { 1 } else { 0 });

    // Two worker threads are enough for "poll the node" plus "send one payment";
    // the whole point on a 4 GB machine is to stay small.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("zerocoin-rpc")
        .enable_all()
        .build()
        .map_err(|error| format!("creating the background runtime: {error}"))?;

    // One background task keeps the window fed. On desktop the embedded-node
    // controller runs first (probe → spawn → wait for readiness), so the poll
    // loop never reports a node "offline" while this app is still booting it;
    // Android goes straight to the poll loop over the live session.
    #[cfg(not(target_os = "android"))]
    runtime.spawn(run_backend(
        ui.as_weak(),
        network,
        backend.clone(),
        data_dir.clone(),
        auto_spawn,
    ));
    #[cfg(target_os = "android")]
    runtime.spawn(run_backend(ui.as_weak(), backend.clone()));

    // The callbacks need the same backend (a clone — it is cheap: an address
    // or an Arc) and data directory: the Download Shield's byte copy reads
    // the master keystore under it and never writes there.
    wire_callbacks(&ui, backend, runtime.handle().clone(), data_dir);

    let outcome = ui.run().map_err(|error| error.to_string());
    // The backend task never returns on its own; abandon it rather than block
    // the exit on a runtime that still holds an infinite task. An embedded
    // node that was spawned stays detached and keeps serving after the window
    // closes; the next launch simply reattaches to it via the port probe. On
    // Android the session dies with the process, exactly as a mobile app
    // should.
    runtime.shutdown_background();
    outcome
}

// ---------------------------------------------------------------------------
// Backend: how this front-end reaches the node
// ---------------------------------------------------------------------------

/// One flat view of everything the poll loop learns about the node.
struct Snapshot {
    network_display: String,
    height: i32,
    /// Mempool transaction count — with the height, the ledger's staleness key.
    mempool: i32,
    peers: i32,
    /// `Some(present)` once the node answers its identity probe; `None` when
    /// it cannot answer, so a transient failure never flips the view.
    wallet_present: Option<bool>,
    address: String,
    confirmed_fah: u64,
    spendable_fah: u64,
}

/// The two ways the wallet reaches a node. Desktop speaks the loopback
/// JSON-RPC to a `zerocoind` (spawned on demand); Android drives the node's
/// dispatch table in-process through `Session`, because a mobile app cannot
/// spawn a daemon. Both answer on the exact same method names, so everything
/// above this enum is platform-blind.
#[derive(Clone)]
enum Backend {
    /// Desktop: the node's loopback RPC endpoint.
    #[cfg(not(target_os = "android"))]
    Rpc(SocketAddr),
    /// Android (and desktop tests): the node's dispatch table, shared.
    #[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
    Session(Arc<Session>),
}

impl Backend {
    /// One call with the node's error strings passed through verbatim — they
    /// are the user's best explanation of what went wrong.
    async fn call(&self, method: &str, params: Value, deadline: Duration) -> Result<Value, String> {
        match self {
            #[cfg(not(target_os = "android"))]
            Backend::Rpc(rpc_addr) => rpc_call_async(*rpc_addr, method, params, deadline).await,
            Backend::Session(session) => {
                // The dispatch table is synchronous (and `createwallet` /
                // `sendtoaddress` run argon2id), so it must never execute on
                // the async workers: the blocking pool absorbs the work.
                let session = Arc::clone(session);
                let method = method.to_string();
                let call = tokio::task::spawn_blocking(move || session.call(&method, &params));
                match timeout(deadline, call).await {
                    Ok(Ok(Ok(value))) => Ok(value),
                    Ok(Ok(Err(error))) => Err(error.to_string()),
                    Ok(Err(join_error)) => Err(format!("the wallet task failed: {join_error}")),
                    Err(_) => Err(format!(
                        "the wallet session did not answer within {}s",
                        deadline.as_secs()
                    )),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RPC client (asynchronous twin of `crate::node::rpc_call`)
// ---------------------------------------------------------------------------

/// One length-prefixed JSON-RPC exchange to the desktop node.
#[cfg(not(target_os = "android"))]
async fn rpc_call_async(
    rpc_addr: SocketAddr,
    method: &str,
    params: Value,
    deadline: Duration,
) -> Result<Value, String> {
    let request = RpcRequest {
        method: method.to_string(),
        params,
    };
    let payload = serde_json::to_vec(&request).map_err(|e| format!("encoding the RPC request: {e}"))?;
    if payload.len() > MAX_LEN_PREFIXED {
        return Err("RPC request exceeds the node's 8 MiB limit".to_string());
    }

    let exchange = async move {
        let mut stream = TcpStream::connect(rpc_addr)
            .await
            .map_err(|e| format!("cannot connect to zerocoind at {rpc_addr}: {e}"))?;

        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        stream
            .write_all(&frame)
            .await
            .map_err(|e| format!("writing the RPC request: {e}"))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("writing the RPC request: {e}"))?;

        let mut length_bytes = [0u8; 4];
        stream
            .read_exact(&mut length_bytes)
            .await
            .map_err(|e| format!("reading the RPC reply: {e}"))?;
        let length = u32::from_le_bytes(length_bytes) as usize;
        if length > MAX_LEN_PREFIXED {
            return Err("RPC reply exceeds the node's 8 MiB limit".to_string());
        }
        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("reading the RPC reply: {e}"))?;

        let response: RpcResponse =
            serde_json::from_slice(&body).map_err(|e| format!("malformed RPC reply: {e}"))?;
        match (response.result, response.error) {
            (_, Some(error)) => Err(error),
            (Some(result), None) => Ok(result),
            (None, None) => Ok(Value::Null),
        }
    };

    match timeout(deadline, exchange).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "zerocoind at {rpc_addr} did not answer within {}s",
            deadline.as_secs()
        )),
    }
}

fn json_fah(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// A `usize`/`u64` count narrowed to the `int` the UI properties expect.
fn json_int(value: &Value, key: &str) -> i32 {
    json_fah(value, key).min(i32::MAX as u64) as i32
}

// ---------------------------------------------------------------------------
// Poll loop: node -> UI
// ---------------------------------------------------------------------------

/// Read chain height, mempool size, peers and balances through whichever
/// backend this platform uses.
async fn poll_once(backend: &Backend) -> Result<Snapshot, String> {
    let info = backend.call("getinfo", json!({}), RPC_TIMEOUT).await?;

    let network_display = info
        .get("network")
        .and_then(Value::as_str)
        .map(display_network)
        .unwrap_or_default();

    // Authoritative wallet-identity probe for the welcome/dashboard split.
    // An unanswered probe degrades to `None` — leave the view alone — never
    // a guess.
    let wallet_present = backend
        .call("walletstatus", json!({}), RPC_TIMEOUT)
        .await
        .ok()
        .and_then(|status| status.get("present").and_then(Value::as_bool));

    // `getbalance` fails while the node runs without a wallet loaded; the chain
    // data above is still valid, so degrade to empty balances instead of
    // declaring the whole node offline.
    let (address, confirmed_fah, spendable_fah) =
        match backend.call("getbalance", json!({}), RPC_TIMEOUT).await {
            Ok(balance) => (
                balance
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                json_fah(&balance, "confirmed"),
                json_fah(&balance, "spendable"),
            ),
            Err(_) => (String::new(), 0, 0),
        };

    Ok(Snapshot {
        network_display,
        height: json_int(&info, "height"),
        mempool: json_int(&info, "mempool"),
        peers: json_int(&info, "peers"),
        wallet_present,
        address,
        confirmed_fah,
        spendable_fah,
    })
}

/// Refresh the window from the node, forever (once the backend controller has
/// ensured a node exists). Lives on the Tokio runtime; the process tears it
/// down with `shutdown_background` when the window closes. `boot_note` is the
/// text of a boot notice that a late-starting node should eventually retract;
/// `offline_note` is the message shown while the node cannot be reached.
async fn poll_loop(
    weak: Weak<WalletWindow>,
    backend: Backend,
    boot_note: Option<String>,
    offline_note: String,
) {
    let mut consecutive_failures = 0u32;
    let mut showing_offline = false;
    let mut pending_note = boot_note;
    // When the ledger was last rebuilt, and for which (height, mempool) state.
    let mut last_history: Option<(i32, i32, Instant)> = None;
    let mut wallet_gone = false;

    loop {
        match poll_once(&backend).await {
            Ok(snapshot) => {
                consecutive_failures = 0;
                // Retract whichever background note is still on screen.
                let mut retract = Vec::new();
                if showing_offline {
                    showing_offline = false;
                    retract.push(offline_note.clone());
                }
                if let Some(note) = pending_note.take() {
                    retract.push(note);
                }

                if snapshot.wallet_present == Some(false) {
                    // No identity on this node (welcome frame): clear the
                    // ledger exactly once, so a removed wallet cannot leave
                    // its history on screen.
                    if !wallet_gone {
                        wallet_gone = true;
                        last_history = None;
                        push_history(&weak, &Value::Null);
                    }
                } else {
                    // Rebuild when the chain tip or the mempool moved, and at
                    // a slow fallback cadence otherwise.
                    let key = (snapshot.height, snapshot.mempool);
                    let stale = last_history.map_or(true, |(height, mempool, at)| {
                        (height, mempool) != key || at.elapsed() >= HISTORY_REFRESH_INTERVAL
                    });
                    if stale {
                        match backend.call("wallethistory", json!({}), RPC_TIMEOUT).await {
                            Ok(history) => {
                                last_history = Some((key.0, key.1, Instant::now()));
                                push_history(&weak, &history);
                            }
                            // The probe said a wallet exists but the ledger
                            // call failed: retry on the next tick.
                            Err(_) => last_history = None,
                        }
                    }
                    wallet_gone = false;
                }

                push_snapshot(&weak, snapshot, retract);
            }
            Err(_) => {
                consecutive_failures += 1;
                // One failed poll can be a mid-restart node; two in a row is
                // real. A more specific boot/failure note, if still on
                // screen, outranks the generic one (push_offline defers).
                if consecutive_failures >= 2 && !showing_offline {
                    showing_offline = true;
                    push_offline(&weak, offline_note.clone());
                }
            }
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Rebuild the ledger model from one `wallethistory` answer. `Value::Null`
/// (or a malformed answer) reads as "no rows", which is exactly what the
/// welcome frame needs.
fn push_history(weak: &Weak<WalletWindow>, history: &Value) {
    let rows: Vec<LedgerRow> = history
        .get("history")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(ledger_row)
                .take(HISTORY_UI_ROWS)
                .collect()
        })
        .unwrap_or_default();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_history_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
    });
}

/// One ledger row from one `wallethistory` entry, or `None` if the entry is
/// malformed. The amounts are the node's exact Fah integers; formatting is
/// the same pure-integer path as the balances.
fn ledger_row(entry: &Value) -> Option<LedgerRow> {
    let direction = entry.get("direction").and_then(Value::as_str)?;
    let amount = entry.get("amount").and_then(Value::as_i64).unwrap_or(0);
    let fee = entry.get("fee").and_then(Value::as_u64).unwrap_or(0);
    let height = entry.get("height").and_then(Value::as_u64).unwrap_or(0);
    let confirmations = entry
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let (label, incoming) = match direction {
        "mined" => ("Mined", true),
        "sent" => ("Sent", false),
        _ => ("Received", true),
    };
    let status = if height == 0 {
        "Pending".to_string()
    } else if confirmations <= 1 {
        "1 confirmation".to_string()
    } else {
        format!("{} confirmations", group_thousands(confirmations))
    };
    let detail = if direction == "sent" && fee > 0 {
        format!("{label} · {status} · fee {} Fah", group_thousands(fee))
    } else {
        format!("{label} · {status}")
    };

    let magnitude = amount.unsigned_abs();
    let sign = if amount < 0 { '-' } else { '+' };
    Some(LedgerRow {
        amount_text: format!("{sign}{} ZRO", format_fah(magnitude)).into(),
        detail_text: detail.into(),
        incoming,
    })
}

fn push_snapshot(weak: &Weak<WalletWindow>, snapshot: Snapshot, retract: Vec<String>) {
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_node_online(true);
        if !snapshot.network_display.is_empty() {
            ui.set_network_name(snapshot.network_display.into());
        }
        ui.set_chain_height(snapshot.height);
        ui.set_peer_count(snapshot.peers);
        // The welcome/dashboard split follows the node's authoritative
        // identity probe: an identity that appears (created or imported
        // here — even by another tool) routes straight to the dashboard,
        // and its absence returns to the welcome session. The address is
        // dropped with the identity so the two views can never disagree.
        // The Download Shield outranks the probe: while a fresh keystore
        // awaits its first backup, the welcome frame holds even though the
        // identity already exists — only a confirmed backup unlocks.
        if let Some(present) = snapshot.wallet_present {
            let wanted = if present && !ui.get_show_download_prompt() {
                1
            } else {
                0
            };
            if ui.get_view_mode() != wanted {
                ui.set_view_mode(wanted);
                if !present {
                    ui.set_wallet_address("".into());
                }
            }
        }
        if !snapshot.address.is_empty() {
            ui.set_wallet_address(snapshot.address.into());
        }
        ui.set_confirmed_balance(format_fah(snapshot.confirmed_fah).into());
        ui.set_confirmed_balance_fah(format!("{} Fah", group_thousands(snapshot.confirmed_fah)).into());
        ui.set_spendable_balance(format_fah(snapshot.spendable_fah).into());
        ui.set_spendable_balance_fah(format!("{} Fah", group_thousands(snapshot.spendable_fah)).into());
        // Only retract background notes (boot / offline notices) while they
        // are still the message on screen — never stomp on a send result the
        // user is still reading.
        let current = ui.get_status_message();
        if retract.iter().any(|note| note.as_str() == current.as_str()) {
            ui.set_status_message("".into());
            ui.set_status_is_error(false);
        }
    });
}

fn push_offline(weak: &Weak<WalletWindow>, note: String) {
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_node_online(false);
        ui.set_chain_height(0);
        ui.set_peer_count(0);
        ui.set_confirmed_balance(format_fah(0).into());
        ui.set_confirmed_balance_fah("0 Fah".into());
        ui.set_spendable_balance(format_fah(0).into());
        ui.set_spendable_balance_fah("0 Fah".into());
        // The address belongs to the wallet file, not the connection, so it is
        // kept. The outage is surfaced in the status line instead.
        if ui.get_status_message().is_empty() {
            ui.set_status_message(note.into());
            ui.set_status_is_error(true);
        }
    });
}

#[cfg(not(target_os = "android"))]
fn offline_note(rpc_addr: SocketAddr) -> String {
    format!(
        "Cannot reach the node at {rpc_addr}. It keeps retrying — restart the wallet to relaunch an embedded node."
    )
}

// ---------------------------------------------------------------------------
// Embedded node: spawn-on-demand controller (desktop only)
// ---------------------------------------------------------------------------

/// The desktop backend: bring up the embedded node when needed, then hand the
/// same task over to the poll loop. Running both in one task means the poll
/// loop can never report "offline" at a node this app is itself still
/// booting. (Android has no daemon; its variant goes straight to the poll
/// loop over the in-process session.)
#[cfg(not(target_os = "android"))]
async fn run_backend(
    weak: Weak<WalletWindow>,
    network: String,
    backend: Backend,
    data_dir: PathBuf,
    auto_spawn: bool,
) {
    let Backend::Rpc(rpc_addr) = backend else {
        return;
    };
    let mut boot_note = None;
    if auto_spawn && !probe_rpc(rpc_addr).await {
        match spawn_embedded_node(&network, &data_dir) {
            Ok(()) => {
                boot_note = Some(EMBEDDED_BOOT_NOTE.to_string());
                push_status_note(&weak, EMBEDDED_BOOT_NOTE, false);
                if !wait_for_rpc(rpc_addr, EMBEDDED_READY_TIMEOUT).await {
                    // No answer in time: say so, and keep the note around so
                    // a late-starting node still clears it on its first
                    // successful poll.
                    push_status_note(&weak, EMBEDDED_READY_FAILURE, true);
                    boot_note = Some(EMBEDDED_READY_FAILURE.to_string());
                }
            }
            Err(note) => push_status_note(&weak, &note, true),
        }
    }
    poll_loop(
        weak,
        Backend::Rpc(rpc_addr),
        boot_note,
        offline_note(rpc_addr),
    )
    .await;
}

/// The Android backend: the in-process session was opened in `run_wallet`;
/// go straight to the poll loop — there is nothing to spawn, and no daemon
/// to restart when a poll fails.
#[cfg(target_os = "android")]
async fn run_backend(weak: Weak<WalletWindow>, backend: Backend) {
    poll_loop(weak, backend, None, ANDROID_OFFLINE_NOTE.to_string()).await;
}

/// Is anything listening on `rpc_addr` right now? A loopback connect resolves
/// instantly either way; the timeout only bounds a firewall that drops the SYN.
#[cfg(not(target_os = "android"))]
async fn probe_rpc(rpc_addr: SocketAddr) -> bool {
    matches!(
        timeout(EMBEDDED_PROBE_TIMEOUT, TcpStream::connect(rpc_addr)).await,
        Ok(Ok(_))
    )
}

/// Wait, bounded, for the freshly spawned node to bind its RPC endpoint.
#[cfg(not(target_os = "android"))]
async fn wait_for_rpc(rpc_addr: SocketAddr, deadline: Duration) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        if probe_rpc(rpc_addr).await {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        sleep(EMBEDDED_READY_POLL).await;
    }
}

/// Launch a detached, windowless `zerocoind` for this network and data
/// directory. Returns as soon as the process is started.
///
/// No password is passed: the daemon comes up walletless and the onboarding
/// view creates or imports the wallet over RPC, so the password never appears
/// in the process list. The child is deliberately left running past this
/// wallet: closing and reopening the GUI (or updating the binaries) simply
/// reattaches to the same node via the port probe, and the files it serves
/// persist under `data_dir` regardless.
#[cfg(not(target_os = "android"))]
fn spawn_embedded_node(network: &str, data_dir: &Path) -> Result<(), String> {
    let daemon = locate_embedded_daemon()?;
    let mut command = tokio::process::Command::new(&daemon);
    command
        .arg("--network")
        .arg(network)
        .arg("--datadir")
        .arg(data_dir)
        // Isolation: strip any inherited wallet password. If the operator's
        // shell had exported the variable, the daemon would auto-create a
        // wallet at boot from it — bypassing onboarding and leaking the
        // dashboard onto a machine that never chose an identity. The embedded
        // node must always come up walletless, so onboarding is the only path.
        .env_remove(crate::node::WALLET_PASSWORD_ENV)
        // Fully detached: no inherited handles, no pipes to drain. The
        // banner is operator output for manual runs, not for the GUI.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW — without it Windows flashes a console window for
        // the daemon and ties the child to this process's console.
        command.creation_flags(0x0800_0000);
    }
    let child = command
        .spawn()
        .map_err(|e| format!("starting the embedded node ({}): {e}", daemon.display()))?;
    // Dropping the handle detaches the child: it keeps running after the
    // wallet exits, and tokio reaps it in the background whenever it does.
    drop(child);
    Ok(())
}

/// Find the `zerocoind` binary that ships with this wallet: beside the wallet
/// executable first (installed layout), then under Cargo's target directories
/// (development layout).
#[cfg(not(target_os = "android"))]
fn locate_embedded_daemon() -> Result<PathBuf, String> {
    let daemon_name = if cfg!(windows) { "zerocoind.exe" } else { "zerocoind" };
    let exe =
        std::env::current_exe().map_err(|e| format!("locating the wallet executable: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "the wallet executable has no parent directory".to_string())?;

    let mut candidates = vec![dir.join(daemon_name)];
    for profile in ["debug", "release"] {
        candidates.push(dir.join("target").join(profile).join(daemon_name));
    }
    if let Some(parent) = dir.parent() {
        for profile in ["debug", "release"] {
            candidates.push(parent.join("target").join(profile).join(daemon_name));
        }
    }

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            format!(
                "cannot find {daemon_name} beside the wallet — reinstall, or start a node and pass --rpc"
            )
        })
}

/// Write a background note into the status line. Never stomps on a message
/// the user is still reading: only an empty line, or the specific boot note
/// this call supersedes, may be replaced.
#[cfg(not(target_os = "android"))]
fn push_status_note(weak: &Weak<WalletWindow>, note: &str, is_error: bool) {
    let note = note.to_string();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        let current = ui.get_status_message();
        if !current.is_empty() && current.as_str() != EMBEDDED_BOOT_NOTE {
            return;
        }
        ui.set_status_message(note.into());
        ui.set_status_is_error(is_error);
    });
}

// ---------------------------------------------------------------------------
// UI callbacks: UI -> node
// ---------------------------------------------------------------------------

fn wire_callbacks(ui: &WalletWindow, backend: Backend, runtime: Handle, data_dir: PathBuf) {
    let weak = ui.as_weak();

    ui.on_request_copy_address({
        let weak = weak.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let address = ui.get_wallet_address().to_string();
            if address.is_empty() {
                ui.set_status_message("No wallet address to copy yet.".into());
                ui.set_status_is_error(true);
                return;
            }
            match copy_to_clipboard(&address) {
                Ok(()) => {
                    ui.set_status_message(COPY_OK_MESSAGE.into());
                    ui.set_status_is_error(false);
                    ui.set_address_copied(true);
                    // Timers run on the event loop thread, so `upgrade` is valid
                    // inside the closure.
                    let weak = weak.clone();
                    Timer::single_shot(COPY_FEEDBACK, move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.set_address_copied(false);
                            if ui.get_status_message().as_str() == COPY_OK_MESSAGE {
                                ui.set_status_message("".into());
                                ui.set_status_is_error(false);
                            }
                        }
                    });
                }
                Err(error) => {
                    ui.set_status_message(format!("Clipboard unavailable: {error}").into());
                    ui.set_status_is_error(true);
                }
            }
        }
    });

    ui.on_request_send({
        let weak = weak.clone();
        let runtime = runtime.clone();
        let backend = backend.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_sending() {
                return;
            }

            let recipient = ui.get_recipient_address().to_string();
            let amount_text = ui.get_amount_zro().to_string();
            let password = ui.get_wallet_password().to_string();

            let amount_fah = match validate_send(recipient.trim(), &amount_text, &password) {
                Ok(amount_fah) => amount_fah,
                Err(message) => {
                    ui.set_status_message(message.into());
                    ui.set_status_is_error(true);
                    return;
                }
            };

            ui.set_sending(true);
            ui.set_status_message("Unlocking keystore and signing…".into());
            ui.set_status_is_error(false);

            let recipient = recipient.trim().to_string();
            let task_handle = runtime.clone();
            let weak = weak.clone();
            let backend = backend.clone();
            task_handle.spawn(async move {
                // This call runs the node's exact `sendtoaddress` handler:
                // argon2id unlock, AES-256-GCM decrypt, ECDSA sign, mempool
                // admit, broadcast — entirely off the UI thread.
                let result = backend
                    .call(
                        "sendtoaddress",
                        json!({
                            "address": recipient,
                            "amount": amount_fah,
                            "fee": DEFAULT_FEE_FAH,
                            "password": password,
                        }),
                        SEND_TIMEOUT,
                    )
                    .await;

                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_sending(false);
                    // The submitted password is never kept in the UI.
                    ui.set_wallet_password("".into());
                    ui.set_password_visible(false);
                    match result {
                        Ok(reply) => {
                            let txid = reply.get("txid").and_then(Value::as_str).unwrap_or_default();
                            ui.set_recipient_address("".into());
                            ui.set_amount_zro("".into());
                            if txid.is_empty() {
                                ui.set_status_message("Transaction broadcast.".into());
                            } else {
                                ui.set_status_message(format!("Transaction broadcast: {txid}").into());
                            }
                            ui.set_status_is_error(false);
                        }
                        Err(error) => {
                            // Wrong password, insufficient funds, bad address,
                            // node down — whatever the node said, verbatim.
                            // The form is kept so the user can retry.
                            ui.set_status_message(error.into());
                            ui.set_status_is_error(true);
                        }
                    }
                });
            });
        }
    });

    ui.on_request_create_wallet({
        let weak = weak.clone();
        let runtime = runtime.clone();
        let backend = backend.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_onboarding_busy() {
                return;
            }
            // While the Download Shield is up, the form is frozen behind
            // the overlay; a keyboard submission must not re-enter here.
            if ui.get_show_download_prompt() {
                return;
            }

            let password = ui.get_wallet_password().to_string();
            let confirm = ui.get_wallet_password_confirm().to_string();
            if let Err(message) = validate_new_wallet_password(&password, &confirm) {
                ui.set_status_message(message.into());
                ui.set_status_is_error(true);
                return;
            }

            ui.set_onboarding_busy(true);
            ui.set_status_message("Creating the wallet…".into());
            ui.set_status_is_error(false);

            // The same `createwallet` handler the CLI drives. The password
            // travels inside the RPC body — never on any command line — and
            // the node seals the keystore before it keeps the key.
            let task_handle = runtime.clone();
            let weak = weak.clone();
            let backend = backend.clone();
            task_handle.spawn(async move {
                let result = backend
                    .call(
                        "createwallet",
                        json!({ "password": password }),
                        SEND_TIMEOUT,
                    )
                    .await;

                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_onboarding_busy(false);
                    // The submitted passwords never stay in the UI.
                    ui.set_wallet_password("".into());
                    ui.set_wallet_password_confirm("".into());
                    ui.set_password_visible(false);
                    match result {
                        Ok(reply) => {
                            let address = reply
                                .get("address")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            ui.set_wallet_address(address.into());
                            // The identity exists from this moment on — but
                            // the dashboard stays locked behind the Wallet
                            // Export / Download Shield until the fresh
                            // keystore has been saved once. The welcome
                            // frame is held (`view-mode` 0) even if the
                            // poll loop already saw the identity; only a
                            // confirmed backup clears the shield.
                            ui.set_show_download_prompt(true);
                            ui.set_view_mode(0);
                            ui.set_status_message(
                                "Wallet created. Download your backup file to unlock the dashboard."
                                    .into(),
                            );
                            ui.set_status_is_error(false);
                        }
                        Err(error) => {
                            // Failed create — the form is kept so the user
                            // can retry; whatever the node said, verbatim.
                            ui.set_status_message(error.into());
                            ui.set_status_is_error(true);
                        }
                    }
                });
            });
        }
    });

    ui.on_request_import_wallet({
        let weak = weak.clone();
        let runtime = runtime.clone();
        let backend = backend.clone();
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_onboarding_busy() {
                return;
            }

            let seed_text = ui.get_wallet_seed().to_string();
            let password = ui.get_wallet_password().to_string();
            if password.is_empty() {
                ui.set_status_message("Enter the password that decrypts this wallet.".into());
                ui.set_status_is_error(true);
                return;
            }
            let source = match parse_import_source(&seed_text) {
                Ok(source) => source,
                Err(message) => {
                    ui.set_status_message(message.into());
                    ui.set_status_is_error(true);
                    return;
                }
            };

            ui.set_onboarding_busy(true);
            ui.set_status_message("Importing the wallet…".into());
            ui.set_status_is_error(false);

            let task_handle = runtime.clone();
            let weak = weak.clone();
            let backend = backend.clone();
            task_handle.spawn(async move {
                // A keystore is proven by unlocking it under the password
                // before anything is written; a seed is re-sealed. Either
                // way the node performs the identity swap and rolls the
                // previous wallet back on failure.
                let params = match source {
                    ImportSource::Secret(secret) => {
                        json!({ "secret": secret, "password": password })
                    }
                    ImportSource::Keystore(keystore) => {
                        json!({ "keystore": keystore, "password": password })
                    }
                };
                let result = backend.call("importwallet", params, SEND_TIMEOUT).await;

                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_onboarding_busy(false);
                    ui.set_wallet_password("".into());
                    ui.set_password_visible(false);
                    match result {
                        Ok(reply) => {
                            let address = reply
                                .get("address")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            // Only a successful import clears the pasted
                            // keystore / seed text.
                            ui.set_wallet_seed("".into());
                            ui.set_wallet_address(address.into());
                            ui.set_view_mode(1);
                            ui.set_status_message(
                                "Wallet imported. Your balance is restored as the chain syncs."
                                    .into(),
                            );
                            ui.set_status_is_error(false);
                        }
                        Err(error) => {
                            // Keep the pasted material so a mistyped password
                            // can be corrected without retyping the seed.
                            ui.set_status_message(error.into());
                            ui.set_status_is_error(true);
                        }
                    }
                });
            });
        }
    });

    ui.on_request_download_backup({
        let weak = weak.clone();
        // The native save dialog blocks on the OS: it runs on a dedicated
        // thread so the Slint event loop (and the window with it) never
        // freezes. The window stays clickable while the dialog is up, so
        // this flag pins the shield to one dialog at a time.
        let dialog_open = Arc::new(AtomicBool::new(false));
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            // Only meaningful while the shield is up — there is no fresh
            // wallet to export otherwise.
            if !ui.get_show_download_prompt() {
                return;
            }
            if dialog_open.swap(true, Ordering::SeqCst) {
                return;
            }

            // Read-side only: the master keystore under the per-user data
            // directory (%APPDATA%\ZeroCoin\<network> on Windows) is never
            // touched — the export is a byte copy to the path the user
            // picks in the OS dialog.
            let keystore = data_dir.join(WALLET_FILE_NAME);
            if !keystore.is_file() {
                dialog_open.store(false, Ordering::SeqCst);
                ui.set_status_message(
                    "The wallet file is not on disk yet — try again in a moment.".into(),
                );
                ui.set_status_is_error(true);
                return;
            }

            ui.set_status_message("Choose where to save your wallet backup…".into());
            ui.set_status_is_error(false);

            let weak = weak.clone();
            let dialog_open = dialog_open.clone();
            std::thread::spawn(move || {
                let outcome = match pick_backup_destination() {
                    Ok(Some(path)) => std::fs::read(&keystore)
                        .and_then(|bytes| std::fs::write(&path, bytes))
                        .map(|_| path)
                        .map_err(|error| format!("Writing the backup failed: {error}")),
                    Ok(None) => Err(
                        "Backup cancelled. The dashboard unlocks after the wallet file is saved."
                            .to_string(),
                    ),
                    Err(message) => Err(message),
                };

                let _ = weak.upgrade_in_event_loop(move |ui| {
                    dialog_open.store(false, Ordering::SeqCst);
                    match outcome {
                        Ok(path) => {
                            // The OS confirmed the write: the shield lifts
                            // and the dashboard unlocks.
                            ui.set_show_download_prompt(false);
                            ui.set_view_mode(1);
                            ui.set_status_message(
                                format!(
                                    "Backup saved to {}. Keep it somewhere safe.",
                                    path.display()
                                )
                                .into(),
                            );
                            ui.set_status_is_error(false);
                        }
                        Err(message) => {
                            // Cancelled or failed: the shield stays up and
                            // explains itself in its banner.
                            ui.set_status_message(message.into());
                            ui.set_status_is_error(true);
                        }
                    }
                });
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Platform integrations
// ---------------------------------------------------------------------------

/// Copy `text` to the OS clipboard.
#[cfg(not(target_os = "android"))]
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.set_text(text.to_owned()))
        .map_err(|error| error.to_string())
}

/// Android clipboard via JNI: Slint exposes no clipboard API and there is no
/// `arboard` backend for the platform, so talk to the activity's
/// ClipboardManager directly. The `JavaVM` and Activity handles come from
/// `ndk-context`, which the android-activity glue registers at startup.
#[cfg(target_os = "android")]
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    use jni::objects::{JObject, JValue};
    use jni::JavaVM;

    let context = ndk_context::android_context();
    // SAFETY: `ndk-context` caches the raw VM/Activity handles the
    // android-activity glue installed before `android_main` ran; both stay
    // valid for the life of the process.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }
        .map_err(|error| format!("JNI initialisation: {error}"))?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|error| format!("JNI attach: {error}"))?;
    let activity = unsafe { JObject::from_raw(context.context().cast()) };

    let label = env
        .new_string(text)
        .map_err(|error| format!("JNI string: {error}"))?;
    let clip = env
        .call_static_method(
            "android/content/ClipData",
            "newPlainText",
            "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
            &[JValue::Object(&label), JValue::Object(&label)],
        )
        .and_then(|value| value.l())
        .map_err(|error| format!("JNI ClipData.newPlainText: {error}"))?;

    // "clipboard" is Context.CLIPBOARD_SERVICE.
    let service = env
        .new_string("clipboard")
        .map_err(|error| format!("JNI string: {error}"))?;
    let manager = env
        .call_method(
            &activity,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[JValue::Object(&service)],
        )
        .and_then(|value| value.l())
        .map_err(|error| format!("JNI getSystemService: {error}"))?;

    env.call_method(
        &manager,
        "setPrimaryClip",
        "(Landroid/content/ClipData;)V",
        &[JValue::Object(&clip)],
    )
    .map_err(|error| format!("JNI setPrimaryClip: {error}"))?;
    Ok(())
}

/// Ask the user where to save the wallet backup. `Ok(None)` means cancelled.
#[cfg(not(target_os = "android"))]
fn pick_backup_destination() -> Result<Option<PathBuf>, String> {
    Ok(rfd::FileDialog::new()
        .set_title("Save your ZeroCoin wallet backup")
        .set_file_name(WALLET_FILE_NAME)
        .save_file())
}

/// Android has no native save dialog reachable from Rust without a larger
/// platform integration; the backup is written to the app's private external
/// files directory (visible over USB, no permission needed) and the path is
/// reported to the user. The shield's contract — a confirmed byte copy of
/// the keystore before the dashboard unlocks — is preserved: the copy is
/// real, only the destination is fixed.
#[cfg(target_os = "android")]
fn pick_backup_destination() -> Result<Option<PathBuf>, String> {
    let dir = ANDROID_BACKUP_DIR
        .get()
        .ok_or_else(|| "the app storage directory is not available yet".to_string())?;
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("creating the backup directory: {error}"))?;
    Ok(Some(dir.join(WALLET_FILE_NAME)))
}

/// The client-side pre-flight. Consensus rules are the node's job; this only
/// catches what a human would want to fix before a round-trip.
fn validate_send(recipient: &str, amount_text: &str, password: &str) -> Result<u64, String> {
    if recipient.is_empty() {
        return Err("Enter the recipient's ZRO address.".to_string());
    }
    let amount_fah = parse_zro_to_fah(amount_text)?;
    if amount_fah == 0 {
        return Err("Enter an amount greater than zero.".to_string());
    }
    if password.is_empty() {
        return Err("Enter the wallet password to unlock the keystore.".to_string());
    }
    Ok(amount_fah)
}

// ---------------------------------------------------------------------------
// Onboarding pre-flight (client-side; the node re-validates everything)
// ---------------------------------------------------------------------------

/// Pre-flight for the "Create New Wallet" form: an empty password would
/// produce a keystore nothing protects, and a mistyped confirmation would
/// lock the user out of the wallet they just made.
fn validate_new_wallet_password(password: &str, confirm: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("Choose a password for the new wallet.".to_string());
    }
    if password.chars().count() < 8 {
        return Err("Use at least 8 characters — the keystore's only protection.".to_string());
    }
    if password != confirm {
        return Err("The two passwords do not match.".to_string());
    }
    Ok(())
}

/// What a user pasted into the welcome view's import field.
enum ImportSource {
    /// The raw 64-hex secp256k1 scalar (the "recovery seed").
    Secret(String),
    /// The full text of a `wallet.json` keystore, re-sealed instead of
    /// re-derived, so the identity is restored byte-for-byte.
    Keystore(String),
}

/// Classify pasted import material: JSON (starts with `{`) is a keystore;
/// anything else must be exactly 64 hex characters, whitespace ignored
/// (people paste seeds in groups).
fn parse_import_source(text: &str) -> Result<ImportSource, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(
            "Paste a recovery seed (64 hex characters) or the contents of a wallet.json keystore."
                .to_string(),
        );
    }
    if trimmed.starts_with('{') {
        return Ok(ImportSource::Keystore(trimmed.to_string()));
    }
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() == 64 && compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(ImportSource::Secret(compact));
    }
    Err("The seed must be exactly 64 hex characters, or paste a wallet.json keystore instead."
        .to_string())
}

// ---------------------------------------------------------------------------
// ZRO <-> Fah formatting (pure integer math; no floats, no rounding drift)
// ---------------------------------------------------------------------------

/// Parse a ZRO amount typed by a human into Fah. Accepts "12", "12.5",
/// "0.00000001", ".5", "1,000" — but never a sign or an exponent.
fn parse_zro_to_fah(text: &str) -> Result<u64, String> {
    // Accept the separators people actually type.
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != '_')
        .collect();
    if cleaned.is_empty() {
        return Err("Enter an amount in ZRO.".to_string());
    }

    let (whole_text, fraction_text) = match cleaned.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (cleaned.as_str(), ""),
    };

    if whole_text.is_empty() && fraction_text.is_empty() {
        return Err(format!("'{cleaned}' is not a valid ZRO amount."));
    }
    if !whole_text.bytes().all(|b| b.is_ascii_digit())
        || !fraction_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("'{cleaned}' is not a valid ZRO amount."));
    }
    if fraction_text.len() > 8 {
        return Err("At most 8 decimal places (1 Fah = 0.00000001 ZRO).".to_string());
    }

    let whole: u64 = if whole_text.is_empty() {
        0
    } else {
        whole_text
            .parse()
            .map_err(|_| "Amount is too large.".to_string())?
    };
    let fraction: u64 = if fraction_text.is_empty() {
        0
    } else {
        // Scale the typed fraction to Fah: "5" -> 50_000_000, "05" -> 5_000_000.
        let digits: u64 = fraction_text
            .parse()
            .map_err(|_| "Amount is too large.".to_string())?;
        digits * 10u64.pow((8 - fraction_text.len()) as u32)
    };

    whole
        .checked_mul(FAH_PER_ZRO)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| "Amount is too large.".to_string())
}

/// Format Fah as ZRO with exactly eight decimals, e.g. `1,250.00000000`.
fn format_fah(fah: u64) -> String {
    format!(
        "{}.{:08}",
        group_thousands(fah / FAH_PER_ZRO),
        fah % FAH_PER_ZRO
    )
}

fn group_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(character);
    }
    grouped
}

fn display_network(name: &str) -> String {
    match name {
        "devnet" => "Devnet".to_string(),
        "mainnet" => "Mainnet".to_string(),
        "regtest" => "Regtest".to_string(),
        "test" => "Test".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Arguments (desktop only; same surface as `zerocoin-cli`)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "android"))]
fn parse_args() -> Result<(String, Option<SocketAddr>, bool), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut network = "devnet".to_string();
    let mut rpc: Option<SocketAddr> = None;
    let mut no_spawn = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--network" => network = next_value(&args, &mut i, "--network")?,
            "--rpc" => rpc = Some(parse_addr(&next_value(&args, &mut i, "--rpc")?)?),
            "--no-spawn" => no_spawn = true,
            "--help" | "-h" => {
                println!("{HELP_TEXT}");
                std::process::exit(0);
            }
            other => return Err(format!("unexpected argument '{other}' (try --help)")),
        }
        i += 1;
    }

    Ok((network, rpc, no_spawn))
}

#[cfg(not(target_os = "android"))]
fn next_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} expects a value"))
}

#[cfg(not(target_os = "android"))]
fn parse_addr(text: &str) -> Result<SocketAddr, String> {
    text.parse::<SocketAddr>()
        .map_err(|e| format!("'{text}' is not a valid HOST:PORT address: {e}"))
}

// ---------------------------------------------------------------------------
// Tests (pure formatting helpers — the RPC surface is integration-tested
// against a live node in `tests/`, so these stay dependency-free)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_and_fractional_amounts() {
        assert_eq!(parse_zro_to_fah("1").unwrap(), 100_000_000);
        assert_eq!(parse_zro_to_fah("12.5").unwrap(), 1_250_000_000);
        assert_eq!(parse_zro_to_fah("0.00000001").unwrap(), 1);
        assert_eq!(parse_zro_to_fah(".5").unwrap(), 50_000_000);
        assert_eq!(parse_zro_to_fah("5.").unwrap(), 500_000_000);
        assert_eq!(parse_zro_to_fah("1,000").unwrap(), 100_000_000_000);
        assert_eq!(parse_zro_to_fah(" 0.05 ").unwrap(), 5_000_000);
    }

    #[test]
    fn rejects_malformed_amounts() {
        assert!(parse_zro_to_fah("").is_err());
        assert!(parse_zro_to_fah(".").is_err());
        assert!(parse_zro_to_fah("-1").is_err());
        assert!(parse_zro_to_fah("1.2.3").is_err());
        assert!(parse_zro_to_fah("1e3").is_err());
        assert!(parse_zro_to_fah("0.000000001").is_err()); // nine decimals
        assert!(parse_zro_to_fah("18446744073709551616").is_err()); // u64 overflow
    }

    #[test]
    fn formats_fah_as_eight_decimal_zro() {
        assert_eq!(format_fah(0), "0.00000000");
        assert_eq!(format_fah(1), "0.00000001");
        assert_eq!(format_fah(100_000_000), "1.00000000");
        assert_eq!(format_fah(125_000_000_000), "1,250.00000000");
        assert_eq!(format_fah(99_999_999), "0.99999999");
    }

    #[test]
    fn groups_thousands() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1_000), "1,000");
        assert_eq!(group_thousands(107), "107");
        assert_eq!(group_thousands(12_345_678), "12,345,678");
    }

    #[test]
    fn validates_send_input() {
        assert!(validate_send("", "1", "pw").is_err());
        assert!(validate_send("Zaddr", "0", "pw").is_err());
        assert!(validate_send("Zaddr", "1", "").is_err());
        assert_eq!(validate_send("Zaddr", "2.5", "pw").unwrap(), 250_000_000);
    }

    #[test]
    fn rounds_trip_through_fah() {
        for text in ["1", "0.5", "12345.67890123", "0.00000001"] {
            let fah = parse_zro_to_fah(text).unwrap();
            let rendered = format_fah(fah).replace(',', "");
            assert_eq!(parse_zro_to_fah(&rendered).unwrap(), fah);
        }
    }

    /// End-to-end check of the async RPC client against a real loopback node:
    /// framing, response parsing, and verbatim error pass-through — the same
    /// contract `zerocoin::node::rpc_call` gives the CLI.
    #[test]
    fn async_client_talks_to_a_live_node() {
        use crate::node::{Node, NodeConfig};

        let dir = tempfile::tempdir().expect("temp directory");
        let config = NodeConfig {
            params: ChainParams::regtest(),
            data_dir: dir.path().to_path_buf(),
            p2p_listen: "127.0.0.1:0".parse().unwrap(),
            rpc_listen: Some("127.0.0.1:0".parse().unwrap()),
            seeds: Vec::new(),
            wallet_password: "gui-test-password".to_string(),
        };
        let node = Node::spawn(&config).expect("spawning the test node");
        let rpc_addr = node.rpc_addr.expect("RPC listener bound");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");

        let info = runtime
            .block_on(rpc_call_async(rpc_addr, "getinfo", json!({}), RPC_TIMEOUT))
            .expect("getinfo over the async client");
        assert_eq!(info.get("network").and_then(Value::as_str), Some("regtest"));
        assert_eq!(json_int(&info, "height"), 0);
        assert_eq!(json_int(&info, "peers"), 0);

        let balance = runtime
            .block_on(rpc_call_async(rpc_addr, "getbalance", json!({}), RPC_TIMEOUT))
            .expect("getbalance over the async client");
        assert!(!balance
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty());
        assert_eq!(json_fah(&balance, "confirmed"), 0);
        assert_eq!(json_fah(&balance, "spendable"), 0);

        // The node's error strings must reach the caller verbatim.
        let error = runtime
            .block_on(rpc_call_async(rpc_addr, "sendtoaddress", json!({}), RPC_TIMEOUT))
            .expect_err("sendtoaddress without parameters must fail");
        assert!(error.contains("address"), "unexpected error: {error}");

        node.stop();
    }

    /// The spawn-on-demand controller hinges on the port probe being both
    /// truthful and bounded: up while a listener is bound, down right after it
    /// is released.
    #[test]
    fn probes_the_rpc_endpoint() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("probe test runtime");

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binding a probe target");
            let addr = listener.local_addr().expect("probe target address");
            assert!(probe_rpc(addr).await, "a bound listener must probe as up");
            drop(listener);
            assert!(!probe_rpc(addr).await, "a released port must probe as down");
        });
    }

    /// The readiness wait must give up on its own — an embedded node that
    /// never starts may not freeze the wallet forever.
    #[test]
    fn readiness_wait_gives_up_on_a_dead_endpoint() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("readiness test runtime");

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binding a probe target");
            let addr = listener.local_addr().expect("probe target address");
            drop(listener);

            let start = std::time::Instant::now();
            assert!(!wait_for_rpc(addr, Duration::from_millis(100)).await);
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the readiness wait must be bounded"
            );
        });
    }

    #[test]
    fn validates_new_wallet_passwords() {
        assert!(validate_new_wallet_password("", "").is_err());
        assert!(validate_new_wallet_password("short", "short").is_err());
        assert!(validate_new_wallet_password("longenough1", "longenough2").is_err());
        assert!(validate_new_wallet_password("longenough1", "longenough1").is_ok());
    }

    #[test]
    fn classifies_import_material() {
        let seed = "ab".repeat(32);
        match parse_import_source(&seed).expect("a clean 64-hex seed") {
            ImportSource::Secret(parsed) => assert_eq!(parsed, seed),
            ImportSource::Keystore(_) => panic!("a 64-hex string must classify as a secret"),
        }
        // Interior whitespace is cosmetic: people paste seeds in groups.
        let spaced = format!("{} {}", &seed[..32], &seed[32..]);
        assert!(matches!(
            parse_import_source(&spaced).expect("a whitespace-grouped seed"),
            ImportSource::Secret(_)
        ));
        // Uppercase hex is a valid seed too.
        assert!(matches!(
            parse_import_source(&seed.to_uppercase()).expect("uppercase hex"),
            ImportSource::Secret(_)
        ));
        match parse_import_source("  {\"version\":1}  ").expect("a JSON blob") {
            ImportSource::Keystore(text) => assert_eq!(text, "{\"version\":1}"),
            ImportSource::Secret(_) => panic!("JSON must classify as a keystore"),
        }
        assert!(parse_import_source("").is_err());
        assert!(parse_import_source("not-a-seed").is_err());
        assert!(parse_import_source(&"zz".repeat(32)).is_err());
        assert!(parse_import_source(&seed[..62]).is_err()); // 62 hex characters
    }

    /// The onboarding contract against a live walletless node, over the same
    /// async client the GUI uses: probe → create → refuse to clobber → prove
    /// the keystore restores the identity → reject a wrong password without
    /// disturbing the loaded wallet.
    #[test]
    fn wallet_lifecycle_over_the_async_client() {
        use crate::node::{Node, NodeConfig};

        let dir = tempfile::tempdir().expect("temp directory");
        let config = NodeConfig {
            params: ChainParams::regtest(),
            data_dir: dir.path().to_path_buf(),
            p2p_listen: "127.0.0.1:0".parse().unwrap(),
            rpc_listen: Some("127.0.0.1:0".parse().unwrap()),
            seeds: Vec::new(),
            // No password: exactly how the GUI spawns its embedded node. It
            // must come up walletless and wait for a lifecycle call.
            wallet_password: String::new(),
        };
        let node = Node::spawn(&config).expect("spawning the walletless test node");
        let rpc_addr = node.rpc_addr.expect("RPC listener bound");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");

        // 1. Walletless: the identity probe answers false, the chain data
        //    still flows (the GUI must not call this "offline"), and
        //    balances are unavailable until an identity exists.
        let status = runtime
            .block_on(rpc_call_async(rpc_addr, "walletstatus", json!({}), RPC_TIMEOUT))
            .expect("walletstatus on a walletless node");
        assert_eq!(status.get("present").and_then(Value::as_bool), Some(false));
        assert!(status.get("address").map(Value::is_null).unwrap_or(false));
        let info = runtime
            .block_on(rpc_call_async(rpc_addr, "getinfo", json!({}), RPC_TIMEOUT))
            .expect("getinfo on a walletless node");
        assert_eq!(info.get("network").and_then(Value::as_str), Some("regtest"));
        let balance_error = runtime
            .block_on(rpc_call_async(rpc_addr, "getbalance", json!({}), RPC_TIMEOUT))
            .expect_err("getbalance must fail with no wallet loaded");
        assert!(
            balance_error.contains("no wallet"),
            "unexpected error: {balance_error}"
        );

        // 2. Create: the same call the "Create Wallet" button makes.
        let created = runtime
            .block_on(rpc_call_async(
                rpc_addr,
                "createwallet",
                json!({ "password": "onboarding-test" }),
                SEND_TIMEOUT,
            ))
            .expect("createwallet over the async client");
        assert_eq!(created.get("created").and_then(Value::as_bool), Some(true));
        let created_address = created
            .get("address")
            .and_then(Value::as_str)
            .expect("created address")
            .to_string();
        assert!(!created_address.is_empty());
        // The keystore file is the GUI's synchronous first-paint signal.
        let keystore_path = dir.path().join(WALLET_FILE_NAME);
        assert!(keystore_path.is_file(), "createwallet must write the keystore");

        // 3. The create path must never clobber an identity...
        let refused = runtime
            .block_on(rpc_call_async(
                rpc_addr,
                "createwallet",
                json!({ "password": "something-else" }),
                SEND_TIMEOUT,
            ))
            .expect_err("createwallet must refuse to overwrite");
        assert!(
            refused.contains("already present"),
            "unexpected error: {refused}"
        );

        // ...and the probe now reports the identity the dashboard needs.
        let status = runtime
            .block_on(rpc_call_async(rpc_addr, "walletstatus", json!({}), RPC_TIMEOUT))
            .expect("walletstatus after create");
        assert_eq!(status.get("present").and_then(Value::as_bool), Some(true));
        assert_eq!(
            status.get("address").and_then(Value::as_str),
            Some(created_address.as_str())
        );

        // 4. Restore from the keystore itself — literally the file contents a
        //    user pastes back after a wipe. Import is a full identity swap,
        //    so it may replace the wallet the node is already holding.
        let keystore_text =
            std::fs::read_to_string(&keystore_path).expect("reading the keystore the node wrote");
        assert!(matches!(
            parse_import_source(&keystore_text).expect("wallet.json classifies as a keystore"),
            ImportSource::Keystore(_)
        ));
        let reimported = runtime
            .block_on(rpc_call_async(
                rpc_addr,
                "importwallet",
                json!({ "keystore": keystore_text.clone(), "password": "onboarding-test" }),
                SEND_TIMEOUT,
            ))
            .expect("importwallet(keystore)");
        assert_eq!(
            reimported.get("source").and_then(Value::as_str),
            Some("keystore")
        );
        assert_eq!(
            reimported.get("address").and_then(Value::as_str),
            Some(created_address.as_str()),
            "the keystore must restore the same identity"
        );

        // 5. A wrong password is rejected by the AEAD tag before anything is
        //    written, and the loaded identity survives untouched.
        let rejected = runtime
            .block_on(rpc_call_async(
                rpc_addr,
                "importwallet",
                json!({ "keystore": keystore_text, "password": "not-the-password" }),
                SEND_TIMEOUT,
            ))
            .expect_err("a wrong keystore password must be rejected");
        assert!(rejected.contains("rejected"), "unexpected error: {rejected}");
        let status = runtime
            .block_on(rpc_call_async(rpc_addr, "walletstatus", json!({}), RPC_TIMEOUT))
            .expect("walletstatus after the failed import");
        assert_eq!(
            status.get("address").and_then(Value::as_str),
            Some(created_address.as_str()),
            "a failed import must leave the identity alone"
        );

        node.stop();
    }

    /// The "Import Existing Wallet → recovery seed" path on the machine that
    /// kept nothing but the 64-hex scalar: import must materialise the same
    /// keystore file the create flow would have written.
    #[test]
    fn restores_an_identity_from_a_raw_seed() {
        use crate::node::{Node, NodeConfig};

        let dir = tempfile::tempdir().expect("temp directory");
        let config = NodeConfig {
            params: ChainParams::regtest(),
            data_dir: dir.path().to_path_buf(),
            p2p_listen: "127.0.0.1:0".parse().unwrap(),
            rpc_listen: Some("127.0.0.1:0".parse().unwrap()),
            seeds: Vec::new(),
            wallet_password: String::new(),
        };
        let node = Node::spawn(&config).expect("spawning the walletless test node");
        let rpc_addr = node.rpc_addr.expect("RPC listener bound");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");

        // The same material a user pastes: 64 hex characters.
        let seed = "11".repeat(32);
        let imported = runtime
            .block_on(rpc_call_async(
                rpc_addr,
                "importwallet",
                json!({ "secret": seed, "password": "seed-import-test" }),
                SEND_TIMEOUT,
            ))
            .expect("importwallet(secret) on a walletless node");
        assert_eq!(imported.get("imported").and_then(Value::as_bool), Some(true));
        assert_eq!(imported.get("source").and_then(Value::as_str), Some("secret"));
        let address = imported
            .get("address")
            .and_then(Value::as_str)
            .expect("imported address")
            .to_string();
        assert!(!address.is_empty());

        // The file on disk, the probe and the reply all agree on the
        // restored identity.
        assert!(dir.path().join(WALLET_FILE_NAME).is_file());
        let status = runtime
            .block_on(rpc_call_async(rpc_addr, "walletstatus", json!({}), RPC_TIMEOUT))
            .expect("walletstatus after the seed import");
        assert_eq!(status.get("present").and_then(Value::as_bool), Some(true));
        assert_eq!(
            status.get("address").and_then(Value::as_str),
            Some(address.as_str())
        );

        node.stop();
    }

    /// The mobile backend path in one test: the same dispatch table the
    /// loopback RPC serves, driven in-process through `Session` — wallet
    /// lifecycle, balances and the ledger call the Android history view
    /// depends on.
    #[test]
    fn session_backend_serves_the_wallet_over_the_shared_dispatch() {
        let dir = tempfile::tempdir().expect("temp directory");
        let session =
            Session::open(ChainParams::regtest(), dir.path()).expect("opening the session");
        let backend = Backend::Session(Arc::new(session));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime");

        // Walletless: the probe is the synchronous identity answer the UI
        // waits for, and the ledger is honestly empty — not an error.
        let status = runtime
            .block_on(backend.call("walletstatus", json!({}), RPC_TIMEOUT))
            .expect("walletstatus through the session backend");
        assert_eq!(status.get("present").and_then(Value::as_bool), Some(false));
        let history = runtime
            .block_on(backend.call("wallethistory", json!({}), RPC_TIMEOUT))
            .expect_err("wallethistory without a wallet must be refused");
        assert!(
            history.contains("no wallet"),
            "unexpected error: {history}"
        );

        // Create: the same call the "Create Wallet" button makes, and the
        // exact JSON the button's code parses back out.
        let created = runtime
            .block_on(backend.call(
                "createwallet",
                json!({ "password": "session-backend-test" }),
                SEND_TIMEOUT,
            ))
            .expect("createwallet through the session backend");
        assert_eq!(created.get("created").and_then(Value::as_bool), Some(true));
        let address = created
            .get("address")
            .and_then(Value::as_str)
            .expect("created address")
            .to_string();

        let balance = runtime
            .block_on(backend.call("getbalance", json!({}), RPC_TIMEOUT))
            .expect("getbalance through the session backend");
        assert_eq!(
            balance.get("address").and_then(Value::as_str),
            Some(address.as_str())
        );

        // A brand-new wallet has an empty, well-formed ledger.
        let history = runtime
            .block_on(backend.call("wallethistory", json!({}), RPC_TIMEOUT))
            .expect("wallethistory through the session backend");
        assert_eq!(
            history.get("history").and_then(Value::as_array).map(Vec::len),
            Some(0)
        );
    }
}
