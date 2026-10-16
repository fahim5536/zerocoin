//! `zerocoind` — the ZeroCoin full-node daemon.
//!
//! Starts a node on the chosen network: it opens (or creates) the chain in the OS
//! user-directory data path, serves the authenticated P2P protocol, and runs the
//! loopback JSON-RPC server that `zerocoin-cli` and the desktop wallet talk to. It
//! runs until stopped by `zerocoin-cli stop` (which sets the RPC stop flag) or by
//! terminating the process.
//!
//! The wallet file is encrypted with AES-256-GCM over an argon2id key, so it is
//! only created when a password is supplied (`--password` or the environment).
//! Started without one — the way `zerocoin-gui` embeds the daemon — the node comes
//! up walletless and the wallet is created or imported later through the RPC
//! lifecycle (`createwallet` / `importwallet`), which is exactly the onboarding
//! flow the desktop wallet presents.
//!
//! Usage:
//! ```text
//! zerocoind [--network devnet|regtest|mainnet] [--datadir DIR]
//!           [--p2p HOST:PORT] [--rpc HOST:PORT] [--connect HOST:PORT]...
//!           [--password PW]
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use zerocoin::node::{Node, NodeConfig};
use zerocoin::params::ChainParams;

/// The wallet password is secret material; it is read from an argument or the
/// environment. When neither is set the daemon starts *walletless* rather than
/// fall back to a shared default that would make every node's wallet trivially
/// unlockable — the embedded GUI node creates or imports the wallet over RPC.
const PASSWORD_ENV: &str = zerocoin::node::WALLET_PASSWORD_ENV;

fn main() {
    match run() {
        Ok(()) => {}
        Err(message) => {
            eprintln!("zerocoind: {message}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut network = "devnet".to_string();
    let mut datadir: Option<PathBuf> = None;
    let mut p2p: Option<SocketAddr> = None;
    let mut rpc: Option<SocketAddr> = None;
    let mut seeds: Vec<SocketAddr> = Vec::new();
    let mut password: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag {
            "--network" => network = value(&mut i)?,
            "--datadir" => datadir = Some(PathBuf::from(value(&mut i)?)),
            "--p2p" => p2p = Some(parse_addr(&value(&mut i)?)?),
            "--rpc" => rpc = Some(parse_addr(&value(&mut i)?)?),
            "--connect" => seeds.push(parse_addr(&value(&mut i)?)?),
            "--password" => password = Some(value(&mut i)?),
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown argument '{other}' (try --help)")),
        }
        i += 1;
    }

    let params = ChainParams::by_name(&network)
        .ok_or_else(|| format!("unknown network '{network}' (use mainnet, devnet or regtest)"))?;

    let data_dir = datadir.unwrap_or_else(|| default_datadir(params.name));
    let p2p_listen = p2p.unwrap_or_else(|| addr_on_loopback_or_any(params.default_p2p_port));
    let rpc_listen = Some(rpc.unwrap_or_else(|| {
        format!("127.0.0.1:{}", params.default_rpc_port)
            .parse()
            .expect("valid loopback RPC address")
    }));

    // No password: the node still opens and serves the chain; the wallet is
    // simply not materialised. `Node::open` only auto-creates a wallet when a
    // password is present, so an absent wallet file stays absent until the
    // operator (or the GUI) asks for one via `createwallet` / `importwallet`.
    let wallet_password = password
        .or_else(|| std::env::var(PASSWORD_ENV).ok())
        .unwrap_or_default();

    let config = NodeConfig {
        params,
        data_dir: data_dir.clone(),
        p2p_listen,
        rpc_listen,
        seeds: seeds.clone(),
        wallet_password,
    };

    let running = Node::spawn(&config).map_err(|e| format!("failed to start node: {e}"))?;

    // Startup banner: everything an operator needs to drive the node.
    let address = {
        let wallet = running.state.wallet.lock().unwrap();
        wallet
            .as_ref()
            .map(|w| w.address_string().to_string())
            .unwrap_or_else(|| "<none>".to_string())
    };
    println!("ZeroCoin node starting");
    println!("  network   : {}", params.name);
    println!("  chain id  : {:#010x}", params.chain_id.0);
    println!("  pow engine: {}", params.engine.name());
    println!("  data dir  : {}", data_dir.display());
    println!("  p2p       : {} (listening)", running.p2p_addr);
    if let Some(rpc_addr) = running.rpc_addr {
        println!("  rpc       : {rpc_addr} (loopback only)");
    }
    println!("  wallet    : {address}");
    if address == "<none>" {
        println!();
        println!("No wallet is loaded yet. Create or import one from the desktop");
        println!("wallet on first launch, or restart with --password PW to create one now.");
    }
    for seed in &seeds {
        println!("  connecting: {seed}");
    }
    println!();
    println!("Drive this node with zerocoin-cli, e.g.:");
    println!("  zerocoin-cli --network {} mine --blocks 101", params.name);
    println!("  zerocoin-cli --network {} getbalance", params.name);
    println!("  zerocoin-cli --network {} stop", params.name);
    println!();
    println!("Running. Stop with 'zerocoin-cli stop' or Ctrl-C.");

    // Block until the stop flag is raised (by the RPC 'stop' method) or the process is
    // terminated. The accept and RPC loops poll the same flag and shut down cleanly.
    while !running.state.is_stopped() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    println!("Stop requested; shutting down.");
    running.stop();
    Ok(())
}

fn parse_addr(text: &str) -> Result<SocketAddr, String> {
    text.parse::<SocketAddr>()
        .map_err(|e| format!("'{text}' is not a valid HOST:PORT address: {e}"))
}

/// Bind P2P on all interfaces by default so peers can dial in.
fn addr_on_loopback_or_any(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port))
}

fn default_datadir(network: &str) -> PathBuf {
    // One shared resolver with `zerocoin-gui`: the daemon the desktop wallet
    // spawns and the daemon started by hand always read the same files.
    zerocoin::datadir::default_datadir(network)
}

fn print_help() {
    println!(
        "zerocoind — the ZeroCoin (ZRO) full-node daemon\n\
         \n\
         OPTIONS:\n  \
           --network NAME     mainnet | devnet | regtest (default: devnet)\n  \
           --datadir DIR      data directory for the chain store and wallet\n  \
           --p2p HOST:PORT    P2P listen address (default: 0.0.0.0:<network port>)\n  \
           --rpc HOST:PORT    RPC listen address (default: 127.0.0.1:<network port>)\n  \
           --connect HOST:PORT  a seed peer to dial (repeatable)\n  \
           --password PW      wallet password; encrypts a wallet created at startup\n  \
                              (or set ZRO_WALLET_PASSWORD). Without it the node\n  \
                              starts walletless; create or import one from\n  \
                              the desktop wallet on first launch\n  \
           --help             this message\n\
         \n\
         When no --datadir is given, state lives under the per-user application\n\
         directory (Windows: %APPDATA%\\ZeroCoin, macOS: ~/Library/Application\n\
         Support/ZeroCoin, Linux: ~/.local/share/zerocoin). ZRO_HOME overrides it.\n\
         \n\
         The RPC server binds to loopback only; it is a separate trust boundary from\n\
         the authenticated P2P fabric and is never exposed to the network."
    );
}
