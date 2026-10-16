//! `zerocoin-cli` — the command-line client for a running `zerocoind`.
//!
//! Every subcommand is one JSON-RPC call to the node's loopback RPC server. The CLI
//! holds no keys and no state; it is a thin, authenticated-by-locality client, just
//! as `bitcoin-cli` is to `bitcoind`.
//!
//! Usage:
//! ```text
//! zerocoin-cli [--network devnet|regtest|mainnet] [--rpc HOST:PORT] <command> [options]
//!
//!   getinfo                                   chain/network summary
//!   getnewaddress                             the wallet's receiving address
//!   getbalance                                confirmed and spendable balances (Fah)
//!   getpeercount                              number of connected peers
//!   getpoolinfo                               in-built pool: contributors, weight, share target
//!   mine --blocks N                           mine N blocks; splits the reward with pool
//!                                             share-miners when any contributed (alias: generate)
//!   sendtoaddress --address A --amount FAH \
//!                 [--fee FAH] --password PW   build, sign and broadcast a payment
//!   stop                                      ask the node to shut down
//! ```

use std::net::SocketAddr;

use serde_json::{json, Value};
use zerocoin::node::rpc_call;
use zerocoin::params::ChainParams;

fn main() {
    match run() {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Err(message) => {
            eprintln!("zerocoin-cli: {message}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut network = "devnet".to_string();
    let mut rpc: Option<SocketAddr> = None;
    let mut rest: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--network" => {
                network = next_value(&args, &mut i, "--network")?;
            }
            "--rpc" => {
                rpc = Some(parse_addr(&next_value(&args, &mut i, "--rpc")?)?);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(String::new());
            }
            _ => {
                // Everything from the first non-flag token onward is the command.
                rest.extend(args[i..].iter().cloned());
                break;
            }
        }
        i += 1;
    }

    let params = ChainParams::by_name(&network)
        .ok_or_else(|| format!("unknown network '{network}' (use mainnet, devnet or regtest)"))?;
    let rpc_addr = rpc.unwrap_or_else(|| {
        format!("127.0.0.1:{}", params.default_rpc_port)
            .parse()
            .expect("valid loopback RPC address")
    });

    let command = rest
        .first()
        .cloned()
        .ok_or_else(|| "no command given (try --help)".to_string())?;
    let opts = &rest[1..];

    let (method, payload): (&str, Value) = match command.as_str() {
        "getinfo" => ("getinfo", json!({})),
        "getnewaddress" => ("getnewaddress", json!({})),
        "getbalance" => ("getbalance", json!({})),
        "getpeercount" => ("getpeercount", json!({})),
        "getpoolinfo" => ("getpoolinfo", json!({})),
        "stop" => ("stop", json!({})),
        "mine" | "generate" => {
            let blocks = parse_u64(opt(opts, "--blocks"), "--blocks")?
                .ok_or("mine requires --blocks N")?;
            ("generate", json!({ "blocks": blocks }))
        }
        "sendtoaddress" | "send" => {
            let address = opt(opts, "--address").ok_or("sendtoaddress requires --address A")?;
            let amount = parse_u64(opt(opts, "--amount"), "--amount")?
                .ok_or("sendtoaddress requires --amount FAH (1 ZRO = 100000000 Fah)")?;
            let fee = parse_u64(opt(opts, "--fee"), "--fee")?.unwrap_or(1_000);
            let password = match opt(opts, "--password") {
                Some(pw) => pw.to_string(),
                None => std::env::var(zerocoin::node::WALLET_PASSWORD_ENV).map_err(|_| {
                    "sendtoaddress requires --password PW (or set ZRO_WALLET_PASSWORD)"
                })?,
            };
            (
                "sendtoaddress",
                json!({
                    "address": address,
                    "amount": amount,
                    "fee": fee,
                    "password": password,
                }),
            )
        }
        "help" => {
            print_help();
            return Ok(String::new());
        }
        other => return Err(format!("unknown command '{other}' (try --help)")),
    };

    let result = rpc_call(rpc_addr, method, payload).map_err(|e| e.to_string())?;
    Ok(pretty(&result))
}

/// The value following `--flag`, or `None` if the flag is absent.
fn opt<'a>(opts: &'a [String], flag: &str) -> Option<&'a str> {
    let position = opts.iter().position(|o| o == flag)?;
    opts.get(position + 1).map(|s| s.as_str())
}

fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_u64(value: Option<&str>, flag: &str) -> Result<Option<u64>, String> {
    match value {
        None => Ok(None),
        Some(text) => text
            .parse::<u64>()
            .map(Some)
            .map_err(|e| format!("{flag} expects a non-negative integer: {e}")),
    }
}

fn parse_addr(text: &str) -> Result<SocketAddr, String> {
    text.parse::<SocketAddr>()
        .map_err(|e| format!("'{text}' is not a valid HOST:PORT address: {e}"))
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn print_help() {
    println!(
        "zerocoin-cli — command-line client for zerocoind\n\
         \n\
         GLOBAL OPTIONS:\n  \
           --network NAME   mainnet | devnet | regtest (default: devnet)\n  \
           --rpc HOST:PORT  node RPC address (default: 127.0.0.1:<network port>)\n\
         \n\
         COMMANDS:\n  \
           getinfo\n  \
           getnewaddress\n  \
           getbalance\n  \
           getpeercount\n  \
           getpoolinfo\n  \
           mine --blocks N\n  \
           sendtoaddress --address A --amount FAH [--fee FAH] --password PW\n  \
           stop\n\
         \n\
         Amounts are in Fah (1 ZRO = 100,000,000 Fah)."
    );
}
