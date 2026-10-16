# ZeroCoin (ZRO) — Multi-Platform Build Guide (Desktop · Android · iOS)

This guide covers building ZeroCoin beyond the Windows desktop: the shared Rust wallet
core, the Android target, and what an iOS build would require. It states plainly what
has been verified on a real machine and what has not. Do not report a build here as
successful unless the command actually printed a success on your machine.

---

## 1. Architecture in one screen

The repository builds one package, `zerocoin`, with three front doors and one shared core:

| Component | Source | UI dependencies |
|-----------|--------|-----------------|
| `zerocoind` — full node: chain state, P2P, loopback JSON-RPC | `src/bin/zerocoind.rs` | none |
| `zerocoin-cli` — thin client: one subcommand = one RPC call | `src/bin/zerocoin_cli.rs` | none |
| `zerocoin-gui` — Slint wallet (desktop today) | `src/bin/zerocoin_gui.rs` | Slint |
| `zerocoin::session` — shared wallet core (library) | `src/session.rs` | none |

`session::Session` opens the exact node state a daemon would run (`Node::open`) and
exposes the same operation handlers the loopback RPC dispatches to (`handle_rpc`) — in
process, with no sockets. A mobile front-end therefore never spawns a daemon and never
re-implements the wire protocol; it calls typed methods:

```rust,ignore
let session = Session::open(ChainParams::mainnet(), data_dir)?;
session.wallet_status()?;                          // WalletStatus { present, address }
session.create_wallet(password)?;                  // -> new receiving address
session.import_secret(password, &hex_secret)?;     // restore from the raw 32-byte key
session.import_keystore(password, keystore_bytes)?; // restore from a wallet.json backup
session.address()?;                                // -> String
session.balance()?;                                // Balance { confirmed_fah, spendable_fah }
session.info()?;                                   // ChainInfo { network, height, tip, peers, ... }
session.mine(blocks)?;                             // dev/test networks only
session.send(password, to, amount_fah, fee_fah)?;  // -> txid, after sign + admit + broadcast
```

`send` reports a txid only after the transaction is signed, admitted to the mempool and
broadcast; confirmation still requires a mined block, and `balance()` distinguishes
`confirmed` from `spendable` (the 100-block coinbase maturity applies to mined rewards,
not to received transfers).

### Storage locations

On desktop, `zerocoin::datadir` resolves the per-user directory
(`%APPDATA%\ZeroCoin\<network>` on Windows). A mobile port must instead point the core
at the app's private sandbox — before any session opens:

```rust,ignore
zerocoin::datadir::set_base_dir(app_sandbox_dir); // e.g. app files dir on Android
```

The keystore (`wallet.json`, argon2id + AES-256-GCM) and the chain file (`chain.json`)
then live entirely inside that directory. Nothing is transmitted anywhere; there is no
remote server in this architecture.

### Cargo features

| Build | Command | UI stack built? |
|-------|---------|-----------------|
| Everything (default) | `cargo build --bins` | yes (`gui` feature is on by default) |
| Core only (daemon + CLI + library) | `cargo build --bins --no-default-features` | no |

The `gui` feature (`dep:slint`, `dep:arboard`, `dep:rfd`) is what pulls in the Slint
stack; `--no-default-features` is the subset that cross-compiles for platforms whose
GUI front-end needs extra SDKs installed.

---

## 2. Verified build matrix

Captured on Windows 11 (PowerShell 5.1), crate root `zerocoin/`, October 2026:

| # | Command | Result |
|---|---------|--------|
| 1 | `cargo test --lib` | ✅ `216 passed; 0 failed` (≈37 s) |
| 2 | `cargo build --bins` | ✅ `zerocoind.exe`, `zerocoin-cli.exe`, `zerocoin-gui.exe` linked |
| 3 | `demos\regtest-maturity.ps1` | ✅ end-to-end: genesis mints nothing; 99 blocks → 0 spendable; 101 blocks → 100 ZRO spendable; clean stop |
| 4 | `cargo check --target aarch64-linux-android --lib --no-default-features` | ✅ `Finished` (≈2 m 30 s) — the shared core compiles for Android |
| 5 | `cargo check --target aarch64-linux-android --bins --no-default-features` | ✅ `Finished` — daemon + CLI compile for Android |
| 6 | `cargo check --target aarch64-linux-android --bin zerocoin-gui` | ⛔ blocked on this machine: needs an Android SDK (see §3.1) |
| 7 | iOS | not attempted — requires a macOS host (see §4) |

`cargo clippy --all-targets` exits 0 (a handful of pre-existing style warnings in
untouched modules); `rustfmt --check src/session.rs` is clean.

---

## 3. Android

### 3.1 What is verified, and what is blocked

The wallet core, the daemon and the CLI genuinely compile for `aarch64-linux-android`
(rows 4–5 above). The *GUI* check stops inside Slint's Android backend build script,
which locates `android.jar` from the Android SDK:

```text
thread 'main' panicked at ...i-slint-backend-android-activity-1.18.1\build.rs:34:56:
No Android platforms found
```

This machine has no Android SDK (`ANDROID_HOME` / `ANDROID_SDK_ROOT` unset, no SDK
directories present, no JDK), so item 6 cannot pass here. That is an environment
requirement, not a code failure — but do not claim an Android app until §3.2 has been
completed and the checks pass on your machine.

### 3.2 Full toolchain (needed for the Android GUI)

```powershell
# 1. Rust target for 64-bit ARM Android (already installed on the dev machine)
rustup target add aarch64-linux-android

# 2. JDK 17 (Temurin or equivalent) for the Android build tooling; set JAVA_HOME

# 3. Android SDK command-line tools only — no Android Studio required
#    https://developer.android.com/studio#command-line-tools-only
sdkmanager "platforms;android-34" "build-tools;34.0.0"
# set ANDROID_HOME (or ANDROID_SDK_ROOT) to the SDK root; the build script above
# accepts either variable, or ANDROID_JAR pointing straight at platforms\android-34\android.jar

# 4. NDK — supplies the linker/runtime for the android target
sdkmanager "ndk;26.3.11579264"
# set ANDROID_NDK_ROOT; cargo-apk wires the NDK toolchain in automatically

# 5. cargo-apk — wraps cargo and produces an installable APK
cargo install cargo-apk

# 6. Re-run the checks that are blocked today, then package
cargo check --target aarch64-linux-android --bin zerocoin-gui
cargo apk build --release
```

Note: `cargo-apk` may need a `[package.metadata.android]` section in `Cargo.toml`
(package id, label, icon). It has deliberately **not** been added here: an untestable
packaging configuration would be guesswork. Add it on a machine with the SDK and
verify before distributing.

### 3.3 Packaging & signing

- Release signing uses a keystore created once, kept **outside the repository**:

  ```powershell
  keytool -genkeypair -v -keystore release.keystore -alias zro `
      -keyalg RSA -keysize 2048 -validity 10000
  apksigner sign --ks release.keystore --out zerocoin-release.apk zerocoin.apk
  # keytool/apksigner ship with the JDK / Android build-tools
  ```

- Play Store distribution requires an Android App Bundle (`bundleRelease` in a Gradle
  shell, or an APK→AAB conversion step). None of this has been run in this repository
  yet — treat Android packaging as pre-release work.
- `release.keystore`, passwords, and store credentials must never be committed; keep
  them in a secret manager or an offline vault.

---

## 4. iOS

Not attempted. Slint 1.18 supports iOS, but every step requires a macOS host:

- macOS 13+ with Xcode 15+, plus `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`
- an iOS `staticlib` crate-type target for the GUI, consumed by an Xcode project
- an Apple Developer account with a provisioning profile for on-device signing, and
  App Store Connect for distribution

Nothing in this repository has been built or tested for iOS. Do not claim iOS support
until those steps are executed on Apple hardware and captured with real output.

---

## 5. Security notes for mobile ports

- The wallet file uses the same cryptography as the desktop wallet (argon2id keystream
  + AES-256-GCM); consensus and key-derivation rules were not changed for mobile.
- Point `datadir::set_base_dir` at the app-private sandbox; `Session` opens the node
  with `rpc_listen: None` and never exposes an RPC socket, so no port is reachable from
  other apps.
- The backup artifact is the `wallet.json` bytes themselves (what the desktop Download
  Shield copies out); restore with `import_keystore`. Backups and passwords must never
  be logged or transmitted anywhere.
- No independent security audit has been performed. Until one is, this wallet is
  pre-release software on every platform.
