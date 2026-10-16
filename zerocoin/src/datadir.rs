//! Where a node keeps its persistent state.
//!
//! The consumer wallet must survive the executable being rebuilt, moved or
//! deleted: the chain store and the encrypted wallet keystore therefore live in
//! the operating system's per-user application directory, not beside the binary
//! and not in a temporary folder the OS is free to reclaim. One project-owned
//! directory tree holds every network:
//!
//! - **Windows** — `%APPDATA%\ZeroCoin` (e.g. `C:\Users\alice\AppData\Roaming\ZeroCoin`)
//! - **macOS**   — `~/Library/Application Support/ZeroCoin`
//! - **Linux**   — `$XDG_DATA_HOME/zerocoin` or `~/.local/share/zerocoin`
//!
//! The `ZRO_HOME` environment variable overrides the base when set, which keeps
//! throwaway test nodes and the operator guides working. Inside that base the
//! path is always `<base>/<network>`, so devnet, regtest and mainnet never share
//! a chain file and a wallet can never be opened against the wrong network.
//!
//! Both `zerocoind` and `zerocoin-gui` call [`default_datadir`], so the daemon
//! the desktop wallet spawns and the daemon an operator starts by hand read and
//! write the exact same files.
//!
//! Mobile applications are the exception to every convention above: an Android
//! or iOS app process has no `HOME`/`APPDATA`, and its writable location is
//! handed to it by the platform at startup, not found in the environment. A
//! mobile binding therefore calls [`set_base_dir`] once with the sandbox
//! directory it was given (e.g. the Android `filesDir`); that override takes
//! precedence over `ZRO_HOME` and the platform default and can be removed with
//! [`clear_base_dir`].

use std::env;
use std::path::PathBuf;
use std::sync::RwLock;

/// Environment override for the data-directory base, kept for operators and
/// tests that need scratch state outside the user profile.
const HOME_ENV: &str = "ZRO_HOME";

/// The data directory for `network` on this machine, e.g.
/// `%APPDATA%\ZeroCoin\devnet` on Windows.
pub fn default_datadir(network: &str) -> PathBuf {
    base_dir().join(network)
}

/// A programmatic override for the base directory, set by mobile bindings
/// whose sandbox path exists only at runtime (see [`set_base_dir`]).
static BASE_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Pin the data-directory base to `path` for the life of the process. Intended
/// for platform bindings that receive their sandbox directory from the OS
/// (Android `filesDir`, iOS Application Support) rather than from the
/// environment.
pub fn set_base_dir(path: impl Into<PathBuf>) {
    *BASE_OVERRIDE.write().unwrap() = Some(path.into());
}

/// Remove a previous [`set_base_dir`] override, restoring `ZRO_HOME` and the
/// platform convention.
pub fn clear_base_dir() {
    *BASE_OVERRIDE.write().unwrap() = None;
}

/// The project-owned base directory, before the network segment is appended.
pub fn base_dir() -> PathBuf {
    if let Some(overridden) = BASE_OVERRIDE.read().unwrap().clone() {
        return overridden;
    }
    if let Some(home) = env::var_os(HOME_ENV) {
        if !home.is_empty() {
            return PathBuf::from(home);
        }
    }
    platform_base()
}

#[cfg(windows)]
fn platform_base() -> PathBuf {
    // %APPDATA% is the roaming profile: the wallet follows a domain user
    // between machines, which is exactly the persistence the wallet wants.
    match env::var_os("APPDATA") {
        Some(appdata) if !appdata.is_empty() => PathBuf::from(appdata).join("ZeroCoin"),
        // A service account can lack APPDATA; fall back to the profile root.
        _ => match env::var_os("USERPROFILE") {
            Some(profile) if !profile.is_empty() => {
                PathBuf::from(profile).join("AppData").join("Roaming").join("ZeroCoin")
            }
            _ => env::temp_dir().join("ZeroCoin"),
        },
    }
}

#[cfg(target_os = "macos")]
fn platform_base() -> PathBuf {
    match env::var_os("HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("ZeroCoin"),
        _ => env::temp_dir().join("ZeroCoin"),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_base() -> PathBuf {
    if let Some(data_home) = env::var_os("XDG_DATA_HOME") {
        if !data_home.is_empty() {
            return PathBuf::from(data_home).join("zerocoin");
        }
    }
    match env::var_os("HOME") {
        Some(home) if !home.is_empty() => {
            PathBuf::from(home).join(".local").join("share").join("zerocoin")
        }
        _ => env::temp_dir().join("zerocoin"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Both the environment and the programmatic override are process-global;
    /// tests that touch either must not interleave with each other.
    static GLOBAL_STATE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn network_segment_namespaces_the_chain_and_wallet() {
        let _guard = GLOBAL_STATE_LOCK.lock().unwrap();
        let dir = default_datadir("devnet");
        assert_eq!(dir.file_name().and_then(|n| n.to_str()), Some("devnet"));
        let regtest = default_datadir("regtest");
        assert_ne!(dir, regtest, "networks never share a data directory");
        assert_eq!(
            regtest.parent(),
            dir.parent(),
            "all networks live under one project base"
        );
    }

    #[test]
    fn zro_home_override_wins() {
        let _guard = GLOBAL_STATE_LOCK.lock().unwrap();
        // The override is read on every call, so setting and clearing it around
        // one assertion exercises both paths without leaking global state.
        clear_base_dir();
        let scratch = env::temp_dir().join("zro-datadir-test-override");
        env::set_var(HOME_ENV, &scratch);
        let overridden = default_datadir("devnet");
        env::remove_var(HOME_ENV);
        let platform = default_datadir("devnet");

        assert_eq!(overridden, scratch.join("devnet"));
        // Without the override the platform path is used; on a normal machine
        // that is not the scratch directory.
        assert_ne!(platform, overridden);
        assert_eq!(platform.file_name().and_then(|n| n.to_str()), Some("devnet"));
    }

    #[test]
    fn programmatic_base_override_outranks_the_environment_and_clears() {
        let _guard = GLOBAL_STATE_LOCK.lock().unwrap();
        let scratch = env::temp_dir().join("zro-datadir-test-env");
        let bound = env::temp_dir().join("zro-datadir-test-bound");

        env::set_var(HOME_ENV, &scratch);
        set_base_dir(&bound);
        assert_eq!(
            default_datadir("regtest"),
            bound.join("regtest"),
            "the programmatic override outranks ZRO_HOME"
        );

        clear_base_dir();
        assert_eq!(
            default_datadir("regtest"),
            scratch.join("regtest"),
            "clearing the override restores environment resolution"
        );

        env::remove_var(HOME_ENV);
    }
}
