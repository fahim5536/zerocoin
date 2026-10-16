//! The desktop entry point for the ZeroCoin wallet GUI (`zerocoin-gui`).
//!
//! All the wallet logic lives in the library (`zerocoin::gui`), because the
//! same code also compiles as a mobile `cdylib` whose entry point the OS calls
//! (`android_main` — Android has no `main`). This binary adds only what a
//! desktop process needs: an `fn main` and a console policy.

// A GUI binary should not open a console window on Windows; in debug builds
// we keep it so `eprintln!` diagnostics stay visible while developing.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = zerocoin::gui::run_wallet() {
        eprintln!("zerocoin-gui: {error}");
        std::process::exit(1);
    }
}
