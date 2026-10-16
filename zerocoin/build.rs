//! Build script for the ZeroCoin package.
//!
//! Compiles the Slint wallet UI (`ui/wallet.slint`) into Rust code that the
//! `gui` library module (`src/gui.rs`) pulls in via `slint::include_modules!`.
//! The compiled output lands in `OUT_DIR`, so the resulting binary needs no
//! `.slint` file or extra tooling at run time — a plain `cargo build` produces
//! everything.

fn main() {
    slint_build::compile("ui/wallet.slint").expect("compiling ui/wallet.slint");
}
