//! `ruso` — the command-line entry point.
//!
//! The binary is a thin shell: it parses arguments, sets up logging, and hands
//! off to [`cli::run`]. Everything of substance lives in the [`cli`] module —
//! scan orchestration, the registry client, and reporting — while compiling and
//! executing checks is the job of the `ruso-script` and `ruso-runtime` crates.
//!
//! User documentation is The Ruso Book (<https://docs.ruso.hopeless-labs.com>).

// `PreparedScript::Ready` carries a `BytecodeProgram` which is large by
// design (probes + pools + instructions). The `Failed` variant is a string;
// the size asymmetry between Ok/Err is intentional.
#![allow(clippy::large_enum_variant)]

mod cli;
mod logging;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run().await
}
