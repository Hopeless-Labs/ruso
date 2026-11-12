# ruso

[![Rust CI](https://github.com/Hopeless-Labs/ruso/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/Hopeless-Labs/ruso/actions/workflows/rust.yml)

> [!NOTE]
> **Development status:** under active development. The RSL, compiler output, and
> grammar may change without notice. Not recommended for production use yet.

`ruso` — a command-line vulnerability scanner driven by shareable checks written
in the **Ruso Scripting Language (RSL)**. Point it at a target and scan against a
library of community checks, or write your own.

📖 **Full documentation:** <https://docs.ruso.hopeless-labs.com>

## Install

```bash
cargo install --git https://github.com/Hopeless-Labs/ruso.git ruso-cli
```

The binary is named `ruso` (the package it comes from is `ruso-cli`).

## Quick start

> Scan only systems you own or are explicitly authorized to test.

```bash
# Scan a target against an entire family of community checks — nothing to write.
ruso scan --family web --target https://target.example.com

# Find a specific check in the registry…
ruso search log4j --tag rce

# …and run it by reference (fetched + cached on first use).
ruso scan --script someuser/log4shell --target https://target.example.com -v
```

Prefer to run your own check? Write a `.rsl` file and scan it directly:

```bash
ruso validate --script check.rsl                              # syntax only, no network
ruso scan     --script check.rsl --target https://target.example.com
```

## Commands at a glance

| | |
|---|---|
| `scan` | Compile + run a check (or `--family`) against targets |
| `validate` / `compile` / `exec` | Check syntax · compile to `.rbc` · run compiled bytecode |
| `search` / `info` / `install` | Discover and fetch published checks |
| `publish` / `yank` / `edit` | Share and manage your own checks |
| `login` / `logout` / `whoami` / `pat` | Registry authentication |

Full flags, examples, and the language reference are in
**[The Ruso Book](https://docs.ruso.hopeless-labs.com)**.

## Repository layout

This is a Cargo workspace holding the three crates that make up Ruso. They are
versioned and released in lockstep.

| Crate | Kind | What it does |
|---|---|---|
| [`crates/ruso-script`](crates/ruso-script) | lib | RSL grammar, parser, and the compiler that lowers `.rsl` source to bytecode |
| [`crates/ruso-runtime`](crates/ruso-runtime) | lib | the bytecode VM — runs probes over HTTP/DNS/TCP/UDP and emits findings |
| [`crates/ruso-cli`](crates/ruso-cli) | bin | the `ruso` binary: scan orchestration, registry client, reporting |

The dependency direction is one-way:

```
ruso-cli ──► ruso-script ──► ruso-runtime
    └───────────────────────────┘
```

A scan runs `.rsl` source → `ruso-script` compiles it to `.rbc` bytecode →
`ruso-runtime` executes that bytecode against the target → `ruso-cli` formats the
findings.

Related repositories: [`ruso-docs`](https://github.com/Hopeless-Labs/ruso-docs)
(The Ruso Book).

## Build from source

```bash
git clone https://github.com/Hopeless-Labs/ruso.git
cd ruso
cargo build --release          # binary at ./target/release/ruso
```

Because all three crates live here, a change to the runtime or the compiler is
picked up by the CLI with no path overrides, `[patch]` sections, or sibling
checkouts — `cargo build` just works.

Useful workspace commands:

```bash
cargo test --workspace                 # the whole suite
cargo test -p ruso-runtime             # one crate
cargo run -p ruso-cli -- scan --help   # run the CLI from source
cargo doc --workspace --no-deps --open # API docs for every crate
```

## Contributing

Keep the quality gate green before committing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

CI runs exactly these three, plus `cargo audit`, on every push and pull request.

## License

Apache License 2.0. See [LICENSE](LICENSE).
