# ruso-cli

`ruso` — the command-line vulnerability scanner. One of the three crates in the
[Ruso](https://github.com/Hopeless-Labs/ruso) workspace; this is the one that
produces the binary.

📖 **Full documentation:** <https://docs.ruso.hopeless-labs.com>

## Install

```bash
cargo install --git https://github.com/Hopeless-Labs/ruso.git ruso-cli
```

The package is `ruso-cli`; the installed binary is `ruso`.

## Quick start

> Scan only systems you own or are explicitly authorized to test.

```bash
ruso scan --family web --target https://target.example.com
ruso search log4j --tag rce
ruso scan --script someuser/log4shell --target https://target.example.com -v
```

See the [workspace README](../../README.md) for the full command table and the
book for every flag.

## In this crate

- `src/cli/args.rs` — the clap command tree
- `src/cli/cmd_registry.rs` / `registry.rs` / `credentials.rs` — registry client
  (search, install, publish, auth)
- `src/cli/discover.rs` / `targets.rs` / `throttle.rs` — scan orchestration
- `src/cli/report.rs` — JSON/CSV report writing, grouped by target
- `src/cli/ui.rs` / `style.rs` / `banner.rs` — console output

## License

Apache License 2.0. See [LICENSE](../../LICENSE).
