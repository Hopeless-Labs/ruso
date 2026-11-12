# ruso-runtime

Bytecode VM and network runtime for Ruso vulnerability checks — executes compiled
`.rbc` programs against HTTP, DNS, TCP, and UDP targets. One of the three crates
in the [Ruso](https://github.com/Hopeless-Labs/ruso) workspace.

📖 **Full documentation:** <https://docs.ruso.hopeless-labs.com>
(architecture, bytecode format, runtime internals, extending).

## Usage

```rust
use ruso_runtime::{Executor, ExecutorConfig, decode_bytecode};

let config = ExecutorConfig {
    base_url: "https://example.com".into(),
    ..Default::default()
};

let program = decode_bytecode(&bytes)?;
let result = Executor::from_bytecode(config, program)?.run().await?;
```

This crate executes bytecode; it does not parse source. Compile `.rsl` with
[`ruso-script`](../ruso-script).

Dependency:

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso.git", branch = "main" }
```

Cargo resolves the crate out of the workspace at that repo, so the same URL
serves both libraries.

## Bytecode

- Magic: `b"RUSO"`
- Version: **`1`** (`ruso_runtime::VERSION`)

The wire format, opcodes, and execution model are documented in
**[The Ruso Book](https://docs.ruso.hopeless-labs.com)** and in the rustdoc for
[`opcode`](src/opcode.rs) and [`runtime::binary`](src/runtime/binary.rs).

## In this crate

- `src/opcode.rs` — the instruction set and bytecode version
- `src/runtime/binary.rs` — the `.rbc` wire format (encode / decode)
- `src/runtime/executor.rs` — the VM loop
- `src/runtime/{http,dns,socket}.rs` — the probe transports
- `src/runtime/matcher.rs` — match evaluation and finding emission

## License

Apache License 2.0. See [LICENSE](../../LICENSE).
