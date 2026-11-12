# ruso-script

Parser and compiler for the **Ruso Scripting Language (RSL)**: `.rsl` source →
`BytecodeProgram`. One of the three crates in the
[Ruso](https://github.com/Hopeless-Labs/ruso) workspace.

📖 **Full documentation:** <https://docs.ruso.hopeless-labs.com>
(language reference, examples, compiler internals).

## Usage

```rust
use ruso_script::{parse, compile};

let program = parse(source)?;
let bytecode = compile(&program);
// hand the bytecode to ruso_runtime::Executor
```

Dependency:

```toml
ruso-script = { git = "https://github.com/Hopeless-Labs/ruso.git", branch = "main" }
```

Cargo resolves the crate out of the workspace at that repo, so the same URL
serves both libraries.

## In this crate

- `src/script/grammar.pest` — the grammar (source of truth for RSL syntax)
- `src/script/parser/` — parse tree → AST, one module per statement family
- `src/script/ast.rs` — the AST the compiler consumes
- `src/compile.rs` — AST → [`ruso-runtime`](../ruso-runtime) bytecode
- `examples/*.rsl` — runnable example checks

Everything else — language reference, tutorials, architecture — lives in
**[The Ruso Book](https://docs.ruso.hopeless-labs.com)**.

## License

Apache License 2.0. See [LICENSE](../../LICENSE).
