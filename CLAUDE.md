# ruso — guidance for Claude

A Cargo workspace holding the three crates of the Ruso vulnerability scanner.
The **Ruso Scripting Language (RSL)** compiles `.rsl` source to `.rbc` bytecode,
which the VM runs against a target.

| Crate | Role |
|---|---|
| `crates/ruso-script` | grammar, parser, compiler (`.rsl` → `BytecodeProgram`) |
| `crates/ruso-runtime` | bytecode VM, probes, matchers, findings |
| `crates/ruso-cli` | the `ruso` binary: scan orchestration, registry client, reporting |

Dependency direction is one-way: `ruso-cli` → `ruso-script` → `ruso-runtime`.
Never introduce a dependency that points the other way.

Documentation lives in **The Ruso Book** (<https://docs.ruso.hopeless-labs.com>,
source in the separate `ruso-docs` repo), not here — the book is the single
source. This repo carries only the README, this file, and rustdoc.

## Quality gate (keep green before any commit)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Run them workspace-wide, not per crate — a change in the runtime can break the
CLI's tests, and CI checks the whole workspace.

## Dev setup

Nothing to set up. All three crates are here, wired together with path
dependencies through `[workspace.dependencies]` in the root `Cargo.toml`. There
are no sibling checkouts, `[patch]` sections, or `.cargo/config.toml` `paths`
overrides any more — if you find yourself adding one, something is wrong.

Shared third-party dependencies (`tokio`, `reqwest`, `thiserror`, `serde_json`,
`tracing`, `futures`) are declared once in `[workspace.dependencies]` and
inherited with `foo.workspace = true`. A crate may *add* features on top
(`reqwest = { workspace = true, features = ["cookies"] }`) but cannot remove
them. Put a dependency used by a single crate in that crate's manifest.

## Conventions

### Workspace-wide

- **Don't bump versions on every change** — accumulate notes under
  `## [Unreleased]` in the root `CHANGELOG.md`, under the heading of the crate
  they affect. The three crates share one version number (`workspace.package`)
  and release together.
- **Document every public item.** New `pub` types, fields, variants, functions,
  and modules need a `///` doc comment that says what the thing *is* and, where
  it isn't obvious, why it exists. The book's `/api` section is generated from
  these, so they are user-facing.
- Match the surrounding code's style and comment density.
- **Don't name private repos in user-facing text** — call the registry the
  "Ruso registry", not `ruso-backend`.

### `ruso-runtime`

- **Bytecode binary format: MAGIC `b"RUSO"`, `VERSION = 1`.** Do **not** bump
  `VERSION` unless the wire format actually changes — it's a coordinated step
  (the registry must redeploy and re-serve recompiled bytecode).
- Prefer small, **network-free regression tests**: build a `BytecodeProgram`,
  run the `Executor`, and assert on the result (see the loop-opcode tests).
- VM loop borrow pattern: decide an action *while* borrowing the loop frame,
  then mutate `context` *after* the borrow ends (the two can't overlap).

### `ruso-script`

- Grammar lives in `src/script/grammar.pest` (Pest compiles it at build time —
  no codegen step). Bundled examples are `examples/*.rsl`.
- Branding: the language is the Ruso Scripting Language (RSL); source is `.rsl`,
  bytecode is `.rbc`. The binary format MAGIC stays `RUSO`.
- A grammar change is a three-step edit: `grammar.pest`, the parser module that
  consumes the new rule, and the AST node it produces — then the compiler.

### `ruso-cli`

- **Preview output / UX changes and get approval before committing them.**
- Reporting: a single `--report <file.json|file.csv>` picks both path and format
  (json/csv only); there is no `--output` flag. The human console always prints;
  `--report` additionally writes the file. The report is **grouped by target**.
