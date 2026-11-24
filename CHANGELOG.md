# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/).

The three crates in this workspace (`ruso-cli`, `ruso-script`, `ruso-runtime`)
share one version number and are released together. Entries are grouped by the
crate they affect.

## [Unreleased]

### Added

- **`confidence` metadata field** (`ruso-script`, `ruso-runtime`, `ruso-cli`).
  A check can now declare how sure it is that a positive result is real,
  separately from `severity`:

  ```
  metadata {
      severity critical
      confidence certain
  }
  ```

  The levels are `tentative` (inferred from a version or banner), `firm` (a
  strong, specific indicator), and `certain` (proven by the target's
  behaviour). The field is optional and has no default: a check that omits it
  reports no confidence. It is carried in the bytecode metadata block, exposed
  as `Finding::confidence`, and written to the `--report` JSON (`confidence`)
  and CSV (a `confidence` column after `severity`). Bytecode compiled before
  this change must be recompiled.
- **`ruso scan --min-confidence <tentative|firm|certain>`** (`ruso-cli`). Runs
  only the scripts that declare at least that confidence. Scripts below the
  level, and scripts that declare none, are skipped before any probe is sent;
  a warning says how many were skipped. `ruso exec` takes the same flag.
- **`ruso search --confidence <level>`** (`ruso-cli`). Exact-match filter on a
  script's declared confidence; the results table gains a `CONFIDENCE` column.
- **`ruso admin recompile --yes`** (`ruso-cli`). Asks the registry to rebuild
  every stored version's bytecode and metadata from its source. Run it once
  after the registry is deployed with a changed bytecode layout.
- **`ruso info` shows severity and confidence** (`ruso-cli`) of the latest
  non-yanked version, when the script declares them.
- **Confidence on the console** (`ruso-cli`). A finding line ends with the
  check's confidence in dimmed parentheses when it declares one:
  `[CRITICAL] 10.0.0.5  Redis exposed without authentication  (certain)`.

### Changed

- **Everything is versioned 0.0.1** while Ruso is in development. The
  workspace version was reset from 1.0.0, and the bytecode `VERSION` is no
  longer bumped when the wire format changes.

### Fixed

- **Five bundled examples** (`ruso-script`) no longer fail to parse:
  `tcp_redis_unauth`, `dns_wire_a`, `dns_wire_txt`, `tcp_http_banner`, and
  `udp_echo` wrote `evidence <probe> regex …`; the `evidence` line now names
  the field (`<probe>.response`).

### Changed

- **The three crates now live in one repository.** `ruso-cli`, `ruso-script`,
  and `ruso-runtime` were previously three separate Git repositories wired
  together with `git` dependencies, a `[patch]` section, and a `paths` override
  in `.cargo/config.toml`. They are now a single Cargo workspace under
  `crates/`, connected by path dependencies. For users this changes only the
  install command:

  ```bash
  # before
  cargo install --git https://github.com/Hopeless-Labs/ruso-cli.git
  # now
  cargo install --git https://github.com/Hopeless-Labs/ruso.git ruso-cli
  ```

  Consumers of the libraries point a single `git` dependency at this repo:

  ```toml
  ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso.git", branch = "main" }
  ruso-script  = { git = "https://github.com/Hopeless-Labs/ruso.git", branch = "main" }
  ```

  No API, grammar, or bytecode change is involved.

#### ruso-script

- **Evidence statements must name an explicit source.** Grammar is now
  `evidence <probe>.body | .response | .header "<name>"`, each with an optional
  trailing `regex '…'`. The source-less `evidence <probe> regex '…'` form is
  removed (hard parse error) — it ran against the body and could not prove a
  header-borne finding. Header values are now first-class evidence.

#### ruso-runtime

- **Evidence is now source-explicit.** `EvidenceKind` is `Body` / `Response` /
  `Header { name }`, each with an optional regex, replacing the old
  `BodyRef` / `ResponseRef` / source-less `Regex` variants. A header value can
  now be used as proof directly (`evidence p.header "X-Powered-By"`); previously
  a bare `evidence p regex '…'` silently ran against the body and mis-fired when
  the proof lived in a header. The bytecode evidence-pool encoding changed
  accordingly (the magic/VERSION are unchanged — the registry is republished in
  lockstep so no old-format evidence bytecode survives).

### Documentation

- Every public item across `ruso-runtime` and `ruso-script` now carries a
  rustdoc comment, including opcode constants, bytecode wire-format helpers, AST
  nodes, and every error variant.

## [0.0.1] - 2026-06-16

Initial development version of `ruso-cli`, `ruso-script`, and `ruso-runtime`,
published at the time as three separate repositories. It was originally
labelled 1.0.0; the project is still in development and is versioned 0.0.1.
