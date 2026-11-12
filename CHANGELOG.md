# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project follows
[Semantic Versioning](https://semver.org/).

The three crates in this workspace (`ruso-cli`, `ruso-script`, `ruso-runtime`)
share one version number and are released together. Entries are grouped by the
crate they affect.

## [Unreleased]

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

## [1.0.0] - 2026-06-16

Initial 1.0 release of `ruso-cli`, `ruso-script`, and `ruso-runtime`, published
at the time as three separate repositories.
