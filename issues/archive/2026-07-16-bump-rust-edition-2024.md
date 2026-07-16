# Bump the workspace to Rust edition 2024

The workspace is pinned to the 2021 edition. The 2024 edition (stable since Rust
1.85) is the current edition and the right default for a greenfield rebuild; there
is no reason this fresh codebase should start an edition behind.

This is a correction to code, not a behavior change — no canonical requirement
names or constrains the Rust edition, so there is no spec delta. The edition is
declared once at the workspace root (`Cargo.toml`, `[workspace.package] edition =
"2021"`) and inherited by every crate via `edition.workspace = true`, so the bump
is centralized.

## Tasks

- [x] Set `edition = "2024"` in `[workspace.package]` in the root `Cargo.toml`.
- [x] Confirm the `rust-version` / toolchain in use supports the 2024 edition
      (Rust 1.85+); add or update a `rust-toolchain.toml` / `rust-version` pin if
      the repo relies on one. (Toolchain is 1.95.0; repo pins no toolchain file and
      declares no `rust-version`, so none was added.)
- [x] Run `cargo fix --edition` if needed and address any 2024 idiom/migration
      lints across all four crates (`abyssum-core`, `abyssum-scanners`,
      `abyssum-cli`, `abyssum-web`). (No `cargo fix --edition` changes were needed
      to compile; applied `cargo clippy --fix` for the 37 `collapsible_if` lints
      newly enabled by let-chain stabilization. The 2024 migration lint set is
      empty here: a clean build under `-W rust-2024-compatibility` plus the named
      behavioral lints — `tail_expr_drop_order`, `unsafe_op_in_unsafe_fn`,
      `edition_2024_expr_fragment_specifier` — emits no warnings across all four
      crates and all targets, so no drop-order/RPIT/unsafe migration applies.)
- [x] Ensure `cargo build`, `cargo test`, and `cargo clippy --all-targets` pass on
      the new edition.
