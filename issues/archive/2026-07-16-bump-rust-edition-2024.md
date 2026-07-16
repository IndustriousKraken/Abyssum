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
      the repo relies on one. (Toolchain is Rust 1.95.0; the repo pins no
      toolchain/MSRV, and `edition = "2024"` already makes Cargo enforce the
      1.85 floor, so no new pin was added.)
- [x] Run `cargo fix --edition` if needed and address any 2024 idiom/migration
      lints across all four crates (`abyssum-core`, `abyssum-scanners`,
      `abyssum-cli`, `abyssum-web`). (Clean build with no `cargo fix --edition`
      migrations; applied the new let-chain `collapsible_if` idiom lints and
      reformatted to the 2024 rustfmt style edition.)
- [x] Ensure `cargo build`, `cargo test`, and `cargo clippy --all-targets` pass on
      the new edition.
