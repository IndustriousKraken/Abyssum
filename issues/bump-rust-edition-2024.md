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

- [ ] Set `edition = "2024"` in `[workspace.package]` in the root `Cargo.toml`.
- [ ] Confirm the `rust-version` / toolchain in use supports the 2024 edition
      (Rust 1.85+); add or update a `rust-toolchain.toml` / `rust-version` pin if
      the repo relies on one.
- [ ] Run `cargo fix --edition` if needed and address any 2024 idiom/migration
      lints across all four crates (`abyssum-core`, `abyssum-scanners`,
      `abyssum-cli`, `abyssum-web`).
- [ ] Ensure `cargo build`, `cargo test`, and `cargo clippy --all-targets` pass on
      the new edition.
