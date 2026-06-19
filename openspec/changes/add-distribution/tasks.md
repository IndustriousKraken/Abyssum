# Tasks

## 1. Release workflow skeleton
- [ ] 1.1 Create `.github/workflows/release.yml` triggered on `push` of `v*` tags and on `workflow_dispatch` with a `dry_run` boolean input (default true) so the build path is CI-exercisable without publishing
- [ ] 1.2 Add a `lint` job that runs `actionlint` against the workflow files
- [ ] 1.3 Add a `test` job (`needs: lint`) that runs `cargo test --workspace` so a release never ships untested binaries

## 2. Cross-compiled build matrix
- [ ] 2.1 Add a `build` job (`needs: test`) with a matrix of the three supported triples: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (both via `cargo-zigbuild`, GLIBC floor `.2.17`), and `aarch64-apple-darwin` (native `cargo build`)
- [ ] 2.2 Install the matching Rust target, plus `zig` and `cargo-zigbuild` for the Linux entries
- [ ] 2.3 Build both binaries (`abyssum`, `abyssum-web`) in `--release` for the matrix target
- [ ] 2.4 For Linux targets, verify the GLIBC floor with `objdump -T` and fail the job if any required `GLIBC_*` exceeds `2.17`
- [ ] 2.5 Strip both release binaries for the matrix target

## 3. Artifacts and checksums
- [ ] 3.1 Stage each binary as a release asset named `<binary>-<tag>-<triple>` for both `abyssum` and `abyssum-web`
- [ ] 3.2 Compute a `.sha256` for every staged asset (`sha256sum` on Linux, `shasum -a 256` normalized to the same format on macOS)
- [ ] 3.3 Self-verify each checksum with `-c` so a mismatched binary/checksum pair fails the build before publish
- [ ] 3.4 Upload the binaries and their `.sha256` files as workflow artifacts (`if-no-files-found: error`)

## 4. Publish job (gated)
- [ ] 4.1 Add a `publish` job (`needs: [test, build]`) that runs only on a real tag push or an explicit non-dry-run dispatch
- [ ] 4.2 Download all built artifacts and create a GitHub Release attaching every `<binary>-<tag>-<triple>` and its `.sha256`, marking pre-release when the tag contains a hyphen

## 5. Installer
- [ ] 5.1 Write repo-root `install.sh` with `set -euo pipefail` and an `ERR` trap that reports the failing step name
- [ ] 5.2 Detect the host OS/arch and map it to a supported triple; print a clear "no pre-built binary for <os>/<arch>" message and exit non-zero for unsupported hosts
- [ ] 5.3 Resolve the version from `--version`/env or the GitHub "latest release" API
- [ ] 5.4 Download both `abyssum` and `abyssum-web` for the host triple plus their `.sha256` files into a tempdir
- [ ] 5.5 Verify every checksum in the tempdir; on any failure, print an error, preserve the tempdir path, and exit non-zero without installing
- [ ] 5.6 Install both verified binaries to `/usr/local/bin` (root/sudo) or `~/.local/bin` (`--user` or unprivileged) with mode `755`

## 6. Lint and local tests (no real targets, no real releases)
- [ ] 6.1 Add a `shellcheck install.sh` step to the workflow's `lint` job
- [ ] 6.2 Add a local smoke test that runs `install.sh` against a **local fixture directory / local mock server** of assets: assert correct-triple selection and successful install on a good checksum
- [ ] 6.3 Add a local negative test: a deliberately corrupted artifact causes `install.sh` to exit non-zero and install nothing onto the destination directory
