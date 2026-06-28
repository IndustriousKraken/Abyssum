# Tasks

## 1. Release workflow skeleton
- [x] 1.1 Create `.github/workflows/release.yml` triggered on `push` of `v*` tags and on `workflow_dispatch` with a `dry_run` boolean input (default true) so the build path is CI-exercisable without publishing
- [x] 1.2 Add a `lint` job that runs `actionlint` against the workflow files
- [x] 1.3 Add a `test` job (`needs: lint`) that runs `cargo test --workspace` so a release never ships untested binaries

## 2. Cross-compiled build matrix
- [x] 2.1 Add a `build` job (`needs: test`) with a matrix of the three supported triples: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (both via `cargo-zigbuild`, GLIBC floor `.2.17`), and `aarch64-apple-darwin` (native `cargo build`)
- [x] 2.2 Install the matching Rust target, plus `zig` and `cargo-zigbuild` for the Linux entries
- [x] 2.3 Build both binaries (`abyssum`, `abyssum-web`) in `--release` for the matrix target
- [x] 2.4 For Linux targets, verify the GLIBC floor with `objdump -T` and fail the job if any required `GLIBC_*` exceeds `2.17`
- [x] 2.5 Strip both release binaries for the matrix target

## 3. Artifacts and checksums
- [x] 3.1 Stage each binary as a release asset named `<binary>-<tag>-<triple>` for both `abyssum` and `abyssum-web`, using the pushed tag string (`github.ref_name`) **verbatim** as `<tag>` (including any leading `v`)
- [x] 3.2 Compute a `.sha256` for every staged asset (`sha256sum` on Linux, `shasum -a 256` normalized to the same format on macOS)
- [x] 3.3 Self-verify each checksum with `-c` so a mismatched binary/checksum pair fails the build before publish
- [x] 3.4 Upload the binaries and their `.sha256` files as workflow artifacts (`if-no-files-found: error`)

## 4. Publish job (gated)
- [x] 4.1 Add a `publish` job (`needs: [lint, test, build]` so the workflow-lint and `shellcheck install.sh` steps in §6 gate publication) that runs only on a real tag push or an explicit non-dry-run dispatch
- [x] 4.2 Download all built artifacts and create a GitHub Release attaching every `<binary>-<tag>-<triple>` and its `.sha256`, marking pre-release when the tag contains a hyphen

## 5. Installer
- [x] 5.1 Write repo-root `install.sh` with `set -euo pipefail` and an `ERR` trap that reports the failing step name
- [x] 5.2 Detect the host OS/arch and map it to a supported triple; print a clear "no pre-built binary for <os>/<arch>" message and exit non-zero for unsupported hosts
- [x] 5.3 Resolve the version from `--version`/env or the GitHub "latest release" API (`tag_name`); use the resolved tag string **verbatim** (including any leading `v`) when reconstructing asset names so they match the published names exactly
- [x] 5.4 Download both `abyssum` and `abyssum-web` for the host triple plus their `.sha256` files into a tempdir
- [x] 5.5 Verify every checksum in the tempdir; on any failure, print an error, preserve the tempdir path, and exit non-zero without installing
- [x] 5.6 Install both verified binaries to `/usr/local/bin` (root/sudo) or `~/.local/bin` (`--user` or unprivileged) with mode `755`
- [x] 5.7 After installing, warn (without failing) if the chosen install directory (e.g. `~/.local/bin`) is not on the user's `PATH`

## 6. Lint and local tests (no real targets, no real releases)
- [x] 6.1 Add a `shellcheck install.sh` step to the workflow's `lint` job
- [x] 6.2 Add a local smoke test that runs `install.sh` against a **local fixture directory / local mock server** of assets, pointing **both** the download base **and** the version-resolution (latest-release API) at the local fixture/mock so the test never contacts `api.github.com` or a real release: assert correct-triple selection and successful install on a good checksum
- [x] 6.3 Add a local negative test: a deliberately corrupted artifact causes `install.sh` to exit non-zero and install nothing onto the destination directory
