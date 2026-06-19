# Design: Distribution

## Technical Approach

A GitHub Actions workflow (`.github/workflows/release.yml`) triggered by version tags
(`v*`) builds both workspace binaries for every supported target, attaches each binary plus
its `.sha256` to a GitHub Release, and a companion `install.sh` at the repo root downloads,
verifies, and installs the right binary on the host. The pattern mirrors the
`octopus-autocoder` pipeline (named in `project.md`) but is adapted to Abyssum's **two**
binaries and its flat Cargo workspace (no `autocoder/` subdirectory — `cargo` runs at the
repo root).

The installer stays deliberately thin: detect → resolve version → download → verify →
place on PATH. No interactive wizard, no config generation — those are Abyssum's own
concern, not the bootstrapper's. Anyone can read the whole script in under a minute, which
is the security property that makes a `curl | bash` install defensible.

## Supported Target Triples

| Triple | Host runner | Build path |
|--------|-------------|------------|
| `x86_64-unknown-linux-gnu`  | `ubuntu-latest` | `cargo-zigbuild`, GLIBC floor 2.17 |
| `aarch64-unknown-linux-gnu` | `ubuntu-latest` | `cargo-zigbuild`, GLIBC floor 2.17 |
| `aarch64-apple-darwin`      | `macos-latest`  | native `cargo build` |

These three cover modern Linux servers/containers (x86_64 and ARM) and Apple Silicon
macs — the realistic operator surface for a bug-bounty CLI/web tool. x86_64 macOS and
Windows are intentionally omitted from v1 and can be added later as their own change.

## Library / Tooling Choices

- **`cargo-zigbuild`** for the Linux targets. It uses `zig cc` as the cross linker so a
  single Ubuntu runner can build both Linux architectures, and — critically — lets us pin
  the **GLIBC floor** via a `.2.17` suffix on the zig target (e.g.
  `x86_64-unknown-linux-gnu.2.17`). GLIBC 2.17 is the RHEL 7 / Ubuntu 16.04 / Debian 9
  baseline; binaries built against it load on any newer glibc, so one artifact runs across
  the whole supported-distro range without per-distro builds.
- **Native `cargo build`** for `aarch64-apple-darwin` on a macOS runner (no cross toolchain
  needed; the runner is already Apple Silicon).
- **`actionlint`** to lint the workflow itself, and **`shellcheck`** to lint `install.sh`.
- **`softprops/action-gh-release`** to attach the artifacts to the GitHub Release.
- **`sha256sum`** (Linux) / **`shasum -a 256`** (macOS) for checksums, normalized to the
  `<hex>␣␣<name>` format so one `install.sh` verifies artifacts regardless of which OS
  produced them.

## Key Decisions

### Decision: Pin a GLIBC floor and verify it at build time
A release binary that silently requires a newer glibc than an operator's distro provides is
a latent field failure. The workflow inspects the built Linux binaries' required
dynamic-symbol versions with `objdump -T` and fails the job if any required `GLIBC_*`
exceeds the 2.17 floor — catching a dependency that leaks a newer-glibc symbol at build
time, not in user-land.

### Decision: Checksum self-verification before publish
Right after computing each `.sha256`, the workflow runs `sha256sum -c` against it. A
checksum file that does not match its binary fails the job, so a corrupt or mismatched pair
can never reach a release.

### Decision: Thin installer, fail-closed verification
`install.sh` runs `set -euo pipefail` and a `trap ... ERR` that reports which step failed.
Checksum verification happens in the download tempdir **before** anything is placed on
PATH; a verification failure exits non-zero, leaves PATH untouched, and preserves the
tempdir for inspection. The installer never `chmod +x` / installs a binary it has not
verified.

### Decision: Two binaries per host, installed together
Unlike the single-binary exemplar, Abyssum delivers `abyssum` and `abyssum-web`. The
installer downloads and verifies **both** matching artifacts for the host and installs both
to the same bin directory, so a host always has a consistent CLI+web pair from one release.

### Decision: Asset naming encodes name + version + triple
Assets are named `<binary>-<version>-<triple>` (e.g.
`abyssum-v2.0.0-x86_64-unknown-linux-gnu`) with a sibling `.sha256`. The installer
reconstructs these names from detected host facts and the resolved version, so no manifest
or index file is required.

### Decision: Default vs. user install location
Root (or sudo-capable) installs land in `/usr/local/bin`; unprivileged or `--user` installs
land in `~/.local/bin`. Either way the binaries end up on a conventional PATH directory.

## Testing

- The release workflow is exercised in CI in a **dry-run** path (build matrix runs,
  publish step is gated off) so the build/checksum logic is validated without creating a
  real release. No git tags are created by any task here.
- `install.sh` is unit-tested via `shellcheck` and a local smoke test that points the
  download base at a **local fixture server / local files** (never a real GitHub release):
  assert it picks the correct triple, verifies a good checksum, and — given a deliberately
  corrupted artifact — aborts non-zero without installing.
- No real third-party targets and no real release endpoints are contacted in any test.
