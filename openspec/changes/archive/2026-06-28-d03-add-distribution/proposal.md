## Why

Abyssum ships as **self-contained static binaries** (`abyssum`, `abyssum-web`) with no
Python runtime and no interpreter (see `project.md`). For that promise to hold, a tagged
release must reliably produce cross-compiled binaries for every supported host, and an
operator must be able to install the right one with a single command and a verifiable
chain of custody.

This change adds the build-and-deliver pipeline: a release workflow that cross-compiles
both binaries for the supported target triples and publishes each alongside a SHA-256
checksum, and a thin `install.sh` that downloads the correct binary for the host, verifies
its checksum, and places it on PATH — failing safely if verification fails. It is the last
change in the order because it packages binaries that only exist once the CLI
(`add-cli`) and web (`add-web-interface`) surfaces are built.

## What Changes

### 1. Cross-compiled release artifacts on tag

On a version tag, build release binaries of both `abyssum` and `abyssum-web` for each
supported target triple, producing portable Linux binaries with a fixed minimum GLIBC
floor and a native macOS binary. Each binary is published as a release asset.

### 2. Per-artifact SHA-256 checksums

Every published binary is accompanied by a SHA-256 checksum file. The checksum is computed
and self-verified during the build so a malformed checksum fails the pipeline before
publish, never in an operator's hands.

### 3. Thin host-aware installer

A small `install.sh` detects the host OS/architecture, resolves the release version,
downloads the matching binaries and their checksums, verifies each checksum, and installs
the verified binaries onto PATH. Verification failure aborts the install with a clear error
and without placing an unverified binary on PATH.

### 4. Installer and workflow linting

The release workflow lints itself (and `install.sh` is shellchecked) so the delivery
machinery is validated by CI rather than discovered broken at release time.

## Impact

- Adds the `distribution` capability to `openspec/specs/`.
- Depends on `add-cli` and `add-web-interface` being archived first (the binaries must
  exist) per `IMPLEMENTATION_ORDER.md`.
- Introduces no scanning behavior; it is build/delivery machinery only.
