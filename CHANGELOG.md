# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-10-23

### Changed
- Updated CI Node.js version to `22` and configured napi default node version.

## [0.2.0] - 2026-10-12

### Added
- **N-API Async Worker (`stepAsync` / `step_async`)**:
  - Implemented `napi::Task` trait (`StepTask`) to execute heavy CGGMP cryptographic operations off the main thread.
  - Keeps Node.js main event loop completely unblocked while maintaining backwards compatibility with synchronous `step`.
- **Memory Zeroization & Protection (`destroy` / `isDestroyed`)**:
  - Added explicit zeroization of keyshare secrets, Paillier primes ($p, q$), session context, and masking values using `zeroize`.
  - Guard against use-after-free with `is_destroyed: bool` flag throwing `"Executor has already been destroyed"`.
  - Implemented `Drop` trait to ensure zeroization on object destruction.
- **Identifiable Abort (`AbortBlame`) Error Parsing**:
  - Added structured `{ blameParty: number, reason: string }` error reporting and `parseAbortBlameError` helper for slashing malicious nodes.
- **V8 Heap Isolation via `napi::External` Handles**:
  - Support passing and keeping `KeyShare` and `AuxInfo` as Rust heap pointers (`External<Arc<Mutex<T>>>`) without exposing sensitive bytes in V8 heap memory.
- Added comprehensive Rust unit tests and Jest Phase 2 integration tests.

## [0.1.7] - 2026-09-02

### Fixed
- **2-of-3 Threshold Signing**:
  - Fixed recipient index routing in `drive_sm` (`OneParty(i)` mapped to global party index `signers[i]`).
  - Fixed dangling pointer / premature drop issue for signing data by persisting `_data` within `ProtocolState::Signing`.
  - Added support for 32-byte prehashed data via `PrehashedDataToSign` and aligned reliable broadcast configuration.
  - Safely handle trailing inputs when state machine is already finished (`ProtocolState::None`).
- Added E2E integration test for 2-of-3 threshold signing across all 2-party combinations (`[0, 1]`, `[0, 2]`, `[1, 2]`).

## [0.1.6] - 2026-01-22

### Fixed
- Added `GITHUB_TOKEN` to the Publish step in CI workflow.

## [0.1.5] - 2026-01-22

### Fixed
- Updated CI deployment settings.

### Fixed
- Removed redundant artifact renaming step in CI test job. The build artifact is already correctly named `cggmp-node-binding.linux-x64-gnu.node`, so `mv` was failing.

## [0.1.2] - 2026-01-20

### Fixed
- Fixed CI test failure by renaming the built artifact to match the platform-specific filename expected by `index.js` (`cggmp-node-binding.linux-x64-gnu.node`) during the test job.

## [0.1.1] - 2026-01-20

### Fixed
- Updated `index.js` to correctly load platform-specific native bindings based on `process.platform` and `process.arch`.
- Added support for multiple architectures including Linux (gnu/musl), macOS (x64/arm64), Windows, and Android.
