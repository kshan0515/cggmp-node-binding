# Changelog

All notable changes to this project will be documented in this file.

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
