# Changelog

All notable changes to this project will be documented in this file.

## [0.1.2] - 2026-01-20

### Fixed
- Fixed CI test failure by renaming the built artifact to match the platform-specific filename expected by `index.js` (`cggmp-node-binding.linux-x64-gnu.node`) during the test job.

## [0.1.1] - 2026-01-20

### Fixed
- Updated `index.js` to correctly load platform-specific native bindings based on `process.platform` and `process.arch`.
- Added support for multiple architectures including Linux (gnu/musl), macOS (x64/arm64), Windows, and Android.