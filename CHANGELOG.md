# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2026-01-20

### Fixed
- Updated `index.js` to correctly load platform-specific native bindings based on `process.platform` and `process.arch`.
- Added support for multiple architectures including Linux (gnu/musl), macOS (x64/arm64), Windows, and Android.
