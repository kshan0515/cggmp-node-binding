# @kshan0515/cggmp-node-binding

## Project Overview
This project is a Node.js native binding for the **CGGMP24 MPC ECDSA protocol**, enabling distributed key generation (DKG) and threshold signing directly from Node.js applications. It wraps the Rust `cggmp24` crate using `napi-rs`.

### Tech Stack
- **Language:** Rust (Core logic), TypeScript/JavaScript (Interface)
- **Frameworks/Libraries:** 
    - `napi-rs` (Native bindings)
    - `cggmp24` (Rust MPC implementation)
    - `round-based` (State machine handling)
    - `prost` (Protocol Buffers)
    - `Jest` (Testing)
- **Package Manager:** `pnpm`

## Directory Structure
- `src/`: Source code
    - `lib.rs`: Main Rust entry point. Defines the `CggmpExecutor` class and `napi` exports. Manages protocol state machines.
    - `index.ts`: TypeScript entry point. Handles loading the native module (supports Jest mocking).
    - `proto/`: Protobuf generated files (implied).
- `proto/`: Protocol Buffer definitions (`cggmp.proto`).
- `__tests__/`: Jest unit and integration tests.
- `index.js`: Native module loader (generated/managed by `napi`).
- `build.rs`: Rust build script (likely for compiling Protobufs).

## Building and Running

### Prerequisites
- Node.js >= 18
- Rust (stable)
- `pnpm`

### Key Commands
- **Install Dependencies:**
  ```bash
  pnpm install
  ```
- **Build Native Binding:**
  ```bash
  pnpm build
  ```
  This runs `napi build --platform --release`.
- **Run Tests:**
  ```bash
  pnpm test
  ```
  Runs `jest`.
- **Generate Artifacts:**
  ```bash
  pnpm artifacts
  ```

## Development Conventions

- **Hybrid Codebase:** The project mixes Rust and TypeScript. Rust handles the heavy cryptographic lifting and protocol state machines, while TypeScript provides the user-facing API.
- **N-API:** All native interactions are mediated through `napi-rs`. The `CggmpExecutor` struct in Rust maps to the JavaScript class.
- **State Machines:** The Rust implementation uses a state machine pattern (`ProtocolState` enum in `lib.rs`) to manage the asynchronous and multi-round nature of MPC protocols (Keygen, AuxGen, Signing).
- **Protobuf:** Messages exchanged between parties are serialized using Protobuf (`prost`).
- **Testing:** Tests are written in TypeScript using Jest (`__tests__/*.test.ts`).
