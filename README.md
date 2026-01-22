# cggmp-node-binding

[![CI](https://github.com/kshan0515/cggmp-node-binding/actions/workflows/ci.yml/badge.svg)](https://github.com/kshan0515/cggmp-node-binding/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@kshan0515/cggmp-node-binding)](https://www.npmjs.com/package/@kshan0515/cggmp-node-binding)

Node.js native binding for **CGGMP24 MPC ECDSA protocol** - Distributed key generation and threshold signing without exposing private keys.

Based on [cggmp21](https://github.com/LFDT-Lockness/cggmp21) Rust implementation.

## Features

- **Distributed Key Generation (DKG)**: Generate ECDSA key shares across multiple parties
- **Threshold Signing**: Sign messages with a subset of parties (t-of-n)
- **Auxiliary Info Generation**: Generate pre-computation data for efficient signing
- **State Machine API**: Round-based protocol execution with `CggmpExecutor`
- **Cross-platform**: Pre-built binaries for macOS, Linux, and Windows

## Installation

```bash
npm install @kshan0515/cggmp-node-binding
# or
pnpm add @kshan0515/cggmp-node-binding
# or
yarn add @kshan0515/cggmp-node-binding
```

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| macOS | x64, arm64 (Apple Silicon) |
| Linux | x64 (glibc, musl), arm64 (glibc) |
| Windows | x64 |

## Usage

```typescript
import { CggmpExecutor, generatePrimes } from '@kshan0515/cggmp-node-binding';

// Create executor for party 0 in a 2-of-3 threshold setup
const executor = new CggmpExecutor(
  'session-id',
  'execution-id',
  0,  // party index
  2,  // threshold
  3   // total parties
);

// Start auxiliary info generation
executor.startAuxGen();

// Process protocol rounds
const outgoing = executor.step([]);
// ... exchange messages with other parties ...

// Check status
const snapshot = JSON.parse(executor.snapshot());
console.log(snapshot.status);

// After aux gen, start keygen
executor.startKeygen();
// ... continue processing rounds ...

// After keygen, export key share
const keyShare = executor.exportKeyshare();

// For signing, import key share and start signing
executor.importKeyshare(keyShare);
executor.setSigners('[0, 1]');  // Select signers
executor.startSigning('0x...');  // Message hash (32 bytes hex)
```

## API

### `CggmpExecutor`

Main class for MPC protocol execution.

#### Constructor
```typescript
new CggmpExecutor(
  sessionId: string,
  executionId: string,
  partyIndex: number,
  threshold: number,
  partiesCount: number
)
```

#### Methods

| Method | Description |
|--------|-------------|
| `startAuxGen()` | Start auxiliary info generation |
| `startAuxGenWithPrimes(primes: Buffer)` | Start aux gen with pre-generated primes |
| `startKeygen()` | Start distributed key generation |
| `startSigning(txHex: string)` | Start signing (32-byte hash as hex) |
| `step(inputs: Buffer[]): Buffer[]` | Process incoming messages and return outgoing |
| `snapshot(): string` | Get current state as JSON |
| `setSigners(json: string)` | Set signer indices for signing |
| `importKeyshare(data: Buffer)` | Import key share |
| `exportKeyshare(): Buffer` | Export key share |
| `importAuxInfo(data: Buffer)` | Import auxiliary info |
| `exportAuxInfo(): Buffer` | Export auxiliary info |

### `generatePrimes(): Buffer`

Pre-generate safe primes for faster auxiliary info generation.

## Protocol Flow

1. **Auxiliary Info Generation**: Generate Paillier keys and ring-Pedersen parameters
2. **Key Generation**: Generate ECDSA key shares using VSS
3. **Signing**: Create threshold signatures with selected signers

## Building from Source

Requirements:
- Node.js >= 18
- Rust (stable)
- pnpm

```bash
# Install dependencies
pnpm install

# Build native binary
pnpm build

# Run tests
pnpm test
```

## Security

This library implements the CGGMP24 protocol which provides:
- UC-secure key generation
- Identifiable abort in case of malicious behavior
- Threshold security (t-of-n)

**Warning**: This is a cryptographic library. Use with caution in production environments.

## License

MIT

## References

- [CGGMP24 Paper](https://eprint.iacr.org/2021/060)
- [cggmp21 Rust Implementation](https://github.com/LFDT-Lockness/cggmp21)
