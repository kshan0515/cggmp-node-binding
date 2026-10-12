/* tslint:disable */
/* eslint-disable */

export function generatePrimes(): Buffer

export interface AbortBlameResponse {
  blameParty: number
  reason: string
}

export function parseAbortBlameError(errMessage: string): AbortBlameResponse | null

export class CggmpExecutor {
  constructor(sessionId: string, executionId: string, partyIndex: number, threshold: number, partiesCount: number)
  isDestroyed(): boolean
  destroy(): void
  exportKeyshare(): Buffer
  exportAuxInfo(): Buffer
  importKeyshare(data: Buffer): void
  importAuxInfo(data: Buffer): void
  startKeygen(): void
  startAuxGen(): void
  startAuxGenWithPrimes(primesBuf: Buffer): void
  setSigners(json: string): void
  startSigning(txHex: string): void
  step(inputs: Buffer[]): Buffer[]
  stepAsync(inputs: Buffer[]): Promise<Buffer[]>
  snapshot(): string
  exportKeyshareBin(): Buffer
  exportAuxInfoBin(): Buffer
  exportKeyshareHandle(): unknown
  importKeyshareHandle(handle: unknown): void
  exportAuxInfoHandle(): unknown
  importAuxInfoHandle(handle: unknown): void
}

export function processSession(sessionId: string, executionId: string, incomingEnvelopesJson: string): string
export function auxInfoGen(paramsJson: string): string
export function keygen(paramsJson: string): string
export function signing(paramsJson: string): string
