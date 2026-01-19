/* tslint:disable */
/* eslint-disable */

/* 
 * bindings/cggmp 빌드시 index.d.ts 파일 초기화 이슈로 복사본 파일 보존 용
 * binding 모듈 내 클래스 수정, 함수 추가시 해당파일 수정 필요
 */

export class CggmpExecutor {
  constructor(sessionId: string, executionId: string, partyIndex: number, threshold: number, partiesCount: number)
  exportKeyshare(): Buffer
  exportAuxInfo(): Buffer
  importKeyshare(keyshare: Buffer): void
  importAuxInfo(auxInfo: Buffer): void
  startKeygen(): void
  startAuxGen(): void
  setSigners(signersJson: string): void
  startSigning(txContextHex: string): void
  /**
   * Phase 2 바이너리 최적화: Protobuf 인코딩된 Buffer 배열을 직접 주고받습니다.
   */
  step(incomingEnvelopes: Buffer[]): Buffer[]
  snapshot(): string
}

export function processSession(sessionId: string, executionId: string, incomingEnvelopesJson: string): string
export function auxInfoGen(paramsJson: string): string
export function keygen(paramsJson: string): string
export function signing(paramsJson: string): string