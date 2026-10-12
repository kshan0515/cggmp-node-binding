import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ec as EC } from 'elliptic';
import { CggmpExecutor, parseAbortBlameError } from '../index';
import { Envelope } from '../src/proto/cggmp';

const secp256k1 = new EC('secp256k1');

function verifySignature(publicKeyHex: string, msgHashHex: string, rHex: string, sHex: string): boolean {
  try {
    const key = secp256k1.keyFromPublic(publicKeyHex, 'hex');
    const msgHash = Buffer.from(msgHashHex, 'hex');
    return key.verify(msgHash, { r: rHex, s: sHex });
  } catch (e) {
    console.error('verifySignature error:', e);
    return false;
  }
}

function routeMessages(
  nodes: { executor: CggmpExecutor; index: number }[],
  outgoings: { [nodeIndex: number]: Buffer[] }
): { [nodeIndex: number]: Buffer[] } {
  const nextIncomings: { [nodeIndex: number]: Buffer[] } = {};
  for (const node of nodes) {
    nextIncomings[node.index] = [];
  }

  for (const senderIndex of Object.keys(outgoings).map(Number)) {
    const msgs = outgoings[senderIndex] || [];
    for (const msgBuf of msgs) {
      const env = Envelope.decode(msgBuf);
      const recipients = env.toParties.length === 0
        ? nodes.map(n => n.index).filter(idx => idx !== senderIndex)
        : env.toParties;

      for (const recipient of recipients) {
        if (nextIncomings[recipient] !== undefined) {
          nextIncomings[recipient].push(msgBuf);
        }
      }
    }
  }

  return nextIncomings;
}

// 비동기 프로토콜 구동 헬퍼 (stepAsync 활용)
async function runProtocolRoundsAsync(
  nodes: { executor: CggmpExecutor; index: number }[],
  initialOutgoings: { [nodeIndex: number]: Buffer[] },
  maxRounds = 30
): Promise<void> {
  let outgoings = initialOutgoings;
  let rounds = 0;

  while (rounds < maxRounds) {
    const incomings = routeMessages(nodes, outgoings);
    const hasIncoming = Object.values(incomings).some(arr => arr.length > 0);
    if (!hasIncoming) break;

    outgoings = {};
    const stepPromises = nodes.map(async n => {
      const out = await n.executor.stepAsync(incomings[n.index]);
      return { index: n.index, out };
    });

    const results = await Promise.all(stepPromises);
    for (const r of results) {
      outgoings[r.index] = r.out;
    }
    rounds++;

    const allFinished = nodes.every(n => {
      const s = JSON.parse(n.executor.snapshot()).status;
      return s.endsWith('_finished') || s === 'keyshare_ready';
    });
    if (allFinished) break;
  }
}

const PRECOMPUTED_PRIMES: Buffer[] = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'primes.json'), 'utf-8')
).map((b64: string) => Buffer.from(b64, 'base64'));

describe('Phase 2 고도화 기능 검증 (Phase 2 Enhancement Verification)', () => {
  const SESSION_ID = 'phase2-test-session';
  const THRESHOLD = 2;
  const PARTIES_COUNT = 3;
  const timeoutMs = 60000;
  jest.setTimeout(timeoutMs);

  describe('1. 명시적 메모리 제로화 및 Use-After-Free 방어 (destroy / isDestroyed)', () => {
    test('destroy() 호출 후 isDestroyed()가 true여야 하며, 재호출 시 적절한 예외를 던져야 한다', async () => {
      const executor = new CggmpExecutor('test-session', 'test-exec', 0, 2, 3);
      expect(executor.isDestroyed()).toBe(false);

      executor.startKeygen();
      expect(executor.isDestroyed()).toBe(false);

      // destroy 호출
      executor.destroy();
      expect(executor.isDestroyed()).toBe(true);

      // 동기 step 호출 시 차단
      expect(() => executor.step([])).toThrow(/Executor has already been destroyed/);

      // 비동기 stepAsync 호출 시 Promise reject 차단
      await expect(executor.stepAsync([])).rejects.toThrow(/Executor has already been destroyed/);

      // 다른 API 호출 시에도 차단
      expect(() => executor.startKeygen()).toThrow(/Executor has already been destroyed/);
      expect(() => executor.exportKeyshare()).toThrow(/Executor has already been destroyed/);
      expect(() => executor.exportKeyshareHandle()).toThrow(/Executor has already been destroyed/);
      expect(() => executor.snapshot()).toThrow(/Executor has already been destroyed/);

      // 중복 destroy 호출은 안전해야 함 (idempotent)
      expect(() => executor.destroy()).not.toThrow();
      expect(executor.isDestroyed()).toBe(true);
    });
  });

  describe('2. Identifiable Abort (AbortBlame) 에러 구조체 파싱 검증', () => {
    test('JSON 형식의 AbortBlame 메시지를 정확히 파싱해야 한다', () => {
      const blameJson = JSON.stringify({
        blameParty: 1,
        reason: "Party decommitment doesn't match commitment",
      });

      const parsed = parseAbortBlameError(blameJson);
      expect(parsed).not.toBeNull();
      expect(parsed?.blameParty).toBe(1);
      expect(parsed?.reason).toBe("Party decommitment doesn't match commitment");
    });

    test('CGGMP 내부 에러 문자열에서 AbortBlame 정보를 추출해야 한다', () => {
      const internalErr = "Protocol aborted; malicious parties: [AbortBlame { faulty_party: 2, data_message: MsgId(1), proof_message: MsgId(2) }]; reason: InvalidSchnorrProof";
      const parsed = parseAbortBlameError(internalErr);
      expect(parsed).not.toBeNull();
      expect(parsed?.blameParty).toBe(2);
      expect(parsed?.reason).toContain("Schnorr proof");
    });

    test('알 수 없는 일반 에러의 경우 null을 반환해야 한다', () => {
      const genericErr = "Invalid arguments: party index out of range";
      const parsed = parseAbortBlameError(genericErr);
      expect(parsed).toBeNull();
    });
  });

  describe('3. N-API 비동기 워커화 (stepAsync) 및 V8 힙 격리 핸들 (External Handle) E2E 검증', () => {
    let keyShares: { [partyIndex: number]: Buffer } = {};
    let keyShareHandles: { [partyIndex: number]: any } = {};
    let sharedPublicKeyHex = '';

    test('stepAsync 비동기 워커로 AuxGen 및 DKG 완료 및 External Pointer Handle 전환 성공', async () => {
      // 1. AuxGen 비동기 수행
      const auxExecutors = [0, 1, 2].map(
        idx => new CggmpExecutor(SESSION_ID, 'exec-aux-async', idx, THRESHOLD, PARTIES_COUNT)
      );
      const auxNodes = auxExecutors.map((executor, index) => ({ executor, index }));
      const initialAuxOutgoings: { [index: number]: Buffer[] } = {};

      for (const node of auxNodes) {
        node.executor.startAuxGenWithPrimes(PRECOMPUTED_PRIMES[node.index]);
        initialAuxOutgoings[node.index] = await node.executor.stepAsync([]);
      }

      await runProtocolRoundsAsync(auxNodes, initialAuxOutgoings);

      const auxHandles: { [partyIndex: number]: any } = {};
      for (const node of auxNodes) {
        const snap = JSON.parse(node.executor.snapshot());
        expect(snap.status).toBe('aux_gen_finished');
        // V8 힙에 노출되지 않는 External 핸들로 추출
        auxHandles[node.index] = node.executor.exportAuxInfoHandle();
        expect(auxHandles[node.index]).toBeDefined();
      }

      // 2. DKG 비동기 수행 (AuxInfo를 External Handle로 주입)
      const dkgExecutors = [0, 1, 2].map(
        idx => new CggmpExecutor(SESSION_ID, 'exec-dkg-async', idx, THRESHOLD, PARTIES_COUNT)
      );
      const dkgNodes = dkgExecutors.map((executor, index) => ({ executor, index }));
      const initialDkgOutgoings: { [index: number]: Buffer[] } = {};

      for (const node of dkgNodes) {
        // Node.js Buffer 없이 포인터 핸들로 직접 주입
        node.executor.importAuxInfoHandle(auxHandles[node.index]);
        node.executor.startKeygen();
        initialDkgOutgoings[node.index] = await node.executor.stepAsync([]);
      }

      await runProtocolRoundsAsync(dkgNodes, initialDkgOutgoings);

      for (const node of dkgNodes) {
        const snap = JSON.parse(node.executor.snapshot());
        expect(snap.status).toBe('keyshare_ready');
        expect(snap.publicKey).toBeDefined();

        keyShares[node.index] = node.executor.exportKeyshare();
        // V8 힙 격리를 위한 External Handle 저장
        keyShareHandles[node.index] = node.executor.exportKeyshareHandle();
        expect(keyShareHandles[node.index]).toBeDefined();

        sharedPublicKeyHex = snap.publicKey;
      }

      expect(sharedPublicKeyHex).toBeTruthy();
    }, timeoutMs);

    test('External Pointer Handle로 복원된 노드들이 stepAsync로 서명 성공', async () => {
      const actualSigners: [number, number] = [0, 1];
      const signersJson = JSON.stringify(actualSigners);
      const executionId = 'exec-signing-async-0-1';
      const txHash = crypto.createHash('sha256').update('test-phase2-async-signing').digest('hex');

      const signingExecutors = actualSigners.map(
        partyIdx => new CggmpExecutor(SESSION_ID, executionId, partyIdx, THRESHOLD, PARTIES_COUNT)
      );
      const signingNodes = signingExecutors.map((executor, idx) => ({
        executor,
        index: actualSigners[idx],
      }));

      const initialSigningOutgoings: { [index: number]: Buffer[] } = {};

      for (const node of signingNodes) {
        // V8 힙의 Buffer를 거치지 않고 Rust 힙 포인터 핸들(External)로 키 주입
        node.executor.importKeyshareHandle(keyShareHandles[node.index]);
        node.executor.setSigners(signersJson);
        node.executor.startSigning(txHash);
        initialSigningOutgoings[node.index] = await node.executor.stepAsync([]);
      }

      await runProtocolRoundsAsync(signingNodes, initialSigningOutgoings);

      for (const node of signingNodes) {
        const snap = JSON.parse(node.executor.snapshot());
        expect(snap.status).toBe('signing_finished');
        expect(snap.signature).toBeDefined();

        const sigObj = JSON.parse(snap.signature);
        const rHex = typeof sigObj.r === 'string' ? sigObj.r : sigObj.r.scalar;
        const sHex = typeof sigObj.s === 'string' ? sigObj.s : sigObj.s.scalar;

        const isValid = verifySignature(sharedPublicKeyHex, txHash, rHex, sHex);
        expect(isValid).toBe(true);

        // 서명 완료 후 메모리 제로화 파기 검증
        node.executor.destroy();
        expect(node.executor.isDestroyed()).toBe(true);
        expect(() => node.executor.step([])).toThrow(/Executor has already been destroyed/);
      }
    }, timeoutMs);
  });
});
