import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { ec as EC } from 'elliptic';
import { CggmpExecutor } from '../index';
import { Envelope } from '../src/proto/cggmp';

const secp256k1 = new EC('secp256k1');

// secp256k1 공개키와 raw 해시 대상으로 ECDSA 서명을 직접 검증
// Node.js crypto.verify는 내부적으로 추가 해싱을 수행하므로,
// 이미 해싱된 데이터(PrehashedDataToSign)로 서명한 결과는 elliptic으로 직접 검증해야 함
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

// 노드 간 메시지 라우팅 헬퍼
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

// 프로토콜 라운드 구동 헬퍼
function runProtocolRounds(
  nodes: { executor: CggmpExecutor; index: number }[],
  initialOutgoings: { [nodeIndex: number]: Buffer[] },
  maxRounds = 30
): void {
  let outgoings = initialOutgoings;
  let rounds = 0;

  while (rounds < maxRounds) {
    const incomings = routeMessages(nodes, outgoings);
    const hasIncoming = Object.values(incomings).some(arr => arr.length > 0);
    if (!hasIncoming) break;

    outgoings = {};
    for (const n of nodes) {
      outgoings[n.index] = n.executor.step(incomings[n.index]);
    }
    rounds++;

    // 모든 노드가 완료 상태에 도달했는지 확인
    const allFinished = nodes.every(n => {
      const s = JSON.parse(n.executor.snapshot()).status;
      return s.endsWith('_finished') || s === 'keyshare_ready';
    });
    if (allFinished) break;
  }
}

// 사전 생성된 3개 노드용 소수 Fixture (AuxGen 2048비트 RSA 안전 소수 연산 4~6분 소요를 0초로 단축)
const PRECOMPUTED_PRIMES: Buffer[] = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'primes.json'), 'utf-8')
).map((b64: string) => Buffer.from(b64, 'base64'));

describe('2-of-3 Threshold Signing E2E Integration Test', () => {
  const SESSION_ID = 'test-session-2of3';
  const THRESHOLD = 2;
  const PARTIES_COUNT = 3;
  const timeoutMs = 60000;
  jest.setTimeout(timeoutMs);

  let keyShares: { [partyIndex: number]: Buffer } = {};
  let sharedPublicKeyHex = '';

  beforeAll(() => {
    // 2. AuxGen 수행 (노드 0, 1, 2 - 사전 계산된 safe primes fixture 주입)
    const auxExecutors = [0, 1, 2].map(
      idx => new CggmpExecutor(SESSION_ID, 'exec-aux-1', idx, THRESHOLD, PARTIES_COUNT)
    );

    const auxNodes = auxExecutors.map((executor, index) => ({ executor, index }));
    const initialAuxOutgoings: { [index: number]: Buffer[] } = {};

    for (const node of auxNodes) {
      // 각 노드마다 고유한 사전 계산 소수 쌍을 주입하여 즉시 실행
      const nodePrimes = PRECOMPUTED_PRIMES[node.index];
      node.executor.startAuxGenWithPrimes(nodePrimes);
      initialAuxOutgoings[node.index] = node.executor.step([]);
    }

    runProtocolRounds(auxNodes, initialAuxOutgoings);

    const auxInfos: { [partyIndex: number]: Buffer } = {};
    for (const node of auxNodes) {
      const snap = JSON.parse(node.executor.snapshot());
      expect(snap.status).toBe('aux_gen_finished');
      auxInfos[node.index] = node.executor.exportAuxInfo();
    }

    // 3. DKG (Keygen) 수행 (노드 0, 1, 2)
    const dkgExecutors = [0, 1, 2].map(
      idx => new CggmpExecutor(SESSION_ID, 'exec-dkg-1', idx, THRESHOLD, PARTIES_COUNT)
    );
    const dkgNodes = dkgExecutors.map((executor, index) => ({ executor, index }));
    const initialDkgOutgoings: { [index: number]: Buffer[] } = {};

    for (const node of dkgNodes) {
      // DKG 전에 AuxInfo 주입
      node.executor.importAuxInfo(auxInfos[node.index]);
      node.executor.startKeygen();
      initialDkgOutgoings[node.index] = node.executor.step([]);
    }

    runProtocolRounds(dkgNodes, initialDkgOutgoings);

    for (const node of dkgNodes) {
      const snap = JSON.parse(node.executor.snapshot());
      expect(snap.status).toBe('keyshare_ready');
      expect(snap.publicKey).toBeDefined();
      keyShares[node.index] = node.executor.exportKeyshare();
      sharedPublicKeyHex = snap.publicKey;
    }

    expect(sharedPublicKeyHex).toBeTruthy();
  }, timeoutMs);

  const signerCombinations: [number, number][] = [
    [0, 1],
    [0, 2],
    [1, 2],
  ];

  test.each(signerCombinations)(
    '서명자 서브그룹 [%i, %i] 조합으로 32바이트 해시 서명 생성 및 검증 성공',
    (partyA: number, partyB: number) => {
      const actualSigners: [number, number] = [partyA, partyB];
      const signersJson = JSON.stringify(actualSigners);
      const executionId = `exec-signing-${partyA}-${partyB}`;

      // 32바이트 테스트 해시 생성 (Keccak256 / SHA256)
      const txHash = crypto.createHash('sha256').update(`test-message-${partyA}-${partyB}`).digest('hex');

      const signingExecutors = actualSigners.map(
        partyIdx => new CggmpExecutor(SESSION_ID, executionId, partyIdx, THRESHOLD, PARTIES_COUNT)
      );
      const signingNodes = signingExecutors.map((executor, idx) => ({
        executor,
        index: actualSigners[idx],
      }));

      const initialSigningOutgoings: { [index: number]: Buffer[] } = {};

      for (const node of signingNodes) {
        node.executor.importKeyshare(keyShares[node.index]);
        node.executor.setSigners(signersJson);
        node.executor.startSigning(txHash);
        initialSigningOutgoings[node.index] = node.executor.step([]);
      }

      runProtocolRounds(signingNodes, initialSigningOutgoings);

      for (const node of signingNodes) {
        const snap = JSON.parse(node.executor.snapshot());
        expect(snap.status).toBe('signing_finished');
        expect(snap.signature).toBeDefined();

        const sigObj = JSON.parse(snap.signature);
        expect(sigObj.r).toBeDefined();
        expect(sigObj.s).toBeDefined();

        const rHex = typeof sigObj.r === 'string' ? sigObj.r : sigObj.r.scalar;
        const sHex = typeof sigObj.s === 'string' ? sigObj.s : sigObj.s.scalar;

        // DKG로 생성된 sharedPublicKey에 대해 (r, s) 서명 유효성 검증
        const isValid = verifySignature(sharedPublicKeyHex, txHash, rHex, sHex);
        expect(isValid).toBe(true);
      }
    },
    timeoutMs
  );
});
