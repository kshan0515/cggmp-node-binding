// Redirect to native mock when under Jest; otherwise load native binding.
// Use CommonJS require to match napi output.
// eslint-disable-next-line @typescript-eslint/no-var-requires
declare const require: any;
declare const process: any;
const isJest = !!process?.env?.JEST_WORKER_ID;

// eslint-disable-next-line @typescript-eslint/no-var-requires
const native = isJest ? require('cggmp-native') : require('../index.js');

export const {
  CggmpExecutor,
  process_session,
  aux_info_gen,
  keygen,
  signing,
} = native as typeof import('../index.d.ts');

export default native;
