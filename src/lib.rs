#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use napi::{
  bindgen_prelude::{AsyncTask, Buffer, External},
  Env, Error, Result, Status, Task,
};
use prost::Message as _;
use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use round_based::{Incoming, MessageDestination, MessageType};
use round_based::state_machine::{ProceedResult, StateMachine};
use serde::{Deserialize, Serialize};
use base64::Engine as _;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

use cggmp24::key_share::{AnyKeyShare, AuxInfo, KeyShare};
use cggmp24::supported_curves::Secp256k1;
use cggmp24::signing::{SigningError, PrehashedDataToSign, AnyDataToSign};
use cggmp24::{ExecutionId, Signature};
use cggmp24_keygen::key_share::CoreKeyShare;
use cggmp24_keygen::msg::threshold as keygen_msg;
use cggmp24_keygen::KeygenBuilder;

mod proto {
  include!(concat!(env!("OUT_DIR"), "/cggmp.v1.rs"));
}

use proto::{envelope::Payload, Envelope, Round};
use sha2::{Digest as DigestTrait, Sha256};

const PAYLOAD_FORMAT_BINCODE: &str = "bincode";

type Curve = Secp256k1;
type AlgoDigest = Sha256;
type SecLevel = cggmp24::security_level::SecurityLevel128;

type KeygenMsg = keygen_msg::Msg<Curve, SecLevel, AlgoDigest>;
type SigningMsg = cggmp24::signing::msg::Msg<Secp256k1, sha2::Sha256>;
type AuxGenMsg = cggmp24::key_refresh::msg::Msg<AlgoDigest, SecLevel>;
type AuxInfoMsg = AuxInfo<SecLevel>;
type KeyShareWithLevel = KeyShare<Curve, SecLevel>;

pub type KeyShareHandle = Arc<Mutex<KeyShareWithLevel>>;
pub type AuxInfoHandle = Arc<Mutex<AuxInfoMsg>>;

struct UnsafeRng(StdRng);
impl UnsafeRng {
  fn new() -> Self { Self(StdRng::from_entropy()) }
}
impl RngCore for UnsafeRng {
  fn next_u32(&mut self) -> u32 { self.0.next_u32() }
  fn next_u64(&mut self) -> u64 { self.0.next_u64() }
  fn fill_bytes(&mut self, dest: &mut [u8]) { self.0.fill_bytes(dest) }
  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> { self.0.try_fill_bytes(dest) }
}
impl CryptoRng for UnsafeRng {}

enum ProtocolState {
  None,
  Keygen {
    sm: Box<dyn StateMachine<Output = std::result::Result<CoreKeyShare<Secp256k1>, cggmp24::KeygenError>, Msg = KeygenMsg> + 'static>,
    pending: Vec<Incoming<KeygenMsg>>,
  },
  AuxGen {
    sm: Box<dyn StateMachine<Output = std::result::Result<AuxInfoMsg, cggmp24::KeyRefreshError>, Msg = AuxGenMsg> + 'static>,
    pending: Vec<Incoming<AuxGenMsg>>,
  },
  Signing {
    sm: Box<dyn StateMachine<Output = std::result::Result<Signature<Secp256k1>, SigningError>, Msg = SigningMsg> + 'static>,
    pending: Vec<Incoming<SigningMsg>>,
    tx_context: Vec<u8>,
    _keyshare: Box<KeyShareWithLevel>,
    _signers: Vec<u16>,
    _data: Box<dyn AnyDataToSign<Secp256k1> + Send + Sync>,
  },
}

// Safety: `ProtocolState` contains round-based's `StateMachineImpl` which internally uses `Rc<RefCell>`.
// However, the state machine is always exclusively accessed behind a Mutex during step/step_async execution,
// and no references to the internal `Rc` leak outside the state machine. Therefore, moving `ProtocolState`
// across threads is safe.
unsafe impl Send for ProtocolState {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AbortBlame {
  pub blame_party: u16,
  pub reason: String,
}

impl AbortBlame {
  pub fn new(blame_party: u16, reason: impl Into<String>) -> Self {
    Self {
      blame_party,
      reason: reason.into(),
    }
  }

  pub fn to_error(&self) -> Error {
    let json = serde_json::to_string(self).unwrap_or_else(|_| {
      format!("{{\"blameParty\":{},\"reason\":\"{}\"}}", self.blame_party, self.reason)
    });
    Error::new(Status::GenericFailure, json)
  }
}

#[napi(object)]
pub struct AbortBlameResponse {
  pub blame_party: u32,
  pub reason: String,
}

#[napi]
pub fn parse_abort_blame_error(err_message: String) -> Option<AbortBlameResponse> {
  if let Ok(blame) = serde_json::from_str::<AbortBlame>(&err_message) {
    return Some(AbortBlameResponse {
      blame_party: blame.blame_party as u32,
      reason: blame.reason,
    });
  }
  parse_abort_blame(&err_message, None).map(|b| AbortBlameResponse {
    blame_party: b.blame_party as u32,
    reason: b.reason,
  })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutorSnapshot {
  session_id: String,
  execution_id: String,
  party_index: u16,
  threshold: u16,
  parties_count: u16,
  phase: String,
  round: u32,
  processed: usize,
  status: String,
  errors: Vec<String>,
  last_round: Option<String>,
  internal_round: String,
  curve: String,
  has_aux: bool,
  has_keyshare: bool,
  public_key: Option<String>,
  key_share_threshold: Option<u16>,
  signature: Option<String>,
}

#[napi]
pub fn generate_primes() -> Result<Buffer> {
  let mut rng = StdRng::from_entropy();
  let primes: cggmp24::PregeneratedPrimes<SecLevel> = cggmp24::PregeneratedPrimes::generate(&mut rng);
  let buf = bincode::serialize(&primes).map_err(|e| Error::new(Status::GenericFailure, format!("serialize: {e}")))?;
  Ok(Buffer::from(buf))
}

struct CggmpExecutorInner {
  session_id: String,
  execution_id: String,
  party_index: u16,
  threshold: u16,
  parties_count: u16,
  signers_at_keygen: Option<Vec<u16>>,
  rng: Box<UnsafeRng>,
  state: ProtocolState,
  core_keyshare: Option<CoreKeyShare<Secp256k1>>,
  aux_info: Option<AuxInfoMsg>,
  keyshare: Option<KeyShareWithLevel>,
  processed: usize,
  phase: String,
  round: u32,
  errors: Vec<String>,
  last_round: Option<Round>,
  internal_round: String,
  status: String,
  last_signature: Option<String>,
  meta_sent: bool,
  is_destroyed: bool,
}

impl Drop for CggmpExecutorInner {
  fn drop(&mut self) {
    if !self.is_destroyed {
      self.destroy_internal();
    }
  }
}

impl CggmpExecutorInner {
  fn new(session_id: String, execution_id: String, party_index: u16, threshold: u16, parties_count: u16) -> Self {
    Self {
      session_id, execution_id, party_index, threshold, parties_count,
      signers_at_keygen: None, rng: Box::new(UnsafeRng::new()), state: ProtocolState::None,
      core_keyshare: None, aux_info: None, keyshare: None, processed: 0,
      phase: "INIT".to_string(), round: 0, errors: Vec::new(), last_round: None,
      internal_round: "Init".to_string(),
      status: "init".to_string(), last_signature: None,
      meta_sent: false,
      is_destroyed: false,
    }
  }

  fn destroy_internal(&mut self) {
    self.is_destroyed = true;
    self.status = "destroyed".to_string();

    // 1. Explicitly zeroize local keyshares, secret shares, and Paillier primes
    if let Some(ks) = self.keyshare.take() {
      let mut dirty = ks.into_inner();
      dirty.aux.p = paillier_zk::backend::Integer::zero();
      dirty.aux.q = paillier_zk::backend::Integer::zero();
      drop(dirty.core.x); // NonZero<SecretScalar> drops and zeroizes
    }

    if let Some(core) = self.core_keyshare.take() {
      let dirty = core.into_inner();
      drop(dirty.x); // NonZero<SecretScalar> drops and zeroizes
    }

    if let Some(aux) = self.aux_info.take() {
      let mut dirty = aux.into_inner();
      dirty.p = paillier_zk::backend::Integer::zero();
      dirty.q = paillier_zk::backend::Integer::zero();
    }

    // 2. Explicitly zeroize protocol state and round masking temps
    match std::mem::replace(&mut self.state, ProtocolState::None) {
      ProtocolState::Signing { mut tx_context, mut pending, _keyshare, .. } => {
        tx_context.zeroize();
        pending.clear();
        let mut dirty = _keyshare.into_inner();
        dirty.aux.p = paillier_zk::backend::Integer::zero();
        dirty.aux.q = paillier_zk::backend::Integer::zero();
        drop(dirty.core.x);
      }
      ProtocolState::Keygen { mut pending, .. } => {
        pending.clear();
      }
      ProtocolState::AuxGen { mut pending, .. } => {
        pending.clear();
      }
      ProtocolState::None => {}
    }

    // 3. Zeroize sensitive session strings and last signature
    self.session_id.zeroize();
    self.execution_id.zeroize();
    if let Some(mut sig) = self.last_signature.take() {
      sig.zeroize();
    }
    for err in &mut self.errors {
      err.zeroize();
    }
    self.errors.clear();
  }

  fn try_combine_shares(&mut self) {
    if let (Some(core), Some(aux)) = (&self.core_keyshare, &self.aux_info) {
      if let Ok(ks) = KeyShare::from_parts((core.clone(), aux.clone())) {
        self.keyshare = Some(ks);
        self.status = "keyshare_ready".to_string();
      }
    }
  }

  fn export_keyshare(&self) -> Result<Buffer> {
    let ks = self.keyshare.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "keyshare not ready"))?;
    let buf = serde_json::to_vec(ks).map_err(|e| Error::new(Status::GenericFailure, format!("export: {e}")))?;
    Ok(Buffer::from(buf))
  }

  fn export_aux_info(&self) -> Result<Buffer> {
    let aux = self.aux_info.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "aux info not ready"))?;
    let buf = serde_json::to_vec(aux).map_err(|e| Error::new(Status::GenericFailure, format!("export: {e}")))?;
    Ok(Buffer::from(buf))
  }

  fn export_keyshare_bin(&self) -> Result<Buffer> {
    self.export_keyshare()
  }

  fn export_aux_info_bin(&self) -> Result<Buffer> {
    self.export_aux_info()
  }

  fn import_keyshare(&mut self, data: &[u8]) -> Result<()> {
    let ks: KeyShareWithLevel = if !data.is_empty() && data[0] == b'{' {
      serde_json::from_slice(data).map_err(|e| Error::new(Status::InvalidArg, format!("parse json: {e}")))?
    } else {
      match serde_json::from_slice(data) {
        Ok(k) => k,
        Err(_) => {
          let decoded = base64::engine::general_purpose::STANDARD.decode(data)
            .map_err(|e| Error::new(Status::InvalidArg, format!("not json and not base64: {e}")))?;
          serde_json::from_slice(&decoded)
            .map_err(|e| Error::new(Status::InvalidArg, format!("parse legacy base64-json: {e}")))?
        }
      }
    };
    self.keyshare = Some(ks);
    self.status = "keyshare_ready".to_string();
    Ok(())
  }

  fn import_aux_info(&mut self, data: &[u8]) -> Result<()> {
    let aux: AuxInfoMsg = if !data.is_empty() && data[0] == b'{' {
      serde_json::from_slice(data).map_err(|e| Error::new(Status::InvalidArg, format!("parse json: {e}")))?
    } else {
      match serde_json::from_slice(data) {
        Ok(a) => a,
        Err(_) => {
          let decoded = base64::engine::general_purpose::STANDARD.decode(data)
            .map_err(|e| Error::new(Status::InvalidArg, format!("not json and not base64: {e}")))?;
          serde_json::from_slice(&decoded)
            .map_err(|e| Error::new(Status::InvalidArg, format!("parse legacy base64-json: {e}")))?
        }
      }
    };
    self.aux_info = Some(aux);
    self.try_combine_shares();
    Ok(())
  }

  fn start_keygen(&mut self) -> Result<()> {
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "keygen"));
    let builder = KeygenBuilder::<Secp256k1>::new(eid, self.party_index, self.parties_count).set_threshold(self.threshold).enforce_reliable_broadcast(false);
    self.state = ProtocolState::Keygen { sm: Box::new(builder.into_state_machine(extend_mut(&mut self.rng))), pending: Vec::new() };
    self.phase = "KEYGEN".to_string(); self.status = "running".to_string(); self.round = Round::Keygen as u32; self.last_round = Some(Round::Keygen);
    self.internal_round = "Round 1 (Commitment)".to_string();
    Ok(())
  }

  fn start_aux_gen(&mut self) -> Result<()> {
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "aux_gen"));
    let rng = extend_mut(&mut self.rng);
    let primes: cggmp24::PregeneratedPrimes<SecLevel> = cggmp24::PregeneratedPrimes::generate(rng);
    let builder = cggmp24::aux_info_gen(eid, self.party_index, self.parties_count, primes).enforce_reliable_broadcast(false);
    self.state = ProtocolState::AuxGen { sm: Box::new(builder.into_state_machine(rng)), pending: Vec::new() };
    self.phase = "AUX_GEN".to_string(); self.status = "running".to_string(); self.round = Round::AuxInfo as u32; self.last_round = Some(Round::AuxInfo);
    self.internal_round = "Round 1 (Paillier Gen)".to_string();
    Ok(())
  }

  fn start_aux_gen_with_primes(&mut self, primes_buf: &[u8]) -> Result<()> {
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "aux_gen"));
    let primes: cggmp24::PregeneratedPrimes<SecLevel> = bincode::deserialize(primes_buf).map_err(|e| Error::new(Status::InvalidArg, format!("invalid primes: {e}")))?;
    let rng = extend_mut(&mut self.rng);
    let builder = cggmp24::aux_info_gen(eid, self.party_index, self.parties_count, primes).enforce_reliable_broadcast(false);
    self.state = ProtocolState::AuxGen { sm: Box::new(builder.into_state_machine(rng)), pending: Vec::new() };
    self.phase = "AUX_GEN".to_string(); self.status = "running".to_string(); self.round = Round::AuxInfo as u32; self.last_round = Some(Round::AuxInfo);
    self.internal_round = "Round 1 (Paillier Gen)".to_string();
    Ok(())
  }

  fn set_signers(&mut self, json: String) -> Result<()> {
    let parsed: Vec<u16> = serde_json::from_str(&json).map_err(|e| Error::new(Status::InvalidArg, format!("invalid json: {e}")))?;
    self.signers_at_keygen = Some(parsed);
    Ok(())
  }

  fn start_signing(&mut self, tx_hex: String) -> Result<()> {
    let ks = self.keyshare.clone().ok_or_else(|| Error::new(Status::InvalidArg, "keyshare missing"))?;
    let tx = hex::decode(tx_hex).map_err(|e| Error::new(Status::InvalidArg, format!("invalid hex: {e}")))?;
    let data: Box<dyn AnyDataToSign<Secp256k1> + Send + Sync> = if tx.len() == 32 {
      let scalar = generic_ec::Scalar::<Secp256k1>::from_be_bytes_mod_order(&tx);
      Box::new(PrehashedDataToSign::from_scalar(scalar).insecure_assume_preimage_known())
    } else {
      Box::new(cggmp24::DataToSign::<Secp256k1>::digest::<sha2::Sha256>(&tx))
    };
    let min = ks.min_signers();
    let selected = self.signers_at_keygen.clone().unwrap_or_else(|| (0..min).collect());
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "signing"));
    let ks_boxed = Box::new(ks);
    let my_idx = selected.iter().position(|&p| p == self.party_index).ok_or_else(|| Error::new(Status::InvalidArg, "not in signers"))? as u16;
    let sm = cggmp24::signing(eid, my_idx, extend_ref(selected.as_slice()), extend_ref(&*ks_boxed))
      .enforce_reliable_broadcast(false)
      .sign_sync(extend_mut(&mut self.rng), extend_ref(&*data));
    self.state = ProtocolState::Signing { sm: Box::new(sm), pending: Vec::new(), tx_context: tx, _keyshare: ks_boxed, _signers: selected, _data: data };
    self.phase = "SIGNING".to_string(); self.status = "running".to_string(); self.round = Round::Signing as u32; self.last_round = Some(Round::Signing);
    self.internal_round = "Round 1 (Partial Sign)".to_string();
    Ok(())
  }

  fn step_internal(&mut self, raw_inputs: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    self.processed += raw_inputs.len();

    // 1. Rayon parallel deserialization
    let my_party_index = self.party_index;
    match &mut self.state {
      ProtocolState::Keygen { pending, .. } => {
        let decoded_msgs: Vec<Incoming<KeygenMsg>> = raw_inputs.par_iter().filter_map(|buf| {
          if let Ok(env) = Envelope::decode(buf.as_slice()) {
            if let Some(Payload::Keygen(k)) = env.payload {
              let is_broadcast = env.to_parties.is_empty();
              if !is_broadcast && !env.to_parties.contains(&(my_party_index as u32)) {
                return None;
              }
              let msg_type = if is_broadcast { MessageType::Broadcast } else { MessageType::P2P };
              let msg: KeygenMsg = bincode::deserialize(&k.payload).ok()?;
              return Some(Incoming { id: 0, sender: env.from_party as u16, msg_type, msg });
            }
          }
          if buf.len() < 5 { return None; }
          let from_party = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as u16;
          let is_broadcast = buf[4] != 0;
          let msg_type = if is_broadcast { MessageType::Broadcast } else { MessageType::P2P };
          let msg: KeygenMsg = bincode::deserialize(&buf[5..]).ok()?;
          Some(Incoming { id: 0, sender: from_party, msg_type, msg })
        }).collect();
        pending.extend(decoded_msgs);
      }
      ProtocolState::AuxGen { pending, .. } => {
        let decoded_msgs: Vec<Incoming<AuxGenMsg>> = raw_inputs.par_iter().filter_map(|buf| {
          if let Ok(env) = Envelope::decode(buf.as_slice()) {
            if let Some(Payload::AuxInfo(a)) = env.payload {
              let is_broadcast = env.to_parties.is_empty();
              if !is_broadcast && !env.to_parties.contains(&(my_party_index as u32)) {
                return None;
              }
              let msg_type = if is_broadcast { MessageType::Broadcast } else { MessageType::P2P };
              let msg: AuxGenMsg = bincode::deserialize(&a.payload).ok()?;
              return Some(Incoming { id: 0, sender: env.from_party as u16, msg_type, msg });
            }
          }
          if buf.len() < 5 { return None; }
          let from_party = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as u16;
          let is_broadcast = buf[4] != 0;
          let msg_type = if is_broadcast { MessageType::Broadcast } else { MessageType::P2P };
          let msg: AuxGenMsg = bincode::deserialize(&buf[5..]).ok()?;
          Some(Incoming { id: 0, sender: from_party, msg_type, msg })
        }).collect();
        pending.extend(decoded_msgs);
      }
      ProtocolState::Signing { pending, _signers, .. } => {
        let decoded_msgs: Vec<Incoming<SigningMsg>> = raw_inputs.par_iter().filter_map(|buf| {
          if let Ok(env) = Envelope::decode(buf.as_slice()) {
            if let Some(Payload::Signing(s)) = env.payload {
              let is_broadcast = env.to_parties.is_empty();
              if !is_broadcast && !env.to_parties.contains(&(my_party_index as u32)) {
                return None;
              }
              let msg_type = if is_broadcast { MessageType::Broadcast } else { MessageType::P2P };
              let msg: SigningMsg = bincode::deserialize(&s.payload).ok()?;
              let sender = _signers.iter().position(|&s| s == (env.from_party as u16))? as u16;
              return Some(Incoming { id: 0, sender, msg_type, msg });
            }
          }
          if buf.len() < 5 { return None; }
          let from_party_global = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as u16;
          let is_broadcast = buf[4] != 0;
          let msg_type = if is_broadcast { MessageType::Broadcast } else { MessageType::P2P };
          let msg: SigningMsg = bincode::deserialize(&buf[5..]).ok()?;
          let sender = _signers.iter().position(|&s| s == from_party_global)? as u16;
          Some(Incoming { id: 0, sender, msg_type, msg })
        }).collect();
        pending.extend(decoded_msgs);
      }
      ProtocolState::None => {
        return Ok(Vec::new());
      }
    }

    // 2. Drive state machine
    let mut outgoing = Vec::new();
    match &mut self.state {
      ProtocolState::Keygen { sm, pending, .. } => {
        let out = drive_sm(sm.as_mut(), pending, Round::Keygen as i32, &self.session_id, &self.execution_id, self.party_index, self.threshold, self.parties_count, None, &mut outgoing, &[], &mut self.meta_sent, &mut self.internal_round, |msg| {
            match msg {
                keygen_msg::Msg::Round1(_) => "Round 1 (Commitment)".to_string(),
                keygen_msg::Msg::Round2Broad(_) | keygen_msg::Msg::Round2Uni(_) => "Round 2 (VSS & Share)".to_string(),
                keygen_msg::Msg::Round3(_) => "Round 3 (Verify & Proofs)".to_string(),
                _ => "Reliability Check".to_string(),
            }
        })?;
        if let Some(res) = out {
          self.core_keyshare = Some(res.map_err(|e| {
            let debug_s = format!("{e:?}");
            if let Some(blame) = parse_abort_blame(&debug_s, None) {
              blame.to_error()
            } else {
              Error::new(Status::GenericFailure, format!("{e:?}"))
            }
          })?);
          self.status = "keygen_finished".to_string(); self.state = ProtocolState::None; self.try_combine_shares();
          self.internal_round = "Finished".to_string();
        }
      }
      ProtocolState::AuxGen { sm, pending, .. } => {
        let out = drive_sm(sm.as_mut(), pending, Round::AuxInfo as i32, &self.session_id, &self.execution_id, self.party_index, self.threshold, self.parties_count, None, &mut outgoing, &[], &mut self.meta_sent, &mut self.internal_round, |msg| {
            match msg {
                cggmp24::key_refresh::msg::Msg::Round1(_) => "Round 1 (Paillier Gen)".to_string(),
                cggmp24::key_refresh::msg::Msg::Round2(_) => "Round 2 (ZKP Verify)".to_string(),
                cggmp24::key_refresh::msg::Msg::Round3(_) => "Round 3 (Finalize)".to_string(),
                _ => "Reliability Check".to_string(),
            }
        })?;
        if let Some(res) = out {
          self.aux_info = Some(res.map_err(|e| {
            let debug_s = format!("{e:?}");
            if let Some(blame) = parse_abort_blame(&debug_s, None) {
              blame.to_error()
            } else {
              Error::new(Status::GenericFailure, format!("{e:?}"))
            }
          })?);
          self.status = "aux_gen_finished".to_string(); self.state = ProtocolState::None; self.try_combine_shares();
          self.internal_round = "Finished".to_string();
        }
      }
      ProtocolState::Signing { sm, pending, tx_context, _signers, .. } => {
        let out = drive_sm(sm.as_mut(), pending, Round::Signing as i32, &self.session_id, &self.execution_id, self.party_index, self.threshold, self.parties_count, Some(_signers.as_slice()), &mut outgoing, tx_context, &mut self.meta_sent, &mut self.internal_round, |msg| {
            match msg {
                cggmp24::signing::msg::Msg::Round1a(_) | cggmp24::signing::msg::Msg::Round1b(_) => "Round 1 (Partial Sign)".to_string(),
                cggmp24::signing::msg::Msg::Round2(_) => "Round 2 (Verify)".to_string(),
                cggmp24::signing::msg::Msg::Round3(_) => "Round 3 (Combine)".to_string(),
                cggmp24::signing::msg::Msg::Round4(_) => "Round 4 (Finalize)".to_string(),
                _ => "Reliability Check".to_string(),
            }
        })?;
        if let Some(res) = out {
          let sig = res.map_err(|e| {
            let debug_s = format!("{e:?}");
            if let Some(blame) = parse_abort_blame(&debug_s, Some(_signers.as_slice())) {
              blame.to_error()
            } else {
              Error::new(Status::GenericFailure, format!("{e:?}"))
            }
          })?;
          outgoing.push(make_envelope(&self.session_id, &self.execution_id, Round::Signing as i32, self.party_index, self.threshold, self.parties_count, &[], encode_msg(&sig)?, tx_context, self.meta_sent));
          self.meta_sent = true;
          self.status = "signing_finished".to_string(); self.state = ProtocolState::None;
          self.last_signature = Some(serde_json::to_string(&sig).unwrap());
        }
      }
      ProtocolState::None => {}
    }

    if !self.status.ends_with("_finished") && self.status != "keyshare_ready" {
      self.status = match &self.state {
        ProtocolState::None => "idle".to_string(),
        ProtocolState::Keygen { .. } => "keygen_running".to_string(),
        ProtocolState::AuxGen { .. } => "aux_gen_running".to_string(),
        ProtocolState::Signing { .. } => "signing_running".to_string(),
      };
    }
    encode_envelopes_raw(&outgoing)
  }

  fn snapshot(&self) -> Result<String> {
    let (public_key, key_share_threshold) = if let Some(ks) = &self.keyshare {
      (Some(hex::encode(ks.core.shared_public_key.to_bytes(true))), Some(ks.min_signers()))
    } else if let Some(core) = &self.core_keyshare {
      (Some(hex::encode(core.shared_public_key.to_bytes(true))), None)
    } else { (None, None) };
    let snap = ExecutorSnapshot {
      session_id: self.session_id.clone(), execution_id: self.execution_id.clone(), party_index: self.party_index, threshold: self.threshold, parties_count: self.parties_count, phase: self.phase.clone(), round: self.round, processed: self.processed, status: self.status.clone(), errors: self.errors.clone(), last_round: self.last_round.map(|r| format!("{:?}", r)),
      internal_round: self.internal_round.clone(),
      curve: "secp256k1".to_string(), has_aux: self.aux_info.is_some(), has_keyshare: self.keyshare.is_some(), public_key, key_share_threshold, signature: self.last_signature.clone(),
    };
    serde_json::to_string(&snap).map_err(|e| Error::new(Status::GenericFailure, format!("{e}")))
  }
}

pub struct StepTask {
  inner: Arc<Mutex<CggmpExecutorInner>>,
  inputs: Vec<Vec<u8>>,
}

impl Task for StepTask {
  type Output = Vec<Vec<u8>>;
  type JsValue = Vec<Buffer>;

  fn compute(&mut self) -> Result<Self::Output> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.step_internal(std::mem::take(&mut self.inputs))
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into_iter().map(Buffer::from).collect())
  }
}

#[napi]
pub struct CggmpExecutor {
  inner: Arc<Mutex<CggmpExecutorInner>>,
}

impl Drop for CggmpExecutor {
  fn drop(&mut self) {
    if let Ok(mut inner) = self.inner.lock() {
      if !inner.is_destroyed {
        inner.destroy_internal();
      }
    }
  }
}

#[napi]
impl CggmpExecutor {
  #[napi(constructor)]
  pub fn new(session_id: String, execution_id: String, party_index: u16, threshold: u16, parties_count: u16) -> Result<Self> {
    if session_id.is_empty() || execution_id.is_empty() {
      return Err(Error::new(Status::InvalidArg, "session_id and execution_id are required"));
    }
    let inner = CggmpExecutorInner::new(session_id, execution_id, party_index, threshold, parties_count);
    Ok(Self {
      inner: Arc::new(Mutex::new(inner)),
    })
  }

  #[napi]
  pub fn is_destroyed(&self) -> Result<bool> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    Ok(inner.is_destroyed)
  }

  #[napi(js_name = "is_destroyed")]
  pub fn is_destroyed_alias(&self) -> Result<bool> {
    self.is_destroyed()
  }

  #[napi]
  pub fn destroy(&self) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if !inner.is_destroyed {
      inner.destroy_internal();
    }
    Ok(())
  }

  #[napi]
  pub fn export_keyshare(&self) -> Result<Buffer> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.export_keyshare()
  }

  #[napi]
  pub fn export_aux_info(&self) -> Result<Buffer> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.export_aux_info()
  }

  #[napi]
  pub fn import_keyshare(&self, data: Buffer) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.import_keyshare(&data)
  }

  #[napi]
  pub fn import_aux_info(&self, data: Buffer) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.import_aux_info(&data)
  }

  #[napi]
  pub fn start_keygen(&self) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.start_keygen()
  }

  #[napi]
  pub fn start_aux_gen(&self) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.start_aux_gen()
  }

  #[napi]
  pub fn start_aux_gen_with_primes(&self, primes_buf: Buffer) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.start_aux_gen_with_primes(&primes_buf)
  }

  #[napi]
  pub fn set_signers(&self, json: String) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.set_signers(json)
  }

  #[napi]
  pub fn start_signing(&self, tx_hex: String) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.start_signing(tx_hex)
  }

  #[napi]
  pub fn step(&self, inputs: Vec<Buffer>) -> Result<Vec<Buffer>> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    let raw_inputs: Vec<Vec<u8>> = inputs.iter().map(|b| b.to_vec()).collect();
    let raw_outputs = inner.step_internal(raw_inputs)?;
    Ok(raw_outputs.into_iter().map(Buffer::from).collect())
  }

  #[napi]
  pub fn step_async(&self, inputs: Vec<Buffer>) -> Result<AsyncTask<StepTask>> {
    let raw_inputs: Vec<Vec<u8>> = inputs.iter().map(|b| b.to_vec()).collect();
    Ok(AsyncTask::new(StepTask {
      inner: self.inner.clone(),
      inputs: raw_inputs,
    }))
  }

  #[napi(js_name = "step_async")]
  pub fn step_async_alias(&self, inputs: Vec<Buffer>) -> Result<AsyncTask<StepTask>> {
    self.step_async(inputs)
  }

  #[napi]
  pub fn snapshot(&self) -> Result<String> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.snapshot()
  }

  #[napi]
  pub fn export_keyshare_bin(&self) -> Result<Buffer> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.export_keyshare_bin()
  }

  #[napi]
  pub fn export_aux_info_bin(&self) -> Result<Buffer> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    inner.export_aux_info_bin()
  }

  #[napi]
  pub fn export_keyshare_handle(&self) -> Result<External<KeyShareHandle>> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    let ks = inner.keyshare.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "keyshare not ready"))?;
    Ok(External::new(Arc::new(Mutex::new(ks.clone()))))
  }

  #[napi]
  pub fn import_keyshare_handle(&self, handle: External<KeyShareHandle>) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    let guard = handle.lock().map_err(|_| Error::from_reason("KeyShare handle mutex poisoned"))?;
    inner.keyshare = Some(guard.clone());
    inner.status = "keyshare_ready".to_string();
    Ok(())
  }

  #[napi]
  pub fn export_aux_info_handle(&self) -> Result<External<AuxInfoHandle>> {
    let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    let aux = inner.aux_info.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "aux info not ready"))?;
    Ok(External::new(Arc::new(Mutex::new(aux.clone()))))
  }

  #[napi]
  pub fn import_aux_info_handle(&self, handle: External<AuxInfoHandle>) -> Result<()> {
    let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
    if inner.is_destroyed {
      return Err(Error::from_reason("Executor has already been destroyed"));
    }
    let guard = handle.lock().map_err(|_| Error::from_reason("AuxInfo handle mutex poisoned"))?;
    inner.aux_info = Some(guard.clone());
    inner.try_combine_shares();
    Ok(())
  }
}

fn encode_envelopes_raw(envs: &[Envelope]) -> Result<Vec<Vec<u8>>> {
  envs.iter().map(|env| {
    let mut buf = Vec::new();
    env.encode(&mut buf).map_err(|e| Error::new(Status::GenericFailure, format!("encode: {e}")))?;
    Ok(buf)
  }).collect()
}

fn encode_msg<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
  bincode::serialize(msg).map_err(|e| Error::new(Status::GenericFailure, format!("encode: {e}")))
}

fn parse_abort_blame(err_str: &str, signers: Option<&[u16]>) -> Option<AbortBlame> {
  // 1. Look for `faulty_party: (\d+)` or `faulty_party: PartyIndex\((\d+)\)`
  if let Some(idx) = err_str.find("faulty_party") {
    let remainder = &err_str[idx + "faulty_party".len()..];
    let digits: String = remainder.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    if let Ok(party) = digits.parse::<u16>() {
      let global_party = signers.and_then(|s| s.get(party as usize).copied()).unwrap_or(party);
      return Some(AbortBlame::new(global_party, clean_abort_reason(err_str)));
    }
  }

  // 2. Look for `parties: [(\d+)` or `malicious parties: [(\d+)`
  if let Some(idx) = err_str.find("parties") {
    let remainder = &err_str[idx + "parties".len()..];
    let digits: String = remainder.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    if let Ok(party) = digits.parse::<u16>() {
      let global_party = signers.and_then(|s| s.get(party as usize).copied()).unwrap_or(party);
      return Some(AbortBlame::new(global_party, clean_abort_reason(err_str)));
    }
  }

  // 3. Look for `Round1NotReliable` or `Round1aNotReliable`
  if err_str.contains("Round1NotReliable") || err_str.contains("Round1aNotReliable") {
    let digits: String = err_str.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    if let Ok(party) = digits.parse::<u16>() {
      let global_party = signers.and_then(|s| s.get(party as usize).copied()).unwrap_or(party);
      return Some(AbortBlame::new(global_party, "Reliable broadcast verification failed".to_string()));
    }
  }

  None
}

fn clean_abort_reason(err_str: &str) -> String {
  if err_str.contains("InvalidDecommitment") {
    "Party decommitment doesn't match commitment".to_string()
  } else if err_str.contains("InvalidSchnorrProof") {
    "Party provided invalid Schnorr proof".to_string()
  } else if err_str.contains("FeldmanVerificationFailed") {
    "Feldman VSS verification failed: party secret share is inconsistent".to_string()
  } else if err_str.contains("EncProofOfK") {
    "Paillier encryption proof of K failed".to_string()
  } else if err_str.contains("InvalidPsiPrimePrime") {
    "Paillier operation proof (Psi'') is invalid".to_string()
  } else if err_str.contains("InvalidPsi") {
    "Paillier affine operation proof (Psi) is invalid".to_string()
  } else if err_str.contains("invalid_ring_pedersen_parameters") {
    "Invalid Ring-Pedersen parameters".to_string()
  } else if err_str.contains("invalid_mod_proof") {
    "Invalid modulo proof".to_string()
  } else if err_str.contains("invalid_fac_proof") {
    "Invalid factorization proof".to_string()
  } else if err_str.contains("Round1aNotReliable") || err_str.contains("Round1NotReliable") {
    "Round 1 broadcast message not reliable".to_string()
  } else {
    err_str.lines().next().unwrap_or(err_str).trim().to_string()
  }
}

fn drive_sm<M, O, F>(
  sm: &mut dyn StateMachine<Output = O, Msg = M>,
  pending: &mut Vec<Incoming<M>>,
  round: i32,
  sid: &str, eid: &str, from: u16, t: u16, n: u16,
  signers: Option<&[u16]>,
  outgoing: &mut Vec<Envelope>,
  tx: &[u8],
  meta_sent: &mut bool,
  internal_round: &mut String,
  get_round_name: F
) -> Result<Option<O>>
where
  M: Clone + Serialize + for<'de> Deserialize<'de>,
  F: Fn(&M) -> String,
{
  loop {
    match sm.proceed() {
      ProceedResult::SendMsg(out) => {
        let to = match out.recipient {
          MessageDestination::AllParties => Vec::new(),
          MessageDestination::OneParty(i) => {
            let global_party = if let Some(signers) = signers {
              signers.get(i as usize).copied().unwrap_or(i)
            } else {
              i
            };
            vec![global_party as u32]
          }
        };
        *internal_round = get_round_name(&out.msg);
        outgoing.push(make_envelope(sid, eid, round, from, t, n, &to, encode_msg(&out.msg)?, tx, *meta_sent));
        *meta_sent = true;
      }
      ProceedResult::NeedsOneMoreMessage => {
        if !pending.is_empty() {
          let msg = pending.remove(0); // FIFO
          let sender = msg.sender;
          let global_sender = signers.and_then(|s| s.get(sender as usize).copied()).unwrap_or(sender);
          if let Err(_e) = sm.received_msg(msg) {
            return Err(AbortBlame::new(
              global_sender,
              format!("rejected by state machine: invalid message from party {global_sender}")
            ).to_error());
          }
        } else {
          return Ok(None);
        }
      }
      ProceedResult::Yielded => continue,
      ProceedResult::Output(o) => return Ok(Some(o)),
      ProceedResult::Error(err) => {
        let err_debug = format!("{err:?}");
        if let Some(blame) = parse_abort_blame(&err_debug, signers) {
          return Err(blame.to_error());
        }
        let err_display = format!("{err}");
        if let Some(blame) = parse_abort_blame(&err_display, signers) {
          return Err(blame.to_error());
        }
        return Err(Error::new(Status::GenericFailure, err_display));
      }
    }
  }
}

fn make_envelope(sid: &str, eid: &str, round: i32, from: u16, t: u16, n: u16, to: &[u32], payload: Vec<u8>, tx: &[u8], meta_sent: bool) -> Envelope {
  let p_enum = if round == Round::Keygen as i32 { Some(Payload::Keygen(proto::Keygen { payload })) }
    else if round == Round::AuxInfo as i32 { Some(Payload::AuxInfo(proto::AuxInfo { payload })) }
    else if round == Round::Signing as i32 { Some(Payload::Signing(proto::Signing { payload, tx_context: tx.to_vec() })) }
    else { None };

  let curve = proto::Curve::Secp256k1 as i32;

  let meta = if meta_sent {
    None
  } else {
    Some(proto::Meta { curve, threshold: t as u32, parties_count: n as u32, party_index: from as u32, tx_context: tx.to_vec(), retry: 0, payload_format: PAYLOAD_FORMAT_BINCODE.to_string(), key_id: String::new() })
  };

  Envelope { version: 1, session_id: sid.to_string(), execution_id: eid.to_string(), round, from_party: from as u32, to_parties: to.to_vec(), meta, payload: p_enum }
}

fn derive_execution_seed(sid: &str, eid: &str, phase: &str) -> &'static [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(sid.as_bytes()); hasher.update(b":"); hasher.update(eid.as_bytes()); hasher.update(b":"); hasher.update(phase.as_bytes());
  let mut seed = [0u8; 32]; seed.copy_from_slice(&hasher.finalize()); Box::leak(Box::new(seed))
}

fn extend_mut<T>(v: &mut T) -> &'static mut T { unsafe { &mut *(v as *mut T) } }
fn extend_ref<T: ?Sized>(v: &T) -> &'static T { unsafe { &*(v as *const T) } }

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_abort_blame_parsing() {
    let debug_err = "Protocol aborted; malicious parties: [AbortBlame { faulty_party: 1, data_message: MsgId(1), proof_message: MsgId(2) }]; reason: InvalidDecommitment";
    let blame = parse_abort_blame(debug_err, None).expect("should parse blame");
    assert_eq!(blame.blame_party, 1);
    assert_eq!(blame.reason, "Party decommitment doesn't match commitment");

    let json_err = blame.to_error();
    assert!(json_err.to_string().contains("\"blameParty\":1"));

    let parsed = parse_abort_blame_error(blame.to_error().reason).expect("should parse json");
    assert_eq!(parsed.blame_party, 1);
  }

  #[test]
  fn test_abort_blame_with_signers_mapping() {
    let signers = [0, 2];
    let debug_err = "SigningAborted::EncProofOfK([(AbortBlame { faulty_party: 1, data_message: MsgId(1), proof_message: MsgId(2) }, InvalidProof)])";
    let blame = parse_abort_blame(debug_err, Some(&signers)).expect("should parse blame");
    // party 1 in signers [0, 2] is global party 2
    assert_eq!(blame.blame_party, 2);
  }

  #[test]
  fn test_destroy_and_zeroization() {
    let mut inner = CggmpExecutorInner::new(
      "session-destroy".to_string(),
      "exec-destroy".to_string(),
      0,
      2,
      3,
    );

    assert!(!inner.is_destroyed);
    inner.start_keygen().unwrap();
    assert_eq!(inner.phase, "KEYGEN");

    // Perform explicit destroy
    inner.destroy_internal();
    assert!(inner.is_destroyed);
    assert_eq!(inner.status, "destroyed");
    assert!(inner.session_id.is_empty());
    assert!(inner.execution_id.is_empty());

    // Calling snapshot should report destroyed status
    let snap_res = inner.snapshot();
    assert!(snap_res.is_ok());
    assert!(snap_res.unwrap().contains("\"status\":\"destroyed\""));
  }

  #[test]
  fn test_dkg_aux_signing_inner_protocol() {
    let primes_json = include_str!("../__tests__/fixtures/primes.json");
    let primes_b64: Vec<String> = serde_json::from_str(primes_json).unwrap();
    let primes_bytes: Vec<Vec<u8>> = primes_b64.iter().map(|b| {
      base64::engine::general_purpose::STANDARD.decode(b).unwrap()
    }).collect();

    let sid = "test-cargo-session";
    let t = 2;
    let n = 3;

    // 1. AuxGen for 3 parties
    let mut aux_inners: Vec<CggmpExecutorInner> = (0..3).map(|i| {
      CggmpExecutorInner::new(sid.to_string(), "aux-exec".to_string(), i, t, n)
    }).collect();

    let mut outgoings: std::collections::HashMap<u16, Vec<Vec<u8>>> = std::collections::HashMap::new();
    for (i, inner) in aux_inners.iter_mut().enumerate() {
      inner.start_aux_gen_with_primes(&primes_bytes[i]).unwrap();
      let out = inner.step_internal(vec![]).unwrap();
      outgoings.insert(i as u16, out);
    }

    // Run aux rounds
    for _ in 0..10 {
      let mut incomings: std::collections::HashMap<u16, Vec<Vec<u8>>> = std::collections::HashMap::new();
      for i in 0..3 { incomings.insert(i, Vec::new()); }
      for (from, msgs) in &outgoings {
        for msg in msgs {
          let env = Envelope::decode(msg.as_slice()).unwrap();
          let recipients: Vec<u16> = if env.to_parties.is_empty() {
            (0..3).filter(|&p| p != *from).collect()
          } else {
            env.to_parties.iter().map(|&p| p as u16).collect()
          };
          for r in recipients {
            incomings.get_mut(&r).unwrap().push(msg.clone());
          }
        }
      }
      outgoings.clear();
      for (i, inner) in aux_inners.iter_mut().enumerate() {
        let inc = incomings.remove(&(i as u16)).unwrap();
        let out = inner.step_internal(inc).unwrap();
        outgoings.insert(i as u16, out);
      }
      let all_finished = aux_inners.iter().all(|e| {
        let snap = e.snapshot().unwrap();
        snap.contains("\"aux_gen_finished\"")
      });
      if all_finished { break; }
    }

    // Export aux infos (JSON bytes)
    let aux_infos: Vec<Vec<u8>> = aux_inners.iter().map(|e| {
      let aux = e.aux_info.as_ref().unwrap();
      serde_json::to_vec(aux).unwrap()
    }).collect();

    // 2. DKG Keygen for 3 parties
    let mut dkg_inners: Vec<CggmpExecutorInner> = (0..3).map(|i| {
      CggmpExecutorInner::new(sid.to_string(), "dkg-exec".to_string(), i, t, n)
    }).collect();

    outgoings.clear();
    for (i, inner) in dkg_inners.iter_mut().enumerate() {
      inner.import_aux_info(&aux_infos[i]).unwrap();
      inner.start_keygen().unwrap();
      let out = inner.step_internal(vec![]).unwrap();
      outgoings.insert(i as u16, out);
    }

    for _ in 0..10 {
      let mut incomings: std::collections::HashMap<u16, Vec<Vec<u8>>> = std::collections::HashMap::new();
      for i in 0..3 { incomings.insert(i, Vec::new()); }
      for (from, msgs) in &outgoings {
        for msg in msgs {
          let env = Envelope::decode(msg.as_slice()).unwrap();
          let recipients: Vec<u16> = if env.to_parties.is_empty() {
            (0..3).filter(|&p| p != *from).collect()
          } else {
            env.to_parties.iter().map(|&p| p as u16).collect()
          };
          for r in recipients {
            incomings.get_mut(&r).unwrap().push(msg.clone());
          }
        }
      }
      outgoings.clear();
      for (i, inner) in dkg_inners.iter_mut().enumerate() {
        let inc = incomings.remove(&(i as u16)).unwrap();
        let out = inner.step_internal(inc).unwrap();
        outgoings.insert(i as u16, out);
      }
      let all_finished = dkg_inners.iter().all(|e| {
        let snap = e.snapshot().unwrap();
        snap.contains("\"keyshare_ready\"")
      });
      if all_finished { break; }
    }

    let _shared_public_key = dkg_inners[0].keyshare.as_ref().unwrap().core.shared_public_key;

    // 3. Test 2-of-3 Signing with parties [0, 2]
    let signing_parties = vec![0u16, 2u16];
    let signers_json = serde_json::to_string(&signing_parties).unwrap();
    let tx_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let mut signing_inners: Vec<CggmpExecutorInner> = signing_parties.iter().map(|&p| {
      let mut s = CggmpExecutorInner::new(sid.to_string(), "signing-exec-0-2".to_string(), p, t, n);
      s.keyshare = dkg_inners[p as usize].keyshare.clone();
      s.set_signers(signers_json.clone()).unwrap();
      s.start_signing(tx_hash.to_string()).unwrap();
      s
    }).collect();

    outgoings.clear();
    for (i, inner) in signing_inners.iter_mut().enumerate() {
      let out = inner.step_internal(vec![]).unwrap();
      outgoings.insert(signing_parties[i], out);
    }

    for _ in 0..10 {
      let mut incomings: std::collections::HashMap<u16, Vec<Vec<u8>>> = std::collections::HashMap::new();
      for &p in &signing_parties { incomings.insert(p, Vec::new()); }
      for (from, msgs) in &outgoings {
        for msg in msgs {
          let env = Envelope::decode(msg.as_slice()).unwrap();
          let recipients: Vec<u16> = if env.to_parties.is_empty() {
            signing_parties.iter().copied().filter(|&p| p != *from).collect()
          } else {
            env.to_parties.iter().map(|&p| p as u16).collect()
          };
          for r in recipients {
            if let Some(queue) = incomings.get_mut(&r) {
              queue.push(msg.clone());
            }
          }
        }
      }
      outgoings.clear();
      for (i, inner) in signing_inners.iter_mut().enumerate() {
        let p = signing_parties[i];
        let inc = incomings.remove(&p).unwrap();
        let out = inner.step_internal(inc).unwrap();
        outgoings.insert(p, out);
      }
      let all_finished = signing_inners.iter().all(|e| {
        let snap = e.snapshot().unwrap();
        snap.contains("\"signing_finished\"")
      });
      if all_finished { break; }
    }

    for inner in &signing_inners {
      assert!(inner.last_signature.is_some());
    }

    // 4. Test zeroize on destroy
    let mut party0 = signing_inners.remove(0);
    assert!(party0.keyshare.is_some());
    party0.destroy_internal();
    assert!(party0.is_destroyed);
    assert!(party0.keyshare.is_none());
  }
}
