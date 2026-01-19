#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use napi::{Error, Result, Status};
use prost::Message as _;
use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use round_based::{Incoming, MessageDestination, MessageType};
use round_based::state_machine::{ProceedResult, StateMachine};
use serde::{Deserialize, Serialize};
use base64::Engine as _;
use rayon::prelude::*;

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
  },
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
  internal_round: String, // Added detailed internal round info
  curve: String,
  has_aux: bool,
  has_keyshare: bool,
  public_key: Option<String>,
  key_share_threshold: Option<u16>,
  signature: Option<String>,
}

#[napi]
pub fn generate_primes() -> Result<napi::bindgen_prelude::Buffer> {
  let mut rng = StdRng::from_entropy();
  let primes: cggmp24::PregeneratedPrimes<SecLevel> = cggmp24::PregeneratedPrimes::generate(&mut rng);
  let buf = bincode::serialize(&primes).map_err(|e| Error::new(Status::GenericFailure, format!("serialize: {e}")))?;
  Ok(napi::bindgen_prelude::Buffer::from(buf))
}

#[napi]
pub struct CggmpExecutor {
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
  internal_round: String, // Added detailed internal round info
  status: String,
  last_signature: Option<String>,
  meta_sent: bool,
}

#[napi]
impl CggmpExecutor {
  #[napi(constructor)]
  pub fn new(session_id: String, execution_id: String, party_index: u16, threshold: u16, parties_count: u16) -> Result<Self> {
    if session_id.is_empty() || execution_id.is_empty() {
      return Err(Error::new(Status::InvalidArg, "session_id and execution_id are required"));
    }
    Ok(Self {
      session_id, execution_id, party_index, threshold, parties_count,
      signers_at_keygen: None, rng: Box::new(UnsafeRng::new()), state: ProtocolState::None,
      core_keyshare: None, aux_info: None, keyshare: None, processed: 0,
      phase: "INIT".to_string(), round: 0, errors: Vec::new(), last_round: None,
      internal_round: "Init".to_string(),
      status: "init".to_string(), last_signature: None,
      meta_sent: false,
    })
  }

  #[napi]
  pub fn export_keyshare(&self) -> Result<napi::bindgen_prelude::Buffer> {
    let ks = self.keyshare.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "keyshare not ready"))?;
    let buf = serde_json::to_vec(ks).map_err(|e| Error::new(Status::GenericFailure, format!("export: {e}")))?;
    Ok(napi::bindgen_prelude::Buffer::from(buf))
  }

  #[napi]
  pub fn export_aux_info(&self) -> Result<napi::bindgen_prelude::Buffer> {
    let aux = self.aux_info.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "aux info not ready"))?;
    let buf = serde_json::to_vec(aux).map_err(|e| Error::new(Status::GenericFailure, format!("export: {e}")))?;
    Ok(napi::bindgen_prelude::Buffer::from(buf))
  }

  #[napi]
  pub fn import_keyshare(&mut self, data: napi::bindgen_prelude::Buffer) -> Result<()> {
    let ks: KeyShareWithLevel = if !data.is_empty() && data[0] == b'{' {
      serde_json::from_slice(&data).map_err(|e| Error::new(Status::InvalidArg, format!("parse json: {e}")))?
    } else {
      match serde_json::from_slice(&data) {
        Ok(k) => k,
        Err(_) => {
          let decoded = base64::engine::general_purpose::STANDARD.decode(&data)
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

  #[napi]
  pub fn import_aux_info(&mut self, data: napi::bindgen_prelude::Buffer) -> Result<()> {
    let aux: AuxInfoMsg = if !data.is_empty() && data[0] == b'{' {
      serde_json::from_slice(&data).map_err(|e| Error::new(Status::InvalidArg, format!("parse json: {e}")))?
    } else {
      match serde_json::from_slice(&data) {
        Ok(a) => a,
        Err(_) => {
          let decoded = base64::engine::general_purpose::STANDARD.decode(&data)
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

  #[napi]
  pub fn start_keygen(&mut self) -> Result<()> {
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "keygen"));
    let builder = KeygenBuilder::<Secp256k1>::new(eid, self.party_index, self.parties_count).set_threshold(self.threshold).enforce_reliable_broadcast(false);
    self.state = ProtocolState::Keygen { sm: Box::new(builder.into_state_machine(extend_mut(&mut self.rng))), pending: Vec::new() };
    self.phase = "KEYGEN".to_string(); self.status = "running".to_string(); self.round = Round::Keygen as u32; self.last_round = Some(Round::Keygen);
    self.internal_round = "Round 1 (Commitment)".to_string(); // Initial round
    Ok(())
  }

  #[napi]
  pub fn start_aux_gen(&mut self) -> Result<()> {
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "aux_gen"));
    let rng = extend_mut(&mut self.rng);
    let primes: cggmp24::PregeneratedPrimes<SecLevel> = cggmp24::PregeneratedPrimes::generate(rng);
    let builder = cggmp24::aux_info_gen(eid, self.party_index, self.parties_count, primes).enforce_reliable_broadcast(false);
    self.state = ProtocolState::AuxGen { sm: Box::new(builder.into_state_machine(rng)), pending: Vec::new() };
    self.phase = "AUX_GEN".to_string(); self.status = "running".to_string(); self.round = Round::AuxInfo as u32; self.last_round = Some(Round::AuxInfo);
    self.internal_round = "Round 1 (Paillier Gen)".to_string(); // Initial round
    Ok(())
  }

  #[napi]
  pub fn start_aux_gen_with_primes(&mut self, primes_buf: napi::bindgen_prelude::Buffer) -> Result<()> {
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "aux_gen"));
    let primes: cggmp24::PregeneratedPrimes<SecLevel> = bincode::deserialize(&primes_buf).map_err(|e| Error::new(Status::InvalidArg, format!("invalid primes: {e}")))?;
    let rng = extend_mut(&mut self.rng);
    let builder = cggmp24::aux_info_gen(eid, self.party_index, self.parties_count, primes).enforce_reliable_broadcast(false);
    self.state = ProtocolState::AuxGen { sm: Box::new(builder.into_state_machine(rng)), pending: Vec::new() };
    self.phase = "AUX_GEN".to_string(); self.status = "running".to_string(); self.round = Round::AuxInfo as u32; self.last_round = Some(Round::AuxInfo);
    self.internal_round = "Round 1 (Paillier Gen)".to_string(); // Initial round
    Ok(())
  }

  #[napi]
  pub fn set_signers(&mut self, json: String) -> Result<()> {
    let parsed: Vec<u16> = serde_json::from_str(&json).map_err(|e| Error::new(Status::InvalidArg, format!("invalid json: {e}")))?;
    self.signers_at_keygen = Some(parsed);
    Ok(())
  }

  #[napi]
  pub fn start_signing(&mut self, tx_hex: String) -> Result<()> {
    let ks = self.keyshare.clone().ok_or_else(|| Error::new(Status::InvalidArg, "keyshare missing"))?;
    let tx = hex::decode(tx_hex).map_err(|e| Error::new(Status::InvalidArg, format!("invalid hex: {e}")))?;
    // 32바이트인 경우 이미 해시된 데이터로 처리, 아니면 SHA256으로 해싱
    let data: Box<dyn AnyDataToSign<Secp256k1>> = if tx.len() == 32 {
      Box::new(PrehashedDataToSign::from_scalar(generic_ec::Scalar::<Secp256k1>::from_be_bytes_mod_order(&tx)))
    } else {
      Box::new(cggmp24::DataToSign::<Secp256k1>::digest::<sha2::Sha256>(&tx))
    };
    let min = ks.min_signers();
    let selected = self.signers_at_keygen.clone().unwrap_or_else(|| (0..min).collect());
    let eid = ExecutionId::new(derive_execution_seed(&self.session_id, &self.execution_id, "signing"));
    let ks_boxed = Box::new(ks);
    let my_idx = selected.iter().position(|&p| p == self.party_index).ok_or_else(|| Error::new(Status::InvalidArg, "not in signers"))? as u16;
    let sm = cggmp24::signing(eid, my_idx, extend_ref(selected.as_slice()), extend_ref(&*ks_boxed)).sign_sync(extend_mut(&mut self.rng), extend_ref(&*data));
    self.state = ProtocolState::Signing { sm: Box::new(sm), pending: Vec::new(), tx_context: tx, _keyshare: ks_boxed, _signers: selected };
    self.phase = "SIGNING".to_string(); self.status = "running".to_string(); self.round = Round::Signing as u32; self.last_round = Some(Round::Signing);
    self.internal_round = "Round 1 (Partial Sign)".to_string(); // Initial round
    Ok(())
  }

  #[napi]
  pub fn step(&mut self, inputs: Vec<napi::bindgen_prelude::Buffer>) -> Result<Vec<napi::bindgen_prelude::Buffer>> {
    self.processed += inputs.len();
    
    // 1. 스레드 안전한 Vec<u8>로 변환 (NAPI Buffer는 스레드 이동 불가)
    let raw_inputs: Vec<Vec<u8>> = inputs.iter().map(|b| b.to_vec()).collect();

    // 2. Phase 5: Rayon을 사용한 병렬 역직렬화
    match &mut self.state {
      ProtocolState::Keygen { pending, .. } => {
        let decoded_msgs: Vec<Incoming<KeygenMsg>> = raw_inputs.par_iter().filter_map(|buf| {
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
      ProtocolState::None => { if !inputs.is_empty() { return Err(Error::new(Status::InvalidArg, "no protocol")); } }
    }

    // 2. 상태 머신 구동 (메시지 소진 시까지 반복)
    let mut outgoing = Vec::new();
    match &mut self.state {
      ProtocolState::Keygen { sm, pending, .. } => {
        let out = drive_sm(sm.as_mut(), pending, Round::Keygen as i32, &self.session_id, &self.execution_id, self.party_index, self.threshold, self.parties_count, &mut outgoing, &[], &mut self.meta_sent, &mut self.internal_round, |msg| {
            match msg {
                keygen_msg::Msg::Round1(_) => "Round 1 (Commitment)".to_string(),
                keygen_msg::Msg::Round2Broad(_) | keygen_msg::Msg::Round2Uni(_) => "Round 2 (VSS & Share)".to_string(),
                keygen_msg::Msg::Round3(_) => "Round 3 (Verify & Proofs)".to_string(),
                _ => "Reliability Check".to_string(),
            }
        })?;
        if let Some(res) = out {
          self.core_keyshare = Some(res.map_err(|e| Error::new(Status::GenericFailure, format!("{e:?}")))?);
          self.status = "keygen_finished".to_string(); self.state = ProtocolState::None; self.try_combine_shares();
          self.internal_round = "Finished".to_string();
        }
      }
      ProtocolState::AuxGen { sm, pending, .. } => {
        let out = drive_sm(sm.as_mut(), pending, Round::AuxInfo as i32, &self.session_id, &self.execution_id, self.party_index, self.threshold, self.parties_count, &mut outgoing, &[], &mut self.meta_sent, &mut self.internal_round, |msg| {
            match msg {
                cggmp24::key_refresh::msg::Msg::Round1(_) => "Round 1 (Paillier Gen)".to_string(),
                cggmp24::key_refresh::msg::Msg::Round2(_) => "Round 2 (ZKP Verify)".to_string(),
                cggmp24::key_refresh::msg::Msg::Round3(_) => "Round 3 (Finalize)".to_string(),
                _ => "Reliability Check".to_string(),
            }
        })?;
        if let Some(res) = out {
          self.aux_info = Some(res.map_err(|e| Error::new(Status::GenericFailure, format!("{e:?}")))?);
          self.status = "aux_gen_finished".to_string(); self.state = ProtocolState::None; self.try_combine_shares();
          self.internal_round = "Finished".to_string();
        }
      }
      ProtocolState::Signing { sm, pending, tx_context, .. } => {
        let out = drive_sm(sm.as_mut(), pending, Round::Signing as i32, &self.session_id, &self.execution_id, self.party_index, self.threshold, self.parties_count, &mut outgoing, tx_context, &mut self.meta_sent, &mut self.internal_round, |msg| {
            match msg {
                cggmp24::signing::msg::Msg::Round1a(_) | cggmp24::signing::msg::Msg::Round1b(_) => "Round 1 (Partial Sign)".to_string(),
                cggmp24::signing::msg::Msg::Round2(_) => "Round 2 (Verify)".to_string(),
                cggmp24::signing::msg::Msg::Round3(_) => "Round 3 (Combine)".to_string(),
                cggmp24::signing::msg::Msg::Round4(_) => "Round 4 (Finalize)".to_string(),
                _ => "Reliability Check".to_string(),
            }
        })?;
        if let Some(res) = out {
          let sig = res.map_err(|e| Error::new(Status::GenericFailure, format!("{e:?}")))?;
          outgoing.push(make_envelope(&self.session_id, &self.execution_id, Round::Signing as i32, self.party_index, self.threshold, self.parties_count, &[], encode_msg(&sig)?, tx_context, self.meta_sent));
          self.meta_sent = true;
          self.status = "signing_finished".to_string(); self.state = ProtocolState::None;
          self.last_signature = Some(serde_json::to_string(&sig).unwrap());
          self.internal_round = "Finished".to_string();
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
    encode_envelopes_bin(&outgoing)
  }

  #[napi]
  pub fn snapshot(&self) -> Result<String> {
    let (public_key, key_share_threshold) = if let Some(ks) = &self.keyshare {
        (Some(hex::encode(ks.core.shared_public_key.to_bytes(true))), Some(ks.min_signers()))
    } else if let Some(core) = &self.core_keyshare {
        (Some(hex::encode(core.shared_public_key.to_bytes(true))), None)
    } else { (None, None) };
    let snap = ExecutorSnapshot {
      session_id: self.session_id.clone(), execution_id: self.execution_id.clone(), party_index: self.party_index, threshold: self.threshold, parties_count: self.parties_count, phase: self.phase.clone(), round: self.round, processed: self.processed, status: self.status.clone(), errors: self.errors.clone(), last_round: self.last_round.map(|r| format!("{:?}", r)),
      internal_round: self.internal_round.clone(), // Added
      curve: "secp256k1".to_string(), has_aux: self.aux_info.is_some(), has_keyshare: self.keyshare.is_some(), public_key, key_share_threshold, signature: self.last_signature.clone(),
    };
    serde_json::to_string(&snap).map_err(|e| Error::new(Status::GenericFailure, format!("{e}")))
  }

  #[napi]
  pub fn export_keyshare_bin(&self) -> Result<napi::bindgen_prelude::Buffer> {
    let ks = self.keyshare.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "keyshare not ready"))?;
    let buf = serde_json::to_vec(ks).map_err(|e| Error::new(Status::GenericFailure, format!("export: {e}")))?;
    Ok(napi::bindgen_prelude::Buffer::from(buf))
  }

  #[napi]
  pub fn export_aux_info_bin(&self) -> Result<napi::bindgen_prelude::Buffer> {
    let aux = self.aux_info.as_ref().ok_or_else(|| Error::new(Status::InvalidArg, "aux info not ready"))?;
    let buf = serde_json::to_vec(aux).map_err(|e| Error::new(Status::GenericFailure, format!("export: {e}")))?;
    Ok(napi::bindgen_prelude::Buffer::from(buf))
  }

  fn try_combine_shares(&mut self) {
    if let (Some(core), Some(aux)) = (&self.core_keyshare, &self.aux_info) {
      if let Ok(ks) = KeyShare::from_parts((core.clone(), aux.clone())) {
        self.keyshare = Some(ks); self.status = "keyshare_ready".to_string();
      }
    }
  }
}

fn encode_envelopes_bin(envs: &[Envelope]) -> Result<Vec<napi::bindgen_prelude::Buffer>> {
  envs.iter().map(|env| {
    let mut buf = Vec::new();
    env.encode(&mut buf).map_err(|e| Error::new(Status::GenericFailure, format!("encode: {e}")))?;
    Ok(napi::bindgen_prelude::Buffer::from(buf))
  }).collect()
}

fn encode_msg<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
  bincode::serialize(msg).map_err(|e| Error::new(Status::GenericFailure, format!("encode: {e}")))
}

fn drive_sm<M, O, F>(
    sm: &mut dyn StateMachine<Output = O, Msg = M>,
    pending: &mut Vec<Incoming<M>>,
    round: i32,
    sid: &str, eid: &str, from: u16, t: u16, n: u16,
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
        let to = match out.recipient { MessageDestination::AllParties => Vec::new(), MessageDestination::OneParty(i) => vec![i as u32] };
        *internal_round = get_round_name(&out.msg); // Update internal round
        outgoing.push(make_envelope(sid, eid, round, from, t, n, &to, encode_msg(&out.msg)?, tx, *meta_sent));
        *meta_sent = true;
      }
      ProceedResult::NeedsOneMoreMessage => {
        if !pending.is_empty() {
          let msg = pending.remove(0); // FIFO
          sm.received_msg(msg).map_err(|_| Error::new(Status::GenericFailure, "rejected by state machine"))?;
        } else {
          return Ok(None);
        }
      }
      ProceedResult::Yielded => continue,
      ProceedResult::Output(o) => return Ok(Some(o)),
      ProceedResult::Error(err) => return Err(Error::new(Status::GenericFailure, format!("{err}"))),
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