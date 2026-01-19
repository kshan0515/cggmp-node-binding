use napi::{Error, Result, Status};
use serde_json;

use crate::proto::{self, envelope::Payload, Envelope, Round};
use crate::{SigningMsg};

pub fn decode_signing_msg(bytes: &[u8]) -> Result<SigningMsg> {
  serde_json::from_slice(bytes)
    .map_err(|e| Error::new(Status::InvalidArg, format!("decode signing msg: {e}")))
}

pub fn encode_signing_msg(msg: &SigningMsg) -> Result<Vec<u8>> {
  serde_json::to_vec(msg)
    .map_err(|e| Error::new(Status::GenericFailure, format!("encode signing msg: {e}")))
}

pub fn outgoing_to_envelopes(
  messages: Vec<(Option<u16>, SigningMsg)>,
  session_id: &str,
  execution_id: &str,
  curve: i32,
  threshold: u16,
  parties_count: u16,
  from_party: u16,
  tx_context: Vec<u8>,
) -> Result<Vec<Envelope>> {
  let mut envs = Vec::new();
  for (recipient, msg) in messages {
    let payload = encode_signing_msg(&msg)?;
    let to_parties = match recipient {
      None => Vec::new(),
      Some(i) => vec![i as u32],
    };
    envs.push(Envelope {
      version: 1,
      session_id: session_id.to_string(),
      execution_id: execution_id.to_string(),
      round: Round::Signing as i32,
      from_party: from_party as u32,
      to_parties,
      meta: Some(proto::Meta {
        curve,
        threshold: threshold as u32,
        parties_count: parties_count as u32,
        party_index: from_party as u32,
        tx_context: tx_context.clone(),
        retry: 0,
      }),
      payload: Some(Payload::Signing(proto::Signing {
        payload,
        tx_context: tx_context.clone(),
      })),
    });
  }
  Ok(envs)
}
