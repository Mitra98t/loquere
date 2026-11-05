//! Scambio FriendAccept dopo il consenso; parsing separato dalla fiducia.

use crate::{FrameDecoder, FrameError, encode_frame};
use zeroize::Zeroizing;

const HEADER: [u8; 2] = [1, 4];
const SECRET_LEN: usize = 32;
const MAX_RECORD: usize = 1024 * 1024 + 2 + SECRET_LEN;

/// Dati riservati trasmessi dopo consenso, non ancora verificati dal chiamante.
pub struct FriendAccept {
    discovery_secret: Zeroizing<[u8; SECRET_LEN]>,
    device_list: Vec<u8>,
}

impl FriendAccept {
    /// Segreto di scoperta da conservare cifrato; non pubblicarlo.
    pub fn discovery_secret(&self) -> &[u8; SECRET_LEN] {
        &self.discovery_secret
    }
    /// DeviceList firmata da decodificare e associare all'account autenticato.
    pub fn device_list(&self) -> &[u8] {
        &self.device_list
    }
}

/// Codifica il contenuto riservato per uno stream TLS autenticato.
pub fn encode_friend_accept(
    secret: &[u8; SECRET_LEN],
    device_list: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    if device_list.is_empty() {
        return Err(FrameError::Failed);
    }
    if device_list.len() > MAX_RECORD - HEADER.len() - SECRET_LEN {
        return Err(FrameError::TooLarge);
    }
    let mut body = Zeroizing::new(Vec::with_capacity(
        HEADER.len() + SECRET_LEN + device_list.len(),
    ));
    body.extend_from_slice(&HEADER);
    body.extend_from_slice(secret);
    body.extend_from_slice(device_list);
    encode_frame(&body, MAX_RECORD).map(Zeroizing::new)
}

/// Riceve un FriendAccept; il chiamante deve verificare autorizzazione e firma.
pub struct FriendAcceptDecoder {
    inner: FrameDecoder,
    done: bool,
    failed: bool,
}

impl Default for FriendAcceptDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FriendAcceptDecoder {
    /// Crea un decoder per un singolo record.
    pub fn new() -> Self {
        Self {
            inner: FrameDecoder::new(MAX_RECORD),
            done: false,
            failed: false,
        }
    }

    /// Consuma al massimo un record e restituisce i dati non ancora verificati.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(usize, Option<FriendAccept>), FrameError> {
        if self.done || self.failed {
            return Err(FrameError::Failed);
        }
        let (used, record) = self.inner.push(bytes).inspect_err(|_| self.failed = true)?;
        let Some(record) = record else {
            return Ok((used, None));
        };
        let record = Zeroizing::new(record);
        if record.len() <= HEADER.len() + SECRET_LEN || !record.starts_with(&HEADER) {
            self.failed = true;
            return Err(FrameError::Failed);
        }
        let mut secret = Zeroizing::new([0; SECRET_LEN]);
        secret.copy_from_slice(&record[2..2 + SECRET_LEN]);
        let device_list = record[2 + SECRET_LEN..].to_vec();
        self.done = true;
        Ok((
            used,
            Some(FriendAccept {
                discovery_secret: secret,
                device_list,
            }),
        ))
    }

    /// Verifica che il record sia completo alla chiusura dello stream.
    pub fn finish(&mut self) -> Result<(), FrameError> {
        if self.failed {
            return Err(FrameError::Failed);
        }
        if !self.done {
            self.failed = true;
            return Err(FrameError::Truncated);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_every_split_without_consuming_next_record() {
        let encoded = encode_friend_accept(&[7; 32], b"signed-list").unwrap();
        for split in 0..encoded.len() {
            let mut decoder = FriendAcceptDecoder::new();
            assert!(decoder.push(&encoded[..split]).unwrap().1.is_none());
            let mut tail = Zeroizing::new(encoded[split..].to_vec());
            tail.push(99);
            let (used, accept) = decoder.push(&tail).unwrap();
            assert_eq!(used, encoded.len() - split);
            let accept = accept.unwrap();
            assert_eq!(accept.discovery_secret(), &[7; 32]);
            assert_eq!(accept.device_list(), b"signed-list");
            assert_eq!(decoder.finish(), Ok(()));
        }
    }

    #[test]
    fn rejects_wrong_type_empty_list_oversized_and_truncated() {
        assert!(encode_friend_accept(&[0; 32], &[]).is_err());
        assert!(encode_friend_accept(&[0; 32], &vec![0; MAX_RECORD]).is_err());
        let mut decoder = FriendAcceptDecoder::new();
        assert!(decoder.push(&crate::encode_friend_ack()).is_err());
        assert!(decoder.finish().is_err());
        let mut decoder = FriendAcceptDecoder::new();
        decoder.push(&[0, 0]).unwrap();
        assert_eq!(decoder.finish(), Err(FrameError::Truncated));
    }
}
