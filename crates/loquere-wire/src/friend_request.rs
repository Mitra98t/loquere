//! Primo record FriendRequest: parsing soltanto, nessuna autorizzazione.

use crate::{FrameDecoder, FrameError, encode_frame};
use zeroize::Zeroizing;

const MAX_RECORD: usize = 4096;
const HEADER: [u8; 2] = [1, 2];
const TOKEN_LEN: usize = 16;

/// Dati ricevuti non ancora verificati; il token viene azzerato al rilascio.
pub struct FriendRequest {
    token: Zeroizing<[u8; TOKEN_LEN]>,
    certificate: Vec<u8>,
}

impl FriendRequest {
    /// Token da validare con l'invito emesso localmente.
    pub fn token(&self) -> &[u8; TOKEN_LEN] {
        &self.token
    }
    /// Certificato da verificare e confrontare con la chiave TLS del peer.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

/// Codifica un FriendRequest. I byte restituiti contengono il token segreto.
pub fn encode_friend_request(
    token: &[u8; TOKEN_LEN],
    certificate: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    if certificate.is_empty() {
        return Err(FrameError::Failed);
    }
    if certificate.len() > MAX_RECORD - HEADER.len() - TOKEN_LEN {
        return Err(FrameError::TooLarge);
    }
    let mut payload = Zeroizing::new(Vec::with_capacity(
        HEADER.len() + TOKEN_LEN + certificate.len(),
    ));
    payload.extend_from_slice(&HEADER);
    payload.extend_from_slice(token);
    payload.extend_from_slice(certificate);
    encode_frame(&payload, MAX_RECORD).map(Zeroizing::new)
}

/// Decoder incrementale per il primo FriendRequest su stream di controllo.
pub struct FriendRequestDecoder {
    inner: FrameDecoder,
    done: bool,
    failed: bool,
}

impl Default for FriendRequestDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FriendRequestDecoder {
    /// Crea un decoder indipendente dallo stato dell'invito.
    pub fn new() -> Self {
        Self {
            inner: FrameDecoder::new(MAX_RECORD),
            done: false,
            failed: false,
        }
    }

    /// Consuma un record, lasciando al chiamante eventuali byte successivi.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(usize, Option<FriendRequest>), FrameError> {
        if self.failed || self.done {
            return Err(FrameError::Failed);
        }
        let (used, record) = self.inner.push(bytes).inspect_err(|_| self.failed = true)?;
        let Some(record) = record else {
            return Ok((used, None));
        };
        let record = Zeroizing::new(record);
        if record.len() <= HEADER.len() + TOKEN_LEN || !record.starts_with(&HEADER) {
            self.failed = true;
            return Err(FrameError::Failed);
        }
        let mut token = Zeroizing::new([0; TOKEN_LEN]);
        token.copy_from_slice(&record[2..2 + TOKEN_LEN]);
        let certificate = record[2 + TOKEN_LEN..].to_vec();
        self.done = true;
        Ok((used, Some(FriendRequest { token, certificate })))
    }

    /// Rifiuta la chiusura se il record non è completo.
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
    fn parses_every_fragmentation_and_leaves_extra_bytes() {
        let encoded = encode_friend_request(&[7; 16], b"certificate").unwrap();
        for split in 0..encoded.len() {
            let mut decoder = FriendRequestDecoder::new();
            assert!(decoder.push(&encoded[..split]).unwrap().1.is_none());
            let mut tail = encoded[split..].to_vec();
            tail.extend_from_slice(b"next");
            let (used, request) = decoder.push(&tail).unwrap();
            assert_eq!(used, encoded.len() - split);
            let request = request.unwrap();
            assert_eq!(request.token(), &[7; 16]);
            assert_eq!(request.certificate(), b"certificate");
            assert_eq!(decoder.finish(), Ok(()));
        }
    }

    #[test]
    fn rejects_empty_oversized_unknown_and_truncated_records() {
        assert!(encode_friend_request(&[0; 16], &[]).is_err());
        assert!(encode_friend_request(&[0; 16], &vec![0; MAX_RECORD]).is_err());
        let mut decoder = FriendRequestDecoder::new();
        let bad = encode_frame(&[1, 3, 0], MAX_RECORD).unwrap();
        assert!(decoder.push(&bad).is_err());
        assert!(decoder.push(&[]).is_err());
        let mut decoder = FriendRequestDecoder::new();
        decoder.push(&[0, 0, 0]).unwrap();
        assert_eq!(decoder.finish(), Err(FrameError::Truncated));
    }
}
