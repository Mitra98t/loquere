//! Framing dello stream chat (D-40); l'autenticazione rimane a OpenMLS.

use crate::{FrameDecoder, FrameError, encode_frame};

const MAX_CHAT_FRAME: usize = 1024 * 1024;
const VERSION: u8 = 1;
const MLS_APPLICATION: u8 = 1;

/// Errore irreversibile nel framing dello stream chat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatFrameError {
    /// Frame troppo grande o stream troncato.
    Framing(FrameError),
    /// Header, versione, tipo o contenuto non validi.
    InvalidRecord,
    /// Decoder già invalidato da un errore precedente.
    Failed,
}

/// Incapsula un messaggio applicativo MLS serializzato, senza interpretarlo.
pub fn encode_chat_message(message: &[u8]) -> Result<Vec<u8>, ChatFrameError> {
    if message.is_empty() {
        return Err(ChatFrameError::InvalidRecord);
    }
    if message.len() > MAX_CHAT_FRAME - 2 {
        return Err(ChatFrameError::Framing(FrameError::TooLarge));
    }
    let mut payload = Vec::with_capacity(message.len() + 2);
    payload.extend_from_slice(&[VERSION, MLS_APPLICATION]);
    payload.extend_from_slice(message);
    encode_frame(&payload, MAX_CHAT_FRAME).map_err(ChatFrameError::Framing)
}

/// Un frame in attesa di scrittura su QUIC, gestibile anche parzialmente.
pub struct PendingChatFrame {
    bytes: Vec<u8>,
    offset: usize,
}

impl PendingChatFrame {
    /// Codifica un ciphertext MLS per l'invio senza effettuare I/O.
    pub fn new(message: &[u8]) -> Result<Self, ChatFrameError> {
        Ok(Self {
            bytes: encode_chat_message(message)?,
            offset: 0,
        })
    }

    /// Byte non ancora accettati da QUIC; vuoto soltanto a invio completato.
    pub fn remaining(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    /// Registra i byte effettivamente accettati; rifiuta avanzamenti impossibili.
    pub fn advance(&mut self, written: usize) -> Result<(), ChatFrameError> {
        if written > self.remaining().len() {
            return Err(ChatFrameError::InvalidRecord);
        }
        self.offset += written;
        Ok(())
    }
}

/// Decoder incrementale; i byte restituiti non sono ancora autenticati.
pub struct ChatFrameDecoder {
    inner: FrameDecoder,
    failed: bool,
}

impl Default for ChatFrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatFrameDecoder {
    /// Inizializza un decoder per uno stream chat.
    pub fn new() -> Self {
        Self {
            inner: FrameDecoder::new(MAX_CHAT_FRAME),
            failed: false,
        }
    }

    /// Consuma al massimo un record; i byte non consumati vanno riproposti.
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<Vec<u8>>), ChatFrameError> {
        if self.failed {
            return Err(ChatFrameError::Failed);
        }
        let (consumed, frame) = self.inner.push(input).map_err(|error| {
            self.failed = true;
            ChatFrameError::Framing(error)
        })?;
        let Some(frame) = frame else {
            return Ok((consumed, None));
        };
        if frame.len() < 3 || frame[0] != VERSION || frame[1] != MLS_APPLICATION {
            self.failed = true;
            return Err(ChatFrameError::InvalidRecord);
        }
        Ok((consumed, Some(frame[2..].to_vec())))
    }

    /// Controlla che lo stream non sia terminato a metà record.
    pub fn finish(&mut self) -> Result<(), ChatFrameError> {
        if self.failed {
            return Err(ChatFrameError::Failed);
        }
        self.inner.finish().map_err(|error| {
            self.failed = true;
            ChatFrameError::Framing(error)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fragment_boundary_and_multiple_records() {
        let frame = encode_chat_message(b"ciphertext").unwrap();
        for split in 0..frame.len() {
            let mut decoder = ChatFrameDecoder::new();
            assert_eq!(decoder.push(&frame[..split]).unwrap(), (split, None));
            assert_eq!(
                decoder.push(&frame[split..]).unwrap(),
                (frame.len() - split, Some(b"ciphertext".to_vec()))
            );
            assert_eq!(decoder.finish(), Ok(()));
        }
        let mut decoder = ChatFrameDecoder::new();
        let combined = [frame.as_slice(), frame.as_slice()].concat();
        let (used, first) = decoder.push(&combined).unwrap();
        assert_eq!(first, Some(b"ciphertext".to_vec()));
        assert_eq!(decoder.push(&combined[used..]).unwrap().1, first);
    }

    #[test]
    fn rejects_bad_records_and_incomplete_streams() {
        assert_eq!(encode_chat_message(&[]), Err(ChatFrameError::InvalidRecord));
        assert_eq!(
            encode_chat_message(&vec![0; MAX_CHAT_FRAME - 1]),
            Err(ChatFrameError::Framing(FrameError::TooLarge))
        );
        for payload in [&[][..], &[1, 1][..], &[2, 1, 7][..], &[1, 2, 7][..]] {
            let bytes = encode_frame(payload, MAX_CHAT_FRAME).unwrap();
            let mut decoder = ChatFrameDecoder::new();
            assert_eq!(decoder.push(&bytes), Err(ChatFrameError::InvalidRecord));
            assert_eq!(decoder.push(&[]), Err(ChatFrameError::Failed));
        }
        let mut decoder = ChatFrameDecoder::new();
        assert_eq!(
            decoder.push(&[0, 16, 0, 1]),
            Err(ChatFrameError::Framing(FrameError::TooLarge))
        );
        let mut decoder = ChatFrameDecoder::new();
        decoder.push(&[0, 0]).unwrap();
        assert_eq!(
            decoder.finish(),
            Err(ChatFrameError::Framing(FrameError::Truncated))
        );
    }

    #[test]
    fn partial_writes_preserve_order_and_do_not_skip_bytes() {
        let expected = encode_chat_message(b"ciphertext").unwrap();
        let mut frame = PendingChatFrame::new(b"ciphertext").unwrap();
        assert_eq!(
            frame.advance(expected.len() + 1),
            Err(ChatFrameError::InvalidRecord)
        );
        let mut written = Vec::new();
        while !frame.remaining().is_empty() {
            let count = frame.remaining().len().min(3);
            written.extend_from_slice(&frame.remaining()[..count]);
            frame.advance(count).unwrap();
        }
        assert_eq!(written, expected);
        assert_eq!(frame.advance(0), Ok(()));
        assert_eq!(frame.advance(1), Err(ChatFrameError::InvalidRecord));
    }
}
