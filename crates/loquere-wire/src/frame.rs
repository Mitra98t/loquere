//! Codec incrementale sans-IO per frame con prefisso di lunghezza.
//!
//! È un componente generico, non definisce ancora i tipi o il protocollo
//! applicativo degli stream di controllo e chat.

/// Errore di codifica o decodifica di un frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// La lunghezza dichiarata supera il limite configurato o u32.
    TooLarge,
    /// Lo stream è terminato a metà di un frame.
    Truncated,
    /// Il decoder è inutilizzabile dopo un errore di framing.
    Failed,
}

/// Codifica un payload con lunghezza u32 big-endian, entro il limite dato.
pub fn encode_frame(payload: &[u8], max_len: usize) -> Result<Vec<u8>, FrameError> {
    if payload.len() > max_len {
        return Err(FrameError::TooLarge);
    }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Ricostruisce un frame alla volta, senza bufferizzare byte successivi.
///
/// Dopo un errore il decoder resta invalido: il chiamante deve chiudere lo
/// stream invece di interpretare byte successivi come un nuovo frame.
pub struct FrameDecoder {
    max_len: usize,
    header: [u8; 4],
    header_len: usize,
    expected: Option<usize>,
    payload: Vec<u8>,
    failed: bool,
}

impl Drop for FrameDecoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.payload.zeroize();
    }
}

impl FrameDecoder {
    /// Crea un decoder con un limite per singolo payload.
    pub fn new(max_len: usize) -> Self {
        Self {
            max_len,
            header: [0; 4],
            header_len: 0,
            expected: None,
            payload: Vec::new(),
            failed: false,
        }
    }

    /// Consuma al massimo un frame; restituisce i byte consumati e il payload
    /// completo, se disponibile. Il chiamante ripropone i byte non consumati.
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<Vec<u8>>), FrameError> {
        if self.failed {
            return Err(FrameError::Failed);
        }
        let mut consumed = 0;
        if self.expected.is_none() {
            let count = (4 - self.header_len).min(input.len());
            self.header[self.header_len..self.header_len + count].copy_from_slice(&input[..count]);
            self.header_len += count;
            consumed += count;
            if self.header_len < 4 {
                return Ok((consumed, None));
            }
            let len = u32::from_be_bytes(self.header) as usize;
            if len > self.max_len {
                self.failed = true;
                return Err(FrameError::TooLarge);
            }
            self.expected = Some(len);
        }
        let expected = self.expected.expect("header completo");
        let count = (expected - self.payload.len()).min(input.len() - consumed);
        self.payload
            .extend_from_slice(&input[consumed..consumed + count]);
        consumed += count;
        if self.payload.len() == expected {
            self.header_len = 0;
            self.expected = None;
            return Ok((consumed, Some(std::mem::take(&mut self.payload))));
        }
        Ok((consumed, None))
    }

    /// Controlla che la fine dello stream coincida con un confine di frame.
    pub fn finish(&mut self) -> Result<(), FrameError> {
        if self.failed {
            return Err(FrameError::Failed);
        }
        if self.header_len != 0 || self.expected.is_some() {
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
    fn fragmented_frames_and_concatenated_empty_frame() {
        let mut bytes = encode_frame(b"hello", 5).unwrap();
        bytes.extend(encode_frame(b"", 5).unwrap());
        let mut decoder = FrameDecoder::new(5);
        for byte in &bytes[..8] {
            assert_eq!(decoder.push(&[*byte]).unwrap(), (1, None));
        }
        let (consumed, frame) = decoder.push(&bytes[8..]).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(frame.unwrap(), b"hello");
        assert_eq!(decoder.push(&bytes[9..]).unwrap(), (4, Some(vec![])));
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn size_limit_and_truncation_poison_decoder() {
        assert_eq!(encode_frame(b"123", 2), Err(FrameError::TooLarge));
        let mut decoder = FrameDecoder::new(2);
        assert_eq!(decoder.push(&[0, 0, 0, 3]), Err(FrameError::TooLarge));
        assert_eq!(decoder.push(&[]), Err(FrameError::Failed));
        let mut decoder = FrameDecoder::new(2);
        assert_eq!(decoder.push(&[0, 0, 0, 2, 1]), Ok((5, None)));
        assert_eq!(decoder.finish(), Err(FrameError::Truncated));
        assert_eq!(decoder.finish(), Err(FrameError::Failed));
        let mut decoder = FrameDecoder::new(2);
        decoder.push(&[0, 0]).unwrap();
        assert_eq!(decoder.finish(), Err(FrameError::Truncated));
    }
}
