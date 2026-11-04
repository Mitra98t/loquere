//! Primo messaggio di controllo D-41. Non effettua autorizzazioni.

use crate::{FrameDecoder, FrameError, encode_frame};

const MAX_CONTROL_FRAME: usize = 256;
const HELLO: [u8; 2] = [1, 1];

/// Codifica `Hello{}`; il peer deve comunque verificare l'amicizia.
pub fn encode_control_hello() -> Vec<u8> {
    encode_frame(&HELLO, MAX_CONTROL_FRAME).expect("Hello rientra nel limite")
}

/// Riceve il primo record di controllo; non verifica l'identità del peer.
pub struct ControlHelloDecoder {
    inner: FrameDecoder,
    done: bool,
    failed: bool,
}

impl Default for ControlHelloDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlHelloDecoder {
    /// Crea un decoder per il primo record dello stream di controllo.
    pub fn new() -> Self {
        Self {
            inner: FrameDecoder::new(MAX_CONTROL_FRAME),
            done: false,
            failed: false,
        }
    }

    /// Restituisce byte consumati e `true` solo quando Hello è completo.
    /// I byte successivi sono lasciati al chiamante e non vengono validati.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(usize, bool), FrameError> {
        if self.failed || self.done {
            return Err(FrameError::Failed);
        }
        let (used, record) = self.inner.push(bytes).inspect_err(|_| {
            self.failed = true;
        })?;
        match record {
            None => Ok((used, false)),
            Some(record) if record == HELLO => {
                self.done = true;
                Ok((used, true))
            }
            Some(_) => {
                self.failed = true;
                Err(FrameError::Failed)
            }
        }
    }

    /// Rifiuta una chiusura prima del completamento del primo Hello.
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
    fn hello_is_incremental_and_leaves_following_records_untouched() {
        let hello = encode_control_hello();
        for split in 0..hello.len() {
            let mut decoder = ControlHelloDecoder::new();
            assert_eq!(decoder.push(&hello[..split]), Ok((split, false)));
            let mut rest = hello[split..].to_vec();
            rest.extend_from_slice(b"following");
            assert_eq!(decoder.push(&rest), Ok((hello.len() - split, true)));
            assert_eq!(decoder.finish(), Ok(()));
            assert_eq!(decoder.push(&[]), Err(FrameError::Failed));
        }
    }

    #[test]
    fn invalid_oversized_and_missing_hello_fail_closed() {
        for payload in [&[][..], &[1][..], &[1, 2][..], &[1, 1, 0][..]] {
            let mut decoder = ControlHelloDecoder::new();
            assert!(
                decoder
                    .push(&encode_frame(payload, MAX_CONTROL_FRAME).unwrap())
                    .is_err()
            );
            assert_eq!(decoder.finish(), Err(FrameError::Failed));
        }
        let mut decoder = ControlHelloDecoder::new();
        assert_eq!(decoder.push(&[0, 0, 1, 1]), Err(FrameError::TooLarge));
        let mut decoder = ControlHelloDecoder::new();
        assert_eq!(decoder.finish(), Err(FrameError::Truncated));
        assert_eq!(
            decoder.push(&encode_control_hello()),
            Err(FrameError::Failed)
        );
    }
}
