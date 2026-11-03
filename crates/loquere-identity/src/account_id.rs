use crate::IdentityError;
use loquere_crypto::{CryptoError, PublicKey};

/// Identificatore dell'account: la chiave pubblica Ed25519 dell'account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountId(pub(crate) [u8; 32]);

impl AccountId {
    /// Crea un identificatore da una chiave pubblica valida.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        PublicKey::from_bytes(bytes)?;
        Ok(Self(bytes))
    }

    /// Restituisce i byte dell'identificatore.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Codifica l'identificatore in Base32 RFC 4648 senza padding (52 caratteri).
    pub fn to_base32(self) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut output = String::with_capacity(52);
        let mut accumulator = 0u32;
        let mut bits = 0u8;
        for byte in self.0 {
            accumulator = (accumulator << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                output.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
            }
        }
        if bits != 0 {
            output.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
        }
        output
    }

    /// Decodifica Base32 RFC 4648 senza padding e rifiuta codifiche non canoniche.
    pub fn from_base32(value: &str) -> Result<Self, IdentityError> {
        if value.len() != 52 {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut output = [0u8; 32];
        let mut output_len = 0usize;
        let mut accumulator = 0u32;
        let mut bits = 0u8;
        for byte in value.bytes() {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err(IdentityError::InvalidEncoding),
            };
            accumulator = (accumulator << 5) | u32::from(value);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                if output_len >= output.len() {
                    return Err(IdentityError::InvalidEncoding);
                }
                output[output_len] = ((accumulator >> bits) & 0xff) as u8;
                output_len += 1;
            }
        }
        if output_len != 32 || bits != 4 || accumulator & 0x0f != 0 {
            return Err(IdentityError::InvalidEncoding);
        }
        Self::from_bytes(output).map_err(IdentityError::from)
    }

    /// Restituisce la chiave pubblica dell'account.
    pub fn public_key(self) -> Result<PublicKey, CryptoError> {
        PublicKey::from_bytes(self.0)
    }
}
