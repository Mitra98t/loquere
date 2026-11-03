#![forbid(unsafe_code)]

//! Primitive crittografiche e tipi chiave di Loquere.
//!
//! Questa crate espone firme Ed25519 tramite `ed25519-dalek`; non implementa
//! primitive crittografiche proprie.

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

/// Chiave pubblica Ed25519, serializzata nella forma canonica di 32 byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Costruisce una chiave pubblica verificandone la codifica.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    /// Restituisce la codifica canonica della chiave.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Verifica una firma Ed25519 sui byte esatti del messaggio.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidPublicKey)?;
        key.verify(message, &DalekSignature::from_bytes(&signature.0))
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// Firma Ed25519, serializzata nella forma canonica di 64 byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Costruisce una firma da byte; la validità è determinata da [`PublicKey::verify`].
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Restituisce i byte della firma.
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

/// Chiave privata Ed25519. Il materiale segreto viene azzerato quando l'oggetto
/// viene rilasciato.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// Genera una nuova chiave con il generatore casuale del sistema operativo.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Importa una chiave privata da 32 byte.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&bytes))
    }

    /// Restituisce la chiave pubblica corrispondente.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    /// Firma i byte esatti del messaggio.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message).to_bytes())
    }
}

/// Errori esposti dalle primitive di questa crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// I byte non rappresentano una chiave pubblica Ed25519 valida.
    InvalidPublicKey,
    /// Firma non valida per chiave e messaggio forniti.
    InvalidSignature,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKey => formatter.write_str("chiave pubblica Ed25519 non valida"),
            Self::InvalidSignature => formatter.write_str("firma Ed25519 non valida"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_signs_and_verifies() {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        let message = b"loquere M0";
        let signature = secret.sign(message);

        assert_eq!(public.verify(message, &signature), Ok(()));
        assert_eq!(PublicKey::from_bytes(public.to_bytes()), Ok(public));
    }

    #[test]
    fn signature_does_not_verify_for_different_message() {
        let secret = SecretKey::generate();
        let signature = secret.sign(b"messaggio originale");

        assert_eq!(
            secret
                .public_key()
                .verify(b"messaggio modificato", &signature),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn private_key_import_is_deterministic() {
        let secret = SecretKey::from_bytes([7; 32]);
        let restored = SecretKey::from_bytes([7; 32]);

        assert_eq!(secret.public_key(), restored.public_key());
        assert_eq!(secret.sign(b"test"), restored.sign(b"test"));
    }
}
