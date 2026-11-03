#![forbid(unsafe_code)]

//! Primitive crittografiche e tipi chiave di Loquere.
//!
//! Questa crate espone firme Ed25519 tramite `ed25519-dalek`; non implementa
//! primitive crittografiche proprie.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

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
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        Self(key)
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

/// Dati cifrati con ChaCha20-Poly1305.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBox {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl SealedBox {
    /// Cifra i dati con chiave da 32 byte e dati associati autenticati.
    pub fn seal(
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Self, CryptoError> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::MessageTooLong)?;
        Ok(Self {
            nonce: nonce.into(),
            ciphertext,
        })
    }

    /// Autentica e decifra; il plaintext viene azzerato al rilascio.
    pub fn open(
        &self,
        key: &[u8; 32],
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Codifica la busta: versione 1, nonce da 12 byte, ciphertext e tag.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.nonce.len() + self.ciphertext.len());
        bytes.push(1);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Decodifica una busta versionata; la verifica del tag avviene in [`Self::open`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 1 + 12 + 16 || bytes[0] != 1 {
            return Err(CryptoError::InvalidCiphertext);
        }
        let nonce = bytes[1..13]
            .try_into()
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        Ok(Self {
            nonce,
            ciphertext: bytes[13..].to_vec(),
        })
    }
}

/// Envelope autenticato con chiave derivata da passphrase tramite Argon2id.
/// Parametri fissi per versione: 64 MiB, 3 passaggi, parallelismo 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassphraseEnvelope {
    salt: [u8; 16],
    sealed: SealedBox,
}

impl PassphraseEnvelope {
    /// Cifra con passphrase UTF-8; i dati associati legano il ciphertext al contesto.
    pub fn seal(
        passphrase: &str,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Self, CryptoError> {
        if passphrase.is_empty() {
            return Err(CryptoError::EmptyPassphrase);
        }
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_passphrase_key(passphrase, &salt)?;
        let sealed = SealedBox::seal(&key, plaintext, associated_data)?;
        Ok(Self { salt, sealed })
    }

    /// Decifra e autentica; passphrase errata e dati alterati danno lo stesso errore.
    pub fn open(
        &self,
        passphrase: &str,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if passphrase.is_empty() {
            return Err(CryptoError::AuthenticationFailed);
        }
        let key = derive_passphrase_key(passphrase, &self.salt)?;
        self.sealed.open(&key, associated_data)
    }

    /// Codifica versione, salt casuale e busta AEAD.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sealed = self.sealed.to_bytes();
        let mut bytes = Vec::with_capacity(1 + self.salt.len() + sealed.len());
        bytes.push(1);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&sealed);
        bytes
    }

    /// Decodifica l'envelope; la passphrase verifica il tag in [`Self::open`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 1 + 16 + 1 + 12 + 16 || bytes[0] != 1 {
            return Err(CryptoError::InvalidCiphertext);
        }
        let salt = bytes[1..17]
            .try_into()
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let sealed = SealedBox::from_bytes(&bytes[17..])?;
        Ok(Self { salt, sealed })
    }
}

fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| CryptoError::KdfFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| CryptoError::KdfFailure)?;
    Ok(key)
}

/// Errori esposti dalle primitive di questa crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// I byte non rappresentano una chiave pubblica Ed25519 valida.
    InvalidPublicKey,
    /// Firma non valida per chiave e messaggio forniti.
    InvalidSignature,
    /// La busta cifrata è troncata o usa una versione non supportata.
    InvalidCiphertext,
    /// Il tag AEAD non corrisponde a chiave, dati associati o ciphertext.
    AuthenticationFailed,
    /// Il messaggio supera i limiti del cifrario.
    MessageTooLong,
    /// Passphrase vuota non ammessa.
    EmptyPassphrase,
    /// Derivazione della chiave fallita.
    KdfFailure,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKey => formatter.write_str("chiave pubblica Ed25519 non valida"),
            Self::InvalidSignature => formatter.write_str("firma Ed25519 non valida"),
            Self::InvalidCiphertext => formatter.write_str("busta cifrata non valida"),
            Self::AuthenticationFailed => formatter.write_str("autenticazione AEAD non riuscita"),
            Self::MessageTooLong => {
                formatter.write_str("messaggio troppo lungo per ChaCha20-Poly1305")
            }
            Self::EmptyPassphrase => formatter.write_str("la passphrase non può essere vuota"),
            Self::KdfFailure => formatter.write_str("derivazione della chiave non riuscita"),
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

    #[test]
    fn sealed_box_round_trips_and_authenticates_associated_data() {
        let key = [9; 32];
        let sealed = SealedBox::seal(&key, b"segreto", b"account-key:v1").unwrap();
        let encoded = sealed.to_bytes();
        let decoded = SealedBox::from_bytes(&encoded).unwrap();

        assert_eq!(&*decoded.open(&key, b"account-key:v1").unwrap(), b"segreto");
        assert_eq!(
            decoded.open(&key, b"device-key:v1").unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn sealed_box_rejects_tampering_and_malformed_input() {
        let key = [3; 32];
        let mut bytes = SealedBox::seal(&key, b"payload", b"").unwrap().to_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = SealedBox::from_bytes(&bytes).unwrap();
        assert_eq!(
            tampered.open(&key, b"").unwrap_err(),
            CryptoError::AuthenticationFailed
        );
        assert_eq!(
            SealedBox::from_bytes(&[1, 2, 3]),
            Err(CryptoError::InvalidCiphertext)
        );
    }

    #[test]
    fn passphrase_envelope_round_trips_and_rejects_wrong_passphrase() {
        let envelope =
            PassphraseEnvelope::seal("passphrase di test", b"seme account", b"identity:v1")
                .unwrap();
        let decoded = PassphraseEnvelope::from_bytes(&envelope.to_bytes()).unwrap();

        assert_eq!(
            &*decoded.open("passphrase di test", b"identity:v1").unwrap(),
            b"seme account"
        );
        assert_eq!(
            decoded
                .open("passphrase errata", b"identity:v1")
                .unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn passphrase_envelope_rejects_empty_password_and_wrong_context() {
        assert_eq!(
            PassphraseEnvelope::seal("", b"x", b""),
            Err(CryptoError::EmptyPassphrase)
        );
        let envelope = PassphraseEnvelope::seal("secret", b"x", b"first").unwrap();
        assert_eq!(
            envelope.open("secret", b"second").unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }
}
