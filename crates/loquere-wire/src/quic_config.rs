use crate::tls::{
    build_client_tls_config, build_provisional_invite_server_tls_config, build_server_tls_config,
};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use loquere_crypto::{PublicKey, SecretKey};
use quinn_proto::TransportConfig;
use quinn_proto::crypto::{AeadKey as QuinnAeadKey, HandshakeTokenKey};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::sync::Arc;
use zeroize::Zeroizing;

const DATAGRAM_BUFFER_BYTES: usize = 1024 * 1024;

/// Crea config QUIC client sans-IO con TLS 1.3, mTLS Ed25519 raw keys,
/// ALPN `loquere/1` e 0-RTT disabilitato.
pub fn build_quic_client_config(
    local_key: Arc<SecretKey>,
    expected_peer: PublicKey,
) -> Result<quinn_proto::ClientConfig, QuicConfigError> {
    let tls = build_client_tls_config(local_key, expected_peer)?;
    let crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| QuicConfigError::CryptoConfiguration)?;
    let mut config = quinn_proto::ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_BYTES))
        .datagram_send_buffer_size(DATAGRAM_BUFFER_BYTES);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Crea config QUIC server sans-IO. L'orologio per i token è iniettato dal
/// chiamante; la crate non consulta il clock di sistema.
pub fn build_quic_server_config(
    local_key: Arc<SecretKey>,
    accepted_peers: impl IntoIterator<Item = [u8; 32]>,
    time_source: Arc<dyn quinn_proto::TimeSource>,
) -> Result<quinn_proto::ServerConfig, QuicConfigError> {
    let tls = build_server_tls_config(local_key, accepted_peers)?;
    build_server_from_tls(tls, time_source)
}

/// Configurazione QUIC per primo contatto. Non usare senza gate d'invito
/// verificato e applicazione obbligatoria delle restrizioni D-45.
pub fn build_provisional_invite_quic_server_config(
    local_key: Arc<SecretKey>,
    time_source: Arc<dyn quinn_proto::TimeSource>,
) -> Result<quinn_proto::ServerConfig, QuicConfigError> {
    let tls = build_provisional_invite_server_tls_config(local_key)?;
    build_server_from_tls(tls, time_source)
}

fn build_server_from_tls(
    tls: rustls::ServerConfig,
    time_source: Arc<dyn quinn_proto::TimeSource>,
) -> Result<quinn_proto::ServerConfig, QuicConfigError> {
    let crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|_| QuicConfigError::CryptoConfiguration)?;
    let mut config =
        quinn_proto::ServerConfig::new(Arc::new(crypto), Arc::new(TokenKey::generate()));
    let mut transport = TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_BYTES))
        .datagram_send_buffer_size(DATAGRAM_BUFFER_BYTES);
    config.transport = Arc::new(transport);
    config.time_source(time_source);
    Ok(config)
}

struct TokenKey(Zeroizing<[u8; 32]>);

impl TokenKey {
    fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key);
        Self(key)
    }
}

impl HandshakeTokenKey for TokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn QuinnAeadKey> {
        let hkdf = Hkdf::<Sha256>::new(Some(random_bytes), &*self.0);
        let mut key = Zeroizing::new([0u8; 32]);
        // HKDF-SHA256 cannot fail for this fixed, 32-byte output.
        if hkdf
            .expand(b"loquere:quic-retry-token:v1", &mut *key)
            .is_err()
        {
            key.copy_from_slice(&*self.0);
        }
        Box::new(TokenAead(key))
    }
}

struct TokenAead(Zeroizing<[u8; 32]>);

impl QuinnAeadKey for TokenAead {
    fn seal(
        &self,
        data: &mut Vec<u8>,
        additional_data: &[u8],
    ) -> Result<(), quinn_proto::crypto::CryptoError> {
        let cipher = ChaCha20Poly1305::new((&*self.0).into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: data,
                    aad: additional_data,
                },
            )
            .map_err(|_| quinn_proto::crypto::CryptoError)?;
        data.clear();
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], quinn_proto::crypto::CryptoError> {
        if data.len() < 12 + 16 {
            return Err(quinn_proto::crypto::CryptoError);
        }
        let cipher = ChaCha20Poly1305::new((&*self.0).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&data[..12]),
                    Payload {
                        msg: &data[12..],
                        aad: additional_data,
                    },
                )
                .map_err(|_| quinn_proto::crypto::CryptoError)?,
        );
        let plaintext_len = plaintext.len();
        data[..plaintext_len].copy_from_slice(&plaintext);
        Ok(&mut data[..plaintext_len])
    }
}

/// Errore di conversione dei parametri TLS/QUIC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicConfigError {
    /// TLS non può essere convertito in una configurazione QUIC valida.
    CryptoConfiguration,
    /// Configurazione TLS sottostante non valida.
    Tls(crate::TlsConfigError),
}

impl From<crate::TlsConfigError> for QuicConfigError {
    fn from(error: crate::TlsConfigError) -> Self {
        Self::Tls(error)
    }
}

impl core::fmt::Display for QuicConfigError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CryptoConfiguration => formatter.write_str("configurazione QUIC non valida"),
            Self::Tls(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for QuicConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    struct FixedTime(SystemTime);

    impl quinn_proto::TimeSource for FixedTime {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    #[test]
    fn creates_quic_configs_without_async_runtime() {
        let client_key = Arc::new(SecretKey::generate());
        let server_key = Arc::new(SecretKey::generate());
        let _client =
            build_quic_client_config(client_key.clone(), server_key.public_key()).unwrap();
        let _server = build_quic_server_config(
            server_key,
            [client_key.public_key().to_bytes()],
            Arc::new(FixedTime(SystemTime::UNIX_EPOCH + Duration::from_secs(10))),
        )
        .unwrap();
    }

    #[test]
    fn quic_retry_token_aead_authenticates_context() {
        let token_key = TokenKey::generate();
        let aead = token_key.aead_from_hkdf(b"random retry token context");
        let mut data = b"token payload".to_vec();
        aead.seal(&mut data, b"address binding").unwrap();
        assert_eq!(
            aead.open(&mut data, b"address binding").unwrap(),
            b"token payload"
        );

        let mut tampered = b"token payload".to_vec();
        aead.seal(&mut tampered, b"address binding").unwrap();
        assert!(aead.open(&mut tampered, b"wrong address").is_err());
    }
}
