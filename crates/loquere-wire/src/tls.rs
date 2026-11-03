use loquere_crypto::{CryptoError, PublicKey, SecretKey, Signature};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureAlgorithm,
    SignatureScheme,
};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Costruisce una configurazione TLS 1.3 client con chiave pubblica grezza
/// Ed25519 e un solo peer ammesso.
pub fn build_client_tls_config(
    local_key: Arc<SecretKey>,
    expected_peer: PublicKey,
) -> Result<rustls::ClientConfig, TlsConfigError> {
    let cert = certified_key(local_key)?;
    let verifier = Arc::new(PeerVerifier::new([expected_peer.to_bytes()]));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsConfigError::InvalidProvider)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(cert),
        ));
    config.alpn_protocols = vec![b"loquere/1".to_vec()];
    config.enable_early_data = false;
    Ok(config)
}

/// Costruisce una configurazione TLS 1.3 server con autenticazione client
/// obbligatoria e lista di chiavi dispositivo autorizzate.
pub fn build_server_tls_config(
    local_key: Arc<SecretKey>,
    accepted_peers: impl IntoIterator<Item = [u8; 32]>,
) -> Result<rustls::ServerConfig, TlsConfigError> {
    let cert = certified_key(local_key)?;
    let verifier = Arc::new(PeerVerifier::new(accepted_peers));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsConfigError::InvalidProvider)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(cert),
        ));
    config.alpn_protocols = vec![b"loquere/1".to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
}

fn certified_key(secret: Arc<SecretKey>) -> Result<Arc<CertifiedKey>, TlsConfigError> {
    let public = secret.public_key().to_bytes();
    let mut spki = [0u8; 44];
    spki[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
    spki[ED25519_SPKI_PREFIX.len()..].copy_from_slice(&public);
    let key = Arc::new(LoquereSigningKey { secret, spki });
    let cert = CertificateDer::from(spki.to_vec());
    Ok(Arc::new(CertifiedKey::new(vec![cert], key)))
}

struct LoquereSigningKey {
    secret: Arc<SecretKey>,
    spki: [u8; 44],
}

impl fmt::Debug for LoquereSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoquereEd25519SigningKey")
    }
}

impl SigningKey for LoquereSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(LoquereSigner(self.secret.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        Some(rustls::pki_types::SubjectPublicKeyInfoDer::from(
            &self.spki[..],
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct LoquereSigner(Arc<SecretKey>);

impl fmt::Debug for LoquereSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoquereEd25519Signer")
    }
}

impl Signer for LoquereSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[derive(Debug)]
struct PeerVerifier {
    allowed: HashSet<[u8; 32]>,
    root_hints: Vec<DistinguishedName>,
}

impl PeerVerifier {
    fn new(keys: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            allowed: keys.into_iter().collect(),
            root_hints: Vec::new(),
        }
    }

    fn check_peer(&self, cert: &CertificateDer<'_>) -> Result<PublicKey, Error> {
        let public = public_key_from_spki(cert.as_ref())
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !self.allowed.contains(&public.to_bytes()) {
            return Err(Error::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        Ok(public)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(Error::InvalidCertificate(CertificateError::BadSignature));
        }
        let public = self.check_peer(cert)?;
        let signature: [u8; 64] = dss
            .signature()
            .try_into()
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadSignature))?;
        public
            .verify(message, &Signature::from_bytes(signature))
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadSignature))?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() || !ocsp_response.is_empty() {
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        self.check_peer(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        self.check_peer(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn public_key_from_spki(spki: &[u8]) -> Option<PublicKey> {
    if spki.len() != 44 || spki[..12] != ED25519_SPKI_PREFIX {
        return None;
    }
    PublicKey::from_bytes(spki[12..].try_into().ok()?).ok()
}

/// Errore nella preparazione dei parametri TLS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsConfigError {
    /// Provider crittografico o versione TLS non disponibile.
    InvalidProvider,
    /// Chiave pubblica Ed25519 o sua codifica SPKI non valida.
    InvalidIdentity,
}

impl From<CryptoError> for TlsConfigError {
    fn from(_: CryptoError) -> Self {
        Self::InvalidIdentity
    }
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProvider => formatter.write_str("provider TLS non disponibile"),
            Self::InvalidIdentity => formatter.write_str("identità Ed25519 non valida"),
        }
    }
}

impl std::error::Error for TlsConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn builds_mutual_tls_configs_requiring_only_rfc7250_raw_keys() {
        let local = Arc::new(SecretKey::generate());
        let peer = SecretKey::generate();
        let client = build_client_tls_config(local.clone(), peer.public_key()).unwrap();
        let server = build_server_tls_config(local, [peer.public_key().to_bytes()]).unwrap();

        assert_eq!(client.alpn_protocols, [b"loquere/1".to_vec()]);
        assert_eq!(server.alpn_protocols, [b"loquere/1".to_vec()]);
        assert_eq!(client.max_fragment_size, None);
        assert_eq!(server.max_early_data_size, 0);
    }

    #[test]
    fn peer_verifier_rejects_unlisted_key_and_non_spki_certificate() {
        let expected = SecretKey::generate().public_key();
        let stranger = SecretKey::generate().public_key();
        let verifier = PeerVerifier::new([expected.to_bytes()]);
        let spki = {
            let mut bytes = ED25519_SPKI_PREFIX.to_vec();
            bytes.extend_from_slice(&stranger.to_bytes());
            CertificateDer::from(bytes)
        };
        assert!(matches!(
            verifier.check_peer(&spki),
            Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
        ));
        assert!(
            verifier
                .check_peer(&CertificateDer::from(vec![1, 2, 3]))
                .is_err()
        );
    }

    #[test]
    fn rustls_completes_mutual_tls13_handshake_with_raw_ed25519_keys() {
        let client_secret = Arc::new(SecretKey::generate());
        let server_secret = Arc::new(SecretKey::generate());
        let client_public = client_secret.public_key();
        let server_public = server_secret.public_key();
        let client_config =
            Arc::new(build_client_tls_config(client_secret, server_public).unwrap());
        let server_config =
            Arc::new(build_server_tls_config(server_secret, [client_public.to_bytes()]).unwrap());
        let server_name = ServerName::try_from("loquere".to_owned()).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();

        for _ in 0..10 {
            let mut client_to_server = Vec::new();
            client.write_tls(&mut client_to_server).unwrap();
            if !client_to_server.is_empty() {
                server.read_tls(&mut Cursor::new(client_to_server)).unwrap();
                server.process_new_packets().unwrap();
            }

            let mut server_to_client = Vec::new();
            server.write_tls(&mut server_to_client).unwrap();
            if !server_to_client.is_empty() {
                client.read_tls(&mut Cursor::new(server_to_client)).unwrap();
                client.process_new_packets().unwrap();
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
        }
        panic!("TLS 1.3 handshake did not complete");
    }
}
