#![forbid(unsafe_code)]

//! Conversazioni cifrate con MLS RFC 9420.
//!
//! Questa prima base usa lo storage in memoria fornito da OpenMLS; la
//! persistenza cifrata e la replica dei commit sono passi separati e non sono
//! simulati da questo modulo.

use loquere_crypto::SecretKey;
use loquere_store::RecordLog;
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, MlsGroup,
    MlsGroupCreateConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent,
    ProtocolVersion, StagedWelcome,
};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::{
    OpenMlsProvider,
    signatures::{Signer, SignerError},
    types::SignatureScheme,
};
use std::fmt;
use std::{collections::HashMap, path::Path};

/// Suite MLS di Loquere (D-16): X25519, ChaCha20-Poly1305, SHA-256 ed Ed25519.
pub const LOQUERE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Gruppo MLS locale. Il provider e lo stato sono confinati a questo oggetto.
pub struct Conversation {
    provider: LoquereProvider,
    group: MlsGroup,
    signer: DeviceSigner,
    persistence: Option<RecordLog>,
}

#[derive(Default)]
struct LoquereProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

type StorageEntries = HashMap<Vec<u8>, Vec<u8>>;
type DecodedSnapshot = (Vec<u8>, StorageEntries);

impl OpenMlsProvider for LoquereProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// Commit, Welcome e ratchet tree pubblici da distribuire al nuovo membro.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberWelcome {
    /// Commit MLS per i membri già presenti.
    pub commit: Vec<u8>,
    /// Welcome MLS cifrato per il nuovo membro.
    pub welcome: Vec<u8>,
    /// Albero ratchet pubblico necessario al join.
    pub ratchet_tree: Vec<u8>,
}

/// Errori durante creazione o gestione di una conversazione MLS.
#[derive(Debug)]
pub enum ChatError {
    /// MLS/OpenMLS ha rifiutato l'operazione o il messaggio.
    Mls(String),
    /// Il messaggio ricevuto non è un messaggio applicativo MLS.
    NotApplicationMessage,
    /// Il messaggio supera il limite di payload di un messaggio applicativo.
    MessageTooLarge,
    /// Errore del log persistente cifrato.
    Store(String),
    /// Stato MLS persistente assente o malformato.
    InvalidSnapshot,
}

impl fmt::Display for ChatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mls(error) => write!(formatter, "errore MLS: {error}"),
            Self::NotApplicationMessage => {
                formatter.write_str("il messaggio MLS non contiene testo applicativo")
            }
            Self::MessageTooLarge => formatter.write_str("messaggio oltre il limite MLS"),
            Self::Store(error) => write!(formatter, "errore persistenza MLS: {error}"),
            Self::InvalidSnapshot => formatter.write_str("snapshot MLS non valido"),
        }
    }
}

impl std::error::Error for ChatError {}

impl Conversation {
    /// Crea una conversazione MLS privata con il dispositivo corrente come
    /// primo membro. La chiave Ed25519 è la stessa identità di dispositivo
    /// usata per `DeviceCert` e TLS.
    pub fn create(device_key: SecretKey) -> Result<Self, ChatError> {
        let signer = DeviceSigner(device_key);
        let provider = LoquereProvider::default();
        let credential = credential_for(&signer);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(LOQUERE_CIPHERSUITE)
            .build();
        let group = MlsGroup::new(&provider, &signer, &config, credential)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        Ok(Self {
            provider,
            group,
            signer,
            persistence: None,
        })
    }

    /// Crea un gruppo e salva lo stato OpenMLS in un log cifrato con la chiave
    /// di storage derivata dal master key locale.
    pub fn create_persistent(
        device_key: SecretKey,
        path: impl AsRef<Path>,
        storage_key: [u8; 32],
    ) -> Result<Self, ChatError> {
        let mut conversation = Self::create(device_key)?;
        conversation.persistence = Some(open_state_log(path, storage_key)?);
        conversation.persist_state()?;
        Ok(conversation)
    }

    /// Riapre l'ultimo snapshot completo del gruppo dopo averne verificato il
    /// log AEAD. La chiave dispositivo deve essere quella associata al gruppo.
    pub fn open_persistent(
        device_key: SecretKey,
        path: impl AsRef<Path>,
        storage_key: [u8; 32],
    ) -> Result<Self, ChatError> {
        let opened = RecordLog::open(path, storage_key)
            .map_err(|error| ChatError::Store(error.to_string()))?;
        let snapshot = opened.records.last().ok_or(ChatError::InvalidSnapshot)?;
        let (group_id, entries) = decode_snapshot(snapshot)?;
        let provider = provider_from_entries(entries);
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
            .map_err(|error| ChatError::Mls(error.to_string()))?
            .ok_or(ChatError::InvalidSnapshot)?;
        Ok(Self {
            provider,
            group,
            signer: DeviceSigner(device_key),
            persistence: Some(opened.log),
        })
    }

    /// Cifra un messaggio applicativo con l'epoch MLS corrente.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ChatError> {
        if plaintext.len() > 64 * 1024 {
            return Err(ChatError::MessageTooLarge);
        }
        let message = self
            .group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        self.persist_state()?;
        message
            .tls_serialize_detached()
            .map_err(|error| ChatError::Mls(error.to_string()))
    }

    /// Produce un KeyPackage MLS autenticato dalla chiave dispositivo.
    pub fn key_package(&mut self) -> Result<Vec<u8>, ChatError> {
        let key_package = KeyPackage::builder()
            .build(
                LOQUERE_CIPHERSUITE,
                &self.provider,
                &self.signer,
                credential_for(&self.signer),
            )
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        let bytes = MlsMessageOut::from(key_package.key_package().clone())
            .tls_serialize_detached()
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        self.persist_state()?;
        Ok(bytes)
    }

    /// Aggiunge un membro usando il suo KeyPackage; il commit viene applicato
    /// localmente e restituito per l'ordinamento/distribuzione nel DAG.
    pub fn add_member(&mut self, package: &[u8]) -> Result<MemberWelcome, ChatError> {
        let package_message = MlsMessageIn::tls_deserialize_exact(package)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        let package = match package_message.extract() {
            MlsMessageBodyIn::KeyPackage(package) => package
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|error| ChatError::Mls(error.to_string()))?,
            _ => return Err(ChatError::NotApplicationMessage),
        };
        let (commit, welcome, _) = self
            .group
            .add_members(&self.provider, &self.signer, &[package])
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        self.persist_state()?;
        Ok(MemberWelcome {
            commit: commit
                .tls_serialize_detached()
                .map_err(|error| ChatError::Mls(error.to_string()))?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|error| ChatError::Mls(error.to_string()))?,
            ratchet_tree: self
                .group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|error| ChatError::Mls(error.to_string()))?,
        })
    }

    /// Entra in un gruppo attraverso un Welcome validato da OpenMLS.
    pub fn join(
        mut pending_member: Self,
        welcome_bytes: &[u8],
        ratchet_tree_bytes: &[u8],
    ) -> Result<Self, ChatError> {
        let provider = pending_member.provider;
        let signer = pending_member.signer;
        let persistence = pending_member.persistence;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(LOQUERE_CIPHERSUITE)
            .build();
        let welcome_message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        let welcome = match welcome_message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(ChatError::NotApplicationMessage),
        };
        let ratchet_tree =
            openmls::prelude::RatchetTreeIn::tls_deserialize_exact(ratchet_tree_bytes)
                .map_err(|error| ChatError::Mls(error.to_string()))?;
        let group = StagedWelcome::new_from_welcome(
            &provider,
            config.join_config(),
            welcome,
            Some(ratchet_tree),
        )
        .map_err(|error| ChatError::Mls(error.to_string()))?
        .into_group(&provider)
        .map_err(|error| ChatError::Mls(error.to_string()))?;
        pending_member.group = group;
        let mut joined = Self {
            provider,
            group: pending_member.group,
            signer,
            persistence,
        };
        joined.persist_state()?;
        Ok(joined)
    }

    /// Elabora e applica un commit ricevuto, avanzando l'epoch MLS.
    pub fn process_commit(&mut self, bytes: &[u8]) -> Result<(), ChatError> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        let processed = self
            .group
            .process_message(&self.provider, protocol_message)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => self
                .group
                .merge_staged_commit(&self.provider, *commit)
                .map_err(|error| ChatError::Mls(error.to_string()))
                .and_then(|()| self.persist_state()),
            _ => Err(ChatError::NotApplicationMessage),
        }
    }

    /// Autentica e decifra un messaggio MLS. Commit e proposte sono rifiutati
    /// da questa API e dovranno essere gestiti dal coordinatore del DAG.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ChatError> {
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        let processed = self
            .group
            .process_message(&self.provider, protocol_message)
            .map_err(|error| ChatError::Mls(error.to_string()))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                let plaintext = message.into_bytes();
                self.persist_state()?;
                Ok(plaintext)
            }
            _ => Err(ChatError::NotApplicationMessage),
        }
    }

    /// Epoch MLS attuale.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Identificatore MLS del gruppo, non segreto.
    pub fn group_id(&self) -> &[u8] {
        self.group.group_id().as_slice()
    }

    fn persist_state(&mut self) -> Result<(), ChatError> {
        let Some(log) = &mut self.persistence else {
            return Ok(());
        };
        let entries = self
            .provider
            .storage
            .values
            .read()
            .map_err(|_| ChatError::InvalidSnapshot)?;
        let snapshot = encode_snapshot(self.group.group_id().as_slice(), &entries)?;
        log.append(&snapshot)
            .map_err(|error| ChatError::Store(error.to_string()))?;
        Ok(())
    }
}

const SNAPSHOT_MAGIC: &[u8; 8] = b"LQMLS\0\0\x01";

fn open_state_log(path: impl AsRef<Path>, key: [u8; 32]) -> Result<RecordLog, ChatError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| ChatError::Store(error.to_string()))?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ChatError::Store(error.to_string()))?;
    RecordLog::open(path, key)
        .map(|opened| opened.log)
        .map_err(|error| ChatError::Store(error.to_string()))
}

fn encode_snapshot(
    group_id: &[u8],
    entries: &HashMap<Vec<u8>, Vec<u8>>,
) -> Result<Vec<u8>, ChatError> {
    let mut bytes = SNAPSHOT_MAGIC.to_vec();
    put_bytes(&mut bytes, group_id)?;
    let count = u32::try_from(entries.len()).map_err(|_| ChatError::InvalidSnapshot)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_unstable_by_key(|(key, _)| key.as_slice());
    for (key, value) in sorted {
        put_bytes(&mut bytes, key)?;
        put_bytes(&mut bytes, value)?;
    }
    Ok(bytes)
}

fn decode_snapshot(bytes: &[u8]) -> Result<DecodedSnapshot, ChatError> {
    if !bytes.starts_with(SNAPSHOT_MAGIC) {
        return Err(ChatError::InvalidSnapshot);
    }
    let mut cursor = SNAPSHOT_MAGIC.len();
    let group_id = take_bytes(bytes, &mut cursor)?;
    let count = take_u32(bytes, &mut cursor)? as usize;
    if count > 1_000_000 {
        return Err(ChatError::InvalidSnapshot);
    }
    let mut entries = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = take_bytes(bytes, &mut cursor)?;
        let value = take_bytes(bytes, &mut cursor)?;
        if entries.insert(key, value).is_some() {
            return Err(ChatError::InvalidSnapshot);
        }
    }
    if cursor != bytes.len() {
        return Err(ChatError::InvalidSnapshot);
    }
    Ok((group_id, entries))
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ChatError> {
    let length = u32::try_from(value.len()).map_err(|_| ChatError::InvalidSnapshot)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ChatError> {
    let end = cursor.checked_add(4).ok_or(ChatError::InvalidSnapshot)?;
    let encoded = bytes.get(*cursor..end).ok_or(ChatError::InvalidSnapshot)?;
    *cursor = end;
    Ok(u32::from_be_bytes(
        encoded.try_into().map_err(|_| ChatError::InvalidSnapshot)?,
    ))
}

fn take_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, ChatError> {
    let length = take_u32(bytes, cursor)? as usize;
    let end = cursor
        .checked_add(length)
        .ok_or(ChatError::InvalidSnapshot)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ChatError::InvalidSnapshot)?
        .to_vec();
    *cursor = end;
    Ok(value)
}

fn provider_from_entries(entries: StorageEntries) -> LoquereProvider {
    LoquereProvider {
        crypto: RustCrypto::default(),
        storage: MemoryStorage {
            values: std::sync::RwLock::new(entries),
        },
    }
}

fn credential_for(signer: &DeviceSigner) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(signer.public_key().to_vec()).into(),
        signature_key: signer.public_key().to_vec().into(),
    }
}

struct DeviceSigner(SecretKey);

impl DeviceSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key().to_bytes()
    }
}

impl Signer for DeviceSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_crypto::Signature;

    #[test]
    fn group_uses_device_identity_suite_and_encrypts_messages() {
        let mut conversation = Conversation::create(SecretKey::generate()).unwrap();
        assert_eq!(conversation.epoch(), 0);
        assert!(!conversation.group_id().is_empty());

        let ciphertext = conversation.encrypt(b"messaggio MLS").unwrap();
        assert_ne!(ciphertext, b"messaggio MLS");
    }

    #[test]
    fn rejects_oversized_and_malformed_messages() {
        let mut conversation = Conversation::create(SecretKey::generate()).unwrap();
        assert!(matches!(
            conversation.encrypt(&vec![0; 64 * 1024 + 1]),
            Err(ChatError::MessageTooLarge)
        ));
        assert!(conversation.decrypt(b"not an MLS message").is_err());
    }

    #[test]
    fn device_signer_is_ed25519_and_matches_device_public_key() {
        let secret = SecretKey::generate();
        let expected_public = secret.public_key().to_bytes();
        let signer = DeviceSigner(secret);
        assert_eq!(signer.public_key(), expected_public);
        let payload = b"MLS signer self-test";
        let signature: Signature = signer.0.sign(payload);
        signer.0.public_key().verify(payload, &signature).unwrap();
        assert_eq!(signer.signature_scheme(), SignatureScheme::ED25519);
    }

    #[test]
    fn welcomes_second_device_and_exchanges_mls_messages() {
        let mut alice = Conversation::create(SecretKey::generate()).unwrap();
        let mut bob_identity = Conversation::create(SecretKey::generate()).unwrap();
        let package = bob_identity.key_package().unwrap();
        let welcome = alice.add_member(&package).unwrap();
        let mut bob =
            Conversation::join(bob_identity, &welcome.welcome, &welcome.ratchet_tree).unwrap();
        assert_eq!(alice.epoch(), bob.epoch());

        let ciphertext = alice.encrypt(b"ciao Bob").unwrap();
        assert_eq!(bob.decrypt(&ciphertext).unwrap(), b"ciao Bob");
        let ciphertext = bob.encrypt(b"ciao Alice").unwrap();
        assert_eq!(alice.decrypt(&ciphertext).unwrap(), b"ciao Alice");
    }

    #[test]
    fn persistent_group_reopens_and_continues_message_ratchets() {
        let path = std::env::temp_dir().join(format!(
            "loquere-mls-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = SecretKey::generate();
        let key_bytes = key.to_bytes();
        let storage_key = [0x42; 32];
        let mut alice = Conversation::create_persistent(key, &path, storage_key).unwrap();
        let mut bob = Conversation::create(SecretKey::generate()).unwrap();
        let ciphertext = alice.encrypt(b"before restart").unwrap();
        assert!(!ciphertext.is_empty());
        let epoch = alice.epoch();
        drop(alice);

        let mut reopened =
            Conversation::open_persistent(SecretKey::from_bytes(*key_bytes), &path, storage_key)
                .unwrap();
        assert_eq!(reopened.epoch(), epoch);
        let package = bob.key_package().unwrap();
        let welcome = reopened.add_member(&package).unwrap();
        let bob = Conversation::join(bob, &welcome.welcome, &welcome.ratchet_tree).unwrap();
        let ciphertext = reopened.encrypt(b"after restart").unwrap();
        let mut bob = bob;
        assert_eq!(bob.decrypt(&ciphertext).unwrap(), b"after restart");
        drop(reopened);
        let mut reopened =
            Conversation::open_persistent(SecretKey::from_bytes(*key_bytes), &path, storage_key)
                .unwrap();
        assert_eq!(reopened.epoch(), bob.epoch());
        let ciphertext = reopened.encrypt(b"after second restart").unwrap();
        assert_eq!(bob.decrypt(&ciphertext).unwrap(), b"after second restart");
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }
}
