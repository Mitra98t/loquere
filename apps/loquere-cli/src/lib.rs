//! Comandi CLI di Loquere e formattazione dei relativi risultati.

mod terminal;

use loquere_chat::{ChatError, Conversation};
use loquere_identity::{Account, DeviceRole, IdentityError, Invitation, InviteOptions};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use zeroize::Zeroizing;

/// Dati pubblici di un invito dopo la verifica crittografica.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteSummary {
    /// Account indicato nel certificato firmato.
    pub account_id: String,
    /// Nome suggerito da chi ha creato l'invito.
    pub display_name: String,
    /// Timestamp Unix; zero indica che l'invito non scade.
    pub expires_at: u32,
    /// Se il token è monouso.
    pub single_use: bool,
    /// Se il creatore consente l'accettazione automatica.
    pub auto_accept: bool,
    /// Candidati di rete inclusi nell'invito.
    pub candidates: Vec<InviteCandidateSummary>,
}

/// Indirizzo IP e porta pubblicati nell'invito.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteCandidateSummary {
    /// Indirizzo IP.
    pub address: IpAddr,
    /// Porta UDP.
    pub port: u16,
}

/// Decodifica un URI/codice invito e ne verifica firma e certificato.
pub fn inspect_invite(code: &str) -> Result<InviteSummary, loquere_identity::IdentityError> {
    let invite = Invitation::parse_code(code)?;
    let options = invite.options();
    Ok(InviteSummary {
        account_id: invite.account_id().to_base32(),
        display_name: invite.display_name().to_owned(),
        expires_at: invite.expires_at(),
        single_use: options.single_use,
        auto_accept: options.auto_accept,
        candidates: invite
            .candidates()
            .iter()
            .map(|candidate| InviteCandidateSummary {
                address: candidate.address,
                port: candidate.port,
            })
            .collect(),
    })
}

/// Formatta i dati verificati senza mai mostrare il token dell'invito.
pub fn format_invite(summary: &InviteSummary) -> String {
    let expiration = if summary.expires_at == 0 {
        "mai (timestamp 0)".to_owned()
    } else {
        format!("Unix {}", summary.expires_at)
    };
    let candidates = if summary.candidates.is_empty() {
        "  (nessuno)".to_owned()
    } else {
        summary
            .candidates
            .iter()
            .map(|candidate| format!("  {}:{}", candidate.address, candidate.port))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "Invito Loquere verificato\nAccount: {}\nNome: {}\nScadenza: {}\nMonouso: {}\nAccettazione automatica: {}\nCandidati UDP:\n{}",
        summary.account_id,
        summary.display_name,
        expiration,
        yes_no(summary.single_use),
        yes_no(summary.auto_accept),
        candidates,
    )
}

/// Crea un account e salva la sua identità cifrata senza sovrascrivere file.
pub fn create_identity_file(
    path: impl AsRef<Path>,
    device_name: String,
    passphrase: &str,
    created_at: u64,
) -> Result<String, IdentityFileError> {
    let account = Account::create(device_name, created_at).map_err(IdentityFileError::Identity)?;
    let encrypted = account
        .protect_with_passphrase(passphrase)
        .map_err(IdentityFileError::Identity)?;
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(IdentityFileError::Io)?;
    if let Err(error) = file.write_all(&encrypted).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(IdentityFileError::Io(error));
    }
    Ok(account.account_id().to_base32())
}

/// Riepilogo pubblico di un'identità sbloccata e verificata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySummary {
    /// Identificatore pubblico dell'account.
    pub account_id: String,
    /// Identificatore pubblico del dispositivo corrente.
    pub device_id: String,
    /// Nome certificato del dispositivo.
    pub device_name: String,
    /// Ruolo firmato dal certificato.
    pub role: DeviceRole,
    /// Timestamp Unix di creazione del certificato.
    pub created_at: u64,
}

/// Informazioni pubbliche essenziali di una conversazione MLS locale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatSummary {
    /// Identificatore del gruppo MLS in esadecimale.
    pub group_id: String,
    /// Epoch del gruppo.
    pub epoch: u64,
}

/// Sblocca un'identità e restituisce l'account per l'uso da parte del nodo.
pub fn unlock_identity_file(
    path: impl AsRef<Path>,
    passphrase: &str,
) -> Result<Account, IdentityFileError> {
    let encoded = fs::read(path).map_err(IdentityFileError::Io)?;
    Account::unprotect_with_passphrase(&encoded, passphrase).map_err(IdentityFileError::Identity)
}

/// Crea un gruppo MLS persistente usando la chiave dispositivo e una chiave
/// di storage derivata dal master key dell'identità sbloccata.
pub fn create_chat_state(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
) -> Result<ChatSummary, ChatFileError> {
    let account =
        unlock_identity_file(identity_path, passphrase).map_err(ChatFileError::Identity)?;
    let storage_key = account
        .derive_storage_key(b"loquere:mls:state:v1")
        .map_err(|error| ChatFileError::Identity(IdentityFileError::Identity(error)))?;
    let device_key = loquere_crypto::SecretKey::from_bytes(*account.device_signing_key());
    let conversation = Conversation::create_persistent(device_key, state_path, *storage_key)
        .map_err(ChatFileError::Chat)?;
    Ok(chat_summary(&conversation))
}

/// Apre una conversazione MLS cifrata usando l'identità che ne possiede le chiavi.
pub fn open_chat_state(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
) -> Result<Conversation, ChatFileError> {
    let account =
        unlock_identity_file(identity_path, passphrase).map_err(ChatFileError::Identity)?;
    let storage_key = account
        .derive_storage_key(b"loquere:mls:state:v1")
        .map_err(|error| ChatFileError::Identity(IdentityFileError::Identity(error)))?;
    let device_key = loquere_crypto::SecretKey::from_bytes(*account.device_signing_key());
    Conversation::open_persistent(device_key, state_path, *storage_key).map_err(ChatFileError::Chat)
}

/// Ispeziona un gruppo MLS persistente senza esporne lo stato segreto.
pub fn inspect_chat_state(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
) -> Result<ChatSummary, ChatFileError> {
    open_chat_state(identity_path, passphrase, state_path)
        .map(|conversation| chat_summary(&conversation))
}

fn chat_summary(conversation: &Conversation) -> ChatSummary {
    ChatSummary {
        group_id: encode_hex(conversation.group_id()),
        epoch: conversation.epoch(),
    }
}

/// Apre e verifica un'identità protetta da passphrase.
pub fn inspect_identity_file(
    path: impl AsRef<Path>,
    passphrase: &str,
) -> Result<IdentitySummary, IdentityFileError> {
    let account = unlock_identity_file(path, passphrase)?;
    let certificate = account.device_cert();
    certificate.verify().map_err(IdentityFileError::Identity)?;
    Ok(IdentitySummary {
        account_id: account.account_id().to_base32(),
        device_id: encode_hex(&certificate.device_id().to_bytes()),
        device_name: certificate.name().to_owned(),
        role: certificate.role(),
        created_at: certificate.created_at(),
    })
}

/// Crea un invito firmato dall'identità locale, senza contattare il destinatario.
pub fn create_invite_from_file(
    path: impl AsRef<Path>,
    passphrase: &str,
    display_name: String,
    expires_at: u32,
) -> Result<String, IdentityFileError> {
    let encoded = fs::read(path).map_err(IdentityFileError::Io)?;
    let account = Account::unprotect_with_passphrase(&encoded, passphrase)
        .map_err(IdentityFileError::Identity)?;
    let invite = account
        .create_invite(
            display_name,
            expires_at,
            InviteOptions {
                single_use: true,
                auto_accept: false,
            },
            Vec::new(),
        )
        .map_err(IdentityFileError::Identity)?;
    invite.to_uri().map_err(IdentityFileError::Identity)
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

/// Formatta i dati pubblici di un'identità, senza accedere alle chiavi private.
pub fn format_identity(summary: &IdentitySummary) -> String {
    let role = match summary.role {
        DeviceRole::Admin => "Admin",
        DeviceRole::Member => "Member",
    };
    format!(
        "Identità Loquere verificata\nAccount: {}\nDispositivo: {}\nID dispositivo: {}\nRuolo: {}\nCreato (Unix): {}",
        summary.account_id, summary.device_name, summary.device_id, role, summary.created_at,
    )
}

/// Chiede e conferma una passphrase senza mostrarla sul terminale.
pub fn prompt_passphrase() -> Result<Zeroizing<String>, IdentityFileError> {
    let first = terminal::read_hidden("Passphrase: ").map_err(IdentityFileError::Io)?;
    let second = terminal::read_hidden("Conferma passphrase: ").map_err(IdentityFileError::Io)?;
    if first != second {
        return Err(IdentityFileError::PassphraseMismatch);
    }
    if first.is_empty() {
        return Err(IdentityFileError::EmptyPassphrase);
    }
    Ok(first)
}

/// Chiede la passphrase di un'identità esistente senza mostrarla.
pub fn prompt_existing_passphrase() -> Result<Zeroizing<String>, IdentityFileError> {
    let passphrase = terminal::read_hidden("Passphrase: ").map_err(IdentityFileError::Io)?;
    if passphrase.is_empty() {
        return Err(IdentityFileError::EmptyPassphrase);
    }
    Ok(passphrase)
}

/// Errori nell'apertura o creazione di uno stato chat persistente.
#[derive(Debug)]
pub enum ChatFileError {
    /// Impossibile sbloccare o usare l'identità.
    Identity(IdentityFileError),
    /// Operazione MLS o log cifrato non riuscita.
    Chat(ChatError),
}

impl std::fmt::Display for ChatFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(error) => write!(formatter, "identità non disponibile: {error}"),
            Self::Chat(error) => write!(formatter, "conversazione non disponibile: {error}"),
        }
    }
}

impl std::error::Error for ChatFileError {}

/// Errori della creazione di un file d'identità.
#[derive(Debug)]
pub enum IdentityFileError {
    /// Errore crittografico o di codifica dell'identità.
    Identity(IdentityError),
    /// Errore del filesystem o del terminale.
    Io(std::io::Error),
    /// Le due passphrase inserite non coincidono.
    PassphraseMismatch,
    /// La passphrase non può essere vuota.
    EmptyPassphrase,
}

impl std::fmt::Display for IdentityFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(error) => write!(formatter, "identità non valida: {error}"),
            Self::Io(error) => write!(formatter, "errore I/O: {error}"),
            Self::PassphraseMismatch => formatter.write_str("le passphrase non coincidono"),
            Self::EmptyPassphrase => formatter.write_str("la passphrase non può essere vuota"),
        }
    }
}

impl std::error::Error for IdentityFileError {}

fn yes_no(value: bool) -> &'static str {
    if value { "sì" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_identity::{Account, InviteCandidate, InviteOptions};

    #[test]
    fn invite_inspection_verifies_and_displays_public_fields_without_token() {
        let account = Account::create("Portatile Alice".to_owned(), 1).unwrap();
        let invite = account
            .create_invite(
                "Alice".to_owned(),
                1234,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![InviteCandidate {
                    address: "192.0.2.4".parse().unwrap(),
                    port: 4567,
                }],
            )
            .unwrap();

        let summary = inspect_invite(&invite.to_uri().unwrap()).unwrap();
        let rendered = format_invite(&summary);
        assert_eq!(summary.account_id, account.account_id().to_base32());
        assert!(rendered.contains("192.0.2.4:4567"));
        assert!(rendered.contains("Monouso: sì"));
        assert!(!rendered.contains(&format!("{:?}", invite.token())));
    }

    #[test]
    fn invite_inspection_rejects_malformed_or_tampered_codes() {
        assert!(inspect_invite("loquere://invite/nope").is_err());
    }

    #[test]
    fn identity_file_is_encrypted_private_and_never_overwritten() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "loquere-cli-identity-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("identity.loq");
        let account_id =
            create_identity_file(&path, "Portatile".to_owned(), "a strong passphrase", 1).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(8).any(|window| window == b"LOQID\x01\0\0"));
        assert!(create_identity_file(&path, "Altro".to_owned(), "password", 2).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(account_id.len(), 52);
        let summary = inspect_identity_file(&path, "a strong passphrase").unwrap();
        assert_eq!(summary.account_id, account_id);
        assert_eq!(summary.device_name, "Portatile");
        assert!(inspect_identity_file(&path, "wrong passphrase").is_err());
        let state_path = directory.join("conversation.mls");
        let chat = create_chat_state(&path, "a strong passphrase", &state_path).unwrap();
        assert_eq!(chat.epoch, 0);
        let reopened = inspect_chat_state(&path, "a strong passphrase", &state_path).unwrap();
        assert_eq!(reopened, chat);
        assert!(open_chat_state(&path, "wrong passphrase", &state_path).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn invite_creation_from_file_is_signed_and_defaults_to_manual_single_use() {
        let account = Account::create("PC Alice".to_owned(), 1).unwrap();
        let protected = account
            .protect_with_passphrase("a strong passphrase")
            .unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "loquere-cli-invite-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::write(&path, protected).unwrap();

        let code =
            create_invite_from_file(&path, "a strong passphrase", "Alice".to_owned(), 99).unwrap();
        let invite = Invitation::parse_code(&code).unwrap();
        assert_eq!(invite.account_id(), account.account_id());
        assert_eq!(invite.display_name(), "Alice");
        assert!(invite.options().single_use);
        assert!(!invite.options().auto_accept);
        assert!(invite.candidates().is_empty());
        let _ = std::fs::remove_file(path);
    }
}
