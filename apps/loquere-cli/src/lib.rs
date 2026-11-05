//! Comandi CLI di Loquere e formattazione dei relativi risultati.

mod friend_store;
mod invite_store;
mod terminal;

pub use friend_store::{FriendStore, FriendStoreError};
pub use invite_store::{InviteStoreError, PersistentInviteGrant};

use loquere_chat::{ChatError, Conversation, MemberWelcome};
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

/// Genera un KeyPackage MLS per un nuovo membro; lo stato privato resta nel
/// file persistente locale, mentre i byte restituiti sono pubblicabili.
pub fn create_chat_key_package(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
) -> Result<Vec<u8>, ChatFileError> {
    open_chat_state(identity_path, passphrase, state_path)?
        .key_package()
        .map_err(ChatFileError::Chat)
}

/// Aggiunge un KeyPackage e restituisce commit, Welcome e ratchet tree MLS.
pub fn add_chat_member(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
    key_package: &[u8],
) -> Result<MemberWelcome, ChatFileError> {
    open_chat_state(identity_path, passphrase, state_path)?
        .add_member(key_package)
        .map_err(ChatFileError::Chat)
}

/// Unisce al gruppo il dispositivo con KeyPackage già generato e persistito.
pub fn join_chat_state(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
    welcome: &[u8],
    ratchet_tree: &[u8],
) -> Result<ChatSummary, ChatFileError> {
    let pending = open_chat_state(identity_path, passphrase, state_path)?;
    Conversation::join(pending, welcome, ratchet_tree)
        .map(|conversation| chat_summary(&conversation))
        .map_err(ChatFileError::Chat)
}

/// Applica un commit MLS ricevuto dai membri già presenti.
pub fn apply_chat_commit(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
    commit: &[u8],
) -> Result<ChatSummary, ChatFileError> {
    let mut conversation = open_chat_state(identity_path, passphrase, state_path)?;
    conversation
        .process_commit(commit)
        .map_err(ChatFileError::Chat)?;
    Ok(chat_summary(&conversation))
}

/// Cifra un messaggio e restituisce il frame TLS-serializzato da trasferire.
pub fn encrypt_chat_message(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
    plaintext: &[u8],
) -> Result<Vec<u8>, ChatFileError> {
    open_chat_state(identity_path, passphrase, state_path)?
        .encrypt(plaintext)
        .map_err(ChatFileError::Chat)
}

/// Decifra e autentica un messaggio MLS ricevuto.
pub fn decrypt_chat_message(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ChatFileError> {
    open_chat_state(identity_path, passphrase, state_path)?
        .decrypt(ciphertext)
        .map_err(ChatFileError::Chat)
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

/// Genera un invito e lo salva cifrato prima di restituire il link.
/// Non invia richieste né rende ancora il nodo raggiungibile.
pub fn create_persistent_invite_from_file(
    path: impl AsRef<Path>,
    passphrase: &str,
    display_name: String,
    expires_at: u32,
    state_path: impl AsRef<Path>,
    candidates: Vec<loquere_identity::InviteCandidate>,
) -> Result<String, String> {
    let account = unlock_identity_file(path, passphrase).map_err(|error| error.to_string())?;
    let invite = account
        .create_invite(
            display_name,
            expires_at,
            InviteOptions {
                single_use: true,
                auto_accept: false,
            },
            candidates,
        )
        .map_err(|error| error.to_string())?;
    let uri = invite.to_uri().map_err(|error| error.to_string())?;
    PersistentInviteGrant::create(state_path, &account, &invite)
        .map_err(|error| format!("impossibile salvare l'invito: {error:?}"))?;
    Ok(uri)
}

/// Revoca localmente un invito salvato; non invia notifiche di rete.
pub fn revoke_invite_file(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
) -> Result<(), String> {
    let account =
        unlock_identity_file(identity_path, passphrase).map_err(|error| error.to_string())?;
    let (mut grant, _) = PersistentInviteGrant::load(state_path, &account)
        .map_err(|error| format!("impossibile aprire l'invito: {error:?}"))?;
    grant
        .revoke()
        .map_err(|error| format!("impossibile revocare l'invito: {error:?}"))
}

/// Riceve e verifica una sola richiesta via UDP/QUIC, senza accettarla.
/// Invia FriendAck dopo la verifica. Alla restituzione chiude il socket, senza
/// inviare FriendAccept né salvare un contatto.
pub fn receive_invite_request_once(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
    address: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> Result<loquere_identity::DeviceCert, String> {
    receive_invite_request_inner(
        identity_path,
        passphrase,
        state_path,
        address,
        timeout,
        |_| {},
    )
}

fn receive_invite_request_inner(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    state_path: impl AsRef<Path>,
    address: std::net::SocketAddr,
    timeout: std::time::Duration,
    on_ready: impl FnOnce(std::net::SocketAddr),
) -> Result<loquere_identity::DeviceCert, String> {
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let now_unix = || -> Result<u32, String> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs();
        u32::try_from(seconds).map_err(|_| "orologio oltre il limite supportato".to_owned())
    };
    if timeout.is_zero() || timeout > Duration::from_secs(3600) {
        return Err("timeout non valido: massimo un'ora".to_owned());
    }
    let owner =
        unlock_identity_file(identity_path, passphrase).map_err(|error| error.to_string())?;
    let (mut grant, invite) = PersistentInviteGrant::load(state_path, &owner)
        .map_err(|error| format!("impossibile aprire l'invito: {error:?}"))?;
    let now = now_unix()?;
    invite.verify_at(now).map_err(|error| error.to_string())?;
    grant
        .begin(&invite.token(), now, 0)
        .map_err(|error| format!("invito non disponibile: {error:?}"))?;
    grant
        .cancel(0)
        .map_err(|error| format!("invito non disponibile: {error:?}"))?;
    let key = Arc::new(loquere_crypto::SecretKey::from_bytes(
        *owner.device_signing_key(),
    ));
    let mut receiver = loquere_net::InviteReceiver::bind_system(
        address,
        Duration::from_millis(25),
        loquere_net::EcnHandling::IgnoreExplicitly,
        key,
        invite.token(),
    )
    .map_err(|error| format!("impossibile avviare il ricevitore: {error:?}"))?;
    on_ready(
        receiver
            .local_addr()
            .map_err(|error| format!("socket non disponibile: {error:?}"))?,
    );
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "timeout non valido".to_owned())?;
    let mut buffer = zeroize::Zeroizing::new(vec![0; 65_507]);
    while Instant::now() < deadline {
        let now = now_unix()?;
        invite.verify_at(now).map_err(|error| error.to_string())?;
        if let Some(received) = receiver
            .step(&mut buffer, Instant::now(), u64::from(now))
            .map_err(|error| format!("ricezione richiesta non riuscita: {error:?}"))?
        {
            let certificate = grant
                .reserve_friend_request(&received.request, &received.peer, now, 1)
                .map_err(|error| format!("richiesta non valida: {error:?}"))?;
            receiver
                .acknowledge_verified()
                .map_err(|error| format!("riscontro non accodato: {error:?}"))?;
            let ack_deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < ack_deadline {
                let now = now_unix()?;
                if let Err(error) = receiver.step(&mut buffer, Instant::now(), u64::from(now)) {
                    if receiver.ack_queued() {
                        break;
                    }
                    return Err(format!("riscontro non inviato: {error:?}"));
                }
            }
            if !receiver.ack_queued() {
                return Err("riscontro non accodato entro il timeout".to_owned());
            }
            grant
                .cancel(1)
                .map_err(|error| format!("errore stato invito: {error:?}"))?;
            return Ok(certificate);
        }
    }
    Err("nessuna richiesta ricevuta entro il timeout".to_owned())
}

/// Avvia un tentativo di richiesta dopo conferma esplicita del chiamante.
/// Il successo indica la ricezione di FriendAck, non l'accettazione
/// dell'amicizia né la creazione di un contatto.
pub fn send_invite_request_once(
    identity_path: impl AsRef<Path>,
    passphrase: &str,
    invite_code: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err("timeout non valido: massimo un minuto".to_owned());
    }
    let invite = Invitation::parse_code(invite_code).map_err(|error| error.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let now = u32::try_from(now).map_err(|_| "orologio oltre il limite supportato".to_owned())?;
    invite.verify_at(now).map_err(|error| error.to_string())?;
    let candidate = invite
        .candidates()
        .first()
        .ok_or_else(|| "invito senza candidati di rete".to_owned())?;
    let destination = std::net::SocketAddr::new(candidate.address, candidate.port);
    let account =
        unlock_identity_file(identity_path, passphrase).map_err(|error| error.to_string())?;
    let local = Arc::new(loquere_crypto::SecretKey::from_bytes(
        *account.device_signing_key(),
    ));
    let mut requester = loquere_net::InviteRequester::connect(
        destination,
        invite.device_id(),
        invite.token(),
        local,
        &account.device_cert().to_bytes(),
        Instant::now(),
    )
    .map_err(|error| format!("connessione non avviata: {error:?}"))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "timeout non valido".to_owned())?;
    let mut buffer = Zeroizing::new(vec![0; 65_507]);
    let mut queued = false;
    while Instant::now() < deadline {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs();
        if invite.expires_at() != 0 && now > u64::from(invite.expires_at()) {
            return Err("invito scaduto".to_owned());
        }
        match requester.step(&mut buffer, Instant::now(), now) {
            Ok(written) => {
                queued |= written;
                if requester.acknowledged() {
                    return Ok(());
                }
            }
            Err(error) if !queued => return Err(format!("tentativo non riuscito: {error:?}")),
            Err(_) => break,
        }
    }
    if queued {
        Err("richiesta accodata ma nessun riscontro ricevuto".to_owned())
    } else {
        Err("richiesta non accodata entro il timeout".to_owned())
    }
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
        let state_path = path.with_extension("invite-log");
        let code = create_persistent_invite_from_file(
            &path,
            "a strong passphrase",
            "Alice".to_owned(),
            99,
            &state_path,
            vec![loquere_identity::InviteCandidate {
                address: "192.0.2.1".parse().unwrap(),
                port: 4444,
            }],
        )
        .unwrap();
        let expected = Invitation::parse_code(&code).unwrap();
        assert!(
            send_invite_request_once(
                &path,
                "a strong passphrase",
                &code,
                std::time::Duration::from_secs(1)
            )
            .is_err()
        );
        let (_, restored) = PersistentInviteGrant::load(&state_path, &account).unwrap();
        assert_eq!(restored, expected);
        assert!(
            receive_invite_request_once(
                &path,
                "a strong passphrase",
                &state_path,
                "127.0.0.1:12345".parse().unwrap(),
                std::time::Duration::from_secs(1),
            )
            .is_err()
        ); // l'invito scaduto è rifiutato prima di aprire il socket
        assert_eq!(restored.candidates()[0].port, 4444);
        assert!(
            create_persistent_invite_from_file(
                &path,
                "a strong passphrase",
                "Alice".to_owned(),
                99,
                &state_path,
                vec![]
            )
            .is_err()
        );
        revoke_invite_file(&path, "a strong passphrase", &state_path).unwrap();
        let (mut grant, _) = PersistentInviteGrant::load(&state_path, &account).unwrap();
        assert!(grant.begin(&expected.token(), 1, 1).is_err());
        drop(grant);
        std::fs::remove_file(state_path).unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cli_libraries_exchange_request_and_ack_over_udp() {
        use std::{net::UdpSocket, sync::mpsc, time::Duration};
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("loquere-cli-net-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let owner = Account::create("Owner".into(), 1).unwrap();
        let peer = Account::create("Peer".into(), 1).unwrap();
        let owner_path = directory.join("owner");
        let peer_path = directory.join("peer");
        let state_path = directory.join("invite");
        std::fs::write(
            &owner_path,
            owner.protect_with_passphrase("test passphrase").unwrap(),
        )
        .unwrap();
        std::fs::write(
            &peer_path,
            peer.protect_with_passphrase("test passphrase").unwrap(),
        )
        .unwrap();
        let temporary = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = temporary.local_addr().unwrap();
        drop(temporary);
        let invite = owner
            .create_invite(
                "Owner".into(),
                0,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![loquere_identity::InviteCandidate {
                    address: address.ip(),
                    port: address.port(),
                }],
            )
            .unwrap();
        drop(PersistentInviteGrant::create(&state_path, &owner, &invite).unwrap());
        let code = invite.to_uri().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let owner_thread = owner_path.clone();
        let state_thread = state_path.clone();
        let listener = std::thread::spawn(move || {
            receive_invite_request_inner(
                owner_thread,
                "test passphrase",
                state_thread,
                address,
                Duration::from_secs(30),
                |bound| {
                    ready_tx.send(bound).unwrap();
                },
            )
        });
        assert_eq!(
            ready_rx.recv_timeout(Duration::from_secs(30)).unwrap(),
            address
        );
        send_invite_request_once(
            &peer_path,
            "test passphrase",
            &code,
            Duration::from_secs(10),
        )
        .unwrap();
        let cert = listener.join().unwrap().unwrap();
        assert_eq!(cert.account_id(), peer.account_id());
        assert_eq!(cert.device_id(), peer.device_public_key());
        let (mut grant, _) = PersistentInviteGrant::load(&state_path, &owner).unwrap();
        grant.begin(&invite.token(), 1, 99).unwrap(); // FriendAck non consuma il token.
        grant.cancel(99).unwrap();
        drop(grant);
        std::fs::remove_file(owner_path).unwrap();
        std::fs::remove_file(peer_path).unwrap();
        std::fs::remove_file(state_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
