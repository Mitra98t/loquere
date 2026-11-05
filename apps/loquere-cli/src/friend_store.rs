//! Persistenza locale di una lista dispositivi di un amico già approvato.

use loquere_identity::{
    Account, AccountId, DeviceList, DeviceListUpdateError, IdentityError, Invitation,
    TrustedDeviceList,
};
use loquere_store::{RecordLog, StoreError};
use std::path::Path;

const DISCOVERY_RECORD: &[u8] = b"loquere:friend-discovery:v1\0";
const COMPLETE_RECORD: &[u8] = b"loquere:friend-complete:v1\0";

/// Errori nella persistenza della lista fidata.
#[derive(Debug)]
pub enum FriendStoreError {
    /// Errore del log cifrato.
    Store(StoreError),
    /// Lista serializzata non valida.
    Identity(IdentityError),
    /// Aggiornamento non consentito.
    Update(DeviceListUpdateError),
    /// Il log non contiene una lista iniziale.
    Empty,
    /// Il log appartiene a un account diverso da quello atteso.
    WrongAccount,
    /// Segreto duplicato, malformato o non corrispondente alla lista fidata.
    InvalidSecret,
}

/// Dati di un FriendAccept verificato; non implica consenso o persistenza.
pub struct VerifiedFriendAccept {
    device_list: DeviceList,
    discovery_secret: zeroize::Zeroizing<[u8; 32]>,
}

impl VerifiedFriendAccept {
    /// Lista firmata corrispondente all'account e al peer TLS attesi.
    pub fn device_list(&self) -> &DeviceList {
        &self.device_list
    }
    /// Segreto riservato da salvare cifrato e non pubblicare.
    pub fn discovery_secret(&self) -> &[u8; 32] {
        &self.discovery_secret
    }
}

/// Verifica la lista di un FriendAccept contro l'account e la chiave TLS
/// autenticata. Non approva l'amicizia e non salva il segreto ricevuto.
pub fn verify_friend_accept(
    accept: &loquere_wire::FriendAccept,
    expected_account: AccountId,
    authenticated_peer: &[u8; 32],
) -> Result<VerifiedFriendAccept, FriendStoreError> {
    let list = DeviceList::from_bytes(accept.device_list()).map_err(FriendStoreError::Identity)?;
    if list.account_id() != expected_account || !list.contains_device(authenticated_peer) {
        return Err(FriendStoreError::WrongAccount);
    }
    Ok(VerifiedFriendAccept {
        device_list: list,
        discovery_secret: zeroize::Zeroizing::new(*accept.discovery_secret()),
    })
}

/// Log cifrato per un amico approvato; non implementa il flusso di amicizia.
pub struct FriendStore {
    log: RecordLog,
    trusted: TrustedDeviceList,
    discovery_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
}

impl FriendStore {
    /// Dopo consenso esplicito salva lista e segreto verificati nello stesso
    /// record autenticato. Non invia messaggi e non sostituisce file esistenti.
    pub fn create_verified(
        path: impl AsRef<Path>,
        owner: &Account,
        accept: &VerifiedFriendAccept,
    ) -> Result<Self, FriendStoreError> {
        let key = friend_storage_key(owner, accept.device_list().account_id())?;
        let mut log = create_empty_log(path.as_ref(), *key)?;
        let list = accept.device_list().to_bytes();
        let length = u32::try_from(list.len()).map_err(|_| FriendStoreError::InvalidSecret)?;
        let mut record = zeroize::Zeroizing::new(COMPLETE_RECORD.to_vec());
        record.extend_from_slice(&length.to_le_bytes());
        record.extend_from_slice(&list);
        record.extend_from_slice(accept.discovery_secret());
        log.append(&record).map_err(FriendStoreError::Store)?;
        Ok(Self {
            log,
            trusted: TrustedDeviceList::from_approved_friend(accept.device_list().clone()),
            discovery_secret: Some(zeroize::Zeroizing::new(*accept.discovery_secret())),
        })
    }

    /// Dopo la conferma esplicita dell'utente, valida invito, peer TLS e lista
    /// e salva la fiducia con una chiave derivata dedicata a questo account.
    /// Il chiamante resta responsabile di token, consenso e flusso FriendAccept.
    pub fn create_from_approved_invitation(
        path: impl AsRef<Path>,
        owner: &Account,
        invite: &Invitation,
        now: u32,
        authenticated_peer: &[u8; 32],
        devices: DeviceList,
    ) -> Result<Self, FriendStoreError> {
        invite
            .validate_peer_list(now, authenticated_peer, &devices)
            .map_err(FriendStoreError::Identity)?;
        let key = friend_storage_key(owner, devices.account_id())?;
        Self::create(path, *key, devices)
    }

    /// Riapre la fiducia di un account noto con la chiave derivata locale.
    pub fn open_for_account(
        path: impl AsRef<Path>,
        owner: &Account,
        friend: AccountId,
    ) -> Result<Self, FriendStoreError> {
        let key = friend_storage_key(owner, friend)?;
        Self::open(path, *key, friend)
    }

    /// Inizializza un log vuoto con una lista approvata esplicitamente.
    /// Non usare per approvare automaticamente un invito ricevuto.
    pub fn create(
        path: impl AsRef<Path>,
        key: [u8; 32],
        approved: DeviceList,
    ) -> Result<Self, FriendStoreError> {
        let mut log = create_empty_log(path.as_ref(), key)?;
        log.append(&approved.to_bytes())
            .map_err(FriendStoreError::Store)?;
        Ok(Self {
            log,
            trusted: TrustedDeviceList::from_approved_friend(approved),
            discovery_secret: None,
        })
    }

    /// Riapre e verifica ogni aggiornamento in ordine; non crea fiducia nuova.
    pub fn open(
        path: impl AsRef<Path>,
        key: [u8; 32],
        expected: AccountId,
    ) -> Result<Self, FriendStoreError> {
        std::fs::File::open(path.as_ref())
            .map_err(|error| FriendStoreError::Store(StoreError::Io(error)))?;
        let opened = RecordLog::open(path, key).map_err(FriendStoreError::Store)?;
        let mut records = opened.records.iter();
        let first = records.next().ok_or(FriendStoreError::Empty)?;
        let (first, mut discovery_secret) =
            if let Some(payload) = first.strip_prefix(COMPLETE_RECORD) {
                let length_bytes: [u8; 4] = payload
                    .get(..4)
                    .ok_or(FriendStoreError::InvalidSecret)?
                    .try_into()
                    .map_err(|_| FriendStoreError::InvalidSecret)?;
                let list_len = u32::from_le_bytes(length_bytes) as usize;
                let end = 4usize
                    .checked_add(list_len)
                    .ok_or(FriendStoreError::InvalidSecret)?;
                if payload.len() != end.checked_add(32).ok_or(FriendStoreError::InvalidSecret)? {
                    return Err(FriendStoreError::InvalidSecret);
                }
                let list =
                    DeviceList::from_bytes(&payload[4..end]).map_err(FriendStoreError::Identity)?;
                let mut secret = zeroize::Zeroizing::new([0; 32]);
                secret.copy_from_slice(&payload[end..]);
                (list, Some(secret))
            } else {
                (
                    DeviceList::from_bytes(first).map_err(FriendStoreError::Identity)?,
                    None,
                )
            };
        if first.account_id() != expected {
            return Err(FriendStoreError::WrongAccount);
        }
        let mut trusted = TrustedDeviceList::from_approved_friend(first);
        for bytes in records {
            if bytes.starts_with(DISCOVERY_RECORD) {
                if discovery_secret.is_some() || bytes.len() != DISCOVERY_RECORD.len() + 32 {
                    return Err(FriendStoreError::InvalidSecret);
                }
                let mut secret = zeroize::Zeroizing::new([0; 32]);
                secret.copy_from_slice(&bytes[DISCOVERY_RECORD.len()..]);
                discovery_secret = Some(secret);
            } else {
                let next = DeviceList::from_bytes(bytes).map_err(FriendStoreError::Identity)?;
                trusted.update(next).map_err(FriendStoreError::Update)?;
            }
        }
        Ok(Self {
            log: opened.log,
            trusted,
            discovery_secret,
        })
    }

    /// Valida e salva prima di rendere visibile un aggiornamento in memoria.
    pub fn update(&mut self, next: DeviceList) -> Result<(), FriendStoreError> {
        let mut candidate = TrustedDeviceList::from_approved_friend(self.trusted.current().clone());
        candidate.update(next).map_err(FriendStoreError::Update)?;
        self.log
            .append(&candidate.current().to_bytes())
            .map_err(FriendStoreError::Store)?;
        self.trusted = candidate;
        Ok(())
    }

    /// Controlla il peer TLS rispetto alla lista fidata corrente.
    pub fn permits_device(&self, peer: &[u8; 32]) -> bool {
        self.trusted.permits_device(peer)
    }

    /// Salva una volta il segreto di un'accettazione già verificata e approvata.
    /// La gestione della rotazione del segreto non è ancora implementata.
    pub fn save_verified_discovery(
        &mut self,
        accept: &VerifiedFriendAccept,
    ) -> Result<(), FriendStoreError> {
        if self.discovery_secret.is_some() || accept.device_list() != self.trusted.current() {
            return Err(FriendStoreError::InvalidSecret);
        }
        let mut record = zeroize::Zeroizing::new(DISCOVERY_RECORD.to_vec());
        record.extend_from_slice(accept.discovery_secret());
        self.log.append(&record).map_err(FriendStoreError::Store)?;
        self.discovery_secret = Some(zeroize::Zeroizing::new(*accept.discovery_secret()));
        Ok(())
    }

    /// Restituisce il segreto fidato se presente; non pubblicarlo.
    pub fn discovery_secret(&self) -> Option<&[u8; 32]> {
        self.discovery_secret.as_deref()
    }
}

fn create_empty_log(path: &Path, key: [u8; 32]) -> Result<RecordLog, FriendStoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(
        options
            .open(path)
            .map_err(|error| FriendStoreError::Store(StoreError::Io(error)))?,
    );
    Ok(RecordLog::open(path, key)
        .map_err(FriendStoreError::Store)?
        .log)
}

fn friend_storage_key(
    owner: &Account,
    friend: AccountId,
) -> Result<zeroize::Zeroizing<[u8; 32]>, FriendStoreError> {
    let mut purpose = b"loquere:friend-store:v1\0".to_vec();
    purpose.extend_from_slice(&friend.to_bytes());
    owner
        .derive_storage_key(&purpose)
        .map_err(FriendStoreError::Identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_crypto::SecretKey;
    use loquere_identity::{DeviceCert, DeviceRole, InviteOptions};

    #[test]
    fn revocation_survives_restart_and_rejects_old_list() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("loquere-friend-{}-{nonce}.log", std::process::id()));
        let account = SecretKey::generate();
        let device = SecretKey::generate();
        let cert = DeviceCert::issue(
            &account,
            device.public_key(),
            "test".into(),
            DeviceRole::Member,
            0,
        )
        .unwrap();
        let id = device.public_key().to_bytes();
        let first = DeviceList::issue(&account, 1, vec![cert], vec![]).unwrap();
        let revoked = DeviceList::issue(&account, 2, vec![], vec![id]).unwrap();
        let mut store = FriendStore::create(&path, [7; 32], first.clone()).unwrap();
        assert!(store.permits_device(&id));
        store.update(revoked).unwrap();
        drop(store);
        let mut reopened = FriendStore::open(&path, [7; 32], first.account_id()).unwrap();
        assert!(!reopened.permits_device(&id));
        assert!(matches!(
            reopened.update(first),
            Err(FriendStoreError::Update(
                DeviceListUpdateError::RollbackOrConflict
            ))
        ));
        drop(reopened);
        assert!(
            FriendStore::open(
                &path,
                [8; 32],
                AccountId::from_bytes(account.public_key().to_bytes()).unwrap()
            )
            .is_err()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn approved_invite_is_bound_to_peer_and_owner_key() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "loquere-friend-invite-{}-{nonce}.log",
            std::process::id()
        ));
        let owner = Account::create("Owner".into(), 1).unwrap();
        let friend = Account::create("Friend".into(), 1).unwrap();
        let invite = friend
            .create_invite(
                "Friend".into(),
                100,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![],
            )
            .unwrap();
        let list = friend.initial_device_list().unwrap();
        let peer = friend.device_public_key().to_bytes();
        assert!(
            FriendStore::create_from_approved_invitation(
                &path,
                &owner,
                &invite,
                50,
                &[0; 32],
                list.clone()
            )
            .is_err()
        );
        assert!(!path.exists());
        let store =
            FriendStore::create_from_approved_invitation(&path, &owner, &invite, 50, &peer, list)
                .unwrap();
        assert!(store.permits_device(&peer));
        drop(store);
        let reopened = FriendStore::open_for_account(&path, &owner, friend.account_id()).unwrap();
        assert!(reopened.permits_device(&peer));
        drop(reopened);
        let other = Account::create("Other".into(), 1).unwrap();
        assert!(FriendStore::open_for_account(&path, &other, friend.account_id()).is_err());
        assert!(FriendStore::open_for_account(&path, &owner, other.account_id()).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn friend_accept_requires_matching_signed_list_and_active_tls_peer() {
        let friend = Account::create("Friend".into(), 1).unwrap();
        let other = Account::create("Other".into(), 1).unwrap();
        let list = friend.initial_device_list().unwrap();
        let frame = loquere_wire::encode_friend_accept(friend.discovery_secret(), &list.to_bytes())
            .unwrap();
        let (_, accept) = loquere_wire::FriendAcceptDecoder::new()
            .push(&frame)
            .unwrap();
        let accept = accept.unwrap();
        let peer = friend.device_public_key().to_bytes();
        let verified = verify_friend_accept(&accept, friend.account_id(), &peer).unwrap();
        assert_eq!(verified.device_list(), &list);
        assert_eq!(verified.discovery_secret(), friend.discovery_secret());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("loquere-discovery-{}-{nonce}", std::process::id()));
        let mut store = FriendStore::create(&path, [6; 32], list.clone()).unwrap();
        store.save_verified_discovery(&verified).unwrap();
        assert!(store.save_verified_discovery(&verified).is_err());
        drop(store);
        let encoded = std::fs::read(&path).unwrap();
        assert!(
            !encoded
                .windows(32)
                .any(|window| window == friend.discovery_secret())
        );
        let store = FriendStore::open(&path, [6; 32], friend.account_id()).unwrap();
        assert_eq!(store.discovery_secret(), Some(friend.discovery_secret()));
        drop(store);
        std::fs::remove_file(path).unwrap();
        let path =
            std::env::temp_dir().join(format!("loquere-complete-{}-{nonce}", std::process::id()));
        let owner = Account::create("Owner".into(), 1).unwrap();
        let store = FriendStore::create_verified(&path, &owner, &verified).unwrap();
        assert_eq!(store.discovery_secret(), Some(friend.discovery_secret()));
        assert!(store.permits_device(&peer));
        drop(store);
        assert!(FriendStore::create_verified(&path, &owner, &verified).is_err());
        let reopened = FriendStore::open_for_account(&path, &owner, friend.account_id()).unwrap();
        assert_eq!(reopened.discovery_secret(), Some(friend.discovery_secret()));
        assert!(reopened.permits_device(&peer));
        drop(reopened);
        let other_owner = Account::create("Other owner".into(), 1).unwrap();
        assert!(FriendStore::open_for_account(&path, &other_owner, friend.account_id()).is_err());
        std::fs::remove_file(path).unwrap();
        assert!(verify_friend_accept(&accept, other.account_id(), &peer).is_err());
        assert!(
            verify_friend_accept(
                &accept,
                friend.account_id(),
                &other.device_public_key().to_bytes()
            )
            .is_err()
        );
        let mut altered = list.to_bytes();
        altered[10] ^= 1;
        let frame =
            loquere_wire::encode_friend_accept(friend.discovery_secret(), &altered).unwrap();
        let (_, accept) = loquere_wire::FriendAcceptDecoder::new()
            .push(&frame)
            .unwrap();
        assert!(verify_friend_accept(&accept.unwrap(), friend.account_id(), &peer).is_err());
    }
}
