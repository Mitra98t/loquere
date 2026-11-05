//! Persistenza locale di una lista dispositivi di un amico già approvato.

use loquere_identity::{
    Account, AccountId, DeviceList, DeviceListUpdateError, IdentityError, Invitation,
    TrustedDeviceList,
};
use loquere_store::{RecordLog, StoreError};
use std::path::Path;

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
}

impl FriendStore {
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
        let path = path.as_ref();
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
        let opened = RecordLog::open(path, key).map_err(FriendStoreError::Store)?;
        let mut log = opened.log;
        log.append(&approved.to_bytes())
            .map_err(FriendStoreError::Store)?;
        Ok(Self {
            log,
            trusted: TrustedDeviceList::from_approved_friend(approved),
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
        let first = DeviceList::from_bytes(first).map_err(FriendStoreError::Identity)?;
        if first.account_id() != expected {
            return Err(FriendStoreError::WrongAccount);
        }
        let mut trusted = TrustedDeviceList::from_approved_friend(first);
        for bytes in records {
            let next = DeviceList::from_bytes(bytes).map_err(FriendStoreError::Identity)?;
            trusted.update(next).map_err(FriendStoreError::Update)?;
        }
        Ok(Self {
            log: opened.log,
            trusted,
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
