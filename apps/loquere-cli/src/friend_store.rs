//! Persistenza locale di una lista dispositivi di un amico già approvato.

use loquere_identity::{
    AccountId, DeviceList, DeviceListUpdateError, IdentityError, TrustedDeviceList,
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

/// Log cifrato per un amico approvato; non implementa il flusso di amicizia.
pub struct FriendStore {
    log: RecordLog,
    trusted: TrustedDeviceList,
}

impl FriendStore {
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

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_crypto::SecretKey;
    use loquere_identity::{DeviceCert, DeviceRole};

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
}
