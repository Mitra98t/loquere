//! Persistenza locale del consumo e della revoca di un invito emesso.

use loquere_identity::{Account, IdentityError, Invitation};
use loquere_store::{RecordLog, StoreError};
use loquere_wire::{InviteGrant, InviteGrantError};
use std::path::Path;

const CONSUMED: &[u8] = b"\x01";
const REVOKED: &[u8] = b"\x02";

/// Errori nella gestione persistente dell'invito.
#[derive(Debug)]
pub enum InviteStoreError {
    /// Log cifrato non disponibile o corrotto.
    Store(StoreError),
    /// Invito non valido o non appartenente al dispositivo locale.
    Identity(IdentityError),
    /// Operazione incompatibile con lo stato dell'invito.
    Grant(InviteGrantError),
    /// Log vuoto, scambiato o contenente eventi non validi.
    InvalidLog,
}

/// Un invito locale e il suo consumo persistente; non invia FriendAccept.
/// La prenotazione in corso non sopravvive al riavvio. Come per gli altri log,
/// una copia locale precedente autenticata non è distinguibile senza ancoraggio
/// monotono esterno; il chiamante deve serializzare gli accessi al file.
pub struct PersistentInviteGrant {
    log: RecordLog,
    grant: InviteGrant,
    single_use: bool,
    unavailable: bool,
    poisoned: bool,
}

impl PersistentInviteGrant {
    /// Salva un invito emesso localmente prima di renderlo utilizzabile.
    /// Crea il file senza sovrascrivere dati esistenti.
    pub fn create(
        path: impl AsRef<Path>,
        owner: &Account,
        invite: &Invitation,
    ) -> Result<Self, InviteStoreError> {
        validate_owner(owner, invite)?;
        let key = storage_key(owner)?;
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
                .map_err(|error| InviteStoreError::Store(StoreError::Io(error)))?,
        );
        let mut log = RecordLog::open(path, *key)
            .map_err(InviteStoreError::Store)?
            .log;
        let bytes = zeroize::Zeroizing::new(invite.to_bytes().map_err(InviteStoreError::Identity)?);
        log.append(&bytes).map_err(InviteStoreError::Store)?;
        Ok(Self::from_parts(log, invite))
    }

    /// Riapre solo il log relativo all'invito e all'identità attesi.
    pub fn open(
        path: impl AsRef<Path>,
        owner: &Account,
        invite: &Invitation,
    ) -> Result<Self, InviteStoreError> {
        validate_owner(owner, invite)?;
        let path = path.as_ref();
        let (grant, stored) = match Self::load(path, owner) {
            Ok(result) => result,
            Err(_) => {
                // Compatibilità con i log v1 che richiedono l'invito noto.
                let mut purpose = zeroize::Zeroizing::new(b"loquere:invite-store:v1\0".to_vec());
                purpose.extend_from_slice(&invite.token());
                let key = owner
                    .derive_storage_key(&purpose)
                    .map_err(InviteStoreError::Identity)?;
                Self::load_with_key(path, owner, &key)?
            }
        };
        if &stored != invite {
            return Err(InviteStoreError::InvalidLog);
        }
        Ok(grant)
    }

    /// Riapre lo stato e recupera l'invito cifrato senza richiedere il link.
    pub fn load(
        path: impl AsRef<Path>,
        owner: &Account,
    ) -> Result<(Self, Invitation), InviteStoreError> {
        let key = storage_key(owner)?;
        Self::load_with_key(path, owner, &key)
    }

    fn load_with_key(
        path: impl AsRef<Path>,
        owner: &Account,
        key: &[u8; 32],
    ) -> Result<(Self, Invitation), InviteStoreError> {
        std::fs::File::open(path.as_ref())
            .map_err(|error| InviteStoreError::Store(StoreError::Io(error)))?;
        let opened = RecordLog::open(path, *key).map_err(InviteStoreError::Store)?;
        let invite =
            Invitation::from_bytes(opened.records.first().ok_or(InviteStoreError::InvalidLog)?)
                .map_err(InviteStoreError::Identity)?;
        validate_owner(owner, &invite)?;
        let mut grant = Self::from_parts(opened.log, &invite);
        for record in opened.records.iter().skip(1) {
            if grant.unavailable
                || (record.as_slice() != REVOKED
                    && !(grant.single_use && record.as_slice() == CONSUMED))
            {
                return Err(InviteStoreError::InvalidLog);
            }
            grant.unavailable = true;
            grant.grant.revoke();
        }
        Ok((grant, invite))
    }

    fn from_parts(log: RecordLog, invite: &Invitation) -> Self {
        Self {
            log,
            grant: InviteGrant::new(
                invite.token(),
                invite.expires_at(),
                invite.options().single_use,
            ),
            single_use: invite.options().single_use,
            unavailable: false,
            poisoned: false,
        }
    }

    /// Prenota il token per una sessione; non equivale a consenso.
    pub fn begin(
        &mut self,
        token: &[u8; 16],
        now: u32,
        request_id: u64,
    ) -> Result<(), InviteStoreError> {
        if self.poisoned {
            return Err(InviteStoreError::InvalidLog);
        }
        self.grant
            .begin(token, now, request_id)
            .map_err(InviteStoreError::Grant)
    }

    /// Annulla la prenotazione di una sessione rifiutata o disconnessa.
    pub fn cancel(&mut self, request_id: u64) -> Result<(), InviteStoreError> {
        if self.poisoned {
            return Err(InviteStoreError::InvalidLog);
        }
        self.grant
            .cancel(request_id)
            .map_err(InviteStoreError::Grant)
    }

    /// Dopo consenso e verifica, registra il consumo prima di segnalare successo.
    pub fn accept(&mut self, request_id: u64, now: u32) -> Result<(), InviteStoreError> {
        if self.poisoned {
            return Err(InviteStoreError::InvalidLog);
        }
        self.grant
            .accept(request_id, now)
            .map_err(InviteStoreError::Grant)?;
        if self.single_use {
            self.unavailable = true;
            if let Err(error) = self.log.append(CONSUMED) {
                self.poisoned = true;
                return Err(InviteStoreError::Store(error));
            }
        }
        Ok(())
    }

    /// Registra la revoca prima di confermarla al chiamante.
    pub fn revoke(&mut self) -> Result<(), InviteStoreError> {
        if self.poisoned {
            return Err(InviteStoreError::InvalidLog);
        }
        if self.unavailable {
            return Ok(());
        }
        self.grant.revoke();
        self.unavailable = true;
        if let Err(error) = self.log.append(REVOKED) {
            self.poisoned = true;
            return Err(InviteStoreError::Store(error));
        }
        Ok(())
    }
}

fn validate_owner(owner: &Account, invite: &Invitation) -> Result<(), InviteStoreError> {
    invite.verify().map_err(InviteStoreError::Identity)?;
    if invite.account_id() != owner.account_id() || invite.device_id() != owner.device_public_key()
    {
        return Err(InviteStoreError::Identity(IdentityError::KeyMismatch));
    }
    Ok(())
}

fn storage_key(owner: &Account) -> Result<zeroize::Zeroizing<[u8; 32]>, InviteStoreError> {
    owner
        .derive_storage_key(b"loquere:invite-store:v2")
        .map_err(InviteStoreError::Identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_identity::InviteOptions;

    fn path() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("loquere-invite-{}-{nonce}.log", std::process::id()))
    }

    #[test]
    fn consumed_token_stays_unavailable_after_restart() {
        let path = path();
        let owner = Account::create("Owner".into(), 1).unwrap();
        let invite = owner
            .create_invite(
                "Owner".into(),
                100,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![],
            )
            .unwrap();
        let mut grant = PersistentInviteGrant::create(&path, &owner, &invite).unwrap();
        assert!(PersistentInviteGrant::create(&path, &owner, &invite).is_err());
        grant.begin(&invite.token(), 50, 1).unwrap();
        grant.accept(1, 50).unwrap();
        drop(grant);
        let mut reopened = PersistentInviteGrant::open(&path, &owner, &invite).unwrap();
        assert!(matches!(
            reopened.begin(&invite.token(), 50, 2),
            Err(InviteStoreError::Grant(InviteGrantError::Unavailable))
        ));
        drop(reopened);
        let other = Account::create("Other".into(), 1).unwrap();
        assert!(PersistentInviteGrant::open(&path, &other, &invite).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cancelled_request_and_revocation_survive_restart_as_expected() {
        let path = path();
        let owner = Account::create("Owner".into(), 1).unwrap();
        let invite = owner
            .create_invite(
                "Owner".into(),
                0,
                InviteOptions {
                    single_use: false,
                    auto_accept: false,
                },
                vec![],
            )
            .unwrap();
        let mut grant = PersistentInviteGrant::create(&path, &owner, &invite).unwrap();
        grant.begin(&invite.token(), 50, 1).unwrap();
        drop(grant);
        let mut grant = PersistentInviteGrant::open(&path, &owner, &invite).unwrap();
        grant.begin(&invite.token(), 50, 1).unwrap();
        grant.cancel(1).unwrap();
        grant.begin(&invite.token(), 50, 2).unwrap();
        grant.accept(2, 50).unwrap();
        drop(grant);
        let mut grant = PersistentInviteGrant::open(&path, &owner, &invite).unwrap();
        grant.begin(&invite.token(), 50, 3).unwrap();
        grant.revoke().unwrap();
        drop(grant);
        let mut reopened = PersistentInviteGrant::open(&path, &owner, &invite).unwrap();
        assert!(reopened.begin(&invite.token(), 50, 4).is_err());
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn opens_legacy_v1_when_invitation_is_known() {
        let path = path();
        let owner = Account::create("Owner".into(), 1).unwrap();
        let invite = owner
            .create_invite(
                "Owner".into(),
                0,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![],
            )
            .unwrap();
        let mut purpose = zeroize::Zeroizing::new(b"loquere:invite-store:v1\0".to_vec());
        purpose.extend_from_slice(&invite.token());
        let key = owner.derive_storage_key(&purpose).unwrap();
        let mut log = RecordLog::open(&path, *key).unwrap().log;
        log.append(&invite.to_bytes().unwrap()).unwrap();
        drop(log);
        let mut reopened = PersistentInviteGrant::open(&path, &owner, &invite).unwrap();
        reopened.begin(&invite.token(), 10, 1).unwrap();
        reopened.accept(1, 10).unwrap();
        drop(reopened);
        let mut reopened = PersistentInviteGrant::open(&path, &owner, &invite).unwrap();
        assert!(reopened.begin(&invite.token(), 10, 2).is_err());
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
}
