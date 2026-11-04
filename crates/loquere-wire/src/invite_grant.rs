//! Prenotazione sans-IO di un invito. La persistenza appartiene all'engine.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Rifiuto interno: il protocollo esterno non deve rivelare la motivazione.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteGrantError {
    /// Token errato, scaduto, revocato o già usato.
    Unavailable,
    /// Una richiesta è già in attesa di conferma.
    Pending,
    /// La risposta non appartiene alla richiesta in attesa.
    WrongRequest,
}

/// Stato temporaneo di un token d'invito, posseduto da un solo thread.
///
/// `request_id` deve identificare univocamente la sessione autenticata. Stato,
/// prenotazioni e consumo sono solo in memoria: non usare dopo un riavvio
/// senza aver ripristinato lo stato persistente dell'invito.
pub struct InviteGrant {
    token: Zeroizing<[u8; 16]>,
    expires_at: u32,
    single_use: bool,
    pending: Option<u64>,
    unavailable: bool,
}

impl InviteGrant {
    /// Il token è fornito dall'invito emesso e il tempo è iniettato dal chiamante.
    pub fn new(token: [u8; 16], expires_at: u32, single_use: bool) -> Self {
        Self {
            token: Zeroizing::new(token),
            expires_at,
            single_use,
            pending: None,
            unavailable: false,
        }
    }

    /// Verifica il token e riserva l'invito a una sola richiesta alla volta.
    /// Questo non implica approvazione dell'utente né accettazione dell'amicizia.
    pub fn begin(
        &mut self,
        token: &[u8; 16],
        now: u32,
        request_id: u64,
    ) -> Result<(), InviteGrantError> {
        let valid_token = bool::from(self.token.as_slice().ct_eq(token));
        if !valid_token || self.unavailable || (self.expires_at != 0 && now > self.expires_at) {
            return Err(InviteGrantError::Unavailable);
        }
        if self.pending.is_some() {
            return Err(InviteGrantError::Pending);
        }
        self.pending = Some(request_id);
        Ok(())
    }

    /// Conferma il consumo dopo consenso e validazione della richiesta.
    /// Per un invito monouso la transizione va persistita prima di FriendAccept.
    pub fn accept(&mut self, request_id: u64, now: u32) -> Result<(), InviteGrantError> {
        if self.pending != Some(request_id) {
            return Err(InviteGrantError::WrongRequest);
        }
        if self.unavailable || (self.expires_at != 0 && now > self.expires_at) {
            self.pending = None;
            return Err(InviteGrantError::Unavailable);
        }
        self.pending = None;
        if self.single_use {
            self.unavailable = true;
        }
        Ok(())
    }

    /// Annulla la richiesta dopo rifiuto o disconnessione, senza consumarla.
    pub fn cancel(&mut self, request_id: u64) -> Result<(), InviteGrantError> {
        if self.pending != Some(request_id) {
            return Err(InviteGrantError::WrongRequest);
        }
        self.pending = None;
        Ok(())
    }

    /// Revoca immediatamente il token e annulla eventuali richieste in attesa.
    pub fn revoke(&mut self) {
        self.unavailable = true;
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_use_reserves_one_request_and_only_consumes_on_accept() {
        let token = [7; 16];
        let mut grant = InviteGrant::new(token, 100, true);
        assert_eq!(
            grant.begin(&[8; 16], 50, 1),
            Err(InviteGrantError::Unavailable)
        );
        assert_eq!(grant.begin(&token, 50, 1), Ok(()));
        assert_eq!(grant.begin(&token, 50, 2), Err(InviteGrantError::Pending));
        assert_eq!(grant.accept(2, 50), Err(InviteGrantError::WrongRequest));
        assert_eq!(grant.cancel(1), Ok(()));
        assert_eq!(grant.begin(&token, 100, 2), Ok(()));
        assert_eq!(grant.accept(2, 100), Ok(()));
        assert_eq!(
            grant.begin(&token, 100, 3),
            Err(InviteGrantError::Unavailable)
        );
    }

    #[test]
    fn expired_revoked_and_reusable_tokens_are_handled() {
        let token = [9; 16];
        let mut grant = InviteGrant::new(token, 20, false);
        assert_eq!(grant.begin(&token, 20, 1), Ok(()));
        assert_eq!(grant.accept(1, 21), Err(InviteGrantError::Unavailable));
        assert_eq!(
            grant.begin(&token, 21, 2),
            Err(InviteGrantError::Unavailable)
        );
        let mut grant = InviteGrant::new(token, 0, false);
        assert_eq!(grant.begin(&token, 50, 1), Ok(()));
        assert_eq!(grant.accept(1, 50), Ok(()));
        assert_eq!(grant.begin(&token, 50, 2), Ok(()));
        grant.revoke();
        assert_eq!(grant.accept(2, 50), Err(InviteGrantError::WrongRequest));
        assert_eq!(
            grant.begin(&token, 50, 3),
            Err(InviteGrantError::Unavailable)
        );
    }
}
