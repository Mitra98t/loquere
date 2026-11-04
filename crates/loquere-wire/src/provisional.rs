//! Limitazione sans-IO di una sessione iniziale qualificata dal gate (D-45).

use crate::{FrameError, FriendRequest, FriendRequestDecoder};

/// Violazione del protocollo o fase non corretta; chiudere la connessione.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionalError {
    /// Il primo record è assente, troncato o malformato.
    InvalidRequest(FrameError),
    /// Azione non ammessa nella fase corrente.
    UnexpectedAction,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Reading,
    AwaitingDecision,
    Approved,
    Closed,
}

/// Guard di una singola connessione QUIC provvisoria.
///
/// Il chiamante deve creare il guard solo dopo gate invito e TLS completato,
/// inoltrare tutti gli eventi rilevanti e chiudere QUIC su ogni errore. Questo
/// oggetto non può da solo bloccare stream aperti direttamente sul nodo QUIC.
pub struct ProvisionalSession {
    state: State,
    decoder: FriendRequestDecoder,
}

impl Default for ProvisionalSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisionalSession {
    /// Inizializza la fase che ammette solo il primo FriendRequest.
    pub fn new() -> Self {
        Self {
            state: State::Reading,
            decoder: FriendRequestDecoder::new(),
        }
    }

    /// Riceve byte dallo stream di controllo iniziale; nessun byte successivo
    /// al FriendRequest è ammesso prima della decisione.
    pub fn receive_control(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<FriendRequest>, ProvisionalError> {
        if self.state != State::Reading {
            return self.close_unexpected();
        }
        let (used, request) = match self.decoder.push(bytes) {
            Ok(value) => value,
            Err(error) => {
                self.state = State::Closed;
                return Err(ProvisionalError::InvalidRequest(error));
            }
        };
        if used != bytes.len() {
            return self.close_unexpected();
        }
        if request.is_some() {
            self.state = State::AwaitingDecision;
        }
        Ok(request)
    }

    /// Stream supplementari, datagrammi o chiusura prematura vanno rifiutati.
    pub fn reject_unexpected_activity(&mut self) -> Result<(), ProvisionalError> {
        self.close_unexpected()
    }

    /// Promuove solo dopo verifica del peer TLS, certificato e token, consenso
    /// esplicito e persistenza del consumo monouso. Il chiamante deve aver già
    /// completato tutte queste verifiche; il guard non le esegue da sé.
    pub fn approve_verified(&mut self) -> Result<(), ProvisionalError> {
        if self.state != State::AwaitingDecision {
            return self.close_unexpected();
        }
        self.state = State::Approved;
        Ok(())
    }

    /// Indica solo la promozione locale esplicita, non la creazione di amicizia.
    pub fn is_approved(&self) -> bool {
        self.state == State::Approved
    }

    fn close_unexpected<T>(&mut self) -> Result<T, ProvisionalError> {
        self.state = State::Closed;
        Err(ProvisionalError::UnexpectedAction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_friend_request;

    #[test]
    fn only_complete_request_can_reach_explicit_approval() {
        let encoded = encode_friend_request(&[7; 16], b"certificate").unwrap();
        let mut session = ProvisionalSession::new();
        assert!(session.receive_control(&encoded[..3]).unwrap().is_none());
        let request = session.receive_control(&encoded[3..]).unwrap().unwrap();
        assert_eq!(request.token(), &[7; 16]);
        assert!(!session.is_approved());
        session.approve_verified().unwrap();
        assert!(session.is_approved());
    }

    #[test]
    fn premature_approval_or_extra_activity_is_fail_closed() {
        let mut session = ProvisionalSession::new();
        assert_eq!(
            session.approve_verified(),
            Err(ProvisionalError::UnexpectedAction)
        );
        assert!(!session.is_approved());
        let mut session = ProvisionalSession::new();
        let mut encoded = encode_friend_request(&[7; 16], b"cert").unwrap().to_vec();
        encoded.push(0);
        assert!(session.receive_control(&encoded).is_err());
        assert!(session.approve_verified().is_err());
        let mut session = ProvisionalSession::new();
        assert!(session.reject_unexpected_activity().is_err());
        assert!(session.receive_control(&[]).is_err());
    }
}
