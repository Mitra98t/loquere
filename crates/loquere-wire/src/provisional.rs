//! Limitazione sans-IO di una sessione iniziale qualificata dal gate (D-45).

use crate::{FrameError, FriendRequest, FriendRequestDecoder, QuicEvent};
use quinn_proto::{ConnectionHandle, Dir, Side, StreamEvent, StreamId};

/// Violazione del protocollo o fase non corretta; chiudere la connessione.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionalError {
    /// Il primo record è assente, troncato o malformato.
    InvalidRequest(FrameError),
    /// Azione non ammessa nella fase corrente.
    UnexpectedAction,
}

/// Operazione QUIC richiesta dopo l'ispezione di un evento provvisorio.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionalAction {
    /// Nessuna operazione applicativa richiesta.
    None,
    /// Accettare lo stream bidirezionale e verificare con `accept_stream`.
    AcceptStream,
    /// Leggere lo stream di controllo e passare i byte a `receive_control`.
    ReadControl(StreamId),
}

/// Associa gli eventi QUIC di un'unica connessione allo stream di controllo 0.
/// Il driver deve esaminare ogni evento, svuotare tutti gli stream accettabili
/// dopo `AcceptStream` e interrompere la connessione su qualsiasi errore.
pub struct ProvisionalEventGuard {
    connection: ConnectionHandle,
    control_accepted: bool,
    closed: bool,
}

impl ProvisionalEventGuard {
    /// Associa un guard a una connessione qualificata dal gate d'invito.
    pub fn new(connection: ConnectionHandle) -> Self {
        Self {
            connection,
            control_accepted: false,
            closed: false,
        }
    }

    /// Controlla un evento QUIC prima di qualsiasi elaborazione applicativa.
    pub fn inspect(&mut self, event: &QuicEvent) -> Result<ProvisionalAction, ProvisionalError> {
        if self.closed {
            return Err(ProvisionalError::UnexpectedAction);
        }
        let control = StreamId::new(Side::Client, Dir::Bi, 0);
        match event {
            QuicEvent::Connected(handle) if *handle == self.connection => {
                Ok(ProvisionalAction::None)
            }
            QuicEvent::Stream { connection, event } if *connection == self.connection => {
                match event {
                    StreamEvent::Opened { dir: Dir::Bi } => Ok(ProvisionalAction::AcceptStream),
                    StreamEvent::Readable { id } if *id == control && self.control_accepted => {
                        Ok(ProvisionalAction::ReadControl(*id))
                    }
                    StreamEvent::Writable { id } if *id == control && self.control_accepted => {
                        Ok(ProvisionalAction::None)
                    }
                    StreamEvent::Available { .. } => Ok(ProvisionalAction::None),
                    _ => self.fail(),
                }
            }
            QuicEvent::DatagramsUnblocked(handle) if *handle == self.connection => {
                Ok(ProvisionalAction::None)
            }
            _ => self.fail(),
        }
    }

    /// Valida ogni stream restituito da `accept_bi_stream`; ne è ammesso uno solo.
    pub fn accept_stream(&mut self, id: StreamId) -> Result<(), ProvisionalError> {
        if self.closed || self.control_accepted || id != StreamId::new(Side::Client, Dir::Bi, 0) {
            return self.fail();
        }
        self.control_accepted = true;
        Ok(())
    }

    fn fail<T>(&mut self) -> Result<T, ProvisionalError> {
        self.closed = true;
        Err(ProvisionalError::UnexpectedAction)
    }
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

    #[test]
    fn event_guard_rejects_extra_streams_datagrams_and_other_connections() {
        let handle = ConnectionHandle(5);
        let stream = StreamId::new(Side::Client, Dir::Bi, 0);
        let mut guard = ProvisionalEventGuard::new(handle);
        assert_eq!(
            guard.inspect(&QuicEvent::Stream {
                connection: handle,
                event: StreamEvent::Opened { dir: Dir::Bi }
            }),
            Ok(ProvisionalAction::AcceptStream)
        );
        assert_eq!(guard.accept_stream(stream), Ok(()));
        assert_eq!(
            guard.inspect(&QuicEvent::Stream {
                connection: handle,
                event: StreamEvent::Readable { id: stream }
            }),
            Ok(ProvisionalAction::ReadControl(stream))
        );
        assert_eq!(
            guard.accept_stream(StreamId::new(Side::Client, Dir::Bi, 1)),
            Err(ProvisionalError::UnexpectedAction)
        );
        assert!(guard.inspect(&QuicEvent::Connected(handle)).is_err());
        let mut guard = ProvisionalEventGuard::new(handle);
        assert!(guard.inspect(&QuicEvent::DatagramReceived(handle)).is_err());
        let mut guard = ProvisionalEventGuard::new(handle);
        assert!(
            guard
                .inspect(&QuicEvent::Connected(ConnectionHandle(6)))
                .is_err()
        );
        let mut guard = ProvisionalEventGuard::new(handle);
        assert!(
            guard
                .inspect(&QuicEvent::Stream {
                    connection: handle,
                    event: StreamEvent::Opened { dir: Dir::Uni }
                })
                .is_err()
        );
    }
}
