//! Ricevitore esclusivo per una sessione provvisoria di invito.

use crate::{
    EcnHandling, MAX_UDP_PAYLOAD, UdpIngressFilter, UdpQuicEndpoint, UdpSocketAdapter,
    UdpSocketError,
};
use loquere_crypto::SecretKey;
use loquere_wire::{
    FriendRequest, ProvisionalAction, ProvisionalError, ProvisionalEventGuard, ProvisionalSession,
    QuicEvent, QuicNode, QuicOutput, QuicStreamError, build_provisional_invite_quic_server_config,
};
use quinn_proto::{ConnectionHandle, StreamId, TimeSource};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Errore fatale: il ricevitore chiude il socket e non può essere riutilizzato.
#[derive(Debug)]
pub enum InviteReceiverError {
    /// Configurazione crittografica QUIC non valida.
    Config(loquere_wire::QuicConfigError),
    /// Errore del gate.
    Gate(loquere_wire::GateError),
    /// Errore socket.
    Socket(UdpSocketError),
    /// Errore stream QUIC.
    Stream(QuicStreamError),
    /// Violazione delle restrizioni della sessione provvisoria.
    Protocol(ProvisionalError),
    /// Record FriendAccept malformato o troppo grande.
    Frame(loquere_wire::FrameError),
    /// Connessione non autenticata, chiusa o multipla.
    Connection,
    /// Il ricevitore è stato chiuso dopo un errore.
    Closed,
}

/// Richiesta non ancora autorizzata: occorrono verifica e consenso dell'utente.
pub struct ReceivedFriendRequest {
    /// Chiave dispositivo autenticata da TLS.
    pub peer: [u8; 32],
    /// Token e certificato da verificare con l'invito locale.
    pub request: FriendRequest,
}

/// Possiede socket e QUIC e non espone accesso diretto agli stream.
///
/// Il chiamante deve avviare questo ricevitore solo per un invito attivo,
/// verificandone scadenza, revoca e consumo nel registro persistente. Una
/// richiesta ricevuta non concede fiducia e non invia `FriendAccept`.
pub struct InviteReceiver {
    endpoint: Option<UdpQuicEndpoint>,
    token: Zeroizing<[u8; 16]>,
    inviter: [u8; 32],
    connection: Option<ConnectionHandle>,
    stream: Option<StreamId>,
    guard: Option<ProvisionalEventGuard>,
    session: ProvisionalSession,
    waiting: bool,
    ack: Option<Vec<u8>>,
    ack_offset: usize,
    accept_out: Option<Zeroizing<Vec<u8>>>,
    accept_offset: usize,
    accept_decoder: loquere_wire::FriendAcceptDecoder,
    peer_accept: Option<loquere_wire::FriendAccept>,
}

struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}

impl InviteReceiver {
    /// Variante per un nodo reale: usa l'orologio del sistema per i token QUIC.
    pub fn bind_system(
        address: SocketAddr,
        timeout: Duration,
        ecn: EcnHandling,
        key: Arc<SecretKey>,
        token: [u8; 16],
    ) -> Result<Self, InviteReceiverError> {
        Self::bind(
            address,
            timeout,
            ecn,
            key,
            token,
            Arc::new(SystemTimeSource),
        )
    }
    /// Apre un socket dedicato a un solo invito; il chiamante sceglie il bind.
    pub fn bind(
        address: SocketAddr,
        timeout: Duration,
        ecn: EcnHandling,
        key: Arc<SecretKey>,
        token: [u8; 16],
        time_source: Arc<dyn TimeSource>,
    ) -> Result<Self, InviteReceiverError> {
        let inviter = key.public_key().to_bytes();
        let token = Zeroizing::new(token);
        let mut ingress = UdpIngressFilter::new(inviter);
        ingress
            .authorize_peer_secret(token.as_slice(), inviter)
            .map_err(InviteReceiverError::Gate)?;
        let config = build_provisional_invite_quic_server_config(key, time_source)
            .map_err(InviteReceiverError::Config)?;
        let socket = UdpSocketAdapter::bind_with_ecn_handling(address, timeout, ecn)
            .map_err(InviteReceiverError::Socket)?;
        let reset_key = SecretKey::generate().to_bytes();
        let node = QuicNode::server(*reset_key, Arc::new(config));
        Ok(Self {
            endpoint: Some(UdpQuicEndpoint::new(socket, ingress, node)),
            token,
            inviter,
            connection: None,
            stream: None,
            guard: None,
            session: ProvisionalSession::new(),
            waiting: false,
            ack: None,
            ack_offset: 0,
            accept_out: None,
            accept_offset: 0,
            accept_decoder: loquere_wire::FriendAcceptDecoder::new(),
            peer_accept: None,
        })
    }

    /// Indirizzo effettivo del socket.
    pub fn local_addr(&self) -> Result<SocketAddr, InviteReceiverError> {
        self.endpoint
            .as_ref()
            .ok_or(InviteReceiverError::Closed)?
            .local_addr()
            .map_err(InviteReceiverError::Socket)
    }

    /// Accoda il riscontro solo dopo che il chiamante ha verificato token,
    /// certificato e corrispondenza della chiave TLS. Non accetta l'amicizia.
    pub fn acknowledge_verified(&mut self) -> Result<(), InviteReceiverError> {
        if self.endpoint.is_none() || !self.waiting || self.ack.is_some() {
            return Err(InviteReceiverError::Connection);
        }
        self.ack = Some(loquere_wire::encode_friend_ack());
        Ok(())
    }

    /// Indica solo che QUIC ha accodato il riscontro, non che sia arrivato.
    pub fn ack_queued(&self) -> bool {
        self.ack
            .as_ref()
            .is_some_and(|ack| self.ack_offset == ack.len())
    }

    /// Dopo consenso esplicito, verifica di identità/token e persistenza del
    /// consumo monouso, accoda i propri dati cifrati da TLS. Il chiamante deve
    /// avere effettuato e persistito tutte le verifiche prima della chiamata.
    pub fn accept_after_consent(
        &mut self,
        discovery_secret: &[u8; 32],
        device_list: &[u8],
    ) -> Result<(), InviteReceiverError> {
        if !self.ack_queued() || self.accept_out.is_some() || self.endpoint.is_none() {
            return Err(InviteReceiverError::Connection);
        }
        let frame = loquere_wire::encode_friend_accept(discovery_secret, device_list)
            .map_err(InviteReceiverError::Frame)?;
        self.session
            .approve_verified()
            .map_err(InviteReceiverError::Protocol)?;
        self.accept_out = Some(frame);
        Ok(())
    }

    /// Ritorna i dati dell'altro lato; la firma e l'account sono da verificare.
    pub fn take_peer_accept(&mut self) -> Option<loquere_wire::FriendAccept> {
        self.peer_accept.take()
    }

    /// Indica solo che QUIC ha accodato i dati locali, non la loro consegna.
    pub fn accept_queued(&self) -> bool {
        self.accept_out
            .as_ref()
            .is_some_and(|frame| self.accept_offset == frame.len())
    }

    /// Avanza i timer e riceve al massimo un datagramma. Tutti gli eventi
    /// prodotti vengono controllati; su errore il socket viene chiuso.
    pub fn step(
        &mut self,
        buffer: &mut [u8],
        now: Instant,
        unix_seconds: u64,
    ) -> Result<Option<ReceivedFriendRequest>, InviteReceiverError> {
        let result = self.step_inner(buffer, now, unix_seconds);
        if result.is_err() {
            self.endpoint = None;
        }
        result
    }

    fn step_inner(
        &mut self,
        buffer: &mut [u8],
        now: Instant,
        unix_seconds: u64,
    ) -> Result<Option<ReceivedFriendRequest>, InviteReceiverError> {
        if buffer.len() < MAX_UDP_PAYLOAD {
            return Err(InviteReceiverError::Socket(
                UdpSocketError::ReceiveBufferTooSmall,
            ));
        }
        if let (Some(ack), Some(handle), Some(stream)) = (&self.ack, self.connection, self.stream)
            && self.ack_offset < ack.len()
        {
            let write = self
                .endpoint
                .as_mut()
                .ok_or(InviteReceiverError::Closed)?
                .node_mut()
                .write_stream(handle, stream, &ack[self.ack_offset..]);
            match write {
                Ok(written) => self.ack_offset += written,
                Err(QuicStreamError::Write(quinn_proto::WriteError::Blocked)) => {}
                Err(error) => return Err(InviteReceiverError::Stream(error)),
            }
        }
        if self.ack_queued()
            && let (Some(frame), Some(handle), Some(stream)) =
                (&self.accept_out, self.connection, self.stream)
            && self.accept_offset < frame.len()
        {
            let write = self
                .endpoint
                .as_mut()
                .ok_or(InviteReceiverError::Closed)?
                .node_mut()
                .write_stream(handle, stream, &frame[self.accept_offset..]);
            match write {
                Ok(written) => self.accept_offset += written,
                Err(QuicStreamError::Write(quinn_proto::WriteError::Blocked)) => {}
                Err(error) => return Err(InviteReceiverError::Stream(error)),
            }
        }
        let polled = self
            .endpoint
            .as_mut()
            .ok_or(InviteReceiverError::Closed)?
            .poll(now);
        let mut request = self.process(polled, now, unix_seconds)?;
        let received = self
            .endpoint
            .as_mut()
            .ok_or(InviteReceiverError::Closed)?
            .receive_once(buffer, now, unix_seconds)
            .map_err(InviteReceiverError::Socket)?;
        if let Some(output) = received {
            let next = self.process(output, now, unix_seconds)?;
            if request.is_some() && next.is_some() {
                return Err(InviteReceiverError::Connection);
            }
            if next.is_some() {
                request = next;
            }
        }
        Ok(request)
    }

    fn process(
        &mut self,
        output: QuicOutput,
        now: Instant,
        unix_seconds: u64,
    ) -> Result<Option<ReceivedFriendRequest>, InviteReceiverError> {
        let mut outputs = std::collections::VecDeque::from([output]);
        let mut result = None;
        while let Some(output) = outputs.pop_front() {
            for event in &output.events {
                if let QuicEvent::Connected(handle) = event {
                    if self.connection.is_some() {
                        return Err(InviteReceiverError::Connection);
                    }
                    let peer = self
                        .endpoint
                        .as_mut()
                        .ok_or(InviteReceiverError::Closed)?
                        .node_mut()
                        .authenticated_peer(*handle);
                    if peer.is_none() {
                        return Err(InviteReceiverError::Connection);
                    }
                    self.connection = Some(*handle);
                    self.guard = Some(ProvisionalEventGuard::new(*handle));
                }
                let guard = self.guard.as_mut().ok_or(InviteReceiverError::Connection)?;
                match guard
                    .inspect(event)
                    .map_err(InviteReceiverError::Protocol)?
                {
                    ProvisionalAction::None => {}
                    ProvisionalAction::AcceptStream => loop {
                        let next = self
                            .endpoint
                            .as_mut()
                            .ok_or(InviteReceiverError::Closed)?
                            .node_mut()
                            .accept_bi_stream(
                                self.connection.ok_or(InviteReceiverError::Connection)?,
                            );
                        match next {
                            Ok(stream) => {
                                guard
                                    .accept_stream(stream)
                                    .map_err(InviteReceiverError::Protocol)?;
                                self.stream = Some(stream);
                            }
                            Err(QuicStreamError::NoIncomingStream) => break,
                            Err(error) => return Err(InviteReceiverError::Stream(error)),
                        }
                    },
                    ProvisionalAction::ReadControl(stream) => {
                        if Some(stream) != self.stream {
                            return Err(InviteReceiverError::Connection);
                        }
                    }
                }
            }
            for transmit in &output.datagrams {
                self.endpoint
                    .as_ref()
                    .ok_or(InviteReceiverError::Closed)?
                    .send(
                        transmit,
                        Some((self.inviter, self.token.as_slice())),
                        unix_seconds,
                    )
                    .map_err(InviteReceiverError::Socket)?;
            }
            if let (Some(handle), Some(stream)) = (self.connection, self.stream) {
                let (mut read, more) = self
                    .endpoint
                    .as_mut()
                    .ok_or(InviteReceiverError::Closed)?
                    .node_mut()
                    .read_stream(now, handle, stream, MAX_UDP_PAYLOAD)
                    .map_err(InviteReceiverError::Stream)?;
                if !read.bytes.is_empty() {
                    if self.waiting && self.session.is_approved() {
                        let bytes_len = read.bytes.len();
                        let parsed = self.accept_decoder.push(&read.bytes);
                        use zeroize::Zeroize;
                        read.bytes.zeroize();
                        let (used, accept) = parsed.map_err(InviteReceiverError::Frame)?;
                        if used != bytes_len || (accept.is_some() && self.peer_accept.is_some()) {
                            return Err(InviteReceiverError::Connection);
                        }
                        if accept.is_some() {
                            self.peer_accept = accept;
                        }
                        if read.finished {
                            return Err(InviteReceiverError::Connection);
                        }
                        if !more.events.is_empty() || !more.datagrams.is_empty() {
                            outputs.push_back(more);
                        }
                        continue;
                    }
                    if self.waiting {
                        return Err(InviteReceiverError::Protocol(
                            ProvisionalError::UnexpectedAction,
                        ));
                    }
                    let parsed = self
                        .session
                        .receive_control(&read.bytes)
                        .map_err(InviteReceiverError::Protocol);
                    use zeroize::Zeroize;
                    read.bytes.zeroize();
                    if let Some(request) = parsed? {
                        let peer = self
                            .endpoint
                            .as_mut()
                            .ok_or(InviteReceiverError::Closed)?
                            .node_mut()
                            .authenticated_peer(handle)
                            .ok_or(InviteReceiverError::Connection)?;
                        self.waiting = true;
                        result = Some(ReceivedFriendRequest { peer, request });
                    }
                }
                if read.finished {
                    return Err(InviteReceiverError::Connection);
                }
                if !more.events.is_empty() || !more.datagrams.is_empty() {
                    outputs.push_back(more);
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_identity::{Account, DeviceCert, InviteOptions};
    use loquere_wire::{
        QuicEvent, build_quic_client_config, encode_friend_request, gate_key_id_for,
    };
    use std::time::SystemTime;

    struct FixedTime;
    impl TimeSource for FixedTime {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    #[test]
    fn receiver_owns_socket_and_delivers_only_guarded_request() {
        let inviter = Account::create("Invitante".into(), 1).unwrap();
        let peer = Account::create("Peer".into(), 1).unwrap();
        let invitation = inviter
            .create_invite(
                "Invitante".into(),
                0,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![],
            )
            .unwrap();
        let token = invitation.token();
        let inviter_id = inviter.device_public_key().to_bytes();
        let inviter_key = Arc::new(SecretKey::from_bytes(*inviter.device_signing_key()));
        let peer_key = Arc::new(SecretKey::from_bytes(*peer.device_signing_key()));
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut receiver = InviteReceiver::bind(
            address,
            Duration::from_millis(2),
            EcnHandling::IgnoreExplicitly,
            inviter_key,
            token,
            Arc::new(FixedTime),
        )
        .unwrap();
        let socket = UdpSocketAdapter::bind_with_ecn_handling(
            address,
            Duration::from_millis(2),
            EcnHandling::IgnoreExplicitly,
        )
        .unwrap();
        let mut ingress = UdpIngressFilter::new(inviter_id);
        ingress.authorize_peer_secret(&token, inviter_id).unwrap();
        let mut client = UdpQuicEndpoint::new(socket, ingress, QuicNode::client([0x33; 32]));
        let config = build_quic_client_config(peer_key, inviter.device_public_key()).unwrap();
        let client_handle = client
            .node_mut()
            .connect(
                Instant::now(),
                receiver.local_addr().unwrap(),
                "loquere",
                config,
                Some(gate_key_id_for(inviter_id, &token).unwrap()),
            )
            .unwrap();
        let mut client_buffer = vec![0; MAX_UDP_PAYLOAD];
        let mut receiver_buffer = vec![0; MAX_UDP_PAYLOAD];
        let start = Instant::now();
        let mut sent = false;
        let mut received = false;
        for tick in 0..200 {
            let now = start + Duration::from_millis(tick * 10);
            let mut outputs = vec![client.poll(now)];
            if let Some(output) = client.receive_once(&mut client_buffer, now, 1000).unwrap() {
                outputs.push(output);
            }
            for output in outputs {
                for transmit in &output.datagrams {
                    client
                        .send(transmit, Some((inviter_id, &token)), 1000)
                        .unwrap();
                }
                if !sent
                    && output.events.iter().any(
                        |e| matches!(e, QuicEvent::Connected(handle) if *handle == client_handle),
                    )
                {
                    let stream = client.node_mut().open_bi_stream(client_handle).unwrap();
                    let bytes =
                        encode_friend_request(&token, &peer.device_cert().to_bytes()).unwrap();
                    assert_eq!(
                        client
                            .node_mut()
                            .write_stream(client_handle, stream, &bytes)
                            .unwrap(),
                        bytes.len()
                    );
                    sent = true;
                }
            }
            if let Some(request) = receiver.step(&mut receiver_buffer, now, 1000).unwrap() {
                assert_eq!(request.peer, peer.device_public_key().to_bytes());
                assert_eq!(request.request.token(), &token);
                let cert = DeviceCert::from_bytes(request.request.certificate()).unwrap();
                assert_eq!(cert.device_id().to_bytes(), request.peer);
                received = true;
                break;
            }
        }
        assert!(sent && received);
    }

    #[test]
    fn fatal_error_closes_socket_and_cannot_be_reused() {
        let key = Arc::new(SecretKey::generate());
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut receiver = InviteReceiver::bind(
            address,
            Duration::from_millis(2),
            EcnHandling::IgnoreExplicitly,
            key,
            [1; 16],
            Arc::new(FixedTime),
        )
        .unwrap();
        assert!(matches!(
            receiver.step(&mut [0; 8], Instant::now(), 1),
            Err(InviteReceiverError::Socket(
                UdpSocketError::ReceiveBufferTooSmall
            ))
        ));
        assert!(matches!(
            receiver.local_addr(),
            Err(InviteReceiverError::Closed)
        ));
    }
}
