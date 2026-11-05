//! Invio provvisorio di una richiesta tramite gate e QUIC (D-45, D-46).

use crate::{
    EcnHandling, MAX_UDP_PAYLOAD, UdpIngressFilter, UdpQuicEndpoint, UdpSocketAdapter,
    UdpSocketError,
};
use loquere_crypto::{PublicKey, SecretKey};
use loquere_wire::{
    QuicEvent, QuicNode, QuicOutput, QuicStreamError, build_quic_client_config,
    encode_friend_request, gate_key_id_for,
};
use quinn_proto::{ConnectionHandle, StreamId, WriteError};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Errore fatale del richiedente; il socket viene chiuso.
#[derive(Debug)]
pub enum InviteRequesterError {
    /// Configurazione QUIC o identità non valida.
    Config(loquere_wire::QuicConfigError),
    /// Errore del filtro silenzioso.
    Gate(loquere_wire::GateError),
    /// Errore socket.
    Socket(UdpSocketError),
    /// Connessione QUIC non avviabile.
    Connect(quinn_proto::ConnectError),
    /// Errore stream QUIC.
    Stream(QuicStreamError),
    /// Richiesta non codificabile.
    Frame(loquere_wire::FrameError),
    /// Connessione persa o attività inattesa.
    Connection,
    /// Il richiedente è stato chiuso dopo un errore.
    Closed,
}

/// Un tentativo isolato; non conferma consegna o amicizia.
pub struct InviteRequester {
    endpoint: Option<UdpQuicEndpoint>,
    handle: ConnectionHandle,
    inviter: [u8; 32],
    token: Zeroizing<[u8; 16]>,
    frame: Zeroizing<Vec<u8>>,
    offset: usize,
    stream: Option<StreamId>,
    ack: loquere_wire::FriendAckDecoder,
    acknowledged: bool,
    accept_decoder: loquere_wire::FriendAcceptDecoder,
    peer_accept: Option<loquere_wire::FriendAccept>,
    accept_out: Option<Zeroizing<Vec<u8>>>,
    accept_offset: usize,
}

impl InviteRequester {
    /// Apre un socket temporaneo e prepara la richiesta. Il chiamante deve
    /// prima verificare l'invito e ottenere conferma per contattare il peer.
    pub fn connect(
        destination: SocketAddr,
        inviter: PublicKey,
        token: [u8; 16],
        local: Arc<SecretKey>,
        certificate: &[u8],
        now: Instant,
    ) -> Result<Self, InviteRequesterError> {
        let inviter_id = inviter.to_bytes();
        let token = Zeroizing::new(token);
        let frame =
            encode_friend_request(&token, certificate).map_err(InviteRequesterError::Frame)?;
        let bind_ip = match destination.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = UdpSocketAdapter::bind_with_ecn_handling(
            SocketAddr::new(bind_ip, 0),
            Duration::from_millis(25),
            EcnHandling::IgnoreExplicitly,
        )
        .map_err(InviteRequesterError::Socket)?;
        let mut ingress = UdpIngressFilter::new(inviter_id);
        ingress
            .authorize_peer_secret(token.as_slice(), inviter_id)
            .map_err(InviteRequesterError::Gate)?;
        let config =
            build_quic_client_config(local, inviter).map_err(InviteRequesterError::Config)?;
        let reset = SecretKey::generate().to_bytes();
        let mut endpoint = UdpQuicEndpoint::new(socket, ingress, QuicNode::client(*reset));
        let gate =
            gate_key_id_for(inviter_id, token.as_slice()).map_err(InviteRequesterError::Gate)?;
        let handle = endpoint
            .node_mut()
            .connect(now, destination, "loquere", config, Some(gate))
            .map_err(InviteRequesterError::Connect)?;
        Ok(Self {
            endpoint: Some(endpoint),
            handle,
            inviter: inviter_id,
            token,
            frame,
            offset: 0,
            stream: None,
            ack: loquere_wire::FriendAckDecoder::new(),
            acknowledged: false,
            accept_decoder: loquere_wire::FriendAcceptDecoder::new(),
            peer_accept: None,
            accept_out: None,
            accept_offset: 0,
        })
    }

    /// `true` solo dopo FriendAck verificato; non implica amicizia accettata.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// Dati non verificati ricevuti dall'emittente: il chiamante deve
    /// controllare la lista contro l'invito e il peer TLS prima di fidarsi.
    pub fn peer_accept(&self) -> Option<&loquere_wire::FriendAccept> {
        self.peer_accept.as_ref()
    }

    /// Dopo la verifica del FriendAccept remoto e la conferma dell'utente,
    /// accoda i propri dati. La persistenza spetta al chiamante.
    pub fn respond_after_verification(
        &mut self,
        secret: &[u8; 32],
        device_list: &[u8],
    ) -> Result<(), InviteRequesterError> {
        if !self.acknowledged
            || self.peer_accept.is_none()
            || self.accept_out.is_some()
            || self.endpoint.is_none()
        {
            return Err(InviteRequesterError::Connection);
        }
        self.accept_out = Some(
            loquere_wire::encode_friend_accept(secret, device_list)
                .map_err(InviteRequesterError::Frame)?,
        );
        Ok(())
    }

    /// Indica soltanto che QUIC ha accodato la risposta, non la consegna.
    pub fn accept_queued(&self) -> bool {
        self.accept_out
            .as_ref()
            .is_some_and(|frame| self.accept_offset == frame.len())
    }

    /// Avanza il tentativo e scrive il frame anche in presenza di scritture
    /// parziali. `true` significa solo che QUIC ha accodato tutti i byte.
    pub fn step(
        &mut self,
        buffer: &mut [u8],
        now: Instant,
        unix_seconds: u64,
    ) -> Result<bool, InviteRequesterError> {
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
    ) -> Result<bool, InviteRequesterError> {
        if buffer.len() < MAX_UDP_PAYLOAD {
            return Err(InviteRequesterError::Socket(
                UdpSocketError::ReceiveBufferTooSmall,
            ));
        }
        let output = self
            .endpoint
            .as_mut()
            .ok_or(InviteRequesterError::Closed)?
            .poll(now);
        self.process(output, now, unix_seconds)?;
        let output = self
            .endpoint
            .as_mut()
            .ok_or(InviteRequesterError::Closed)?
            .receive_once(buffer, now, unix_seconds)
            .map_err(InviteRequesterError::Socket)?;
        if let Some(output) = output {
            self.process(output, now, unix_seconds)?;
        }
        if let Some(stream) = self.stream
            && self.offset < self.frame.len()
        {
            let result = self
                .endpoint
                .as_mut()
                .ok_or(InviteRequesterError::Closed)?
                .node_mut()
                .write_stream(self.handle, stream, &self.frame[self.offset..]);
            match result {
                Ok(written) => self.offset += written,
                Err(QuicStreamError::Write(WriteError::Blocked)) => {}
                Err(error) => return Err(InviteRequesterError::Stream(error)),
            }
        }
        if let (Some(stream), Some(frame)) = (self.stream, &self.accept_out)
            && self.accept_offset < frame.len()
        {
            let result = self
                .endpoint
                .as_mut()
                .ok_or(InviteRequesterError::Closed)?
                .node_mut()
                .write_stream(self.handle, stream, &frame[self.accept_offset..]);
            match result {
                Ok(written) => self.accept_offset += written,
                Err(QuicStreamError::Write(WriteError::Blocked)) => {}
                Err(error) => return Err(InviteRequesterError::Stream(error)),
            }
        }
        Ok(self.offset == self.frame.len())
    }

    fn process(
        &mut self,
        output: QuicOutput,
        now: Instant,
        unix_seconds: u64,
    ) -> Result<(), InviteRequesterError> {
        let mut pending = std::collections::VecDeque::from([output]);
        while let Some(output) = pending.pop_front() {
            let mut readable = false;
            for event in &output.events {
                match event {
                    QuicEvent::Connected(handle)
                        if *handle == self.handle && self.stream.is_none() =>
                    {
                        let node = self
                            .endpoint
                            .as_mut()
                            .ok_or(InviteRequesterError::Closed)?
                            .node_mut();
                        if node.authenticated_peer(self.handle) != Some(self.inviter) {
                            return Err(InviteRequesterError::Connection);
                        }
                        self.stream = Some(
                            node.open_bi_stream(self.handle)
                                .map_err(InviteRequesterError::Stream)?,
                        );
                    }
                    QuicEvent::Stream {
                        connection,
                        event: quinn_proto::StreamEvent::Writable { id },
                    } if *connection == self.handle && Some(*id) == self.stream => {}
                    QuicEvent::Stream {
                        connection,
                        event: quinn_proto::StreamEvent::Readable { id },
                    } if *connection == self.handle && Some(*id) == self.stream => {
                        readable = true;
                    }
                    QuicEvent::Stream {
                        connection,
                        event: quinn_proto::StreamEvent::Available { .. },
                    } if *connection == self.handle => {}
                    QuicEvent::DatagramsUnblocked(handle) if *handle == self.handle => {}
                    _ => return Err(InviteRequesterError::Connection),
                }
            }
            for transmit in &output.datagrams {
                self.endpoint
                    .as_ref()
                    .ok_or(InviteRequesterError::Closed)?
                    .send(
                        transmit,
                        Some((self.inviter, self.token.as_slice())),
                        unix_seconds,
                    )
                    .map_err(InviteRequesterError::Socket)?;
            }
            if readable {
                let stream = self.stream.ok_or(InviteRequesterError::Connection)?;
                let (read, more) = self
                    .endpoint
                    .as_mut()
                    .ok_or(InviteRequesterError::Closed)?
                    .node_mut()
                    .read_stream(now, self.handle, stream, MAX_UDP_PAYLOAD)
                    .map_err(InviteRequesterError::Stream)?;
                if !read.bytes.is_empty() {
                    let bytes = Zeroizing::new(read.bytes);
                    let mut remaining = bytes.as_slice();
                    if !self.acknowledged {
                        let (used, done) = self
                            .ack
                            .push(remaining)
                            .map_err(InviteRequesterError::Frame)?;
                        remaining = &remaining[used..];
                        self.acknowledged = done;
                    }
                    if self.acknowledged && !remaining.is_empty() {
                        let (used, accept) = self
                            .accept_decoder
                            .push(remaining)
                            .map_err(InviteRequesterError::Frame)?;
                        if used != remaining.len()
                            || (accept.is_some() && self.peer_accept.is_some())
                        {
                            return Err(InviteRequesterError::Connection);
                        }
                        if accept.is_some() {
                            self.peer_accept = accept;
                        }
                    }
                }
                if read.finished && !self.acknowledged {
                    return Err(InviteRequesterError::Connection);
                }
                if !more.events.is_empty() || !more.datagrams.is_empty() {
                    pending.push_back(more);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InviteReceiver;
    use loquere_identity::{Account, DeviceCert, InviteOptions};

    #[test]
    fn requester_and_receiver_exchange_verified_request_over_udp() {
        let inviter = Account::create("Invitante".into(), 1).unwrap();
        let peer = Account::create("Peer".into(), 1).unwrap();
        let invite = inviter
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
        let inviter_key = Arc::new(SecretKey::from_bytes(*inviter.device_signing_key()));
        let peer_key = Arc::new(SecretKey::from_bytes(*peer.device_signing_key()));
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut receiver = InviteReceiver::bind_system(
            address,
            Duration::from_millis(2),
            EcnHandling::IgnoreExplicitly,
            inviter_key,
            invite.token(),
        )
        .unwrap();
        let mut requester = InviteRequester::connect(
            receiver.local_addr().unwrap(),
            inviter.device_public_key(),
            invite.token(),
            peer_key,
            &peer.device_cert().to_bytes(),
            Instant::now(),
        )
        .unwrap();
        assert!(
            requester
                .respond_after_verification(
                    peer.discovery_secret(),
                    &peer.initial_device_list().unwrap().to_bytes()
                )
                .is_err()
        );
        assert!(
            receiver
                .accept_after_consent(
                    inviter.discovery_secret(),
                    &inviter.initial_device_list().unwrap().to_bytes()
                )
                .is_err()
        );
        let mut receive_buffer = vec![0; MAX_UDP_PAYLOAD];
        let mut send_buffer = vec![0; MAX_UDP_PAYLOAD];
        let start = Instant::now();
        let mut received = false;
        let mut queued = false;
        let mut inviter_accepted = false;
        let mut peer_responded = false;
        let mut reciprocal_received = false;
        for tick in 0..400 {
            let now = start + Duration::from_millis(tick * 10);
            queued |= requester.step(&mut send_buffer, now, 1000).unwrap();
            if let Some(request) = receiver.step(&mut receive_buffer, now, 1000).unwrap() {
                assert_eq!(request.peer, peer.device_public_key().to_bytes());
                assert_eq!(request.request.token(), &invite.token());
                let cert = DeviceCert::from_bytes(request.request.certificate()).unwrap();
                assert_eq!(cert.account_id(), peer.account_id());
                assert_eq!(cert.device_id().to_bytes(), request.peer);
                received = true;
                receiver.acknowledge_verified().unwrap();
            }
            if received && receiver.ack_queued() && !inviter_accepted {
                // Il consenso e la persistenza del token sono simulati nel test.
                receiver
                    .accept_after_consent(
                        inviter.discovery_secret(),
                        &inviter.initial_device_list().unwrap().to_bytes(),
                    )
                    .unwrap();
                inviter_accepted = true;
            }
            if let Some(accept) = requester.peer_accept()
                && !peer_responded
            {
                let list = loquere_identity::DeviceList::from_bytes(accept.device_list()).unwrap();
                assert_eq!(list.account_id(), inviter.account_id());
                assert!(list.contains_device(&inviter.device_public_key().to_bytes()));
                assert_eq!(accept.discovery_secret(), inviter.discovery_secret());
                requester
                    .respond_after_verification(
                        peer.discovery_secret(),
                        &peer.initial_device_list().unwrap().to_bytes(),
                    )
                    .unwrap();
                peer_responded = true;
            }
            if let Some(accept) = receiver.take_peer_accept() {
                let list = loquere_identity::DeviceList::from_bytes(accept.device_list()).unwrap();
                assert_eq!(list.account_id(), peer.account_id());
                assert!(list.contains_device(&peer.device_public_key().to_bytes()));
                assert_eq!(accept.discovery_secret(), peer.discovery_secret());
                reciprocal_received = true;
            }
            if reciprocal_received && requester.accept_queued() {
                break;
            }
        }
        assert!(queued && received && requester.acknowledged());
        assert!(receiver.ack_queued());
        assert!(
            inviter_accepted && peer_responded && reciprocal_received && receiver.accept_queued()
        );
    }
}
