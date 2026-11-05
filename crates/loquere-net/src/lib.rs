#![forbid(unsafe_code)]

//! Filtro dei datagrammi UDP prima del driver QUIC.

use loquere_wire::{
    GateDecision, GateError, QuicNode, QuicOutput, QuicTransmit, SilentFilter,
    gate_initial_datagram, gate_key_id_for, is_quic_initial_packet,
};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

mod invite_receiver;
pub use invite_receiver::{InviteReceiver, InviteReceiverError, ReceivedFriendRequest};

/// Socket UDP bloccante da possedere nel thread `net`.
///
/// Il buffer di ricezione appartiene al chiamante. L'adapter usa solo API
/// portabili `std`; trasmissioni che richiedono ECN, source-IP override o GSO
/// falliscono esplicitamente finché non sarà aggiunto il backend OS dedicato.
pub struct UdpSocketAdapter {
    socket: UdpSocket,
    ecn_handling: EcnHandling,
}

/// Politica esplicita per i codepoint ECN che l'API UDP standard non può
/// applicare. La modalità predefinita è `Reject`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EcnHandling {
    /// Non inviare pacchetti se Quinn richiede un codepoint ECN.
    #[default]
    Reject,
    /// Invia comunque, accettando esplicitamente di non applicare ECN.
    IgnoreExplicitly,
}

/// Collegamento tra socket, filtro d'ingresso e macchina QUIC sans-IO.
/// L'istanza va posseduta dal solo thread `net`; l'engine interagisce con
/// [`Self::node_mut`] e consegna al socket i datagrammi prodotti.
pub struct UdpQuicEndpoint {
    socket: UdpSocketAdapter,
    ingress: UdpIngressFilter,
    node: QuicNode,
}

/// Datagramma ricevuto dalla socket, senza interpretazione del payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedDatagram {
    /// Byte scritti nel buffer fornito a [`UdpSocketAdapter::receive`].
    pub length: usize,
    /// Indirizzo sorgente UDP.
    pub source: SocketAddr,
}

/// Errore di trasporto UDP o metadato non supportato dall'adapter portabile.
#[derive(Debug)]
pub enum UdpSocketError {
    /// Operazione socket fallita.
    Io(io::Error),
    /// L'operazione richiede un backend OS non ancora implementato.
    UnsupportedMetadata(&'static str),
    /// Iniziale non prefissato o credenziale non corrispondente.
    Gate(GateError),
    /// Un QUIC Initial deve essere inviato con [`UdpSocketAdapter::send_gate_initial`].
    InitialRequiresGate,
    /// Datagramma più grande del massimo payload UDP IP consentito.
    DatagramTooLarge,
    /// Il buffer di ricezione può troncare un datagramma UDP valido.
    ReceiveBufferTooSmall,
}

impl UdpSocketAdapter {
    /// Apre un socket su un indirizzo esplicito. Per IPv4 e IPv6 si creano
    /// adapter distinti, entrambi posseduti dal thread `net`.
    pub fn bind(address: SocketAddr, read_timeout: Duration) -> Result<Self, UdpSocketError> {
        Self::bind_with_ecn_handling(address, read_timeout, EcnHandling::Reject)
    }

    /// Come [`Self::bind`], con una scelta esplicita per l'ECN.
    pub fn bind_with_ecn_handling(
        address: SocketAddr,
        read_timeout: Duration,
        ecn_handling: EcnHandling,
    ) -> Result<Self, UdpSocketError> {
        let socket = UdpSocket::bind(address).map_err(UdpSocketError::Io)?;
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(UdpSocketError::Io)?;
        Ok(Self {
            socket,
            ecn_handling,
        })
    }

    /// Indirizzo locale effettivamente assegnato, utile quando la porta era 0.
    pub fn local_addr(&self) -> Result<SocketAddr, UdpSocketError> {
        self.socket.local_addr().map_err(UdpSocketError::Io)
    }

    /// Riceve un singolo datagramma nel buffer fornito, evitando allocazioni
    /// interne e mantenendo l'indirizzo sorgente.
    pub fn receive(&self, buffer: &mut [u8]) -> Result<ReceivedDatagram, UdpSocketError> {
        let (length, source) = self.socket.recv_from(buffer).map_err(UdpSocketError::Io)?;
        Ok(ReceivedDatagram { length, source })
    }

    /// Invia un `Transmit` Quinn se i suoi metadati sono rappresentabili
    /// dall'API UDP portabile. Non modifica il payload QUIC.
    pub fn send(&self, transmit: &QuicTransmit) -> Result<usize, UdpSocketError> {
        self.validate_transmit(transmit)?;
        if is_quic_initial_packet(&transmit.payload) {
            return Err(UdpSocketError::InitialRequiresGate);
        }
        self.socket
            .send_to(&transmit.payload, transmit.destination)
            .map_err(UdpSocketError::Io)
    }

    /// Prefissa e invia un QUIC v1 Initial con la credenziale associata alla
    /// trasmissione. Il timestamp Unix è fornito dal chiamante.
    pub fn send_gate_initial(
        &self,
        transmit: &QuicTransmit,
        recipient_device_id: [u8; 32],
        secret: &[u8],
        timestamp_unix_seconds: u64,
    ) -> Result<usize, UdpSocketError> {
        self.validate_transmit(transmit)?;
        if !is_quic_initial_packet(&transmit.payload) {
            return Err(UdpSocketError::Gate(GateError::NotInitialPacket));
        }
        let key_id = gate_key_id_for(recipient_device_id, secret).map_err(UdpSocketError::Gate)?;
        if transmit.gate_key_id != Some(key_id) {
            return Err(UdpSocketError::UnsupportedMetadata(
                "gate key ID non corrisponde al segreto del peer",
            ));
        }
        let datagram = gate_initial_datagram(
            recipient_device_id,
            secret,
            timestamp_unix_seconds,
            &transmit.payload,
        )
        .map_err(UdpSocketError::Gate)?;
        self.socket
            .send_to(&datagram, transmit.destination)
            .map_err(UdpSocketError::Io)
    }

    fn validate_transmit(&self, transmit: &QuicTransmit) -> Result<(), UdpSocketError> {
        if transmit.payload.len() > 65_507 {
            return Err(UdpSocketError::DatagramTooLarge);
        }
        if transmit.ecn.is_some() && self.ecn_handling == EcnHandling::Reject {
            return Err(UdpSocketError::UnsupportedMetadata("ECN"));
        }
        if transmit.segment_size.is_some() {
            return Err(UdpSocketError::UnsupportedMetadata("UDP GSO"));
        }
        if let Some(source_ip) = transmit.source_ip {
            let local_ip = self.socket.local_addr().map_err(UdpSocketError::Io)?.ip();
            if source_ip != local_ip {
                return Err(UdpSocketError::UnsupportedMetadata(
                    "source IP diverso dall'indirizzo di bind",
                ));
            }
        }
        Ok(())
    }
}

impl UdpQuicEndpoint {
    /// Collega i tre componenti senza trasferire ownership del clock o del
    /// thread: il chiamante resta responsabile di invocare poll e timer.
    pub fn new(socket: UdpSocketAdapter, ingress: UdpIngressFilter, node: QuicNode) -> Self {
        Self {
            socket,
            ingress,
            node,
        }
    }

    /// Riceve un datagramma, lo filtra e, solo se autorizzato, lo passa a QUIC.
    /// `None` indica timeout o pacchetto silenziosamente scartato.
    pub fn receive_once(
        &mut self,
        buffer: &mut [u8],
        now: std::time::Instant,
        now_unix_seconds: u64,
    ) -> Result<Option<QuicOutput>, UdpSocketError> {
        if buffer.len() < MAX_UDP_PAYLOAD {
            return Err(UdpSocketError::ReceiveBufferTooSmall);
        }
        let received = match self.socket.receive(buffer) {
            Ok(received) => received,
            Err(UdpSocketError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let datagram = &buffer[..received.length];
        let Some(accepted) =
            self.ingress
                .inspect(&self.node, received.source, datagram, now_unix_seconds)
        else {
            return Ok(None);
        };
        let local_ip = self.socket.local_addr()?.ip();
        Ok(Some(self.node.receive(
            now,
            received.source,
            Some(local_ip),
            None,
            accepted.peer_gate_key_id,
            accepted.packet,
        )))
    }

    /// Fa avanzare timer e trasmissioni sans-IO di Quinn.
    pub fn poll(&mut self, now: std::time::Instant) -> QuicOutput {
        self.node.poll(now)
    }

    /// Invia un pacchetto prodotto da Quinn, applicando il gate agli Initial.
    pub fn send(
        &self,
        transmit: &QuicTransmit,
        gate_peer: Option<([u8; 32], &[u8])>,
        now_unix_seconds: u64,
    ) -> Result<usize, UdpSocketError> {
        if is_quic_initial_packet(&transmit.payload) {
            let (recipient_device_id, secret) =
                gate_peer.ok_or(UdpSocketError::InitialRequiresGate)?;
            self.socket
                .send_gate_initial(transmit, recipient_device_id, secret, now_unix_seconds)
        } else {
            self.socket.send(transmit)
        }
    }

    /// Accesso alla macchina QUIC per connect, stream, datagrammi e stato.
    pub fn node_mut(&mut self) -> &mut QuicNode {
        &mut self.node
    }

    /// Registra un segreto peer nel filtro d'ingresso.
    pub fn authorize_secret(&mut self, secret: &[u8]) -> Result<[u8; 16], GateError> {
        self.ingress.authorize_secret(secret)
    }

    /// Autorizza un peer e registra il key ID necessario alle risposte Initial.
    pub fn authorize_peer_secret(
        &mut self,
        secret: &[u8],
        peer_device_id: [u8; 32],
    ) -> Result<[u8; 16], GateError> {
        self.ingress.authorize_peer_secret(secret, peer_device_id)
    }

    /// Indirizzo locale effettivo del socket.
    pub fn local_addr(&self) -> Result<SocketAddr, UdpSocketError> {
        self.socket.local_addr()
    }
}

const MAX_UDP_PAYLOAD: usize = 65_507;

impl std::fmt::Display for UdpSocketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "socket UDP: {error}"),
            Self::UnsupportedMetadata(metadata) => {
                write!(formatter, "metadato UDP non supportato: {metadata}")
            }
            Self::Gate(error) => write!(formatter, "filtro gate: {error}"),
            Self::InitialRequiresGate => {
                formatter.write_str("un QUIC Initial richiede il prefisso gate autenticato")
            }
            Self::DatagramTooLarge => formatter.write_str("datagramma UDP troppo grande"),
            Self::ReceiveBufferTooSmall => {
                formatter.write_str("buffer troppo piccolo per ricevere UDP senza troncamenti")
            }
        }
    }
}

impl std::error::Error for UdpSocketError {}

/// Pacchetto ammesso dal filtro UDP, pronto per [`QuicNode::receive`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedDatagram<'a> {
    /// Payload QUIC, senza eventuale prefisso Loquere.
    pub packet: &'a [u8],
    /// Credenziale che ha autenticato un Initial; `None` per CID già noti.
    pub gate_key_id: Option<[u8; 16]>,
    /// Key ID destinatario remoto, utile per prefissare una risposta Initial.
    pub peer_gate_key_id: Option<[u8; 16]>,
}

/// Filtro d'ingresso UDP: i primi pacchetti richiedono un segreto gate, gli
/// altri devono portare un CID locale autenticato. Non apre socket e non invia.
pub struct UdpIngressFilter {
    gate: SilentFilter,
    peer_gate_ids: std::collections::HashMap<[u8; 16], [u8; 16]>,
}

impl UdpIngressFilter {
    /// Crea il filtro per l'identità pubblica del dispositivo destinatario.
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            gate: SilentFilter::new(device_id),
            peer_gate_ids: std::collections::HashMap::new(),
        }
    }

    /// Registra il segreto di un invito o di una relazione esistente.
    pub fn authorize_secret(&mut self, secret: &[u8]) -> Result<[u8; 16], GateError> {
        self.gate.authorize_secret(secret)
    }

    /// Registra una credenziale legata anche al DeviceId remoto, così le
    /// risposte QUIC Initial possono essere prefissate con il key ID destinato
    /// a quel peer. Il valore restituito è il key ID locale d'ingresso.
    pub fn authorize_peer_secret(
        &mut self,
        secret: &[u8],
        peer_device_id: [u8; 32],
    ) -> Result<[u8; 16], GateError> {
        let local_key_id = self.gate.authorize_secret(secret)?;
        let peer_key_id = gate_key_id_for(peer_device_id, secret)?;
        self.peer_gate_ids.insert(local_key_id, peer_key_id);
        Ok(local_key_id)
    }

    /// Revoca il segreto identificato dal key ID.
    pub fn revoke(&mut self, key_id: &[u8; 16]) -> bool {
        self.peer_gate_ids.remove(key_id);
        self.gate.revoke_key_id(key_id)
    }

    /// Ispeziona un datagramma senza produrre alcuna risposta per input
    /// malformati, Initial non autorizzati o Connection ID inventati.
    pub fn inspect<'a>(
        &mut self,
        node: &QuicNode,
        source: SocketAddr,
        datagram: &'a [u8],
        now_unix_seconds: u64,
    ) -> Option<AcceptedDatagram<'a>> {
        if has_initial_after_gate_prefix(datagram) {
            return match self
                .gate
                .inspect_initial(source, datagram, now_unix_seconds)
            {
                GateDecision::PassInitial { packet, key_id } => Some(AcceptedDatagram {
                    packet,
                    gate_key_id: Some(key_id),
                    peer_gate_key_id: self.peer_gate_ids.get(&key_id).copied(),
                }),
                GateDecision::Drop => None,
            };
        }

        if loquere_wire::is_quic_initial_packet(datagram) {
            return None;
        }
        let cid = destination_cid(datagram)?;
        node.validates_local_connection_id(cid)
            .then_some(AcceptedDatagram {
                packet: datagram,
                gate_key_id: None,
                peer_gate_key_id: None,
            })
    }
}

const GATE_PREFIX_LEN: usize = 40;
const LOCAL_CID_LEN: usize = 16;

fn has_initial_after_gate_prefix(datagram: &[u8]) -> bool {
    datagram
        .get(GATE_PREFIX_LEN..)
        .is_some_and(loquere_wire::is_quic_initial_packet)
}

fn destination_cid(datagram: &[u8]) -> Option<&[u8]> {
    let first = *datagram.first()?;
    if first & 0x80 != 0 {
        if datagram.len() < 6 {
            return None;
        }
        let version = u32::from_be_bytes(datagram[1..5].try_into().ok()?);
        // Unsupported versions, including Version Negotiation, never reach Quinn.
        if version != 1 || first & 0x30 == 0 {
            return None;
        }
        let cid_len = usize::from(datagram[5]);
        if cid_len != LOCAL_CID_LEN {
            return None;
        }
        datagram.get(6..6 + cid_len)
    } else {
        // RFC 9287 permette al peer di azzerare il bit fisso dopo la
        // negoziazione; il CID autenticato rimane obbligatorio per passare.
        if datagram.len() < 1 + LOCAL_CID_LEN {
            return None;
        }
        datagram.get(1..1 + LOCAL_CID_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_crypto::SecretKey;
    use loquere_wire::{build_quic_client_config, build_quic_server_config, gate_initial_datagram};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    struct FixedTime;

    impl quinn_proto::TimeSource for FixedTime {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 99], port))
    }

    #[test]
    fn only_authorized_initial_packets_pass_and_gate_key_is_returned() {
        let device_id = [0x52; 32];
        let peer_device_id = [0x12; 32];
        let secret = [0xa3; 16];
        let packet = [0xc0, 0, 0, 0, 1, 0];
        let datagram = gate_initial_datagram(device_id, &secret, 1000, &packet).unwrap();
        let mut filter = UdpIngressFilter::new(device_id);
        let node = QuicNode::client([0x11; 32]);

        assert_eq!(filter.inspect(&node, source(4000), &datagram, 1000), None);
        let key_id = filter
            .authorize_peer_secret(&secret, peer_device_id)
            .unwrap();
        let accepted = filter
            .inspect(&node, source(4000), &datagram, 1000)
            .unwrap();
        assert_eq!(accepted.packet, packet);
        assert_eq!(accepted.gate_key_id, Some(key_id));
        assert_eq!(
            accepted.peer_gate_key_id,
            Some(gate_key_id_for(peer_device_id, &secret).unwrap())
        );
        assert_eq!(filter.inspect(&node, source(4001), &packet, 1000), None);
    }

    #[test]
    fn malformed_mac_and_unknown_connection_ids_are_silently_dropped() {
        let device_id = [0x25; 32];
        let secret = [0x71; 16];
        let packet = [0xc0, 0, 0, 0, 1, 0];
        let mut datagram = gate_initial_datagram(device_id, &secret, 1500, &packet).unwrap();
        datagram[25] ^= 1;
        let mut filter = UdpIngressFilter::new(device_id);
        filter.authorize_secret(&secret).unwrap();
        let node = QuicNode::client([0x19; 32]);

        assert_eq!(filter.inspect(&node, source(4000), &datagram, 1500), None);
        let forged_short_packet = [0x40; 64];
        assert_eq!(
            filter.inspect(&node, source(4000), &forged_short_packet, 1500),
            None
        );
        let forged_greased_packet = [0x00; 64];
        assert_eq!(
            destination_cid(&forged_greased_packet),
            Some(&forged_greased_packet[1..17])
        );
        assert_eq!(
            filter.inspect(&node, source(4000), &forged_greased_packet, 1500),
            None
        );
        let unsupported = [0xc0, 0, 0, 0, 2, 0];
        assert_eq!(
            filter.inspect(&node, source(4000), &unsupported, 1500),
            None
        );
    }

    #[test]
    fn expired_gate_initial_is_not_misparsed_as_a_short_header() {
        let device_id = [0x29; 32];
        let secret = [0x72; 16];
        let packet = [0xc0, 0, 0, 0, 1, 0];
        let datagram = gate_initial_datagram(device_id, &secret, 1_000, &packet).unwrap();
        let mut filter = UdpIngressFilter::new(device_id);
        filter.authorize_secret(&secret).unwrap();
        let node = QuicNode::client([0x19; 32]);

        // Expired packets are rejected by the gate even though their prefix
        // cannot be distinguished by guessing based on the current timestamp.
        assert_eq!(filter.inspect(&node, source(4000), &datagram, 10_000), None);
    }

    #[test]
    fn udp_adapter_sends_and_receives_without_changing_payload() {
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let first = UdpSocketAdapter::bind(loopback, Duration::from_secs(1)).unwrap();
        let second = UdpSocketAdapter::bind(loopback, Duration::from_secs(1)).unwrap();
        let destination = second.local_addr().unwrap();
        let payload = b"raw quic payload".to_vec();
        let transmit = QuicTransmit {
            destination,
            source_ip: None,
            ecn: None,
            segment_size: None,
            connection: None,
            gate_key_id: None,
            payload: payload.clone(),
        };

        assert_eq!(first.send(&transmit).unwrap(), payload.len());
        let mut buffer = [0u8; 64];
        let received = second.receive(&mut buffer).unwrap();
        assert_eq!(&buffer[..received.length], payload);
        assert_eq!(received.source, first.local_addr().unwrap());
    }

    #[test]
    fn udp_adapter_rejects_metadata_it_cannot_apply() {
        let socket = UdpSocketAdapter::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            Duration::from_millis(10),
        )
        .unwrap();
        let mut transmit = QuicTransmit {
            destination: source(1),
            source_ip: None,
            ecn: Some(quinn_proto::EcnCodepoint::Ect0),
            segment_size: None,
            connection: None,
            gate_key_id: None,
            payload: vec![1, 2, 3],
        };
        assert!(matches!(
            socket.send(&transmit),
            Err(UdpSocketError::UnsupportedMetadata("ECN"))
        ));
        transmit.ecn = None;
        transmit.segment_size = Some(1200);
        assert!(matches!(
            socket.send(&transmit),
            Err(UdpSocketError::UnsupportedMetadata("UDP GSO"))
        ));
    }

    #[test]
    fn udp_adapter_requires_and_applies_gate_prefix_for_initial() {
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let sender = UdpSocketAdapter::bind(loopback, Duration::from_secs(1)).unwrap();
        let receiver = UdpSocketAdapter::bind(loopback, Duration::from_secs(1)).unwrap();
        let device_id = [0x36; 32];
        let secret = [0x92; 16];
        let payload = vec![0xc0, 0, 0, 0, 1, 0];
        let transmit = QuicTransmit {
            destination: receiver.local_addr().unwrap(),
            source_ip: None,
            ecn: None,
            segment_size: None,
            connection: None,
            gate_key_id: Some(gate_key_id_for(device_id, &secret).unwrap()),
            payload: payload.clone(),
        };
        assert!(matches!(
            sender.send(&transmit),
            Err(UdpSocketError::InitialRequiresGate)
        ));
        assert_eq!(
            sender
                .send_gate_initial(&transmit, device_id, &secret, 5000)
                .unwrap(),
            payload.len() + 40
        );
        let mut buffer = [0u8; 128];
        let received = receiver.receive(&mut buffer).unwrap();
        assert_eq!(received.length, payload.len() + 40);
        let mut ingress = UdpIngressFilter::new(device_id);
        ingress.authorize_secret(&secret).unwrap();
        let accepted = ingress
            .inspect(
                &QuicNode::client([0x11; 32]),
                received.source,
                &buffer[..received.length],
                5000,
            )
            .unwrap();
        assert_eq!(accepted.packet, payload);
    }

    #[test]
    fn combined_endpoint_drops_unauthorized_packets_and_handles_timeouts() {
        let socket = UdpSocketAdapter::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            Duration::from_millis(5),
        )
        .unwrap();
        let ingress = UdpIngressFilter::new([0x44; 32]);
        let mut endpoint = UdpQuicEndpoint::new(socket, ingress, QuicNode::client([0x11; 32]));
        let now = std::time::Instant::now();
        assert!(matches!(
            endpoint.receive_once(&mut [0; MAX_UDP_PAYLOAD], now, 1000),
            Ok(None)
        ));
        assert!(matches!(
            endpoint.receive_once(&mut [0; 32], now, 1000),
            Err(UdpSocketError::ReceiveBufferTooSmall)
        ));
    }

    #[test]
    fn temporary_invite_gate_connects_unknown_device_and_receives_request() {
        let inviter = loquere_identity::Account::create("Invitante".into(), 1).unwrap();
        let requester = loquere_identity::Account::create("Richiedente".into(), 1).unwrap();
        let invitation = inviter
            .create_invite(
                "Invitante".into(),
                0,
                loquere_identity::InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![],
            )
            .unwrap();
        let inviter_key = Arc::new(SecretKey::from_bytes(*inviter.device_signing_key()));
        let requester_key = Arc::new(SecretKey::from_bytes(*requester.device_signing_key()));
        let inviter_id = inviter_key.public_key().to_bytes();
        let requester_id = requester_key.public_key().to_bytes();
        let token = invitation.token();
        let client_config =
            build_quic_client_config(requester_key, inviter_key.public_key()).unwrap();
        let server_config = Arc::new(
            loquere_wire::build_provisional_invite_quic_server_config(
                inviter_key,
                Arc::new(FixedTime),
            )
            .unwrap(),
        );
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let make_socket = || {
            UdpSocketAdapter::bind_with_ecn_handling(
                loopback,
                Duration::from_millis(2),
                EcnHandling::IgnoreExplicitly,
            )
            .unwrap()
        };
        // Il filtro client è isolato e temporaneamente legato al DK dell'invito.
        let mut client_ingress = UdpIngressFilter::new(inviter_id);
        let mut server_ingress = UdpIngressFilter::new(inviter_id);
        client_ingress
            .authorize_peer_secret(&token, inviter_id)
            .unwrap();
        server_ingress
            .authorize_peer_secret(&token, inviter_id)
            .unwrap();
        let mut client =
            UdpQuicEndpoint::new(make_socket(), client_ingress, QuicNode::client([0x31; 32]));
        let mut server = UdpQuicEndpoint::new(
            make_socket(),
            server_ingress,
            QuicNode::server([0x32; 32], server_config),
        );
        let gate = gate_key_id_for(inviter_id, &token).unwrap();
        let client_handle = client
            .node_mut()
            .connect(
                std::time::Instant::now(),
                server.local_addr().unwrap(),
                "loquere",
                client_config,
                Some(gate),
            )
            .unwrap();
        let mut client_buffer = vec![0; MAX_UDP_PAYLOAD];
        let mut server_buffer = vec![0; MAX_UDP_PAYLOAD];
        let start = std::time::Instant::now();
        let mut client_connected = false;
        let mut server_handle = None;
        for tick in 0..100 {
            let now = start + Duration::from_millis(tick * 10);
            let output = client.poll(now);
            client_connected |= output.events.iter().any(|event| matches!(event, loquere_wire::QuicEvent::Connected(handle) if *handle == client_handle));
            for transmit in &output.datagrams {
                client
                    .send(transmit, Some((inviter_id, &token)), 1_000_000)
                    .unwrap();
            }
            if let Some(output) = server
                .receive_once(&mut server_buffer, now, 1_000_000)
                .unwrap()
            {
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((inviter_id, &token)), 1_000_000)
                        .unwrap();
                }
                for event in output.events {
                    if let loquere_wire::QuicEvent::Connected(handle) = event {
                        server_handle = Some(handle);
                    }
                }
            }
            if let Some(output) = client
                .receive_once(&mut client_buffer, now, 1_000_000)
                .unwrap()
            {
                for transmit in &output.datagrams {
                    client
                        .send(transmit, Some((inviter_id, &token)), 1_000_000)
                        .unwrap();
                }
                client_connected |= output.events.iter().any(|event| matches!(event, loquere_wire::QuicEvent::Connected(handle) if *handle == client_handle));
            }
            if client_connected && server_handle.is_some() {
                break;
            }
        }
        let server_handle = server_handle.expect("server provisional TLS non completato");
        assert!(client_connected);
        assert_eq!(
            server.node_mut().authenticated_peer(server_handle),
            Some(requester_id)
        );
        assert_eq!(
            client.node_mut().authenticated_peer(client_handle),
            Some(inviter_id)
        );

        let stream = client.node_mut().open_bi_stream(client_handle).unwrap();
        let request =
            loquere_wire::encode_friend_request(&token, &requester.device_cert().to_bytes())
                .unwrap();
        assert_eq!(
            client
                .node_mut()
                .write_stream(client_handle, stream, &request)
                .unwrap(),
            request.len()
        );
        let mut incoming = None;
        let mut session = loquere_wire::ProvisionalSession::new();
        let mut event_guard = loquere_wire::ProvisionalEventGuard::new(server_handle);
        let mut received = false;
        for tick in 100..200 {
            let now = start + Duration::from_millis(tick * 10);
            for transmit in client.poll(now).datagrams {
                client
                    .send(&transmit, Some((inviter_id, &token)), 1_000_000)
                    .unwrap();
            }
            if let Some(output) = server
                .receive_once(&mut server_buffer, now, 1_000_000)
                .unwrap()
            {
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((inviter_id, &token)), 1_000_000)
                        .unwrap();
                }
                for event in &output.events {
                    if event_guard.inspect(event).unwrap()
                        == loquere_wire::ProvisionalAction::AcceptStream
                    {
                        loop {
                            match server.node_mut().accept_bi_stream(server_handle) {
                                Ok(stream) => {
                                    event_guard.accept_stream(stream).unwrap();
                                    incoming = Some(stream);
                                }
                                Err(loquere_wire::QuicStreamError::NoIncomingStream) => break,
                                Err(error) => panic!("stream non valido: {error:?}"),
                            }
                        }
                    }
                }
            }
            if let Some(stream) = incoming {
                let (read, output) = server
                    .node_mut()
                    .read_stream(now, server_handle, stream, MAX_UDP_PAYLOAD)
                    .unwrap();
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((inviter_id, &token)), 1_000_000)
                        .unwrap();
                }
                for event in &output.events {
                    assert_ne!(
                        event_guard.inspect(event).unwrap(),
                        loquere_wire::ProvisionalAction::AcceptStream
                    );
                }
                if let Some(request) = session.receive_control(&read.bytes).unwrap() {
                    assert_eq!(request.token(), &token);
                    let cert =
                        loquere_identity::DeviceCert::from_bytes(request.certificate()).unwrap();
                    assert_eq!(cert.account_id(), requester.account_id());
                    assert_eq!(cert.device_id().to_bytes(), requester_id);
                    assert!(!session.is_approved());
                    received = true;
                    break;
                }
            }
        }
        assert!(received, "FriendRequest non ricevuto");
    }

    #[test]
    fn two_udp_endpoints_exchange_mls_message_over_gated_quic() {
        let client_key = Arc::new(SecretKey::generate());
        let server_key = Arc::new(SecretKey::generate());
        // Il gruppo è predisposto fuori banda: qui si verifica soltanto la
        // consegna del messaggio MLS, non il protocollo di amicizia/join.
        let mut alice =
            loquere_chat::Conversation::create(SecretKey::from_bytes(*client_key.to_bytes()))
                .unwrap();
        let mut bob_pending =
            loquere_chat::Conversation::create(SecretKey::from_bytes(*server_key.to_bytes()))
                .unwrap();
        let package = bob_pending.key_package().unwrap();
        let welcome = alice.add_member(&package).unwrap();
        let mut bob =
            loquere_chat::Conversation::join(bob_pending, &welcome.welcome, &welcome.ratchet_tree)
                .unwrap();
        let client_config =
            build_quic_client_config(client_key.clone(), server_key.public_key()).unwrap();
        let server_config = Arc::new(
            build_quic_server_config(
                server_key.clone(),
                [client_key.public_key().to_bytes()],
                Arc::new(FixedTime),
            )
            .unwrap(),
        );
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let client_socket = UdpSocketAdapter::bind_with_ecn_handling(
            loopback,
            Duration::from_millis(2),
            EcnHandling::IgnoreExplicitly,
        )
        .unwrap();
        let server_socket = UdpSocketAdapter::bind_with_ecn_handling(
            loopback,
            Duration::from_millis(2),
            EcnHandling::IgnoreExplicitly,
        )
        .unwrap();
        let client_device = client_key.public_key().to_bytes();
        let server_device = server_key.public_key().to_bytes();
        let shared_secret = [0x61; 32];
        let client_gate = gate_key_id_for(server_device, &shared_secret).unwrap();
        let mut client_ingress = UdpIngressFilter::new(client_device);
        let mut server_ingress = UdpIngressFilter::new(server_device);
        client_ingress
            .authorize_peer_secret(&shared_secret, server_device)
            .unwrap();
        server_ingress
            .authorize_peer_secret(&shared_secret, client_device)
            .unwrap();
        let mut client =
            UdpQuicEndpoint::new(client_socket, client_ingress, QuicNode::client([0x11; 32]));
        let mut server = UdpQuicEndpoint::new(
            server_socket,
            server_ingress,
            QuicNode::server([0x22; 32], server_config),
        );
        let server_addr = server.local_addr().unwrap();
        let client_handle = client
            .node_mut()
            .connect(
                std::time::Instant::now(),
                server_addr,
                "loquere",
                client_config,
                Some(client_gate),
            )
            .unwrap();
        let mut client_buffer = vec![0; MAX_UDP_PAYLOAD];
        let mut server_buffer = vec![0; MAX_UDP_PAYLOAD];
        let start = std::time::Instant::now();
        let mut client_connected = false;
        let mut server_connected = false;
        let mut server_handle = None;

        for tick in 0..100 {
            let now = start + Duration::from_millis(tick * 10);
            let output = client.poll(now);
            client_connected |= output.events.iter().any(|event| {
                matches!(event, loquere_wire::QuicEvent::Connected(handle) if *handle == client_handle)
            });
            for transmit in &output.datagrams {
                client
                    .send(transmit, Some((server_device, &shared_secret)), 1_000_000)
                    .unwrap();
            }

            if let Some(output) = server
                .receive_once(&mut server_buffer, now, 1_000_000)
                .unwrap()
            {
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((client_device, &shared_secret)), 1_000_000)
                        .unwrap();
                }
                if let Some(handle) = output.events.iter().find_map(|event| match event {
                    loquere_wire::QuicEvent::Connected(handle) => Some(*handle),
                    _ => None,
                }) {
                    server_connected = true;
                    server_handle = Some(handle);
                }
            }
            if let Some(output) = client
                .receive_once(&mut client_buffer, now, 1_000_000)
                .unwrap()
            {
                for transmit in &output.datagrams {
                    client
                        .send(transmit, Some((server_device, &shared_secret)), 1_000_000)
                        .unwrap();
                }
                client_connected |= output.events.iter().any(|event| {
                    matches!(event, loquere_wire::QuicEvent::Connected(handle) if *handle == client_handle)
                });
            }
            if client_connected && server_connected {
                break;
            }
        }

        assert!(client_connected, "UDP client handshake did not complete");
        assert!(server_connected, "UDP server handshake did not complete");
        assert_eq!(client.node_mut().is_established(client_handle), Some(true));
        assert_eq!(
            client.node_mut().authenticated_peer(client_handle),
            Some(server_device)
        );
        assert_eq!(
            server.node_mut().authenticated_peer(server_handle.unwrap()),
            Some(client_device)
        );

        // Il primo stream bidirezionale trasporta Hello prima dello stream chat.
        // La lista amici non esiste ancora: qui i dispositivi sono preautorizzati
        // dalla configurazione TLS e dal segreto gate del test.
        let control = client.node_mut().open_bi_stream(client_handle).unwrap();
        let hello = loquere_wire::encode_control_hello();
        assert_eq!(
            client
                .node_mut()
                .write_stream(client_handle, control, &hello)
                .unwrap(),
            hello.len()
        );
        let mut incoming_control = None;
        let mut hello_decoder = loquere_wire::FirstControlDecoder::new();
        let mut hello_received = false;
        for tick in 100..200 {
            let now = start + Duration::from_millis(tick * 10);
            for transmit in client.poll(now).datagrams {
                client
                    .send(&transmit, Some((server_device, &shared_secret)), 1_000_000)
                    .unwrap();
            }
            if let Some(output) = server
                .receive_once(&mut server_buffer, now, 1_000_000)
                .unwrap()
            {
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((client_device, &shared_secret)), 1_000_000)
                        .unwrap();
                }
                if output.events.iter().any(|event| {
                    matches!(
                        event,
                        loquere_wire::QuicEvent::Stream {
                            event: quinn_proto::StreamEvent::Opened {
                                dir: quinn_proto::Dir::Bi
                            },
                            ..
                        }
                    )
                }) {
                    incoming_control = Some(
                        server
                            .node_mut()
                            .accept_bi_stream(server_handle.unwrap())
                            .unwrap(),
                    );
                }
            }
            if let Some(incoming) = incoming_control {
                let (read, output) = server
                    .node_mut()
                    .read_stream(now, server_handle.unwrap(), incoming, MAX_UDP_PAYLOAD)
                    .unwrap();
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((client_device, &shared_secret)), 1_000_000)
                        .unwrap();
                }
                let (used, message) = hello_decoder.push(&read.bytes).unwrap();
                assert_eq!(used, read.bytes.len());
                if let Some(message) = message {
                    assert!(matches!(message, loquere_wire::FirstControl::Hello));
                    hello_received = true;
                    break;
                }
            }
        }
        assert!(
            hello_received,
            "Hello non ricevuto sullo stream di controllo"
        );
        hello_decoder.finish().unwrap();

        // Poi scambia un frame MLS su uno stream chat dedicato.
        let stream = client.node_mut().open_bi_stream(client_handle).unwrap();
        let plaintext = b"ciao da OpenMLS su QUIC";
        let ciphertext = alice.encrypt(plaintext).unwrap();
        assert!(!ciphertext.windows(plaintext.len()).any(|w| w == plaintext));
        let mut frame = loquere_wire::PendingChatFrame::new(&ciphertext).unwrap();
        while !frame.remaining().is_empty() {
            let chunk = &frame.remaining()[..frame.remaining().len().min(7)];
            let written = client
                .node_mut()
                .write_stream(client_handle, stream, chunk)
                .unwrap();
            assert!(written > 0);
            frame.advance(written).unwrap();
        }
        client
            .node_mut()
            .finish_stream(client_handle, stream)
            .unwrap();
        let mut received_frame = None;
        let mut incoming_stream = None;
        let mut received_bytes = Vec::new();
        let mut trace = Vec::new();
        for tick in 200..300 {
            let now = start + Duration::from_millis(tick * 10);
            let client_output = client.poll(now);
            trace.push(format!(
                "client poll: {:?}, datagrams {:?}",
                client_output.events,
                client_output
                    .datagrams
                    .iter()
                    .map(|d| (d.payload.first().copied(), d.payload.len()))
                    .collect::<Vec<_>>()
            ));
            for transmit in client_output.datagrams {
                client
                    .send(&transmit, Some((server_device, &shared_secret)), 1_000_000)
                    .unwrap();
            }
            if let Some(output) = server
                .receive_once(&mut server_buffer, now, 1_000_000)
                .unwrap()
            {
                trace.push(format!(
                    "server receive: {:?}, {} datagrams",
                    output.events,
                    output.datagrams.len()
                ));
                let stream_opened = output.events.iter().any(|event| {
                    matches!(
                        event,
                        loquere_wire::QuicEvent::Stream {
                            event: quinn_proto::StreamEvent::Opened {
                                dir: quinn_proto::Dir::Bi,
                                ..
                            },
                            ..
                        }
                    )
                });
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((client_device, &shared_secret)), 1_000_000)
                        .unwrap();
                }
                if stream_opened {
                    let server_handle = server_handle.expect("server handshake handle");
                    incoming_stream =
                        Some(server.node_mut().accept_bi_stream(server_handle).unwrap());
                }
            }
            if let Some(incoming) = incoming_stream {
                let (read, output) = server
                    .node_mut()
                    .read_stream(now, server_handle.unwrap(), incoming, MAX_UDP_PAYLOAD)
                    .unwrap();
                trace.push(format!(
                    "server read: {} bytes, finished={}",
                    read.bytes.len(),
                    read.finished
                ));
                for transmit in &output.datagrams {
                    server
                        .send(transmit, Some((client_device, &shared_secret)), 1_000_000)
                        .unwrap();
                }
                received_bytes.extend(read.bytes);
                if read.finished {
                    received_frame = Some(received_bytes);
                    break;
                }
            }
        }
        let received = received_frame.unwrap_or_else(|| panic!("frame non ricevuto: {trace:#?}"));
        let mut decoder = loquere_wire::ChatFrameDecoder::new();
        let (consumed, decoded) = decoder.push(&received).unwrap();
        assert_eq!(consumed, received.len());
        let decoded = decoded.expect("frame incompleto");
        assert_eq!(decoded, ciphertext);
        assert_eq!(bob.decrypt(&decoded).unwrap(), plaintext);
        assert!(
            bob.decrypt(&decoded).is_err(),
            "MLS deve rifiutare il replay"
        );
        decoder.finish().unwrap();
    }
}
