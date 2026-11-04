#![forbid(unsafe_code)]

//! Filtro dei datagrammi UDP prima del driver QUIC.

use loquere_wire::{
    GateDecision, GateError, QuicNode, QuicOutput, QuicTransmit, SilentFilter,
    gate_initial_datagram, gate_key_id_for, is_quic_initial_packet,
};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Socket UDP bloccante da possedere nel thread `net`.
///
/// Il buffer di ricezione appartiene al chiamante. L'adapter usa solo API
/// portabili `std`; trasmissioni che richiedono ECN, source-IP override o GSO
/// falliscono esplicitamente finché non sarà aggiunto il backend OS dedicato.
pub struct UdpSocketAdapter {
    socket: UdpSocket,
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
        let socket = UdpSocket::bind(address).map_err(UdpSocketError::Io)?;
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(UdpSocketError::Io)?;
        Ok(Self { socket })
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
        if transmit.ecn.is_some() {
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
            accepted.gate_key_id,
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
}

/// Filtro d'ingresso UDP: i primi pacchetti richiedono un segreto gate, gli
/// altri devono portare un CID locale autenticato. Non apre socket e non invia.
pub struct UdpIngressFilter {
    gate: SilentFilter,
}

impl UdpIngressFilter {
    /// Crea il filtro per l'identità pubblica del dispositivo destinatario.
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            gate: SilentFilter::new(device_id),
        }
    }

    /// Registra il segreto di un invito o di una relazione esistente.
    pub fn authorize_secret(&mut self, secret: &[u8]) -> Result<[u8; 16], GateError> {
        self.gate.authorize_secret(secret)
    }

    /// Revoca il segreto identificato dal key ID.
    pub fn revoke(&mut self, key_id: &[u8; 16]) -> bool {
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
        if first & 0x40 == 0 || datagram.len() < 1 + LOCAL_CID_LEN {
            return None;
        }
        datagram.get(1..1 + LOCAL_CID_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_wire::gate_initial_datagram;
    use std::time::Duration;

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 99], port))
    }

    #[test]
    fn only_authorized_initial_packets_pass_and_gate_key_is_returned() {
        let device_id = [0x52; 32];
        let secret = [0xa3; 16];
        let packet = [0xc0, 0, 0, 0, 1, 0];
        let datagram = gate_initial_datagram(device_id, &secret, 1000, &packet).unwrap();
        let mut filter = UdpIngressFilter::new(device_id);
        let node = QuicNode::client([0x11; 32]);

        assert_eq!(filter.inspect(&node, source(4000), &datagram, 1000), None);
        let key_id = filter.authorize_secret(&secret).unwrap();
        let accepted = filter
            .inspect(&node, source(4000), &datagram, 1000)
            .unwrap();
        assert_eq!(accepted.packet, packet);
        assert_eq!(accepted.gate_key_id, Some(key_id));
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
}
