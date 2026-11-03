use blake2::Blake2sMac;
use blake2::digest::{Mac, consts::U8, consts::U16};
use bytes::BytesMut;
use quinn_proto::crypto::HmacKey;
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, ConnectionId, ConnectionIdGenerator, DatagramEvent,
    Endpoint, EndpointConfig, Event, ServerConfig,
};
use rand_core::{OsRng, RngCore};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type ResetMac = Blake2sMac<U16>;
type CidMac = Blake2sMac<U8>;

/// Un datagramma QUIC in uscita prodotto dalla macchina sans-IO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTransmit {
    /// Destinazione del datagramma.
    pub destination: SocketAddr,
    /// Indirizzo locale da usare come sorgente, se Quinn lo richiede.
    pub source_ip: Option<IpAddr>,
    /// Codepoint ECN da applicare al datagramma.
    pub ecn: Option<quinn_proto::EcnCodepoint>,
    /// Segment size per UDP GSO, quando disponibile.
    pub segment_size: Option<usize>,
    /// Byte UDP da inviare senza ulteriori modifiche.
    pub payload: Vec<u8>,
}

/// Eventi applicativi essenziali prodotti dalle connessioni.
#[derive(Debug, Eq, PartialEq)]
pub enum QuicEvent {
    /// Handshake TLS/QUIC completato.
    Connected(ConnectionHandle),
    /// Connessione chiusa o persa.
    Lost(ConnectionHandle),
    /// Un'applicazione deve elaborare l'evento di uno stream.
    Stream {
        /// Connessione proprietaria dello stream.
        connection: ConnectionHandle,
        /// Evento Quinn da passare allo strato applicativo.
        event: quinn_proto::StreamEvent,
    },
    /// Uno o più datagrammi applicativi sono pronti alla lettura.
    DatagramReceived(ConnectionHandle),
    /// Un precedente invio di datagrammi applicativi è ora sbloccato.
    DatagramsUnblocked(ConnectionHandle),
}

/// Uscite in risposta a un input o a un avanzamento del timer.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct QuicOutput {
    /// Datagrams pronti per il socket UDP del chiamante.
    pub datagrams: Vec<QuicTransmit>,
    /// Eventi da consegnare al livello engine.
    pub events: Vec<QuicEvent>,
}

/// Dati restituiti da una lettura non bloccante di stream QUIC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicStreamRead {
    /// Byte letti in ordine, fino al limite richiesto.
    pub bytes: Vec<u8>,
    /// `true` se il peer ha terminato lo stream e tutti i byte sono stati letti.
    pub finished: bool,
}

/// Errori delle operazioni applicative sugli stream.
#[derive(Debug)]
pub enum QuicStreamError {
    /// La connessione non esiste più.
    UnknownConnection,
    /// Il limite di stream concorrenti è stato raggiunto.
    StreamsExhausted,
    /// Nessuno stream bidirezionale remoto è attualmente disponibile.
    NoIncomingStream,
    /// Errore durante la scrittura.
    Write(quinn_proto::WriteError),
    /// Errore durante la chiusura in scrittura.
    Finish(quinn_proto::FinishError),
    /// Lo stream non è leggibile al momento o è stato chiuso.
    Readable(quinn_proto::ReadableError),
    /// Errore durante l'estrazione dei dati.
    Read(quinn_proto::ReadError),
}

const MAX_STREAM_READ_BYTES: usize = 64 * 1024;

/// Endpoint QUIC sans-IO. Il socket, il clock monotono e l'invio dei datagrammi
/// restano responsabilità del chiamante.
pub struct QuicNode {
    endpoint: Endpoint,
    connections: BTreeMap<ConnectionHandle, Connection>,
}

impl QuicNode {
    /// Crea un endpoint client. I pacchetti in ingresso devono prima superare
    /// [`crate::SilentFilter`].
    pub fn client(reset_key: [u8; 32]) -> Self {
        Self::new(reset_key, None)
    }

    /// Crea un endpoint server con config QUIC già autenticata.
    pub fn server(reset_key: [u8; 32], config: Arc<ServerConfig>) -> Self {
        Self::new(reset_key, Some(config))
    }

    fn new(reset_key: [u8; 32], server_config: Option<Arc<ServerConfig>>) -> Self {
        let reset_key = Arc::new(ResetKey(Zeroizing::new(reset_key)));
        let cid_key = Arc::new(random_key());
        let mut endpoint_config = EndpointConfig::new(reset_key);
        endpoint_config.cid_generator(move || Box::new(AuthenticatedCidGenerator::new(*cid_key)));
        let endpoint = Endpoint::new(Arc::new(endpoint_config), server_config, false, None);
        Self {
            endpoint,
            connections: BTreeMap::new(),
        }
    }

    /// Avvia una connessione QUIC con config TLS già validata.
    pub fn connect(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        server_name: &str,
        config: ClientConfig,
    ) -> Result<ConnectionHandle, quinn_proto::ConnectError> {
        let (handle, connection) = self.endpoint.connect(now, config, remote, server_name)?;
        self.connections.insert(handle, connection);
        Ok(handle)
    }

    /// Elabora un datagramma ricevuto, già privato del prefisso del gate.
    pub fn receive(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        ecn: Option<quinn_proto::EcnCodepoint>,
        datagram: &[u8],
    ) -> QuicOutput {
        let mut output = QuicOutput::default();
        let mut buffer = Vec::new();
        let event = self.endpoint.handle(
            now,
            remote,
            local_ip,
            ecn,
            BytesMut::from(datagram),
            &mut buffer,
        );
        match event {
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                if let Some(connection) = self.connections.get_mut(&handle) {
                    connection.handle_event(event);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                match self.endpoint.accept(incoming, now, &mut buffer, None) {
                    Ok((handle, connection)) => {
                        self.connections.insert(handle, connection);
                    }
                    Err(error) => {
                        if let Some(response) = error.response {
                            output
                                .datagrams
                                .push(QuicTransmit::from_transmit(response, &buffer));
                        }
                    }
                }
            }
            Some(DatagramEvent::Response(transmit)) => {
                output
                    .datagrams
                    .push(QuicTransmit::from_transmit(transmit, &buffer));
            }
            None => {}
        }
        self.pump(now, &mut output);
        output
    }

    /// Avanza i timer QUIC e produce i datagrammi/eventi disponibili.
    pub fn poll(&mut self, now: Instant) -> QuicOutput {
        let mut output = QuicOutput::default();
        let handles: Vec<_> = self.connections.keys().copied().collect();
        for handle in handles {
            if let Some(connection) = self.connections.get_mut(&handle) {
                if connection
                    .poll_timeout()
                    .is_some_and(|deadline| deadline <= now)
                {
                    connection.handle_timeout(now);
                }
            }
        }
        self.pump(now, &mut output);
        output
    }

    /// Prossima scadenza QUIC da programmare nel timer del chiamante.
    pub fn next_timeout(&mut self) -> Option<Instant> {
        self.connections
            .values_mut()
            .filter_map(Connection::poll_timeout)
            .min()
    }

    /// Dice se la connessione è stata stabilita.
    pub fn is_established(&self, handle: ConnectionHandle) -> Option<bool> {
        self.connections
            .get(&handle)
            .map(|connection| !connection.is_handshaking())
    }

    /// Apre uno stream bidirezionale QUIC.
    pub fn open_bi_stream(
        &mut self,
        handle: ConnectionHandle,
    ) -> Result<quinn_proto::StreamId, QuicStreamError> {
        let connection = self
            .connections
            .get_mut(&handle)
            .ok_or(QuicStreamError::UnknownConnection)?;
        connection
            .streams()
            .open(quinn_proto::Dir::Bi)
            .ok_or(QuicStreamError::StreamsExhausted)
    }

    /// Accetta uno stream bidirezionale remoto già notificato da un evento
    /// `StreamEvent::Opened`.
    pub fn accept_bi_stream(
        &mut self,
        handle: ConnectionHandle,
    ) -> Result<quinn_proto::StreamId, QuicStreamError> {
        let connection = self
            .connections
            .get_mut(&handle)
            .ok_or(QuicStreamError::UnknownConnection)?;
        connection
            .streams()
            .accept(quinn_proto::Dir::Bi)
            .ok_or(QuicStreamError::NoIncomingStream)
    }

    /// Scrive byte su uno stream già aperto. La scrittura può essere parziale;
    /// l'applicazione deve riprendere sui successivi eventi `Writable`.
    pub fn write_stream(
        &mut self,
        handle: ConnectionHandle,
        stream: quinn_proto::StreamId,
        bytes: &[u8],
    ) -> Result<usize, QuicStreamError> {
        let connection = self
            .connections
            .get_mut(&handle)
            .ok_or(QuicStreamError::UnknownConnection)?;
        connection
            .send_stream(stream)
            .write(bytes)
            .map_err(QuicStreamError::Write)
    }

    /// Segna la fine dei byte inviati sullo stream.
    pub fn finish_stream(
        &mut self,
        handle: ConnectionHandle,
        stream: quinn_proto::StreamId,
    ) -> Result<(), QuicStreamError> {
        let connection = self
            .connections
            .get_mut(&handle)
            .ok_or(QuicStreamError::UnknownConnection)?;
        connection
            .send_stream(stream)
            .finish()
            .map_err(QuicStreamError::Finish)
    }

    /// Legge dati disponibili in ordine e avanza i timer/trasmissioni necessari
    /// al controllo di flusso. Ogni chiamata alloca al massimo 64 KiB.
    pub fn read_stream(
        &mut self,
        now: Instant,
        handle: ConnectionHandle,
        stream: quinn_proto::StreamId,
        max_bytes: usize,
    ) -> Result<(QuicStreamRead, QuicOutput), QuicStreamError> {
        let limit = max_bytes.min(MAX_STREAM_READ_BYTES);
        let connection = self
            .connections
            .get_mut(&handle)
            .ok_or(QuicStreamError::UnknownConnection)?;
        let mut recv_stream = connection.recv_stream(stream);
        let mut chunks = recv_stream.read(true).map_err(QuicStreamError::Readable)?;
        let mut bytes = Vec::with_capacity(limit);
        let mut finished = false;
        while bytes.len() < limit {
            match chunks.next(limit - bytes.len()) {
                Ok(Some(chunk)) => bytes.extend_from_slice(&chunk.bytes),
                Ok(None) => {
                    finished = true;
                    break;
                }
                Err(quinn_proto::ReadError::Blocked) => break,
                Err(error) => return Err(QuicStreamError::Read(error)),
            }
        }
        let _should_transmit = chunks.finalize();
        let mut output = QuicOutput::default();
        self.pump(now, &mut output);
        Ok((QuicStreamRead { bytes, finished }, output))
    }

    fn pump(&mut self, now: Instant, output: &mut QuicOutput) {
        let handles: Vec<_> = self.connections.keys().copied().collect();
        let mut lost = Vec::new();
        for handle in handles {
            let Some(connection) = self.connections.get_mut(&handle) else {
                continue;
            };
            while let Some(event) = connection.poll_endpoint_events() {
                if let Some(connection_event) = self.endpoint.handle_event(handle, event) {
                    connection.handle_event(connection_event);
                }
            }
            loop {
                let mut buffer = Vec::new();
                let Some(transmit) = connection.poll_transmit(now, 1, &mut buffer) else {
                    break;
                };
                output
                    .datagrams
                    .push(QuicTransmit::from_transmit(transmit, &buffer));
            }
            while let Some(event) = connection.poll() {
                match event {
                    Event::Connected => output.events.push(QuicEvent::Connected(handle)),
                    Event::ConnectionLost { .. } => {
                        output.events.push(QuicEvent::Lost(handle));
                        lost.push(handle);
                    }
                    Event::Stream(event) => output.events.push(QuicEvent::Stream {
                        connection: handle,
                        event,
                    }),
                    Event::DatagramReceived => {
                        output.events.push(QuicEvent::DatagramReceived(handle));
                    }
                    Event::DatagramsUnblocked => {
                        output.events.push(QuicEvent::DatagramsUnblocked(handle));
                    }
                    Event::HandshakeDataReady => {}
                }
            }
        }
        for handle in lost {
            self.connections.remove(&handle);
        }
        output.events.dedup();
    }
}

impl QuicTransmit {
    fn from_transmit(transmit: quinn_proto::Transmit, buffer: &[u8]) -> Self {
        Self {
            destination: transmit.destination,
            source_ip: transmit.src_ip,
            ecn: transmit.ecn,
            segment_size: transmit.segment_size,
            payload: buffer[..transmit.size].to_vec(),
        }
    }
}

struct ResetKey(Zeroizing<[u8; 32]>);

impl HmacKey for ResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        if signature_out.len() != 16 {
            signature_out.fill(0);
            return;
        }
        let Ok(mut mac) = ResetMac::new_from_slice(&*self.0) else {
            signature_out.fill(0);
            return;
        };
        mac.update(data);
        signature_out.copy_from_slice(&mac.finalize().into_bytes());
    }

    fn signature_len(&self) -> usize {
        16
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), quinn_proto::crypto::CryptoError> {
        if signature.len() != 16 {
            return Err(quinn_proto::crypto::CryptoError);
        }
        let mut expected = [0u8; 16];
        self.sign(data, &mut expected);
        bool::from(expected.ct_eq(signature))
            .then_some(())
            .ok_or(quinn_proto::crypto::CryptoError)
    }
}

struct AuthenticatedCidGenerator {
    key: Zeroizing<[u8; 32]>,
}

impl AuthenticatedCidGenerator {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }
}

impl ConnectionIdGenerator for AuthenticatedCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes[..8]);
        let mut mac = CidMac::new_from_slice(&*self.key).expect("BLAKE2s accepts a 32-byte key");
        mac.update(&bytes[..8]);
        bytes[8..].copy_from_slice(&mac.finalize().into_bytes());
        ConnectionId::new(&bytes)
    }

    fn validate(&self, _cid: &ConnectionId) -> Result<(), quinn_proto::InvalidCid> {
        // Prevent Quinn from emitting stateless resets. Active CIDs are resolved
        // by Endpoint's connection index before this fallback is consulted.
        Err(quinn_proto::InvalidCid)
    }

    fn cid_len(&self) -> usize {
        16
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        Some(Duration::from_secs(600))
    }
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_quic_client_config, build_quic_server_config};
    use loquere_crypto::SecretKey;
    use std::collections::VecDeque;
    use std::time::SystemTime;

    struct FixedTime;

    impl quinn_proto::TimeSource for FixedTime {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    #[test]
    fn two_nodes_complete_mutual_quic_handshake_without_sockets() {
        let client_key = Arc::new(SecretKey::generate());
        let server_key = Arc::new(SecretKey::generate());
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
        let client_addr = SocketAddr::from(([127, 0, 0, 1], 41001));
        let server_addr = SocketAddr::from(([127, 0, 0, 1], 41002));
        let mut client = QuicNode::client(random_key());
        let mut server = QuicNode::server(random_key(), server_config);
        let client_handle = client
            .connect(Instant::now(), server_addr, "loquere", client_config)
            .unwrap();
        let mut client_connected = false;
        let mut server_connected = false;
        let start = Instant::now();

        for tick in 0..40 {
            let now = start + Duration::from_millis(tick * 25);
            let mut queue = VecDeque::new();
            let client_output = client.poll(now);
            record_events(
                &client_output.events,
                0,
                client_handle,
                &mut client_connected,
                &mut server_connected,
            );
            enqueue_output(&mut queue, 0, client_output);
            let server_output = server.poll(now);
            record_events(
                &server_output.events,
                1,
                client_handle,
                &mut client_connected,
                &mut server_connected,
            );
            enqueue_output(&mut queue, 1, server_output);
            while let Some((destination, datagram)) = queue.pop_front() {
                let output = if destination == 0 {
                    server.receive(now, client_addr, None, None, &datagram.payload)
                } else {
                    client.receive(now, server_addr, None, None, &datagram.payload)
                };
                record_events(
                    &output.events,
                    1 - destination,
                    client_handle,
                    &mut client_connected,
                    &mut server_connected,
                );
                enqueue_output(&mut queue, 1 - destination, output);
            }
            if client_connected && server_connected {
                break;
            }
        }

        assert!(client_connected, "client QUIC handshake did not finish");
        assert!(server_connected, "server QUIC handshake did not finish");
        assert_eq!(client.is_established(client_handle), Some(true));

        let server_handle = *server.connections.keys().next().unwrap();
        let stream = client.open_bi_stream(client_handle).unwrap();
        assert_eq!(
            client
                .write_stream(client_handle, stream, b"hello from loquere")
                .unwrap(),
            b"hello from loquere".len()
        );
        client.finish_stream(client_handle, stream).unwrap();
        let now = start + Duration::from_secs(2);
        let outgoing = client.poll(now);
        for datagram in outgoing.datagrams {
            let _ = server.receive(now, client_addr, None, None, &datagram.payload);
        }
        let incoming_stream = server.accept_bi_stream(server_handle).unwrap();
        let (read, _output) = server
            .read_stream(now, server_handle, incoming_stream, MAX_STREAM_READ_BYTES)
            .unwrap();
        assert_eq!(read.bytes, b"hello from loquere");
        assert!(read.finished);
    }

    fn enqueue_output(
        queue: &mut VecDeque<(u8, QuicTransmit)>,
        destination: u8,
        output: QuicOutput,
    ) {
        queue.extend(
            output
                .datagrams
                .into_iter()
                .map(|datagram| (destination, datagram)),
        );
    }

    fn record_events(
        events: &[QuicEvent],
        owner: u8,
        client_handle: ConnectionHandle,
        client_connected: &mut bool,
        server_connected: &mut bool,
    ) {
        for event in events {
            match event {
                QuicEvent::Connected(handle) if owner == 0 && *handle == client_handle => {
                    *client_connected = true;
                }
                QuicEvent::Connected(_) if owner == 1 => *server_connected = true,
                QuicEvent::Connected(_) => {}
                QuicEvent::Lost(_) => panic!("connection lost during handshake"),
                QuicEvent::Stream { .. }
                | QuicEvent::DatagramReceived(_)
                | QuicEvent::DatagramsUnblocked(_) => {}
            }
        }
    }
}
