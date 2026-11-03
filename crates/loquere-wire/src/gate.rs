use blake2::digest::{Mac, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;

const PREFIX_LEN: usize = 24;
const TIMESTAMP_WINDOW_SECONDS: u64 = 120;
const MAX_TRACKED_SOURCES: usize = 1024;
const MAX_REPLAYS_PER_SOURCE: usize = 4096;
const GATE_DOMAIN: &[u8] = b"loquere-gate";

type GateMac = Blake2sMac<U16>;

/// Risultato silenzioso del controllo del prefisso QUIC iniziale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateDecision<'a> {
    /// Pacchetto scartato senza inviare risposta.
    Drop,
    /// Datagramma autorizzato; contiene il pacchetto QUIC senza prefisso.
    PassInitial { packet: &'a [u8] },
}

#[derive(Default)]
struct SourceReplayState {
    seen: HashSet<(u64, [u8; 16])>,
}

/// Filtro deterministico del percorso pre-autenticazione QUIC.
/// Non legge l'orologio e non apre socket: `now_unix_seconds` e la sorgente
/// vengono forniti dal proprietario del socket.
pub struct SilentFilter {
    device_id: [u8; 32],
    replay_state: HashMap<SocketAddr, SourceReplayState>,
}

impl SilentFilter {
    /// Crea il filtro per l'identità pubblica del dispositivo destinatario.
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            device_id,
            replay_state: HashMap::new(),
        }
    }

    /// Controlla un datagramma iniziale. Scarta ogni pacchetto malformato,
    /// con MAC non valido, fuori finestra temporale o già osservato.
    pub fn inspect_initial<'a>(
        &mut self,
        source: SocketAddr,
        datagram: &'a [u8],
        now_unix_seconds: u64,
    ) -> GateDecision<'a> {
        if datagram.len() <= PREFIX_LEN {
            return GateDecision::Drop;
        }
        let timestamp_bytes: [u8; 8] = match datagram[..8].try_into() {
            Ok(bytes) => bytes,
            Err(_) => return GateDecision::Drop,
        };
        let timestamp = u64::from_be_bytes(timestamp_bytes);
        if timestamp.abs_diff(now_unix_seconds) > TIMESTAMP_WINDOW_SECONDS {
            return GateDecision::Drop;
        }
        let provided_mac = &datagram[8..PREFIX_LEN];
        let packet = &datagram[PREFIX_LEN..];
        if packet[0] & 0x80 == 0 {
            return GateDecision::Drop;
        }

        let key = gate_key(&self.device_id);
        let mut mac = match GateMac::new_from_slice(&key) {
            Ok(mac) => mac,
            Err(_) => return GateDecision::Drop,
        };
        mac.update(&timestamp_bytes);
        mac.update(packet);
        let expected = mac.finalize().into_bytes();
        if !bool::from(expected.as_slice().ct_eq(provided_mac)) {
            return GateDecision::Drop;
        }

        self.replay_state.retain(|_, state| {
            state.seen.retain(|(seen_at, _)| {
                seen_at.abs_diff(now_unix_seconds) <= TIMESTAMP_WINDOW_SECONDS
            });
            !state.seen.is_empty()
        });
        if !self.replay_state.contains_key(&source)
            && self.replay_state.len() >= MAX_TRACKED_SOURCES
        {
            return GateDecision::Drop;
        }
        let source_state = self.replay_state.entry(source).or_default();
        source_state
            .seen
            .retain(|(seen_at, _)| seen_at.abs_diff(now_unix_seconds) <= TIMESTAMP_WINDOW_SECONDS);
        let mut replay_id = [0u8; 16];
        replay_id.copy_from_slice(provided_mac);
        if source_state.seen.contains(&(timestamp, replay_id))
            || source_state.seen.len() >= MAX_REPLAYS_PER_SOURCE
        {
            return GateDecision::Drop;
        }
        source_state.seen.insert((timestamp, replay_id));
        GateDecision::PassInitial { packet }
    }

    /// Numero di sorgenti per cui è attivo un set anti-replay.
    pub fn tracked_sources(&self) -> usize {
        self.replay_state.len()
    }
}

fn gate_key(device_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    blake2::digest::Update::update(&mut hasher, GATE_DOMAIN);
    blake2::digest::Update::update(&mut hasher, device_id);
    blake2::digest::FixedOutput::finalize_fixed(hasher).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_datagram(device_id: &[u8; 32], timestamp: u64) -> Vec<u8> {
        let packet = [0xc0, 0, 0, 0, 1, 0];
        let timestamp_bytes = timestamp.to_be_bytes();
        let key = gate_key(device_id);
        let mut mac = GateMac::new_from_slice(&key).unwrap();
        mac.update(&timestamp_bytes);
        mac.update(&packet);
        let tag = mac.finalize().into_bytes();
        let mut datagram = Vec::with_capacity(PREFIX_LEN + packet.len());
        datagram.extend_from_slice(&timestamp_bytes);
        datagram.extend_from_slice(&tag);
        datagram.extend_from_slice(&packet);
        datagram
    }

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    #[test]
    fn valid_initial_packet_passes_once_and_is_replay_protected_per_source() {
        let device_id = [0x34; 32];
        let mut filter = SilentFilter::new(device_id);
        let datagram = valid_datagram(&device_id, 1_000);

        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 1_030),
            GateDecision::PassInitial {
                packet: &datagram[PREFIX_LEN..]
            }
        );
        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 1_030),
            GateDecision::Drop
        );
        assert!(matches!(
            filter.inspect_initial(source(4001), &datagram, 1_030),
            GateDecision::PassInitial { .. }
        ));
    }

    #[test]
    fn invalid_mac_timestamp_and_short_datagrams_are_silently_dropped() {
        let device_id = [0x12; 32];
        let mut filter = SilentFilter::new(device_id);
        let mut datagram = valid_datagram(&device_id, 1_000);
        datagram[10] ^= 1;
        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 1_000),
            GateDecision::Drop
        );
        let datagram = valid_datagram(&device_id, 1_000);
        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 1_121),
            GateDecision::Drop
        );
        assert_eq!(
            filter.inspect_initial(source(4000), &[0; 24], 1_000),
            GateDecision::Drop
        );
    }

    #[test]
    fn source_and_packet_are_bound_to_the_mac() {
        let device_id = [0x71; 32];
        let mut filter = SilentFilter::new(device_id);
        let mut datagram = valid_datagram(&device_id, 100);
        let last = datagram.len() - 1;
        datagram[last] ^= 1;
        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 100),
            GateDecision::Drop
        );
        assert_eq!(filter.tracked_sources(), 0);
    }
}
