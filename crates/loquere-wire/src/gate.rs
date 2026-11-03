use blake2::digest::{Mac, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const PREFIX_LEN: usize = 40;
const KEY_ID_LEN: usize = 16;
const TAG_LEN: usize = 16;
const TIMESTAMP_WINDOW_SECONDS: u64 = 120;
const MAX_TRACKED_SOURCES: usize = 1024;
const MAX_REPLAYS_PER_SOURCE: usize = 4096;
const GATE_DOMAIN: &[u8] = b"loquere:gate:v2";
const GATE_KEY_INFO: &[u8] = b"loquere:gate-mac:v2\0";
const GATE_KEY_ID_DOMAIN: &[u8] = b"loquere:gate-key-id:v2\0";

type GateMac = Blake2sMac<U16>;

/// Risultato silenzioso del controllo del prefisso QUIC iniziale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateDecision<'a> {
    /// Pacchetto scartato senza inviare risposta.
    Drop,
    /// Datagramma autorizzato; contiene il pacchetto QUIC senza prefisso.
    PassInitial {
        /// Pacchetto QUIC Initial senza prefisso Loquere.
        packet: &'a [u8],
        /// Credenziale che ha autenticato il prefisso.
        key_id: [u8; KEY_ID_LEN],
    },
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
    credentials: HashMap<[u8; KEY_ID_LEN], Zeroizing<[u8; 32]>>,
    replay_state: HashMap<SocketAddr, SourceReplayState>,
}

impl SilentFilter {
    /// Crea il filtro per l'identità pubblica del dispositivo destinatario.
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            device_id,
            credentials: HashMap::new(),
            replay_state: HashMap::new(),
        }
    }

    /// Autorizza una credenziale segreta condivisa e restituisce il suo key ID
    /// opaco da inserire nel prefisso dei pacchetti iniziali.
    pub fn authorize_secret(&mut self, secret: &[u8]) -> Result<[u8; KEY_ID_LEN], GateError> {
        let key = derive_gate_key(secret, &self.device_id)?;
        let key_id = gate_key_id(&key);
        if let Some(existing) = self.credentials.get(&key_id) {
            if !bool::from(existing.as_slice().ct_eq(key.as_slice())) {
                return Err(GateError::KeyIdCollision);
            }
        } else {
            self.credentials.insert(key_id, key);
        }
        Ok(key_id)
    }

    /// Revoca una credenziale precedentemente autorizzata.
    pub fn revoke_key_id(&mut self, key_id: &[u8; KEY_ID_LEN]) -> bool {
        self.credentials.remove(key_id).is_some()
    }

    /// Numero di credenziali segrete attualmente autorizzate.
    pub fn authorized_credentials(&self) -> usize {
        self.credentials.len()
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
        let key_id: [u8; KEY_ID_LEN] = match datagram[8..8 + KEY_ID_LEN].try_into() {
            Ok(key_id) => key_id,
            Err(_) => return GateDecision::Drop,
        };
        let provided_mac = &datagram[8 + KEY_ID_LEN..PREFIX_LEN];
        let packet = &datagram[PREFIX_LEN..];
        if !is_quic_initial_packet(packet) {
            return GateDecision::Drop;
        }
        let Some(key) = self.credentials.get(&key_id) else {
            return GateDecision::Drop;
        };
        let expected = gate_mac(key, &timestamp_bytes, &key_id, packet);
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
        GateDecision::PassInitial { packet, key_id }
    }

    /// Numero di sorgenti per cui è attivo un set anti-replay.
    pub fn tracked_sources(&self) -> usize {
        self.replay_state.len()
    }
}

/// Costruisce il datagramma iniziale con prefisso autenticato per un peer.
/// `secret` deve essere condiviso fuori banda tramite invito o relazione già
/// autenticata; un DeviceId pubblico da solo non è sufficiente.
pub fn gate_initial_datagram(
    recipient_device_id: [u8; 32],
    secret: &[u8],
    timestamp: u64,
    packet: &[u8],
) -> Result<Vec<u8>, GateError> {
    if !is_quic_initial_packet(packet) {
        return Err(GateError::NotInitialPacket);
    }
    let key = derive_gate_key(secret, &recipient_device_id)?;
    let key_id = gate_key_id(&key);
    let timestamp_bytes = timestamp.to_be_bytes();
    let mac = gate_mac(&key, &timestamp_bytes, &key_id, packet);
    let mut datagram = Vec::with_capacity(PREFIX_LEN + packet.len());
    datagram.extend_from_slice(&timestamp_bytes);
    datagram.extend_from_slice(&key_id);
    datagram.extend_from_slice(&mac);
    datagram.extend_from_slice(packet);
    Ok(datagram)
}

/// Deriva il key ID che il destinatario deve autorizzare per `secret`.
pub fn gate_key_id_for(
    recipient_device_id: [u8; 32],
    secret: &[u8],
) -> Result<[u8; KEY_ID_LEN], GateError> {
    let key = derive_gate_key(secret, &recipient_device_id)?;
    Ok(gate_key_id(&key))
}

/// Riconosce un pacchetto QUIC Initial v1 non prefissato.
pub fn is_quic_initial_packet(packet: &[u8]) -> bool {
    if packet.len() < 5 || packet[0] & 0x80 == 0 {
        return false;
    }
    let version = u32::from_be_bytes(packet[1..5].try_into().expect("length checked"));
    version == 1 && packet[0] & 0x30 == 0
}

fn derive_gate_key(
    secret: &[u8],
    recipient_device_id: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, GateError> {
    if secret.len() < 16 {
        return Err(GateError::SecretTooShort);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(GATE_DOMAIN), secret);
    let mut info = Vec::with_capacity(GATE_KEY_INFO.len() + recipient_device_id.len());
    info.extend_from_slice(GATE_KEY_INFO);
    info.extend_from_slice(recipient_device_id);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, &mut *key)
        .map_err(|_| GateError::KeyDerivation)?;
    Ok(key)
}

fn gate_key_id(key: &[u8; 32]) -> [u8; KEY_ID_LEN] {
    let mut hasher = Blake2s256::new();
    blake2::digest::Update::update(&mut hasher, GATE_KEY_ID_DOMAIN);
    blake2::digest::Update::update(&mut hasher, key);
    let digest = blake2::digest::FixedOutput::finalize_fixed(hasher);
    digest[..KEY_ID_LEN].try_into().expect("digest is 32 bytes")
}

fn gate_mac(
    key: &[u8; 32],
    timestamp: &[u8; 8],
    key_id: &[u8; KEY_ID_LEN],
    packet: &[u8],
) -> [u8; TAG_LEN] {
    let mut mac = GateMac::new_from_slice(key).expect("BLAKE2s accepts a 32-byte key");
    mac.update(timestamp);
    mac.update(key_id);
    mac.update(packet);
    mac.finalize().into_bytes().into()
}

/// Errori nella gestione delle credenziali del filtro silenzioso.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateError {
    /// Il segreto condiviso deve contenere almeno 128 bit.
    SecretTooShort,
    /// Impossibile derivare la chiave del filtro.
    KeyDerivation,
    /// Collisione rilevata tra due key ID diversi.
    KeyIdCollision,
    /// Il pacchetto non ha un header QUIC Initial a header lungo.
    NotInitialPacket,
}

impl core::fmt::Display for GateError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SecretTooShort => formatter.write_str("segreto gate troppo corto"),
            Self::KeyDerivation => formatter.write_str("derivazione chiave gate fallita"),
            Self::KeyIdCollision => formatter.write_str("collisione del key ID gate"),
            Self::NotInitialPacket => formatter.write_str("il datagramma non è un QUIC Initial"),
        }
    }
}

impl std::error::Error for GateError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_datagram(device_id: &[u8; 32], secret: &[u8], timestamp: u64) -> Vec<u8> {
        let packet = [0xc0, 0, 0, 0, 1, 0];
        gate_initial_datagram(*device_id, secret, timestamp, &packet).unwrap()
    }

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    #[test]
    fn valid_initial_packet_passes_once_and_is_replay_protected_per_source() {
        let device_id = [0x34; 32];
        let secret = [0xa5; 16];
        let mut filter = SilentFilter::new(device_id);
        filter.authorize_secret(&secret).unwrap();
        let datagram = valid_datagram(&device_id, &secret, 1_000);

        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 1_030),
            GateDecision::PassInitial {
                packet: &datagram[PREFIX_LEN..],
                key_id: gate_key_id_for(device_id, &secret).unwrap(),
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
        let secret = [0x12; 16];
        let mut filter = SilentFilter::new(device_id);
        filter.authorize_secret(&secret).unwrap();
        let mut datagram = valid_datagram(&device_id, &secret, 1_000);
        datagram[10] ^= 1;
        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 1_000),
            GateDecision::Drop
        );
        let datagram = valid_datagram(&device_id, &secret, 1_000);
        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 1_121),
            GateDecision::Drop
        );
        assert_eq!(
            filter.inspect_initial(source(4000), &[0; PREFIX_LEN], 1_000),
            GateDecision::Drop
        );
    }

    #[test]
    fn source_and_packet_are_bound_to_the_mac() {
        let device_id = [0x71; 32];
        let secret = [0x71; 16];
        let mut filter = SilentFilter::new(device_id);
        filter.authorize_secret(&secret).unwrap();
        let mut datagram = valid_datagram(&device_id, &secret, 100);
        let last = datagram.len() - 1;
        datagram[last] ^= 1;
        assert_eq!(
            filter.inspect_initial(source(4000), &datagram, 100),
            GateDecision::Drop
        );
        assert_eq!(filter.tracked_sources(), 0);
    }

    #[test]
    fn public_device_id_does_not_authorize_packets_and_credentials_are_revocable() {
        let device_id = [0x55; 32];
        let secret = [0x9a; 16];
        let datagram = valid_datagram(&device_id, &secret, 500);
        let mut filter = SilentFilter::new(device_id);
        assert_eq!(
            filter.inspect_initial(source(4400), &datagram, 500),
            GateDecision::Drop
        );

        let key_id = filter.authorize_secret(&secret).unwrap();
        assert_eq!(filter.authorized_credentials(), 1);
        assert!(matches!(
            filter.inspect_initial(source(4400), &datagram, 500),
            GateDecision::PassInitial { .. }
        ));
        assert!(filter.revoke_key_id(&key_id));
        assert_eq!(filter.authorized_credentials(), 0);
        assert_eq!(
            filter.inspect_initial(source(4401), &datagram, 500),
            GateDecision::Drop
        );
    }

    #[test]
    fn gate_credential_is_bound_to_the_recipient_device() {
        let first_recipient = [0x31; 32];
        let other_recipient = [0x32; 32];
        let secret = [0x41; 16];
        let packet = [0xc0, 0, 0, 0, 1, 0];
        let datagram = gate_initial_datagram(other_recipient, &secret, 700, &packet).unwrap();
        let mut filter = SilentFilter::new(first_recipient);
        filter.authorize_secret(&secret).unwrap();
        assert_eq!(
            filter.inspect_initial(source(4500), &datagram, 700),
            GateDecision::Drop
        );
        assert_eq!(
            gate_initial_datagram(first_recipient, &[1; 15], 700, &packet),
            Err(GateError::SecretTooShort)
        );
        assert_eq!(
            gate_initial_datagram(first_recipient, &secret, 700, &[0x40]),
            Err(GateError::NotInitialPacket)
        );
    }

    #[test]
    fn only_quic_v1_initial_packets_receive_gate_prefixes() {
        assert!(is_quic_initial_packet(&[0xc0, 0, 0, 0, 1]));
        assert!(!is_quic_initial_packet(&[0xe0, 0, 0, 0, 1]));
        assert!(!is_quic_initial_packet(&[0xc0, 0, 0, 0, 2]));
        assert!(!is_quic_initial_packet(&[0x40, 0, 0, 0, 1]));
    }
}
