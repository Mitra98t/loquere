#![forbid(unsafe_code)]

//! Filtro dei datagrammi UDP prima del driver QUIC.

use loquere_wire::{GateDecision, GateError, QuicNode, SilentFilter};
use std::net::SocketAddr;

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
}
