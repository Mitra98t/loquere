#![forbid(unsafe_code)]

//! Simulatore di rete deterministico senza I/O reale.

use std::collections::BTreeMap;

/// Identificatore stabile di un nodo virtuale.
pub type NodeId = u32;

/// Parametri di un collegamento diretto tra due nodi.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkConfig {
    /// Ritardo minimo di propagazione in millisecondi.
    pub latency_ms: u32,
    /// Jitter uniforme da `-jitter_ms` a `+jitter_ms`.
    pub jitter_ms: u32,
    /// Probabilità di perdita in basis point (0–10 000).
    pub loss_basis_points: u16,
    /// Banda di uscita in byte al secondo; zero significa illimitata.
    pub bandwidth_bytes_per_second: u32,
}

impl LinkConfig {
    /// Link LAN ideale.
    pub const LAN: Self = Self {
        latency_ms: 1,
        jitter_ms: 0,
        loss_basis_points: 0,
        bandwidth_bytes_per_second: 0,
    };

    fn validate(self) -> Result<Self, SimError> {
        if self.loss_basis_points > 10_000 {
            return Err(SimError::InvalidLossRate);
        }
        Ok(self)
    }
}

/// Esito della richiesta di invio del pacchetto.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// Pacchetto schedulato per la consegna.
    Scheduled,
    /// Pacchetto perso dal modello probabilistico del link.
    Lost,
    /// Link isolato da una partizione di rete.
    Partitioned,
    /// Non esiste un collegamento diretto tra i nodi.
    NoRoute,
}

/// Pacchetto consegnato dal simulatore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    /// Mittente virtuale.
    pub from: NodeId,
    /// Destinatario virtuale.
    pub to: NodeId,
    /// Byte trasportati, invariati.
    pub payload: Vec<u8>,
    /// Istante di consegna simulato in millisecondi.
    pub delivered_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct LinkState {
    config: LinkConfig,
    partitioned: bool,
    next_available_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScheduledPacket {
    delivered_at_ms: u64,
    order: u64,
    delivery: Delivery,
}

/// Simulatore pseudo-casuale riproducibile, con collegamenti diretti.
pub struct NetworkSimulator {
    random_state: u64,
    next_order: u64,
    links: BTreeMap<(NodeId, NodeId), LinkState>,
    packets: Vec<ScheduledPacket>,
}

impl NetworkSimulator {
    /// Crea un simulatore con seme esplicito.
    pub fn new(seed: u64) -> Self {
        Self {
            random_state: seed,
            next_order: 0,
            links: BTreeMap::new(),
            packets: Vec::new(),
        }
    }

    /// Aggiunge o sostituisce un link diretto.
    pub fn add_link(
        &mut self,
        from: NodeId,
        to: NodeId,
        config: LinkConfig,
    ) -> Result<(), SimError> {
        if from == to {
            return Err(SimError::SelfLink);
        }
        self.links.insert(
            (from, to),
            LinkState {
                config: config.validate()?,
                partitioned: false,
                next_available_ms: 0,
            },
        );
        Ok(())
    }

    /// Attiva o risolve una partizione sul singolo link diretto.
    pub fn set_partitioned(
        &mut self,
        from: NodeId,
        to: NodeId,
        partitioned: bool,
    ) -> Result<(), SimError> {
        let link = self.links.get_mut(&(from, to)).ok_or(SimError::NoRoute)?;
        link.partitioned = partitioned;
        Ok(())
    }

    /// Invia byte sul link diretto e programma una consegna futura.
    pub fn send(&mut self, from: NodeId, to: NodeId, payload: &[u8], now_ms: u64) -> SendOutcome {
        let Some((config, partitioned, next_available_ms)) = self
            .links
            .get(&(from, to))
            .map(|link| (link.config, link.partitioned, link.next_available_ms))
        else {
            return SendOutcome::NoRoute;
        };
        if partitioned {
            return SendOutcome::Partitioned;
        }
        if self.random_below(10_000) < u64::from(config.loss_basis_points) {
            return SendOutcome::Lost;
        }

        let start_ms = now_ms.max(next_available_ms);
        let serialization_ms = if config.bandwidth_bytes_per_second == 0 {
            0
        } else {
            (payload.len() as u64 * 1000).div_ceil(u64::from(config.bandwidth_bytes_per_second))
        };
        let transfer_end_ms = start_ms.saturating_add(serialization_ms);
        let jitter_range = i64::from(config.jitter_ms);
        let jitter = if jitter_range == 0 {
            0
        } else {
            self.random_below((jitter_range as u64) * 2 + 1) as i64 - jitter_range
        };
        let latency = (i64::from(config.latency_ms) + jitter).max(0) as u64;
        let delivered_at_ms = transfer_end_ms.saturating_add(latency);
        let Some(link) = self.links.get_mut(&(from, to)) else {
            return SendOutcome::NoRoute;
        };
        link.next_available_ms = transfer_end_ms;
        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        self.packets.push(ScheduledPacket {
            delivered_at_ms,
            order,
            delivery: Delivery {
                from,
                to,
                payload: payload.to_vec(),
                delivered_at_ms,
            },
        });
        SendOutcome::Scheduled
    }

    /// Estrae tutti i pacchetti arrivati entro `now_ms`, ordinati per tempo e invio.
    pub fn receive_due(&mut self, now_ms: u64) -> Vec<Delivery> {
        self.packets
            .sort_by_key(|packet| (packet.delivered_at_ms, packet.order));
        let due_count = self
            .packets
            .partition_point(|packet| packet.delivered_at_ms <= now_ms);
        self.packets
            .drain(..due_count)
            .map(|packet| packet.delivery)
            .collect()
    }

    /// Numero di pacchetti in volo.
    pub fn pending_packets(&self) -> usize {
        self.packets.len()
    }

    fn random_below(&mut self, upper_bound: u64) -> u64 {
        // SplitMix64: deterministico, usato solo per simulazione, mai per segreti.
        self.random_state = self.random_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.random_state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        value % upper_bound
    }
}

/// Errori di configurazione del simulatore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimError {
    /// Un link non può partire e terminare sullo stesso nodo.
    SelfLink,
    /// Probabilità di perdita oltre il 100%.
    InvalidLossRate,
    /// Il link richiesto non esiste.
    NoRoute,
}

impl core::fmt::Display for SimError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SelfLink => formatter.write_str("un link non può collegare un nodo a sé stesso"),
            Self::InvalidLossRate => formatter.write_str("probabilità di perdita oltre il 100%"),
            Self::NoRoute => formatter.write_str("nessun link configurato"),
        }
    }
}

impl std::error::Error for SimError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_arrive_after_latency_and_preserve_order() {
        let mut simulator = NetworkSimulator::new(7);
        simulator
            .add_link(
                1,
                2,
                LinkConfig {
                    latency_ms: 10,
                    jitter_ms: 0,
                    loss_basis_points: 0,
                    bandwidth_bytes_per_second: 0,
                },
            )
            .unwrap();
        assert_eq!(simulator.send(1, 2, b"a", 5), SendOutcome::Scheduled);
        assert_eq!(simulator.send(1, 2, b"b", 5), SendOutcome::Scheduled);
        assert!(simulator.receive_due(14).is_empty());
        let received = simulator.receive_due(15);
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].payload, b"a");
        assert_eq!(received[1].payload, b"b");
    }

    #[test]
    fn same_seed_reproduces_loss_and_jitter_trace() {
        fn trace(seed: u64) -> Vec<(SendOutcome, Vec<Delivery>)> {
            let mut simulator = NetworkSimulator::new(seed);
            simulator
                .add_link(
                    0,
                    1,
                    LinkConfig {
                        latency_ms: 50,
                        jitter_ms: 15,
                        loss_basis_points: 2_000,
                        bandwidth_bytes_per_second: 0,
                    },
                )
                .unwrap();
            (0u8..20)
                .map(|i| {
                    let at = u64::from(i) * 3;
                    let outcome = simulator.send(0, 1, &[i], at);
                    let deliveries = simulator.receive_due(at + 100);
                    (outcome, deliveries)
                })
                .collect()
        }
        assert_eq!(trace(1234), trace(1234));
        assert_ne!(trace(1234), trace(1235));
    }

    #[test]
    fn partitions_and_full_loss_drop_packets_without_delivery() {
        let mut simulator = NetworkSimulator::new(9);
        simulator
            .add_link(
                1,
                2,
                LinkConfig {
                    latency_ms: 1,
                    jitter_ms: 0,
                    loss_basis_points: 10_000,
                    bandwidth_bytes_per_second: 0,
                },
            )
            .unwrap();
        assert_eq!(simulator.send(1, 2, b"lost", 0), SendOutcome::Lost);
        simulator.set_partitioned(1, 2, true).unwrap();
        assert_eq!(simulator.send(1, 2, b"cut", 0), SendOutcome::Partitioned);
        assert!(simulator.receive_due(u64::MAX).is_empty());
    }

    #[test]
    fn bandwidth_serializes_packets_and_unconfigured_links_have_no_route() {
        let mut simulator = NetworkSimulator::new(1);
        assert_eq!(simulator.send(1, 2, b"x", 0), SendOutcome::NoRoute);
        simulator
            .add_link(
                1,
                2,
                LinkConfig {
                    latency_ms: 0,
                    jitter_ms: 0,
                    loss_basis_points: 0,
                    bandwidth_bytes_per_second: 1000,
                },
            )
            .unwrap();
        simulator.send(1, 2, &[0; 10], 0);
        simulator.send(1, 2, &[0; 10], 0);
        let received = simulator.receive_due(10);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].delivered_at_ms, 10);
        assert_eq!(simulator.receive_due(20).len(), 1);
    }
}
