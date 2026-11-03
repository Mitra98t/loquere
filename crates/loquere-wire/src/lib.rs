#![forbid(unsafe_code)]

//! Macchine a stati sans-IO per il trasporto Loquere.

mod gate;
mod quic_config;
mod tls;

pub use gate::{GateDecision, SilentFilter};
pub use quic_config::{QuicConfigError, build_quic_client_config, build_quic_server_config};
pub use tls::{TlsConfigError, build_client_tls_config, build_server_tls_config};
