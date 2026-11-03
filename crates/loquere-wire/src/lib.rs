#![forbid(unsafe_code)]

//! Macchine a stati sans-IO per il trasporto Loquere.

mod gate;
mod tls;

pub use gate::{GateDecision, SilentFilter};
pub use tls::{TlsConfigError, build_client_tls_config, build_server_tls_config};
