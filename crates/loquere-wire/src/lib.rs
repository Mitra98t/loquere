#![forbid(unsafe_code)]

//! Macchine a stati sans-IO per il trasporto Loquere.

mod gate;

pub use gate::{GateDecision, SilentFilter};
