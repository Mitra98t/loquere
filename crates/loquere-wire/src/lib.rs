#![forbid(unsafe_code)]

//! Macchine a stati sans-IO per il trasporto Loquere.

mod chat_frame;
mod control_frame;
mod frame;
mod friend_request;
mod gate;
mod invite_grant;
mod provisional;
mod quic_config;
mod quic_node;
mod tls;

pub use chat_frame::{ChatFrameDecoder, ChatFrameError, PendingChatFrame, encode_chat_message};
pub use control_frame::{ControlHelloDecoder, encode_control_hello};
pub use frame::{FrameDecoder, FrameError, encode_frame};
pub use friend_request::{
    FirstControl, FirstControlDecoder, FriendRequest, FriendRequestDecoder, encode_friend_request,
};
pub use gate::{
    GateDecision, GateError, SilentFilter, gate_initial_datagram, gate_key_id_for,
    is_quic_initial_packet,
};
pub use invite_grant::{InviteGrant, InviteGrantError};
pub use provisional::{
    ProvisionalAction, ProvisionalError, ProvisionalEventGuard, ProvisionalSession,
};
pub use quic_config::{
    QuicConfigError, build_provisional_invite_quic_server_config, build_quic_client_config,
    build_quic_server_config,
};
pub use quic_node::{
    QuicDatagramError, QuicEvent, QuicNode, QuicOutput, QuicStreamError, QuicStreamRead,
    QuicTransmit,
};
pub use tls::{
    TlsConfigError, build_client_tls_config, build_provisional_invite_server_tls_config,
    build_server_tls_config,
};
