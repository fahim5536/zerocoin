//! The P2P transport: an authenticated handshake, secure framing, and the
//! application message set.
//!
//! ZeroCoin nodes talk over TCP, but never in the clear. A connection is
//! established in two stages:
//!
//! 1. **Handshake** ([`handshake`]): an ephemeral-ephemeral secp256k1 ECDH, each
//!    side signing the transcript with its long-term [`handshake::NodeIdentity`].
//!    This authenticates both peers (defeating a man-in-the-middle) and derives
//!    forward-secret directional session keys.
//! 2. **Framing** ([`frame`]): every subsequent record is sealed with AES-256-GCM
//!    and tagged with HMAC-SHA256 over a monotonic sequence number, giving
//!    confidentiality, integrity, and replay/reorder protection.
//!
//! Only then do [`message`] payloads — version, discovery, inventory, transactions
//! and blocks — flow over the channel.
//!
//! The layer depends on `crypto` (keys, hashes), `ledger` (transactions) and
//! `consensus` (blocks); nothing below it depends on the network.

pub mod frame;
pub mod handshake;
pub mod message;

pub use frame::{FrameError, SecureChannel, FRAME_OVERHEAD, MAX_PLAINTEXT_BYTES};
pub use handshake::{
    begin_handshake, finish_handshake, respond_to_hello, ChannelKeys, HandshakeError, Hello,
    HelloBack, InitiatorState, NodeIdentity, SessionKeys,
};
pub use message::{
    Inventory, InvKind, Message, MessageError, VersionPayload, PROTOCOL_VERSION,
};
