//! Authenticated key-agreement handshake for the P2P transport.
//!
//! Before any application message flows, two nodes run this handshake to establish
//! a pair of directional session keys. It provides:
//!
//! - **Forward-secret key agreement**: an ephemeral-ephemeral secp256k1 ECDH whose
//!   secret is discarded after the session, so recording the wire traffic and later
//!   stealing a node's long-term key does not decrypt past sessions.
//! - **Mutual authentication**: each side signs the handshake transcript with its
//!   long-term [`NodeIdentity`] key. The responder's signature additionally covers
//!   the initiator's ephemeral and static keys, binding the response to *this*
//!   session. A man-in-the-middle cannot forge either signature, and cannot
//!   substitute an ephemeral key without invalidating one, so it can neither
//!   impersonate a node nor split the session.
//!
//! The transcript hash also salts the HKDF that expands the shared secret, so the
//! session keys are bound to both identities and the chain id.
//!
//! The output is a [`SessionKeys`] pair, one [`crate::network::frame::SecureChannel`]
//! per direction.

use hkdf::Hkdf;
use k256::ecdh::EphemeralSecret;
use k256::PublicKey as K256PublicKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::hash::{sha256d, Hash256};
use crate::crypto::secp256k1::{PrivateKey, PublicKey, Signature};

const INIT_TAG: &[u8] = b"ZRO/handshake/init/v1\0";
const RESP_TAG: &[u8] = b"ZRO/handshake/resp/v1\0";
const SESSION_INFO: &[u8] = b"ZRO/session/v1";

/// A node's long-term P2P identity. Distinct from any wallet key: it only ever
/// signs handshake transcripts, never transactions.
pub struct NodeIdentity {
    secret: PrivateKey,
}

impl NodeIdentity {
    pub fn random() -> Self {
        NodeIdentity {
            secret: PrivateKey::random(),
        }
    }

    pub fn from_secret(secret: PrivateKey) -> Self {
        NodeIdentity { secret }
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }

    fn sign(&self, digest: &Hash256) -> Signature {
        // The secret was validated at construction, so signing cannot fail here.
        self.secret
            .sign(digest)
            .expect("identity secret is a valid scalar")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    #[error("peer is on chain {found:#x} but this node serves {expected:#x}")]
    ChainMismatch { expected: u32, found: u32 },
    #[error("peer ephemeral key is not a valid secp256k1 point")]
    InvalidEphemeralKey,
    #[error("peer handshake signature is invalid: the transcript was tampered with or the identity does not match")]
    BadSignature,
}

/// The first handshake message, sent by the dialing node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub chain: u32,
    /// Compressed SEC1 ephemeral public key (hex).
    pub ephemeral_hex: String,
    pub static_key: PublicKey,
    pub signature: Signature,
}

/// The second handshake message, sent by the listening node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloBack {
    pub chain: u32,
    pub ephemeral_hex: String,
    pub static_key: PublicKey,
    pub signature: Signature,
}

/// A 32-byte AES key plus a 32-byte HMAC key for one direction of the channel.
#[derive(Clone)]
pub struct ChannelKeys {
    pub enc: [u8; 32],
    pub mac: [u8; 32],
}

/// Directional session keys. `send`/`recv` are from this node's point of view.
#[derive(Clone)]
pub struct SessionKeys {
    pub send: ChannelKeys,
    pub recv: ChannelKeys,
    /// The authenticated identity of the peer on the other end.
    pub peer_identity: PublicKey,
}

impl SessionKeys {
    /// Turn the negotiated keys into a live [`SecureChannel`], wired so this node
    /// sends on `send` and receives on `recv`. The peer's mirrored channel does
    /// the opposite, so the two directions never share a key.
    pub fn channel(&self) -> crate::network::frame::SecureChannel {
        // The keys are 32 bytes by construction, so `new` cannot fail here.
        crate::network::frame::SecureChannel::new(
            &self.send.enc,
            &self.send.mac,
            &self.recv.enc,
            &self.recv.mac,
        )
        .expect("session keys are 32 bytes")
    }
}

/// Initiator state kept between sending `Hello` and receiving `HelloBack`. It holds
/// the ephemeral secret, which is consumed to complete the ECDH.
pub struct InitiatorState {
    chain: u32,
    ephemeral: EphemeralSecret,
    ephemeral_pub: [u8; 33],
    our_static: PublicKey,
}

/// Begin a handshake: create an ephemeral key and the signed `Hello`.
pub fn begin_handshake(identity: &NodeIdentity, chain: u32) -> (InitiatorState, Hello) {
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = K256PublicKey::from(&ephemeral);
    let eph_bytes = ephemeral_pub.to_sec1_bytes();
    let mut eph_arr = [0u8; 33];
    eph_arr.copy_from_slice(&eph_bytes);

    let our_static = identity.public_key();
    let transcript = initiator_transcript(chain, &our_static, &eph_arr);
    let signature = identity.sign(&transcript);

    let hello = Hello {
        chain,
        ephemeral_hex: hex::encode(eph_arr),
        static_key: our_static,
        signature,
    };
    let state = InitiatorState {
        chain,
        ephemeral,
        ephemeral_pub: eph_arr,
        our_static,
    };
    (state, hello)
}

/// Responder side: validate a `Hello`, produce the response and the session keys.
pub fn respond_to_hello(
    identity: &NodeIdentity,
    chain: u32,
    hello: &Hello,
) -> Result<(SessionKeys, HelloBack), HandshakeError> {
    if hello.chain != chain {
        return Err(HandshakeError::ChainMismatch {
            expected: chain,
            found: hello.chain,
        });
    }
    let init_eph = parse_ephemeral(&hello.ephemeral_hex)?;
    // Authenticate the initiator's transcript before doing any key work.
    let init_transcript = initiator_transcript(chain, &hello.static_key, &init_eph);
    if hello
        .static_key
        .verify(&init_transcript, &hello.signature)
        .is_err()
    {
        return Err(HandshakeError::BadSignature);
    }

    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let resp_pub = K256PublicKey::from(&ephemeral);
    let resp_bytes = resp_pub.to_sec1_bytes();
    let mut resp_eph = [0u8; 33];
    resp_eph.copy_from_slice(&resp_bytes);

    let our_static = identity.public_key();
    // The responder's transcript binds the initiator's keys, so this HelloBack can
    // only ever authenticate this exact session.
    let resp_transcript =
        responder_transcript(chain, &our_static, &resp_eph, &hello.static_key, &init_eph);
    let signature = identity.sign(&resp_transcript);

    let peer_pub = K256PublicKey::from_sec1_bytes(&init_eph)
        .map_err(|_| HandshakeError::InvalidEphemeralKey)?;
    let shared = ephemeral.diffie_hellman(&peer_pub);
    // The salt must be computed in a fixed (initiator, responder) order on both
    // sides, or the peers derive different keys. Here the initiator is the peer.
    let salt = session_salt(&hello.static_key, &init_eph, &our_static, &resp_eph, chain);
    let keys = derive_session_keys(shared.raw_secret_bytes().as_slice(), &salt, false, hello.static_key);

    let back = HelloBack {
        chain,
        ephemeral_hex: hex::encode(resp_eph),
        static_key: our_static,
        signature,
    };
    Ok((keys, back))
}

/// Initiator side: validate `HelloBack` and derive the same session keys.
pub fn finish_handshake(
    state: InitiatorState,
    back: &HelloBack,
) -> Result<SessionKeys, HandshakeError> {
    if back.chain != state.chain {
        return Err(HandshakeError::ChainMismatch {
            expected: state.chain,
            found: back.chain,
        });
    }
    let resp_eph = parse_ephemeral(&back.ephemeral_hex)?;
    let init_eph = state.ephemeral_pub;
    let resp_transcript = responder_transcript(
        state.chain,
        &back.static_key,
        &resp_eph,
        &state.our_static,
        &init_eph,
    );
    if back
        .static_key
        .verify(&resp_transcript, &back.signature)
        .is_err()
    {
        return Err(HandshakeError::BadSignature);
    }

    let peer_pub = K256PublicKey::from_sec1_bytes(&resp_eph)
        .map_err(|_| HandshakeError::InvalidEphemeralKey)?;
    let shared = state.ephemeral.diffie_hellman(&peer_pub);
    let salt = session_salt(&state.our_static, &init_eph, &back.static_key, &resp_eph, state.chain);
    Ok(derive_session_keys(
        shared.raw_secret_bytes().as_slice(),
        &salt,
        true,
        back.static_key,
    ))
}

fn parse_ephemeral(hex_key: &str) -> Result<[u8; 33], HandshakeError> {
    let bytes = hex::decode(hex_key).map_err(|_| HandshakeError::InvalidEphemeralKey)?;
    if bytes.len() != 33 {
        return Err(HandshakeError::InvalidEphemeralKey);
    }
    // Validate it is a real curve point before it is used in ECDH.
    K256PublicKey::from_sec1_bytes(&bytes).map_err(|_| HandshakeError::InvalidEphemeralKey)?;
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn initiator_transcript(chain: u32, static_key: &PublicKey, ephemeral: &[u8; 33]) -> Hash256 {
    let mut data = Vec::with_capacity(4 + 33 + 33 + INIT_TAG.len());
    data.extend_from_slice(INIT_TAG);
    data.extend_from_slice(&chain.to_le_bytes());
    data.extend_from_slice(&static_key.to_sec1());
    data.extend_from_slice(ephemeral);
    sha256d(&data)
}

fn responder_transcript(
    chain: u32,
    resp_static: &PublicKey,
    resp_eph: &[u8; 33],
    init_static: &PublicKey,
    init_eph: &[u8; 33],
) -> Hash256 {
    let mut data = Vec::with_capacity(4 + 33 * 4 + RESP_TAG.len());
    data.extend_from_slice(RESP_TAG);
    data.extend_from_slice(&chain.to_le_bytes());
    data.extend_from_slice(&resp_static.to_sec1());
    data.extend_from_slice(resp_eph);
    data.extend_from_slice(&init_static.to_sec1());
    data.extend_from_slice(init_eph);
    sha256d(&data)
}

fn session_salt(
    init_static: &PublicKey,
    init_eph: &[u8; 33],
    resp_static: &PublicKey,
    resp_eph: &[u8; 33],
    chain: u32,
) -> Hash256 {
    let mut data = Vec::with_capacity(4 + 33 * 4);
    data.extend_from_slice(b"ZRO/session-salt/v1\0");
    data.extend_from_slice(&chain.to_le_bytes());
    data.extend_from_slice(&init_static.to_sec1());
    data.extend_from_slice(init_eph);
    data.extend_from_slice(&resp_static.to_sec1());
    data.extend_from_slice(resp_eph);
    sha256d(&data)
}

/// Expand the ECDH shared secret into two directional channel keys with HKDF-SHA256.
/// `is_initiator` selects which half this node sends on, so the two peers derive
/// mirrored send/recv keys.
fn derive_session_keys(
    shared_secret: &[u8],
    salt: &Hash256,
    is_initiator: bool,
    peer_identity: PublicKey,
) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(&salt.0), shared_secret);
    let mut okm = [0u8; 128];
    // `expand` cannot fail for a 128-byte output with SHA-256 (limit is 8160).
    hk.expand(SESSION_INFO, &mut okm)
        .expect("128 bytes is within the HKDF output limit");

    let init_enc: [u8; 32] = okm[0..32].try_into().unwrap();
    let init_mac: [u8; 32] = okm[32..64].try_into().unwrap();
    let resp_enc: [u8; 32] = okm[64..96].try_into().unwrap();
    let resp_mac: [u8; 32] = okm[96..128].try_into().unwrap();

    let (send, recv) = if is_initiator {
        (
            ChannelKeys { enc: init_enc, mac: init_mac },
            ChannelKeys { enc: resp_enc, mac: resp_mac },
        )
    } else {
        (
            ChannelKeys { enc: resp_enc, mac: resp_mac },
            ChannelKeys { enc: init_enc, mac: init_mac },
        )
    };
    SessionKeys {
        send,
        recv,
        peer_identity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: u32 = 0x2E01_0001;

    #[test]
    fn handshake_produces_mirrored_keys() {
        let alice = NodeIdentity::random();
        let bob = NodeIdentity::random();

        let (state, hello) = begin_handshake(&alice, CHAIN);
        let (bob_keys, back) = respond_to_hello(&bob, CHAIN, &hello).expect("bob responds");
        let alice_keys = finish_handshake(state, &back).expect("alice finishes");

        // What Alice sends on, Bob receives on, and vice versa.
        assert_eq!(alice_keys.send.enc, bob_keys.recv.enc);
        assert_eq!(alice_keys.send.mac, bob_keys.recv.mac);
        assert_eq!(alice_keys.recv.enc, bob_keys.send.enc);
        assert_eq!(alice_keys.recv.mac, bob_keys.send.mac);
        // Directions differ, so the two halves are independent.
        assert_ne!(alice_keys.send.enc, alice_keys.recv.enc);
        // Identities are authenticated.
        assert_eq!(alice_keys.peer_identity, bob.public_key());
        assert_eq!(bob_keys.peer_identity, alice.public_key());
    }

    #[test]
    fn chain_mismatch_rejected() {
        let alice = NodeIdentity::random();
        let bob = NodeIdentity::random();
        let (_state, hello) = begin_handshake(&alice, CHAIN);
        assert!(matches!(
            respond_to_hello(&bob, 0xdead, &hello),
            Err(HandshakeError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn tampered_hello_signature_rejected() {
        let alice = NodeIdentity::random();
        let bob = NodeIdentity::random();
        let (_state, mut hello) = begin_handshake(&alice, CHAIN);
        // An attacker swaps the ephemeral key but cannot re-sign for Alice.
        let attacker = NodeIdentity::random();
        let (attacker_state, attacker_hello) = begin_handshake(&attacker, CHAIN);
        let _ = attacker_state;
        hello.ephemeral_hex = attacker_hello.ephemeral_hex;
        assert!(matches!(
            respond_to_hello(&bob, CHAIN, &hello),
            Err(HandshakeError::BadSignature)
        ));
    }

    #[test]
    fn impersonated_static_key_rejected() {
        let alice = NodeIdentity::random();
        let bob = NodeIdentity::random();
        let mallory = NodeIdentity::random();
        let (_state, mut hello) = begin_handshake(&alice, CHAIN);
        // Mallory claims Alice's static key but signs with her own: verification
        // uses the claimed key, so the signature will not check out.
        let transcript = initiator_transcript(CHAIN, &alice.public_key(), &hex_to_eph(&hello.ephemeral_hex));
        hello.signature = mallory.sign(&transcript);
        assert!(matches!(
            respond_to_hello(&bob, CHAIN, &hello),
            Err(HandshakeError::BadSignature)
        ));
    }

    fn hex_to_eph(hex_key: &str) -> [u8; 33] {
        parse_ephemeral(hex_key).unwrap()
    }
}
