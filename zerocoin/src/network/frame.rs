//! Authenticated, encrypted P2P framing.
//!
//! The reference `payd` prototype sent length-prefixed *plaintext* JSON over TCP:
//! anyone on the path could read it, alter it, replay it, or inject a frame of
//! their own. ZeroCoin closes all four holes at the transport layer. After the
//! [`crate::network::handshake`] establishes a pair of directional session keys,
//! every application message is carried in a frame that is:
//!
//! - **confidential** — the payload is sealed with AES-256-GCM under the
//!   direction's encryption key, so a passive observer learns nothing but the
//!   length;
//! - **authentic and tamper-evident** — the sealed bytes carry *two* independent
//!   integrity checks: the GCM tag, and an HMAC-SHA256 over the whole framed
//!   record (header included). An attacker without the MAC key cannot forge or
//!   modify a frame that a peer will accept;
//! - **replay- and reorder-proof** — a monotonic 64-bit sequence number is baked
//!   into the header, the GCM associated data, the HMAC, and the AES nonce. A
//!   peer accepts a frame only if its sequence number is exactly the next one it
//!   expects, so a recorded frame replayed or delivered out of order is rejected.
//!
//! ## Frame layout
//!
//! ```text
//! MAGIC(4) || seq(8, LE) || len(4, LE) || nonce(12) || ciphertext||tag(len) || mac(32)
//!   |           |             |             |                 |                   |
//!  "ZRO\0"   counter       ct length     derived from seq   AES-256-GCM        HMAC-SHA256
//! ```
//!
//! `len` is the length of the AES-GCM output, i.e. the plaintext length plus the
//! 16-byte GCM tag. The HMAC covers `MAGIC || seq || len || nonce || ciphertext`,
//! and the GCM associated data is `MAGIC || seq || len`, so neither the routing
//! header nor the body can be changed without detection.
//!
//! ## Nonce safety
//!
//! AES-GCM is catastrophically broken if a nonce is ever reused under the same
//! key. Here the nonce is *derived* from the sequence number rather than drawn at
//! random: `nonce = 0x00000000 || seq`. Because each direction has its own key,
//! the sequence starts at zero and only ever increments, and a receiver rejects
//! any frame whose sequence is not the next expected value, a (key, nonce) pair
//! can never repeat. Deriving it also lets the receiver confirm the nonce matches
//! the sequence it authenticates, catching a swapped-nonce forgery before any
//! decryption is attempted.

use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::NETWORK_MAGIC;

type HmacSha256 = Hmac<Sha256>;

pub const MAGIC_LEN: usize = 4;
pub const SEQ_LEN: usize = 8;
pub const LEN_LEN: usize = 4;
pub const NONCE_LEN: usize = 12;
pub const MAC_LEN: usize = 32;
/// AES-GCM appends a 16-byte authentication tag to the ciphertext.
pub const GCM_TAG_LEN: usize = 16;
/// The fixed cleartext prefix: magic + sequence + length.
pub const HEADER_LEN: usize = MAGIC_LEN + SEQ_LEN + LEN_LEN;
/// Bytes of framing wrapped around every plaintext payload.
pub const FRAME_OVERHEAD: usize = HEADER_LEN + NONCE_LEN + GCM_TAG_LEN + MAC_LEN;

/// Largest plaintext one frame may carry (4 MiB). This is a transport bound, not
/// a consensus rule: block validation applies no size or weight limit, so a block
/// may be consensus-valid yet too large to relay (F-3). The cap exists so a
/// hostile length field cannot make a peer allocate an unbounded buffer before
/// the frame is authenticated.
pub const MAX_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
/// The matching cap on the AES-GCM output (plaintext + tag).
pub const MAX_CIPHER_BYTES: usize = MAX_PLAINTEXT_BYTES + GCM_TAG_LEN;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame does not begin with the ZeroCoin magic bytes")]
    BadMagic,
    #[error("frame ended in the middle of the {0}")]
    Truncated(&'static str),
    #[error("frame body of {0} bytes exceeds the {MAX_CIPHER_BYTES}-byte limit")]
    TooLarge(usize),
    #[error("frame failed authentication: it was modified, or the session keys do not match")]
    AuthFailed,
    #[error("frame sequence {found} is not the expected {expected}: replay or reordering")]
    ReplayOrOutOfOrder { expected: u64, found: u64 },
    #[error("frame nonce does not correspond to its sequence number")]
    NonceMismatch,
    #[error("channel key has the wrong length")]
    BadKey,
    #[error("AES-GCM cipher operation failed")]
    Cipher,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// One direction-pair of authenticated channel state.
///
/// A `SecureChannel` seals outgoing messages with the *send* keys and opens
/// incoming frames with the *recv* keys, tracking a sequence number in each
/// direction. Two peers that completed a handshake hold mirrored channels: what
/// one seals, the other opens.
pub struct SecureChannel {
    send_cipher: Aes256Gcm,
    recv_cipher: Aes256Gcm,
    send_mac: [u8; MAC_LEN],
    recv_mac: [u8; MAC_LEN],
    send_seq: u64,
    recv_seq: u64,
}

impl SecureChannel {
    /// Build a channel from raw directional keys. Returns [`FrameError::BadKey`]
    /// if a key is not 32 bytes.
    pub fn new(
        send_enc: &[u8; 32],
        send_mac: &[u8; 32],
        recv_enc: &[u8; 32],
        recv_mac: &[u8; 32],
    ) -> Result<Self, FrameError> {
        let send_cipher = Aes256Gcm::new_from_slice(send_enc).map_err(|_| FrameError::BadKey)?;
        let recv_cipher = Aes256Gcm::new_from_slice(recv_enc).map_err(|_| FrameError::BadKey)?;
        Ok(SecureChannel {
            send_cipher,
            recv_cipher,
            send_mac: *send_mac,
            recv_mac: *recv_mac,
            send_seq: 0,
            recv_seq: 0,
        })
    }

    /// The next sequence number this channel will send on. Exposed for diagnostics.
    pub fn send_seq(&self) -> u64 {
        self.send_seq
    }

    /// The next sequence number this channel expects to receive.
    pub fn recv_seq(&self) -> u64 {
        self.recv_seq
    }

    /// Seal `plaintext` into a complete authenticated frame ready for the wire.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, FrameError> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(FrameError::TooLarge(plaintext.len()));
        }
        let seq = self.send_seq;
        let nonce = nonce_from_seq(seq);

        // The header is fixed once we know the plaintext length, because the GCM
        // output length is deterministic (plaintext + 16-byte tag).
        let ct_len = plaintext.len() + GCM_TAG_LEN;
        let header = build_header(seq, ct_len);

        let ciphertext = self
            .send_cipher
            .encrypt(
                AesNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| FrameError::Cipher)?;
        debug_assert_eq!(ciphertext.len(), ct_len);

        let mac = compute_mac(&self.send_mac, &header, &nonce, &ciphertext);

        let mut frame = Vec::with_capacity(FRAME_OVERHEAD + plaintext.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&mac);

        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(frame)
    }

    /// Parse and authenticate a complete frame, returning the plaintext.
    ///
    /// This is the trust boundary: every check — magic, bounds, sequence, nonce,
    /// HMAC, then GCM tag — must pass before any plaintext is handed back, and the
    /// plaintext is only revealed after the ciphertext has been authenticated.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, FrameError> {
        if frame.len() < HEADER_LEN {
            return Err(FrameError::Truncated("header"));
        }
        if frame[..MAGIC_LEN] != NETWORK_MAGIC {
            return Err(FrameError::BadMagic);
        }

        let mut seq_bytes = [0u8; SEQ_LEN];
        seq_bytes.copy_from_slice(&frame[MAGIC_LEN..MAGIC_LEN + SEQ_LEN]);
        let seq = u64::from_le_bytes(seq_bytes);

        let mut len_bytes = [0u8; LEN_LEN];
        len_bytes.copy_from_slice(&frame[HEADER_LEN - LEN_LEN..HEADER_LEN]);
        let ct_len = u32::from_le_bytes(len_bytes) as usize;

        if ct_len < GCM_TAG_LEN {
            return Err(FrameError::Truncated("ciphertext"));
        }
        if ct_len > MAX_CIPHER_BYTES {
            return Err(FrameError::TooLarge(ct_len));
        }
        // header + nonce + ciphertext + mac
        if frame.len() < HEADER_LEN + NONCE_LEN + ct_len + MAC_LEN {
            return Err(FrameError::Truncated("body"));
        }

        let nonce = &frame[HEADER_LEN..HEADER_LEN + NONCE_LEN];
        let body_start = HEADER_LEN + NONCE_LEN;
        let ciphertext = &frame[body_start..body_start + ct_len];
        let mac = &frame[body_start + ct_len..body_start + ct_len + MAC_LEN];
        let header = &frame[..HEADER_LEN];

        // Replay / reorder protection first: cheap, and it stops an attacker from
        // making us do any crypto on a frame we have already seen.
        if seq != self.recv_seq {
            return Err(FrameError::ReplayOrOutOfOrder {
                expected: self.recv_seq,
                found: seq,
            });
        }
        // The nonce is derived from the sequence, so it must match exactly.
        if nonce != nonce_from_seq(seq) {
            return Err(FrameError::NonceMismatch);
        }
        // Authenticate the record with the HMAC before decrypting.
        let expected = compute_mac(&self.recv_mac, header, nonce, ciphertext);
        if !constant_time_eq(&expected, mac) {
            return Err(FrameError::AuthFailed);
        }
        // Finally, the GCM tag authenticates the ciphertext against the header AAD.
        let plaintext = self
            .recv_cipher
            .decrypt(
                AesNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| FrameError::AuthFailed)?;

        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(plaintext)
    }

    /// Seal `plaintext` and write the resulting frame to `writer`.
    pub fn write_frame<W: Write>(&mut self, writer: &mut W, plaintext: &[u8]) -> Result<(), FrameError> {
        let frame = self.seal(plaintext)?;
        writer.write_all(&frame)?;
        writer.flush()?;
        Ok(())
    }

    /// Read one frame from `reader`, authenticate it, and return the plaintext.
    ///
    /// Returns `Ok(None)` on a clean end-of-stream at a frame boundary (the peer
    /// disconnected). A partial frame is an error, not a clean close.
    pub fn read_frame<R: Read>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
        let mut magic = [0u8; MAGIC_LEN];
        if !read_exact_or_eof(reader, &mut magic)? {
            return Ok(None);
        }
        if magic != NETWORK_MAGIC {
            return Err(FrameError::BadMagic);
        }
        let mut seq_bytes = [0u8; SEQ_LEN];
        if !read_exact_or_eof(reader, &mut seq_bytes)? {
            return Err(FrameError::Truncated("sequence number"));
        }
        let mut len_bytes = [0u8; LEN_LEN];
        if !read_exact_or_eof(reader, &mut len_bytes)? {
            return Err(FrameError::Truncated("length field"));
        }
        let ct_len = u32::from_le_bytes(len_bytes) as usize;
        if ct_len < GCM_TAG_LEN {
            return Err(FrameError::Truncated("ciphertext"));
        }
        if ct_len > MAX_CIPHER_BYTES {
            return Err(FrameError::TooLarge(ct_len));
        }

        let mut nonce = [0u8; NONCE_LEN];
        if !read_exact_or_eof(reader, &mut nonce)? {
            return Err(FrameError::Truncated("nonce"));
        }
        let mut ciphertext = vec![0u8; ct_len];
        if !read_exact_or_eof(reader, &mut ciphertext)? {
            return Err(FrameError::Truncated("ciphertext"));
        }
        let mut mac = [0u8; MAC_LEN];
        if !read_exact_or_eof(reader, &mut mac)? {
            return Err(FrameError::Truncated("authentication tag"));
        }

        // Reassemble and route through `open`, so there is a single verification path.
        let mut frame = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct_len + MAC_LEN);
        frame.extend_from_slice(&magic);
        frame.extend_from_slice(&seq_bytes);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&mac);

        let plaintext = self.open(&frame)?;
        Ok(Some(plaintext))
    }
}

/// The cleartext routing header: `MAGIC || seq || len`, which also serves as the
/// GCM associated data and the HMAC prefix.
fn build_header(seq: u64, ct_len: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&NETWORK_MAGIC);
    header.extend_from_slice(&seq.to_le_bytes());
    header.extend_from_slice(&(ct_len as u32).to_le_bytes());
    header
}

/// Derive the 12-byte AES-GCM nonce from a sequence number: four zero bytes
/// followed by the little-endian counter.
fn nonce_from_seq(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[NONCE_LEN - SEQ_LEN..].copy_from_slice(&seq.to_le_bytes());
    nonce
}

/// HMAC-SHA256 over `header || nonce || ciphertext`, the encrypt-then-MAC tag.
fn compute_mac(mac_key: &[u8; MAC_LEN], header: &[u8], nonce: &[u8], ciphertext: &[u8]) -> [u8; MAC_LEN] {
    // HMAC accepts a key of any length; a 32-byte key is always valid.
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(header);
    mac.update(nonce);
    mac.update(ciphertext);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Constant-time comparison of two MACs, so verification timing does not leak how
/// many leading bytes an attacker guessed correctly.
fn constant_time_eq(a: &[u8; MAC_LEN], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if b.len() != MAC_LEN {
        return false;
    }
    a.ct_eq(b).into()
}

/// Fill `buf` from `reader`. Returns `false` on a clean or partial end-of-stream,
/// `true` only when the buffer was completely filled.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool, std::io::Error> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => return Ok(false),
            n => filled += n,
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::handshake::{begin_handshake, finish_handshake, respond_to_hello, NodeIdentity};

    const CHAIN: u32 = 0x2E01_0001;

    /// Two channels with mirrored keys, as produced by a completed handshake.
    fn handshake_pair() -> (SecureChannel, SecureChannel) {
        let alice_id = NodeIdentity::random();
        let bob_id = NodeIdentity::random();
        let (state, hello) = begin_handshake(&alice_id, CHAIN);
        let (bob_keys, back) = respond_to_hello(&bob_id, CHAIN, &hello).expect("bob responds");
        let alice_keys = finish_handshake(state, &back).expect("alice finishes");
        let alice = SecureChannel::new(
            &alice_keys.send.enc,
            &alice_keys.send.mac,
            &alice_keys.recv.enc,
            &alice_keys.recv.mac,
        )
        .expect("alice channel");
        let bob = SecureChannel::new(
            &bob_keys.send.enc,
            &bob_keys.send.mac,
            &bob_keys.recv.enc,
            &bob_keys.recv.mac,
        )
        .expect("bob channel");
        (alice, bob)
    }

    /// Two channels sharing one key set in both directions, for tests that only
    /// need a self-consistent seal/open loop.
    fn symmetric_pair() -> (SecureChannel, SecureChannel) {
        let enc = [7u8; 32];
        let mac = [9u8; 32];
        let a = SecureChannel::new(&enc, &mac, &enc, &mac).unwrap();
        let b = SecureChannel::new(&enc, &mac, &enc, &mac).unwrap();
        (a, b)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (mut alice, mut bob) = handshake_pair();
        let msg = b"hello zerocoin";
        let frame = alice.seal(msg).expect("seals");
        let recovered = bob.open(&frame).expect("opens");
        assert_eq!(recovered, msg);
    }

    #[test]
    fn frame_layout_has_expected_overhead() {
        let (mut alice, _) = handshake_pair();
        let msg = b"0123456789";
        let frame = alice.seal(msg).expect("seals");
        assert_eq!(frame.len(), FRAME_OVERHEAD + msg.len());
        assert_eq!(&frame[..MAGIC_LEN], &NETWORK_MAGIC);
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let (mut alice, _) = handshake_pair();
        let msg = b"a secret payment instruction";
        let frame = alice.seal(msg).expect("seals");
        // The plaintext must not appear anywhere in the frame.
        assert!(!frame
            .windows(msg.len())
            .any(|w| w == msg));
    }

    #[test]
    fn many_frames_sequence_correctly() {
        let (mut alice, mut bob) = handshake_pair();
        for i in 0..50u64 {
            let msg = format!("message {i}");
            let frame = alice.seal(msg.as_bytes()).expect("seals");
            let recovered = bob.open(&frame).expect("opens");
            assert_eq!(recovered, msg.as_bytes());
        }
        assert_eq!(alice.send_seq(), 50);
        assert_eq!(bob.recv_seq(), 50);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (mut alice, mut bob) = handshake_pair();
        let mut frame = alice.seal(b"transfer 50 ZRO to me").expect("seals");
        // Flip one bit of the ciphertext region.
        let ct_index = HEADER_LEN + NONCE_LEN;
        frame[ct_index] ^= 0x01;
        assert!(matches!(bob.open(&frame), Err(FrameError::AuthFailed)));
    }

    #[test]
    fn tampered_header_rejected() {
        let (mut alice, mut bob) = handshake_pair();
        let mut frame = alice.seal(b"payload").expect("seals");
        // Alter the sequence number in the header; the HMAC covers it.
        frame[MAGIC_LEN] ^= 0xff;
        // Either the sequence is now wrong, or the HMAC fails — both are rejections.
        assert!(matches!(
            bob.open(&frame),
            Err(FrameError::ReplayOrOutOfOrder { .. } | FrameError::AuthFailed)
        ));
    }

    #[test]
    fn replayed_frame_rejected() {
        let (mut alice, mut bob) = handshake_pair();
        let frame = alice.seal(b"spend one coin").expect("seals");
        bob.open(&frame).expect("first delivery accepted");
        // A recorder replays the exact bytes.
        assert!(matches!(
            bob.open(&frame),
            Err(FrameError::ReplayOrOutOfOrder { expected: 1, found: 0 })
        ));
    }

    #[test]
    fn reordered_frames_rejected() {
        let (mut alice, mut bob) = handshake_pair();
        let first = alice.seal(b"first").expect("seals");
        let second = alice.seal(b"second").expect("seals");
        // Delivering the newer frame first is out of order.
        assert!(matches!(
            bob.open(&second),
            Err(FrameError::ReplayOrOutOfOrder { expected: 0, found: 1 })
        ));
        // The genuinely-next frame still opens.
        assert_eq!(bob.open(&first).expect("opens"), b"first");
    }

    #[test]
    fn swapped_nonce_rejected() {
        let (mut alice, mut bob) = handshake_pair();
        let mut frame = alice.seal(b"payload").expect("seals");
        // Corrupt the nonce; it must equal nonce_from_seq(seq).
        frame[HEADER_LEN] ^= 0x01;
        assert!(matches!(bob.open(&frame), Err(FrameError::NonceMismatch)));
    }

    #[test]
    fn bad_magic_rejected() {
        let (mut alice, mut bob) = handshake_pair();
        let mut frame = alice.seal(b"payload").expect("seals");
        frame[0] ^= 0xff;
        assert!(matches!(bob.open(&frame), Err(FrameError::BadMagic)));
    }

    #[test]
    fn truncated_frame_rejected() {
        let (mut alice, mut bob) = handshake_pair();
        let frame = alice.seal(b"payload").expect("seals");
        let short = &frame[..frame.len() - 5];
        assert!(matches!(bob.open(short), Err(FrameError::Truncated(_))));
    }

    #[test]
    fn oversized_plaintext_rejected() {
        let (mut alice, _) = handshake_pair();
        let huge = vec![0u8; MAX_PLAINTEXT_BYTES + 1];
        assert!(matches!(alice.seal(&huge), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn wrong_session_keys_rejected() {
        let (mut alice, _) = handshake_pair();
        let (mut stranger, _) = handshake_pair();
        let frame = alice.seal(b"for bob only").expect("seals");
        // A different session has different keys: authentication must fail.
        assert!(matches!(stranger.open(&frame), Err(FrameError::AuthFailed)));
    }

    #[test]
    fn stream_roundtrip_over_in_memory_pipe() {
        let (mut alice, mut bob) = handshake_pair();
        let mut wire: Vec<u8> = Vec::new();
        alice.write_frame(&mut wire, b"one").expect("writes");
        alice.write_frame(&mut wire, b"two").expect("writes");

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(bob.read_frame(&mut cursor).expect("reads").as_deref(), Some(&b"one"[..]));
        assert_eq!(bob.read_frame(&mut cursor).expect("reads").as_deref(), Some(&b"two"[..]));
        // Clean EOF at a frame boundary.
        assert!(bob.read_frame(&mut cursor).expect("eof").is_none());
    }

    #[test]
    fn symmetric_channel_roundtrip() {
        let (mut a, mut b) = symmetric_pair();
        let frame = a.seal(b"loopback").expect("seals");
        assert_eq!(b.open(&frame).expect("opens"), b"loopback");
    }

    #[test]
    fn nonce_is_derived_from_sequence() {
        assert_eq!(nonce_from_seq(0)[..4], [0, 0, 0, 0]);
        assert_eq!(&nonce_from_seq(1)[4..], &1u64.to_le_bytes());
        assert_ne!(nonce_from_seq(1), nonce_from_seq(2));
    }
}
