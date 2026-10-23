# Vendored upstream verification materials (P2.10)

This directory closes blocker CB-3 of
`docs/architecture/CRYPTO_BLOCKER_REGISTER.md`: until P2.10 the GPG
verification in `../ORIGIN.md` §2 was a recorded transcript — the only
evidence — and `../SHA256SUMS` proved non-drift of the vendored tree, not its
upstream identity. A third party could not re-verify the release from the
repository alone.

Contents (pins recorded in `../ORIGIN.md` §1–§2 and the `../SHA256SUMS`
archive line):

| File | Size | SHA-256 |
|---|---|---|
| `libsecp256k1-0.8.0.tar.gz` | 2,436,784 bytes | `dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b` |
| `libsecp256k1-0.8.0.tar.gz.sig` | 566 bytes | `c7eb14bbd67fe94b9ac4b556df6ae18aebb450092c836d05a6e13ea005fc7ac8` |

`secp256k1-release-signing-key.asc` is the **public** verification key for
fingerprint `6A8F 9C26 6528 E25A EB1D 7731 C237 1D91 CB71 6EA7` (RSA 4096,
Sebastian Falbesoner / theStack), fetched from
`https://keys.openpgp.org/vks/v1/by-fingerprint/6A8F9C266528E25AEB1D7731C2371D91CB716EA7`
— the copy whose self-signatures extend validity to 2030-12-19. See
`../ORIGIN.md` §2 for the recorded anomaly: the `https://github.com/thestack.gpg`
copy was stale (expired 2025-11-20) and produced `EXPKEYSIG`; the fingerprint
never changed. The key file is intentionally not pinned by hash — a keyserver
may legitimately re-serve updated self-signature packets for the same
fingerprint — but by fingerprint, which is the identity the gate enforces.

Only public material is vendored: an archive, its detached signature, and a
public key. No private key material exists here, and none may ever be added.

## Re-verification

`scripts/gate-p2-10-provenance.ps1` re-derives the whole chain from this
directory and exits 0 only if every step passes:

1. the archive and signature match the pinned sizes and SHA-256 values, and
   the `SHA256SUMS` archive line records the same hash;
2. the vendored key carries exactly the pinned fingerprint (`gpg --show-keys`,
   checked before anything is imported anywhere);
3. the detached signature verifies against the vendored key in an isolated,
   throwaway GnuPG home — `GOODSIG`/`VALIDSIG` for the pinned fingerprint,
   exit code 0 (`TRUST_UNDEFINED` is expected and is not a failure: the trust
   anchor is the pinned fingerprint, not a web-of-trust path);
4. every file listed in `SHA256SUMS` is byte-identical to the same relative
   path in the archive's inner tree and still hashes to its recorded value.

The P2.6 transcript in `../ORIGIN.md` remains the historical acquisition
record; the standing evidence is this gate, executable by anyone with a clone.
