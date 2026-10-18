"""ZeroCoin baseline-vector verifier.

A dependency-free re-implementation of the consensus primitives the Rust crate
defines: hashing, secp256k1 signing, transaction serialization, the script
interpreter, sighash, difficulty, subsidy, proof of work, block headers and the
UTXO state root.

Nothing here imports from the Rust tree. Every expected value under
``test/vectors/`` is recomputed from the published ``input`` alone, so a case
passes only when two independent implementations agree byte for byte. Values
that cannot be recomputed (a Rust call result or a network constant table) are
reported as ANCHOR by ``run_vectors.py`` and never counted as verification.

Byte-order convention: ``Hash256.0`` in Rust holds the raw digest bytes. The
JSON form ``{"internal_hex": ..., "display_hex": ...}`` publishes those bytes
and their reverse, which is the big-endian "display" form. All arithmetic here
works on internal bytes unless a case says ``display``.
"""

import hashlib
import hmac

MASK256 = (1 << 256) - 1
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


class VectorMismatch(Exception):
    """A recomputed value disagrees with the vector's expected value."""


class Unsupported(Exception):
    """The verifier has no independent implementation for this case."""


def hx(data):
    return data.hex()


def unhex(text):
    return bytes.fromhex(text)


def le32(value):
    return (value & MASK32).to_bytes(4, "little")


def le64(value):
    return (value & MASK64).to_bytes(8, "little")


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256(data):
    return hashlib.sha256(data).digest()


def sha256d(data):
    return sha256(sha256(data))


def hash256_json(digest):
    return {"display_hex": digest[::-1].hex(), "internal_hex": digest.hex()}


def parse_hash256(obj):
    return unhex(obj["internal_hex"])


_ROL = lambda x, n: ((x << n) | (x >> (32 - n))) & MASK32

_RMD_R1 = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_RMD_R2 = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_RMD_S1 = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_RMD_S2 = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_RMD_K1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_RMD_K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _rmd_f(round_index, x, y, z):
    if round_index == 0:
        return x ^ y ^ z
    if round_index == 1:
        return (x & y) | (~x & z)
    if round_index == 2:
        return (x | ~y) ^ z
    if round_index == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rmd_fp(round_index, x, y, z):
    if round_index == 0:
        return x ^ (y | ~z)
    if round_index == 1:
        return (x & z) | (y & ~z)
    if round_index == 2:
        return (x | ~y) ^ z
    if round_index == 3:
        return (x & y) | (~x & z)
    return x ^ y ^ z


def ripemd160(data):
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    message = bytearray(data)
    bit_length = len(data) * 8
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += bit_length.to_bytes(8, "little")

    for offset in range(0, len(message), 64):
        words = [int.from_bytes(message[offset + 4 * i:offset + 4 * i + 4], "little")
                 for i in range(16)]
        al, bl, cl, dl, el = state
        ar, br, cr, dr, er = state
        for j in range(80):
            rnd = j // 16
            t = (al + _rmd_f(rnd, bl, cl, dl) + words[_RMD_R1[j]] + _RMD_K1[rnd]) & MASK32
            t = (_ROL(t, _RMD_S1[j]) + el) & MASK32
            al, el, dl, cl, bl = el, dl, _ROL(cl, 10), bl, t

            t = (ar + _rmd_fp(rnd, br, cr, dr) + words[_RMD_R2[j]] + _RMD_K2[rnd]) & MASK32
            t = (_ROL(t, _RMD_S2[j]) + er) & MASK32
            ar, er, dr, cr, br = er, dr, _ROL(cr, 10), br, t

        t = (state[1] + cl + dr) & MASK32
        state[1] = (state[2] + dl + er) & MASK32
        state[2] = (state[3] + el + ar) & MASK32
        state[3] = (state[4] + al + br) & MASK32
        state[4] = (state[0] + bl + cr) & MASK32
        state[0] = t

    return b"".join(value.to_bytes(4, "little") for value in state)


def hash160(data):
    return ripemd160(sha256(data))


# ---------------------------------------------------------------------------
# Base58Check
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {ch: i for i, ch in enumerate(B58_ALPHABET)}


def b58encode(data):
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = B58_ALPHABET[remainder] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def b58decode(text):
    number = 0
    for ch in text:
        if ch not in B58_INDEX:
            raise ValueError("not base58: %r" % ch)
        number = number * 58 + B58_INDEX[ch]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


# ---------------------------------------------------------------------------
# secp256k1
# ---------------------------------------------------------------------------

SECP_P = 2 ** 256 - 2 ** 32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP_G = (SECP_GX, SECP_GY)


def _point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % SECP_P == 0:
        return None
    if left == right:
        slope = 3 * x1 * x1 * pow(2 * y1, SECP_P - 2, SECP_P) % SECP_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, SECP_P - 2, SECP_P) % SECP_P
    x3 = (slope * slope - x1 - x2) % SECP_P
    return (x3, (slope * (x1 - x3) - y1) % SECP_P)


def _point_mul(scalar, point=SECP_G):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def compressed_pubkey(scalar):
    point = _point_mul(scalar)
    prefix = b"\x02" if point[1] % 2 == 0 else b"\x03"
    return prefix + point[0].to_bytes(32, "big")


def parse_pubkey(sec1):
    if len(sec1) != 33 or sec1[0] not in (0x02, 0x03):
        raise ValueError("not a compressed SEC1 point")
    x = int.from_bytes(sec1[1:], "big")
    if x >= SECP_P:
        raise ValueError("x out of field range")
    rhs = (pow(x, 3, SECP_P) + 7) % SECP_P
    y = pow(rhs, (SECP_P + 1) // 4, SECP_P)
    if pow(y, 2, SECP_P) != rhs:
        raise ValueError("not on curve")
    if (y & 1) != (sec1[0] & 1):
        y = SECP_P - y
    return (x, y)


def der_encode(r, s):
    def integer(value):
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def der_decode(der):
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("bad DER header")
    if der[2] != 0x02:
        raise ValueError("bad DER r")
    r_len = der[3]
    r = int.from_bytes(der[4:4 + r_len], "big")
    offset = 4 + r_len
    if der[offset] != 0x02:
        raise ValueError("bad DER s")
    s_len = der[offset + 1]
    s = int.from_bytes(der[offset + 2:offset + 2 + s_len], "big")
    if offset + 2 + s_len != len(der):
        raise ValueError("trailing DER bytes")
    return r, s


def rfc6979_k(secret, digest):
    """RFC 6979 deterministic nonce with HMAC-SHA256, as k256 produces it."""
    x = secret.to_bytes(32, "big")
    h1 = digest

    def mac(key, message):
        return hmac.new(key, message, hashlib.sha256).digest()

    v = b"\x01" * 32
    k = b"\x00" * 32
    k = mac(k, v + b"\x00" + x + h1)
    v = mac(k, v)
    k = mac(k, v + b"\x01" + x + h1)
    v = mac(k, v)
    while True:
        v = mac(k, v)
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < SECP_N:
            return candidate
        k = mac(k, v + b"\x00")
        v = mac(k, v)


def ecdsa_sign(secret, digest):
    """Deterministic low-S signature over a 32-byte digest."""
    z = int.from_bytes(digest, "big") % SECP_N
    nonce = rfc6979_k(secret, digest)
    point = _point_mul(nonce)
    r = point[0] % SECP_N
    if r == 0:
        raise ValueError("zero r")
    s = pow(nonce, SECP_N - 2, SECP_N) * (z + r * secret) % SECP_N
    if s == 0:
        raise ValueError("zero s")
    if s > SECP_N // 2:
        s = SECP_N - s
    return der_encode(r, s)


def ecdsa_verify(pubkey_sec1, digest, der):
    try:
        point = parse_pubkey(pubkey_sec1)
        r, s = der_decode(der)
    except ValueError:
        return False
    if not (1 <= r < SECP_N and 1 <= s < SECP_N):
        return False
    z = int.from_bytes(digest, "big") % SECP_N
    w = pow(s, SECP_N - 2, SECP_N)
    u1 = z * w % SECP_N
    u2 = r * w % SECP_N
    combined = _point_add(_point_mul(u1), _point_mul(u2, point))
    if combined is None:
        return False
    return combined[0] % SECP_N == r


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

MAX_TX_BYTES = 1_000_000
MAX_TX_INPUTS = 10_000
MAX_TX_OUTPUTS = 10_000


class DecodeError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def write_varint(value, out):
    if value <= 0xFC:
        out.append(value)
    elif value <= 0xFFFF:
        out.append(0xFD)
        out += value.to_bytes(2, "little")
    elif value <= 0xFFFFFFFF:
        out.append(0xFE)
        out += value.to_bytes(4, "little")
    else:
        out.append(0xFF)
        out += value.to_bytes(8, "little")


def varint_bytes(value):
    out = bytearray()
    write_varint(value, out)
    return bytes(out)


class _Cursor:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, count):
        end = self.pos + count
        if end > len(self.data):
            raise DecodeError("Truncated")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), "little")

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def u64(self):
        return int.from_bytes(self.take(8), "little")

    def varint(self):
        prefix = self.u8()
        if prefix < 0xFD:
            return prefix
        if prefix == 0xFD:
            value = self.u16()
            if value < 0xFD:
                raise DecodeError("NonMinimalVarInt")
            return value
        if prefix == 0xFE:
            value = self.u32()
            if value < 0x10000:
                raise DecodeError("NonMinimalVarInt")
            return value
        value = self.u64()
        if value < 0x100000000:
            raise DecodeError("NonMinimalVarInt")
        return value


def read_varint(data, pos=0):
    cursor = _Cursor(data)
    cursor.pos = pos
    value = cursor.varint()
    return value, cursor.pos


def tx_serialize(tx):
    out = bytearray()
    out += le32(tx["version"])
    write_varint(len(tx["inputs"]), out)
    for item in tx["inputs"]:
        out += item["txid"]
        out += le32(item["vout"])
        write_varint(len(item["script_sig"]), out)
        out += item["script_sig"]
        out += le32(item["sequence"])
    write_varint(len(tx["outputs"]), out)
    for item in tx["outputs"]:
        out += le64(item["value"])
        write_varint(len(item["script_pubkey"]), out)
        out += item["script_pubkey"]
    out += le32(tx["lock_time"])
    return bytes(out)


def tx_deserialize(data):
    cursor = _Cursor(data)
    version = cursor.u32()
    input_count = cursor.varint()
    if input_count > MAX_TX_INPUTS:
        raise DecodeError("TooManyInputs")
    inputs = []
    for _ in range(input_count):
        txid = cursor.take(32)
        vout = cursor.u32()
        script_len = cursor.varint()
        if script_len > MAX_TX_BYTES:
            raise DecodeError("ScriptTooLarge")
        script_sig = cursor.take(script_len)
        sequence = cursor.u32()
        inputs.append({
            "txid": txid,
            "vout": vout,
            "script_sig": script_sig,
            "sequence": sequence,
        })
    output_count = cursor.varint()
    if output_count > MAX_TX_OUTPUTS:
        raise DecodeError("TooManyOutputs")
    outputs = []
    for _ in range(output_count):
        value = cursor.u64()
        script_len = cursor.varint()
        if script_len > MAX_TX_BYTES:
            raise DecodeError("ScriptTooLarge")
        outputs.append({"value": value, "script_pubkey": cursor.take(script_len)})
    lock_time = cursor.u32()
    return {
        "version": version,
        "inputs": inputs,
        "outputs": outputs,
        "lock_time": lock_time,
    }


def tx_from_json(obj):
    inputs = obj["inputs"]
    if isinstance(inputs, int):
        inputs = []
    outputs = obj["outputs"]
    if isinstance(outputs, int):
        outputs = []
    return {
        "version": obj["version"],
        "inputs": [{
            "txid": unhex(item["txid_hex"]),
            "vout": item["vout"],
            "script_sig": unhex(item["script_sig_hex"]),
            "sequence": item["sequence"],
        } for item in inputs],
        "outputs": [{
            "value": item["value"],
            "script_pubkey": unhex(item["script_pubkey_hex"]),
        } for item in outputs],
        "lock_time": obj["lock_time"],
    }


def tx_txid(tx):
    return sha256d(tx_serialize(tx))


def tx_output_value(tx):
    total = 0
    for item in tx["outputs"]:
        total += item["value"]
        if total > MASK64:
            return None
    return total


def tx_is_coinbase(tx):
    if len(tx["inputs"]) != 1:
        return False
    return tx["inputs"][0]["txid"] == b"\x00" * 32 and tx["inputs"][0]["vout"] == MASK32


# ---------------------------------------------------------------------------
# Script
# ---------------------------------------------------------------------------

MAX_STACK_ITEMS = 1_000
MAX_SCRIPT_ELEMENT = 520
MAX_OPS_PER_SCRIPT = 201
MAX_SCRIPT_SIZE = 10_000

OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_VERIFY = 0x69
OP_DROP = 0x75
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC


class ScriptError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def push_data(item, out):
    length = len(item)
    if length < OP_PUSHDATA1:
        out.append(length)
    elif length <= 0xFF:
        out.append(OP_PUSHDATA1)
        out.append(length)
    else:
        out.append(OP_PUSHDATA2)
        out += length.to_bytes(2, "little")
    out += item


def p2pkh_script_pubkey(pubkey_hash):
    out = bytearray([OP_DUP, OP_HASH160])
    push_data(pubkey_hash, out)
    out += bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    return bytes(out)


def p2pkh_script_sig(signature, pubkey):
    out = bytearray()
    push_data(signature, out)
    push_data(pubkey, out)
    return bytes(out)


def script_is_true(item):
    if not item:
        return False
    for index, byte in enumerate(item):
        if byte != 0:
            if index == len(item) - 1 and byte == 0x80:
                return False
            return True
    return False


def _script_push(stack, item):
    if len(item) > MAX_SCRIPT_ELEMENT:
        raise ScriptError("ElementTooLarge")
    if len(stack) >= MAX_STACK_ITEMS:
        raise ScriptError("StackOverflow")
    stack.append(item)


def _pop(stack):
    if not stack:
        raise ScriptError("StackUnderflow")
    return stack.pop()


def run_script(script, stack, checker):
    if len(script) > MAX_SCRIPT_SIZE:
        raise ScriptError("ScriptTooLarge")
    ops = 0
    index = 0
    size = len(script)
    while index < size:
        opcode = script[index]
        index += 1
        if opcode <= OP_PUSHDATA2:
            if opcode < OP_PUSHDATA1:
                push_len = opcode
            elif opcode == OP_PUSHDATA1:
                if index + 1 > size:
                    raise ScriptError("Truncated")
                push_len = script[index]
                index += 1
            else:
                if index + 2 > size:
                    raise ScriptError("Truncated")
                push_len = int.from_bytes(script[index:index + 2], "little")
                index += 2
            if index + push_len > size:
                raise ScriptError("Truncated")
            _script_push(stack, script[index:index + push_len])
            index += push_len
            continue

        ops += 1
        if ops > MAX_OPS_PER_SCRIPT:
            raise ScriptError("TooManyOps")

        if opcode == OP_VERIFY:
            if not script_is_true(_pop(stack)):
                raise ScriptError("VerifyFailed")
        elif opcode == OP_DROP:
            _pop(stack)
        elif opcode == OP_DUP:
            if not stack:
                raise ScriptError("StackUnderflow")
            _script_push(stack, stack[-1])
        elif opcode == OP_EQUAL:
            left = _pop(stack)
            right = _pop(stack)
            _script_push(stack, b"\x01" if left == right else b"")
        elif opcode == OP_EQUALVERIFY:
            left = _pop(stack)
            right = _pop(stack)
            if left != right:
                raise ScriptError("EqualVerifyFailed")
        elif opcode == OP_HASH160:
            _script_push(stack, hash160(_pop(stack)))
        elif opcode == OP_CHECKSIG:
            pubkey = _pop(stack)
            signature = _pop(stack)
            _script_push(stack, b"\x01" if checker(signature, pubkey) else b"")
        else:
            raise ScriptError("UnsupportedOpcode")


def script_verify(script_sig, script_pubkey, checker):
    stack = []
    run_script(script_sig, stack, checker)
    run_script(script_pubkey, stack, checker)
    if not stack or not script_is_true(stack[-1]):
        raise ScriptError("EvalFalse")


# ---------------------------------------------------------------------------
# Sighash
# ---------------------------------------------------------------------------

SIGHASH_TAG = b"ZRO/sighash/v1\0"
SIGHASH_ALL = 1


def signature_preimage(tx, input_index, script_code, chain_id, sighash_type=SIGHASH_ALL):
    """The exact bytes `signature_hash` digests, or None past the last input."""
    if input_index >= len(tx["inputs"]):
        return None
    out = bytearray(SIGHASH_TAG)
    out += le32(chain_id)
    out += le32(tx["version"])
    write_varint(len(tx["inputs"]), out)
    for index, item in enumerate(tx["inputs"]):
        out += item["txid"]
        out += le32(item["vout"])
        script = script_code if index == input_index else b""
        write_varint(len(script), out)
        out += script
        out += le32(item["sequence"])
    write_varint(len(tx["outputs"]), out)
    for item in tx["outputs"]:
        out += le64(item["value"])
        write_varint(len(item["script_pubkey"]), out)
        out += item["script_pubkey"]
    out += le32(tx["lock_time"])
    out += le32(sighash_type)
    return bytes(out)


def signature_hash(tx, input_index, script_code, chain_id, sighash_type=SIGHASH_ALL):
    """The chain-bound sha256d digest a signature commits to."""
    preimage = signature_preimage(tx, input_index, script_code, chain_id, sighash_type)
    return None if preimage is None else sha256d(preimage)


def tx_sig_checker(tx, input_index, script_code, chain_id):
    """The closure the script interpreter calls for OP_CHECKSIG."""

    def check(signature_with_type, pubkey_sec1):
        if not signature_with_type or signature_with_type[-1] != SIGHASH_ALL:
            return False
        digest = signature_hash(tx, input_index, script_code, chain_id, SIGHASH_ALL)
        if digest is None:
            return False
        try:
            signature = signature_with_type[:-1]
            return ecdsa_verify(pubkey_sec1, digest, signature)
        except (ValueError, ArithmeticError):
            return False

    return check


# ---------------------------------------------------------------------------
# Uint256 difficulty arithmetic
# ---------------------------------------------------------------------------

DIFFICULTY_PARAMS = {
    "target_spacing_seconds": 60,
    "retarget_interval": 1_440,
    "max_adjustment_factor": 4,
    "pow_limit_bits": 0x1E00FFFF,
}

MAINNET_POW_LIMIT_BITS = 0x1E00FFFF
TRIVIAL_POW_LIMIT_BITS = 0x207FFFFF


def leading_zeros(value):
    return 256 - value.bit_length()


def compact_to_target(bits):
    """value = mantissa * 256^(exponent - 3); a set sign bit means zero."""
    exponent = (bits >> 24) & 0xFF
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        return 0
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return (mantissa << (8 * (exponent - 3))) & MASK256


def target_to_compact(target):
    """Bitcoin's compact encoding, rounding the mantissa down."""
    if target == 0:
        return 0
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        shifted = (target << (8 * (3 - size))) & MASK256
    else:
        shifted = target >> (8 * (size - 3))
    mantissa = shifted & 0x00FFFFFF
    exponent = size
    if mantissa & 0x00800000:
        mantissa >>= 8
        exponent += 1
    return ((exponent << 24) | (mantissa & 0x007FFFFF)) & MASK32


def target_be_hex(target):
    return target.to_bytes(32, "big").hex()


def hash_meets_target(pow_hash, target):
    """Comparison is on the big-endian byte value and is inclusive."""
    return int.from_bytes(pow_hash, "big") <= target


def required_work(target):
    """(~target) / (target + 1) + 1, modulo 2^256 like the Rust limbs."""
    if target == 0:
        return 0
    denominator = (target + 1) & MASK256
    quotient = ((target ^ MASK256) & MASK256) // denominator
    return (quotient + 1) & MASK256


def target_window_seconds(params):
    return params["retarget_interval"] * params["target_spacing_seconds"]


def next_difficulty(prev_bits, actual_window_seconds, params):
    prev_target = compact_to_target(prev_bits)
    expected = max(target_window_seconds(params), 1)
    factor = max(params["max_adjustment_factor"], 2)

    min_timespan = expected // factor
    max_timespan = expected * factor
    actual = min(max(actual_window_seconds, max(min_timespan, 1)), max_timespan)

    if leading_zeros(prev_target) >= 20:
        new_target = ((prev_target * actual) & MASK256) // expected
    else:
        new_target = ((prev_target // expected) * actual) & MASK256

    pow_limit = compact_to_target(params["pow_limit_bits"])
    capped = pow_limit if new_target > pow_limit or new_target == 0 else new_target
    return target_to_compact(capped)


def validate_bits(bits, params):
    """None when the block's own difficulty is legal, else the error kind."""
    target = compact_to_target(bits)
    if target == 0:
        return "ZeroTarget"
    if target > compact_to_target(params["pow_limit_bits"]):
        return "TargetAbovePowLimit"
    return None


# ---------------------------------------------------------------------------
# Reward: subsidy, maturity, coinbase, pool split
# ---------------------------------------------------------------------------

FAH_PER_ZRO = 100_000_000
INITIAL_SUBSIDY = 50 * FAH_PER_ZRO
HALVING_INTERVAL = 210_000
MAX_HALVINGS = 64
MAX_SUPPLY = 21_000_000 * FAH_PER_ZRO
COINBASE_MATURITY = 100

COINBASE_TAG = b"ZeroCoin"
POOL_COINBASE_TAG = b"ZeroCoin/pool"


def block_subsidy(height):
    if height == 0:
        return 0
    halvings = height // HALVING_INTERVAL
    if halvings >= MAX_HALVINGS:
        return 0
    return INITIAL_SUBSIDY >> halvings


def block_reward(height, fees):
    """None when subsidy + fees overflows u64."""
    total = block_subsidy(height) + fees
    return None if total > MASK64 else total


def maturity_height(height):
    return min(height + COINBASE_MATURITY, MASK64)


def total_supply_ceiling():
    total = 0
    halvings = 0
    while halvings < MAX_HALVINGS:
        per_block = INITIAL_SUBSIDY >> halvings
        if per_block == 0:
            break
        total = total + (per_block * HALVING_INTERVAL)
        total = min(total, MASK64)
        halvings += 1
    return total


def script_num(value):
    if value == 0:
        return b""
    out = bytearray()
    while value > 0:
        out.append(value & 0xFF)
        value >>= 8
    if out[-1] & 0x80:
        out.append(0x00)
    return bytes(out)


def parse_script_num(data):
    if not data:
        return 0
    if len(data) > 8:
        return None
    if data[-1] & 0x80:
        return None
    value = 0
    for byte in reversed(data):
        value = (value << 8) | byte
    return value


def coinbase_transaction(height, pubkey_hash, reward, tag=COINBASE_TAG):
    script_sig = bytearray()
    push_data(script_num(height), script_sig)
    push_data(tag, script_sig)
    return {
        "version": 1,
        "inputs": [{
            "txid": b"\x00" * 32,
            "vout": MASK32,
            "script_sig": bytes(script_sig),
            "sequence": MASK32,
        }],
        "outputs": [{
            "value": reward,
            "script_pubkey": p2pkh_script_pubkey(pubkey_hash),
        }],
        "lock_time": 0,
    }


def pool_coinbase_transaction(height, reward, payouts):
    script_sig = bytearray()
    push_data(script_num(height), script_sig)
    push_data(POOL_COINBASE_TAG, script_sig)
    return {
        "version": 1,
        "inputs": [{
            "txid": b"\x00" * 32,
            "vout": MASK32,
            "script_sig": bytes(script_sig),
            "sequence": MASK32,
        }],
        "outputs": [{
            "value": value,
            "script_pubkey": p2pkh_script_pubkey(pubkey_hash),
        } for pubkey_hash, value in payouts],
        "lock_time": 0,
    }


def coinbase_height(tx):
    if not tx_is_coinbase(tx):
        return None
    script = tx["inputs"][0]["script_sig"]
    if not script:
        return None
    length = script[0]
    if length > 8 or len(script) < 1 + length:
        return None
    return parse_script_num(script[1:1 + length])


def split_reward(reward, payouts):
    """Proportional floor shares, remainder to the first, zero shares dropped."""
    total_weight = sum(weight for _, weight in payouts)
    if reward == 0 or total_weight == 0:
        return []
    out = []
    allocated = 0
    for pubkey_hash, weight in payouts:
        if weight == 0:
            continue
        share = reward * weight // total_weight
        allocated += share
        out.append([pubkey_hash, share])
    if out:
        out[0][1] += reward - allocated
    return [pair for pair in out if pair[1] > 0]


def validate_coinbase(tx, height, fees, subsidy_issued):
    """Return (claimed, None) or (None, error_kind), in the Rust check order."""
    if not tx_is_coinbase(tx):
        return None, "NotCoinbase"
    committed = coinbase_height(tx)
    if committed is None:
        return None, "MissingHeightCommitment"
    if committed != height:
        return None, "BadCoinbaseHeight"

    claimed = 0
    for output in tx["outputs"]:
        claimed += output["value"]
        if claimed > MASK64:
            return None, "RewardOverflow"

    if height == 0 and claimed != 0:
        return None, "GenesisPremine"

    allowed = block_reward(height, fees)
    if allowed is None:
        return None, "RewardOverflow"
    if claimed > allowed:
        return None, "TooMuchReward"
    if claimed < fees:
        return None, "BelowFees"

    issued = subsidy_issued + block_subsidy(height)
    if issued > MASK64:
        return None, "RewardOverflow"
    if issued > MAX_SUPPLY:
        return None, "SupplyCapExceeded"
    return claimed, None


# ---------------------------------------------------------------------------
# Proof of work engines
# ---------------------------------------------------------------------------

ENGINE_ID_TRIVIAL = 0
ENGINE_ID_SCRATCHPAD = 1
TRIVIAL_ENGINE_NAME = "sha256d-trivial"
SCRATCHPAD_ENGINE_NAME = "scratchpad-memory-hard"

SCRATCHPAD_CELL = 32


def trivial_hash(preimage, nonce):
    """sha256d(preimage || nonce_le64)."""
    return sha256d(preimage + le64(nonce))


def scratchpad_hash(preimage, nonce, memory_bytes, rounds):
    """Seed, fill, data-dependent rounds, then one streaming SHA-256 finalizer."""
    cells = max(memory_bytes // SCRATCHPAD_CELL, 1)
    state = sha256(preimage + le64(nonce))

    pad = []
    for _ in range(cells):
        state = sha256(state)
        pad.append(state)

    power_of_two = (cells & (cells - 1)) == 0
    mask = cells - 1
    for _ in range(rounds):
        index_word = int.from_bytes(state[0:8], "little")
        index = (index_word & mask) if power_of_two else (index_word % cells)
        state = sha256(state + pad[index])
        pad[index] = state

    finalizer = sha256(state + b"".join(pad))
    return finalizer


def mine(hasher, preimage, target, start=0):
    """Search nonces upward until one meets the target."""
    nonce = start
    while nonce <= MASK64:
        candidate = hasher(preimage, nonce)
        if hash_meets_target(candidate, target):
            return nonce, candidate
        nonce += 1
    raise Unsupported("nonce exhausted")


# ---------------------------------------------------------------------------
# Block header, Merkle root, genesis
# ---------------------------------------------------------------------------

HEADER_TAG = b"ZRO/header/v1\0"
EMPTY_MERKLE_TAG = b"ZRO/merkle:empty\0"
BLOCK_VERSION = 1
GENESIS_TIMESTAMP = 1_735_689_600
GENESIS_MESSAGE = b"No premine, no owner: ZeroCoin is issued only by proof of work"


def header_preimage(header):
    out = bytearray(HEADER_TAG)
    out += le32(header["version"])
    out += le32(header["chain"])
    out += le64(header["height"])
    out += header["previous_hash"]
    out += header["merkle_root"]
    out += le64(header["timestamp"])
    out += le32(header["difficulty_bits"])
    out.append(header["engine_id"])
    return bytes(out)


def merkle_root(leaves):
    """sha256d over duplicate-when-odd pairs; empty is the domain tag."""
    if not leaves:
        return sha256d(EMPTY_MERKLE_TAG)
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        index = 0
        while index < len(level):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            nxt.append(sha256d(left + right))
            index += 2
        level = nxt
    return level[0]


def genesis_coinbase():
    script_sig = bytearray()
    push_data(b"", script_sig)
    push_data(GENESIS_MESSAGE, script_sig)
    return {
        "version": 1,
        "inputs": [{
            "txid": b"\x00" * 32,
            "vout": MASK32,
            "script_sig": bytes(script_sig),
            "sequence": MASK32,
        }],
        "outputs": [],
        "lock_time": 0,
    }


def genesis_header(params, merkle):
    return {
        "version": BLOCK_VERSION,
        "chain": params["chain_id"],
        "height": 0,
        "previous_hash": b"\x00" * 32,
        "merkle_root": merkle,
        "timestamp": GENESIS_TIMESTAMP,
        "difficulty_bits": params["genesis_bits"],
        "engine_id": params["engine_id"],
        "nonce": 0,
    }


def params_engine_hash(params):
    if params["engine_id"] == ENGINE_ID_TRIVIAL:
        return trivial_hash
    memory = params["memory_bytes"]
    rounds = params["rounds"]
    return lambda preimage, nonce: scratchpad_hash(preimage, nonce, memory, rounds)


def genesis_block(params):
    """Mine block 0 from nonce 0; deterministic on every network."""
    coinbase = genesis_coinbase()
    merkle = merkle_root([tx_txid(coinbase)])
    header = genesis_header(params, merkle)
    target = compact_to_target(params["genesis_bits"])
    nonce, _ = mine(params_engine_hash(params), header_preimage(header), target, 0)
    header["nonce"] = nonce
    return {"header": header, "transactions": [coinbase]}


# ---------------------------------------------------------------------------
# Network parameters (pinned table, used only by ANCHOR cases)
# ---------------------------------------------------------------------------

NETWORKS = {
    "mainnet": {
        "name": "mainnet",
        "chain_id": 0x5A524F01,
        "engine_id": ENGINE_ID_SCRATCHPAD,
        "engine_name": SCRATCHPAD_ENGINE_NAME,
        "genesis_bits": MAINNET_POW_LIMIT_BITS,
        "allow_pow_retarget": True,
        "base58_pubkey_prefix": 0x00,
        "default_p2p_port": 8233,
        "default_rpc_port": 8232,
        "memory_bytes": 2 * 1024 * 1024,
        "rounds": 4096,
    },
    "devnet": {
        "name": "devnet",
        "chain_id": 0x5A524F02,
        "engine_id": ENGINE_ID_SCRATCHPAD,
        "engine_name": SCRATCHPAD_ENGINE_NAME,
        "genesis_bits": TRIVIAL_POW_LIMIT_BITS,
        "allow_pow_retarget": True,
        "base58_pubkey_prefix": 0x6F,
        "default_p2p_port": 18233,
        "default_rpc_port": 18232,
        "memory_bytes": 64 * 1024,
        "rounds": 1024,
    },
    "regtest": {
        "name": "regtest",
        "chain_id": 0x5A524F00,
        "engine_id": ENGINE_ID_TRIVIAL,
        "engine_name": TRIVIAL_ENGINE_NAME,
        "genesis_bits": TRIVIAL_POW_LIMIT_BITS,
        "allow_pow_retarget": False,
        "base58_pubkey_prefix": 0x6F,
        "default_p2p_port": 18444,
        "default_rpc_port": 18443,
    },
}

REGTEST_CHAIN = NETWORKS["regtest"]["chain_id"]


# ---------------------------------------------------------------------------
# Addresses (Base58Check over version || hash160)
# ---------------------------------------------------------------------------

ADDRESS_CHECKSUM_LEN = 4
ADDRESS_PAYLOAD_LEN = 21


class AddressError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


class CryptoError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def private_scalar(raw):
    """Reject 0 and anything at or above the curve order."""
    if len(raw) != 32:
        raise CryptoError("InvalidSecret")
    value = int.from_bytes(raw, "big")
    if value == 0 or value >= SECP_N:
        raise CryptoError("InvalidSecret")
    return value


def address_encode(version, payload):
    body = bytes([version]) + payload
    return b58encode(body + sha256d(body)[:ADDRESS_CHECKSUM_LEN])


def address_decode(text):
    try:
        raw = b58decode(text)
    except ValueError:
        raise AddressError("BadEncoding")
    if len(raw) < ADDRESS_PAYLOAD_LEN + ADDRESS_CHECKSUM_LEN:
        raise AddressError("BadLength")
    body, checksum = raw[:-ADDRESS_CHECKSUM_LEN], raw[-ADDRESS_CHECKSUM_LEN:]
    if sha256d(body)[:ADDRESS_CHECKSUM_LEN] != checksum:
        raise AddressError("BadChecksum")
    if len(body) != ADDRESS_PAYLOAD_LEN:
        raise AddressError("BadLength")
    return body[0], body[1:]


def address_decode_for_network(text, expected_version):
    version, payload = address_decode(text)
    if version != expected_version:
        raise AddressError("WrongNetwork")
    return version, payload


# ---------------------------------------------------------------------------
# UTXO set
# ---------------------------------------------------------------------------

class UtxoSet:
    """A sorted map from outpoint to entry, exactly like the Rust BTreeMap."""

    def __init__(self):
        self.entries = {}

    def __len__(self):
        return len(self.entries)

    def insert_output(self, txid, vout, value, script, height):
        self.entries[(txid, vout)] = {
            "value": value,
            "script": script,
            "height": height,
            "is_coinbase": False,
        }

    def insert_coinbase(self, txid, vout, value, script, height):
        self.entries[(txid, vout)] = {
            "value": value,
            "script": script,
            "height": height,
            "is_coinbase": True,
        }

    def apply_coinbase(self, tx, height):
        txid = tx_txid(tx)
        for index, output in enumerate(tx["outputs"]):
            self.insert_coinbase(txid, index, output["value"], output["script_pubkey"], height)
        return txid

    def balance_of_script(self, script):
        total = 0
        for entry in self.entries.values():
            if entry["script"] == script:
                total = (total + entry["value"]) & MASK64
        return total

    def state_root(self):
        buf = bytearray()
        for txid, vout in sorted(self.entries):
            entry = self.entries[(txid, vout)]
            buf += txid
            buf += le32(vout)
            buf += le64(entry["value"])
            buf += le64(len(entry["script"]))
            buf += entry["script"]
            buf += le64(entry["height"])
            buf.append(1 if entry["is_coinbase"] else 0)
        return sha256d(bytes(buf))

    def apply_transaction(self, tx, chain_id, height, spend_height):
        """Return (fee, None) or (None, error_kind); state is unchanged on error."""
        if not tx["inputs"]:
            return None, "NoInputs"

        seen = set()
        for item in tx["inputs"]:
            outpoint = (item["txid"], item["vout"])
            if outpoint in seen:
                return None, "DoubleSpend"
            seen.add(outpoint)

        input_total = 0
        for index, item in enumerate(tx["inputs"]):
            entry = self.entries.get((item["txid"], item["vout"]))
            if entry is None:
                return None, "MissingInput"
            spendable_at = entry["height"]
            if entry["is_coinbase"]:
                spendable_at = maturity_height(entry["height"])
            if spendable_at > spend_height:
                return None, "ImmatureCoinbase"
            checker = tx_sig_checker(tx, index, entry["script"], chain_id)
            try:
                script_verify(item["script_sig"], entry["script"], checker)
            except ScriptError:
                return None, "ScriptInvalid"
            input_total += entry["value"]
            if input_total > MASK64:
                return None, "InputOverflow"

        output_total = tx_output_value(tx)
        if output_total is None:
            return None, "OutputOverflow"
        if output_total > input_total:
            return None, "NegativeFee"
        fee = input_total - output_total

        for item in tx["inputs"]:
            del self.entries[(item["txid"], item["vout"])]
        txid = tx_txid(tx)
        for index, output in enumerate(tx["outputs"]):
            self.insert_output(txid, index, output["value"], output["script_pubkey"], height)
        return fee, None


# ---------------------------------------------------------------------------
# Fixtures published by the Rust emitter
# ---------------------------------------------------------------------------

def sample_tx():
    return {
        "version": 1,
        "inputs": [{
            "txid": b"\x11" * 32,
            "vout": 0,
            "script_sig": bytes([1, 2, 3]),
            "sequence": MASK32,
        }],
        "outputs": [{
            "value": 5_000_000_000,
            "script_pubkey": bytes([0x76, 0xA9, 0x14]),
        }],
        "lock_time": 0,
    }


def payment_tx():
    return {
        "version": 1,
        "inputs": [
            {
                "txid": b"\x22" * 32,
                "vout": 1,
                "script_sig": b"",
                "sequence": 0xFFFFFFFE,
            },
            {
                "txid": b"\x33" * 32,
                "vout": 7,
                "script_sig": b"",
                "sequence": 0,
            },
        ],
        "outputs": [
            {"value": 1, "script_pubkey": b""},
            {"value": 2_100_000_000_000_000, "script_pubkey": bytes([0x6A])},
        ],
        "lock_time": 500_000,
    }


def dummy_tx():
    """The checker-bound throwaway transaction used by the script reject cases."""
    return {
        "version": 1,
        "inputs": [{
            "txid": b"\x00" * 32,
            "vout": MASK32,
            "script_sig": b"",
            "sequence": MASK32,
        }],
        "outputs": [],
        "lock_time": 0,
    }


def sign_input(tx, index, secret, script_code, chain_id=REGTEST_CHAIN,
               sighash_type=SIGHASH_ALL):
    """Sign one input against `script_code` and write its P2PKH scriptSig."""
    digest = signature_hash(tx, index, script_code, chain_id, sighash_type)
    if digest is None:
        raise Unsupported("input index out of range")
    with_type = ecdsa_sign(secret, digest) + bytes([sighash_type])
    tx["inputs"][index]["script_sig"] = p2pkh_script_sig(with_type, compressed_pubkey(secret))
    return with_type


# ---------------------------------------------------------------------------
# Independent verification
# ---------------------------------------------------------------------------
#
# Every expected value is recomputed from the case's own inputs with the
# primitives above. A case that cannot be recomputed raises `Unsupported` rather
# than passing, and nothing is ever compared against itself.

ANCHOR_CASES = {
    "chain.anchors.boot_invariants",
    "chain.anchors.network_params",
    "difficulty.params",
    "pow.engine_ids",
    "reward.constants",
}

# Documentation-only fields: they carry no consensus meaning and cannot be
# derived from an input, so they are neither verified nor required.
DESCRIPTIVE_FIELDS = {"label"}


def _assert_equal(where, actual, expected):
    """Deep comparison that reports the first disagreement with its path."""
    if isinstance(expected, bool) or isinstance(actual, bool):
        if actual is not expected:
            raise VectorMismatch(f"{where}: expected {expected!r}, recomputed {actual!r}")
        return
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise VectorMismatch(
                f"{where}: expected an object, recomputed {type(actual).__name__}"
            )
        missing = sorted(set(expected) - set(actual) - DESCRIPTIVE_FIELDS)
        extra = sorted(set(actual) - set(expected) - DESCRIPTIVE_FIELDS)
        if missing or extra:
            raise VectorMismatch(f"{where}: missing={missing} unexpected={extra}")
        for key in sorted(expected):
            if key in DESCRIPTIVE_FIELDS:
                continue
            _assert_equal(f"{where}.{key}", actual[key], expected[key])
        return
    if isinstance(expected, list):
        if not isinstance(actual, list):
            raise VectorMismatch(
                f"{where}: expected a list, recomputed {type(actual).__name__}"
            )
        if len(actual) != len(expected):
            raise VectorMismatch(
                f"{where}: expected {len(expected)} items, recomputed {len(actual)}"
            )
        for index, (left, right) in enumerate(zip(actual, expected)):
            _assert_equal(f"{where}[{index}]", left, right)
        return
    if actual != expected:
        raise VectorMismatch(f"{where}: expected {expected!r}, recomputed {actual!r}")


def _compare(case, recomputed):
    _assert_equal(case["id"], recomputed, case["expected"])


def _pkh(scalar):
    """The P2PKH hash the published fixtures use for a scalar."""
    return hash160(compressed_pubkey(scalar))


def _p2pkh(scalar):
    return p2pkh_script_pubkey(_pkh(scalar))


def _rejecting_checker(_signature, _pubkey):
    """A checker that never accepts, for scripts that never reach OP_CHECKSIG."""
    return False


def _verify_hash(case):
    name = case["id"].rsplit(".", 1)[1]
    data = case["input"]
    if name in ("abc", "empty"):
        return {"sha256_hex": sha256(data["data_utf8"].encode("utf-8")).hex()}
    if name == "zerocoin":
        return {"hash256": hash256_json(sha256d(data["data_utf8"].encode("utf-8")))}
    if name == "pubkey_scalar_1":
        return {"hash160_hex": hash160(unhex(data["pubkey_sec1_hex"])).hex()}
    if name == "display_reversal":
        return {"display_hex": unhex(data["internal_hex"])[::-1].hex()}
    raise Unsupported(case["id"])


def _verify_varint(case):
    raw = varint_bytes(case["input"]["value"])
    return {"bytes_hex": raw.hex(), "length": len(raw)}


def _verify_transaction(case):
    name = case["id"].rsplit(".", 1)[1]
    data = case["input"]
    if name == "coinbase_147":
        height = data["height"]
        tx = coinbase_transaction(height, _pkh(data["payout_scalar"]), block_subsidy(height))
        return {
            "committed_height": coinbase_height(tx),
            "is_coinbase": tx_is_coinbase(tx),
            "output_value": tx_output_value(tx),
            "script_pubkey_hex": tx["outputs"][0]["script_pubkey"].hex(),
            "script_sig_hex": tx["inputs"][0]["script_sig"].hex(),
            "serialized_hex": tx_serialize(tx).hex(),
            "txid": hash256_json(tx_txid(tx)),
        }
    if name == "decode_nonminimal_varint":
        try:
            tx_deserialize(unhex(data["bytes_hex"]))
        except DecodeError as error:
            return {"kind": error.kind}
        raise VectorMismatch(f"{case['id']}: a non-minimal varint was accepted")

    tx = tx_from_json(data)
    raw = tx_serialize(tx)
    out = {"serialized_hex": raw.hex(), "txid": hash256_json(tx_txid(tx))}
    if "serialized_len" in case["expected"]:
        out["serialized_len"] = len(raw)
    if "roundtrip" in case["expected"]:
        out["roundtrip"] = tx_serialize(tx_deserialize(raw)) == raw
    if "output_value" in case["expected"]:
        out["output_value"] = tx_output_value(tx)
    if "is_coinbase" in case["expected"]:
        out["is_coinbase"] = tx_is_coinbase(tx)
    return out


def _verify_script(case):
    name = case["id"].rsplit(".", 1)[1]
    data = case["input"]
    if case["id"].endswith("push_data.lengths"):
        out = {}
        for length in data["lengths"]:
            buf = bytearray()
            push_data(b"\xab" * length, buf)
            out[f"len_{length}"] = bytes(buf).hex()
        return out
    if name == "p2pkh_script_pubkey":
        script = p2pkh_script_pubkey(unhex(data["pubkey_hash_hex"]))
        return {"length": len(script), "script_hex": script.hex()}
    if name == "p2pkh_script_sig":
        script = p2pkh_script_sig(
            unhex(data["signature_with_sighash_hex"]), unhex(data["pubkey_sec1_hex"])
        )
        return {"length": len(script), "script_hex": script.hex()}
    if name == "p2pkh_spend_accepted":
        if data["sighash_type"] != SIGHASH_ALL:
            raise Unsupported(f"{case['id']}: only SIGHASH_ALL is modelled")
        tx = tx_deserialize(unhex(data["tx_hex"]))
        checker = tx_sig_checker(
            tx, data["input_index"], unhex(data["script_code_hex"]), data["chain_id"]
        )
        try:
            script_verify(
                unhex(data["script_sig_hex"]), unhex(data["script_pubkey_hex"]), checker
            )
        except ScriptError as error:
            return {"accepted": False, "error_kind": error.kind, "txid": tx_txid(tx).hex()}
        return {"accepted": True, "error_kind": None, "txid": tx_txid(tx).hex()}

    try:
        script_verify(
            unhex(data["script_sig_hex"]),
            unhex(data["script_pubkey_hex"]),
            _rejecting_checker,
        )
    except ScriptError as error:
        return {"accepted": False, "error_kind": error.kind}
    return {"accepted": True, "error_kind": None}


def _verify_sighash(case, corpus):
    name = case["id"].rsplit(".", 1)[1]
    data = case["input"]
    if name == "out_of_range_index":
        tx = payment_tx()
        if len(tx["inputs"]) != data["input_count"]:
            raise VectorMismatch(f"{case['id']}: fixture input count changed")
        digest = signature_hash(tx, data["input_index"], _p2pkh(1), REGTEST_CHAIN)
        return {"digest": None if digest is None else hash256_json(digest)}
    if name == "digest_stability":
        siblings = (
            "ledger.sighash.regtest_index_0",
            "ledger.sighash.regtest_index_1",
            "ledger.sighash.mainnet_chain_binding",
            "ledger.sighash.type_02_is_folded_in",
        )
        digests = {}
        for sibling_id in siblings:
            sibling = corpus.get(sibling_id)
            if sibling is None:
                raise VectorMismatch(f"{case['id']}: sibling {sibling_id} is missing")
            digests[sibling_id] = parse_hash256(sibling["expected"]["digest"])
        return {
            "index_0_equals_index_1": digests[siblings[0]] == digests[siblings[1]],
            "regtest_equals_mainnet": digests[siblings[0]] == digests[siblings[2]],
            "type_all_equals_type_02": digests[siblings[0]] == digests[siblings[3]],
        }
    if name == "signature_der":
        digest = parse_hash256(data["digest"])
        der = ecdsa_sign(data["scalar"], digest)
        return {
            "der_hex": der.hex(),
            "der_len": len(der),
            "verified": ecdsa_verify(compressed_pubkey(data["scalar"]), digest, der),
            "verified_under_other_key": ecdsa_verify(
                compressed_pubkey(data["scalar"] + 1), digest, der
            ),
        }

    tx = tx_deserialize(unhex(data["tx_hex"]))
    if tx_txid(tx).hex() != data["txid"]:
        raise VectorMismatch(f"{case['id']}: tx_hex does not hash to the published txid")
    preimage = signature_preimage(
        tx,
        data["input_index"],
        unhex(data["script_code_hex"]),
        data["chain_id"],
        data["sighash_type"],
    )
    if preimage is None:
        raise VectorMismatch(f"{case['id']}: input index {data['input_index']} is out of range")
    return {"digest": hash256_json(sha256d(preimage)), "preimage_hex": preimage.hex()}


def _header_from_json(data):
    return {
        "version": data["version"],
        "chain": data["chain"],
        "height": data["height"],
        "previous_hash": unhex(data["previous_hash_hex"]),
        "merkle_root": unhex(data["merkle_root_hex"]),
        "timestamp": data["timestamp"],
        "difficulty_bits": data["difficulty_bits"],
        "engine_id": data["engine_id"],
    }


def _verify_chain_header(case):
    name = case["id"].rsplit(".", 1)[1]
    data = case["input"]
    if name.startswith("preimage_regtest"):
        preimage = header_preimage(_header_from_json(data))
        out = {
            "pow_hash": hash256_json(trivial_hash(preimage, data["nonce"])),
            "preimage_hex": preimage.hex(),
        }
        if "preimage_len" in case["expected"]:
            out["preimage_len"] = len(preimage)
        return out
    if name == "mainnet_genesis_preimage_digest":
        preimage = header_preimage(_header_from_json(data))
        digest = sha256d(preimage)
        return {
            "pinned_anchor": hash256_json(digest),
            "preimage_digest": hash256_json(digest),
            "preimage_hex": preimage.hex(),
        }
    raise Unsupported(case["id"])


def _verify_merkle(case):
    data = case["input"]
    leaves = [unhex(text) for text in data.get("leaves_hex", [])]
    if "leaves" in data and data["leaves"] != len(leaves):
        raise VectorMismatch(f"{case['id']}: the published leaf count is wrong")
    return {"root": hash256_json(merkle_root(leaves))}


def _verify_difficulty(case):
    case_id = case["id"]
    data = case["input"]
    name = case_id.rsplit(".", 1)[1]
    if case_id.startswith("difficulty.compact."):
        target = compact_to_target(data["bits"])
        return {
            "is_zero": target == 0,
            "roundtrip_bits": target_to_compact(target),
            "target_be_hex": target_be_hex(target),
        }
    if name == "validate_bits":
        params = dict(DIFFICULTY_PARAMS)
        params["pow_limit_bits"] = data["pow_limit_bits"]
        out = {}
        for key, bits in data["bits"].items():
            kind = validate_bits(bits, params)
            out[key] = {"bits": bits, "error_kind": kind, "ok": kind is None}
        return out
    if name == "hash_meets_target":
        target = compact_to_target(data["bits"])
        return {
            "all_ones_hash": hash_meets_target(b"\xff" * 32, target),
            "equal_to_target": hash_meets_target(target.to_bytes(32, "big"), target),
            "zero_hash": hash_meets_target(b"\x00" * 32, target),
        }
    if name == "required_work":
        return {
            key: target_be_hex(required_work(compact_to_target(bits)))
            for key, bits in data["bits"].items()
        }
    if name == "clamps":
        out = {}
        for key, row in case["expected"].items():
            window = row["actual_window_seconds"]
            next_bits = next_difficulty(data["prev_bits"], window, DIFFICULTY_PARAMS)
            out[key] = {
                "actual_window_seconds": window,
                "next_bits": next_bits,
                "next_target_be_hex": target_be_hex(compact_to_target(next_bits)),
                "prev_bits": data["prev_bits"],
            }
        return out
    if name == "at_floor":
        return {
            "next_bits": next_difficulty(
                data["prev_bits"], data["actual_window_seconds"], DIFFICULTY_PARAMS
            )
        }
    raise Unsupported(case_id)


def _verify_pow(case):
    case_id = case["id"]
    data = case["input"]
    if case_id.startswith("pow.trivial."):
        preimage = unhex(data["preimage_hex"])
        if case_id.endswith("mine_from_zero"):
            nonce, _ = mine(trivial_hash, preimage, compact_to_target(data["target_bits"]), 0)
            return {"nonce": nonce}
        return {"hash": hash256_json(trivial_hash(preimage, data["nonce"]))}
    if case_id.startswith("pow.scratchpad."):
        if data["engine_id"] != ENGINE_ID_SCRATCHPAD:
            raise VectorMismatch(f"{case_id}: a scratchpad row must name engine 1")
        digest = scratchpad_hash(
            unhex(data["preimage_hex"]), data["nonce"], data["memory_bytes"], data["rounds"]
        )
        return {"hash": hash256_json(digest)}
    raise Unsupported(case_id)


def _verify_reward_subsidy(case):
    case_id = case["id"]
    data = case["input"]
    if case_id.startswith("reward.subsidy.table"):
        return {
            "rows": [{"height": h, "subsidy_fah": block_subsidy(h)} for h in data["heights"]]
        }
    if case_id.startswith("reward.maturity.table"):
        return {
            "rows": [
                {"height": h, "maturity_height": maturity_height(h)} for h in data["heights"]
            ]
        }
    if case_id.endswith("block_reward"):
        out = {}
        for row in data["rows"]:
            out[row["key"]] = block_reward(row["height"], row["fees"])
        return out
    if case_id.startswith("reward.split_reward."):
        out = {}
        for reward, weights in data["cases"]:
            matches = [
                key
                for key, row in case["expected"].items()
                if row["reward"] == reward and row["weights"] == weights
            ]
            if len(matches) != 1:
                # Every published input must have exactly one expected row, so an
                # unmatched input is corpus drift, not a harness limitation.
                raise VectorMismatch(
                    f"{case_id}: {len(matches)} expected rows match the input {reward}/{weights}"
                )
            pairs = split_reward(
                reward,
                [(bytes([index + 1]) * 20, weight) for index, weight in enumerate(weights)],
            )
            out[matches[0]] = {
                "payouts": [
                    {"hash160_hex": pubkey_hash.hex(), "value": value}
                    for pubkey_hash, value in pairs
                ],
                "reward": reward,
                "total": sum(value for _, value in pairs),
                "weights": list(weights),
            }
        return out
    raise Unsupported(case_id)


def _coinbase_verdict(height, claimed, fees, issued):
    tx = coinbase_transaction(height, _pkh(1), claimed)
    claimed_value, kind = validate_coinbase(tx, height, fees, issued)
    return {"claimed": claimed_value, "error_kind": kind, "ok": kind is None}


def _verify_reward_coinbase(case):
    case_id = case["id"]
    data = case["input"]
    if case_id.endswith("height_commitment"):
        rows = []
        for row in data["rows"]:
            tx = coinbase_transaction(
                row["height"], _pkh(data["payout_scalar"]), row["reward_fah"]
            )
            rows.append({
                "committed_height": coinbase_height(tx),
                "height": row["height"],
                "script_sig_hex": tx["inputs"][0]["script_sig"].hex(),
                "txid_internal_hex": tx_txid(tx).hex(),
            })
        return {"rows": rows}
    if case_id.endswith("valid_at_147"):
        return _coinbase_verdict(
            data["height"], data["claimed"], data["fees"], data["subsidy_issued"]
        )
    if case_id.endswith("accepts_fees_and_underclaim"):
        out = {}
        for row in data["rows"]:
            out[row["key"]] = _coinbase_verdict(
                row["height"], row["claimed"], row["fees"], data["subsidy_issued"]
            )
        return out
    if case_id.endswith("reject_not_coinbase"):
        claimed, kind = validate_coinbase(tx_deserialize(unhex(data["tx_hex"])), 1, 0, 0)
        return {"claimed": claimed, "error_kind": kind, "ok": kind is None}
    if case_id.endswith("reject_wrong_height"):
        tx = coinbase_transaction(data["committed_height"], _pkh(1), data["claimed"])
        claimed, kind = validate_coinbase(tx, data["block_height"], 0, 0)
        return {"claimed": claimed, "error_kind": kind, "ok": kind is None}
    if case_id.endswith("pool_invariance"):
        height = data["height"]
        subsidy = block_subsidy(height)
        shares = [
            (bytes([index + 1]) * 20, weight) for index, weight in enumerate(data["weights"])
        ]
        pool = pool_coinbase_transaction(height, subsidy, split_reward(subsidy, shares))
        solo = coinbase_transaction(height, _pkh(1), subsidy)
        return {"pool_total": tx_output_value(pool), "solo_total": tx_output_value(solo)}
    return _coinbase_verdict(
        data["height"], data["claimed"], data.get("fees", 0), data.get("subsidy_issued", 0)
    )


def _insert_entry(target, row):
    if row["is_coinbase"]:
        target.insert_coinbase(
            unhex(row["txid_hex"]),
            row["vout"],
            row["value"],
            unhex(row["script_hex"]),
            row["height"],
        )
    else:
        target.insert_output(
            unhex(row["txid_hex"]),
            row["vout"],
            row["value"],
            unhex(row["script_hex"]),
            row["height"],
        )


def _funded_spend(mined_at, payout_scalar, receiver_scalar, fee):
    """A coinbase at `mined_at` and a signed P2PKH spend of its first output."""
    subsidy = block_subsidy(mined_at)
    funded = UtxoSet()
    coinbase_txid = funded.apply_coinbase(
        coinbase_transaction(mined_at, _pkh(payout_scalar), subsidy), mined_at
    )
    spend = {
        "version": 1,
        "inputs": [{
            "txid": coinbase_txid,
            "vout": 0,
            "script_sig": b"",
            "sequence": MASK32,
        }],
        "outputs": [{
            "value": subsidy - fee,
            "script_pubkey": _p2pkh(receiver_scalar),
        }],
        "lock_time": 0,
    }
    sign_input(spend, 0, payout_scalar, _p2pkh(payout_scalar))
    return funded, spend


def _verify_state_root(case):
    name = case["id"].rsplit(".", 1)[1]
    data = case["input"]
    if name == "empty":
        root = UtxoSet().state_root()
        return {"pinned_anchor": hash256_json(root), "root": hash256_json(root)}
    if name == "layout_probe":
        probe = UtxoSet()
        _insert_entry(probe, data["entry_0"])
        _insert_entry(probe, data["entry_1"])
        root = probe.state_root()
        return {"pinned_anchor": hash256_json(root), "root": hash256_json(root)}
    if name == "order_independence":
        forward = UtxoSet()
        backward = UtxoSet()
        for row in data["entries"]:
            _insert_entry(forward, row)
        for row in reversed(data["entries"]):
            _insert_entry(backward, row)
        ascending = forward.state_root()
        descending = backward.state_root()
        return {
            "ascending": hash256_json(ascending),
            "descending": hash256_json(descending),
            "equal": ascending == descending,
        }
    if name == "funded_coinbase":
        funded = UtxoSet()
        txid = funded.apply_coinbase(
            coinbase_transaction(
                data["height"], _pkh(data["payout_scalar"]), data["subsidy_fah"]
            ),
            data["height"],
        )
        return {
            "balance_of_payout_script": funded.balance_of_script(_p2pkh(data["payout_scalar"])),
            "entries": len(funded),
            "root": hash256_json(funded.state_root()),
            "txid": hash256_json(txid),
        }
    if name == "after_signed_spend":
        payout = _p2pkh(data["payout_scalar"])
        receiver = _p2pkh(data["receiver_scalar"])
        subsidy = block_subsidy(data["funded_height"])
        funded = UtxoSet()
        coinbase_txid = funded.apply_coinbase(
            coinbase_transaction(data["funded_height"], _pkh(data["payout_scalar"]), subsidy),
            data["funded_height"],
        )
        spend = {
            "version": 1,
            "inputs": [{
                "txid": coinbase_txid,
                "vout": 0,
                "script_sig": b"",
                "sequence": MASK32,
            }],
            "outputs": [{
                "value": subsidy - data["fee_fah"],
                "script_pubkey": receiver,
            }],
            "lock_time": 0,
        }
        sign_input(spend, 0, data["payout_scalar"], payout)
        fee, kind = funded.apply_transaction(
            spend, REGTEST_CHAIN, data["spend_height"], data["spend_height"]
        )
        if kind is not None:
            raise VectorMismatch(f"{case['id']}: the spend was rejected with {kind}")
        return {
            "entries": len(funded),
            "fee": fee,
            "payout_balance": funded.balance_of_script(payout),
            "receiver_balance": funded.balance_of_script(receiver),
            "root": hash256_json(funded.state_root()),
            "txid": hash256_json(tx_txid(spend)),
        }
    if name == "immature_coinbase":
        if maturity_height(data["mined_at"]) != data["matures_at"]:
            raise VectorMismatch(f"{case['id']}: the published maturity is wrong")
        funded, spend = _funded_spend(data["mined_at"], 1, 2, 1_000)
        # Only `spend_height` is consulted before the error, never the block height.
        _, kind = funded.apply_transaction(
            spend, REGTEST_CHAIN, data["matures_at"], data["spend_height"]
        )
        return {"kind": kind}
    if name == "double_spend":
        funded, spend = _funded_spend(1, 1, 2, 1_000)
        coinbase_txid = spend["inputs"][0]["txid"]
        double = {
            "version": 1,
            "inputs": [{
                "txid": coinbase_txid,
                "vout": 0,
                "script_sig": b"",
                "sequence": MASK32,
            } for _ in range(data["occurrences"])],
            "outputs": spend["outputs"],
            "lock_time": 0,
        }
        for index in range(len(double["inputs"])):
            sign_input(double, index, 1, _p2pkh(1))
        _, kind = funded.apply_transaction(double, REGTEST_CHAIN, 101, 101)
        return {"kind": kind}
    if name == "missing_input":
        funded, spend = _funded_spend(1, 1, 2, 1_000)
        fee, kind = funded.apply_transaction(
            spend, REGTEST_CHAIN, data["spent_at"], data["spent_at"]
        )
        if kind is not None:
            raise VectorMismatch(f"{case['id']}: the first spend was rejected with {kind}")
        _, kind = funded.apply_transaction(
            spend, REGTEST_CHAIN, data["retried_at"], data["retried_at"]
        )
        return {"kind": kind}
    if name == "negative_fee":
        if block_subsidy(1) != data["inputs"]:
            raise VectorMismatch(f"{case['id']}: the fixture value does not match the subsidy")
        funded, spend = _funded_spend(1, 1, 2, 0)
        spend["outputs"][0]["value"] = data["outputs"]
        sign_input(spend, 0, 1, _p2pkh(1))
        _, kind = funded.apply_transaction(spend, REGTEST_CHAIN, 101, 101)
        return {"kind": kind}
    if name == "no_inputs":
        empty = {"version": 1, "inputs": [], "outputs": [], "lock_time": 0}
        _, kind = UtxoSet().apply_transaction(empty, REGTEST_CHAIN, 101, 101)
        return {"kind": kind}
    if name == "script_invalid":
        funded, spend = _funded_spend(1, data["payout_script_from"], 2, 1_000)
        sign_input(spend, 0, data["signer"], _p2pkh(data["payout_script_from"]))
        _, kind = funded.apply_transaction(spend, REGTEST_CHAIN, 101, 101)
        return {"kind": kind}
    if name == "input_overflow":
        script = _p2pkh(1)
        txid = b"\x77" * 32
        huge = UtxoSet()
        for index, value in enumerate(data["entry_values"]):
            huge.insert_output(txid, index, value, script, 1)
        tx = {
            "version": 1,
            "inputs": [{
                "txid": txid,
                "vout": index,
                "script_sig": b"",
                "sequence": MASK32,
            } for index in range(len(data["entry_values"]))],
            "outputs": [{"value": 1, "script_pubkey": _p2pkh(2)}],
            "lock_time": 0,
        }
        for index in range(len(tx["inputs"])):
            sign_input(tx, index, 1, script)
        _, kind = huge.apply_transaction(tx, REGTEST_CHAIN, 101, 101)
        return {"kind": kind}
    if name == "output_overflow":
        funded, spend = _funded_spend(1, 1, 2, 0)
        spend["outputs"] = [
            {"value": value, "script_pubkey": b""} for value in data["output_values"]
        ]
        sign_input(spend, 0, 1, _p2pkh(1))
        _, kind = funded.apply_transaction(spend, REGTEST_CHAIN, 101, 101)
        return {"kind": kind}
    raise Unsupported(case["id"])


def _block_digest(params, block):
    header = block["header"]
    return params_engine_hash(params)(header_preimage(header), header["nonce"])


def _layout_probe_root(corpus):
    case = corpus.get("ledger.state_root.layout_probe")
    if case is None:
        raise VectorMismatch("the layout-probe case is missing from the corpus")
    probe = UtxoSet()
    _insert_entry(probe, case["input"]["entry_0"])
    _insert_entry(probe, case["input"]["entry_1"])
    return probe.state_root()


def _anchor_constants(corpus):
    coinbase_txid = tx_txid(genesis_coinbase())
    merkle = merkle_root([coinbase_txid])
    return {
        "empty_state_root": UtxoSet().state_root(),
        "genesis_coinbase_txid": coinbase_txid,
        "genesis_hash_devnet": _block_digest(
            NETWORKS["devnet"], genesis_block(NETWORKS["devnet"])
        ),
        "genesis_hash_regtest": _block_digest(
            NETWORKS["regtest"], genesis_block(NETWORKS["regtest"])
        ),
        "genesis_merkle_root": merkle,
        "genesis_preimage_digest_mainnet": sha256d(
            header_preimage(genesis_header(NETWORKS["mainnet"], merkle))
        ),
        "state_root_layout_probe": _layout_probe_root(corpus),
    }


def _verify_anchor(case, corpus):
    case_id = case["id"]
    if case_id == "difficulty.params":
        return {
            "max_adjustment_factor": DIFFICULTY_PARAMS["max_adjustment_factor"],
            "pow_limit_bits": DIFFICULTY_PARAMS["pow_limit_bits"],
            "retarget_interval": DIFFICULTY_PARAMS["retarget_interval"],
            "target_spacing_seconds": DIFFICULTY_PARAMS["target_spacing_seconds"],
            "target_window_seconds": target_window_seconds(DIFFICULTY_PARAMS),
        }
    if case_id == "pow.engine_ids":
        return {
            "scratchpad_id": ENGINE_ID_SCRATCHPAD,
            "scratchpad_name": SCRATCHPAD_ENGINE_NAME,
            "trivial_id": ENGINE_ID_TRIVIAL,
            "trivial_name": TRIVIAL_ENGINE_NAME,
        }
    if case_id == "reward.constants":
        return {
            "coinbase_maturity": COINBASE_MATURITY,
            "fah_per_zro": FAH_PER_ZRO,
            "halving_interval": HALVING_INTERVAL,
            "initial_subsidy_fah": INITIAL_SUBSIDY,
            "max_halvings": MAX_HALVINGS,
            "max_supply_fah": MAX_SUPPLY,
            "total_supply_ceiling_fah": total_supply_ceiling(),
        }
    if case_id == "chain.anchors.network_params":
        out = {"genesis_timestamp": GENESIS_TIMESTAMP}
        for name in case["input"]["networks"]:
            params = NETWORKS[name]
            out[name] = {
                "allow_pow_retarget": params["allow_pow_retarget"],
                "base58_pubkey_prefix": params["base58_pubkey_prefix"],
                "chain_id": params["chain_id"],
                "default_p2p_port": params["default_p2p_port"],
                "default_rpc_port": params["default_rpc_port"],
                "engine_id": params["engine_id"],
                "engine_name": params["engine_name"],
                "genesis_bits": params["genesis_bits"],
                "name": params["name"],
            }
        return out
    if case_id == "chain.anchors.pinned_constants":
        return {key: hash256_json(value) for key, value in _anchor_constants(corpus).items()}
    if case_id == "chain.anchors.boot_invariants":
        pinned = corpus.get("chain.anchors.pinned_constants")
        if pinned is None:
            raise VectorMismatch(f"{case_id}: the pinned-constants case is missing")
        for key, digest in _anchor_constants(corpus).items():
            _assert_equal(
                f"{case_id}.{key}", hash256_json(digest), pinned["expected"].get(key)
            )
        return {"ok": True}
    raise Unsupported(case_id)


def _verify_anchor_genesis(case):
    data = case["input"]
    params = NETWORKS[data["name"]]
    for key, value in data.items():
        if key == "name":
            continue
        if params.get(key) != value:
            raise VectorMismatch(f"{case['id']}: the network table disagrees on {key}")
    block = genesis_block(params)
    digest = _block_digest(params, block)
    out = {
        "hash": hash256_json(digest),
        "nonce": block["header"]["nonce"],
        "pinned_anchor": hash256_json(digest),
    }
    if "preimage_hex" in case["expected"]:
        out["preimage_hex"] = header_preimage(block["header"]).hex()
        out["transactions"] = len(block["transactions"])
    return out


def _verify_anchor_genesis_coinbase(case):
    if case["input"]["message_utf8"].encode("utf-8") != GENESIS_MESSAGE:
        raise VectorMismatch(f"{case['id']}: the published message differs from the tag")
    tx = genesis_coinbase()
    txid = tx_txid(tx)
    return {
        "committed_height": coinbase_height(tx),
        "is_coinbase": tx_is_coinbase(tx),
        "merkle_root": hash256_json(merkle_root([txid])),
        "output_value": tx_output_value(tx),
        "outputs": len(tx["outputs"]),
        "script_sig_hex": tx["inputs"][0]["script_sig"].hex(),
        "serialized_hex": tx_serialize(tx).hex(),
        "txid": hash256_json(txid),
    }


def _verify_address(case):
    name = case["id"].rsplit(".", 1)[1]
    data = case["input"]
    if name in ("published_scalar_1", "published_scalar_2", "repo_key_09"):
        secret = private_scalar(unhex(data["scalar_hex"]))
        pubkey = compressed_pubkey(secret)
        pubkey_hash = hash160(pubkey)
        mainnet = address_encode(0x00, pubkey_hash)
        regtest = address_encode(0x6F, pubkey_hash)
        _, decoded_mainnet = address_decode_for_network(mainnet, 0x00)
        _, decoded_regtest = address_decode_for_network(regtest, 0x6F)
        return {
            "address_mainnet": mainnet,
            "address_regtest": regtest,
            "hash160_hex": pubkey_hash.hex(),
            "pubkey_sec1_hex": pubkey.hex(),
            "roundtrip": decoded_mainnet == pubkey_hash and decoded_regtest == pubkey_hash,
        }
    if name == "reject_wrong_network":
        try:
            address_decode_for_network(data["address"], data["expected_version"])
        except AddressError as error:
            return {"kind": error.kind}
        return {"kind": None}
    if name == "reject_typo":
        if data["corrupted"] == data["address"]:
            raise VectorMismatch(f"{case['id']}: the corrupted address is unchanged")
        try:
            address_decode(data["corrupted"])
        except AddressError as error:
            return {"kind": error.kind}
        return {"kind": None}
    if name == "reject_zero_scalar":
        try:
            private_scalar(unhex(data["scalar_hex"]))
        except CryptoError as error:
            return {"kind": error.kind}
        return {"kind": None}
    raise Unsupported(case["id"])


def verify_case(case, corpus=None):
    """Recompute one case from its inputs; return PASS or ANCHOR, or raise."""
    corpus = corpus or {}
    case_id = case["id"]
    if case_id.startswith("hash."):
        recomputed = _verify_hash(case)
    elif case_id.startswith("encoding.varint."):
        recomputed = _verify_varint(case)
    elif case_id.startswith("encoding.transaction."):
        recomputed = _verify_transaction(case)
    elif case_id.startswith("ledger.script."):
        recomputed = _verify_script(case)
    elif case_id.startswith("ledger.sighash."):
        recomputed = _verify_sighash(case, corpus)
    elif case_id.startswith("ledger.state_root."):
        recomputed = _verify_state_root(case)
    elif case_id.startswith("chain.header."):
        recomputed = _verify_chain_header(case)
    elif case_id.startswith("chain.merkle."):
        recomputed = _verify_merkle(case)
    elif case_id.startswith("chain.anchors.genesis_coinbase"):
        recomputed = _verify_anchor_genesis_coinbase(case)
    elif case_id.startswith("chain.anchors.regtest_genesis"):
        recomputed = _verify_anchor_genesis(case)
    elif case_id.startswith("chain.anchors.devnet_genesis"):
        recomputed = _verify_anchor_genesis(case)
    elif case_id.startswith("chain.anchors."):
        recomputed = _verify_anchor(case, corpus)
    elif case_id.startswith("difficulty."):
        recomputed = _verify_anchor(case, corpus) if case_id in ANCHOR_CASES else _verify_difficulty(case)
    elif case_id.startswith("pow."):
        recomputed = _verify_anchor(case, corpus) if case_id in ANCHOR_CASES else _verify_pow(case)
    elif case_id.startswith("reward."):
        if case_id in ANCHOR_CASES:
            recomputed = _verify_anchor(case, corpus)
        elif case_id.startswith("reward.coinbase."):
            recomputed = _verify_reward_coinbase(case)
        else:
            recomputed = _verify_reward_subsidy(case)
    elif case_id.startswith("crypto.address."):
        recomputed = _verify_address(case)
    else:
        raise Unsupported(f"{case_id}: no verifier is registered")
    _compare(case, recomputed)
    return "ANCHOR" if case_id in ANCHOR_CASES else "PASS"
