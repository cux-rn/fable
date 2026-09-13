"""
Fable v0.3 — reference implementation (NOT for production use).

Implements:
  - Fable-P   : 512-bit ARX permutation (16 x 32-bit words)
  - Fable-AEAD: keyed duplex authenticated encryption
  - Fable-Stream: STREAM chunked construction for large files
  - Fable-Hash / XOF: sponge hash

All integers are little-endian 32-bit words.
"""

import struct
import hmac as _hmac

MASK = 0xFFFFFFFF

# ---- constants -----------------------------------------------------------

RC = [
    0xb17217f7, 0x193ea7aa, 0x9c041f7e, 0xf2272ae3,
    0x65dc76ef, 0x90a08566, 0xd54d783f, 0xf1c6c0c0,
    0x22afbfba, 0x5e071979, 0x6f19c912, 0x9c651dc7,
]

ROT = (16, 12, 8, 7)          # provisional, see spec §2.2
R_HEAVY = 12

# Parameter sets: name -> (light rounds, IV1)
PARAMS = {
    'fable':   (8, 0x012020C8),   # default: ver 1 | key 32B | rate 32B | rounds 12/8
    'fable-f': (6, 0x012020C6),   # fast:    rounds 12/6 (ChaCha12-level margin)
}
DEFAULT_SET = 'fable'

IV0_AEAD = 0x4661626C         # "Fabl"
IV1_HASH = 0x01202000

RATE_WORDS = 8                # 256-bit rate
KEY_BYTES = 32
NONCE_BYTES = 24
TAG_BYTES = 32

# ---- permutation ---------------------------------------------------------

def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def _q(s, a, b, c, d, rot=ROT):
    r0, r1, r2, r3 = rot
    s[a] = (s[a] + s[b]) & MASK; s[d] = _rotl(s[d] ^ s[a], r0)
    s[c] = (s[c] + s[d]) & MASK; s[b] = _rotl(s[b] ^ s[c], r1)
    s[a] = (s[a] + s[b]) & MASK; s[d] = _rotl(s[d] ^ s[a], r2)
    s[c] = (s[c] + s[d]) & MASK; s[b] = _rotl(s[b] ^ s[c], r3)


def fable_round(s, i, rot=ROT):
    s[0] ^= RC[i]
    s[5] ^= _rotl(RC[i], 16)
    _q(s, 0, 4, 8, 12, rot); _q(s, 1, 5, 9, 13, rot)
    _q(s, 2, 6, 10, 14, rot); _q(s, 3, 7, 11, 15, rot)
    _q(s, 0, 5, 10, 15, rot); _q(s, 1, 6, 11, 12, rot)
    _q(s, 2, 7, 8, 13, rot); _q(s, 3, 4, 9, 14, rot)


def permute(s, rounds, rot=ROT):
    """In-place Fable-P on a list of 16 words. rounds in {6, 12} normally."""
    assert len(s) == 16
    start = R_HEAVY - rounds          # light rounds use the last RC entries
    for i in range(start, R_HEAVY):
        fable_round(s, i, rot)
    return s


# ---- helpers --------------------------------------------------------------

def _words(b):
    return list(struct.unpack('<%dI' % (len(b) // 4), b))


def _bytes(ws):
    return struct.pack('<%dI' % len(ws), *ws)


def _pad(block, size=32):
    """10* padding to `size` bytes; block must be shorter than size."""
    assert len(block) < size
    return block + b'\x80' + b'\x00' * (size - len(block) - 1)


def _xor_rate(s, block_words):
    for j in range(RATE_WORDS):
        s[j] ^= block_words[j]


# ---- AEAD -----------------------------------------------------------------

def _init(key, nonce, pset):
    assert len(key) == KEY_BYTES and len(nonce) == NONCE_BYTES
    r_light, iv1 = PARAMS[pset]
    k = _words(key)
    s = [IV0_AEAD, iv1] + k + _words(nonce)
    permute(s, R_HEAVY)
    for j in range(8):
        s[8 + j] ^= k[j]
    return s, k, r_light


def _absorb_ad(s, ad, r_light):
    if ad:
        full, rem = divmod(len(ad), 32)
        for i in range(full):
            _xor_rate(s, _words(ad[i * 32:(i + 1) * 32]))
            permute(s, r_light)
        _xor_rate(s, _words(_pad(ad[full * 32:])))
        permute(s, r_light)
    s[15] ^= 0x80000000                       # domain separation


def _finalize(s, k):
    for j in range(8):
        s[8 + j] ^= k[j]
    permute(s, R_HEAVY)
    return _bytes(s[:RATE_WORDS])


def aead_encrypt(key, nonce, ad, msg, pset=DEFAULT_SET):
    """Returns ciphertext || tag."""
    s, k, r_light = _init(key, nonce, pset)
    _absorb_ad(s, ad, r_light)
    out = bytearray()
    full, rem = divmod(len(msg), 32)
    for i in range(full):
        _xor_rate(s, _words(msg[i * 32:(i + 1) * 32]))
        out += _bytes(s[:RATE_WORDS])
        permute(s, r_light)
    last = msg[full * 32:]
    _xor_rate(s, _words(_pad(last)))
    out += _bytes(s[:RATE_WORDS])[:len(last)]
    tag = _finalize(s, k)
    return bytes(out) + tag


def aead_decrypt(key, nonce, ad, ct, tag_len=TAG_BYTES, pset=DEFAULT_SET):
    """Returns plaintext, or raises ValueError on authentication failure."""
    if len(ct) < tag_len:
        raise ValueError('ciphertext too short')
    body, tag = ct[:-tag_len], ct[-tag_len:]
    s, k, r_light = _init(key, nonce, pset)
    _absorb_ad(s, ad, r_light)
    out = bytearray()
    full, rem = divmod(len(body), 32)
    for i in range(full):
        c = _words(body[i * 32:(i + 1) * 32])
        p = [s[j] ^ c[j] for j in range(RATE_WORDS)]
        out += _bytes(p)
        s[:RATE_WORDS] = c
        permute(s, r_light)
    last_c = body[full * 32:]
    ks = _bytes(s[:RATE_WORDS])
    last_p = bytes(a ^ b for a, b in zip(last_c, ks))
    out += last_p
    # replace rate with ciphertext, then apply padding on top
    padded_p = _pad(last_p)
    _xor_rate(s, _words(padded_p))
    expected = _finalize(s, k)[:tag_len]
    if not _hmac.compare_digest(expected, tag):
        raise ValueError('authentication failed')
    return bytes(out)


# ---- STREAM (large files) -------------------------------------------------

STREAM_MAGIC = b'FBLS'
STREAM_VER = 1
DEFAULT_CHUNK = 65536


def _chunk_nonce(nf, ctr, last):
    assert len(nf) == 19 and ctr < 2 ** 32
    return nf + struct.pack('<I', ctr) + bytes([1 if last else 0])


def stream_encrypt(key, file_nonce, data, chunk=DEFAULT_CHUNK, pset=DEFAULT_SET):
    header = STREAM_MAGIC + bytes([STREAM_VER]) + struct.pack('<I', chunk) + file_nonce
    out = bytearray(header)
    n_chunks = len(data) // chunk + 1          # always a (possibly empty) last chunk
    for i in range(n_chunks):
        blk = data[i * chunk:(i + 1) * chunk]
        last = (i == n_chunks - 1)
        out += aead_encrypt(key, _chunk_nonce(file_nonce, i, last), header, blk, pset)
    return bytes(out)


def stream_decrypt(key, blob, pset=DEFAULT_SET):
    if blob[:4] != STREAM_MAGIC or blob[4] != STREAM_VER:
        raise ValueError('bad header')
    chunk = struct.unpack('<I', blob[5:9])[0]
    nf = blob[9:28]
    header = blob[:28]
    body = blob[28:]
    out = bytearray()
    step = chunk + TAG_BYTES
    i = 0
    pos = 0
    while True:
        piece = body[pos:pos + step]
        if len(piece) < TAG_BYTES:
            raise ValueError('truncated')
        last = len(piece) < step
        try:
            out += aead_decrypt(key, _chunk_nonce(nf, i, last), header, piece, pset=pset)
        except ValueError:
            raise ValueError('authentication failed at chunk %d' % i)
        pos += step
        i += 1
        if last:
            break
        if pos == len(body):
            raise ValueError('truncated: missing final chunk')
    return bytes(out)


# ---- Hash / XOF -----------------------------------------------------------

def xof(data, out_len):
    s = [IV0_AEAD, IV1_HASH] + [0] * 14
    full = len(data) // 32
    for i in range(full):
        _xor_rate(s, _words(data[i * 32:(i + 1) * 32]))
        permute(s, R_HEAVY)
    _xor_rate(s, _words(_pad(data[full * 32:])))
    permute(s, R_HEAVY)
    out = bytearray()
    while len(out) < out_len:
        out += _bytes(s[:RATE_WORDS])
        if len(out) < out_len:
            permute(s, R_HEAVY)
    return bytes(out[:out_len])


def hash256(data):
    return xof(data, 32)


def hash512(data):
    return xof(data, 64)
