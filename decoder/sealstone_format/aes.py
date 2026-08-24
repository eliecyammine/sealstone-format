"""AES-256 block cipher and AES-GCM authenticated encryption.

REFERENCE IMPLEMENTATION. NOT CONSTANT TIME. MUST NOT BE USED TO PROTECT DATA.

Python's standard library has no AES, and this decoder runs with no
dependencies so that it still works on a machine with no network and no
package manager. Validated against the FIPS-197 known-answer vectors and the
GCM specification test cases.

Table lookups are data-dependent and leak timing. Fine for verifying a file you
already hold; unusable for anything else.
"""

from __future__ import annotations

# ---------------------------------------------------------------- S-box

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D)


def _xtime(a: int) -> int:
    """Multiply by x in GF(2^8) with the AES polynomial."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    """Multiply two elements of GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


# ---------------------------------------------------------------- key schedule


def _expand_key(key: bytes) -> list[list[int]]:
    """Expand a 128/192/256-bit key into round keys of four words each."""
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError(f"invalid AES key length: {len(key)} bytes")
    nr = nk + 6

    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]

    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                      # RotWord
            temp = [_SBOX[b] for b in temp]                  # SubWord
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]                  # SubWord
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])

    return [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]


# ---------------------------------------------------------------- block cipher


def _add_round_key(state: list[int], round_key: list[int]) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    # State is column-major: index = row + 4*col
    for row in range(1, 4):
        vals = [state[row + 4 * c] for c in range(4)]
        vals = vals[row:] + vals[:row]
        for c in range(4):
            state[row + 4 * c] = vals[c]


def _mix_columns(state: list[int]) -> None:
    for c in range(4):
        col = state[4 * c:4 * c + 4]
        state[4 * c + 0] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
        state[4 * c + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
        state[4 * c + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
        state[4 * c + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)


def encrypt_block(key_schedule: list[list[int]], block: bytes) -> bytes:
    """Encrypt one 16-byte block. GCM never needs decryption."""
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")

    state = list(block)
    rounds = len(key_schedule) - 1

    _add_round_key(state, key_schedule[0])
    for r in range(1, rounds):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, key_schedule[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, key_schedule[rounds])

    return bytes(state)


# ---------------------------------------------------------------- GHASH

_R = 0xE1 << 120  # x^128 + x^7 + x^2 + x + 1, reduction constant


def _gf128_mul(x: int, y: int) -> int:
    """Multiply in GF(2^128) using the GCM bit ordering."""
    z = 0
    v = y
    for i in range(128):
        if x & (1 << (127 - i)):
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h: int, data: bytes) -> int:
    """GHASH over data, which must already be zero-padded to a 16-byte multiple."""
    y = 0
    for i in range(0, len(data), 16):
        y = _gf128_mul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return data if remainder == 0 else data + b"\x00" * (16 - remainder)


# ---------------------------------------------------------------- GCM


def _gctr(key_schedule: list[list[int]], icb: int, data: bytes) -> bytes:
    """CTR mode over `data` starting from counter block `icb`."""
    if not data:
        return b""
    out = bytearray()
    counter = icb
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        keystream = encrypt_block(key_schedule, counter.to_bytes(16, "big"))
        out.extend(a ^ b for a, b in zip(chunk, keystream))
        # Only the low 32 bits of the counter block increment.
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
    return bytes(out)


def _derive_j0(h: int, nonce: bytes) -> int:
    """Derive the initial counter block from the nonce."""
    if len(nonce) == 12:
        return int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    padded = _pad16(nonce) + b"\x00" * 8 + (len(nonce) * 8).to_bytes(8, "big")
    return _ghash(h, padded)


def _gcm(key: bytes, nonce: bytes, data: bytes, aad: bytes, encrypting: bool):
    if not nonce:
        raise ValueError("GCM nonce must not be empty")

    key_schedule = _expand_key(key)
    h = int.from_bytes(encrypt_block(key_schedule, b"\x00" * 16), "big")
    j0 = _derive_j0(h, nonce)

    counter = (j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF)
    result = _gctr(key_schedule, counter, data)

    ciphertext = result if encrypting else data
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    s = _ghash(h, _pad16(aad) + _pad16(ciphertext) + lengths)

    tag = _gctr(key_schedule, j0, s.to_bytes(16, "big"))
    return result, tag


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt and authenticate. Returns (ciphertext, 16-byte tag)."""
    return _gcm(key, nonce, plaintext, aad, encrypting=True)


def gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                aad: bytes = b"") -> bytes:
    """Verify and decrypt. Raises ValueError if the tag does not match.

    The tag is checked before the plaintext is returned, so a caller cannot
    accidentally use unauthenticated data.
    """
    if len(tag) != 16:
        raise ValueError("GCM tag must be 16 bytes")

    plaintext, expected = _gcm(key, nonce, ciphertext, aad, encrypting=False)

    # Not a constant-time comparison. See the module docstring.
    if expected != tag:
        raise ValueError("authentication tag mismatch")

    return plaintext
