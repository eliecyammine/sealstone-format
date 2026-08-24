"""Argon2id key derivation, RFC 9106.

REFERENCE IMPLEMENTATION. NOT CONSTANT TIME.

Uses BLAKE2b from hashlib as its only primitive. H', the compression function
G, memory filling and indexing all follow RFC 9106 and are validated against
its published test vectors.

Pure Python, so it is slow: at 64 MiB / t=3 expect minutes, not milliseconds.
That is fine for verifying a file once.
"""

from __future__ import annotations

import hashlib
import struct

MASK64 = 0xFFFFFFFFFFFFFFFF
BLOCK_WORDS = 128          # 1024 bytes as 64-bit words
SYNC_POINTS = 4            # slices per pass

TYPE_D, TYPE_I, TYPE_ID = 0, 1, 2
VERSION = 0x13


# ---------------------------------------------------------------- H'


def _h_prime(out_len: int, data: bytes) -> bytes:
    """The variable-length hash of RFC 9106 section 3.2."""
    prefixed = struct.pack("<I", out_len) + data

    if out_len <= 64:
        return hashlib.blake2b(prefixed, digest_size=out_len).digest()

    r = (out_len + 31) // 32 - 2
    out = bytearray()

    v = hashlib.blake2b(prefixed, digest_size=64).digest()
    out += v[:32]
    for _ in range(r - 1):
        v = hashlib.blake2b(v, digest_size=64).digest()
        out += v[:32]

    remaining = out_len - 32 * r
    out += hashlib.blake2b(v, digest_size=remaining).digest()

    return bytes(out)


# ---------------------------------------------------------------- G


def _ror64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def _gb(v: list[int], a: int, b: int, c: int, d: int) -> None:
    """The Argon2 variant of the BLAKE2b mixing function, in place."""
    va, vb, vc, vd = v[a], v[b], v[c], v[d]

    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & MASK64
    vd = _ror64(vd ^ va, 32)
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & MASK64
    vb = _ror64(vb ^ vc, 24)
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & MASK64
    vd = _ror64(vd ^ va, 16)
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & MASK64
    vb = _ror64(vb ^ vc, 63)

    v[a], v[b], v[c], v[d] = va, vb, vc, vd


def _permute(v: list[int]) -> None:
    """P, operating on sixteen 64-bit words in place."""
    _gb(v, 0, 4, 8, 12)
    _gb(v, 1, 5, 9, 13)
    _gb(v, 2, 6, 10, 14)
    _gb(v, 3, 7, 11, 15)
    _gb(v, 0, 5, 10, 15)
    _gb(v, 1, 6, 11, 12)
    _gb(v, 2, 7, 8, 13)
    _gb(v, 3, 4, 9, 14)


def _compress(x: list[int], y: list[int], out: list[int]) -> None:
    """G(X, Y) — the Argon2 compression function.

    The block is an 8x8 matrix of 16-byte cells. P is applied to each row,
    then to each column, and the result is XORed back with R.
    """
    r = [x[i] ^ y[i] for i in range(BLOCK_WORDS)]
    q = list(r)

    # Rows: row i occupies words 16i .. 16i+15
    for i in range(8):
        base = 16 * i
        v = q[base:base + 16]
        _permute(v)
        q[base:base + 16] = v

    # Columns: cell (i, j) occupies words 16i+2j and 16i+2j+1
    for j in range(8):
        idx = []
        for i in range(8):
            idx.append(16 * i + 2 * j)
            idx.append(16 * i + 2 * j + 1)
        v = [q[k] for k in idx]
        _permute(v)
        for pos, k in enumerate(idx):
            q[k] = v[pos]

    for i in range(BLOCK_WORDS):
        out[i] = q[i] ^ r[i]


# ---------------------------------------------------------------- helpers


def _block_from_bytes(data: bytes) -> list[int]:
    return list(struct.unpack("<128Q", data))


def _block_to_bytes(block: list[int]) -> bytes:
    return struct.pack("<128Q", *block)


# ---------------------------------------------------------------- main


def hash_raw(password: bytes, salt: bytes, *, time_cost: int, memory_cost: int,
             parallelism: int, tag_length: int = 32, secret: bytes = b"",
             associated_data: bytes = b"", type_: int = TYPE_ID) -> bytes:
    """Derive a tag. `memory_cost` is in kibibytes.

    Parameter validation is deliberately strict: a hostile file must not be
    able to talk this function into an enormous allocation.
    """
    if parallelism < 1 or parallelism > 0xFFFFFF:
        raise ValueError("parallelism out of range")
    if tag_length < 4:
        raise ValueError("tag length must be at least 4")
    if memory_cost < 8 * parallelism:
        raise ValueError("memory cost must be at least 8 * parallelism")
    if time_cost < 1:
        raise ValueError("time cost must be at least 1")

    # H0
    h0 = hashlib.blake2b(
        struct.pack("<IIIIII", parallelism, tag_length, memory_cost,
                    time_cost, VERSION, type_)
        + struct.pack("<I", len(password)) + password
        + struct.pack("<I", len(salt)) + salt
        + struct.pack("<I", len(secret)) + secret
        + struct.pack("<I", len(associated_data)) + associated_data,
        digest_size=64,
    ).digest()

    # Memory geometry
    blocks_total = (memory_cost // (SYNC_POINTS * parallelism)) * (SYNC_POINTS * parallelism)
    lane_length = blocks_total // parallelism
    segment_length = lane_length // SYNC_POINTS

    memory: list[list[int]] = [None] * blocks_total  # type: ignore[list-item]

    # First two blocks of every lane
    for lane in range(parallelism):
        for col in (0, 1):
            seed = h0 + struct.pack("<II", col, lane)
            memory[lane * lane_length + col] = _block_from_bytes(_h_prime(1024, seed))

    zero_block = [0] * BLOCK_WORDS
    scratch = [0] * BLOCK_WORDS

    for pass_n in range(time_cost):
        for slice_n in range(SYNC_POINTS):
            for lane in range(parallelism):
                data_independent = (
                    type_ == TYPE_I
                    or (type_ == TYPE_ID and pass_n == 0 and slice_n < 2)
                )

                address_block: list[int] | None = None
                input_block: list[int] | None = None
                if data_independent:
                    input_block = [0] * BLOCK_WORDS
                    input_block[0] = pass_n
                    input_block[1] = lane
                    input_block[2] = slice_n
                    input_block[3] = blocks_total
                    input_block[4] = time_cost
                    input_block[5] = type_
                    address_block = [0] * BLOCK_WORDS

                start = 2 if (pass_n == 0 and slice_n == 0) else 0

                # The first segment of the first pass starts at index 2,
                # because blocks 0 and 1 are already seeded from H0. That skips
                # the `index % 128 == 0` trigger below, so the first address
                # block has to be generated here instead. Without this the
                # segment reads an all-zero address block, which is invisible
                # at the RFC's test parameters (segment length 2, so the loop
                # body never runs) and wrong at every larger size.
                if data_independent and start == 2:
                    input_block[6] += 1
                    _compress(zero_block, input_block, scratch)
                    _compress(zero_block, list(scratch), address_block)

                for index in range(start, segment_length):
                    col = slice_n * segment_length + index
                    prev = memory[lane * lane_length + (col - 1) % lane_length]

                    if data_independent:
                        if index % BLOCK_WORDS == 0:
                            input_block[6] += 1
                            _compress(zero_block, input_block, scratch)
                            _compress(zero_block, list(scratch), address_block)
                        pseudo = address_block[index % BLOCK_WORDS]
                    else:
                        pseudo = prev[0]

                    j1 = pseudo & 0xFFFFFFFF
                    j2 = (pseudo >> 32) & 0xFFFFFFFF

                    # Which lane to reference
                    if pass_n == 0 and slice_n == 0:
                        ref_lane = lane
                    else:
                        ref_lane = j2 % parallelism

                    # Size of the referenceable window
                    same_lane = ref_lane == lane
                    if pass_n == 0:
                        if slice_n == 0:
                            window = index - 1
                        elif same_lane:
                            window = slice_n * segment_length + index - 1
                        else:
                            window = slice_n * segment_length - (1 if index == 0 else 0)
                    else:
                        if same_lane:
                            window = lane_length - segment_length + index - 1
                        else:
                            window = lane_length - segment_length - (1 if index == 0 else 0)

                    # Map j1 into the window, biased toward recent blocks
                    x = (j1 * j1) >> 32
                    y = (window * x) >> 32
                    zz = window - 1 - y

                    if pass_n == 0:
                        start_pos = 0
                    else:
                        start_pos = 0 if slice_n == SYNC_POINTS - 1 else (slice_n + 1) * segment_length
                    ref_index = (start_pos + zz) % lane_length

                    ref = memory[ref_lane * lane_length + ref_index]
                    here = lane * lane_length + col

                    if pass_n == 0:
                        target = [0] * BLOCK_WORDS
                        _compress(prev, ref, target)
                        memory[here] = target
                    else:
                        # Later passes XOR into the existing block
                        _compress(prev, ref, scratch)
                        existing = memory[here]
                        memory[here] = [existing[i] ^ scratch[i] for i in range(BLOCK_WORDS)]

    # Finalisation: XOR the last block of every lane, then H'
    final = list(memory[(parallelism - 1) * lane_length + lane_length - 1])
    for lane in range(parallelism - 1):
        last = memory[lane * lane_length + lane_length - 1]
        for i in range(BLOCK_WORDS):
            final[i] ^= last[i]

    return _h_prime(tag_length, _block_to_bytes(final))
