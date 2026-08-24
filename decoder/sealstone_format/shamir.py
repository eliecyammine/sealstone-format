"""Shamir's Secret Sharing over GF(2^8).

Splits a key into n fragments, any k of which reconstruct it. Fewer than k
reveal nothing. Applied byte-wise using the AES field polynomial 0x11B.

REFERENCE IMPLEMENTATION. NOT CONSTANT TIME.

The log/exp tables below are indexed by secret data and therefore leak through
the cache. A production implementation needs branch-free arithmetic with no
secret-dependent indices.
"""

from __future__ import annotations

import secrets

# ---------------------------------------------------------------- GF(2^8)

_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # Multiply by the generator 3 (x + 1)
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)
        x &= 0xFF
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


# ---------------------------------------------------------------- split


def split(secret: bytes, threshold: int, shares: int,
          rng=None) -> list[tuple[int, bytes]]:
    """Split `secret` into `shares` fragments, any `threshold` of which recombine.

    Returns (index, share) pairs. Index is the x-coordinate and is never zero,
    since f(0) is the secret.

    `rng` returns a random byte and defaults to a cryptographically secure
    source. Override it only to reproduce fixed test vectors; a predictable
    source here destroys the security of the split entirely.
    """
    if not 2 <= threshold <= shares:
        raise ValueError("need 2 <= threshold <= shares")
    if shares > 255:
        raise ValueError("at most 255 shares (the field has 255 non-zero points)")
    if not secret:
        raise ValueError("secret must not be empty")

    if rng is None:
        def rng() -> int:
            return secrets.randbelow(256)

    out = [bytearray() for _ in range(shares)]

    for byte in secret:
        # f(0) = byte, with random coefficients above it
        coefficients = [byte] + [rng() for _ in range(threshold - 1)]
        for i in range(shares):
            x = i + 1
            # Horner evaluation at x
            acc = 0
            for coefficient in reversed(coefficients):
                acc = _mul(acc, x) ^ coefficient
            out[i].append(acc)

    return [(i + 1, bytes(out[i])) for i in range(shares)]


# ---------------------------------------------------------------- combine


def combine(shares: list[tuple[int, bytes]]) -> bytes:
    """Reconstruct the secret by Lagrange interpolation at x = 0."""
    if len(shares) < 2:
        raise ValueError("need at least two shares")

    indices = [x for x, _ in shares]
    if len(set(indices)) != len(indices):
        raise ValueError("duplicate share indices")
    if any(x == 0 for x in indices):
        raise ValueError("share index 0 is invalid — that point is the secret")

    length = len(shares[0][1])
    if any(len(s) != length for _, s in shares):
        raise ValueError("shares differ in length")

    secret = bytearray()
    for position in range(length):
        acc = 0
        for i, (xi, si) in enumerate(shares):
            # Lagrange basis polynomial evaluated at zero
            numerator, denominator = 1, 1
            for j, (xj, _) in enumerate(shares):
                if i == j:
                    continue
                numerator = _mul(numerator, xj)
                denominator = _mul(denominator, xi ^ xj)
            acc ^= _mul(si[position], _div(numerator, denominator))
        secret.append(acc)

    return bytes(secret)
