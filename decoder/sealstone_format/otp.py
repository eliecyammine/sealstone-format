"""One-time password generation: HOTP (RFC 4226), TOTP (RFC 6238), Steam.

Without this the decoder returns a Base32 secret, which does not log anyone
into anything. Recovering a vault means producing the six digits the service
actually asks for.

Validated against the RFC 4226 and RFC 6238 test vectors.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time as _time

from .encoding import b32_decode

ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"


def _hmac_digest(secret: bytes, counter: int, algorithm: str) -> bytes:
    try:
        digest = ALGORITHMS[algorithm]
    except KeyError:
        raise ValueError(f"unsupported algorithm: {algorithm}") from None
    return hmac.new(secret, struct.pack(">Q", counter), digest).digest()


def _truncate(digest: bytes) -> int:
    """RFC 4226 dynamic truncation: the low nibble of the last byte picks the
    offset, and the top bit of the extracted word is cleared."""
    offset = digest[-1] & 0x0F
    return struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF


def hotp(secret: bytes, counter: int, *, digits: int = 6,
         algorithm: str = "SHA1") -> str:
    """A counter-based code, zero-padded to `digits`."""
    if not 6 <= digits <= 10:
        raise ValueError("digits must be between 6 and 10")
    if counter < 0:
        raise ValueError("counter must not be negative")

    value = _truncate(_hmac_digest(secret, counter, algorithm))
    return str(value % (10 ** digits)).zfill(digits)


def totp(secret: bytes, *, at: float | None = None, period: int = 30,
         digits: int = 6, algorithm: str = "SHA1", epoch: int = 0) -> str:
    """A time-based code.

    `at` is a Unix timestamp, defaulting to now. Pass it explicitly to
    reproduce a code for a known instant.
    """
    if period < 1:
        raise ValueError("period must be at least 1 second")

    now = _time.time() if at is None else at
    counter = int((now - epoch) // period)
    return hotp(secret, counter, digits=digits, algorithm=algorithm)


def steam(secret: bytes, *, at: float | None = None, period: int = 30) -> str:
    """A Steam Guard code: five characters from a 26-symbol alphabet.

    Same HMAC and truncation as HOTP, then repeated division by the alphabet
    size instead of by ten.
    """
    now = _time.time() if at is None else at
    counter = int(now // period)
    value = _truncate(_hmac_digest(secret, counter, "SHA1"))

    out = []
    for _ in range(5):
        out.append(STEAM_ALPHABET[value % len(STEAM_ALPHABET)])
        value //= len(STEAM_ALPHABET)
    return "".join(out)


def seconds_remaining(*, at: float | None = None, period: int = 30) -> float:
    """How long the current code stays valid."""
    now = _time.time() if at is None else at
    return period - (now % period)


def generate(item: dict, *, at: float | None = None) -> str:
    """Produce the current code for an `authenticator` item from a vault.

    The item carries every parameter needed, so recovery does not depend on
    remembering how a particular service was configured.
    """
    if item.get("type") != "authenticator":
        raise ValueError(f"not an authenticator item: {item.get('type')!r}")

    secret = b32_decode(item["secret"])
    otp_type = item.get("otpType", "totp")

    if otp_type == "hotp":
        return hotp(secret, item["counter"],
                    digits=item.get("digits", 6),
                    algorithm=item.get("algorithm", "SHA1"))

    if otp_type == "steam":
        return steam(secret, at=at, period=item.get("period", 30))

    if otp_type == "totp":
        return totp(secret, at=at,
                    period=item.get("period", 30),
                    digits=item.get("digits", 6),
                    algorithm=item.get("algorithm", "SHA1"))

    raise ValueError(f"unsupported otpType: {otp_type!r}")
