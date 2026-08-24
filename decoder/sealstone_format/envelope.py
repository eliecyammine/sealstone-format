"""The Impression envelope: header, key derivation, authenticated encryption.

The header is passed to the AEAD as associated data, so any change to the
version, algorithm identifiers or KDF parameters is detected on open. Without
this an attacker could downgrade a file's KDF parameters to something cheap to
brute-force.

Decode order is verify the tag, then parse, then validate, then act. Nothing is
mutated before the tag verifies.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from . import aes, argon2
from .errors import (
    BrokenSealError,
    HostileParametersError,
    KeyMaterialMismatchError,
    NotAnImpressionError,
    UnsupportedVersionError,
)

MAGIC = b"SEALSTN"
FORMAT_MAJOR = 1
FORMAT_MINOR = 0

KDF_NONE = 0x00        # key supplied directly (at-rest store)
KDF_ARGON2ID = 0x01

AEAD_AES_256_GCM = 0x01
AEAD_CHACHA20_POLY1305 = 0x02   # specified, not implemented in v1

SALT_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16

# RFC 9106 memory-constrained parameter set
DEFAULT_MEMORY_KIB = 65536
DEFAULT_ITERATIONS = 3
DEFAULT_PARALLELISM = 4

# Normative ceilings. Rejected before anything is allocated.
MAX_MEMORY_KIB = 1048576
MAX_ITERATIONS = 16
MAX_PARALLELISM = 16


@dataclass(frozen=True)
class Header:
    format_major: int
    format_minor: int
    kdf_id: int
    aead_id: int
    kdf_memory_kib: int
    kdf_iterations: int
    kdf_parallelism: int
    salt: bytes
    nonce: bytes

    def to_bytes(self) -> bytes:
        return (
            MAGIC
            + bytes([self.format_major, self.format_minor,
                     self.kdf_id, self.aead_id])
            + struct.pack(">I", self.kdf_memory_kib)
            + struct.pack(">I", self.kdf_iterations)
            + bytes([self.kdf_parallelism, len(self.salt)])
            + self.salt
            + bytes([len(self.nonce)])
            + self.nonce
            + b"\x00\x00"
        )


def _parse_header(data: bytes) -> tuple[Header, int]:
    """Parse and sanity-check the header. Returns (header, bytes consumed)."""
    if len(data) < len(MAGIC) + 4:
        raise NotAnImpressionError("file is too short to be an Impression")

    if data[:len(MAGIC)] != MAGIC:
        raise NotAnImpressionError(
            "this file does not begin with the Sealstone magic bytes"
        )

    offset = len(MAGIC)
    major, minor, kdf_id, aead_id = data[offset:offset + 4]
    offset += 4

    if major != FORMAT_MAJOR:
        raise UnsupportedVersionError(
            f"this file is Sealstone Format v{major}; this decoder reads v{FORMAT_MAJOR}"
        )
    # Unknown minor versions are readable; only the major version gates.

    if kdf_id not in (KDF_NONE, KDF_ARGON2ID):
        raise UnsupportedVersionError(f"unknown KDF identifier: 0x{kdf_id:02x}")
    if aead_id != AEAD_AES_256_GCM:
        raise UnsupportedVersionError(
            f"unsupported AEAD identifier: 0x{aead_id:02x} "
            "(this decoder implements AES-256-GCM only)"
        )

    def need(count: int) -> bytes:
        """Read `count` bytes, or say plainly that the file is too short."""
        nonlocal offset
        if len(data) < offset + count:
            raise NotAnImpressionError(
                f"the file is truncated — it ends after {len(data)} bytes but "
                f"the header needs at least {offset + count}"
            )
        chunk = data[offset:offset + count]
        offset += count
        return chunk

    memory_kib, iterations = struct.unpack(">II", need(8))
    parallelism = need(1)[0]

    salt_length = need(1)[0]
    salt = need(salt_length)

    nonce_length = need(1)[0]
    nonce = need(nonce_length)

    if need(2) != b"\x00\x00":
        raise NotAnImpressionError("reserved bytes are not zero")

    if kdf_id == KDF_NONE:
        if (memory_kib, iterations, parallelism) != (0, 0, 0):
            raise NotAnImpressionError(
                "this file declares no key derivation function but carries "
                "KDF parameters, which the format forbids. It was not written "
                "by a conforming implementation."
            )

    # Every KDF parameter is range-checked here, before any allocation and
    # before the value reaches the derivation function. Out of range means the
    # header was altered or the file is malformed; either way, refuse.
    if kdf_id == KDF_ARGON2ID:
        if not 1 <= parallelism <= MAX_PARALLELISM:
            raise HostileParametersError(
                f"This file asks for parallelism {parallelism}, outside the "
                f"permitted range 1 to {MAX_PARALLELISM}. Refusing to open it."
            )
        if not 1 <= iterations <= MAX_ITERATIONS:
            raise HostileParametersError(
                f"This file asks for {iterations} iterations, outside the "
                f"permitted range 1 to {MAX_ITERATIONS}. Refusing to open it."
            )
        if not 8 * parallelism <= memory_kib <= MAX_MEMORY_KIB:
            raise HostileParametersError(
                f"This file asks for {memory_kib} KiB of memory, outside the "
                f"permitted range {8 * parallelism} to {MAX_MEMORY_KIB} KiB. "
                "Refusing to open it."
            )

    header = Header(major, minor, kdf_id, aead_id,
                    memory_kib, iterations, parallelism, salt, nonce)
    return header, offset


def _derive_key(header: Header, passphrase: str | None,
                key: bytes | None) -> bytes:
    if header.kdf_id == KDF_NONE:
        if key is None:
            raise KeyMaterialMismatchError(
                "This file says its key comes from the keychain, not a passphrase. "
                "Either it is a vault store rather than a backup, or the file was "
                "altered. Supply the key, or use a backup you trust."
            )
        if len(key) != 32:
            raise KeyMaterialMismatchError("key must be 32 bytes")
        return key

    if passphrase is None:
        raise KeyMaterialMismatchError(
            "This file is passphrase-protected. Supply the passphrase."
        )

    # NFC normalisation: without it a passphrase containing a composed character
    # derives a different key depending on which platform typed it.
    import unicodedata
    normalised = unicodedata.normalize("NFC", passphrase).encode("utf-8")

    _check_available_memory(header.kdf_memory_kib)

    return argon2.hash_raw(
        password=normalised,
        salt=header.salt,
        time_cost=header.kdf_iterations,
        memory_cost=header.kdf_memory_kib,
        parallelism=header.kdf_parallelism,
        tag_length=32,
        type_=argon2.TYPE_ID,
    )


# Pure Python holds each 1 KiB Argon2 block as a list of 128 Python integers,
# which costs several times the nominal figure. Measured at roughly 6x.
PYTHON_MEMORY_MULTIPLIER = 6


def _check_available_memory(memory_kib: int) -> None:
    """Refuse a derivation the machine cannot complete.

    Being killed by the operating system part-way through is indistinguishable
    from data loss to whoever is trying to open their backup. A clear refusal
    is worth more than an optimistic attempt.
    """
    needed_bytes = memory_kib * 1024 * PYTHON_MEMORY_MULTIPLIER

    try:
        import resource
        page_size = os.sysconf("SC_PAGE_SIZE")
        available = os.sysconf("SC_AVPHYS_PAGES") * page_size
    except (ImportError, ValueError, OSError, AttributeError):
        return  # Cannot tell. Proceed rather than refuse on no evidence.

    if available and needed_bytes > available:
        raise HostileParametersError(
            f"Opening this file needs about {needed_bytes // (1024 * 1024)} MiB "
            f"and only {available // (1024 * 1024)} MiB is free. Close some "
            "programs and try again, or open it with the native implementation."
        )


def seal(plaintext: bytes, *, passphrase: str | None = None,
         key: bytes | None = None,
         memory_kib: int = DEFAULT_MEMORY_KIB,
         iterations: int = DEFAULT_ITERATIONS,
         parallelism: int = DEFAULT_PARALLELISM,
         salt: bytes | None = None,
         nonce: bytes | None = None,
         format_minor: int = FORMAT_MINOR) -> bytes:
    """Produce an Impression.

    `salt` and `nonce` exist so test vectors can be reproduced exactly. Leave
    them as None everywhere else; they must be fresh per file, which is what
    makes single-shot AES-GCM safe here.

    `format_minor` exists to build forward-compatibility vectors. A reader must
    accept an unknown minor version, and proving that needs a file genuinely
    sealed with one rather than a tampered byte.
    """
    if (passphrase is None) == (key is None):
        raise ValueError("supply exactly one of passphrase or key")

    header = Header(
        format_major=FORMAT_MAJOR,
        format_minor=format_minor,
        kdf_id=KDF_ARGON2ID if passphrase is not None else KDF_NONE,
        aead_id=AEAD_AES_256_GCM,
        kdf_memory_kib=memory_kib if passphrase is not None else 0,
        kdf_iterations=iterations if passphrase is not None else 0,
        kdf_parallelism=parallelism if passphrase is not None else 0,
        salt=salt if salt is not None else os.urandom(SALT_LENGTH),
        nonce=nonce if nonce is not None else os.urandom(NONCE_LENGTH),
    )

    header_bytes = header.to_bytes()
    derived = _derive_key(header, passphrase, key)
    ciphertext, tag = aes.gcm_encrypt(derived, header.nonce, plaintext,
                                      aad=header_bytes)

    return header_bytes + ciphertext + tag


def open_impression(data: bytes, *, passphrase: str | None = None,
                    key: bytes | None = None) -> tuple[bytes, Header]:
    """Open an Impression. Returns (plaintext, header).

    Raises BrokenSealError if the file was changed after it was sealed, or if
    the passphrase is wrong. An authenticated cipher cannot tell the two apart.
    """
    header, offset = _parse_header(data)

    body = data[offset:]
    if len(body) < TAG_LENGTH:
        raise NotAnImpressionError("file is truncated — no room for a tag")

    ciphertext, tag = body[:-TAG_LENGTH], body[-TAG_LENGTH:]
    derived = _derive_key(header, passphrase, key)

    try:
        plaintext = aes.gcm_decrypt(derived, header.nonce, ciphertext, tag,
                                    aad=data[:offset])
    except ValueError:
        raise BrokenSealError(
            "This seal is broken. Either the passphrase does not match, or the "
            "file was changed after it was sealed. Nothing has been read from it."
        ) from None

    return plaintext, header
