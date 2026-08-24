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

    memory_kib, iterations = struct.unpack(">II", data[offset:offset + 8])
    offset += 8
    parallelism = data[offset]
    offset += 1

    salt_length = data[offset]
    offset += 1
    salt = data[offset:offset + salt_length]
    offset += salt_length

    nonce_length = data[offset]
    offset += 1
    nonce = data[offset:offset + nonce_length]
    offset += nonce_length

    reserved = data[offset:offset + 2]
    offset += 2
    if reserved != b"\x00\x00":
        raise NotAnImpressionError("reserved bytes are not zero")

    if len(salt) != salt_length or len(nonce) != nonce_length:
        raise NotAnImpressionError("header is truncated")

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

    return argon2.hash_raw(
        password=normalised,
        salt=header.salt,
        time_cost=header.kdf_iterations,
        memory_cost=header.kdf_memory_kib,
        parallelism=header.kdf_parallelism,
        tag_length=32,
        type_=argon2.TYPE_ID,
    )


def seal(plaintext: bytes, *, passphrase: str | None = None,
         key: bytes | None = None,
         memory_kib: int = DEFAULT_MEMORY_KIB,
         iterations: int = DEFAULT_ITERATIONS,
         parallelism: int = DEFAULT_PARALLELISM,
         salt: bytes | None = None,
         nonce: bytes | None = None) -> bytes:
    """Produce an Impression.

    `salt` and `nonce` exist so test vectors can be reproduced exactly. Leave
    them as None everywhere else; they must be fresh per file, which is what
    makes single-shot AES-GCM safe here.
    """
    if (passphrase is None) == (key is None):
        raise ValueError("supply exactly one of passphrase or key")

    header = Header(
        format_major=FORMAT_MAJOR,
        format_minor=FORMAT_MINOR,
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
