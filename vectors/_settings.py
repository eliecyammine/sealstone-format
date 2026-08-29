"""The parameters every family is built from, and the helpers that use them.

One module holds them so no two families can disagree about a salt, a
passphrase or a KDF cost. Determinism is the whole property this corpus has:
salts, nonces and Shamir coefficients are derived from each family's
identifier, so regenerating produces byte-identical files and a diff in
`git status` afterwards means the encoder changed.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent

# The decoder is a sibling rather than an installed package, and every module
# here needs it. Done once, in the module they all import.
sys.path.insert(0, str(ROOT.parent / "decoder"))

from sealstone_format import envelope  # noqa: E402

# Deliberately far too weak to protect anything, so the corpus can be verified
# in a scripting language in seconds. Every family except 10 uses these, and no
# implementation may copy them: a file sealed with 64 KiB and one iteration is
# a file anyone can open. Family 10 carries the real parameters so the ones
# that ship are not the least tested thing here.
FAST_KDF = dict(memory_kib=64, iterations=1, parallelism=1)
REAL_KDF = dict(memory_kib=65536, iterations=3, parallelism=4)

PASSPHRASE = "correct horse battery staple"

# The regions a tampered-file consumer must check, and the byte offset in each.
# Every field of the file appears here, including the length prefixes and the
# reserved bytes — the header is authenticated in full, so no region is exempt.
TAMPER_REGIONS = {
    "magic": 0,
    "formatMajor": 7,
    "formatMinor": 8,
    "kdfId": 9,
    "aeadId": 10,
    "kdfMemory": 11,
    "kdfIterations": 15,
    "kdfParallelism": 19,
    "saltLen": 20,
    "salt": 21,
    "nonceLen": 37,
    "nonce": 38,
    "reserved": 50,
    "ciphertext": -20,
    "tag": -1,
}


def deterministic_bytes(label: str, length: int) -> bytes:
    """Reproducible pseudo-random bytes, derived from a label."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{label}:{counter}".encode()).digest()
        counter += 1
    return out[:length]


def fixed_salt_and_nonce(family: str) -> dict:
    return {
        "salt": deterministic_bytes(f"{family}/salt", envelope.SALT_LENGTH),
        "nonce": deterministic_bytes(f"{family}/nonce", envelope.NONCE_LENGTH),
    }


def canonical(document: dict) -> bytes:
    """Stable JSON encoding so regeneration is byte-identical."""
    return json.dumps(document, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def header_summary(blob: bytes) -> dict:
    header, offset = envelope._parse_header(blob)
    return {
        "formatMajor": header.format_major,
        "formatMinor": header.format_minor,
        "kdfId": header.kdf_id,
        "aeadId": header.aead_id,
        "kdfMemoryKiB": header.kdf_memory_kib,
        "kdfIterations": header.kdf_iterations,
        "kdfParallelism": header.kdf_parallelism,
        "headerLength": offset,
    }
