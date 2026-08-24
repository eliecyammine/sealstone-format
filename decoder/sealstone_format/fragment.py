"""Fragment container: the file or printed sheet a keeper holds.

A fragment is one Shamir share plus enough context to be useful on its own:
which split it belongs to, its index, and how many are needed. Without that
context a share is an anonymous blob nobody can act on.

Two forms. The binary form is what an application writes. The paper form is
Crockford Base32 of those same bytes, grouped for transcription, wrapped in
plain-language instructions — because the person holding this may be reading it
off a sheet years later with no software at all.

The CRC-32 catches transcription error. It is not a security control and does
not detect deliberate modification.
"""

from __future__ import annotations

import zlib

from .encoding import crockford_decode, crockford_encode

MAGIC = b"SEALFRG"
VERSION = 1
SET_ID_LENGTH = 16
HEADER_LENGTH = 29
CHECKSUM_LENGTH = 4


class FragmentError(Exception):
    """A fragment could not be read."""


def encode(set_id: bytes, index: int, threshold: int, total: int,
           share: bytes) -> bytes:
    """Build the binary form of a fragment."""
    if len(set_id) != SET_ID_LENGTH:
        raise FragmentError(f"set id must be {SET_ID_LENGTH} bytes")
    if not 1 <= index <= 255:
        raise FragmentError("index must be between 1 and 255")
    if not 2 <= threshold <= total <= 255:
        raise FragmentError("need 2 <= threshold <= total <= 255")
    if not share or len(share) > 0xFFFF:
        raise FragmentError("share length out of range")

    body = (
        MAGIC
        + bytes([VERSION])
        + set_id
        + bytes([index, threshold, total])
        + len(share).to_bytes(2, "big")
        + share
    )
    return body + zlib.crc32(body).to_bytes(CHECKSUM_LENGTH, "big")


def decode(data: bytes) -> dict:
    """Read the binary form. Returns set_id, index, threshold, total, share."""
    if len(data) < HEADER_LENGTH + CHECKSUM_LENGTH:
        raise FragmentError("this fragment is too short to be complete")

    if data[:len(MAGIC)] != MAGIC:
        raise FragmentError("this does not look like a Sealstone fragment")

    version = data[7]
    if version != VERSION:
        raise FragmentError(
            f"this fragment is version {version}; this reader handles version {VERSION}"
        )

    set_id = data[8:24]
    index, threshold, total = data[24], data[25], data[26]
    share_length = int.from_bytes(data[27:29], "big")

    expected = HEADER_LENGTH + share_length + CHECKSUM_LENGTH
    if len(data) != expected:
        raise FragmentError(
            f"this fragment says it holds {share_length} bytes but the file is "
            f"{len(data) - HEADER_LENGTH - CHECKSUM_LENGTH}. It is truncated or "
            "was mistyped."
        )

    body, checksum = data[:-CHECKSUM_LENGTH], data[-CHECKSUM_LENGTH:]
    if zlib.crc32(body).to_bytes(CHECKSUM_LENGTH, "big") != checksum:
        raise FragmentError(
            "The checksum does not match. Something was mistyped or a character "
            "was dropped. Check the fragment against the sheet and try again."
        )

    if index == 0:
        raise FragmentError("index 0 is invalid — that point is the secret itself")

    return {
        "set_id": set_id,
        "index": index,
        "threshold": threshold,
        "total": total,
        "share": data[HEADER_LENGTH:HEADER_LENGTH + share_length],
    }


def to_paper(set_id: bytes, index: int, threshold: int, total: int,
             share: bytes, *, holder: str | None = None) -> str:
    """Render a fragment as a printable sheet."""
    payload = crockford_encode(encode(set_id, index, threshold, total, share))
    groups = payload.split(" ")

    lines = [
        f"Sealstone fragment {index} of {total} "
        f"— any {threshold} open the vault",
        f"Set {set_id[:2].hex().upper()}-{set_id[2:4].hex().upper()}",
    ]
    if holder:
        lines.append(f"Held by {holder}")
    lines.append("")

    for start in range(0, len(groups), 5):
        lines.append("  " + "  ".join(groups[start:start + 5]))

    lines += [
        "",
        "This is one piece of a key. On its own it opens nothing.",
        f"To open the vault, {threshold} of the {total} people holding pieces",
        "need to bring theirs together.",
        "",
        "Letters are not case sensitive. I and L read as 1, O reads as 0.",
        "There is no expiry date on this sheet.",
    ]
    return "\n".join(lines)


def from_paper(text: str) -> dict:
    """Read a fragment back from a transcribed sheet.

    Instruction lines are skipped, so a whole sheet can be pasted in without
    being trimmed first.
    """
    payload = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if (lowered.startswith(("sealstone fragment", "set ", "held by",
                                "this is one piece", "to open the vault",
                                "need to bring", "letters are not",
                                "there is no expiry"))):
            continue
        payload.append(stripped)

    if not payload:
        raise FragmentError("no fragment data found in this text")

    try:
        data = crockford_decode(" ".join(payload))
    except ValueError as exc:
        raise FragmentError(
            f"This does not decode as a fragment: {exc}. Check for a character "
            "that was misread."
        ) from None

    return decode(data)
