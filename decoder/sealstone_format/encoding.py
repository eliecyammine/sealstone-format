"""Base32 encodings.

RFC 4648 Base32 is what `otpauth://` URIs use for OTP secrets.

Crockford Base32 is used for fragments printed on paper. It omits I, L, O and U
because they are commonly mistranscribed, and decodes leniently: I and l read as
1, O reads as 0, case is ignored, separators are skipped.
"""

from __future__ import annotations

RFC4648_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

_CROCKFORD_DECODE = {c: i for i, c in enumerate(CROCKFORD_ALPHABET)}
_CROCKFORD_DECODE.update({c.lower(): i for i, c in enumerate(CROCKFORD_ALPHABET)})
# The confusable characters Crockford deliberately maps rather than rejects
_CROCKFORD_DECODE.update({
    "I": 1, "i": 1, "L": 1, "l": 1,
    "O": 0, "o": 0,
})
_CROCKFORD_SKIP = set(" -\t\r\n")


def _b32_encode(data: bytes, alphabet: str) -> str:
    out = []
    buffer = bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(alphabet[(buffer >> bits) & 0x1F])
    if bits:
        out.append(alphabet[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


def _b32_decode(text: str, decode_map: dict, skip: set) -> bytes:
    out = bytearray()
    buffer = bits = 0
    for char in text:
        if char in skip or char == "=":
            continue
        try:
            value = decode_map[char]
        except KeyError:
            raise ValueError(f"invalid Base32 character: {char!r}") from None
        buffer = (buffer << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    return bytes(out)


# ---------------------------------------------------------------- RFC 4648

_RFC_DECODE = {c: i for i, c in enumerate(RFC4648_ALPHABET)}
_RFC_DECODE.update({c.lower(): i for i, c in enumerate(RFC4648_ALPHABET)})


def b32_encode(data: bytes) -> str:
    """RFC 4648 Base32, unpadded — the form `otpauth://` uses."""
    return _b32_encode(data, RFC4648_ALPHABET)


def b32_decode(text: str) -> bytes:
    """RFC 4648 Base32. Tolerates lowercase, padding and spaces."""
    return _b32_decode(text, _RFC_DECODE, {" ", "\t", "\r", "\n", "-"})


# ---------------------------------------------------------------- Crockford


def crockford_encode(data: bytes, group: int = 5) -> str:
    """Crockford Base32, grouped for transcription. `group=0` disables grouping."""
    text = _b32_encode(data, CROCKFORD_ALPHABET)
    if group <= 0:
        return text
    return " ".join(text[i:i + group] for i in range(0, len(text), group))


def crockford_decode(text: str) -> bytes:
    """Crockford Base32, decoding leniently. See the module docstring."""
    return _b32_decode(text, _CROCKFORD_DECODE, _CROCKFORD_SKIP)


# ------------------------------------------------------------- identifiers

#: The kinds this format defines, and how each one is generated. Time-ordered
#: identifiers sort by creation so a vault dump reads chronologically. The two
#: random kinds appear in handover URLs, where a timestamp would tell whoever
#: holds the link when the handover was configured.
IDENTIFIER_KINDS = {
    "vlt": "timeOrdered",
    "acc": "timeOrdered",
    "itm": "timeOrdered",
    "lnk": "timeOrdered",
    "kpr": "random",
    "bnd": "random",
}

#: 128 bits in Crockford Base32.
IDENTIFIER_BODY_LENGTH = 26


def parse_identifier(text: str) -> tuple[str, bytes]:
    """Split an identifier into its kind and its 128-bit body.

    The two halves are treated differently on purpose. The kind is matched
    exactly and is always lowercase, because accepting `ACC_` and `acc_` as one
    thing gives two spellings for one identifier and a way for a lookup to miss.

    The body is decoded leniently, the way Crockford intends: `O` is a zero,
    `I` and `l` are ones, and case is ignored. The person retyping a body is a
    keeper working from a printed sheet, and the difference between lenient and
    strict there is the difference between getting in and not.

    Raises ValueError, naming what is wrong with it.
    """
    kind, separator, body = text.partition("_")
    if not separator:
        raise ValueError("an identifier is a kind, an underscore, then a body")
    if kind not in IDENTIFIER_KINDS:
        raise ValueError(f"unknown identifier kind {kind!r}")
    if len(body) != IDENTIFIER_BODY_LENGTH:
        raise ValueError(
            f"{kind} body is {len(body)} characters, expected "
            f"{IDENTIFIER_BODY_LENGTH}")

    decoded = crockford_decode(body)
    # 26 Crockford characters carry 130 bits, of which the top two are padding.
    return kind, decoded[-16:]
