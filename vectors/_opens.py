"""Families whose files a correct implementation must open.
"""

from __future__ import annotations

from _settings import (ROOT, FAST_KDF, REAL_KDF, PASSPHRASE, canonical,
                       deterministic_bytes, fixed_salt_and_nonce,
                       header_summary, write)
from _documents import empty_vault, single_totp_vault, full_vault
from sealstone_format import envelope, fragment, shamir


def build_open_family(family: str, description: str, document: dict,
                      passphrase: str, kdf: dict) -> dict:
    plaintext = canonical(document)
    blob = envelope.seal(plaintext, passphrase=passphrase,
                         **kdf, **fixed_salt_and_nonce(family))

    write(ROOT / family / "impression.seal", blob)
    write(ROOT / family / "plaintext.json", plaintext)

    return {
        "id": family,
        "description": description,
        "kind": "open-succeeds",
        "file": f"{family}/impression.seal",
        "passphraseUtf8Hex": passphrase.encode("utf-8").hex(),
        "expectedPlaintext": f"{family}/plaintext.json",
        "expectedHeader": header_summary(blob),
    }


def build_nfc_family() -> dict:
    family = "04-nfc-passphrase"
    composed = "café naïve"          # precomposed
    decomposed = "café naïve"      # combining marks

    plaintext = canonical(empty_vault())
    blob = envelope.seal(plaintext, passphrase=composed,
                         **FAST_KDF, **fixed_salt_and_nonce(family))
    write(ROOT / family / "impression.seal", blob)
    write(ROOT / family / "plaintext.json", plaintext)

    return {
        "id": family,
        "description": (
            "Sealed with a precomposed passphrase. Both the precomposed and the "
            "decomposed spelling must open it, because the passphrase is "
            "NFC-normalised before key derivation. Without normalisation the "
            "same typed characters produce different keys on different "
            "platforms and the file becomes unopenable on one of them."
        ),
        "kind": "open-succeeds",
        "file": f"{family}/impression.seal",
        "expectedPlaintext": f"{family}/plaintext.json",
        "passphraseUtf8Hex": composed.encode("utf-8").hex(),
        "equivalentPassphrasesUtf8Hex": [
            composed.encode("utf-8").hex(),
            decomposed.encode("utf-8").hex(),
        ],
        "expectedHeader": header_summary(blob),
    }


def build_shamir_family() -> dict:
    family = "08-shamir-3-of-5"
    secret = deterministic_bytes(f"{family}/secret", 32)

    stream = iter(deterministic_bytes(f"{family}/coefficients", 4096))
    shares = shamir.split(secret, 3, 5, rng=lambda: next(stream))

    from itertools import combinations
    reconstructing = [list(c) for c in combinations([i for i, _ in shares], 3)]
    insufficient = [list(c) for c in combinations([i for i, _ in shares], 2)]

    return {
        "id": family,
        "description": (
            "A 3-of-5 split over GF(2^8) with the AES polynomial 0x11B. Every "
            "three-index subset must reconstruct the secret exactly. No "
            "two-index subset may, and no partial information may be derivable "
            "from one."
        ),
        "kind": "shamir",
        "secretHex": secret.hex(),
        "threshold": 3,
        "total": 5,
        "shares": [{"index": index, "shareHex": share.hex()}
                   for index, share in shares],
        "mustReconstruct": reconstructing,
        "mustNotReconstruct": insufficient,
    }


def build_fragment_family() -> dict:
    """The container a keeper holds, in both of its forms.

    Shamir has its own family; this one is about the wrapper around a share.
    Two implementations agreeing on the bytes is what stops a keeper being
    handed a fragment the other one cannot read, which is discovered at the one
    moment nobody can ask anybody.
    """
    family = "13-fragments"
    set_id = deterministic_bytes(f"{family}/set", 16)
    share = deterministic_bytes(f"{family}/share", 32)
    binary = fragment.encode(set_id, 2, 3, 5, share)

    def broken(mutate) -> str:
        data = bytearray(binary)
        mutate(data)
        return bytes(data).hex()

    def flip_a_share_byte(data):
        data[40] ^= 0x01

    def wrong_magic(data):
        data[0] = ord("X")

    def future_version(data):
        data[7] = 9

    def index_zero(data):
        data[24] = 0

    paper = fragment.to_paper(set_id, 2, 3, 5, share)

    return {
        "id": family,
        "description": (
            "One Shamir share in the container a keeper actually holds. The "
            "binary form byte for byte, the paper form it prints as, and the "
            "transcription substitutions a reader must accept when somebody "
            "types it back in. Also the malformed ones: a wrong magic, a "
            "version from the future, an index of zero, a flipped bit the "
            "checksum has to catch, and a truncated file."
        ),
        "kind": "fragments",
        "setIdHex": set_id.hex(),
        "index": 2,
        "threshold": 3,
        "total": 5,
        "shareHex": share.hex(),
        "encodedHex": binary.hex(),
        "paper": paper,
        # Typed back by somebody reading off a sheet: a letter O for a zero, a
        # lowercase l for a one, and whichever case their keyboard was in.
        "retyped": (paper.replace("0", "O").replace("1", "l").lower()),
        "mustReject": [
            {"hex": broken(flip_a_share_byte),
             "reason": "one flipped bit, which the checksum exists to catch"},
            {"hex": broken(wrong_magic),
             "reason": "not a fragment at all"},
            {"hex": broken(future_version),
             "reason": "a version this reader does not handle"},
            {"hex": broken(index_zero),
             "reason": "index zero is the secret itself, never a share"},
            {"hex": binary[:-6].hex(),
             "reason": "truncated, so the length disagrees with the header"},
        ],
    }


def build_real_parameters_family() -> dict:
    family = "10-real-parameters"
    plaintext = canonical(single_totp_vault())
    blob = envelope.seal(plaintext, passphrase=PASSPHRASE,
                         **REAL_KDF, **fixed_salt_and_nonce(family))
    write(ROOT / family / "impression.seal", blob)
    write(ROOT / family / "plaintext.json", plaintext)

    return {
        "id": family,
        "description": (
            "The parameters shipped in production: 64 MiB, 3 iterations, "
            "parallelism 4. Slow to verify in a scripting language, which is "
            "the point of the parameters."
        ),
        "kind": "open-succeeds",
        "slow": True,
        "file": f"{family}/impression.seal",
        "passphraseUtf8Hex": PASSPHRASE.encode("utf-8").hex(),
        "expectedPlaintext": f"{family}/plaintext.json",
        "expectedHeader": header_summary(blob),
    }
