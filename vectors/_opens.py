"""Families whose files a correct implementation must open.
"""

from __future__ import annotations

from _settings import (ROOT, FAST_KDF, REAL_KDF, PASSPHRASE, canonical,
                       deterministic_bytes, fixed_salt_and_nonce,
                       header_summary, write)
from _documents import empty_vault, single_totp_vault, full_vault
from sealstone_format import envelope, shamir


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
