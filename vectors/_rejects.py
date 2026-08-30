"""Families whose files a correct implementation must refuse.

The larger half of the corpus, and the more important one. Anybody can write a
decoder that opens a valid file; the difference between an implementation and a
liability is what it does with one that has been altered, truncated, or written
by a version it has never heard of.
"""

from __future__ import annotations

from _settings import (ROOT, FAST_KDF, PASSPHRASE, TAMPER_REGIONS, canonical,
                       fixed_salt_and_nonce, header_summary, write)
from _documents import empty_vault, single_totp_vault
from sealstone_format import envelope


def build_tamper_family() -> dict:
    family = "05-tamper"
    plaintext = canonical(single_totp_vault())
    blob = envelope.seal(plaintext, passphrase=PASSPHRASE,
                         **FAST_KDF, **fixed_salt_and_nonce(family))
    write(ROOT / family / "original.seal", blob)

    cases = []
    for region, offset in TAMPER_REGIONS.items():
        corrupted = bytearray(blob)
        corrupted[offset] ^= 0x01
        name = f"tampered-{region}.seal"
        write(ROOT / family / name, bytes(corrupted))
        cases.append({
            "region": region,
            "byteOffset": offset,
            "file": f"{family}/{name}",
        })

    return {
        "id": family,
        "description": (
            "One bit flipped in each region of the file. Every case must be "
            "rejected, and no case may return plaintext or mutate a vault."
        ),
        "kind": "open-fails",
        "original": f"{family}/original.seal",
        "passphraseUtf8Hex": PASSPHRASE.encode("utf-8").hex(),
        "cases": cases,
    }


def build_truncation_family() -> dict:
    """Files cut short at every structurally interesting offset.

    Truncation is a different failure from tampering: the bytes that survive
    are genuine, so an implementation that reads before checking length hits an
    index error rather than a message. Both are fail-closed; only one tells the
    user anything.
    """
    family = "11-truncation"
    plaintext = canonical(single_totp_vault())
    blob = envelope.seal(plaintext, passphrase=PASSPHRASE,
                         **FAST_KDF, **fixed_salt_and_nonce(family))
    write(ROOT / family / "original.seal", blob)

    offsets = {
        "empty": 0,
        "partial-magic": 3,
        "magic-only": 7,
        "mid-kdf-params": 11,
        "before-salt-length": 20,
        "mid-salt": 25,
        "before-nonce-length": 37,
        "mid-nonce": 44,
        "before-reserved": 50,
        "header-only": 52,
        "mid-ciphertext": len(blob) - 20,
        "missing-one-tag-byte": len(blob) - 1,
    }

    cases = []
    for name, length in offsets.items():
        filename = f"truncated-{name}.seal"
        write(ROOT / family / filename, blob[:length])
        cases.append({"name": name, "byteLength": length,
                      "file": f"{family}/{filename}"})

    return {
        "id": family,
        "description": (
            "The same file cut short at each structurally interesting offset. "
            "Every one must be refused with a clear error rather than an index "
            "error, a crash, or a partial read."
        ),
        "kind": "open-fails",
        "original": f"{family}/original.seal",
        "passphraseUtf8Hex": PASSPHRASE.encode("utf-8").hex(),
        "cases": cases,
    }


def build_wrong_passphrase_family() -> dict:
    family = "06-wrong-passphrase"
    plaintext = canonical(single_totp_vault())
    blob = envelope.seal(plaintext, passphrase=PASSPHRASE,
                         **FAST_KDF, **fixed_salt_and_nonce(family))
    write(ROOT / family / "impression.seal", blob)

    return {
        "id": family,
        "description": (
            "Correct file, wrong passphrase. Must fail exactly as a tampered "
            "file does — an authenticated cipher cannot tell the two apart, and "
            "an implementation that distinguishes them is leaking."
        ),
        "kind": "open-fails",
        "file": f"{family}/impression.seal",
        "cases": [
            {"reason": "wrong passphrase",
             "passphraseUtf8Hex": "not the passphrase".encode("utf-8").hex()},
            {"reason": "empty passphrase",
             "passphraseUtf8Hex": ""},
            {"reason": "correct passphrase with trailing space",
             "passphraseUtf8Hex": (PASSPHRASE + " ").encode("utf-8").hex()},
        ],
    }


def build_hostile_family() -> dict:
    family = "07-hostile-parameters"
    plaintext = canonical(empty_vault())
    blob = envelope.seal(plaintext, passphrase=PASSPHRASE,
                         **FAST_KDF, **fixed_salt_and_nonce(family))

    cases = []
    variants = [
        ("memory-1TiB", 11, (1 << 30).to_bytes(4, "big"),
         "memory above the permitted ceiling"),
        ("memory-zero", 11, (0).to_bytes(4, "big"),
         "memory below the permitted floor"),
        ("iterations-huge", 15, (0x7FFFFFFF).to_bytes(4, "big"),
         "iteration count above the permitted ceiling"),
        ("iterations-zero", 15, (0).to_bytes(4, "big"),
         "iteration count of zero"),
        ("parallelism-zero", 19, bytes([0]),
         "parallelism of zero"),
        ("parallelism-max", 19, bytes([255]),
         "parallelism above the permitted ceiling"),
    ]
    for name, offset, replacement, reason in variants:
        corrupted = bytearray(blob)
        corrupted[offset:offset + len(replacement)] = replacement
        filename = f"{name}.seal"
        write(ROOT / family / filename, bytes(corrupted))
        cases.append({"name": name, "file": f"{family}/{filename}",
                      "reason": reason})

    return {
        "id": family,
        "description": (
            "Files demanding resources outside the permitted ranges. Each must "
            "be refused before any memory is allocated and before the key "
            "derivation function is called. An implementation that attempts "
            "these will be terminated by the operating system, which a user "
            "cannot distinguish from data loss."
        ),
        "kind": "reject-before-allocation",
        "passphraseUtf8Hex": PASSPHRASE.encode("utf-8").hex(),
        "limits": {
            "kdfMemoryKiB": {"min": "8 * parallelism", "max": envelope.MAX_MEMORY_KIB},
            "kdfIterations": {"min": 1, "max": envelope.MAX_ITERATIONS},
            "kdfParallelism": {"min": 1, "max": envelope.MAX_PARALLELISM},
        },
        "cases": cases,
    }


def build_identifier_family() -> dict:
    """Identifiers, which every reader parses and nothing had checked.

    The scheme is load-bearing in two directions and neither had a vector. The
    prefix is what makes an identifier pasted into the wrong field obvious, and
    the choice of scheme per kind is what keeps a handover URL from carrying
    the time the handover was made.
    """
    family = "12-identifiers"

    valid = [
        {"id": "vlt_01J8ZKQ4T7NBVX2M9DCFGH3RWY", "kind": "vlt", "scheme": "timeOrdered"},
        {"id": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWY", "kind": "acc", "scheme": "timeOrdered"},
        {"id": "itm_01J8ZKQ4T7NBVX2M9DCFGH3RWY", "kind": "itm", "scheme": "timeOrdered"},
        {"id": "lnk_01J8ZKQ4T7NBVX2M9DCFGH3RWY", "kind": "lnk", "scheme": "timeOrdered"},
        {"id": "kpr_ZZZZZZZZZZZZZZZZZZZZZZZZZZ", "kind": "kpr", "scheme": "random"},
        {"id": "bnd_00000000000000000000000000", "kind": "bnd", "scheme": "random"},
    ]

    rejected = [
        {"id": "01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "reason": "no kind prefix, so a reader cannot tell what it names"},
        {"id": "usr_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "reason": "a kind this format does not define"},
        {"id": "acc01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "reason": "no separator between the kind and the body"},
        {"id": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RW",
         "reason": "body one character short of 128 bits"},
        {"id": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWYY",
         "reason": "body one character longer than 128 bits"},
        {"id": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWU",
         "reason": "U is the one character Crockford excludes outright rather "
                   "than mapping, so it cannot appear in a body"},
        {"id": "acc_",
         "reason": "prefix with no body"},
        {"id": "ACC_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "reason": "the kind prefix is lowercase, and matching it loosely "
                   "would let two spellings name one thing"},
    ]

    # Crockford decoding is lenient on the body precisely so a keeper
    # transcribing by hand succeeds. The same file must therefore be found by
    # the same identifier typed with the substitutions people actually make.
    equivalent = [
        {"written": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "typed": "acc_o1J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "reason": "a typed letter O is a zero"},
        {"written": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "typed": "acc_0lJ8ZKQ4T7NBVX2M9DCFGH3RWY",
         "reason": "a typed lowercase L is a one"},
        {"written": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "typed": "acc_0IJ8ZKQ4T7NBVX2M9DCFGH3RWY",
         "reason": "a typed capital I is a one"},
        {"written": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
         "typed": "acc_01j8zkq4t7nbvx2m9dcfgh3rwy",
         "reason": "the body is case-insensitive"},
    ]

    return {
        "id": family,
        "description": (
            "Identifiers of every kind, the malformed ones a reader must "
            "reject, and the transcription substitutions Crockford Base32 "
            "requires it to accept. The kind prefix is matched exactly and is "
            "always lowercase; the body is decoded leniently, because the "
            "person retyping one is a keeper working from paper."
        ),
        "kind": "identifiers",
        "bodyBits": 128,
        "bodyLength": 26,
        "kinds": {
            "timeOrdered": ["vlt", "acc", "itm", "lnk"],
            "random": ["kpr", "bnd"],
        },
        "valid": valid,
        "mustReject": rejected,
        "mustMatch": equivalent,
    }


def build_version_family() -> dict:
    family = "09-versions"
    entries = []

    plaintext = canonical(empty_vault())
    blob = envelope.seal(plaintext, passphrase=PASSPHRASE,
                         **FAST_KDF, **fixed_salt_and_nonce(family))
    write(ROOT / family / "v1.0.seal", blob)
    write(ROOT / family / "v1.0-plaintext.json", plaintext)
    entries.append({
        "version": "1.0",
        "file": f"{family}/v1.0.seal",
        "expectedPlaintext": f"{family}/v1.0-plaintext.json",
        "mustOpen": True,
    })

    # A genuinely sealed forward-minor file must open. This is the positive
    # half of the rule and cannot be produced by patching a byte, because the
    # header is authenticated.
    sealed_minor = envelope.seal(
        plaintext, passphrase=PASSPHRASE, format_minor=9,
        **FAST_KDF, **fixed_salt_and_nonce(f"{family}/minor9"))
    write(ROOT / family / "v1.9-sealed.seal", sealed_minor)
    entries.append({
        "version": "1.9",
        "file": f"{family}/v1.9-sealed.seal",
        "expectedPlaintext": f"{family}/v1.0-plaintext.json",
        "mustOpen": True,
        "note": ("Sealed with minor version 9. A reader must accept an unknown "
                 "minor version rather than refusing it, so this must open."),
    })

    # Patching the minor byte of an existing file must still fail, but on the
    # authentication tag rather than on version grounds.
    forward_minor = bytearray(blob)
    forward_minor[8] = 9
    write(ROOT / family / "v1.9-patched-minor.seal", bytes(forward_minor))
    entries.append({
        "version": "1.9",
        "file": f"{family}/v1.9-patched-minor.seal",
        "mustOpen": False,
        "failsOn": "authenticationTag",
        "note": ("The minor byte was altered after sealing. It must be rejected "
                 "because the header is authenticated, not because the version "
                 "is unknown. Both facts matter: reject it, but for the right "
                 "reason."),
    })

    forward_major = bytearray(blob)
    forward_major[7] = 2
    write(ROOT / family / "v2.0-unknown-major.seal", bytes(forward_major))
    entries.append({
        "version": "2.0",
        "file": f"{family}/v2.0-unknown-major.seal",
        "mustOpen": False,
        "note": "An unknown major version must be refused before anything else.",
    })

    return {
        "id": family,
        "description": (
            "One file per released format version. Every version ever published "
            "must remain openable by the current implementation, forever. This "
            "family grows and never shrinks."
        ),
        "kind": "versions",
        "passphraseUtf8Hex": PASSPHRASE.encode("utf-8").hex(),
        "entries": entries,
    }
