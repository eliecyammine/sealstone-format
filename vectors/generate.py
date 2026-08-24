#!/usr/bin/env python3
"""Regenerate the test vector corpus.

    python3 vectors/generate.py            # skips the slow family
    python3 vectors/generate.py --all      # includes it, takes a few minutes

Output is deterministic: salts, nonces and Shamir coefficients are derived from
each family's identifier, so regenerating produces byte-identical files. A diff
in `git status` after running this means something changed in the encoder.

Passphrases and expected plaintexts are stored as hex so no consumer has to
guess how a file was encoded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "decoder"))

from sealstone_format import envelope, shamir  # noqa: E402

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


# ---------------------------------------------------------------- documents


def empty_vault() -> dict:
    return {
        "formatVersion": 1,
        "vaultId": "00000000-0000-4000-8000-000000000001",
        "createdAt": "2026-08-24T00:00:00Z",
        "updatedAt": "2026-08-24T00:00:00Z",
        "accounts": [],
        "items": [],
        "links": [],
        "keepers": [],
    }


def single_totp_vault() -> dict:
    document = empty_vault()
    document["vaultId"] = "00000000-0000-4000-8000-000000000002"
    document["accounts"] = [{
        "id": "acc_example", "service": "Example", "identifier": "user@example.com",
        "domain": "example.com", "tags": [], "notes": None,
        "createdAt": "2026-08-24T00:00:00Z",
    }]
    document["items"] = [{
        "id": "itm_totp", "accountId": "acc_example", "type": "authenticator",
        "favorite": False, "ordering": 0,
        "createdAt": "2026-08-24T00:00:00Z", "modifiedAt": "2026-08-24T00:00:00Z",
        "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6,
        "period": 30, "counter": None, "otpType": "totp",
    }]
    return document


def full_vault() -> dict:
    """Every item type, both link directions, keepers, and an unknown type.

    The unknown type is the forward-compatibility check: a decoder must carry it
    through a round trip untouched rather than dropping it.
    """
    document = empty_vault()
    document["vaultId"] = "00000000-0000-4000-8000-000000000003"
    document["accounts"] = [
        {"id": "acc_mail", "service": "Mail", "identifier": "user@example.com",
         "domain": "mail.example", "tags": ["email", "keystone"], "notes": None,
         "createdAt": "2026-08-24T00:00:00Z"},
        {"id": "acc_bank", "service": "Bank", "identifier": "user",
         "domain": "bank.example", "tags": ["finance"], "notes": None,
         "createdAt": "2026-08-24T00:00:00Z"},
        {"id": "acc_wallet", "service": "Wallet", "identifier": "main",
         "domain": None, "tags": [], "notes": None,
         "createdAt": "2026-08-24T00:00:00Z"},
    ]
    document["items"] = [
        {"id": "itm_totp", "accountId": "acc_mail", "type": "authenticator",
         "favorite": True, "ordering": 0,
         "createdAt": "2026-08-24T00:00:00Z", "modifiedAt": "2026-08-24T00:00:00Z",
         "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA256", "digits": 8,
         "period": 60, "counter": None, "otpType": "totp"},
        {"id": "itm_hotp", "accountId": "acc_bank", "type": "authenticator",
         "favorite": False, "ordering": 1,
         "createdAt": "2026-08-24T00:00:00Z", "modifiedAt": "2026-08-24T00:00:00Z",
         "secret": "GEZDGNBVGY3TQOJQ", "algorithm": "SHA1", "digits": 6,
         "period": 30, "counter": 7, "otpType": "hotp"},
        {"id": "itm_codes", "accountId": "acc_bank", "type": "recoveryCodes",
         "createdAt": "2026-08-24T00:00:00Z",
         "codes": [{"code": "aaaa-bbbb", "used": False, "usedAt": None},
                   {"code": "cccc-dddd", "used": True,
                    "usedAt": "2026-08-01T00:00:00Z"}]},
        {"id": "itm_contact", "accountId": "acc_mail", "type": "recoveryContact",
         "createdAt": "2026-08-24T00:00:00Z",
         "channel": "email", "value": "backup@example.com"},
        {"id": "itm_questions", "accountId": "acc_bank", "type": "securityQuestions",
         "createdAt": "2026-08-24T00:00:00Z",
         "questions": [{"question": "First pet?", "answer": "redacted"}]},
        {"id": "itm_seed", "accountId": "acc_wallet", "type": "seedPhrase",
         "createdAt": "2026-08-24T00:00:00Z",
         "words": ["abandon"] * 11 + ["about"],
         "wordlist": "BIP39-english", "passphrase": None},
        {"id": "itm_key", "accountId": "acc_bank", "type": "hardwareKey",
         "createdAt": "2026-08-24T00:00:00Z",
         "label": "Blue key", "serial": "0000001", "keyType": "fido2"},
        {"id": "itm_note", "accountId": "acc_wallet", "type": "note",
         "createdAt": "2026-08-24T00:00:00Z",
         "title": "Where the hardware wallet lives", "body": "Second drawer."},
        {"id": "itm_future", "accountId": "acc_mail", "type": "typeFromTheFuture",
         "createdAt": "2026-08-24T00:00:00Z",
         "unknownField": {"nested": [1, 2, 3]}},
    ]
    document["links"] = [
        {"id": "lnk_mail_bank", "sourceAccountId": "acc_mail",
         "targetAccountId": "acc_bank", "method": "email",
         "verifiedAt": "2026-08-24T00:00:00Z", "note": None},
        {"id": "lnk_mail_wallet", "sourceAccountId": "acc_mail",
         "targetAccountId": "acc_wallet", "method": "email",
         "verifiedAt": None, "note": "unverified"},
        {"id": "lnk_bank_mail", "sourceAccountId": "acc_bank",
         "targetAccountId": "acc_mail", "method": "sms",
         "verifiedAt": None, "note": None},
    ]
    document["keepers"] = [{
        "id": "kpr_1", "displayName": "Keeper One", "contact": "one@example.com",
        "bundleId": "bnd_1", "fragmentIndex": 1,
        "issuedAt": "2026-08-24T00:00:00Z", "lastConfirmedAt": None,
        "status": "active",
    }]
    return document


def canonical(document: dict) -> bytes:
    """Stable JSON encoding so regeneration is byte-identical."""
    return json.dumps(document, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------- families


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


# ---------------------------------------------------------------- entry point


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true",
                        help="include the slow real-parameters family")
    args = parser.parse_args()

    # Without --all the slow family is not rebuilt, so its files must survive.
    # Deleting them here would mean a casual regeneration destroys part of the
    # corpus and breaks the determinism check in CI.
    for existing in sorted(ROOT.glob("[0-9][0-9]-*")):
        if existing.is_dir():
            if not args.all and existing.name == "10-real-parameters":
                continue
            shutil.rmtree(existing)

    families = [
        build_open_family("01-empty-vault",
                          "A valid vault with no accounts, items or links.",
                          empty_vault(), PASSPHRASE, FAST_KDF),
        build_open_family("02-single-totp",
                          "One account with one TOTP authenticator.",
                          single_totp_vault(), PASSPHRASE, FAST_KDF),
        build_open_family("03-full-vault",
                          "Every item type, three links, one keeper, and one "
                          "item of an unknown type that must survive a round "
                          "trip untouched.",
                          full_vault(), PASSPHRASE, FAST_KDF),
        build_nfc_family(),
        build_tamper_family(),
        build_wrong_passphrase_family(),
        build_hostile_family(),
        build_shamir_family(),
        build_version_family(),
    ]

    if args.all:
        print("Generating the slow family. This takes a few minutes.",
              file=sys.stderr)
        families.append(build_real_parameters_family())
    else:
        # Carry the existing entry forward unchanged so the manifest keeps
        # describing the files that are still on disk.
        carried = None
        manifest_path = ROOT / "manifest.json"
        if manifest_path.exists():
            for family in json.loads(manifest_path.read_text())["families"]:
                if family["id"] == "10-real-parameters":
                    carried = family
        if carried is not None:
            families.append(carried)
            print("Kept 10-real-parameters as-is. Use --all to regenerate it.",
                  file=sys.stderr)
        else:
            print("10-real-parameters is missing. Run with --all before "
                  "committing.", file=sys.stderr)

    manifest = {
        "formatVersion": 1,
        "corpusVersion": 1,
        "description": (
            "Test vectors for Sealstone Format v1. Any implementation claiming "
            "to read or write this format must pass every family here. "
            "Passphrases and secrets are hex-encoded so no consumer has to "
            "guess an encoding."
        ),
        "families": families,
    }

    manifest_path = ROOT / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

    print(f"Wrote {len(families)} families to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
