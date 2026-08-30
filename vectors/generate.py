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
import json
import shutil
import sys

from _settings import ROOT, FAST_KDF, PASSPHRASE
from _documents import empty_vault, single_totp_vault, full_vault
from _opens import (build_open_family, build_nfc_family, build_shamir_family,
                    build_real_parameters_family)
from _rejects import (build_tamper_family, build_truncation_family,
                      build_wrong_passphrase_family, build_hostile_family,
                      build_identifier_family, build_version_family)


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
                          "Every item type, an authenticator of each otpType "
                          "including a five-digit Steam code, three links, one "
                          "keeper, and one item of an unknown type that must "
                          "survive a round trip untouched.",
                          full_vault(), PASSPHRASE, FAST_KDF),
        build_nfc_family(),
        build_tamper_family(),
        build_wrong_passphrase_family(),
        build_hostile_family(),
        build_shamir_family(),
        build_identifier_family(),
        build_version_family(),
        build_truncation_family(),
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

    # Sorted rather than assembled in order, because the slow family is carried
    # forward and appended last. The corpus asserts its own ordering.
    families.sort(key=lambda family: family["id"])

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
