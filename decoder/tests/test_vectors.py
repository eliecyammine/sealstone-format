"""Runs the vector corpus in `vectors/` against the decoder.

This is the conformance suite. Any implementation of the format has to pass the
same families, so this file doubles as the executable definition of what
"implements Sealstone Format v1" means.

Set SEALSTONE_SLOW_TESTS=1 to include families marked slow.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from itertools import combinations
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealstone_format import envelope, shamir, vault  # noqa: E402
from sealstone_format.errors import (  # noqa: E402
    HostileParametersError,
    SealstoneFormatError,
)

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
RUN_SLOW = os.environ.get("SEALSTONE_SLOW_TESTS") == "1"


def load_manifest() -> dict:
    return json.loads((VECTORS / "manifest.json").read_text())


def families_of_kind(kind: str) -> list[dict]:
    return [f for f in load_manifest()["families"] if f["kind"] == kind]


def passphrase_of(entry: dict, key: str = "passphraseUtf8Hex") -> str:
    return bytes.fromhex(entry[key]).decode("utf-8")


class TestCorpusIntegrity(unittest.TestCase):
    """The corpus must be complete and self-describing before it is trusted."""

    def test_manifest_exists_and_declares_version(self):
        manifest = load_manifest()
        self.assertEqual(manifest["formatVersion"], 1)
        self.assertGreaterEqual(len(manifest["families"]), 9)

    def test_every_referenced_file_exists(self):
        missing = []
        for family in load_manifest()["families"]:
            for value in _all_file_paths(family):
                if not (VECTORS / value).exists():
                    missing.append(value)
        self.assertEqual(missing, [], f"manifest references missing files: {missing}")

    def test_family_ids_are_unique_and_ordered(self):
        ids = [f["id"] for f in load_manifest()["families"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))


def _all_file_paths(node) -> list[str]:
    """Every value in the manifest that names a file."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("file", "original", "expectedPlaintext") and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_all_file_paths(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_all_file_paths(item))
    return found


class TestOpenSucceeds(unittest.TestCase):
    def test_families_open_to_expected_plaintext(self):
        for family in families_of_kind("open-succeeds"):
            if family.get("slow") and not RUN_SLOW:
                continue
            with self.subTest(family=family["id"]):
                blob = (VECTORS / family["file"]).read_bytes()
                expected = (VECTORS / family["expectedPlaintext"]).read_bytes()

                plaintext, header = envelope.open_impression(
                    blob, passphrase=passphrase_of(family))

                self.assertEqual(plaintext, expected)

                # The declared header must match what a parser actually sees.
                declared = family["expectedHeader"]
                self.assertEqual(header.format_major, declared["formatMajor"])
                self.assertEqual(header.kdf_id, declared["kdfId"])
                self.assertEqual(header.aead_id, declared["aeadId"])
                self.assertEqual(header.kdf_memory_kib, declared["kdfMemoryKiB"])
                self.assertEqual(header.kdf_iterations, declared["kdfIterations"])
                self.assertEqual(header.kdf_parallelism, declared["kdfParallelism"])

                # The plaintext must also be a valid vault document.
                vault.parse(plaintext)

    def test_nfc_equivalent_passphrases_all_open(self):
        for family in families_of_kind("open-succeeds"):
            for spelling in family.get("equivalentPassphrasesUtf8Hex", []):
                with self.subTest(family=family["id"], passphrase=spelling[:16]):
                    blob = (VECTORS / family["file"]).read_bytes()
                    expected = (VECTORS / family["expectedPlaintext"]).read_bytes()
                    plaintext, _ = envelope.open_impression(
                        blob, passphrase=bytes.fromhex(spelling).decode("utf-8"))
                    self.assertEqual(plaintext, expected)

    def test_full_vault_preserves_unknown_item_type(self):
        family = next(f for f in families_of_kind("open-succeeds")
                      if f["id"] == "03-full-vault")
        blob = (VECTORS / family["file"]).read_bytes()
        plaintext, _ = envelope.open_impression(blob, passphrase=passphrase_of(family))
        document = vault.parse(plaintext)

        future = [i for i in document["items"] if i["type"] == "typeFromTheFuture"]
        self.assertEqual(len(future), 1)
        self.assertEqual(future[0]["unknownField"], {"nested": [1, 2, 3]})


class TestOpenFails(unittest.TestCase):
    def test_every_tampered_region_is_rejected(self):
        family = next(f for f in families_of_kind("open-fails") if "cases" in f
                      and f["id"] == "05-tamper")
        passphrase = passphrase_of(family)

        # The untampered original must still open, or the family proves nothing.
        original = (VECTORS / family["original"]).read_bytes()
        envelope.open_impression(original, passphrase=passphrase)

        for case in family["cases"]:
            with self.subTest(region=case["region"]):
                blob = (VECTORS / case["file"]).read_bytes()
                with self.assertRaises(SealstoneFormatError):
                    envelope.open_impression(blob, passphrase=passphrase)

    def test_tamper_family_covers_the_whole_file(self):
        family = next(f for f in families_of_kind("open-fails")
                      if f["id"] == "05-tamper")
        regions = {c["region"] for c in family["cases"]}
        required = {"magic", "formatMajor", "formatMinor", "kdfId", "aeadId",
                    "kdfMemory", "kdfIterations", "kdfParallelism",
                    "saltLen", "salt", "nonceLen", "nonce", "reserved",
                    "ciphertext", "tag"}
        self.assertEqual(required - regions, set(),
                         "tamper family does not cover every region of the file")

    def test_wrong_passphrases_are_rejected(self):
        family = next(f for f in families_of_kind("open-fails")
                      if f["id"] == "06-wrong-passphrase")
        blob = (VECTORS / family["file"]).read_bytes()
        for case in family["cases"]:
            with self.subTest(reason=case["reason"]):
                with self.assertRaises(SealstoneFormatError):
                    envelope.open_impression(
                        blob, passphrase=passphrase_of(case))


class TestRejectBeforeAllocation(unittest.TestCase):
    def test_hostile_parameters_are_refused(self):
        for family in families_of_kind("reject-before-allocation"):
            passphrase = passphrase_of(family)
            for case in family["cases"]:
                with self.subTest(case=case["name"]):
                    blob = (VECTORS / case["file"]).read_bytes()
                    # HostileParametersError specifically: these must be caught
                    # by range checks, not by a failed derivation or a crash.
                    with self.assertRaises(HostileParametersError):
                        envelope.open_impression(blob, passphrase=passphrase)

    def test_declared_limits_match_the_implementation(self):
        family = families_of_kind("reject-before-allocation")[0]
        limits = family["limits"]
        self.assertEqual(limits["kdfMemoryKiB"]["max"], envelope.MAX_MEMORY_KIB)
        self.assertEqual(limits["kdfIterations"]["max"], envelope.MAX_ITERATIONS)
        self.assertEqual(limits["kdfParallelism"]["max"], envelope.MAX_PARALLELISM)


class TestShamirVectors(unittest.TestCase):
    def test_declared_subsets_reconstruct(self):
        for family in families_of_kind("shamir"):
            secret = bytes.fromhex(family["secretHex"])
            shares = {s["index"]: bytes.fromhex(s["shareHex"])
                      for s in family["shares"]}

            for subset in family["mustReconstruct"]:
                with self.subTest(family=family["id"], subset=subset):
                    pairs = [(i, shares[i]) for i in subset]
                    self.assertEqual(shamir.combine(pairs), secret)

            for subset in family["mustNotReconstruct"]:
                with self.subTest(family=family["id"], insufficient=subset):
                    pairs = [(i, shares[i]) for i in subset]
                    self.assertNotEqual(shamir.combine(pairs), secret)

    def test_declared_subsets_are_exhaustive(self):
        for family in families_of_kind("shamir"):
            indices = [s["index"] for s in family["shares"]]
            expected = [list(c) for c in combinations(indices, family["threshold"])]
            self.assertEqual(family["mustReconstruct"], expected,
                             "every threshold-sized subset must be listed")


class TestVersionVectors(unittest.TestCase):
    def test_every_released_version_still_opens(self):
        for family in families_of_kind("versions"):
            passphrase = passphrase_of(family)
            for entry in family["entries"]:
                with self.subTest(version=entry["version"]):
                    blob = (VECTORS / entry["file"]).read_bytes()
                    if entry["mustOpen"]:
                        plaintext, _ = envelope.open_impression(
                            blob, passphrase=passphrase)
                        expected = (VECTORS / entry["expectedPlaintext"]).read_bytes()
                        self.assertEqual(plaintext, expected)
                    else:
                        with self.assertRaises(SealstoneFormatError):
                            envelope.open_impression(blob, passphrase=passphrase)

    def test_forward_minor_version_is_accepted(self):
        family = families_of_kind("versions")[0]
        opening = [e for e in family["entries"]
                   if e["version"] == "1.9" and e["mustOpen"]]
        self.assertTrue(opening, "no positive forward-minor vector in the corpus")

        for entry in opening:
            blob = (VECTORS / entry["file"]).read_bytes()
            plaintext, header = envelope.open_impression(
                blob, passphrase=passphrase_of(family))
            self.assertEqual(header.format_minor, 9)
            expected = (VECTORS / entry["expectedPlaintext"]).read_bytes()
            self.assertEqual(plaintext, expected)

    def test_patched_minor_fails_on_the_tag_not_the_version(self):
        from sealstone_format.errors import BrokenSealError, UnsupportedVersionError

        family = families_of_kind("versions")[0]
        entry = next(e for e in family["entries"]
                     if e.get("failsOn") == "authenticationTag")
        blob = (VECTORS / entry["file"]).read_bytes()

        with self.assertRaises(BrokenSealError):
            envelope.open_impression(blob, passphrase=passphrase_of(family))

        # Specifically not a version refusal — the minor version is legal.
        try:
            envelope.open_impression(blob, passphrase=passphrase_of(family))
        except UnsupportedVersionError:
            self.fail("a legal minor version was refused on version grounds")
        except BrokenSealError:
            pass

    def test_unknown_major_is_refused_on_version_grounds(self):
        family = families_of_kind("versions")[0]
        entry = next(e for e in family["entries"] if e["version"] == "2.0")
        blob = (VECTORS / entry["file"]).read_bytes()

        from sealstone_format.errors import UnsupportedVersionError
        with self.assertRaises(UnsupportedVersionError):
            envelope.open_impression(blob, passphrase=passphrase_of(family))


if __name__ == "__main__":
    unittest.main(verbosity=2)
