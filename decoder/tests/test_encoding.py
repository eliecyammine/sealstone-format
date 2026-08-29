"""Base32 and the paper alphabet."""

from __future__ import annotations

import itertools
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealstone_format import envelope, shamir, vault  # noqa: E402
from sealstone_format import aes, argon2, encoding  # noqa: E402
from sealstone_format.errors import (  # noqa: E402
    BrokenSealError,
    HostileParametersError,
    InvalidVaultError,
    KeyMaterialMismatchError,
    NotAnImpressionError,
    SealstoneFormatError,
    UnsupportedVersionError,
)
from tests.support import FAST_KDF, PASSPHRASE, sample_document, sample_bytes  # noqa: F401


class TestEncoding(unittest.TestCase):
    def test_crockford_round_trip(self):
        for length in (1, 5, 16, 32, 33):
            data = bytes(range(length))
            self.assertEqual(
                encoding.crockford_decode(encoding.crockford_encode(data))[:length],
                data)

    def test_crockford_maps_confusable_characters(self):
        self.assertEqual(encoding.crockford_decode("HIJK"),
                         encoding.crockford_decode("h1jk"))
        self.assertEqual(encoding.crockford_decode("0AB"),
                         encoding.crockford_decode("oab"))

    def test_crockford_ignores_separators(self):
        self.assertEqual(encoding.crockford_decode("ABCDE FGHJK"),
                         encoding.crockford_decode("ABCDE-FGHJK"))

    def test_crockford_alphabet_omits_confusables(self):
        for char in "ILOU":
            self.assertNotIn(char, encoding.CROCKFORD_ALPHABET)

    def test_rfc4648_round_trip(self):
        for data in (b"", b"a", b"secret!!", bytes(range(20))):
            self.assertEqual(
                encoding.b32_decode(encoding.b32_encode(data))[:len(data)], data)

    def test_rfc4648_known_value(self):
        # The secret used throughout the sample document.
        self.assertEqual(encoding.b32_decode("JBSWY3DPEHPK3PXP"),
                         b"Hello!\xde\xad\xbe\xef")

    def test_rejects_invalid_characters(self):
        with self.assertRaises(ValueError):
            encoding.b32_decode("ABC!DEF")


if __name__ == "__main__":
    unittest.main()
