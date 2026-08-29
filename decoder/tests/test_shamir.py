"""Splitting a secret and putting it back."""

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


class TestShamir(unittest.TestCase):
    SECRET = bytes(range(32))

    def test_every_three_of_five_subset_reconstructs(self):
        shares = shamir.split(self.SECRET, 3, 5)
        subsets = list(itertools.combinations(shares, 3))
        self.assertEqual(len(subsets), 10)
        for subset in subsets:
            self.assertEqual(shamir.combine(list(subset)), self.SECRET)

    def test_more_than_threshold_also_works(self):
        shares = shamir.split(self.SECRET, 3, 5)
        self.assertEqual(shamir.combine(shares[:4]), self.SECRET)
        self.assertEqual(shamir.combine(shares), self.SECRET)

    def test_below_threshold_reveals_nothing(self):
        shares = shamir.split(self.SECRET, 3, 5)
        for subset in itertools.combinations(shares, 2):
            self.assertNotEqual(shamir.combine(list(subset)), self.SECRET)

    def test_exhaustive_field_arithmetic(self):
        # The field has 256 elements, so every multiplication can be checked.
        for a in range(256):
            for b in range(1, 256):
                self.assertEqual(shamir._div(shamir._mul(a, b), b), a)

    def test_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            shamir.split(self.SECRET, 1, 5)          # threshold below 2
        with self.assertRaises(ValueError):
            shamir.split(self.SECRET, 6, 5)          # threshold above shares
        with self.assertRaises(ValueError):
            shamir.split(b"", 3, 5)                  # empty secret
        with self.assertRaises(ValueError):
            shamir.combine([(0, b"\x01"), (2, b"\x02")])   # index zero
        with self.assertRaises(ValueError):
            shamir.combine([(1, b"\x01"), (1, b"\x02")])   # duplicate index


if __name__ == "__main__":
    unittest.main()
