"""Sealing and opening an impression, and refusing to open a broken one."""

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


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.plaintext = sample_bytes()
        self.blob = envelope.seal(self.plaintext, passphrase=PASSPHRASE, **FAST_KDF)

    def test_round_trip(self):
        opened, header = envelope.open_impression(self.blob, passphrase=PASSPHRASE)
        self.assertEqual(opened, self.plaintext)
        self.assertEqual(header.kdf_id, envelope.KDF_ARGON2ID)
        self.assertEqual(header.aead_id, envelope.AEAD_AES_256_GCM)

    def test_header_leaks_nothing(self):
        header_length = 22 + envelope.SALT_LENGTH + envelope.NONCE_LENGTH
        header = self.blob[:header_length]
        for secret in (b"Google", b"elie", b"JBSWY3DPEHPK3PXP", b"bank"):
            self.assertNotIn(secret, header)

    def test_wrong_passphrase(self):
        with self.assertRaises(BrokenSealError):
            envelope.open_impression(self.blob, passphrase="wrong")

    def test_every_modified_region_is_detected(self):
        # One byte flipped in each region of the file.
        regions = {
            "magic": 0, "formatMajor": 7, "formatMinor": 8, "kdfId": 9,
            "aeadId": 10, "kdfMemory": 11, "kdfIterations": 15,
            "kdfParallelism": 19, "saltLen": 20, "salt": 21, "nonceLen": 37,
            "nonce": 38, "reserved": 50, "ciphertext": -20, "tag": -1,
        }
        for name, position in regions.items():
            corrupted = bytearray(self.blob)
            corrupted[position] ^= 0x01
            with self.subTest(region=name), self.assertRaises(SealstoneFormatError):
                envelope.open_impression(bytes(corrupted), passphrase=PASSPHRASE)

    def test_rejects_hostile_kdf_parameters(self):
        corrupted = bytearray(self.blob)
        corrupted[11:15] = (999_999_999).to_bytes(4, "big")
        with self.assertRaises(HostileParametersError):
            envelope.open_impression(bytes(corrupted), passphrase=PASSPHRASE)

    def test_rejects_non_impression(self):
        for data in (b"", b"PK\x03\x04", b"not a seal at all, really"):
            with self.subTest(data=data), self.assertRaises(NotAnImpressionError):
                envelope.open_impression(data, passphrase=PASSPHRASE)

    def test_rejects_future_major_version(self):
        corrupted = bytearray(self.blob)
        corrupted[7] = 99
        with self.assertRaises(UnsupportedVersionError):
            envelope.open_impression(bytes(corrupted), passphrase=PASSPHRASE)

    def test_key_based_envelope(self):
        blob = envelope.seal(self.plaintext, key=b"K" * 32)
        opened, header = envelope.open_impression(blob, key=b"K" * 32)
        self.assertEqual(opened, self.plaintext)
        self.assertEqual(header.kdf_id, envelope.KDF_NONE)

    def test_wrong_key_material_kind(self):
        blob = envelope.seal(self.plaintext, key=b"K" * 32)
        with self.assertRaises(KeyMaterialMismatchError):
            envelope.open_impression(blob, passphrase=PASSPHRASE)
        with self.assertRaises(KeyMaterialMismatchError):
            envelope.open_impression(self.blob, key=b"K" * 32)

    def test_unicode_passphrase_normalisation(self):
        composed = "café"            # é as one code point
        decomposed = "café"          # e + combining acute
        blob = envelope.seal(b"x", passphrase=composed, **FAST_KDF)
        opened, _ = envelope.open_impression(blob, passphrase=decomposed)
        self.assertEqual(opened, b"x")

    def test_reproducible_with_fixed_salt_and_nonce(self):
        args = dict(passphrase=PASSPHRASE, salt=b"S" * 16, nonce=b"N" * 12, **FAST_KDF)
        self.assertEqual(envelope.seal(b"same", **args), envelope.seal(b"same", **args))

    @unittest.skipUnless(os.environ.get("SEALSTONE_SLOW_TESTS") == "1",
                         "set SEALSTONE_SLOW_TESTS=1 to run at real parameters")
    def test_real_parameters(self):
        blob = envelope.seal(b"x", passphrase=PASSPHRASE)
        self.assertEqual(envelope.open_impression(blob, passphrase=PASSPHRASE)[0], b"x")


if __name__ == "__main__":
    unittest.main()
