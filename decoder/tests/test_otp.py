"""Generating one-time codes."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealstone_format import envelope, fragment, otp, shamir  # noqa: E402
from sealstone_format.encoding import b32_decode  # noqa: E402
from sealstone_format.errors import SealstoneFormatError  # noqa: E402


class TestHOTP(unittest.TestCase):
    """RFC 4226 Appendix D."""

    SECRET = b"12345678901234567890"
    EXPECTED = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]

    def test_rfc4226_vectors(self):
        for counter, expected in enumerate(self.EXPECTED):
            with self.subTest(counter=counter):
                self.assertEqual(otp.hotp(self.SECRET, counter), expected)

    def test_rejects_bad_arguments(self):
        with self.assertRaises(ValueError):
            otp.hotp(self.SECRET, 0, digits=5)
        with self.assertRaises(ValueError):
            otp.hotp(self.SECRET, 0, digits=11)
        with self.assertRaises(ValueError):
            otp.hotp(self.SECRET, -1)
        with self.assertRaises(ValueError):
            otp.hotp(self.SECRET, 0, algorithm="MD5")


class TestTOTP(unittest.TestCase):
    """RFC 6238 Appendix B. Each algorithm uses a different seed length."""

    SEEDS = {
        "SHA1": b"12345678901234567890",
        "SHA256": b"12345678901234567890123456789012",
        "SHA512": b"1234567890123456789012345678901234567890"
                  b"123456789012345678901234",
    }

    VECTORS = [
        (59, {"SHA1": "94287082", "SHA256": "46119246", "SHA512": "90693936"}),
        (1111111109, {"SHA1": "07081804", "SHA256": "68084774", "SHA512": "25091201"}),
        (1111111111, {"SHA1": "14050471", "SHA256": "67062674", "SHA512": "99943326"}),
        (1234567890, {"SHA1": "89005924", "SHA256": "91819424", "SHA512": "93441116"}),
        (2000000000, {"SHA1": "69279037", "SHA256": "90698825", "SHA512": "38618901"}),
        (20000000000, {"SHA1": "65353130", "SHA256": "77737706", "SHA512": "47863826"}),
    ]

    def test_rfc6238_vectors(self):
        for timestamp, expected in self.VECTORS:
            for algorithm, code in expected.items():
                with self.subTest(t=timestamp, algorithm=algorithm):
                    self.assertEqual(
                        otp.totp(self.SEEDS[algorithm], at=timestamp,
                                 digits=8, algorithm=algorithm),
                        code)

    def test_code_is_stable_within_its_period(self):
        secret = self.SEEDS["SHA1"]
        base = 1234567890 - (1234567890 % 30)
        first = otp.totp(secret, at=base)
        self.assertEqual(otp.totp(secret, at=base + 29), first)
        self.assertNotEqual(otp.totp(secret, at=base + 30), first)

    def test_seconds_remaining(self):
        self.assertAlmostEqual(otp.seconds_remaining(at=1000), 20.0)
        self.assertAlmostEqual(otp.seconds_remaining(at=1020), 30.0)


class TestSteam(unittest.TestCase):
    def test_shape(self):
        code = otp.steam(b"12345678901234567890", at=1234567890)
        self.assertEqual(len(code), 5)
        for character in code:
            self.assertIn(character, otp.STEAM_ALPHABET)

    def test_alphabet_omits_confusable_characters(self):
        for character in "01IOL":
            self.assertNotIn(character, otp.STEAM_ALPHABET)


class TestGenerateFromVaultItem(unittest.TestCase):
    """A recovered vault must yield codes, not just secrets."""

    ITEM = {
        "type": "authenticator", "secret": "GEZDGNBVGY3TQOJQ",
        "algorithm": "SHA1", "digits": 6, "period": 30,
        "counter": None, "otpType": "totp",
    }

    def test_totp_item(self):
        secret = b32_decode(self.ITEM["secret"])
        self.assertEqual(otp.generate(self.ITEM, at=1234567890),
                         otp.totp(secret, at=1234567890))

    def test_hotp_item_uses_its_counter(self):
        item = dict(self.ITEM, otpType="hotp", counter=5)
        secret = b32_decode(item["secret"])
        self.assertEqual(otp.generate(item), otp.hotp(secret, 5))

    def test_steam_item(self):
        item = dict(self.ITEM, otpType="steam")
        self.assertEqual(len(otp.generate(item, at=1234567890)), 5)

    def test_rejects_non_authenticator(self):
        with self.assertRaises(ValueError):
            otp.generate({"type": "note"})

    def test_rejects_unknown_otp_type(self):
        with self.assertRaises(ValueError):
            otp.generate(dict(self.ITEM, otpType="magic"))


if __name__ == "__main__":
    unittest.main()
