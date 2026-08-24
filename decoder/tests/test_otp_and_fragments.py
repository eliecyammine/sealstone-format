"""One-time passwords and fragment containers."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealstone_format import fragment, otp, shamir  # noqa: E402
from sealstone_format.encoding import b32_decode  # noqa: E402


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


class TestFragmentBinary(unittest.TestCase):
    SET_ID = bytes(range(16))

    def setUp(self):
        self.shares = shamir.split(bytes(range(32)), 3, 5)

    def test_round_trip(self):
        index, share = self.shares[1]
        blob = fragment.encode(self.SET_ID, index, 3, 5, share)
        decoded = fragment.decode(blob)

        self.assertEqual(decoded["set_id"], self.SET_ID)
        self.assertEqual(decoded["index"], index)
        self.assertEqual(decoded["threshold"], 3)
        self.assertEqual(decoded["total"], 5)
        self.assertEqual(decoded["share"], share)

    def test_checksum_catches_a_changed_byte(self):
        blob = bytearray(fragment.encode(self.SET_ID, 1, 3, 5, self.shares[0][1]))
        for position in (8, 24, 30, len(blob) - 6):
            corrupted = bytearray(blob)
            corrupted[position] ^= 0x01
            with self.subTest(position=position):
                with self.assertRaises(fragment.FragmentError):
                    fragment.decode(bytes(corrupted))

    def test_rejects_truncated(self):
        blob = fragment.encode(self.SET_ID, 1, 3, 5, self.shares[0][1])
        for length in (0, 10, len(blob) - 1):
            with self.subTest(length=length):
                with self.assertRaises(fragment.FragmentError):
                    fragment.decode(blob[:length])

    def test_rejects_foreign_data(self):
        with self.assertRaises(fragment.FragmentError):
            fragment.decode(b"SEALSTN" + b"\x00" * 40)

    def test_rejects_bad_parameters(self):
        share = self.shares[0][1]
        with self.assertRaises(fragment.FragmentError):
            fragment.encode(b"short", 1, 3, 5, share)
        with self.assertRaises(fragment.FragmentError):
            fragment.encode(self.SET_ID, 0, 3, 5, share)
        with self.assertRaises(fragment.FragmentError):
            fragment.encode(self.SET_ID, 1, 6, 5, share)
        with self.assertRaises(fragment.FragmentError):
            fragment.encode(self.SET_ID, 1, 3, 5, b"")


class TestFragmentPaper(unittest.TestCase):
    SET_ID = bytes(range(16))

    def setUp(self):
        self.secret = bytes(range(32))
        self.shares = shamir.split(self.secret, 3, 5)

    def test_whole_sheet_can_be_pasted_back(self):
        index, share = self.shares[1]
        sheet = fragment.to_paper(self.SET_ID, index, 3, 5, share, holder="Sara")
        decoded = fragment.from_paper(sheet)
        self.assertEqual(decoded["share"], share)
        self.assertEqual(decoded["index"], index)

    def test_survives_case_and_confusable_characters(self):
        index, share = self.shares[0]
        sheet = fragment.to_paper(self.SET_ID, index, 3, 5, share)
        mangled = sheet.replace("O", "0").replace("I", "1").lower()
        self.assertEqual(fragment.from_paper(mangled)["share"], share)

    def test_sheet_states_the_threshold_in_words(self):
        sheet = fragment.to_paper(self.SET_ID, 2, 3, 5, self.shares[1][1])
        self.assertIn("fragment 2 of 5", sheet)
        self.assertIn("any 3", sheet)
        self.assertIn("opens nothing", sheet)
        self.assertIn("no expiry", sheet)

    def test_three_sheets_reconstruct_the_key(self):
        sheets = [fragment.to_paper(self.SET_ID, index, 3, 5, share)
                  for index, share in self.shares]
        recovered = []
        for sheet in sheets[:3]:
            decoded = fragment.from_paper(sheet)
            recovered.append((decoded["index"], decoded["share"]))
        self.assertEqual(shamir.combine(recovered), self.secret)

    def test_two_sheets_do_not(self):
        sheets = [fragment.to_paper(self.SET_ID, index, 3, 5, share)
                  for index, share in self.shares]
        recovered = []
        for sheet in sheets[:2]:
            decoded = fragment.from_paper(sheet)
            recovered.append((decoded["index"], decoded["share"]))
        self.assertNotEqual(shamir.combine(recovered), self.secret)

    def test_rejects_text_with_no_fragment(self):
        with self.assertRaises(fragment.FragmentError):
            fragment.from_paper("just some notes\nnothing here\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
