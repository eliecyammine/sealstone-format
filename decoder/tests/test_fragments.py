"""Splitting a key into fragments, on paper and in binary."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealstone_format import envelope, fragment, otp, shamir  # noqa: E402
from sealstone_format.encoding import b32_decode  # noqa: E402
from sealstone_format.errors import SealstoneFormatError  # noqa: E402


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

    def test_rewording_the_sheet_does_not_break_reading_it(self):
        # Payload lines are recognised by shape, not by matching the prose
        # around them, so the sheet's wording can change freely.
        index, share = self.shares[2]
        sheet = fragment.to_paper(self.SET_ID, index, 3, 5, share)
        reworded = (sheet
                    .replace("open it together", "unlock it as a group")
                    .replace("To open what it protects", "Between you"))
        self.assertEqual(fragment.from_paper(reworded)["share"], share)

    def test_set_line_is_not_mistaken_for_payload(self):
        index, share = self.shares[0]
        sheet = fragment.to_paper(self.SET_ID, index, 3, 5, share, holder="Sara")
        self.assertEqual(fragment.from_paper(sheet)["share"], share)

    def test_rejects_text_with_no_fragment(self):
        with self.assertRaises(fragment.FragmentError):
            fragment.from_paper("just some notes\nnothing here\n")


class TestKeeperPathEndToEnd(unittest.TestCase):
    """Fragments to key to open bundle, the whole way through.

    This is the path a keeper walks, and until the CLI could take a raw key it
    stopped one step short: `combine` printed a key and `open` had no way to
    accept one. Each half was tested and the join was not, which is how a
    procedure passes its tests and fails the only time anybody runs it.
    """

    def bundle(self, key: bytes) -> bytes:
        document = {
            "formatVersion": 1,
            "vaultId": "vlt_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
            "createdAt": "2026-08-24T10:00:00Z",
            "updatedAt": "2026-08-24T10:00:00Z",
            "accounts": [{"id": "acc_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
                          "service": "Bank", "identifier": "elie",
                          "createdAt": "2026-08-24T10:00:00Z"}],
            "items": [], "links": [], "keepers": [],
            "handover": {"bundleId": "bnd_00000000000000000000000000",
                         "setId": "4F3A9C21" + "00" * 12,
                         "threshold": 3, "total": 5,
                         "sealedAt": "2026-08-24T10:00:00Z",
                         "note": "For the family."},
        }
        return envelope.seal(json.dumps(document).encode(), key=key)

    def test_three_fragments_reopen_the_bundle(self):
        key = bytes(range(32))
        sealed = self.bundle(key)

        stream = iter(bytes(range(256)) * 32)
        shares = shamir.split(key, 3, 5, rng=lambda: next(stream))

        recovered = shamir.combine(shares[:3])
        self.assertEqual(recovered, key)

        plaintext, _ = envelope.open_impression(sealed, key=recovered)
        document = json.loads(plaintext)
        self.assertEqual(document["handover"]["threshold"], 3)
        self.assertEqual(document["accounts"][0]["service"], "Bank")

    def test_two_fragments_do_not_open_it(self):
        key = bytes(range(32))
        sealed = self.bundle(key)

        stream = iter(bytes(range(256)) * 32)
        shares = shamir.split(key, 3, 5, rng=lambda: next(stream))

        wrong = shamir.combine(shares[:2])
        self.assertNotEqual(wrong, key)
        with self.assertRaises(SealstoneFormatError):
            envelope.open_impression(sealed, key=wrong)

    def test_a_bundle_declares_itself_a_bundle(self):
        """One key tells a reader which of the two documents it is holding."""
        key = bytes(range(32))
        plaintext, _ = envelope.open_impression(self.bundle(key), key=key)
        document = json.loads(plaintext)

        self.assertIn("handover", document)
        self.assertEqual(document["keepers"], [],
                         "a bundle must not tell each keeper who the others are")


if __name__ == "__main__":
    unittest.main()
