"""What a vault document may contain, and what it may not."""

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


class TestVaultDocument(unittest.TestCase):
    def test_valid_document(self):
        self.assertEqual(vault.parse(sample_bytes())["vaultId"],
                         sample_document()["vaultId"])

    def test_unknown_item_type_is_preserved(self):
        parsed = vault.parse(sample_bytes())
        self.assertTrue(any(i["type"] == "somethingFromTheFuture"
                            for i in parsed["items"]))

    def test_dangling_references_rejected(self):
        document = sample_document()
        document["items"][0]["accountId"] = "acc_does_not_exist"
        with self.assertRaises(InvalidVaultError):
            vault.validate(document)

    def test_duplicate_ids_rejected(self):
        document = sample_document()
        document["items"][1]["id"] = document["items"][0]["id"]
        with self.assertRaises(InvalidVaultError):
            vault.validate(document)

    def test_duplicate_link_ids_rejected(self):
        document = sample_document()
        document["links"].append(dict(document["links"][0]))
        with self.assertRaises(InvalidVaultError):
            vault.validate(document)

    def test_duplicate_keeper_ids_rejected(self):
        document = sample_document()
        keeper = {"id": "kpr_1", "displayName": "Sara",
                  "contact": "sara@example.com", "bundleId": "bnd_1",
                  "fragmentIndex": 1, "issuedAt": "2026-08-24T10:00:00Z",
                  "lastConfirmedAt": None, "status": "active"}
        document["keepers"] = [keeper, dict(keeper)]
        with self.assertRaises(InvalidVaultError):
            vault.validate(document)

    def test_hotp_requires_counter(self):
        document = sample_document()
        document["items"][0]["otpType"] = "hotp"
        with self.assertRaises(InvalidVaultError):
            vault.validate(document)

    def test_totp_rejects_counter(self):
        document = sample_document()
        document["items"][0]["counter"] = 5
        with self.assertRaises(InvalidVaultError):
            vault.validate(document)

    def test_out_of_range_digits(self):
        for digits in (5, 11, "6", None):
            document = sample_document()
            document["items"][0]["digits"] = digits
            with self.subTest(digits=digits), self.assertRaises(InvalidVaultError):
                vault.validate(document)

    def test_invalid_base32_secret(self):
        document = sample_document()
        document["items"][0]["secret"] = "not-base32!"
        with self.assertRaises(InvalidVaultError):
            vault.validate(document)

    def test_bad_json(self):
        with self.assertRaises(InvalidVaultError):
            vault.parse(b"{not json")

    def test_summary_reveals_no_secrets(self):
        summary = vault.summarise(sample_document())
        self.assertNotIn("JBSWY3DPEHPK3PXP", summary)
        self.assertNotIn("aaaa-bbbb", summary)


class TestSteamDigits(unittest.TestCase):
    """A Steam code is five characters, and the specification says so.

    The decoder applied the six-to-ten range to every otpType, so it refused
    files this format calls valid. Nothing failed, because no vector carried a
    Steam credential: the specification and the decoder disagreed, and the
    suite agreed with both.
    """

    def _steam(self, digits):
        document = sample_document()
        document["items"][0]["otpType"] = "steam"
        document["items"][0]["digits"] = digits
        return document

    def test_a_steam_code_of_five_is_accepted(self):
        vault.validate(self._steam(5))

    def test_a_steam_code_of_any_other_length_is_refused(self):
        for digits in (4, 6, 8, 10, "5", None):
            with self.subTest(digits=digits), self.assertRaises(InvalidVaultError):
                vault.validate(self._steam(digits))

    def test_the_wider_range_still_belongs_to_the_other_kinds(self):
        for otp_type in ("totp", "hotp"):
            document = sample_document()
            document["items"][0]["otpType"] = otp_type
            document["items"][0]["digits"] = 5
            if otp_type == "hotp":
                document["items"][0]["counter"] = 0
            with self.subTest(otpType=otp_type), self.assertRaises(InvalidVaultError):
                vault.validate(document)


class TestPasswordItem(unittest.TestCase):
    """The password type, whose only required field is the password.

    Neither implementation checked it, so an item claiming to hold a credential
    could hold nothing. In a vault whose purpose is getting somebody back in,
    that is the worst shape a record can take: it stops the search.
    """

    def _with_password(self, **fields):
        document = sample_document()
        item = {"id": "itm_pw", "accountId": "acc_bank", "type": "password",
                "createdAt": "2026-08-24T10:00:00Z"}
        item.update(fields)
        document["items"].append(item)
        return document

    def test_a_password_is_required(self):
        for value in ("", None, 7, {}):
            with self.subTest(password=value), self.assertRaises(InvalidVaultError):
                vault.validate(self._with_password(password=value))

    def test_a_missing_password_is_refused(self):
        with self.assertRaises(InvalidVaultError):
            vault.validate(self._with_password())

    def test_the_other_fields_are_optional(self):
        vault.validate(self._with_password(password="correct horse"))
        vault.validate(self._with_password(password="s", username=None,
                                           site=None, note=None))

    def test_the_other_fields_must_be_strings_when_present(self):
        for field in ("username", "site", "note"):
            with self.subTest(field=field), self.assertRaises(InvalidVaultError):
                vault.validate(self._with_password(password="s", **{field: 7}))

    def test_a_password_is_never_trimmed_before_being_checked(self):
        """A trailing space is load-bearing, so spaces alone are a password."""
        vault.validate(self._with_password(password="   "))

    def test_a_password_past_the_string_ceiling_is_refused(self):
        huge = "a" * (vault.MAX_STRING_BYTES + 1)
        with self.assertRaises(InvalidVaultError):
            vault.validate(self._with_password(password=huge))


class TestKnownItemTypes(unittest.TestCase):
    """The decoder's set of known types against the specification's table.

    A type the specification declares and the decoder does not know is carried
    through as though it came from the future: unvalidated, and silently. That
    is right for a type nobody has heard of and wrong for one that is written
    down two directories away.
    """

    def test_the_known_types_are_exactly_the_types_in_the_specification(self):
        spec = os.path.join(os.path.dirname(__file__), "..", "..",
                            "spec", "sealstone-format-v1.md")
        if not os.path.exists(spec):
            self.skipTest("specification is not beside the decoder")

        with open(spec, encoding="utf-8") as handle:
            text = handle.read()

        # The item table, and only that table: it opens with a header row
        # naming `type`, and runs until the first line that is not a row.
        # Reading every backticked cell in the document instead would pick up
        # KDF parameters and identifier prefixes and pass no matter what.
        lines = text.splitlines()
        try:
            start = next(i for i, line in enumerate(lines)
                         if line.startswith("| `type` |"))
        except StopIteration:
            self.fail("the item table is not where this test expects it")

        declared = set()
        for line in lines[start + 2:]:
            if not line.startswith("| `"):
                break
            declared.add(line[3:line.index("` |")])

        self.assertGreater(len(declared), 1, "the item table did not parse")
        # Both directions. A type in the table and not in the decoder is
        # carried through unvalidated as though it came from the future, which
        # is how `password` shipped unchecked; a type in the decoder and not in
        # the table is a decoder implementing a format nobody wrote down.
        self.assertEqual(vault.KNOWN_ITEM_TYPES, declared)


if __name__ == "__main__":
    unittest.main()
