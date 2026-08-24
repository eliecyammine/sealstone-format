"""Test suite for the reference decoder.

Runs with `python3 -m unittest discover -s tests` — no test framework to
install, so this works anywhere Python does.

Fast parameters are used throughout. One test at the real 64 MiB parameters is
marked slow and skipped unless SEALSTONE_SLOW_TESTS=1.
"""

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

FAST_KDF = dict(memory_kib=64, iterations=1, parallelism=1)
PASSPHRASE = "correct horse battery staple"


def sample_document() -> dict:
    return {
        "formatVersion": 1,
        "vaultId": "550e8400-e29b-41d4-a716-446655440000",
        "createdAt": "2026-08-24T10:00:00Z",
        "updatedAt": "2026-08-24T11:30:00Z",
        "accounts": [
            {"id": "acc_google", "service": "Google",
             "identifier": "elie@example.com", "domain": "google.com",
             "tags": ["email"], "notes": None,
             "createdAt": "2026-08-24T10:00:00Z"},
            {"id": "acc_bank", "service": "Bank", "identifier": "elie",
             "domain": "bank.example", "tags": [], "notes": None,
             "createdAt": "2026-08-24T10:00:00Z"},
        ],
        "items": [
            {"id": "itm_1", "accountId": "acc_google", "type": "authenticator",
             "favorite": True, "ordering": 0,
             "createdAt": "2026-08-24T10:00:00Z",
             "modifiedAt": "2026-08-24T10:00:00Z",
             "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6,
             "period": 30, "counter": None, "otpType": "totp"},
            {"id": "itm_2", "accountId": "acc_bank", "type": "recoveryCodes",
             "createdAt": "2026-08-24T10:00:00Z",
             "codes": [{"code": "aaaa-bbbb", "used": False, "usedAt": None}]},
            {"id": "itm_3", "accountId": "acc_google",
             "type": "somethingFromTheFuture",
             "createdAt": "2026-08-24T10:00:00Z", "payload": {"x": 1}},
        ],
        "links": [
            {"id": "lnk_1", "sourceAccountId": "acc_google",
             "targetAccountId": "acc_bank", "method": "email",
             "verifiedAt": "2026-08-24T10:00:00Z", "note": None},
        ],
        "keepers": [],
    }


def sample_bytes() -> bytes:
    return json.dumps(sample_document(), ensure_ascii=False).encode("utf-8")


class TestAES(unittest.TestCase):
    def test_fips197_aes256_block(self):
        schedule = aes._expand_key(bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
        self.assertEqual(
            aes.encrypt_block(schedule, bytes.fromhex("00112233445566778899aabbccddeeff")),
            bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"))

    def test_fips197_aes128_block(self):
        schedule = aes._expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(
            aes.encrypt_block(schedule, bytes.fromhex("00112233445566778899aabbccddeeff")),
            bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))

    def test_gcm_spec_case_13(self):
        _, tag = aes.gcm_encrypt(b"\x00" * 32, b"\x00" * 12, b"")
        self.assertEqual(tag, bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"))

    def test_gcm_spec_case_14(self):
        ciphertext, tag = aes.gcm_encrypt(b"\x00" * 32, b"\x00" * 12, b"\x00" * 16)
        self.assertEqual(ciphertext, bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"))
        self.assertEqual(tag, bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"))

    def test_gcm_spec_case_2_aes128(self):
        ciphertext, tag = aes.gcm_encrypt(b"\x00" * 16, b"\x00" * 12, b"\x00" * 16)
        self.assertEqual(ciphertext, bytes.fromhex("0388dace60b6a392f328c2b971b2fe78"))
        self.assertEqual(tag, bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf"))

    def test_rejects_modified_inputs(self):
        key, nonce, plaintext, aad = b"k" * 32, b"n" * 12, b"payload", b"header"
        ciphertext, tag = aes.gcm_encrypt(key, nonce, plaintext, aad)
        self.assertEqual(aes.gcm_decrypt(key, nonce, ciphertext, tag, aad), plaintext)

        for label, args in [
            ("ciphertext", (key, nonce, b"\x00" + ciphertext[1:], tag, aad)),
            ("tag", (key, nonce, ciphertext, b"\x00" + tag[1:], aad)),
            ("aad", (key, nonce, ciphertext, tag, b"headeR")),
            ("key", (b"j" * 32, nonce, ciphertext, tag, aad)),
        ]:
            with self.subTest(modified=label), self.assertRaises(ValueError):
                aes.gcm_decrypt(*args)


class TestArgon2(unittest.TestCase):
    """RFC 9106 section 5 test vectors."""

    COMMON = dict(password=b"\x01" * 32, salt=b"\x02" * 16, secret=b"\x03" * 8,
                  associated_data=b"\x04" * 12, time_cost=3, memory_cost=32,
                  parallelism=4, tag_length=32)

    def test_argon2d(self):
        self.assertEqual(
            argon2.hash_raw(type_=argon2.TYPE_D, **self.COMMON).hex(),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")

    def test_argon2i(self):
        self.assertEqual(
            argon2.hash_raw(type_=argon2.TYPE_I, **self.COMMON).hex(),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")

    def test_argon2id(self):
        self.assertEqual(
            argon2.hash_raw(type_=argon2.TYPE_ID, **self.COMMON).hex(),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")

    # The RFC vectors all use m=32, which gives a segment length of 2. The
    # first segment of the first pass then runs zero times, so an entire code
    # path goes unexercised — and that is exactly where a defect lived: the
    # first address block was never generated, and every derivation at a
    # realistic size was wrong while these three vectors passed.
    #
    # Generated with the reference implementation:
    #   printf 'password' | argon2 saltsaltsaltsalt -id -k M -t T -p P -l 32 -r
    REFERENCE_VECTORS = [
        (8, 1, 1, "94c3e0558c1de1901090e8a964635193"),
        (64, 1, 1, "59bf4338b29483094be5f8da77db5f08"),
        (256, 4, 2, "602cef299d3307ab20e7d8cf14531e02"),
        (512, 1, 1, "c6c8932e8f7b0374cde76fcf68df034e"),
        (1024, 1, 1, "4c9a847bca2cfc41d97cbdd56a9739f4"),
        (4096, 3, 4, "7f77af0c247ce317b69574fc9ccf5008"),
    ]

    def test_matches_the_reference_implementation_at_realistic_sizes(self):
        for memory, iterations, parallelism, expected in self.REFERENCE_VECTORS:
            with self.subTest(m=memory, t=iterations, p=parallelism):
                tag = argon2.hash_raw(
                    b"password", b"saltsaltsaltsalt",
                    time_cost=iterations, memory_cost=memory,
                    parallelism=parallelism, tag_length=32,
                    type_=argon2.TYPE_ID)
                self.assertEqual(tag.hex()[:32], expected)

    @unittest.skipUnless(os.environ.get("SEALSTONE_SLOW_TESTS") == "1",
                         "set SEALSTONE_SLOW_TESTS=1 to run at shipping parameters")
    def test_matches_the_reference_at_shipping_parameters(self):
        tag = argon2.hash_raw(b"password", b"saltsaltsaltsalt",
                              time_cost=3, memory_cost=65536, parallelism=4,
                              tag_length=32, type_=argon2.TYPE_ID)
        self.assertEqual(tag.hex()[:32], "ac15942c3e63386a50cb7dab2ef19c9a")


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
    unittest.main(verbosity=2)
