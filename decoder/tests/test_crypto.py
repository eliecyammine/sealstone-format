"""The two primitives, against their published vectors."""

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


if __name__ == "__main__":
    unittest.main()
