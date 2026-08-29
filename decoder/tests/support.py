"""Shared fixtures for the decoder's tests.

Not named `test_*`, so `unittest discover` treats it as what it is: a place the
test modules get their sample document and their fast KDF parameters from,
rather than a module of its own tests.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


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
