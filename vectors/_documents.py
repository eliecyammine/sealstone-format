"""The vault documents the corpus is built from.

Three, deliberately: nothing at all, the smallest useful thing, and one that
exercises every item type at once. An implementation that reads all three has
read every shape the format can take.
"""

from __future__ import annotations




def empty_vault() -> dict:
    return {
        "formatVersion": 1,
        "vaultId": "00000000-0000-4000-8000-000000000001",
        "createdAt": "2026-08-24T00:00:00Z",
        "updatedAt": "2026-08-24T00:00:00Z",
        "accounts": [],
        "items": [],
        "links": [],
        "keepers": [],
    }


def single_totp_vault() -> dict:
    document = empty_vault()
    document["vaultId"] = "00000000-0000-4000-8000-000000000002"
    document["accounts"] = [{
        "id": "acc_example", "service": "Example", "identifier": "user@example.com",
        "domain": "example.com", "tags": [], "notes": None,
        "createdAt": "2026-08-24T00:00:00Z",
    }]
    document["items"] = [{
        "id": "itm_totp", "accountId": "acc_example", "type": "authenticator",
        "favorite": False, "ordering": 0,
        "createdAt": "2026-08-24T00:00:00Z", "modifiedAt": "2026-08-24T00:00:00Z",
        "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6,
        "period": 30, "counter": None, "otpType": "totp",
    }]
    return document


def full_vault() -> dict:
    """Every item type and otpType, both link directions, keepers, and an unknown type.

    This family carries the forward-compatibility checks. A decoder must round
    trip all of them untouched rather than dropping them:

      - an item whose ``type`` it does not know
      - a key at the document root it does not know
      - a key inside an account, a link and a keeper it does not know

    The nested ones matter most in practice. A new optional field lands on an
    account or a keeper far more often than at the root, so that is where a
    decoder that quietly drops what it does not understand will lose real data.
    """
    document = empty_vault()
    document["vaultId"] = "00000000-0000-4000-8000-000000000003"
    document["accounts"] = [
        {"id": "acc_mail", "service": "Mail", "identifier": "user@example.com",
         "domain": "mail.example", "tags": ["email", "keystone"], "notes": None,
         "createdAt": "2026-08-24T00:00:00Z",
         "fieldFromTheFuture": {"nested": [1, 2, 3]}},
        {"id": "acc_bank", "service": "Bank", "identifier": "user",
         "domain": "bank.example", "tags": ["finance"], "notes": None,
         "createdAt": "2026-08-24T00:00:00Z"},
        {"id": "acc_wallet", "service": "Wallet", "identifier": "main",
         "domain": None, "tags": [], "notes": None,
         "createdAt": "2026-08-24T00:00:00Z"},
    ]
    document["items"] = [
        {"id": "itm_totp", "accountId": "acc_mail", "type": "authenticator",
         "favorite": True, "ordering": 0,
         "createdAt": "2026-08-24T00:00:00Z", "modifiedAt": "2026-08-24T00:00:00Z",
         "lastUsedAt": "2026-08-24T09:30:00Z",
         "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA256", "digits": 8,
         "period": 60, "counter": None, "otpType": "totp"},
        {"id": "itm_hotp", "accountId": "acc_bank", "type": "authenticator",
         "favorite": False, "ordering": 1,
         "createdAt": "2026-08-24T00:00:00Z", "modifiedAt": "2026-08-24T00:00:00Z",
         "secret": "GEZDGNBVGY3TQOJQ", "algorithm": "SHA1", "digits": 6,
         "period": 30, "counter": 7, "otpType": "hotp"},
        # Five digits, which is the whole reason this one is here. The
        # specification says the six-to-ten range belongs to totp and hotp and
        # that Steam is always five; with no vector carrying it, a decoder
        # could apply one range to every kind and stay green while refusing
        # files this format calls valid. One did.
        {"id": "itm_steam", "accountId": "acc_bank", "type": "authenticator",
         "favorite": False, "ordering": 2,
         "createdAt": "2026-08-24T00:00:00Z", "modifiedAt": "2026-08-24T00:00:00Z",
         "secret": "MFRGGZDFMZTWQ2LK", "algorithm": "SHA1", "digits": 5,
         "period": 30, "counter": None, "otpType": "steam"},
        {"id": "itm_codes", "accountId": "acc_bank", "type": "recoveryCodes",
         "createdAt": "2026-08-24T00:00:00Z",
         "codes": [{"code": "aaaa-bbbb", "used": False, "usedAt": None},
                   {"code": "cccc-dddd", "used": True,
                    "usedAt": "2026-08-01T00:00:00Z"}]},
        {"id": "itm_contact", "accountId": "acc_mail", "type": "recoveryContact",
         "createdAt": "2026-08-24T00:00:00Z",
         "channel": "email", "value": "backup@example.com"},
        {"id": "itm_questions", "accountId": "acc_bank", "type": "securityQuestions",
         "createdAt": "2026-08-24T00:00:00Z",
         "questions": [{"question": "First pet?", "answer": "redacted"}]},
        {"id": "itm_seed", "accountId": "acc_wallet", "type": "seedPhrase",
         "createdAt": "2026-08-24T00:00:00Z",
         "words": ["abandon"] * 11 + ["about"],
         "wordlist": "BIP39-english", "passphrase": None},
        {"id": "itm_password", "accountId": "acc_mail", "type": "password",
         "createdAt": "2026-08-24T00:00:00Z",
         "password": "correct horse battery staple", "username": "user",
         "site": "mail.example", "note": None},
        {"id": "itm_key", "accountId": "acc_bank", "type": "hardwareKey",
         "createdAt": "2026-08-24T00:00:00Z",
         "label": "Blue key", "serial": "0000001", "keyType": "fido2"},
        {"id": "itm_note", "accountId": "acc_wallet", "type": "note",
         "createdAt": "2026-08-24T00:00:00Z",
         "title": "Where the hardware wallet lives", "body": "Second drawer."},
        {"id": "itm_future", "accountId": "acc_mail", "type": "typeFromTheFuture",
         "createdAt": "2026-08-24T00:00:00Z",
         "unknownField": {"nested": [1, 2, 3]}},
    ]
    document["links"] = [
        {"id": "lnk_mail_bank", "sourceAccountId": "acc_mail",
         "targetAccountId": "acc_bank", "method": "email",
         "verifiedAt": "2026-08-24T00:00:00Z", "note": None,
         "strengthFromTheFuture": "weak"},
        {"id": "lnk_mail_wallet", "sourceAccountId": "acc_mail",
         "targetAccountId": "acc_wallet", "method": "email",
         "verifiedAt": None, "note": "unverified"},
        {"id": "lnk_bank_mail", "sourceAccountId": "acc_bank",
         "targetAccountId": "acc_mail", "method": "sms",
         "verifiedAt": None, "note": None},
    ]
    document["keepers"] = [{
        "id": "kpr_1", "displayName": "Keeper One", "contact": "one@example.com",
        "bundleId": "bnd_1", "fragmentIndex": 1,
        "issuedAt": "2026-08-24T00:00:00Z", "lastConfirmedAt": None,
        "status": "active",
        "relayFromTheFuture": {"endpoint": "https://example.invalid/r"},
    }]
    # At the document root as well, which is the case §3.3 states outright.
    document["settingsFromTheFuture"] = {"autoLockSeconds": 60}
    return document
