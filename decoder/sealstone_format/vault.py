"""The vault document: schema validation and summary.

Strict on structure, lenient on the future. Unknown item types and unknown keys
are preserved rather than discarded, so an older decoder cannot destroy data
written by a newer one on round-trip.

The plaintext is JSON so it stays readable with nothing but a text editor.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import InvalidVaultError

FORMAT_VERSION = 1

KNOWN_ITEM_TYPES = {
    "authenticator",
    "recoveryCodes",
    "recoveryContact",
    "securityQuestions",
    "seedPhrase",
    "hardwareKey",
    "note",
}

LINK_METHODS = {
    "email", "sms", "voice", "backupCodes",
    "securityQuestions", "trustedContact", "hardwareKey", "other",
}

OTP_ALGORITHMS = {"SHA1", "SHA256", "SHA512"}
OTP_TYPES = {"totp", "hotp", "steam"}

# Rejected before allocation, so a hostile document cannot force unbounded work.
MAX_ACCOUNTS = 100_000
MAX_ITEMS = 500_000
MAX_LINKS = 1_000_000


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidVaultError(message)


def _validate_authenticator(item: dict, where: str) -> None:
    otp_type = item.get("otpType")
    _require(otp_type in OTP_TYPES,
             f"{where}: otpType must be one of {sorted(OTP_TYPES)}, got {otp_type!r}")

    _require(isinstance(item.get("secret"), str) and item["secret"],
             f"{where}: secret must be a non-empty Base32 string")

    algorithm = item.get("algorithm")
    _require(algorithm in OTP_ALGORITHMS,
             f"{where}: algorithm must be one of {sorted(OTP_ALGORITHMS)}, got {algorithm!r}")

    digits = item.get("digits")
    _require(isinstance(digits, int) and 6 <= digits <= 10,
             f"{where}: digits must be between 6 and 10, got {digits!r}")

    period = item.get("period")
    _require(isinstance(period, int) and 1 <= period <= 300,
             f"{where}: period must be between 1 and 300 seconds, got {period!r}")

    counter = item.get("counter")
    if otp_type == "hotp":
        _require(isinstance(counter, int) and counter >= 0,
                 f"{where}: an HOTP item needs a counter")
    else:
        _require(counter is None,
                 f"{where}: only HOTP items carry a counter")

    # Base32 validity, checked here rather than at use
    from .encoding import b32_decode
    try:
        b32_decode(item["secret"])
    except ValueError as exc:
        raise InvalidVaultError(f"{where}: secret is not valid Base32 — {exc}") from None


def validate(document: dict[str, Any]) -> dict[str, Any]:
    """Validate a parsed vault document. Returns it unchanged on success.

    Raises InvalidVaultError naming the offending field.
    """
    _require(isinstance(document, dict), "vault document must be a JSON object")

    version = document.get("formatVersion")
    _require(version == FORMAT_VERSION,
             f"formatVersion must be {FORMAT_VERSION}, got {version!r}")
    _require(isinstance(document.get("vaultId"), str), "vaultId must be a string")

    accounts = document.get("accounts", [])
    items = document.get("items", [])
    links = document.get("links", [])
    keepers = document.get("keepers", [])

    for name, collection, ceiling in (("accounts", accounts, MAX_ACCOUNTS),
                                      ("items", items, MAX_ITEMS),
                                      ("links", links, MAX_LINKS)):
        _require(isinstance(collection, list), f"{name} must be a list")
        _require(len(collection) <= ceiling,
                 f"{name} exceeds the ceiling of {ceiling}. Refusing.")
    _require(isinstance(keepers, list), "keepers must be a list")

    # Identifiers unique within their collection
    account_ids: set[str] = set()
    for index, account in enumerate(accounts):
        _require(isinstance(account, dict), f"accounts[{index}] must be an object")
        identifier = account.get("id")
        _require(isinstance(identifier, str) and identifier,
                 f"accounts[{index}]: id must be a non-empty string")
        _require(identifier not in account_ids,
                 f"accounts[{index}]: duplicate id {identifier!r}")
        account_ids.add(identifier)

    item_ids: set[str] = set()
    for index, item in enumerate(items):
        where = f"items[{index}]"
        _require(isinstance(item, dict), f"{where} must be an object")

        identifier = item.get("id")
        _require(isinstance(identifier, str) and identifier,
                 f"{where}: id must be a non-empty string")
        _require(identifier not in item_ids, f"{where}: duplicate id {identifier!r}")
        item_ids.add(identifier)

        account_id = item.get("accountId")
        _require(account_id in account_ids,
                 f"{where}: accountId {account_id!r} does not resolve to an account")

        item_type = item.get("type")
        _require(isinstance(item_type, str), f"{where}: type must be a string")

        # Unknown types pass through untouched rather than being rejected.
        if item_type == "authenticator":
            _validate_authenticator(item, where)

    for index, link in enumerate(links):
        where = f"links[{index}]"
        _require(isinstance(link, dict), f"{where} must be an object")
        for end in ("sourceAccountId", "targetAccountId"):
            value = link.get(end)
            _require(value in account_ids,
                     f"{where}: {end} {value!r} does not resolve to an account")
        method = link.get("method")
        _require(method in LINK_METHODS,
                 f"{where}: method must be one of {sorted(LINK_METHODS)}, got {method!r}")

    return document


def parse(plaintext: bytes) -> dict[str, Any]:
    """Parse and validate the plaintext of an Impression."""
    try:
        document = json.loads(plaintext.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InvalidVaultError(f"vault document is not valid UTF-8 — {exc}") from None
    except json.JSONDecodeError as exc:
        raise InvalidVaultError(f"vault document is not valid JSON — {exc}") from None

    return validate(document)


def summarise(document: dict[str, Any]) -> str:
    """Describe the shape of a vault without printing anything secret."""
    items = document.get("items", [])
    by_type: dict[str, int] = {}
    for item in items:
        by_type[item.get("type", "unknown")] = by_type.get(item.get("type", "unknown"), 0) + 1

    lines = [
        f"  vault      {document.get('vaultId', '?')}",
        f"  created    {document.get('createdAt', '?')}",
        f"  updated    {document.get('updatedAt', '?')}",
        f"  accounts   {len(document.get('accounts', []))}",
        f"  items      {len(items)}",
    ]
    for item_type in sorted(by_type):
        lines.append(f"    {item_type:<22} {by_type[item_type]}")
    lines.append(f"  links      {len(document.get('links', []))}")
    lines.append(f"  keepers    {len(document.get('keepers', []))}")
    return "\n".join(lines)
