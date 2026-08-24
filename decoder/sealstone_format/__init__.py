"""Sealstone Format v1 — reference decoder.

If you are reading this because Sealstone is gone and you need to open a backup,
you are in the right place and everything you need is here.

    python3 -m sealstone_format open backup.seal

The specification is in `spec/`. This package has no dependencies beyond the
Python standard library, deliberately, so it still runs on a machine with no
network and no package manager.

    >>> from sealstone_format import open_impression, parse
    >>> plaintext, header = open_impression(open("backup.seal", "rb").read(),
    ...                                     passphrase="…")
    >>> document = parse(plaintext)

*** This package is a reference implementation for verification. It is not
constant time and must not be used to protect data. ***
"""

from .envelope import Header, open_impression, seal
from .errors import (
    BrokenSealError,
    HostileParametersError,
    InvalidVaultError,
    KeyMaterialMismatchError,
    NotAnImpressionError,
    SealstoneFormatError,
    UnsupportedVersionError,
)
from .vault import parse, summarise, validate

__version__ = "1.0.0-draft"

__all__ = [
    "Header",
    "open_impression",
    "seal",
    "parse",
    "validate",
    "summarise",
    "SealstoneFormatError",
    "NotAnImpressionError",
    "UnsupportedVersionError",
    "HostileParametersError",
    "KeyMaterialMismatchError",
    "BrokenSealError",
    "InvalidVaultError",
]
