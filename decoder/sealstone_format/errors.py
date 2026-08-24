"""Errors raised by this package.

Messages state what happened, what it means, and what to do, in that order.
User-facing copy is derived from them, so a vague message here becomes a vague
message on screen.
"""

from __future__ import annotations


class SealstoneFormatError(Exception):
    """Base class for everything this package raises."""


class NotAnImpressionError(SealstoneFormatError):
    """The file is not a Sealstone Impression at all."""


class UnsupportedVersionError(SealstoneFormatError):
    """The file is an Impression, but of a version this decoder cannot read."""


class HostileParametersError(SealstoneFormatError):
    """The file requests resources beyond the normative ceilings.

    Raised before allocation, never after. A file asking for 64 GiB of memory is
    a denial-of-service attempt wearing a KDF parameter's clothing.
    """


class BrokenSealError(SealstoneFormatError):
    """The seal is broken: wrong passphrase, or the file was modified.

    An authenticated cipher cannot distinguish these two cases, and pretending
    otherwise would be a lie with security consequences.
    """


class KeyMaterialMismatchError(SealstoneFormatError):
    """The file needs different key material than was supplied.

    A passphrase was given for a file whose key comes from the keychain, or a
    key was given for a passphrase-protected file. Also raised when the kdfId
    byte has been altered, since that changes which kind the file claims to be.
    """


class InvalidVaultError(SealstoneFormatError):
    """The Impression opened, but the document inside does not validate."""
