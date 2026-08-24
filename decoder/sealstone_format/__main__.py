"""Command line entry point.

    python3 -m sealstone_format inspect backup.seal
    python3 -m sealstone_format open backup.seal
    python3 -m sealstone_format open backup.seal --codes
    python3 -m sealstone_format combine frag1.txt frag2.txt frag3.txt

`inspect` reads only the header and needs no passphrase — useful for confirming
a file really is an Impression before going looking for the passphrase.

`open` prints no secrets by default: it reports that the seal is intact and
describes the shape of what is inside. --codes prints the current one-time code
for each authenticator. --json writes the whole document to stdout.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import envelope, fragment, otp, shamir, vault
from .errors import SealstoneFormatError


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        print(f"Could not read {path}: {exc.strerror}.", file=sys.stderr)
        raise SystemExit(2) from None


def _cmd_inspect(args) -> int:
    data = _read(args.file)
    header, offset = envelope._parse_header(data)

    print(f"Sealstone Impression v{header.format_major}.{header.format_minor}")
    print(f"  header        {offset} bytes")
    print(f"  body          {len(data) - offset} bytes")
    if header.kdf_id == envelope.KDF_ARGON2ID:
        print("  kdf           Argon2id")
        print(f"    memory      {header.kdf_memory_kib} KiB")
        print(f"    iterations  {header.kdf_iterations}")
        print(f"    parallelism {header.kdf_parallelism}")
    else:
        print("  kdf           none (key supplied directly)")
    print("  aead          AES-256-GCM")
    print()
    print("The header carries no information about the contents — no names, no")
    print("counts, no issuers. That is deliberate.")
    return 0


def _cmd_open(args) -> int:
    data = _read(args.file)

    passphrase = args.passphrase
    if passphrase is None:
        passphrase = getpass.getpass("Passphrase: ")

    print("Deriving the key. This is deliberately slow — it is what makes the",
          file=sys.stderr)
    print("file expensive to attack. Pure Python makes it slower still.",
          file=sys.stderr)

    plaintext, header = envelope.open_impression(data, passphrase=passphrase)
    document = vault.parse(plaintext)

    if args.json:
        json.dump(document, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0

    print()
    print("The seal is intact.")
    print()
    print(vault.summarise(document))

    if args.codes:
        print()
        _print_codes(document)
    else:
        print()
        print("No secrets were printed. Use --codes for current one-time codes,")
        print("or --json to write the full contents to stdout.")

    return 0


def _print_codes(document: dict) -> None:
    """Print the current code for every authenticator in the vault."""
    accounts = {a["id"]: a for a in document.get("accounts", [])}
    rows = []

    for item in document.get("items", []):
        if item.get("type") != "authenticator":
            continue
        account = accounts.get(item.get("accountId"), {})
        label = f"{account.get('service', '?')} ({account.get('identifier', '?')})"
        try:
            rows.append((label, otp.generate(item), item.get("otpType", "totp")))
        except (ValueError, KeyError) as exc:
            rows.append((label, f"[cannot generate: {exc}]", ""))

    if not rows:
        print("No authenticator items in this vault.")
        return

    width = max(len(label) for label, _, _ in rows)
    for label, code, kind in rows:
        suffix = "" if kind == "hotp" else f"   {otp.seconds_remaining():.0f}s left"
        print(f"  {label:<{width}}   {code}{suffix}")


def _cmd_combine(args) -> int:
    parsed = []
    for path in args.fragments:
        raw = _read(path)
        try:
            # A saved binary fragment, or a transcribed sheet.
            if raw.startswith(fragment.MAGIC):
                decoded = fragment.decode(raw)
            else:
                decoded = fragment.from_paper(raw.decode("utf-8", errors="replace"))
        except fragment.FragmentError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            return 1
        parsed.append((path, decoded))

    set_ids = {d["set_id"] for _, d in parsed}
    if len(set_ids) > 1:
        print("These fragments belong to different splits and cannot be "
              "combined. Check that they came from the same vault.",
              file=sys.stderr)
        return 1

    threshold = parsed[0][1]["threshold"]
    if len(parsed) < threshold:
        print(f"This split needs {threshold} fragments and you supplied "
              f"{len(parsed)}. Find {threshold - len(parsed)} more.",
              file=sys.stderr)
        return 1

    indices = [d["index"] for _, d in parsed]
    if len(set(indices)) != len(indices):
        print("The same fragment was supplied more than once. Each must come "
              "from a different keeper.", file=sys.stderr)
        return 1

    key = shamir.combine([(d["index"], d["share"]) for _, d in parsed])
    print(key.hex())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sealstone_format",
        description="Open and inspect Sealstone Impressions.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="read the header only, no passphrase")
    p_inspect.add_argument("file")
    p_inspect.set_defaults(func=_cmd_inspect)

    p_open = sub.add_parser("open", help="open an Impression")
    p_open.add_argument("file")
    p_open.add_argument("--passphrase", help="prompted for if omitted")
    p_open.add_argument("--codes", action="store_true",
                        help="print the current one-time code for each item")
    p_open.add_argument("--json", action="store_true",
                        help="write the full document to stdout")
    p_open.set_defaults(func=_cmd_open)

    p_combine = sub.add_parser(
        "combine", help="recombine fragments into a key")
    p_combine.add_argument("fragments", nargs="+",
                           help="binary fragments or transcribed sheets")
    p_combine.set_defaults(func=_cmd_combine)

    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except SealstoneFormatError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
