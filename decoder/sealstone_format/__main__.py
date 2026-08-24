"""Command line entry point.

    python3 -m sealstone_format open backup.seal
    python3 -m sealstone_format inspect backup.seal
    python3 -m sealstone_format combine frag1.txt frag2.txt frag3.txt

`inspect` reads only the header and needs no passphrase — useful for confirming
a file really is an Impression before going looking for the passphrase.

`open` never prints a secret. It reports that the seal is intact and describes
the shape of what is inside. Use --json when you actually need the contents,
which writes to stdout so you can redirect it somewhere you have chosen.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import envelope, shamir, vault
from .encoding import crockford_decode
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
    print()
    print("No secrets were printed. Use --json to write the full contents to stdout.")
    return 0


def _cmd_combine(args) -> int:
    fragments = []
    for path in args.fragments:
        text = _read(path).decode("utf-8", errors="replace")
        index = None
        payload_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("sealstone fragment"):
                for token in stripped.split():
                    if token.isdigit():
                        index = int(token)
                        break
            elif stripped and not stripped.lower().startswith("set "):
                payload_lines.append(stripped)
        if index is None:
            print(f"{path}: could not find the fragment number.", file=sys.stderr)
            return 2
        fragments.append((index, crockford_decode("".join(payload_lines))))

    key = shamir.combine(fragments)
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
    p_open.add_argument("--json", action="store_true",
                        help="write the full document to stdout")
    p_open.set_defaults(func=_cmd_open)

    p_combine = sub.add_parser("combine", help="recombine fragments into a key")
    p_combine.add_argument("fragments", nargs="+")
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
