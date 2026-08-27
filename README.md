# Sealstone Format

The file format behind [Sealstone](https://sealstone.app) — specification, test vectors, and an independent reference decoder.

**Status: frozen.** Version 1 is stable. Any change that would break an
existing file requires a major version, and every version ever published stays
readable by the current implementation.

---

## Why this repository exists

Sealstone is a personal recovery vault. Its central promise is that a backup you make today is one **you can still open in ten years — with or without Sealstone, and whether or not the company still exists.**

A promise like that is worthless as an assertion. This repository is the proof:

- **The specification** describes the format completely enough to implement from scratch.
- **The test vectors** let any implementation prove it is correct.
- **The reference decoder** is written in Python, deliberately **not** in Swift, so it cannot share a bug with the application. If it opens a file the app wrote, two independent implementations agree.

If Sealstone disappears tomorrow, everything needed to recover a vault is in this repository.

---

## Layout

```
spec/         The format specification
vectors/      Test vector corpus, indexed by manifest.json
decoder/      Reference decoder and the conformance suite
```

## Recovering a vault

If Sealstone is gone and you have a backup, this is the whole procedure:

```
cd decoder
python3 -m sealstone_format inspect  ../backup.seal    # no passphrase needed
python3 -m sealstone_format open     ../backup.seal --codes
```

`--codes` prints the current one-time code for each account, which is what
actually logs you in. `--json` writes everything to stdout.

If the vault was split among keepers, any threshold-many of them combine their
sheets, and the key that comes out opens the handover bundle they were each
given alongside their fragment:

```
python3 -m sealstone_format combine sheet1.txt sheet2.txt sheet3.txt
python3 -m sealstone_format open ../bundle.seal --key <the key it printed>
```

Fragments are accepted as saved binary files or as the text of a printed sheet.
Transcription is forgiving on purpose: the letter O counts as a zero, I and l
count as ones, case does not matter, and spaces and dashes are ignored. Whoever
is doing this is working from paper, possibly years from now, and possibly
without the person who set it up.

No network, no account, and no part of this needs sealstone.app to still
exist.

## Verifying an implementation

```
cd decoder && python3 -m unittest discover -s tests -t .
```

95 tests. `tests/test_vectors.py` runs the corpus in `vectors/` and is the
executable definition of what implementing this format means — any
implementation, in any language, has to pass the same eleven families.

Set `SEALSTONE_SLOW_TESTS=1` to include the family at production parameters.

Regenerate the corpus with `python3 vectors/generate.py --all`. Output is
deterministic, so a diff in `git status` afterwards means the encoder changed.

## Language stack

| Part | Language | Why |
|---|---|---|
| Specification | Markdown | Diffable, reviewable, readable in ten years |
| Test vectors | JSON manifests + binary fixtures | Language-neutral by construction |
| Reference decoder | **Python 3.11+** | Ubiquitous, readable by non-specialists, and **not Swift** — an independent implementation is only independent if it shares no code |

There is no Swift in this repository. The Swift implementation lives in `sealstone-kit`.

## Speed

Pure Python, so key derivation is slow: roughly 50 seconds per derivation at the
real parameters (64 MiB, t=3, p=4) versus milliseconds for the native
implementation. That is fine — this decoder verifies a file once, it does not
open vaults daily.

## Dependencies

None. Python standard library only.

A reference decoder that needs a package manager is a reference decoder that stops working. AES and Argon2id are implemented here rather than imported for that reason, and both are validated against published known-answer vectors (FIPS-197, the GCM specification, RFC 9106).

These implementations are **not constant time** and must not be used to protect data. They verify; they do not guard.

## Branches

`dev` is where work lands. `main` is release. Never push to `main` directly; open a pull request from `dev`. Neither branch is ever deleted.

Activate the workflow hook in a fresh clone:

```
git config core.hooksPath .githooks
```

## Licence

Apache 2.0. The patent grant is deliberate: this format is meant to be implemented by other people, including people who are not us.
