# Sealstone Format

The file format behind [Sealstone](https://sealstone.app) — specification, test vectors, and an independent reference decoder.

**Status: draft. The format is not yet frozen and is subject to change.**
This repository becomes public when the format is frozen. Until then, treat nothing here as stable.

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
vectors/      Test vectors — every implementation must pass all of them
decoder/      Reference decoder, Python, no dependencies beyond the standard
              library and one vendored Argon2id
```

## Language stack

| Part | Language | Why |
|---|---|---|
| Specification | Markdown | Diffable, reviewable, readable in ten years |
| Test vectors | JSON manifests + binary fixtures | Language-neutral by construction |
| Reference decoder | **Python 3.11+** | Ubiquitous, readable by non-specialists, and **not Swift** — an independent implementation is only independent if it shares no code |

There is no Swift in this repository. The Swift implementation lives in `sealstone-kit`.

## Dependencies

The same doctrine as the rest of Sealstone: **none**, beyond the Python standard library and a vendored Argon2id implementation carrying its own RFC 9106 test vectors.

A reference decoder that needs a package manager is a reference decoder that stops working.

## Branches

`dev` is where work lands. `main` is release. Never push to `main` directly; open a pull request from `dev`. Neither branch is ever deleted.

Activate the workflow hook in a fresh clone:

```
git config core.hooksPath .githooks
```

## Licence

Apache 2.0. The patent grant is deliberate: this format is meant to be implemented by other people, including people who are not us.
