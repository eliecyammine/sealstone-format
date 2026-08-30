# Sealstone Format v1

Status: **Specification, frozen.** Version 1.

This document describes the file format Sealstone writes, completely enough to
implement a reader without seeing Sealstone's source. That is its purpose: a
backup you make today should be openable in ten years by software that does not
exist yet, written by someone who has never met us.

Alongside it in this repository are the test vectors any implementation must
pass, and a reference decoder written in Python so it cannot share a bug with
the Swift implementation it verifies.

---

## 1. Design goals

In priority order. Where they conflict, the higher one wins.

1. **Decodable in ten years by someone who has never seen Sealstone**, using this document alone. This is security property P7 and non-negotiable.
2. **Confidential and tamper-evident.** P2 and P3.
3. **No metadata leakage.** The envelope reveals nothing about contents — no names, no counts, no sizes beyond what ciphertext length implies.
4. **Upgradeable.** Cryptographic parameters are versioned so they can be strengthened without breaking old files.
5. **Simple enough to implement correctly.** Every construct that is not needed is a construct that can be got wrong.

**Explicit non-goals.** No streaming (vaults are kilobytes). No compression — it interacts badly with encryption via length side channels and buys nothing at this size. No partial decryption. No random access.

---

## 2. The Impression envelope

The file a user gets when they seal a backup. Extension `.seal`, UTI `app.sealstone.impression`.

### 2.0 On the `.seal` extension

**File extensions are not owned, registered, or allocated by anyone.** There is no authority to apply to and nothing to reserve. The question is only whether a collision is likely and what happens if one occurs.

**Checked, August 2026.** No significant modern claimant. Oracle IRM — the most commonly cited "sealed content" product — does **not** use `.seal`; it prefixes `s` to the original extension, producing `.sdoc`, `.sxls`, `.stxt`. The only historical user found was SEAL, a 32-bit DOS GUI, long dead. Directory sites listing `.seal` generically are indexing that.

**How Apple resolves a collision if one ever arises.** UTIs declared in the system library take precedence over third-party ones. Between two third-party apps, macOS resolves arbitrarily, first-come, **without warning the user**. The user's only remedy is Open With. This is worth knowing but is not a reason to avoid the extension — it is true of every non-system extension.

**Three mitigations, already in the design:**

1. **The UTI is genuinely unique.** `app.sealstone.impression` is reverse-DNS under a domain we control. The *identifier* cannot collide even though the extension theoretically can.
2. **The magic bytes are authoritative, not the extension.** A file beginning `SEALSTN` is a Sealstone Impression regardless of what it is named, and §2.4 step 1 verifies that before anything else. A user who renames a backup loses nothing.
3. **Declare `UTTypeConformsTo: public.data`** so the system treats it sensibly even where no app claims it.

**Decision: keep `.seal`.** Short, readable, on-brand, and — for a file someone may need to recognise in a folder a decade from now — meaningfully better than `.sealstone`. Recorded here as a decision made on evidence rather than an assumption never checked.

### 2.1 Layout

All integers big-endian. The entire header is passed as **associated authenticated data** to the AEAD, so any modification to the version, the algorithm identifiers, or the KDF parameters is detected on open.

```
Offset  Size  Field             Notes
------  ----  ----------------  ----------------------------------------
0       7     magic             ASCII "SEALSTN"
7       1     formatMajor       0x01. Decoders MUST refuse unknown majors
8       1     formatMinor       0x00. Decoders MUST tolerate unknown minors
9       1     kdfId             0x00 = none (key from Keychain; at-rest store
                                       only — KDF param fields MUST be zero)
                                0x01 = Argon2id
10      1     aeadId            0x01 = AES-256-GCM
                                0x02 = ChaCha20-Poly1305
11      4     kdfMemoryKiB      Argon2 m, in kibibytes
15      4     kdfIterations     Argon2 t
19      1     kdfParallelism    Argon2 p
20      1     saltLen           16
21      N     salt              CSPRNG, fresh per file
21+N    1     nonceLen          12
22+N    M     nonce             CSPRNG, fresh per file
22+N+M  2     reserved          MUST be 0x0000
------  ----  ----------------  ----------------------------------------
        var   ciphertext        AEAD(key, nonce, plaintext, aad=header)
        16    tag               AEAD authentication tag
```

Header length with default parameters: 52 bytes.

### 2.2 Key derivation

```
key = Argon2id(
    password    = UTF-8 bytes of the passphrase, NFC-normalised,
    salt        = salt,
    m           = kdfMemoryKiB,
    t           = kdfIterations,
    p           = kdfParallelism,
    outputLen   = 32
)
```

**Default parameters for v1:** `m = 65536` (64 MiB), `t = 3`, `p = 4`.

This is **RFC 9106's own second recommended parameter set**, specified for memory-constrained environments — which is exactly what a phone sealing a backup is. Choosing the RFC's published recommendation rather than a number of our own invention is deliberate: it is defensible in an audit, it is what a reviewer expects to see, and it removes a judgement call from a place where judgement calls are how things go wrong.

Parameters are recorded in the file, so an old backup opens with the parameters it was written with, and new backups can strengthen them without a format change.

**Parameter ranges, normative.** A decoder MUST reject a file whose KDF parameters fall outside these ranges, before allocating anything. The floors matter as much as the ceilings: zero iterations or too little memory is not a weak Argon2 input, it is an invalid one (RFC 9106 requires `m ≥ 8p`, `t ≥ 1`, `p ≥ 1`).

| Parameter | Permitted range | Reason |
|---|---|---|
| `kdfMemoryKiB` | `8 × kdfParallelism` to `1048576` (1 GiB) | Below the floor is not a valid Argon2 input; above the ceiling, a hostile file can demand unbounded memory |
| `kdfIterations` | `1` to `16` | Beyond the ceiling is a denial-of-service disguised as security |
| `kdfParallelism` | `1` to `16` | — |

A decoder MUST also reject a truncated file with a message rather than an index error. Every field read past the magic bytes needs a length check, and the corpus family 11 exercises each offset.

Additionally, before attempting a derivation the implementation MUST check available memory and, if insufficient, **fail with a clear message rather than attempt and be terminated**. On iOS an app that allocates beyond its budget is killed by the system, which to the user is indistinguishable from data loss.

**Unicode normalisation is mandatory and is a real interoperability trap.** A passphrase containing a composed character must derive the same key regardless of which normalisation form the entering platform produced. NFC, always, on write and on read.

### 2.3 Encryption

Exactly one AEAD operation per file:

```
ciphertext || tag = AEAD_Encrypt(key, nonce, plaintext = vaultDocument, aad = header)
```

Because the salt is fresh per file, the key is fresh per file, and each key is used for exactly one encryption. Nonce reuse is therefore not reachable, which is the property that makes single-shot AES-GCM safe here.

### 2.4 Decoding, in order

1. Read and verify `magic`. Refuse otherwise.
2. Refuse unknown `formatMajor`.
3. Refuse unknown `kdfId` or `aeadId`. When `kdfId` is `0x00`, refuse unless `kdfMemoryKiB`, `kdfIterations` and `kdfParallelism` are all zero — the authenticated header detects a file altered after sealing, but not one written this way.
4. Validate `reserved == 0`.
5. Sanity-check KDF parameters against the permitted ranges — a hostile file must not be able to demand 64 GiB of memory, or feed zero iterations to the KDF. **Reject rather than attempt.**
6. Derive the key.
7. AEAD-decrypt with the header as AAD. **Any tag failure means the seal is broken. Stop. Mutate nothing.**
8. Parse the plaintext as UTF-8 JSON.
9. Validate against the schema in §3.
10. Only then may the vault be touched.

Steps 7 and 10 in that order are security property **P3**. A decoder that validates after importing has the defect this ordering exists to prevent.

---

## 3. The vault document

The plaintext inside the envelope: **UTF-8 JSON**. Chosen deliberately over a binary encoding — a stranger with this document and a text editor can understand what they are looking at, which is the ten-year goal.

### 3.1 Top level

```json
{
  "formatVersion": 1,
  "vaultId": "vlt_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
  "createdAt": "2026-08-24T10:00:00Z",
  "updatedAt": "2026-08-24T11:30:00Z",
  "accounts": [],
  "items": [],
  "links": [],
  "keepers": []
}
```

### 3.2 Requiredness, types and limits

The examples above show every field populated, which is a good way to see the
shape and a bad way to learn what is mandatory. This section is the normative
one; where an example and this table disagree, this table wins.

**Present or absent.** A field marked required MUST be present and MUST NOT be
`null`. A field marked optional may be absent or `null`, and the two spellings
mean the same thing: nothing was recorded. A decoder MUST treat them
identically and MUST NOT preserve the difference, because writers disagree
about which to emit and round-tripping the distinction turns a cosmetic
difference into a diff.

| Object | Required | Optional |
|---|---|---|
| Document | `formatVersion`, `vaultId`, `createdAt`, `updatedAt` | `accounts`, `items`, `links`, `keepers`, `bundles`, `handover` |
| Account | `id`, `service`, `createdAt` | `identifier`, `domain`, `tags`, `notes` |
| Item | `id`, `accountId`, `type`, `createdAt` | `favorite`, `ordering`, `modifiedAt`, `lastUsedAt` |
| Link | `id`, `sourceAccountId`, `targetAccountId`, `method` | `verifiedAt`, `note` |

An absent array and an empty array mean the same thing. A decoder MUST accept
either and SHOULD write the empty array.

**Every array in this format is therefore optional**, and the table above says
so. This was worth stating twice because it was once said both ways: the table
listed the document's collections as required while the sentence above said an
absent one is legal, and two implementations read the same specification and
disagreed about whether a file was valid. A collection is optional; a writer
should still emit it empty, so the next reader is not left inferring.

`identifier` is optional because not every account has one. A service with a
single login per person has nothing to put there, and forcing a placeholder is
how vaults fill with accounts called "default".

**Timestamps.** Every field ending in `At` is an RFC 3339 timestamp in UTC with
a `Z` suffix and second precision: `2026-08-24T10:00:00Z`. Fractional seconds
MAY be written and MUST be accepted. Offsets other than `Z` MUST be accepted on
read and MUST NOT be written. A decoder MUST NOT reject a timestamp for being
in the future: clocks are wrong, and a file that will not open because a phone
was set forward is a file that lost data for a reason unrelated to data.

**Numbers.** Every numeric field in this format is an integer. A decoder MUST
reject a non-integral value rather than rounding it, and MUST reject a value
outside the range of a signed 64-bit integer rather than saturating. JSON has
one number type and it is a double, so `1e300` parses happily as a whole number
and then overflows whatever it is converted into. `ordering`, `digits`,
`period`, `counter`, `threshold` and `total` are all subject to this.

**Strings.** UTF-8, and a decoder MUST reject a document that is not
well-formed UTF-8. Strings MAY contain any scalar value including newlines; no
field is trimmed, case-folded or normalised on read. A `password` in particular
is preserved byte for byte, spaces included, because a password with a trailing
space is a password whose trailing space is load-bearing.

**Limits.** A decoder MUST enforce ceilings before allocating, and MUST fail
with an error that names the limit rather than exhausting memory. These are
minimums an implementation must support, not maximums it must impose: a
conforming decoder MUST accept a document within every limit below, and MAY
accept more.

| Limit | Value |
|---|---|
| Plaintext document | 64 MiB |
| Accounts | 100,000 |
| Items | 100,000 |
| Links | 100,000 |
| Keepers | 255 |
| Any single string | 1 MiB |
| `codes`, `questions`, `words` in one item | 10,000 |
| Nesting depth of unknown preserved values | 64 |

The nesting limit is what stops a preserved unknown value being a recursion
bomb. Preservation means a decoder copies structures it does not understand,
and a structure it does not understand is a structure an attacker chose.

**Version numbers.** `formatVersion` is the version of the document in §3.
`version` in the envelope header (§2.1) is the version of the envelope in §2.
They are independent and MUST NOT be assumed equal. The envelope carries bytes
without knowing what they are, so an envelope of version 1 can carry a document
of version 2, and a change to the encryption does not oblige a change to the
document schema. A decoder MUST check each against what it supports and MUST
report which one it could not read; "unsupported version" without saying which
sends the reader to the wrong half of the problem.

### 3.3 The account / item / link model

The founding document modelled items directly. That cannot express the recovery graph, so v1 separates three concepts:

| Entity | Meaning |
|---|---|
| **Account** | A service account. *Google, elie@example.com* |
| **Item** | A credential belonging to an account. A TOTP secret, a set of recovery codes |
| **Link** | *Account A can be used to recover account B* |

The Map is computed entirely over `links`. Getting this separation right in v1 is what makes layer 2 possible without a format break.

**Account**

```json
{
  "id": "acc_01H...",
  "service": "Google",
  "identifier": "elie@example.com",
  "domain": "google.com",
  "tags": ["primary", "email"],
  "notes": null,
  "createdAt": "2026-08-24T10:00:00Z"
}
```

**Item** — discriminated on `type`, always bound to an account.

```json
{
  "id": "itm_01H...",
  "accountId": "acc_01H...",
  "type": "authenticator",
  "favorite": true,
  "ordering": 0,
  "createdAt": "...",
  "modifiedAt": "...",
  "lastUsedAt": "...",

  "secret": "BASE32SECRET",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30,
  "counter": null,
  "otpType": "totp"
}
```

`lastUsedAt` is optional and records when a credential was last used, which for
an authenticator means the last time its code was copied. It exists to answer a
question the user cannot otherwise answer: re-enrolling with a service leaves
two codes for one account, only one of which still works, and the one being
used weekly is not the one to delete. Writing it is optional, and a decoder
that does not write it must still preserve one it reads.

| `type` | Additional fields |
|---|---|
| `authenticator` | `secret` (Base32, RFC 4648 unpadded), `algorithm` (`SHA1`\|`SHA256`\|`SHA512`), `digits` (6–10), `period` (seconds), `counter` (HOTP only), `otpType` (`totp`\|`hotp`\|`steam`) |
| `recoveryCodes` | `codes`: array of `{ "code": "...", "used": false, "usedAt": null }` |
| `recoveryContact` | `channel` (`email`\|`sms`\|`voice`), `value` |
| `securityQuestions` | `questions`: array of `{ "question": "...", "answer": "..." }` |
| `seedPhrase` | `words`: array of strings, `wordlist` (e.g. `BIP39-english`), `passphrase` (optional) |
| `hardwareKey` | `label`, `serial`, `keyType` |
| `password` | `password`, `username` (optional), `site` (optional), `note` (optional) |
| `note` | `title`, `body` |

**On `steam` and `digits`.** A Steam code is five characters, not six to ten.
The range above applies to `totp` and `hotp`; when `otpType` is `steam`,
`digits` is `5`. A reader that applies one range to every kind will reject
Steam credentials that this specification says are valid, and a writer that
emits five for Steam and reads back with the wider rule will refuse its own
output.

**On `password`.** A password is a secret of the same weight as a seed phrase
or a security question answer, both of which this format already carries, so
it introduces no category of risk that was not here. It is included because
what gets somebody back into an account frequently *is* the password, and a
format for regaining access that stops short of it has a hole in the middle.

`username` is the login as the service asks for it, which is not always the
account's `identifier`: the account records who you are, this records what you
type. Only `password` is required, and required means non-empty: an item of
this type carrying an empty string claims a credential is recorded when none
is, which in a vault built for regaining access is the one wrong answer that
stops somebody looking further. It is subject to the string ceiling in §3.2
like every other value, and like every other value it is never trimmed.

**Link**

```json
{
  "id": "lnk_01H...",
  "sourceAccountId": "acc_google",
  "targetAccountId": "acc_bank",
  "method": "email",
  "verifiedAt": "2026-08-24T10:00:00Z",
  "note": null
}
```

Read as: *the Google account can be used to recover the bank account.* `method` is one of `email`, `sms`, `voice`, `backupCodes`, `securityQuestions`, `trustedContact`, `hardwareKey`, `other`.

### 3.4 Validation rules a decoder must enforce

- Every `item.accountId` and every `link` endpoint resolves to an existing account.
- Identifiers are unique within their collection.
- `digits` within the range for that `otpType` (see §3.3); `period` between 1 and 300.
- `counter` MUST be an integer when `otpType` is `hotp`. For any other kind it MUST be
  absent **or** `null`. Both spellings appear in the wild and in the vectors here, and a
  reader that requires absence rejects files this specification calls valid, including
  its own corpus.
- `secret` is valid Base32.
- Unknown `type` values: **preserve the object verbatim and skip it.** Never silently discard — a decoder from an older version must not destroy data written by a newer one on round-trip.
- **Unknown keys: preserve, wherever they appear.** At the document root, and inside every account, item, link and keeper. §6 promises that a new optional field is a minor change which an older decoder "ignores and preserves", and a new optional field lands on an account or a keeper far more often than at the root. Preserving only the root would keep that promise in the one place it matters least.
- Reject documents exceeding the ceilings in §3.2, before allocation.

That preservation rule is what makes forward compatibility real rather than aspirational. It is also easy to leave half-implemented, because preserving unknown item types looks like the hard part and is not the whole of it. A language whose object mapping reads named fields will drop everything else by default and give no sign that it did. Family 03 of the corpus therefore carries an unknown key at the root *and* inside an account, a link and a keeper, so a decoder that implements only some of this fails a vector rather than shipping.

### 3.5 Reserved root keys

A writer may need to store something beside the vault that is not vault
contents: how one person had arranged their own copy of an application, what
they had dismissed, what they had corrected. §3.4 already makes this work —
every decoder preserves unknown keys at the root, and family 03 proves it — so
this section reserves a name rather than adding a mechanism. Nothing here
requires anything of a decoder that §3.4 did not already require.

| Key | Meaning |
|---|---|
| `application` | Written by an application for its own use. **Opaque to this format.** A decoder MUST preserve it like any other unknown key and MUST NOT interpret it. |

**One key, so two writers cannot both claim it.** Without a name set aside, two
applications inventing their own root keys will eventually pick the same one
and silently overwrite each other's contents inside a file that opened cleanly.

**It is not vault data and MUST NOT be required to read one.** A file with this
key removed is still a complete vault. An implementation that has never heard
of the application that wrote it reads every account and item exactly as
before, and a reader that needs this key to make sense of a vault has
misunderstood what it is.

**What does not belong here.** Anything another implementation would need in
order to show the user their own data. If a fact matters to the vault, it
belongs in a field of its own with a version bump behind it, not in an opaque
blob one application can read.

```json
{
  "formatVersion": 1,
  "vaultId": "vlt_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
  "accounts": [],
  "items": [],
  "application": {
    "note": "Contents are the writing application's own. Preserve, do not read."
  }
}
```

### 3.6 Keepers

```json
{
  "id": "kpr_01H...",
  "displayName": "Sara",
  "contact": "sara@example.com",
  "bundleId": "bnd_01H...",
  "fragmentIndex": 2,
  "issuedAt": "2026-08-24T10:00:00Z",
  "lastConfirmedAt": "2026-11-01T10:00:00Z",
  "status": "active"
}
```

`status` is one of `active`, `unreachable`, `revoked`. **The fragment itself is never stored in the vault** — the whole point is that it left. Only the index is kept, so the app can tell the user which fragment a given keeper holds.

**Handover bundle**

```json
{
  "id": "bnd_01H...",
  "label": "Bank and email",
  "itemIds": ["itm_...", "itm_..."],
  "threshold": 3,
  "total": 5,
  "setId": "4F3A9C21...",
  "createdAt": "...",
  "rehearsedAt": "2026-08-25T09:00:00Z",
  "supersededBy": null
}
```

`rehearsedAt` is null until a real reconstruction has succeeded. A keeper set MUST NOT be presented as armed while it is null: an arrangement that has never been reconstructed is an arrangement nobody has evidence works, and the moment it is needed is the wrong moment to find out.

**Where bundle records live: `bundles`, at the document root.** An optional
array of the objects above, absent or empty on a vault that has none. A
keeper's `bundleId` resolves into it, and §4.7's rotation needs it: marking one
bundle `supersededBy` another means both are on record, so a vault that could
hold only one could not describe a rotation at all.

`bundles` and `handover` are different keys and mean opposite things. `bundles`
is a vault's record of the arrangements it has made. `handover` is the object
in §4.2 that marks a file as *being* a bundle rather than a vault, and §4.2
requires it to be absent from every vault: its presence is the one bit that
says which kind of file this is, checkable before anything else is trusted. A file carrying both is malformed:
it claims to be the thing it is describing.

**A bundle record contains no key material and no secret.** It names items by
identifier, records the shape of the split, and says when it was last
rehearsed. Everything that could open anything left the device by design.

A decoder that does not implement handover still preserves `bundles`
untouched, under the preservation rule in §3.4. Layer 1 writes vaults without
it, and must return one it reads exactly as it arrived.


### 3.7 Identifiers

Identifiers are strings of the form `<kind>_<body>`, where `kind` is one of
`vlt`, `acc`, `itm`, `lnk`, `kpr`, `bnd` and `body` is 128 bits rendered in
Crockford Base32. The prefix makes a dump readable and makes a
copied-into-the-wrong-field identifier obvious.

Two generation schemes, and which one applies is fixed by the kind:

| Kind | Scheme | Reason |
|---|---|---|
| `vlt`, `acc`, `itm`, `lnk` | **Time-ordered** — the UUID version 7 layout: a 48-bit millisecond timestamp, the version and variant markers in their fixed positions, random elsewhere | They sort by creation, so a vault dump reads chronologically and a diff is meaningful |
| `kpr`, `bnd` | **Fully random** | These appear in handover URLs. A timestamp there would tell whoever holds the link when the handover was configured |

A reader MUST NOT infer meaning from an identifier beyond its kind prefix.
The timestamp in a time-ordered identifier is a convenience for diagnostics,
never a substitute for `createdAt`, which is the authoritative value.

An implementation MAY use any identifier scheme it likes when writing, provided
identifiers are unique within their collection. The scheme above is what this
implementation writes and what a reader should expect in practice.

---

## 4. Handover bundles and fragments

### 4.1 The vault key is never split

A handover is a subset: the bank and the email, not everything. Splitting the vault key cannot express that, because the vault key opens the whole vault. Keepers would receive far more than they were told they held, silently and undetectably.

**Therefore:**

1. The user selects the items to hand over.
2. A **fresh 32-byte key** is generated by the CSPRNG.
3. Those items are written as a **Handover Bundle** — a normal Impression per §2, with `kdfId = 0x00`, encrypted under that fresh key.
4. **That key** is split into fragments.
5. The vault key is not involved and never leaves the device.

The bundle is reviewable by the user before distribution, and it bounds the consequence of keeper collusion (threat C1) to exactly what was chosen. A user with three handover bundles has three independent fragment sets, each opening only its own bundle.

### 4.2 What is inside a handover bundle

The envelope is ordinary. The plaintext inside it is a vault document per §3,
carrying only the accounts and items being handed over, plus one object saying
what this is and where it came from:

```json
{
  "formatVersion": 1,
  "vaultId": "vlt_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
  "createdAt": "2026-08-24T10:00:00Z",
  "updatedAt": "2026-08-24T10:00:00Z",
  "accounts": [],
  "items": [],
  "links": [],
  "keepers": [],
  "handover": {
    "bundleId": "bnd_01J8ZKQ4T7NBVX2M9DCFGH3RWY",
    "setId": "4F3A9C21000000000000000000000000",
    "threshold": 3,
    "total": 5,
    "sealedAt": "2026-08-24T10:00:00Z",
    "note": "For the family. The bank and the email."
  }
}
```

A bundle is a vault document so that anything able to read a vault can read a
bundle. A keeper reconstructing one in ten years is the least supported user
this format has, and giving them a second document type to find a reader for is
a way of making a bad day worse.

**Rules a decoder MUST enforce:**

| Rule | Why |
|---|---|
| `handover` present means this is a bundle, absent means it is a vault | One bit, checkable before anything else is trusted |
| `vaultId` is the vault it was cut from, not a new one | A keeper handing it back must be matchable to the original |
| `bundleId` is unique per bundle, and stable across reissues of the same set | Rotation replaces the fragments, not the identity of what they open |
| `setId` matches the `setId` in every fragment of the set | Catches a fragment from another set before the reconstruction fails obscurely |
| `threshold` and `total` match the fragments | A bundle that disagrees with its fragments about *k* cannot be opened by following its own instructions |
| `keepers` MUST be empty | A keeper arrangement is a fact about the vault, and copying it into what the keepers hold tells each of them who the others are |
| `links` MUST reference only accounts present in the bundle | A dangling link names an account the keeper was not given, which leaks that it exists |

`note` is what the user wrote for the keepers and is shown to them verbatim. It
is the only free text here, and a decoder MUST NOT interpret it.

A bundle is a valid vault document, so `formatVersion` and §3.4 apply to it
unchanged.

### 4.3 Fragments

The Shamir shares distributed to keepers. **Shamir's Secret Sharing over GF(2⁸)**, applied byte-wise to the 32-byte **bundle** key, with the standard AES field polynomial `0x11B`.

### 4.4 Fragment binary form

```
Offset  Size  Field       Notes
------  ----  ----------  --------------------------------------
0       7     magic       ASCII "SEALFRG"
7       1     version     0x01
8       16    setId       Identifies the split this belongs to
24      1     index       1–255. The x-coordinate. MUST NOT be 0
25      1     threshold   k
26      1     total       n
27      2     shareLen    Length of the share
29      L     share       The y-values
29+L    4     checksum    CRC-32 of bytes 0..29+L-1
```

`index` is never 0, because *f(0)* is the secret itself. As in §2.1, all integers are big-endian.

The checksum is the CRC-32 of IEEE 802.3 — polynomial `0x04C11DB7`, reflected, initial value and final XOR `0xFFFFFFFF`; the same function zlib, gzip and PNG use — stored big-endian. It detects transcription error, not tampering. It is not a security control and the specification says so, because a checksum in a security format that is not labelled invites the wrong assumption.

### 4.5 Fragment paper form

For hand transcription, a fragment is encoded in **Crockford Base32** — case-insensitive, and excludes `I`, `L`, `O` and `U` precisely because those are the characters people mistranscribe. Grouped in fives, with the set identifier and the `k`-of-`n` printed in plain language alongside:

```
Sealstone fragment 2 of 5 — any 3 open it together
Set 4F3A-9C21

  H8K2M  4NP7Q  R9T3V  W5X8Y  Z2B6C
  D4F7G  H9J2K  L5M8N  P3Q6R  S9T2V
  ...
```

**Crockford decoding is lenient by design:** `I` and `l` map to `1`, `O` maps to `0`, and case is ignored. This is the difference between a keeper who succeeds and a keeper who gives up.

### 4.6 What a keeper must hold

A fragment set reconstructs the **bundle key**. It does not carry the bundle.

The sealed handover bundle is an ordinary Impression of a few kilobytes, and no
amount of it can be transcribed from paper. Every keeper therefore receives two
things:

| Item | Form | Identical across keepers? |
|---|---|---|
| The sealed handover bundle | A `.seal` file | **Yes.** It is ciphertext and opens for nobody without *k* fragments |
| Their fragment | Binary file or printed sheet | No. One per keeper |

Distributing fragments without the bundle produces a handover that fails at the
only moment it is used. An implementation MUST track both and MUST NOT report a
handover as armed until every keeper holds both.

### 4.7 Rotation, and what it cannot do

Removing or replacing a keeper means **reissuing the whole set**:

1. Generate a fresh bundle key.
2. Re-encrypt the handover bundle under it.
3. Split the new key into a new fragment set with a new `setId`.
4. Distribute to the current keepers.
5. Mark the old bundle `supersededBy` the new one; the relay deletes the old ciphertext.
6. **Rehearse again.** `rehearsedAt` resets to null.

> **The limitation, stated plainly because the interface must state it too.**
> Reissuing invalidates the old set going forward. It does **not** reach backwards. A keeper who kept a copy of the old bundle *and* their old fragment, and who can find enough other old fragments, retains access to that snapshot of that data forever.
>
> You cannot un-give something you have already given. The honest response is to say so at the moment a keeper is removed, and to recommend rotating the underlying credentials themselves — which is the only thing that actually revokes access.

This is the same shape of truth as a forgotten passphrase: irreducible, a direct consequence of having no vendor authority, and better said out loud than discovered.

---

## 5. The Paper Impression

Not a fallback. A designed artifact and a first-class export target.

**Contents:** what this document is and what to do with it, in plain language; the accounts that matter and their recovery paths; optionally, fragments; optionally, the passphrase; the date it was made; the URL of this specification.

**Constraints:** legible printed at A4 or US Letter on a domestic printer in black and white. No QR code as the *only* representation of anything — a scanner in ten years is an assumption, and human-readable characters are not. Every secret grouped for transcription. No Sealstone branding above the instructions.

> **Open decision.** Whether the passphrase is included by default. Including it makes the sheet self-sufficient and makes the sheet the single point of failure. Excluding it makes the sheet safe to store loosely and useless alone. **Recommendation: excluded by default, includable with an explicit choice and a clear statement of what changes.**

---

## 6. Versioning

| Change | Version bump | Old decoder behaviour |
|---|---|---|
| New optional field | Minor | Ignores and preserves it |
| New item type | Minor | Preserves and skips it |
| New algorithm identifier | Minor | Refuses that file, decodes others |
| Layout change | **Major** | **Refuses** |
| Semantic change to an existing field | **Major** | **Refuses** |

`password` was added the same way and for the same reason: a new item type is
a minor change, an older decoder preserves it and skips it, and no release has
happened for a bump to inform.

**A minor bump is for a field added after a version has shipped.** No release
has happened, so optional fields added before the first one are simply part of
v1 and carry no bump. The freeze in §8.1 covers the layout in §2.1, the meaning
of existing fields, and the parameter ranges; an optional field touches none of
them. Bumping the minor would signal "this may contain something you have not
heard of" to a decoder population that does not exist yet.

**Every version ever published must remain decodable by the current application, forever.** Migration tests run against a corpus containing at least one file from every released version, in `vectors/09-versions`.

---

## 7. Test vectors

Ship with the specification, and version them alongside it. **Built and passing** — `vectors/` in `sealstone-format`, regenerated deterministically by `vectors/generate.py`, indexed by `manifest.json`.

| # | Family | Kind | Cases |
|---|---|---|---|
| 01 | Empty vault | opens | — |
| 02 | Single TOTP item | opens | — |
| 03 | Full vault: every item type, an authenticator of each `otpType` including a five-digit Steam code, three links, a keeper, an unknown item type, and unknown keys at the root and inside an account, a link and a keeper, all of which must survive a round trip untouched | opens | — |
| 04 | NFC passphrase — precomposed and decomposed spellings must both open the same file | opens | 2 spellings |
| 05 | Tamper: one bit flipped in each region of the file | **all must fail** | 15 |
| 06 | Wrong passphrase, empty passphrase, and correct passphrase with trailing whitespace | **all must fail** | 3 |
| 07 | Hostile KDF parameters, above and below every limit | **rejected before allocation** | 6 |
| 08 | 3-of-5 Shamir: every reconstructing subset listed, every subset one share short of the threshold listed | both directions | 10 + 10 |
| 09 | One file per released version, plus a genuinely sealed forward-minor file, a patched-minor file, and an unknown-major file | mixed | 4 |
| 10 | Production parameters — 64 MiB, t=3, p=4 | opens | marked slow |
| 11 | The same file cut short at each structurally interesting offset | **rejected with a clear error** | 12 |
| 12 | Identifiers: every kind, the malformed forms a reader must reject, and the transcription substitutions it must accept | mixed | 6 + 8 + 4 |

**Both directions of the minor-version rule are covered.** A file *sealed* with an unknown minor version must open; a file whose minor byte was *patched* after sealing must fail — and must fail on the authentication tag rather than on version grounds, since the version itself is legal. Only the first can be produced by sealing, and only the second by tampering, so both vectors are needed.

**Rules the corpus enforces on itself**, checked by its own test suite: every file the manifest names must exist; the tamper family must cover every region of the file; the Shamir family must list *every* threshold-sized subset rather than a sample; the limits declared in the manifest must match the implementation's constants; the item types the decoder knows must be exactly the types the table in §3.4 declares; and the identifier kinds the manifest declares must be exactly the kinds the decoder implements, so a manifest cannot drift into describing a format nobody has.

**A rule that only a vector can enforce.** The Steam credential in family 03 is there because the decoder once applied the six-to-ten digit range to every `otpType` and so refused a five-digit Steam code this specification calls valid. Nothing caught it: the specification said one thing, the decoder did another, and with no vector carrying the case the suite agreed with both. A rule written down and not exercised is a rule two implementations can read differently forever.

**The KDF parameters in the corpus are deliberately far too weak, except in family 10.** Every other family is sealed with 64 KiB of memory and a single iteration, so the whole corpus can be verified in a scripting language in seconds. Those numbers protect nothing and MUST NOT be copied into an implementation; §2.2 has the ones that ship, and family 10 seals a file with them so the parameters that go out are not the least tested thing here. A reader that infers its defaults from a vector header will ship a file anybody can open.

Passphrases and secrets are stored as **hex-encoded UTF-8** so no implementer has to infer an encoding — which matters most for family 04, where the whole point is that two byte sequences must derive the same key.

**The reference decoder passes all of them.** It is written in Python rather than Swift precisely so it cannot share a bug with the implementation it verifies, and it is published alongside the specification. It is the only thing that turns the ownership claim from an assertion into a demonstration.

---

## 8. Decisions, closed

All five open decisions are resolved, and the freeze conditions in 8.1 are met. The format is frozen.

| # | Decision | Resolution |
|---|---|---|
| 1 | **Argon2id implementation** | **Vendored pure-Swift, in-repo.** Argon2id is in neither CryptoKit nor swift-crypto today, but a dependency-free pure-Swift implementation of RFC 9106 exists, and an Argon2id PR is open against `apple/swift-crypto`. A reviewed pure-Swift implementation is vendored into the Swift package rather than taken as a dependency: our source, our tests, no package reference, no supply chain. Correctness is proven against RFC 9106's official test vectors. **Migration trigger:** if Argon2id ships in CryptoKit or swift-crypto, move to the platform implementation and delete ours — the `kdfId` field makes that a non-event |
| 2 | **AEAD default** | **AES-256-GCM** (`aeadId = 0x01`). Hardware-accelerated on all supported Apple hardware. `aeadId` keeps the choice reversible; ChaCha20-Poly1305 stays specified at `0x02` and unused |
| 3 | **Passphrase on the Paper Impression** | **Excluded by default.** Includable by explicit user choice, with the consequence stated in the same breath: including it makes the sheet self-sufficient *and* makes the sheet a single point of failure |
| 4 | **Vault-at-rest store format** | **Reuse this envelope.** One format is one thing to get right, one thing to audit, one thing to document, and one thing to migrate. The at-rest key comes from the Keychain rather than a passphrase, so `kdfId = 0x00` (`none`) is reserved for that case and the KDF parameter fields are zero |
| 5 | **Parameter ranges** | **Specified normatively in §2.2.** Floors and ceilings: `8p`–1 GiB, 1–16, 1–16, plus a mandatory available-memory check before derivation |

### 8.1 Freeze conditions

The format is frozen — no layout change without a major version — once all of the following hold:

- [x] Vendored Argon2id passes every RFC 9106 vector.
- [x] All twelve test vector families in §7 exist and pass.
- [x] The Python reference decoder passes every one of them.
- [x] The envelope has been reviewed by someone who did not write it.

**All four hold. The format is frozen as of 24 August 2026.** The layout in §2.1, the field meanings, and the parameter ranges do not change again without a major version, and every decoder that opens a v1 file today must keep opening it.

The Argon2id condition was the last to be met in substance rather than on paper. An early implementation agreed with the RFC's own test vectors and was still wrong at every other parameter size, which no amount of cross-checking two implementations against each other could reveal, because both shared the same misreading. It is now checked against vectors produced by the reference implementation at eight parameter sets.

What freezing does not claim: this has not been through an independent security audit. Freezing fixes the format so that files written today stay readable; it is not a statement that the design has been adversarially reviewed by a third party. Any such audit, when it happens, can still change the *implementations* freely — the format is what is fixed, not the code.

---

## 9. The vault at rest, and iCloud Backup

The at-rest store uses this same envelope with `kdfId = 0x00` — the key comes from the Keychain rather than a passphrase.

| Decision | Value | Reason |
|---|---|---|
| Vault file in iCloud Backup | **Excluded** (`isExcludedFromBackup`) | An undeclared encrypted copy of the vault in Apple's infrastructure contradicts *nothing leaves this device unless you send it*, even though it would be ciphertext |
| Vault key accessibility | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Not synchronised, not migrated to a restored device |
| Restore path | **The sealed Impression, only** | One designed path, which the user has verified. This makes the backup habit load-bearing rather than optional, which is the intent of the whole product |
| macOS | Data protection keychain | The legacy file-based keychain has different access-control behaviour, so an implementation must opt in to get the same semantics as iOS |

**The consequence, and it is deliberate:** restoring a phone from an iCloud backup restores the *app*, not the *vault*. The user is shown a clear explanation and asked for their Impression. A product that quietly restored the vault from iCloud would be a product whose vault was in iCloud.

---

## 10. Knowledge base delivery

The Map needs to know how real services recover accounts. **The obvious implementation leaks the user's entire account list**, which is the most sensitive thing the product holds in aggregate, because it maps where someone's digital life is weakest.

**Normative rules:**

1. The knowledge base **ships bundled** with the application. The Map works fully offline, on day one, with no fetch.
2. Updates fetch **the entire signed bundle**. There is no per-service, per-domain, or per-query endpoint, and none may ever be added.
3. The request carries **only a bundle version**. No identifier, no vault-derived parameter, no account information, no device fingerprint.
4. The bundle is **signed**; an unverified bundle is discarded.
5. The fetch is made by `Features`, never by a core module, preserving property **P4**.
6. A stale bundle **never blocks** the Map. Staleness is displayed as a fact, and findings computed from stale data are marked.

Rule 2 is the load-bearing one. A per-service lookup would be more efficient, smaller, and easier — and it would transmit the shape of the user's digital life to us on every launch.

---

## 11. Relay authentication

The relay must know who is checking in, and the product has no accounts. It authenticates with a **signature, not a login**.

| Step | Mechanism |
|---|---|
| Arming | Generate an Ed25519 keypair. Private key stored in the vault; public key registered with the relay alongside the ciphertext and the interval |
| Check-in | The relay issues a challenge. The app signs it. No password, nothing to phish, nothing replayable |
| Contact | The user's notification address is held for warnings only |
| Compromise | A relay breach yields ciphertext, public keys, timers and contact addresses. **It does not yield the ability to impersonate a user**, because the relay never held anything secret |
| Loss | Losing the vault means losing the check-in key, which means the timer runs down and releases — **which is precisely the intended behaviour**. This is the mechanism working, not a failure mode |

That last row is worth sitting with: the failure mode of losing your device is the one the feature exists to handle, so the authentication design should not fight it.

---

## 12. Import formats at launch

Named so the scope is bounded. Each gets a dedicated adapter, a property-based test suite, and a committed fuzz corpus.

| Format | Notes |
|---|---|
| `otpauth://` URI | Single item. From QR, clipboard, or a text file |
| `otpauth-migration://` | Google Authenticator's batch export payload |
| Aegis | JSON, plain and encrypted |
| 2FAS | JSON backup |
| Ente Auth | Text and encrypted export |
| Raivo | JSON and ZIP |
| Generic JSON / CSV | Explicit column-mapping step, then the standard staging review |

**Every adapter follows the same rule without exception:** parse to staging, validate everything, show a review screen, resolve duplicates, commit atomically, never touch the source file.

Formats beyond this list are added on evidence — a real user with a real file — not on speculation.
