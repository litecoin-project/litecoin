# MWEB Descriptor Standard (Draft)

This document defines the **MWEB descriptor** function `mweb(...)` and its allowed encodings, with strict parsing and canonicalization rules.

## 1. Goals

- Provide a compact, deterministic way to represent MWEB wallet capabilities in a descriptor string.
- Unambiguously distinguish:
  - **Ranged** descriptors (covering all subaddresses).
  - **Single-subaddress** descriptors (covering one specific subaddress).
- Support both **spend-capable** (secret key) and **watch-only** (public key) forms.


## 2. Function signature and allowed forms

Valid forms are:

- `mweb(master_scan,master_spend,*)`
- `mweb(master_scan,master_spend,<i>)`
- `mweb(master_scan,subaddr_spend)`

### 2.1 Ranged (all subaddresses)

```
mweb(master_scan,master_spend,*)
```

Semantics:
- Identifies (and optionally spends) **all** MWEB outputs for the wallet.
- `master_spend` MAY be a secret key (spend-capable) or public key (watch-only).

### 2.2 Single (known subaddress index)

```
mweb(master_scan,master_spend,<i>)
```

Semantics:
- Identifies (and optionally spends) MWEB outputs for exactly one subaddress, specified by index `<i>`.
- `master_spend` MAY be a secret key (spend-capable) or public key (watch-only).
- `<i>` is a decimal, non-negative integer subaddress index.

### 2.3 Single (unknown index, subaddress spend key known)

```
mweb(master_scan,subaddr_spend)
```

Semantics:
- Identifies (and optionally spends) MWEB outputs for exactly one subaddress **without** explicitly encoding its index.
- `subaddr_spend` MAY be a secret key (spend-capable) or public key (watch-only).
- This form is used when the **master spend key** or the **subaddress index** is not known/available, but the **subaddress spend key** is.

## 3. Parameter rules

### 3.1 Parameter 1: `master_scan`

- The first parameter is always the **master scan key (scalar)**.
- **Never** a master scan public key.
- Encoded using a `KEY` expression (see Section 4).

### 3.2 Parameter 2: spend key (`master_spend` or `subaddr_spend`)

The meaning of the second parameter depends on form:

- In 3-parameter forms:
  - `mweb(master_scan,master_spend,*)`
  - `mweb(master_scan,master_spend,<i>)`
  - The second parameter is always **master spend** key material (secret or public).

- In the 2-parameter form:
  - `mweb(master_scan,subaddr_spend)`
  - The second parameter is always **subaddress spend** key material (secret or public).

### 3.3 Parameter 3: selector (`*` or `<i>`)

- In ranged form, the third parameter is the literal `*`.
- In indexed single form, the third parameter is the literal `<i>` where `i` is a decimal integer:
  - Example: `mweb(...,...,17)`

## 4. Key encoding (`KEY` expressions)

All key-like parameters (`master_scan`, `master_spend`, `subaddr_spend`) are encoded using standard `KEY` expressions.

**`KEY` expressions:**
- Optionally, key origin information, consisting of:
  - An open bracket `[`
  - Exactly 8 hex characters for the fingerprint of the key where the derivation starts (see BIP32 for details)
  - Followed by zero or more `/NUM` or `/NUM'` path elements to indicate unhardened or hardened derivation steps between the fingerprint and the key or xpub/xprv root that follows
  - A closing bracket `]`
- Followed by the actual key, which is either:
  - Hex encoded public keys (either 66 characters starting with `02` or `03` for a compressed pubkey, or 130 characters starting with `04` for an uncompressed pubkey).
    - Inside `wpkh` and `wsh`, only compressed public keys are permitted.
    - Inside `tr` and `rawtr`, x-only pubkeys are also permitted (64 hex characters).
  - WIF encoded private keys may be specified instead of the corresponding public key, with the same meaning.
  - `xpub` encoded extended public key or `xprv` encoded extended private key (as defined in BIP32).
    - Followed by zero or more `/NUM` unhardened and `/NUM'` hardened BIP32 derivation steps.
    - Optionally followed by a single `/*` or `/*'` final step to denote all (direct) unhardened or hardened children.
    - The usage of hardened derivation steps requires providing the private key.

(Anywhere a `'` suffix is permitted to denote hardened derivation, the suffix `h` can be used instead.)

## 5. Derivation relationship

If `master_scan`, `subaddr_spend`, and `<i>` are known, then `master_spend` can be derived in our MWEB key derivation design.

This enables import/export canonicalization (Section 6) and validation strategies (Section 7).

## 6. Canonicalization (export) rules

To prevent multiple encodings of the same underlying wallet material, implementations MUST serialize (export) MWEB descriptors using the following canonical forms:

1. **Ranged wallets**
   - Always export:
     - `mweb(master_scan,master_spend,*)`

2. **Single-subaddress wallets**
   - If `master_spend` and the subaddress index `<i>` are known/available:
     - Export:
       - `mweb(master_scan,master_spend,<i>)`
   - Otherwise (when `master_spend` or `<i>` is not known/available, but the subaddress spend key is known):
     - Export:
       - `mweb(master_scan,subaddr_spend)`

Notes:
- An importer MAY accept non-canonical but semantically equivalent representations if they are ever introduced, but exporters MUST follow the rules above.
- Wallets SHOULD preserve the originally imported form only as metadata; descriptor string output MUST be canonical.

## 7. Validation guidelines

On import, implementations SHOULD perform the strongest validation possible given the provided fields:

- For `mweb(master_scan,master_spend,<i>)`:
  - Derive the implied subaddress spend key for `<i>` and ensure internal consistency if the wallet also stores/learns subaddress material.

- For `mweb(master_scan,subaddr_spend)`:
  - No index consistency check is possible by definition.
  - The wallet MAY attempt discovery strategies if it later learns `master_spend` or an index mapping.

- For `mweb(master_scan,master_spend,*)`:
  - Validate literal `*`.
  - If the key material implies derivation paths, validate those paths per existing descriptor key parsing rules.

## 8. Grammar summary

All tokens are ASCII. No whitespace allowed.

```
mweb_desc :=
    "mweb(" master_scan "," master_spend ",*)" |
    "mweb(" master_scan "," master_spend "," index ")" |
    "mweb(" master_scan "," subaddr_spend ")"

index := DIGIT {DIGIT}

master_scan  := KEY   ; scalar (must be private key)
master_spend := KEY   ; master spend sk or pk
subaddr_spend:= KEY   ; subaddress spend sk or pk
```

Type constraints:
- `master_scan` MUST represent a scalar (private key material), not a public key.
- `master_spend` and `subaddr_spend` MAY be public or private key material.
- In 3-arg forms, the second parameter is **master** spend material.
- In the 2-arg form, the second parameter is **subaddress** spend material.

## 9. Behavior Summary

| Descriptor Form                | Range? | Scan? | Spend? | Notes |
|--------------------------------|---:|---:|---:|---|
| `mweb(master_scan_sk,master_spend_sk,*)` | ✅ | ✅ | ✅ | Full wallet |
| `mweb(master_scan_sk,master_spend_pk,*)` | ✅ | ✅ | ❌ | Watch‑only |
| `mweb(master_scan_sk,master_spend_sk,i)` | ❌ | ✅ | ✅ | Single subaddress |
| `mweb(master_scan_sk,master_spend_pk,i)` | ❌ | ✅ | ❌ | Single view‑only |
| `mweb(master_scan_sk,subaddr_spend_sk)` | ❌ | ✅ | ✅ | Single subaddress |
| `mweb(master_scan_sk,subaddr_spend_pk)` | ❌ | ✅ | ❌ | Single view‑only |
