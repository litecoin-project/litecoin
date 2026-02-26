# MWEB PSBT Specification

*Extension to PSBT v2 for MimbleWimble Extension Blocks on Litecoin*\
**Draft 0.1 – 2025‑04‑27**

---

## 1  Overview

Partially‑Signed Bitcoin Transactions (PSBT) are defined in BIP‑0174 (v0) and BIP‑0370 (v2).  This document specifies the additional key–value pairs that allow a PSBT v2 to carry all data required to build, exchange, and sign MimbleWimble Extension Block (MWEB) transactions used by Litecoin.  All unchanged rules from BIP‑0370 continue to apply except where explicitly overridden here.  In particular:

- The magic bytes (`70 73 62 74 ff`) and overall section ordering **do not change**.
- Non‑MWEB wallets may ignore unrecognised MWEB keys as mandated by PSBT’s forward‑compatibility rules.

A *Packet* therefore comprises **one global map**, followed by `inputCount` input maps, `outputCount` output maps, and `kernelCount` kernel maps:

```
┌──────────────-┐
│  Global Map   │
├──────────────-┤
│ Input Map 0   │
│      …        │  × inputCount
│ Input Map N‑1 │
├──────────────-┤
│ Output Map 0  │
│      …        │  × outputCount
│ Output Map M‑1│
├──────────────-┤
│ Kernel Map 0  │
│      …        │  × kernelCount
│ Kernel Map K‑1│
└──────────────-┘
```

All numeric fields are little‑endian unless noted otherwise.

---

## 2  Global Map

In addition to the PSBT v2 keys, the following new keys are defined. The *key‑type byte* values are tentative and allocated from the proprietary range (`0xFC`–`0xFE`) until finalisation.

| Key‑type   | Key‑data | Value‑data | Presence                             | Meaning                                                                                                         |
| ---------- | -------- | ---------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| **0x**`FC` | –        | `32 bytes` | opt.req. in final tx                 | **MwebTxOffset** – aggregate excess blinding factor (a.k.a. *offset*) for the MWEB kernel sum.                  |
| **0x**`FD` | –        | `32 bytes` | opt.req. in final tx                 | **MwebStealthOffset** – stealth offset masking the sender’s excess point when using stealth excess commitments. |
| **0x**`FE` | –        | *var‑int*  | required if `kernelCount` ≠ implicit | **MwebKernelCount** – number of kernel maps to follow. Must equal *kernelSlice.len*.                            |

> **Compatibility:** These keys **MUST NOT** appear in a PSBT whose `psbtVersion` is `0`.  Their presence in a legacy packet invalidates the packet.

All existing global keys from BIP‑0370 (e.g. `Version`, `TxVersion`, `FallbackLocktime`, etc.) remain unchanged.

---

## 3  Input Map Extensions

The table below lists every new MWEB‑specific input key.  For brevity the standard BIP‑0174/BIP‑0370 keys (Non‑Witness UTXO, FinalScriptSig, etc.) are not repeated.

| Key‑type                                                              | Key‑data | Value‑data    | Allowed in v0 | Allowed in v2 | Meaning                                                                                                                      |
| --------------------------------------------------------------------- | -------- | ------------- | ------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `0xFC`                                                                | –        | `32 bytes`    | ✗             | ✓             | **MwebOutputId** – hash referencing the                                                                                      |
| MWEB output being spent (alternate to explicit commit/pub‑key tuple). |          |               |               |               |                                                                                                                              |
| `0xFD`                                                                | –        | commitment    | ✗             | ✓             | **MwebCommit** – Pedersen commitment of the spent output. Either this **or** *OutputId* **MUST** be present.                 |
| `0xFE`                                                                | –        | x‑only pubkey | ✗             | ✓             | **MwebOutputPubkey** – owner pubkey of the output being spent.                                                               |
| `0xF4`                                                                | –        | x‑only pubkey | ✗             | ✓             | **MwebInputPubkey** – excess pubkey corresponding to this input (a.k.a. *payment key*).                                      |
| `0xF5`                                                                | –        | `1 byte`      | ✗             | ✓             | **MwebInputFeatures** – bit‑field describing feature flags (e.g. plain = 0x00).                                               |
| `0xF6`                                                                | –        | signature     | ✗             | ✓             | **MwebInputSignature** – Schnorr sig over message `H(MWEB tx)` signed with *MwebInputPubkey*. Required when finalised.       |
| `0xF7`                                                                | –        | `4 bytes`     | ✗             | ✓             | **MwebAddressIndex** – 32‑bit index into the wallet’s address table for change detection. Optional metadata.                 |
| `0xF8`                                                                | –        | `8 bytes`     | ✗             | ✓             | **MwebAmount** – explicit amount of the coin (for UI / fee‑estimation). Optional; can be derived from commitment+rangeproof. |
| `0xF9`                                                                | –        | `32 bytes`    | ✗             | ✓             | **MwebSharedSecret** – shared secret `r·Q` used in ECDH for confidential addresses.                                          |
| `0xFA`                                                                | –        | x‑only pubkey | ✗             | ✓             | **MwebKeyExchangePubkey** – sender’s ECDH public key `R`.                                                                    |
| `0xFB`                                                                | –        | TLV blob      | ✗             | ✓             | **MwebInputExtraData** – arbitrary application‑specific data.                                                                |

### 3.1  Input Sanity Rules

- Exactly one of **MwebOutputId** *or* the triplet {**MwebCommit**, **MwebOutputPubkey**, **MwebInputPubkey**} **MUST** be present.
- **MwebInputSignature** becomes mandatory once the PSBT is *finalized*.
- No MWEB key may appear more than once per map.

---

## 4  Output Map Extensions

| Key‑type | Key‑data | Value‑data          | v0 | v2 | Meaning                                                                                                 |
| -------- | -------- | ------------------- | -- | -- | ------------------------------------------------------------------------------------------------------- |
| `0xFC`   | –        | stealth addr (66 B) | ✗  | ✓  | **MwebStealthAddress** – concatenation of scan & spend x‑only pubkeys.                                  |
| `0xFD`   | –        | commitment          | ✗  | ✓  | **MwebCommit** – Pedersen commitment of the output amount. Required for finalised outputs.              |
| `0xFE`   | –        | `1 byte`            | ✗  | ✓  | **MwebFeatures** – message layer feature bits.                                                          |
| `0xF4`   | –        | x‑only pubkey       | ✗  | ✓  | **SenderPubkey** – sender’s one‑time key R for ECDH.                                                    |
| `0xF5`   | –        | x‑only pubkey       | ✗  | ✓  | **OutputPubkey** – excess pubkey corresponding to this output.                                          |
| `0xF6`   | –        | struct (58 B)       | ✗  | ✓  | **MwebStandardFields** – compact encoding of *(R, view‑tag, enc\_value, enc\_nonce)* for light wallets. |
| `0xF7`   | –        | range‑proof         | ✗  | ✓  | **RangeProof** – Bulletproof proving commitment ≥ 0 and < 2⁶⁴. Required in finalised PSBT.              |
| `0xF8`   | –        | signature           | ✗  | ✓  | **MwebSignature** – signature by *OutputPubkey* authorising message layer data.                         |
| `0xF9`   | –        | TLV blob            | ✗  | ✓  | **MwebExtraData** – arbitrary extra data.                                                               |

Sanity rules parallel those of the input map.

---

## 5  Kernel Map

Each kernel map encodes one MWEB *transaction kernel*.

| Key‑type | Key‑data | Value‑data    | Meaning                                                                  |
| -------- | -------- | ------------- | ------------------------------------------------------------------------ |
| `0xFC`   | –        | commitment    | **ExcessCommitment** – Pedersen commitment of kernel excess.             |
| `0xFD`   | –        | x‑only pubkey | **StealthExcess** – masked excess when sender anonymity is desired.      |
| `0xFE`   | –        | `8 bytes`     | **Fee** – fee paid by this kernel (litoshis).                            |
| `0xF4`   | –        | `8 bytes`     | **PeginAmount** – amount entering MWEB via this kernel.                  |
| `0xF5`   | –        | *TxOut*       | **Pegout** – legacy output leaving MWEB (repeated key allowed).          |
| `0xF6`   | –        | `4 bytes`     | **LockHeight** – “CSV” style absolute block height.                      |
| `0xF7`   | –        | `1 byte`      | **Features** – kernel feature bits (00 = Plain, 01 = Height‑locked, …).  |
| `0xF8`   | –        | TLV blob      | **ExtraData** – additional application data.                             |
| `0xF9`   | –        | signature     | **Signature** – Schnorr sig proving excess. Required to finalise kernel. |

Multiple **Pegout** records may appear; all other keys are unique.

---

## 6  Modifiability Flag

The global key **TxModifiableFlag** (defined in BIP‑0370) applies unchanged. In practice wallets building an MWEB PSBT SHOULD set the flag to `00` (non‑modifiable) once any MWEB signature or range‑proof has been attached.

---

## 7  Validation Workflow

An implementation SHOULD perform the following high‑level checks (see `(*Packet).SanityCheck()` in reference code):

1. **Structural correctness:** counts match (`inputCount`, `outputCount`, `kernelCount`) and all required global keys are present.
2. **Per‑map uniqueness:** each key‑type/key‑data tuple appears only once.
3. **Version gating:** MWEB keys are rejected when `psbtVersion == 0`.
4. **Cross‑field coherence:**
   - For every input spending an explicit `MwebCommit`, the corresponding commitment must be present in one of the supplied range‑proofs.
   - Sum(Inputs) − Sum(Outputs) = Sum(Fee) + *PeginAmount* − *PegoutAmount*.
5. **Cryptographic validity:** all included signatures, commitments, range‑proofs and bulletproofs verify against the supplied data.

A PSBT failing any mandatory rule **MUST** be rejected.

---

## 8  Examples

Detailed, annotated examples (hex + base64) will be added in a subsequent revision.

---

## 9  Open Issues / TODO

- Allocate final key‑type IDs in the reserved PSBT v2 ranges once BIPs are updated.
- Define canonical order for kernel maps (currently unspecified).
- Expand *Examples* section.

---

## 10  Reference Implementation

The Go reference implementation lives in `ltcsuite/lnd/psbt/mweb.go` (excerpt included below for convenience).

```go
// Packet is the actual psbt representation …
// See source for full details.
```

---

© 2025 Litecoin Core Developers.  Licensed under the MIT License.

