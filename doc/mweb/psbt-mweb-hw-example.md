# MWEB PSBT External Signer Example

This document walks through the intended PSBTv2 flow for creating, signing,
finalizing, and extracting an MWEB transaction when the spend keys live outside
the online wallet, for example on a hardware wallet.

It describes the MWEB PSBT fields implemented in this branch. The older draft
field table in `doc/mweb/psbt-mweb.md` uses provisional `0xFC` style values;
the live implementation uses the `0x90` MWEB key range shown below.

## Current Status

The online wallet can create, update, combine, finalize, and extract MWEB
PSBTs. A software wallet can sign the whole MWEB portion in one pass through
`walletprocesspsbt` or `CWallet::FillPSBT(sign=true)`.

The exact hardware-wallet flow described here is not fully implemented yet.
The most important missing pieces are:

- Standard external-signer routing is not wired to MWEB ownership metadata yet.
  It still expects standard key-origin data such as `hd_keypaths`, while MWEB
  spends use `mweb.address_descriptor`, `mweb.key_exchange_pk`, and related
  metadata.
- MWEB signing is all-or-nothing. `PSBTSignMWEBTx` rebuilds the mutable MWEB
  transaction and signs inputs, outputs, kernels, offsets, and range proofs
  together.

Until those gaps are fixed, treat this document as a hardware-signer target
flow and as a checklist for what an integration must provide.

## Actors

- Online wallet: connected node and watch-only wallet. It selects coins,
  builds the PSBT, adds public UTXO data, estimates fees, and broadcasts the
  final transaction.
- External signer: hardware wallet or signer process. It owns the MWEB scan
  and spend key material needed to identify coins, derive spend keys, create
  output proofs, sign inputs, sign kernels, and compute offsets.
- Recipient: provides an MWEB stealth address.

The example below is an MWEB-to-MWEB spend. Pegin and pegout notes are included
where the fields differ.

## Field Cheat Sheet

### Global MWEB Fields

| Key type | Field | `decodepsbt` name | Set by | Notes |
| --- | --- | --- | --- | --- |
| `0x90` | `PSBT_GLOBAL_MWEB_TX_OFFSET` | `mweb_tx_offset` | Signer | Final aggregate kernel offset. Required for any final MWEB transaction. |
| `0x91` | `PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET` | `mweb_stealth_offset` | Signer | Final stealth offset. Required for any final MWEB transaction. |
| `0x92` | `PSBT_GLOBAL_MWEB_KERNEL_COUNT` | not currently decoded | Creator | Compact-size count of kernel maps that follow the output maps. |

MWEB PSBTs should always be PSBTv2. RPC creators default to PSBTv2, and MWEB
input/output fields plus kernel count are rejected when parsing PSBTv0. Callers
should still pass `psbt_version=2` and reject v0 when any MWEB field is present,
because some MWEB global offset serialization paths are not explicitly v2-gated.

### Input MWEB Fields

| Key type | Field | `decodepsbt` name | Set by | Notes |
| --- | --- | --- | --- | --- |
| `0x90` | `PSBT_IN_MWEB_OUTPUT_ID` | `mweb.output_id` | Creator/updater | Identifies the MWEB output being spent. This is what makes an input an MWEB input in this implementation. |
| `0x91` | `PSBT_IN_MWEB_COMMIT` | `mweb.output_commit` | Updater/signer | Commitment of the output being spent. |
| `0x92` | `PSBT_IN_MWEB_OUTPUT_PUBKEY` | `mweb.output_pubkey` | Updater/signer | Receiver public key of the spent output. |
| `0x93` | `PSBT_IN_MWEB_INPUT_PUBKEY` | `mweb.input_pubkey` | Signer | Ephemeral input public key used by the stealth-key input signature. |
| `0x94` | `PSBT_IN_MWEB_FEATURES` | `mweb.features` | Signer | Input feature byte. Current signing only supports the stealth-key feature. |
| `0x95` | `PSBT_IN_MWEB_INPUT_SIG` | `mweb.signature` | Signer | Schnorr signature for the MWEB input. |
| `0x96` | `PSBT_IN_MWEB_ADDR_DESCRIPTOR` | `mweb.address_descriptor` | Wallet/signer | Single-address MWEB descriptor for the subaddress that owns the spent output. The parser also tolerates the old 4-byte address-index value by ignoring it. |
| `0x97` | `PSBT_IN_MWEB_AMOUNT` | `mweb.amount` | Creator/updater | Explicit input amount. Required by the signer for balance and fee checks. |
| `0x98` | `PSBT_IN_MWEB_SHARED_SECRET` | `mweb.shared_secret` | Wallet/signer | ECDH shared secret. Sensitive; only include when the signer policy expects it. |
| `0x99` | `PSBT_IN_MWEB_KEY_EXCHANGE_PK` | `mweb.key_exchange_pk` | Updater | Public key from the spent output standard fields, used to derive the shared secret. |
| `0x9C` | `PSBT_IN_MWEB_EXTRA_DATA` | `mweb.extra_data` | Creator/signer | Extra input data committed by the input signature when the extra-data feature bit is set. |

### Output MWEB Fields

| Key type | Field | `decodepsbt` name | Set by | Notes |
| --- | --- | --- | --- | --- |
| `0x90` | `PSBT_OUT_MWEB_STEALTH_ADDRESS` | `mweb.address` | Creator | Recipient or change stealth address. |
| `0x91` | `PSBT_OUT_MWEB_COMMIT` | `mweb.output_commit` | Signer | Output commitment. |
| `0x92` | `PSBT_OUT_MWEB_FEATURES` | `mweb.features` | Signer | Output message feature byte. Standard fields are normally present. |
| `0x93` | `PSBT_OUT_MWEB_SENDER_PUBKEY` | `mweb.sender_pubkey` | Signer | Sender public key used in the output signature. |
| `0x94` | `PSBT_OUT_MWEB_OUTPUT_PUBKEY` | `mweb.output_pubkey` | Signer | Receiver/output public key. |
| `0x95` | `PSBT_OUT_MWEB_STANDARD_FIELDS` | split fields | Signer | Encodes key exchange public key, view tag, encrypted value, and encrypted nonce. |
| `0x96` | `PSBT_OUT_MWEB_RANGEPROOF` | `mweb.rangeproof` | Signer | Bulletproof range proof. |
| `0x97` | `PSBT_OUT_MWEB_SIG` | `mweb.sig` | Signer | Output Schnorr signature. |
| `0x98` | `PSBT_OUT_MWEB_EXTRA_DATA` | `mweb.extra_data` | Creator/signer | Extra output message data. Current signing preserves it and sets the output extra-data feature bit. |

### Kernel Fields

Kernel maps are serialized after all output maps. Their count is taken from
`PSBT_GLOBAL_MWEB_KERNEL_COUNT`.

| Key type | Field | `decodepsbt` name | Set by | Notes |
| --- | --- | --- | --- | --- |
| `0x00` | `PSBT_KERN_EXCESS_COMMIT` | `kernels[].commit` | Signer | Kernel excess commitment. |
| `0x01` | `PSBT_KERN_STEALTH_COMMIT` | `kernels[].stealth_commit` | Signer | Stealth excess commitment. |
| `0x02` | `PSBT_KERN_FEE` | `kernels[].fee` | Creator | MWEB fee paid by this kernel. |
| `0x03` | `PSBT_KERN_PEGIN_AMOUNT` | `kernels[].pegin_amount` | Creator | Amount entering MWEB through a pegin. |
| `0x04` | `PSBT_KERN_PEGOUT` | `kernels[].pegouts[]` | Creator | Pegout amount and script. Keydata contains the pegout index when serialized. |
| `0x05` | `PSBT_KERN_LOCK_HEIGHT` | `kernels[].lock_height` | Creator | Kernel lock height. |
| `0x06` | `PSBT_KERN_FEATURES` | not currently decoded | Creator/signer | Feature byte derived from fee, pegin, pegout, lock height, stealth excess, and extra data. |
| `0x07` | `PSBT_KERN_EXTRA_DATA` | `kernels[].extra_data` | Creator/signer | Extra kernel data. Current signing preserves it and sets the kernel extra-data feature bit. |
| `0x08` | `PSBT_KERN_SIG` | `kernels[].signature` | Signer | Kernel Schnorr signature. |
| `0xFC` | `PSBT_KERN_PROPRIETARY` | unknown | Any | Constant exists, but `PSBTKernel` stores unknowns rather than a proprietary map. |

## Step 1: Create a Watch-Only Wallet

The online wallet needs enough information to:

- derive or recognize MWEB receive/change addresses,
- select MWEB coins,
- estimate amounts and fees,
- populate public spent-output data,
- route the PSBT to the correct signer.

In a complete external-signer setup this should come from descriptors or a
signer-specific account export. The exact descriptor import is outside this
example, but the flow starts with a wallet that can watch the relevant MWEB
coins and create MWEB change:

```bash
litecoin-cli createwallet "mweb-watch" true true "" false true
litecoin-cli -rpcwallet=mweb-watch importdescriptors '[...]'
```

For hardware signing, the imported metadata should eventually populate the
single-address MWEB descriptor field for each MWEB input.

## Step 2: Create and Fund the PSBT

Use `walletcreatefundedpsbt` for normal wallet coin selection and fee
calculation. It defaults to PSBTv2; pass `psbt_version=2` explicitly when the
caller controls that argument.

```bash
PSBT=$(
  litecoin-cli -rpcwallet=mweb-watch walletcreatefundedpsbt \
    '[]' \
    '[{"tmweb1recipientaddress...":"1.00000000"}]' \
    0 \
    '{"includeWatching":true,"lockUnspents":true,"changeAddress":"tmweb1changeaddress..."}' \
    true \
    2 \
  | jq -r .psbt
)
```

After this step, the PSBT should contain:

- Global PSBTv2 fields: transaction version, fallback locktime, input count,
  output count, and MWEB kernel count if a kernel exists.
- MWEB input maps: at minimum `mweb.output_id`. If the wallet has coin
  metadata, it may also include `mweb.amount`, `mweb.output_commit`,
  `mweb.output_pubkey`, `mweb.key_exchange_pk`, `mweb.shared_secret`, or
  `mweb.address_descriptor`.
- MWEB output maps: `amount` and `mweb.address` for each recipient or change
  output. Commitments, range proofs, sender pubkeys, output pubkeys, output
  signatures, and standard fields are still absent.
- Kernel maps: fee, pegin amount, pegouts, lock height, and feature bits as
  applicable. The excess commitment, stealth commitment, and kernel signature
  are still absent.
- Global MWEB offsets: absent. They are signer outputs.

For a pegin, the unsigned transaction also has a main-chain pegin output and
the kernel has `pegin_amount`. For a pegout, the MWEB kernel has one or more
`pegouts` entries rather than normal main-chain recipient outputs.

## Step 3: Update Public UTXO Data

If the creator did not already have all spent-output public data, run
`utxoupdatepsbt`. This asks the node for the UTXO set, mempool, txindex, and
provided descriptors.

```bash
PSBT=$(litecoin-cli utxoupdatepsbt "$PSBT")
```

For MWEB inputs, this can fill:

- `mweb.output_commit`,
- `mweb.output_pubkey`,
- `mweb.key_exchange_pk`.

It does not sign, create range proofs, create kernel offsets, or fill MWEB
key-origin data.

A wallet update pass without signing can also be useful:

```bash
PSBT=$(
  litecoin-cli -rpcwallet=mweb-watch walletprocesspsbt \
    "$PSBT" \
    false \
    ALL \
    true \
    false \
  | jq -r .psbt
)
```

This can add wallet-known metadata. Be careful with `mweb.shared_secret`: it is
sensitive and `decodepsbt` prints it when present.

## Step 4: Inspect the PSBT

Use `decodepsbt` to check the exact field state:

```bash
litecoin-cli decodepsbt "$PSBT"
```

Before signing, the decoded MWEB maps should look roughly like this:

```json
{
  "psbt_version": 2,
  "input_count": 1,
  "output_count": 1,
  "inputs": [
    {
      "mweb": {
        "output_id": "...",
        "output_commit": "...",
        "output_pubkey": "...",
        "address_descriptor": "mweb(...,...,7)#...",
        "amount": 100500000,
        "key_exchange_pk": "..."
      }
    }
  ],
  "outputs": [
    {
      "amount": 100000000,
      "mweb": {
        "address": "tmweb1recipientaddress..."
      }
    }
  ],
  "kernels": [
    {
      "fee": 500000
    }
  ]
}
```

Use `analyzepsbt` for role status:

```bash
litecoin-cli analyzepsbt "$PSBT"
```

The PSBT should report the normal global `next: "signer"` role until all MWEB
input, output, kernel, and offset fields are present. There is no separate
`mweb_next` result field.

## Step 5: Hand the PSBT to the Signer

The current software-wallet signing path is:

```bash
SIGNED_PSBT=$(
  litecoin-cli -rpcwallet=mweb-watch walletprocesspsbt \
    "$PSBT" \
    true \
    ALL \
    true \
    false \
  | jq -r .psbt
)
```

That command signs MWEB components when the wallet has the needed MWEB scan,
spend, rewind, and sender-key material. It is not a complete hardware-wallet
route by itself.

The intended hardware signer command is the normal signer `signtx` interface:

```bash
printf 'signtx "%s"\n' "$PSBT" |
  litecoin-signer --stdin --fingerprint F23F9D4A --chain main
```

The standard external-signer wallet plumbing does not yet select MWEB-only
PSBTs because signer matching still looks at standard `hd_keypaths`. A signer
process that returns a PSBT can be merged back with `combinepsbt` when the MWEB
maps, offsets, and pegin scripts are compatible and non-conflicting.

## Step 6: What the Signer Must Verify

The signer should reject the PSBT unless all of these checks pass:

- The PSBT version is 2.
- The main transaction, MWEB inputs, MWEB outputs, and kernel maps match the
  user-confirmed payment, change, fee, pegin, and pegout policy.
- The transaction is not still marked modifiable once MWEB signatures or range
  proofs will be added.
- Every MWEB input has an output id, amount, commitment, output public key, and
  enough key-origin or shared-secret data to derive the spend key.
- Public spent-output data matches the signer's derived view of the coin.
- Output stealth addresses and amounts are exactly what the user approved.
- Pegin and pegout amounts balance with input amounts, output amounts, and
  fees.
- Any MWEB `extra_data` is explicitly accepted by signer policy and shown to the
  user. Current signing preserves and signs it, but the extracted transaction
  can still be rejected by standardness policy.

## Step 7: What the Signer Adds

For each MWEB input, the signer derives or verifies:

- the shared secret from the scan secret and `mweb.key_exchange_pk`, unless a
  trusted `mweb.shared_secret` is explicitly accepted by policy,
- the subaddress index and output spend key,
- the input blinding factor from the shared secret and amount,
- the input commitment and output public key.

Then it fills:

- `PSBT_IN_MWEB_FEATURES`,
- `PSBT_IN_MWEB_INPUT_PUBKEY`,
- `PSBT_IN_MWEB_INPUT_SIG`,
- `PSBT_IN_MWEB_AMOUNT`,
- any missing `PSBT_IN_MWEB_COMMIT`,
- any missing `PSBT_IN_MWEB_OUTPUT_PUBKEY`,
- optionally `PSBT_IN_MWEB_ADDR_DESCRIPTOR`.

It also preserves and signs any existing `PSBT_IN_MWEB_EXTRA_DATA`.

For each MWEB output, the signer generates sender entropy and fills:

- `PSBT_OUT_MWEB_COMMIT`,
- `PSBT_OUT_MWEB_FEATURES`,
- `PSBT_OUT_MWEB_SENDER_PUBKEY`,
- `PSBT_OUT_MWEB_OUTPUT_PUBKEY`,
- `PSBT_OUT_MWEB_STANDARD_FIELDS`,
- `PSBT_OUT_MWEB_RANGEPROOF`,
- `PSBT_OUT_MWEB_SIG`.

It also preserves and signs any existing `PSBT_OUT_MWEB_EXTRA_DATA`.

For each kernel, the signer chooses the kernel blinding factor and stealth
blinding factor, then fills:

- `PSBT_KERN_EXCESS_COMMIT`,
- `PSBT_KERN_STEALTH_COMMIT`,
- `PSBT_KERN_FEATURES`,
- `PSBT_KERN_SIG`.

It preserves any creator-supplied:

- `PSBT_KERN_FEE`,
- `PSBT_KERN_PEGIN_AMOUNT`,
- `PSBT_KERN_PEGOUT`,
- `PSBT_KERN_LOCK_HEIGHT`,
- `PSBT_KERN_EXTRA_DATA`.

Finally, the signer computes and fills:

- `PSBT_GLOBAL_MWEB_TX_OFFSET`,
- `PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET`.

For pegins, signing also finalizes the kernel id and the pegin scriptPubKey must
be updated to commit to that kernel id before standard LTC input signatures are
made.

## Step 8: Inspect the Signed PSBT

After signing:

```bash
litecoin-cli decodepsbt "$SIGNED_PSBT"
litecoin-cli analyzepsbt "$SIGNED_PSBT"
```

The decoded PSBT should now contain:

- `mweb_tx_offset` and `mweb_stealth_offset`,
- MWEB input `features`, `input_pubkey`, and `signature`,
- MWEB output commitment, features, sender pubkey, output pubkey, standard
  fields, range proof, and signature,
- kernel excess commitment, stealth commitment, and signature. Kernel features
  are serialized but not currently printed by `decodepsbt`.

`analyzepsbt` should report `next: "extractor"` once the full PSBT is ready
for extraction, again without a separate `mweb_next` field.

## Step 9: Finalize and Extract

Finalize with extraction enabled:

```bash
FINAL=$(
  litecoin-cli finalizepsbt "$SIGNED_PSBT" true
)

HEX=$(printf '%s\n' "$FINAL" | jq -r .hex)
```

Expected result:

```json
{
  "hex": "...",
  "complete": true
}
```

If `complete` is false, the result contains a PSBT instead of transaction hex.
Inspect it with `decodepsbt` and `analyzepsbt` to find missing or invalid
fields. Finalization now verifies final script signatures, MWEB input
signatures, pegin scripts, and the extracted MWEB transaction before returning
hex; a structurally complete but cryptographically invalid PSBT is not
extracted.

Broadcast the final transaction:

```bash
litecoin-cli sendrawtransaction "$HEX"
```

## Pegin and Pegout Differences

For a pegin:

- The main-chain transaction has an LTC output paying into the MWEB pegin
  script.
- The kernel has `PSBT_KERN_PEGIN_AMOUNT`.
- The signer must finalize the kernel before the pegin script can commit to the
  final kernel id.
- Standard LTC inputs should be signed after the pegin script is updated.

For a pegout:

- The recipient leaves MWEB through one or more `PSBT_KERN_PEGOUT` entries.
- The pegout amount is part of the kernel, not a normal PSBT output map.
- The signer must include pegout amounts and scripts in the kernel signature
  message and in the user-confirmed payment summary.

For pegin-plus-pegout transactions:

- Both `PSBT_KERN_PEGIN_AMOUNT` and `PSBT_KERN_PEGOUT` can be present.
- Fee accounting must include LTC inputs, normal outputs, MWEB input amounts,
  MWEB output amounts, pegins, pegouts, and kernel fees consistently.

## Review Notes and Current Issues

These notes reflect the current code and remaining gaps:

- Standard external-signer routing is not MWEB-aware yet. Hardware signing
  needs signer matching based on MWEB ownership metadata, not only standard
  `hd_keypaths`.
- `PartiallySignedTransaction::Merge` now supports compatible MWEB PSBTs, but
  it intentionally rejects conflicts in strict MWEB fields, offsets, kernel
  data, and finalized pegin scripts.
- MWEB signing is not separated by PSBT role. `PSBTSignMWEBTx` signs inputs,
  outputs, kernels, range proofs, peg-in script updates, and offsets together.
- `FinalizePSBT` verifies final script signatures, MWEB input signatures,
  finalized pegin scripts, and the extracted MWEB transaction before returning
  hex. `IsComplete()` remains a structural field-presence check.
- PSBTv0 gating is still uneven around MWEB globals. MWEB input and output
  fields and kernel count reject v0 on parse, but offset globals and some
  serialization paths are not consistently v2-only.
- MWEB `extra_data` is preserved and signed, and `decodepsbt` prints input,
  output, and kernel extra data. Transactions containing it may still be
  rejected by standardness policy, so hardware signer policy should be explicit.
- Kernel pegout keydata contains an index when serialized, but parsing ignores
  that index and pushes pegouts in wire order.
- Transaction modifiability is not enforced for MWEB. Signers should clear or
  reject `PSBT_GLOBAL_TX_MODIFIABLE` before adding MWEB signatures and proofs.
- MWEB input detection requires `PSBT_IN_MWEB_OUTPUT_ID`. The alternate
  "explicit commitment and pubkey tuple without output id" idea is not
  implemented.
- `decodepsbt` omits some MWEB fields that would be useful while debugging,
  including kernel count and kernel features.
- `walletprocesspsbt sign=false` can expose `mweb.shared_secret` in the PSBT
  when the wallet has it. That may be useful for some signer designs, but it is
  sensitive metadata and should be explicit policy.
