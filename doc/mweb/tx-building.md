# Transaction Building

## Input Selection

Input selection still uses the normal `SelectCoins` flow, but MWEB adds type-aware selection paths and constraints.

#### Transaction Type Order

- If any recipient is MWEB:
  1. Try `MWEB_TO_MWEB`.
  2. If that fails, try `PEGIN`.
- If all recipients are LTC:
  1. Try `LTC_TO_LTC`.
  2. If that fails, try `PEGOUT`.
  3. If that fails, try `PEGIN_PEGOUT`.

The first successful type is used.

#### Spendable Pool

- `AvailableCoins` collects both LTC UTXOs and MWEB coins.
- MWEB coins are included only if the wallet can load the coin and derive its stealth address.
- `coin_control.fPegIn` excludes MWEB candidates.
- `coin_control.fPegOut` excludes LTC candidates.

#### Type Compatibility Rules

Before running the standard selection algorithms, output groups are filtered by `TxType`:

- `LTC_TO_LTC`: MWEB inputs are rejected.
- `MWEB_TO_MWEB` and `PEGOUT`: LTC inputs are rejected.
- `PEGIN` and `PEGIN_PEGOUT`: LTC and MWEB inputs are both allowed.

With `-avoidpartialspends`, LTC outputs can be grouped by destination, but MWEB outputs are always kept ungrouped (one output per group).

#### Manual Input Constraints

When inputs are preselected via coin control:

- A selected MWEB input is invalid for `LTC_TO_LTC`.
- A selected LTC input is invalid for `MWEB_TO_MWEB` and `PEGOUT`.
- If `m_allow_other_inputs=false`, only preselected inputs are used and they must already meet the target.

#### MWEB-Specific Targeting

Selection target is `sum(recipients)` plus the non-input fee estimate for the candidate type (unless fee is being subtracted from outputs):

- `MWEB_TO_MWEB`: kernel + recipient MWEB output weight.
- `PEGIN`: pegin LTC output + HogEx pegin input + MWEB kernel/output weight.
- `PEGOUT`: pegout kernel weight + HogEx pegout output bytes.
- `PEGIN_PEGOUT`: both pegin-side LTC bytes and pegout kernel/HogEx costs.

Waste scoring also adds `MWEB_INPUT_WASTE` per selected MWEB input, biasing toward fewer MWEB inputs when candidate sets are otherwise similar.

## Output Creation

#### Requirements

 - `sender_sk`: SecretKey (ephemeral)
 - `receiver_addr`: StealthAddress
 - `amount`: u64

#### Generated

- `output`: struct
  - `output_commit`: Commitment
  - `output_pk`: PublicKey (sender)
  - `spend_pk`: PublicKey (receiver)
  - `message`: struct
    - `features`: u8
    - `key_exchange_pk`: PublicKey
    - `view_tag`: u8
    - `masked_value`: u64
    - `masked_nonce`: u8[16]
  - `proof`: RangeProof
  - `output_sig`: Signature
- `raw_blind`: BlindingFactor

#### Signing

1. `output_message`: Hash = BLAKE3(features || key_exchange_pk || view_tag || masked_value || masked_nonce)
2. `sig_message`: Hash = BLAKE3(output_commit || output_pk || spend_pk || output_message || rangeproof_hash)
3. `output_sig`: Signature = SCHNORR(sender_sk, sig_message)


## Input Creation

#### Requirements

 - `output_id`: Hash
 - `output_commit`: Commitment
 - `input_sk`: SecretKey (ephemeral)
 - `spend_sk`: SecretKey - Can be calculated from the shared_secret using the Keychain

#### Generated

- `input`: struct
  - `features`: u8
  - `output_id`: Hash
  - `output_commit`: Commitment 
  - `input_pk`: PublicKey
  - `output_pk`: PublicKey
  - `extra_data`: opt<u8[]>
  - `input_sig`: Signature

#### Signing

 1. `key_hash`: SecretKey = BLAKE3(input_pk || output_pk)
 2. `sig_sk`: SecretKey = (spend_sk * key_hash) + input_sk
 3. `msg_hash`: Hash = BLAKE3(features || output_id || extra_data_if_present)
 4. `input_sig`: Signature = SCHNORR(sig_sk, msg_hash)


## Kernel Creation

#### Requirements

- `output_blinds`: BlindingFactor[]
- `input_blinds`: BlindingFactor[]
- `kernel_offset`: BlindingFactor
- `sender_sks`: SecretKey[]
- `input_sks`: SecretKey[]
- `spend_sks`: SecretKey[]
- `stealth_offset`: BlindingFactor
- `fee`: opt<i64>
- `pegin_amount`: opt<i64>
- `pegouts`: opt<array>
  - `amount`: CAmount
  - `scriptPubKey`: CScript
- `lock_height`: opt<i32>

#### Generated

- `kernel`: struct
  - `features`: u8
  - `fee`: opt<i64>
  - `pegin_amount`: opt<i64>
  - `pegouts`: opt<array>
    - `amount`: CAmount
    - `scriptPubKey`: CScript
  - `lock_height`: opt<i32>
  - `excess_commit`: Commitment
  - `stealth_excess_pk`: opt<PublicKey>
  - `kernel_sig`: Signature

#### Signing

1. `excess_blind`: BlindingFactor = sum(output_blinds) - sum(input_blinds) - kernel_offset
2. If `stealth_excess_pk` is present:
   - `stealth_excess_sk`: SecretKey = sum(sender_sks) + sum(input_sks) - sum(spend_sks) - stealth_offset
   - `key_hash`: Hash = BLAKE3(excess_commit || stealth_excess_pk)
   - `sig_sk`: SecretKey = (excess_blind * key_hash) + stealth_excess_sk
3. If `stealth_excess_pk` is absent:
   - `sig_sk`: SecretKey = excess_blind
4. `msg_hash`: Hash = BLAKE3(features || excess_commit || fee || pegin_amount || pegouts || lock_height || stealth_excess_pk)
5. `kernel_sig`: Signature = SCHNORR(sig_sk, msg_hash)

See [kernels.md](./kernels.md) for more details.
