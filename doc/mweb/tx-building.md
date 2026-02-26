# Transaction Building

## Input Selection

TODO

## Output Creation

#### Requirements

 - `output_sk`: SecretKey (ephemeral)
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
3. `output_sig`: Signature = SCHNORR(output_sk, sig_message)


## Input Creation

#### Requirements

 - `output_id`: Hash
 - `output_commit`: Commitment
 - `input_sk`: SecretKey (ephemeral)
 - `output_sk`: SecretKey - Can be calculated from the shared_secret using the Keychain

#### Generated

- `input`: struct
  - `output_id`: Hash
  - `output_commit`: Commitment 
  - `input_pk`: PublicKey
  - `output_pk`: PublicKey
  - `input_sig`: Signature

#### Signing

 1. `key_hash`: SecretKey = BLAKE3(input_pk || output_pk)
 2. `sig_sk`: SecretKey = (output_sk * key_hash) + input_sk
 3. `msg_hash`: Hash = BLAKE3(features || output_id)
 4. `input_sig`: Signature = SCHNORR(sig_sk, msg_hash)


## Kernel Creation

#### Requirements

- `output_blinds`: BlindingFactor[]
- `input_blinds`: BlindingFactor[]
- `kernel_offset`: BlindingFactor
- `output_sks`: SecretKey[]
- `input_sks`: SecretKey[]
- `stealth_offset`: SecretKey
- `fee`: opt<i64>
- `pegin_amount`: opt<i64>
- `pegouts`: opt<array>
  - `amount`: CAmount
  - `scriptPubKey`: CScript
- `lock_height`: opt<u64>

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
2. `stealth_excess_sk`: SecretKey = sum(output_sks) + sum(input_sks) - stealth_offset
3. `key_hash`: Hash = BLAKE3(excess_commit || stealth_excess_pk)
4. `sig_sk`: SecretKey = (excess_blind * key_hash) + stealth_excess_sk
5. `msg_hash`: Hash = BLAKE3(features || excess_commit || fee || pegin_amount || pegouts || lock_height || stealth_excess_pk)
6. `kernel_sig`: Signature = SCHNORR(sig_sk, msg_hash)

See [kernels.md](./kernels.md) for more details.
