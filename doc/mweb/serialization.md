# MWEB Serialization

## MWEB Object Formats

#### mweb_tx_body

| Field Size | Name | Type | Description |
|---|---|---|---|
| 1+ | mweb_input_count | compact_size | Number of MWEB inputs |
| 0+ | mweb_inputs | mweb_input[] | A list of zero or more MWEB inputs |
| 1+ | mweb_output_count | compact_size | Number of MWEB outputs |
| 0+ | mweb_outputs | mweb_output[] | A list of zero or more MWEB outputs |
| 1+ | mweb_kernel_count | compact_size | Number of MWEB kernels |
| 0+ | mweb_kernels | mweb_kernel[] | A list of zero or more MWEB kernels |

#### mweb_input

| Field Size | Name | Type | Description |
|---|---|---|---|
| 1 | features | uint8_t | An input "feature" bitmask. Bit values: 0x01 = STEALTH_KEY_FEATURE_BIT, 0x02 = EXTRA_DATA_FEATURE_BIT |
| 32 | output_id | uint256 | The hash/ID of the output being spent |
| 33 | output_commit | Commitment | The commitment of the output being spent |
| 33 | output_pk | PublicKey | The public key of the output being spent |
| 33 if (features & 0x01) | input_pk | PublicKey | The input public key |
| 1+ if (features & 0x02) | extra_data_len | compact_size | The size of the extra data (in bytes) |
| 0+ | extra_data | uint8_t[] | Optional raw byte array to be used for future soft forks |
| 64 | sig | Signature | The input signature |

#### mweb_output

| Field Size | Name | Type | Description |
|---|---|---|---|
| 33 | output_commit | Commitment | The output commitment |
| 33 | sender_pk | PublicKey | Ephemeral public key (K_s) chosen by sender |
| 33 | receiver_pk | PublicKey | The output public key (K_o) whose private key is known only by the receiver |
| 1 | features | uint8_t | An output "feature" bitmask. 0x01 = STANDARD_FIELDS_FEATURE_BIT, 0x02 = EXTRA_DATA_FEATURE_BIT |
| 33 if (features & 0x01) | key_exchange_pk | PublicKey | The key exchange public key (K_e) |
| 1 if (features & 0x01) | view_tag | uint8_t | A view tag for speeding up identification of a wallet's outputs |
| 8 if (features & 0x01) | masked_value | uint64_t | The encrypted output value |
| 16 if (features & 0x01) | masked_nonce | uint8_t[16] | The encrypted nonce used when calculating the send key |
| 1+ if (features & 0x02) | extra_data_len | compact_size | The size of the extra data (in bytes) |
| 0+ | extra_data | uint8_t[] | Optional raw byte array to be used for future soft forks |
| 675 | rangeproof | RangeProof | The rangeproof for the output_commit |
| 64 | sig | Signature | The output signature |

#### mweb_kernel

| Field Size | Name | Type | Description |
|---|---|---|---|
| 1 | features | uint8_t | A kernel "feature" bitmask. Bit values: 0x01 = FEE_FEATURE_BIT, 0x02 = PEGIN_FEATURE_BIT, 0x04 = PEGOUT_FEATURE_BIT, 0x08 = HEIGHT_LOCK_FEATURE_BIT, 0x10 = STEALTH_EXCESS_FEATURE_BIT, 0x20 = EXTRA_DATA_FEATURE_BIT |
| 1+ if (features & 0x01) | fee | var_int | The kernel fee |
| 1+ if (features & 0x02) | pegin_amount | var_int | The amount being pegged in |
| 1+ if (features & 0x04) | pegout_count | compact_size | The number of pegouts |
| 2+ if (features & 0x04) | pegouts | tuple<var_int, CScript>[] | The amount and scriptPubKey of each pegout |
| 1+ if (features & 0x08) | lock_height | var_int | The kernel's lock height |
| 33 if (features & 0x10) | stealth_excess | PublicKey | The kernel's stealth excess |
| 1+ if (features & 0x20) | extra_data_len | compact_size | The size of the extra data (in bytes) |
| 0+ | extra_data | uint8_t[] | Optional raw byte array to be used for future soft forks |
| 33 | kernel_excess | Commitment | The kernel excess |
| 64 | sig | Signature | The kernel signature |

## Transaction Format Changes

A new transaction "flag" value of `0x08` was added to indicate that a transaction has MWEB data attached to it. The MWEB data is serialized after any script witnesses and before `lock_time`. The new 'extended' transaction format is as follows:

| Field Size | Name | Type | Description |
|---|---|---|---|
| 4 | version | int32_t | Transaction data format version |
| 1 | marker | char | Must be zero |
| 1 | flag | char | Bitmask with bit 1 indicating the existence of script witnesses, and bit 8 indicating the existence of MWEB data |
| 1+ | txin_count | compact_size | Number of transaction inputs |
| 0+ | txins | txin[] | A list of zero or more transaction inputs |
| 1+ | txout_count | compact_size | Number of transaction outputs |
| 0+ | txouts | txouts[] | A list of zero or more transaction outputs |
| 1+ if (flag & 0x01) | script_witnesses | script_witnesses[] | The witness structure as a serialized byte array |
| 1 if (flag & 0x08) | mweb_tx_present | uint8_t | Presence marker for MWEB transaction info. `0x00` = no attached mweb_tx (HogEx encoding), `0x01` = mweb_tx serialized next |
| 1+ if (mweb_tx_present == 0x01) | mweb_tx | mweb_tx | The serialized MWEB transaction data. Exists for mempool txs only. Txs in a block already have MWEB data stripped. |
| 4 | lock_time | uint32_t | The block number or timestamp until which the transaction is locked |

Notes:
* `mweb_tx_present` is serialized using an optional-pointer marker and should be encoded as either `0x00` or `0x01`.
* Current parser behavior is permissive: only `0x01` is treated as "present"; any other value is treated as "absent".
* Unknown optional transaction flag bits are rejected.
* If witness data is encoded (`flag & 0x01`), at least one input witness stack must be non-empty.
* If MWEB flag is set with `mweb_tx_present == 0x00` (HogEx encoding), `txouts` must be non-empty.

#### mweb_tx

| Field Size | Name | Type | Description |
|---|---|---|---|
| 32 | kernel_offset | BlindingFactor | A 32-byte secret scalar |
| 32 | stealth_offset | BlindingFactor | A 32-byte secret scalar |
| 101+ | body | mweb_tx_body | The MWEB inputs, outputs, and kernels. Must contain at least 1 kernel. |

## Block Format Changes

If the last transaction in a block is marked as the HogEx transaction, then immediately following the last transaction in the block will be a single-byte marker indicating whether an `mweb_block` is included. If that marker is `0x01`, an `mweb_block` follows.

| Field Size | Name | Type | Description |
|---|---|---|---|
| 80 | header | CBlockHeader | The block header |
| 1+ | vtx | CTransaction[] | The block's transactions |
| 1 if last transaction is HogEx | has_mweb | uint8_t | Presence marker. `0x00` = no extension block serialized, `0x01` = extension block serialized next |
| 166+ if has_mweb == 1 | mweb_block | mweb_block | The MWEB block data |

Note:
* `has_mweb` is serialized using an optional-pointer marker and should be encoded as either `0x00` or `0x01`.
* Current parser behavior is permissive: only `0x01` is treated as "present"; any other value is treated as "absent".

#### mweb_block

| Field Size | Name | Type | Description |
|---|---|---|---|
| 163+ | header | mweb_header | The MWEB block header |
| 3+ | body | mweb_tx_body | The MWEB inputs, outputs, and kernels. |


#### mweb_header

| Field Size | Name | Type | Description |
|---|---|---|---|
| 1+ | height | var_int | The block height |
| 32 | output_root | uint256 | The output MMR root |
| 32 | kernel_root | uint256 | The kernel MMR root |
| 32 | leafset_root | uint256 | The leafset MMR root |
| 32 | kernel_offset | BlindingFactor | The kernel offset blinding factor |
| 32 | stealth_offset | BlindingFactor | The stealth offset blinding factor |
| 1+ | output_mmr_size | var_int | The number of outputs in the output MMR |
| 1+ | kernel_mmr_size | var_int | The number of kernels in the kernel MMR |
