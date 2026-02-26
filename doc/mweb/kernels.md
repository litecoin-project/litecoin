# Kernels

## Current Features

All kernels begin with a single byte which acts as a bitvector to specify the "features" of the kernel.
The following feature bits are currently supported, though more could be added in the future:

* `FEE_FEATURE_BIT` = `0x01`
* `PEGIN_FEATURE_BIT` = `0x02`
* `PEGOUT_FEATURE_BIT` = `0x04`
* `HEIGHT_LOCK_FEATURE_BIT` = `0x08`
* `STEALTH_EXCESS_FEATURE_BIT` = `0x10`
* `EXTRA_DATA_FEATURE_BIT` = `0x20`

For each feature bit that's set, the corresponding feature rules apply to that kernel.

***NOTE**: Only `FEE_FEATURE_BIT`, `PEGIN_FEATURE_BIT`, `PEGOUT_FEATURE_BIT`, `HEIGHT_LOCK_FEATURE_BIT`, and `STEALTH_EXCESS_FEATURE_BIT` are considered "standard" features.
Transactions specifying the `EXTRA_DATA_FEATURE_BIT` or any higher feature bits are unlikely to be forwarded along the p2p network, nor are they likely to be included by most miners.
This may change in future releases.*

#### Fee

Kernels specifying the `FEE_FEATURE_BIT` shall contain a (non-negative `var_int`) fee field.
The fee value shall be deducted from the total MWEB supply, and may be collected by the miner of the containing block as part of its coinbase reward.

#### Peg-In

Kernels specifying the `PEGIN_FEATURE_BIT` shall contain a (non-negative `var_int`) peg-in amount field.
The peg-in amount shall be added to the total MWEB supply, and must have a corresponding pegin output on the canonical LTC side.

#### Peg-Out

Kernels specifying the `PEGOUT_FEATURE_BIT` shall contain a vector of pegouts, each consisting of a (non-negative `var_int`) peg-out amount field and a valid 4-42 byte LTC script.
The peg-out amount shall be deducted from the total MWEB supply by the miner.
The miner shall add an output to the integrating transaction (`HogEx`) for each pegout specified. The output's `amount` and `scriptPubKey` shall match the one specified in the kernel.

#### Height Lock

Kernels specifying the `HEIGHT_LOCK_FEATURE_BIT` shall contain a (non-negative `var_int`) lock height field.
The kernel shall not be included in any block earlier than the lock height specified.

#### Stealth Excess

Kernels specifying the `STEALTH_EXCESS_FEATURE_BIT` shall contain a (compressed public key) stealth excess (`E'`) field.
The stealth excess will also be used when signing the kernel.

#### Extra Data

Kernels specifying the `EXTRA_DATA_FEATURE_BIT` shall contain a (u8) size field between 0 and 100, followed by the number of bytes specified.
There are currently no consensus rules enforced on the contents of the data, though future soft-forks are likely to take advantage of this field.

## Signature

The kernel shall contain a valid signature for the kernel commitment (`E`). The signed message shall be for the feature byte followed by the excess, and then followed by all included feature fields.

*Example: If the kernel's feature byte is 0x03 (`FEE_FEATURE_BIT` | `PEGIN_FEATURE_BIT`), the message signed shall be: `(0x03 | excess | VARINT(fee) | VARINT(pegin_amount))`*

If the `STEALTH_EXCESS_FEATURE_BIT` is set, instead of signing the kernel with just the kernel excess (`E`), it shall be signed with `BLAKE3(E||E')*E + E'`.

## Soft Forks

New features may be defined in the future via softfork. Consensus rules may be agreed upon for the currently undefined feature bits.
Though new data sections cannot be added without hardforking, future feature bits may be used in conjunction with the `EXTRA_DATA_FEATURE_BIT` to include additional kernel data.
