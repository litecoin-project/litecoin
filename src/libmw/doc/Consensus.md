# Consensus

## Data Formats


## Rules

#### Output Uniqueness

* Output commitments in the UTXO set shall be unique at all times.
* A block shall not be included when it contains an output commitment which already exists in the UTXO set.
  * Block is still invalid even if it also contains an input with said commitment.
* A block shall not contain 2 outputs with the same commitment.
  * Block is still invalid even if it also contains an input with said commitment.
* A block *could* contain an input which spends an output created in the same block, provided the commitment was not already in the UTXO set.
  * To better support payment proofs, the outputs shall still be added to the TXO MMR, but shall be marked as spent.
---

#### Kernel Uniqueness

* A block shall not contain 2 kernels with the same commitment.
---

#### Ordering

* Inputs in a block shall be in ascending order by their raw commitment value.
* Outputs in a block shall be in ascending order by their raw commitment value.
* Kernels in a block shall list pegins first, and then be ordered in ascending order by their raw hashed value.
* Signed owner messages shall be in ascending order by their raw hashed value.
---

#### PMMRs

* After adding all kernels from a block to the end of the kernel MMR, the root shall match the header's kernel root.
* After adding all kernels from a block to the end of the kernel MMR, the size shall match the header's kernel size.
* After adding all outputs from a block to the end of the output MMR, the root shall match the header's output root.
* After adding all outputs from a block to the end of the output MMR, the size shall match the header's output size.
---

#### UTXO LeafSet

* TODO
---

#### Signatures

* Each kernel shall have a valid signature of the `signature_message` for the kernel's `commitment`.
  * TODO: Define`signature_message` serialization for each kernel type
* Each input shall have a valid signature of the message "MWEB" for the input's `commitment`.
* Each output shall have a valid signature of the `signature_message` for the output's `sender_pubkey`.
  * `signature_message` is serialized as `[features, receiver_pubkey, pub_nonce, encrypted_data]`
* Each signed owner message shall be a valid signature of the hash of a kernel in the block.
---

#### Bulletproofs

* Each output shall be coupled with a bulletproof that proves the commitment is to a value in the range `[0, 2^64)`.
* Each bulletproof shall commit to the `owner_data` using its `extra_commit` functionality.
  * TODO: Define `owner_data` serialization
---

#### Kernel Sums

* The sum of all output commitments in the UTXO set at a given block height shall equal the sum of all kernel commitments plus the `total_kernel_offset*G` and the `expected_supply*H` of the block.
  * `sum(utxo.commitments) = sum(kernel.commitments) + (block.total_kernel_offset*G) + (expected_supply*H)`
---

#### Owner Sums

* The sum of all receiver pubkeys for the inputs in a block, plus the sum of all owner pubkeys in the block, plus the `total_owner_offset*G` of the block shall equal the sum of all output sender pubkeys in the block.
  * `sum(input.receiver_pubkey) + sum(owner_pubkey) + (block.total_owner_offset*G) = sum(output.sender_pubkey)`
---

#### Peg-In/Peg-Out Maturity

TBD

---

#### Block Weight

* Outputs shall be counted as having a weight of 18.
* Kernels shall be counted as having a weight of 2.
* Signed owner messages shall be counted as having a weight of 1.
* Extension blocks shall be capped at a maximum total weight of 21,000.
* Inputs shall not contribute toward the block weight.
* Kernel `extra_data` shall not exceed 33 bytes.
  * TODO: Should adding `extra_data` just increase the weight instead?

#### Horizon