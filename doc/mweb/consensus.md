# MWEB Consensus

## Prerequisites

### Notation

* Let `G` and `H` be independent generators of the elliptic curve group
* `H(α||β||γ)` represents BLAKE3 hash of concatenated serializations
* Scalar multiplication denoted as `a⋅G` where `a` is scalar
* Point addition/subtraction uses standard `+`/`-` operators

### Cryptographic Assumptions

* All elliptic curve operations use secp256k1
* BLAKE3 outputs are interpreted as scalars modulo the curve order when used in arithmetic

### Glossary
* **PMMR**: Pruned Merkle Mountain Range (data structure for storing UTXOs)
* **TXO**: Transaction Output
* **UTXO**: Unspent Transaction Output
* **HogEx**: MWEB integration transaction

### Transaction Structure

##### Transaction

* <code>x</code> = kernel offset (scalar)
* <code>x'</code> = stealth offset (scalar)

##### Inputs

* <code>F<sub>i</sub></code> = Input features (bitmask)
    * <code>0x01</code> = Additional input key
    * <code>0x02</code> = Extra Data (Indicating additional byte vector to be included in the signature message)
* <code>O<sub>ID</sub></code> = ID of the output being spent
* <code>C<sub>i</sub></code> = Input commitment (<code>C<sub>o</sub></code> of the output being spent)
* <code>K<sub>i</sub></code> = Input stealth public key (if <code>0x01</code> is set in <code>F<sub>i</sub></code>)
* <code>M<sub>i</sub></code> = Additional input message data (if <code>0x02</code> is set in <code>F<sub>i</sub></code>)
* <code>&sigma;</code> = Input signature

##### Kernels

* <code>M</code> = Type, fee, etc.
* <code>E</code> = Kernel excess
* <code>E'</code> = (Optional) Stealth excess
* <code>&psi;</code> = Kernel signature

##### Outputs

* <code>C<sub>o</sub></code> = Output commitment
* <code>K<sub>s</sub></code> = Sender public key 
* <code>K<sub>o</sub></code> = Output public key
* <code>K<sub>e</sub></code> = Key exchange public key
* <code>t[0]</code> = View tag
* <code>v'</code> = Encrypted value
* <code>n'</code> = Encrypted nonce
* <code>&rho;</code> = Output signature



## Rules

For kernel-specific rules (feature bits, feature-gated fields, and kernel signature message layout), see [kernels.md](./kernels.md).

#### Identifiers

* The kernel ID (<code>K<sub>ID</sub></code>) is the BLAKE3 hash of the serialized kernel.
  * See [kernels.md](./kernels.md) for the kernel serialization format.
* The output ID (<code>O<sub>ID</sub></code>) is the BLAKE3 hash of the serialized output.
  * <code>O<sub>ID</sub> = H(C<sub>o</sub>||H(O<sub>M</sub>)||H(&pi;)||&rho;)</code>
---

#### Transaction Uniqueness

* Output hashes (<code>O<sub>ID</sub></code>) in the UTXO set shall be unique at all times.
* A block shall not contain 2 inputs that spend the same output ID (<code>O<sub>ID</sub></code>).
* A block shall not be included when it contains an output ID (<code>O<sub>ID</sub></code>) which already exists in the UTXO set.
  * Block is still invalid even if it also contains an input with said output ID (<code>O<sub>ID</sub></code>).
* A block shall not contain 2 outputs with the same ID (<code>O<sub>ID</sub></code>).
  * Block is still invalid even if it also contains an input with said output ID (<code>O<sub>ID</sub></code>).
* A block *could* contain an input which spends an output created in the same block, provided the output ID (<code>O<sub>ID</sub></code>) was not already in the UTXO set.
  * To better support payment proofs, the outputs shall still be added to the TXO MMR, but shall be marked as spent.
* A block shall not contain 2 kernels with the same ID (<code>K<sub>ID</sub></code>).
---

#### Ordering

* Inputs in a block shall be in ascending order by output ID (<code>O<sub>ID</sub></code>).
* Outputs in a block shall be in ascending order by output ID (<code>O<sub>ID</sub></code>).
* Kernels in a block shall be ordered by descending supply change (<code>v<sub>pegin</sub> - (v<sub>pegout</sub> + f)</code>), with ties broken by ascending kernel ID (<code>K<sub>ID</sub></code>).
---

#### PMMRs

* After building an MMR with all of the kernels from a block, the root shall match the header's kernel root.
* The number of kernels in a block shall match the header's kernel size.
* After adding all outputs from a block to the end of the output PMMR, the root shall match the header's output root.
* After adding all outputs from a block to the end of the output PMMR, the size shall match the header's output size.
---

#### UTXO LeafSet

* A simple bitset shall be created and maintained to keep track of which TXOs in the output PMMR remain unspent.
* The bit positions shall map 1-to-1 to to PMMR leaf indices. A `0` at that bit position means spent, whereas a `1` means unspent. 
  * Ex: If byte 0 bit 2 is a `1`, that means TXO at leaf index `2` is unspent. If byte 2 bit 1 is a `0`, the TXO at leaf index `17` has been spent. etc.
* The hash of the serialized UTXO set after applying the transactions in a block shall match the header's UTXO leafset hash.
* Each input spent by a block must reference an existing unspent UTXO entry.
* For each spent input, the input's commitment and output pubkey must exactly match the referenced UTXO.
---

#### Signatures

* Each kernel without a stealth excess (`E'`) shall have a valid signature (&psi;) of <code>H(K<sub>M</sub>)</code> that verifies for the kernel's excess(`E`).
  * See [kernels.md](./kernels.md) for the signature message (<code>K<sub>M</sub></code>) serialization format
* Each kernel with a stealth excess (`E'`) shall have a valid signature (&psi;) of <code>H(K<sub>M</sub>)</code> for key <code>E<sub>agg</sub> = H(E||E')⋅E + E'</code>.
* Each input shall have a valid signature (<code>&sigma;</code>) of <code>I<sub>M</sub></code> for key <code>K<sub>sig</sub></code>
    * If an input stealth pubkey <code>K<sub>i</sub></code> is included (<code>0x01</code> set in <code>F<sub>i</sub></code>), <code>K<sub>sig</sub> = K<sub>i</sub> + H(K<sub>i</sub>||K<sub>o</sub>)⋅K<sub>o</sub></code>. Otherwise, <code>K<sub>sig</sub> = K<sub>o</sub></code>.
    * If extra data <code>M<sub>i</sub></code> is included (<code>0x02</code> set in <code>F<sub>i</sub></code>), <code>I<sub>M</sub> = H(F<sub>i</sub>||O<sub>ID</sub>||M<sub>i</sub>)</code>. Otherwise, <code>I<sub>M</sub> = H(F<sub>i</sub>||O<sub>ID</sub>)</code>.
* Each output shall have a valid signature (<code>&rho;</code>) of <code>(C<sub>o</sub>||O<sub>M</sub>||H(&pi;))</code> for the output's sender pubkey (<code>K<sub>s</sub></code>).
  * `output_message` (<code>O<sub>M</sub></code>) is serialized as <code>O<sub>M</sub> = (K<sub>o</sub>||K<sub>e</sub>||t[0]||v'||n'||K<sub>s</sub>)</code>
---

#### Bulletproofs

* Each output shall be coupled with a bulletproof that proves the commitment is to a value in the range `[0, 2^64)`.
* Each bulletproof (<code>&pi;</code>) shall commit to the `output_message` using its `extra_commit` functionality.
---

#### Kernel Sums

* The sum of all output commitments (<code>C<sub>o</sub></code>) in the UTXO set at a given block height shall equal the sum of all kernel commitments (`E`) plus the `total_kernel_offset*G` (`x*G`) and the `expected_supply*H` (<code>v_total</code>) of the block.
  * <code>&Sigma;C<sub>o</sub> = &Sigma;E + (x⋅G) + (v_total⋅H)</code> where <code>v_total</code> is the total MWEB supply at the block height.
---

#### Stealth Sums

* The sum of all sender pubkeys (<code>K<sub>s</sub></code>) in a block and all input pubkeys (<code>K<sub>i</sub></code>) in the block must equal the sum of all stealth excesses (`E'`) plus `total_stealth_offset*G` (`x'*G`) plus the sum of all output pubkeys (<code>K<sub>o</sub></code>) being spent in the block.
  * <code>&Sigma;K<sub>s</sub> + &Sigma;K<sub>i</sub> = &Sigma;E' + x'⋅G + &Sigma;K<sub>o</sub></code>
---

#### Pegging-In && Pegging-Out

* Kernels may include an optional pegout, containing the `amount` & a `scriptPubKey` (serialized `CScript`)
  * The `scriptPubKey` for a pegout shall be non-empty.
  * Miners shall include a matching output in a block's `HogEx` transaction with the exact `amount` and `scriptPubKey` for each pegout in the block.
* Kernels may include an optional pegin `amount`
  * Each pegin kernel must have a corresponding pegin output on the canonical LTC side where the value is <code>v<sub>pegin</sub></code>, witness version is 9, and witness program is the kernel ID (<code>K<sub>ID</sub></code>).
  * The extension block peg-in set must exactly match canonical pegins by `(kernel ID, amount)`.
  * Kernel IDs in the canonical block pegin set must be unique.
* The total MWEB supply (<code>v_total</code>) shall increase by the sum of the block's pegins (<code>v<sub>pegin</sub></code>), and decrease by the sum of the block's pegouts (<code>v<sub>pegout</sub></code>) and the sum of all fees (`f`).
  * <code>v_total<sub>new</sub> = v_total<sub>prev</sub> + &Sigma;v<sub>pegin</sub> - (&Sigma;v<sub>pegout</sub> + &Sigma;f)</code>
* Pegged-out coins require 6 blocks to mature before they can be spent.
---

#### Block Weight

* Outputs shall be counted as having a weight of 17 + 1 (if "standard fields" are included).
  * An additional 1 weight shall be added for every 42 bytes included in the `extra_data` field.
* Kernels shall be counted as having a weight of either 2 (without stealth excess) or 3 (with stealth excess).
  * For each pegout script included, 1 weight shall be added per every 42 bytes of its `scriptPubKey`.
  * An additional 1 weight shall be added for every 42 bytes included in the `extra_data` field.
* Extension blocks shall be capped at a maximum total weight of 200,000.
* Extension blocks shall contain at most 50,000 inputs.
* Inputs shall not contribute toward the block weight unless they contain `extra_data`, which will cost 1 weight per 42 bytes.

#### HogEx

* `HogEx` is a canonical transaction marked with the MWEB serialization flag and an empty MWEB transaction payload.
* `HogEx` is only valid in blocks (never as a loose mempool transaction).
* When MWEB is active:
  * A non-null extension block must be present.
  * The final transaction in the block must be marked as `HogEx`.
  * No earlier transaction in the block may be marked as `HogEx`.
* When MWEB is not active, extension block data must be absent.
* Transactions inside a block must not carry embedded MWEB transaction payloads (`HasMWEBTx() == false`), including `HogEx`.
* `HogEx` must contain at least one output.
* The first `HogEx` output (`vout[0]`) must be a HogAddr witness program: version `8`, 32-byte program.
  * That 32-byte program must equal the MWEB block hash committed by the extension block.
* The extension block height must match the canonical block height.
* Peg-in scripts (witness version `9`, 32-byte program) are not allowed in coinbase or `HogEx` outputs.
* HogEx inputs must match block peg-ins exactly, in block/txout scan order:
  * For the first `HogEx` after activation, every `HogEx` input is a pegin input.
  * For later blocks, `HogEx.vin[0]` must spend the previous block's `HogEx` output `0`, and remaining `HogEx` inputs must be pegin inputs.
  * Missing or extra `HogEx` inputs are invalid.
* `HogEx` outputs after the first (`vout[1..]`) are pegout outputs.
  * They must match the extension block pegouts by (`amount`, `scriptPubKey`) multiset equality.
* Let <code>H<sub>prev</sub></code> be the previous `HogEx.vout[0]` amount (or `0` for first `HogEx`), and let <code>P</code> be this block's total pegins.
  * The `HogEx` fee must be <code>(H<sub>prev</sub> + P) - vout_total</code>, and this must equal the extension block total fee.
  * The new `HogEx.vout[0]` amount must equal <code>H<sub>prev</sub> + supply_change</code>, where <code>supply_change = P - (pegouts + fees)</code>.
* Pegout maturity handling:
  * `HogEx.vout[0]` is not a pegout and is exempt from pegout maturity.
  * `HogEx.vout[1..]` are pegouts and require 6 confirmations before spending.
* Current consensus does **not** globally forbid HogAddr-looking scripts outside `HogEx.vout[0]`; only the first output of `HogEx` is interpreted as the mandatory HogAddr commitment.
