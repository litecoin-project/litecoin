# Data Storage

In addition to extending the existing `CBlock` and `CBlockUndo` objects already used in Litecoin, the following data stores are created and used by the MWEB.

### UTXOs

##### CoinDB (leveldb)

Litecoin's leveldb instance is used to maintain a UTXO table (prefix: 'U') with `UTXO` objects, consisting of the following data fields:

* commitment (key) - The output commitment.
* block_height - The block height the UTXO was included.
* leaf_index - The index of the leaf in the output PMMR.
* output - The full `Output` object, including the rangeproof and owner data.

### PMMRs

##### MMR Info (leveldb)
Litecoin's leveldb instance is used to maintain an MMR Info table (prefix: "M") with `MMRInfo` objects consisting of the following data fields:

* index (key) - File number of the PMMR files.
* pruned_hash - Hash of latest header this PMMR represents.
* compact_index - File number of the PruneList bitset.
* compacted_hash - Hash of the header this MMR was compacted for. You cannot rewind beyond this point.

Each time the PMMRs are flushed to disk, a new MMRInfo object is written to the DB and marked as the latest.

##### Leaves (leveldb)
Litecoin's leveldb instance is used to maintain MMR leaf tables (prefix: 'K' for kernels, 'O' for outputs) to store uncompacted PMMR leaves consisting of the following data fields:

* leaf_index (key) - The zero-based leaf position.
* leaf - The raw leaf data committed to by the PMMR.

Leaves spent before the horizon will be removed during compaction.

##### MMR Hashes (file)

Stored in file `<prefix><index>.dat` where `<prefix>` refers to 'K' for the kernel MMR and 'O' for the output PMMR, and `<index>` is a 6-digit number that matches the `index` value of the latest `MMRInfo` object.
Example: If the latest `MMRInfo` object has an `index` of 123, the matching kernel MMR hash file will be named `K000123.dat`.

The hash file consists of un-compacted leaf hashes and their parent hashes.

// TODO: Describe the process for determining which hashes are stored.

##### Leafset (file)

Stored in file `leaf<index>.dat`.

The leafset file consists of a bitset indicating which leaf indices of the UTXO PMMR are unspent.
Example: If the PMMR contains 5 leaves where leaf indices 0, 1, and 2 are spent, but 3 and 4 are unspent, the file will contain a single byte of 00011000 = 0x18.

##### PruneList (file)

Stored in file `prun<index>.dat`.

The prunelist file consists of a bitset indicating which nodes of the UTXO PMMR are not included in the UTXO PMMR hash file.
Example: If nodes 0, 1, 3, and 4 are compacted (not included in PMMR), then the first byte of the prune list bitset will be 11011000 = 0xD8.