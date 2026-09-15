# Data Storage

In addition to extending the existing `CBlock` and `CTransaction` objects already used in Litecoin, the following data stores are created or modified for MWEB.

### CBlockUndo

After a new block is connected, a `rev<index>.dat` file is created that describes how to remove or "undo" the block from the chain state.
When performing a reorg, the undo file can be processed, which will revert the UTXO set back to the way it was just before the block.

To support undo-ing MWEB blocks, we''ve added a new `mw::BlockUndo` object to `CBlockUndo`, which gets serialized at the end.
This contains the following fields:

* `prev_header` - the MWEB header in the previous block
* `utxos_spent` - vector of `UTXO`s that were spent in the block
* `utxos_added` - vector of coin IDs (hashes) that were added in the block

To revert the block from the chain state, the node adds back the `UTXO`s in `utxos_spent`, removes the matching `UTXO`s in `utxos_added`, and sets `prev_header` as the MWEB chain tip.

NOTE: For backward compatibility, when deserializing a `CBlockUndo`, we first must look up the size of the `CBlockUndo` object.
After deserializing vtxundo (the vector of `CTxUndo`s), if more data remains, assume it\'s the `mw::BlockUndo` object.
If no more data remains, assume the `CBlockUndo` does not have MWEB data.
An `UnserializeBlockUndo` function was added to handle this.

### UTXOs
##### CoinDB (leveldb)

Litecoin's leveldb instance is used to maintain a UTXO table (prefix: 'U') with `UTXO` objects, consisting of the following data fields:

* output_hash (key) - The hash of the output.
* block_height - The block height the UTXO was included.
* leaf_index - The index of the leaf in the output PMMR.
* output - The full `Output` object, including the rangeproof and owner data.

### PMMRs
##### MMR Info (leveldb)
Litecoin's leveldb instance is used to maintain an MMR Info table (prefix: "M") with `MMRInfo` objects consisting of the following data fields:

* version - A version byte that allows for future schema upgrades.
* index (key) - File number of the PMMR files.
* pruned_hash - Hash of latest header this PMMR represents.
* compact_index - File number of the PruneList bitset.
* compacted - Optional full MWEB header this MMR was compacted for (version 2). Its height and output count define the rewind boundary; its hash identifies that boundary.
* cleanup_pending - Whether deletion of old spent leaf records still needs to finish (version 2).

Each time the PMMRs are flushed to disk, a new MMRInfo object is written to the DB and marked as the latest.
Compaction writes version 2 metadata. Versions 0 and 1 reserved an optional compaction hash but never populated it. These uncompacted records retain their existing encoding and are read without a repair or migration.

##### Leaves (leveldb)
Litecoin's leveldb instance is used to maintain MMR leaf tables (prefix: 'O' for outputs) to store uncompacted PMMR leaves consisting of the following data fields:

* leaf_index (key) - The zero-based leaf position.
* leaf - The raw leaf data committed to by the PMMR.

Leaves already spent at the compaction horizon are removed during compaction. Each output leaf is its output ID; full unspent outputs remain in CoinDB.

##### MMR Hashes (file)

Stored in file `<prefix><index>.dat` where `<prefix>` refers to 'O' for the output PMMR, and `<index>` is a 6-digit number that matches the `index` value of the latest `MMRInfo` object.
Example: If the latest `MMRInfo` object has an `index` of 123, the matching output PMMR hash file will be named `O000123.dat`.

The hash file consists of un-compacted leaf hashes and their parent hashes.

##### Leafset (file)

Stored in file `leaf<index>.dat`.

The leafset file starts with an eight-byte next-leaf index, followed by a bitset indicating which leaf indices of the output PMMR are unspent.
Example: If the PMMR contains 5 leaves where leaf indices 0, 1, and 2 are spent, but 3 and 4 are unspent, the file will contain a single byte of 00011000 = 0x18.

##### PruneList (file)

Stored in file `prun<index>.dat`.

The prunelist file consists of a bitset indicating which nodes of the output PMMR are not included in the output PMMR hash file.
Example: If nodes 0, 1, 3, and 4 are compacted (not included in PMMR), then the first byte of the prune list bitset will be 11011000 = 0xD8.

### Spent-history compaction

Compaction follows existing block pruning. Unpruned nodes keep their full MWEB history. On a pruned node, the horizon is the most recent active-chain block whose block or undo data is no longer available. All blocks after that boundary retain their undo data. A node can rewind **to** the boundary, but cannot disconnect it.

Once the chain tip and both durable and cached coin views agree, the node reconstructs the MWEB leafset at the horizon using retained block undo. It reads one undo record at a time and keeps only leaf-membership changes, without retaining all restored outputs or reconstructing the canonical coin set. Outputs unspent at that point remain available even if they have since been spent. Outputs created after the horizon also remain available. This preserves the history needed for retained reorgs and recent light-client requests. The height and leaf count in the stored compaction header enforce the rewind boundary, including across blocks that add no outputs.

For spent subtrees, compaction discards child hashes while retaining the subtree roots needed for proofs, MMR peaks and subsequent appends. A prune-list bit indicates an omitted logical node. Its physical hash-file position is the logical position minus the count of earlier omitted nodes. Prefix counts cached at fixed intervals bound the work needed for each lookup. The current output root, leafset root, leaf numbering and UTXO set do not change.

Publication and recovery proceed in this order:

1. Stream the retained hashes into a new numbered file, write a cumulative prune list, and copy the current leafset to the same generation. Sync all three files and their directory entries. Validate the new MMR's root and leaf count before publication.
2. Synchronously publish version 2 MMRInfo pointing to those files, with the horizon and `cleanup_pending` set. Only then adopt the new generation and retire the old files.
3. Delete spent leaf records in bounded, synchronous database batches. Clear `cleanup_pending` after deletion completes.

A failure before publication leaves the old generation authoritative; a later attempt can replace orphan files. A restart after publication opens the new generation and enforces its horizon immediately. Incomplete leaf deletion resumes idempotently on the next eligible flush, and obsolete files are removed. Missing files or inconsistent roots in a published compacted generation cause startup to fail rather than interpreting compacted hashes with incorrect offsets.

Compaction needs temporary disk space for the new hash file, leafset and prune list while the old generation remains available. It runs under the chainstate lock and may pause block processing while reconstructing the horizon and copying history. Undo files are deleted by the existing block-pruning machinery; compaction does not introduce a separate rewind limit.
