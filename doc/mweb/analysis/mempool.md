# Mempool

## Mempool Acceptance

Here’s the single‑tx mempool acceptance path in v24.x, with the main decision points and where each check happens. Primary flow lives in validation.cpp, with context-free checks in tx_check.cpp and UTXO checks in tx_verify.cpp.

### Entry points

* `ChainstateManager::ProcessTransaction` is the common entry from P2P/RPC; it requires `cs_main`, ensures there’s a mempool, then calls `AcceptToMemoryPool`.
* `AcceptToMemoryPool` builds `ATMPArgs::SingleAccept` and calls `MemPoolAccept::AcceptSingleTransaction`. On failure it uncaches any coins fetched during validation (DoS protection) and periodically flushes state.

### AcceptSingleTransaction (core path)

* `MemPoolAccept::AcceptSingleTransaction` takes `cs_main` + `m_pool.cs`, constructs a `Workspace`, and runs the sequence below.

### PreChecks (cheap + context/UTXO gate)

* Context‑free sanity: `CheckTransaction` and `MWEB::Node::CheckTransaction`.
* Reject coinbase/hogex (not valid in mempool), enforce standardness, size floor, and finality for next block.
* Mempool duplicates (wtxid/txid) and conflicts; conflict handling gates RBF (opt‑in unless full RBF enabled).
* Input availability via `CCoinsViewMemPool` (UTXO + mempool); missing inputs return `TX_MISSING_INPUTS`.
* Sequence locks at tip (`CheckSequenceLocksAtTip`).
* UTXO validity + fee calc via `Consensus::CheckTxInputs` (maturity, value ranges, MWEB inputs/fees).
* Input standardness / witness standardness checks, sigops cost, fee‑rate policy, and ancestor/descendant limits.

### ReplacementChecks (only if conflicts/RBF)

* Enforces BIP125‑style rules: higher feerate than conflicts, no new unconfirmed dependencies, pays incremental relay, etc.

### Script validation

* `PolicyScriptChecks`: CheckInputScripts under STANDARD_SCRIPT_VERIFY_FLAGS, with witness‑stripped detection.
* `ConsensusScriptChecks`: CheckInputsFromMempoolAndCache using current block script flags to seed the script cache (consensus‑critical for caching).

### Finalize

* If test_accept, stop here and return success without adding.
* Otherwise: remove conflicts, addUnchecked, trim mempool (unless bypass/package), and emit `TransactionAddedToMempool`.

### Package variant (if you’re looking at package acceptance)

* `ProcessNewPackage` → `AcceptMultipleTransactions`/`AcceptPackage`, which reuse `PreChecks`/`PolicyScriptChecks`/`ConsensusScriptChecks` but apply package‑level feerate and submission rules.

## Call Graphs

### Single-Tx Acceptance

```
ChainstateManager::ProcessTransaction (src/validation.cpp)
  -> AcceptToMemoryPool (src/validation.cpp)
       -> MemPoolAccept::AcceptSingleTransaction (src/validation.cpp)
            -> PreChecks (src/validation.cpp)
                 -> CheckTransaction (src/consensus/tx_check.cpp)
                 -> MWEB::Node::CheckTransaction (src/mweb/mweb_node.cpp)
                 -> IsStandardTx / AreInputsStandard / IsWitnessStandard (src/policy/*, src/validation.cpp)
                 -> CheckFinalTxAtTip (src/validation.cpp)
                 -> CheckSequenceLocksAtTip (src/validation.cpp)
                 -> Consensus::CheckTxInputs (src/consensus/tx_verify.cpp)
                 -> GetTransactionSigOpCost (src/consensus/tx_verify.cpp)
                 -> CalculateMemPoolAncestors (src/txmempool.cpp)
            -> ReplacementChecks (if conflicts/RBF) (src/validation.cpp)
            -> PolicyScriptChecks (src/validation.cpp)
                 -> CheckInputScripts (src/validation.cpp)
            -> ConsensusScriptChecks (src/validation.cpp)
                 -> CheckInputsFromMempoolAndCache (src/validation.cpp)
                      -> CheckInputScripts (src/validation.cpp)
            -> Finalize (if !test_accept) (src/validation.cpp)
                 -> RemoveStaged / addUnchecked / LimitMempoolSize (src/txmempool.cpp)
                 -> GetMainSignals().TransactionAddedToMempool (src/validation.cpp)
```


### Package Acceptance

```
ProcessNewPackage (src/validation.cpp)
  -> MemPoolAccept::AcceptMultipleTransactions (test_accept=true)
       -> CheckPackage (src/validation.cpp)
       -> PreChecks (per tx) (src/validation.cpp)
            -> CheckTransaction (src/consensus/tx_check.cpp)
            -> MWEB::Node::CheckTransaction (src/mweb/mweb_node.cpp)
            -> IsStandardTx / AreInputsStandard / IsWitnessStandard (src/policy/*, src/validation.cpp)
            -> CheckFinalTxAtTip / CheckSequenceLocksAtTip (src/validation.cpp)
            -> Consensus::CheckTxInputs (src/consensus/tx_verify.cpp)
            -> GetTransactionSigOpCost (src/consensus/tx_verify.cpp)
            -> CalculateMemPoolAncestors (src/txmempool.cpp)
       -> PackageMempoolChecks (src/validation.cpp)
       -> PolicyScriptChecks (per tx) (src/validation.cpp)
            -> CheckInputScripts (src/validation.cpp)
       -> ConsensusScriptChecks (per tx) (src/validation.cpp)
            -> CheckInputsFromMempoolAndCache (src/validation.cpp)
                 -> CheckInputScripts (src/validation.cpp)
       -> (test_accept) returns without Finalize()

  -> MemPoolAccept::AcceptPackage (test_accept=false, child-with-parents)
       -> CheckPackage (src/validation.cpp)
       -> (dedupe already-in-mempool txs)
       -> AcceptMultipleTransactions (for new txs) (src/validation.cpp)
            -> same PreChecks/Policy/Consensus as above
       -> SubmitPackage (src/validation.cpp)
            -> ConsensusScriptChecks (per tx)
            -> CalculateMemPoolAncestors (per tx)
            -> Finalize (per tx)
                 -> addUnchecked / RemoveStaged / LimitMempoolSize (src/txmempool.cpp)
            -> TransactionAddedToMempool (per tx)
```