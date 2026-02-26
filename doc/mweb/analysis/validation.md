# Validation Logic

### Headers

* `ProcessNewBlockHeaders` is the public entry point for header batches. It loops `AcceptBlockHeader`, then notifies the header tip; it never touches block bodies or the UTXO set.
* `AcceptBlockHeader` handles duplicate detection, calls `CheckBlockHeader` (PoW) and `ContextualCheckBlockHeader` (difficulty, checkpoints, timestamps, version bits), then adds the header to the block index. It only admits headers that pass anti-DoS min-work checks.
* `CheckBlockHeader` is context-free header validation (currently just PoW).
* `ContextualCheckBlockHeader` depends on previous header/chain context: difficulty, checkpoints, median time, version bits.

### Blocks

* `CheckBlock` is context-free block validation: header check, merkle root, size limits, coinbase rules, per-tx `CheckTransaction`, and sigops.
* `ProcessNewBlock` is the public entry point for full blocks. It does a cheap CheckBlock first (under cs_main), then calls AcceptBlock to store the block, and finally calls `ActivateBestChain` to connect it if it advances the best chain.
* `AcceptBlock` calls `AcceptBlockHeader`, applies policy gating for unrequested blocks, runs `CheckBlock` + `ContextualCheckBlock`, and writes block data to disk/indices. It marks validity and records `BLOCK_HAVE_DATA`, but does not connect to the UTXO set.
* `ContextualCheckBlock` depends on previous header/chain context: finality/locktime rules, coinbase height, witness commitment/weight rules, and MWEB contextual checks.

### Transactions

* `CheckTransaction` does context-free sanity checks: non-empty vin/vout, size, output ranges, duplicate inputs, coinbase scriptSig size, and no null prevouts for non-coinbase.
* `Consensus::CheckTxInputs` requires a UTXO view: verifies inputs exist/unspent, coinbase/pegout maturity, input value ranges, MWEB input consistency, and computes fees. It assumes a non-coinbase tx.
* Script validation is separate (`CheckInputScripts`) and is invoked after `CheckTxInputs` in both `ConnectBlock` and mempool acceptance.

### Chain Activation

* `ActivateBestChain` is the orchestrator: find most-work chain, disconnect to the fork point, connect new blocks, and emit notifications. It serializes work with m_chainstate_mutex.
* `ConnectTip` connects a single block to the active tip: load block (disk or cached), call `ConnectBlock`, flush view, update mempool, advance m_chain, and record connect traces.
* `ConnectBlock` is the core UTXO application: re-checks `CheckBlock`, enforces BIP30, sequence locks, `CheckTxInputs`, script checks, updates coins/undo data, and validates fees/coinbase reward. It intentionally does not call `ContextualCheckBlock*` (see the comment about upgrade risks).


## Call Graphs

### Header Acceptance

```
ProcessNewBlockHeaders
  -> AcceptBlockHeader
       -> CheckBlockHeader
            -> CheckProofOfWork
       -> ContextualCheckBlockHeader
            -> GetNextWorkRequired
            -> GetLastCheckpoint (if enabled)
            -> timestamp/version/median-time checks
       -> AddToBlockIndex
  -> NotifyHeaderTip
```

### Block Acceptance

```
ProcessNewBlock
  -> CheckBlock
       -> CheckBlockHeader
       -> BlockMerkleRoot
       -> CheckTransaction (per tx)
       -> GetLegacySigOpCount
  -> AcceptBlock
       -> AcceptBlockHeader
            -> CheckBlockHeader
            -> ContextualCheckBlockHeader
            -> AddToBlockIndex
       -> CheckBlock
       -> ContextualCheckBlock
            -> IsFinalTx (per tx)
            -> witness commitment/weight checks
            -> MWEB::Node::ContextualCheckBlock
       -> SaveBlockToDisk
       -> ReceivedBlockTransactions
  -> ActivateBestChain
```

### Best Chain Activation

```
ActivateBestChain
  -> FindMostWorkChain
  -> ActivateBestChainStep
       -> DisconnectTip (loop to fork)
            -> DisconnectBlock
       -> ConnectTip (loop to best)
            -> ReadBlockFromDisk (if needed)
            -> ConnectBlock
                 -> CheckBlock
                 -> CheckTxInputs (per tx)
                 -> CheckInputScripts (per tx)
                 -> UpdateCoins / WriteUndoDataForBlock
                 -> MWEB::Node::ConnectBlock
            -> Flush / FlushStateToDisk
            -> mempool removeForBlock
            -> UpdateTip
       -> MaybeUpdateMempoolForReorg
       -> CheckForkWarningConditions
  -> UpdatedBlockTip / NotifyBlockTip
  -> FlushStateToDisk (periodic)
```


### Header-first Sync

```
PeerManagerImpl::SendMessages (src/net_processing.cpp)
  -> MaybeSendSendHeaders
  -> if !state.fSyncStarted && eligible:
       -> MaybeSendGetHeaders (GETHEADERS)
```

```
ProcessMessage(HEADERS) (src/net_processing.cpp)
  -> ProcessHeadersMessage
       -> CheckHeadersPoW
       -> CheckHeadersAreContinuous
       -> if !connects: HandleFewUnconnectingHeaders
       -> if low-work: TryLowWorkHeadersSync
            -> HeadersSyncState::ProcessNextHeaders (src/headerssync.cpp)
                 -> ValidateAndStoreHeadersCommitments (PRESYNC)
                 -> ValidateAndStoreRedownloadedHeader (REDOWNLOAD)
                 -> PopHeadersReadyForAcceptance
            -> MaybeSendGetHeaders (NextHeadersRequestLocator)
       -> ChainstateManager::ProcessNewBlockHeaders (src/validation.cpp)
            -> AcceptBlockHeader
                 -> CheckBlockHeader (PoW)
                 -> ContextualCheckBlockHeader
                 -> AddToBlockIndex
            -> NotifyHeaderTip
       -> MaybeSendGetHeaders (if full headers msg)
       -> UpdatePeerStateForReceivedHeaders
       -> HeadersDirectFetchBlocks
            -> BlockRequested
            -> GETDATA (block)
```
