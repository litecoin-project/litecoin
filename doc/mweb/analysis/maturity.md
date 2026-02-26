# MWEB Maturity Notes (Pegout vs Wallet Spendability)

## Context

In `test/functional/mweb_basic.py`, there is a TODO asking whether pegout outputs should appear spendable after 5 blocks (since they can be spent on the 6th block).

## Current Behavior

- Consensus/mempool: pegout outputs are valid to spend when they will be mature in the **next** block.
- Wallet maturity/UI/coin selection: pegout outputs are treated as immature until they are mature at the **current tip**.

This creates a 1-block difference:
- spendable-for-mempool after 5 additional blocks,
- wallet-marked mature/available after 6 additional blocks.

This mirrors coinbase behavior.

## Relevant Code

- Pegout maturity constant:
  - `src/consensus/consensus.h` (`PEGOUT_MATURITY = 6`)

- Consensus maturity check (used for tx validity at spend height):
  - `src/consensus/tx_verify.cpp` (`Consensus::CheckTxInputs`)
  - Check: reject if `coin.IsPegout()` and `nSpendHeight - coin.nHeight < PEGOUT_MATURITY`

- Mempool reorg re-check for pegout maturity:
  - `src/validation.cpp` (`filter_final_and_mature` lambda in `Chainstate::MaybeUpdateMempoolForReorg`)

- Wallet maturity calculation (extra block semantics):
  - `src/wallet/wallet.cpp` (`CWallet::GetTxBlocksToMaturity`)
  - For HogEx/pegout txs: `max(0, (PEGOUT_MATURITY + 1) - chain_depth)`
  - `CWallet::IsTxImmature` depends on `GetTxBlocksToMaturity() > 0`

- Wallet coin availability/listunspent path:
  - `src/wallet/spend.cpp` (`AvailableCoins`)
  - Immature txs are skipped early (`if (wallet.IsTxImmature(wtx)) continue;`)
  - `listunspent` is backed by this path (`AvailableCoinsListUnspent`)

## Test References

- Pegout maturity expectation in functional test:
  - `test/functional/mweb_basic.py` (5 blocks: still absent; +1 block: appears)

- Coinbase behavior showing same 1-block wallet offset:
  - `test/functional/wallet_coinbase_category.py`

- Mempool perspective ("mature in next block" accepted):
  - `test/functional/mempool_spend_coinbase.py`

## Discussion Summary

The current mismatch is not accidental in implementation: consensus checks next-block spend validity, while wallet maturity marks outputs as mature only once they are mature at the current chain tip. If desired, wallet policy can be changed to align with mempool eligibility, but that would be a behavior change (not just a test tweak).
