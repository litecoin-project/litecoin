# MWEB Wallet Txs

MWEB-to-MWEB
================

## Send
#### With History
- Single CWalletTx with full CTransaction containing the mw::Transaction
- mw::Coin for all inputs (MINE), sent output (not MINE), and optional change output (MINE)

#### Restore (No History)
- No CTransaction
- Separate CWalletTx and mw::Coin for each input (MINE) and optional change output (MINE)

## Self-Send
#### With History
- Single CWalletTx with full CTransaction containing the mw::Transaction
- mw::Coin for all inputs (MINE), sent output (MINE), and optional change output (MINE)

#### Restore (No History)
- No CTransaction
- Separate CWalletTx and mw::Coin for each input (MINE), sent output (MINE), and optional change output (MINE)

## Receive
#### Seen in Mempool (With History)
- Single CWalletTx with full CTransaction containing the mw::Transaction
- mw::Coin for the received output (MINE)
- No mw::Coin for inputs
- No mw::Coin for optional change output

#### Not Seen in Mempool (No History)
- No CTransaction
- mw::Coin and Partial CWalletTx for the received output (MINE)
- No mw::Coin or CWalletTx for inputs
- No mw::Coin or CWalletTx for optional change output


LTC-to-MWEB (Peg-In)
================

## Send
#### With History
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- mw::Coin for sent MWEB output (not MINE) and optional MWEB change output (MINE)

#### Restore (No History)
- CWalletTx for CTransaction containing only the LTC side (no mw::Transaction)
- No mw::Coin for the sent output
- Separate CWalletTx and mw::Coin for the optional MWEB change output (MINE)

## Self-Send
#### With History
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- mw::Coin for sent MWEB output (MINE) and optional MWEB change output (MINE)

#### Restore (No History)
- CWalletTx for CTransaction containing only the LTC side (no mw::Transaction)
- Separate CWalletTx and mw::Coin for the sent MWEB output (MINE)
- Separate CWalletTx and mw::Coin for the optional MWEB change output (MINE)

## Receive
#### Seen in Mempool (With History)
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- mw::Coin for the received output (MINE)

#### Not Seen in Mempool (No History)
- No CTransaction
- mw::Coin and Partial CWalletTx for the received output (MINE)
- No mw::Coin or CWalletTx for optional change output


MWEB-to-LTC (Peg-Out)
================

Note: For confirmed blocks, the HogEx CWalletTx gets a `pegout_indices` vector whose length matches `vout`.
Entry 0 is a sentinel for the HogAddr output (`{mw::Hash(), 0}`), and each subsequent entry maps the HogEx
pegout output at `vout[i]` to the originating MWEB kernel via `{kernel_id, position_in_kernel}`. This
mapping is used to associate LTC-side pegout outputs with their MWEB kernels and to suppress HogEx outputs
from the tx list when the corresponding MWEB transaction is present in the wallet.

## Send
#### With History
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- mw::Coin for each MWEB input (MINE)
- mw::Coin for optional MWEB change output (MINE)

#### Restore (No History)
- No CTransaction
- Separate CWalletTx and mw::Coin for each input (MINE) and optional MWEB change output (MINE)

## Self-Send
#### With History
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- mw::Coin for each MWEB input (MINE)
- mw::Coin for optional MWEB change output (MINE)
- Pegout output recorded in the mw::Transaction (MINE); HogEx CWalletTx with LTC output (MINE) once confirmed

#### Restore (No History)
- No CWalletTx for the MWEB transaction
- Separate CWalletTx and mw::Coin for each input (MINE) and optional MWEB change output (MINE)
- CWalletTx for the HogEx transaction with the LTC pegout output (MINE)

## Receive
#### Seen in Mempool (With History)
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- Pegout output recorded in the mw::Transaction (MINE)
- No mw::Coin for inputs or MWEB outputs
- HogEx CWalletTx with the LTC pegout output (MINE) once confirmed

#### Not Seen in Mempool (No History)
- No CWalletTx for the MWEB transaction
- CWalletTx for the HogEx transaction with the LTC pegout output (MINE)
- No mw::Coin for inputs or MWEB outputs


LTC-to-MWEB-to-LTC (Peg-in + Peg-Out)
================

## Send
#### With History
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- mw::Coin for each MWEB input (MINE)
- mw::Coin for optional MWEB change output (MINE)

#### Restore (No History)
- CWalletTx for CTransaction containing only the LTC side (no mw::Transaction)
- Separate CWalletTx and mw::Coin for each MWEB input (MINE)
- Separate CWalletTx and mw::Coin for optional MWEB change output (MINE)

## Self-Send
#### With History
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- mw::Coin for each MWEB input (MINE)
- mw::Coin for optional MWEB change output (MINE)
- Pegout output recorded in the mw::Transaction (MINE); HogEx CWalletTx with LTC output (MINE) once confirmed

#### Restore (No History)
- CWalletTx for CTransaction containing only the LTC side (no mw::Transaction)
- Separate CWalletTx and mw::Coin for each MWEB input (MINE)
- Separate CWalletTx and mw::Coin for optional MWEB change output (MINE)
- CWalletTx for the HogEx transaction with the LTC pegout output (MINE)

## Receive
#### Seen in Mempool (With History)
- Single CWalletTx with full, pre-stripped CTransaction containing the LTC side and the mw::Transaction
- Pegout output recorded in the mw::Transaction (MINE)
- No mw::Coin for inputs or MWEB outputs
- HogEx CWalletTx with the LTC pegout output (MINE) once confirmed

#### Not Seen in Mempool (No History)
- No CWalletTx for the MWEB transaction
- CWalletTx for the HogEx transaction with the LTC pegout output (MINE)
- No mw::Coin for inputs or MWEB outputs
