Litecoin Core 24.0.1-rc1 Release Notes
====================================

Release candidate: `v24.0.1-rc1` (12 October 2026).

This is the first release candidate for Litecoin Core 24.0.1. It is intended
for testing before the final release. It brings the Bitcoin Core 24 codebase
to Litecoin, including MWEB node, wallet, descriptor, PSBT, and GUI support.
Mainnet is enabled by default.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/litecoin-project/litecoin/issues>

How to Upgrade
==============

Shut down the older version and wait until it has completely stopped. Back up
your wallets and data directory before starting this version. Then run the
installer on Windows, replace `/Applications/Litecoin-Qt.app` on macOS, or
replace `litecoind` and `litecoin-qt` on Linux.

Node database upgrade and downgrades
-----------------------------------

This version upgrades the on-disk MWEB node database when it encounters the
legacy format. **The upgrade is one-way: older versions cannot use the upgraded
database.** The GUI asks for confirmation before upgrading existing MWEB
records. `litecoind` performs the upgrade automatically at startup.

To return to an older version, restore a data-directory backup made before the
upgrade or use a fresh data directory and download the blockchain again. Keep
wallet backups separately; downloading the blockchain does not restore wallets.

Legacy and descriptor wallets
-----------------------------

Existing legacy wallets remain supported. New wallets use descriptors by
default, including support for MWEB addresses and transactions. Upgrading the
node does not automatically convert legacy wallets to descriptor wallets.

The experimental `migratewallet` RPC converts an unencrypted legacy wallet to
a descriptor wallet. It creates a `<wallet name>-<timestamp>.legacy.bak` backup
and may create separate watch-only and solvables wallets. Encrypted wallet
migration is currently unsupported. Make a new wallet backup after migration
and keep the original backup for recovery.

Migration preserves MWEB history, receiving addresses, imported keys, and
labels. Failed migration restores the legacy backup without removing shared
wallet directories. See [MWEB wallet migration](mweb/migration.md) for details.

Notable Changes
===============

MWEB wallets and transactions
----------------------------

- Descriptor wallets support `mweb(...)` descriptors for spending and
  watch-only use. See the [MWEB descriptor documentation](mweb/mweb-descriptors.md).
- Wallet RPCs support MWEB coin control, transaction funding and signing, and
  PSBTs with MWEB inputs and outputs. PSBT decoding accounts for MWEB amounts,
  fees, and transfers between the main chain and MWEB.
- Payments can combine transparent and MWEB recipients. MWEB change is created
  automatically when needed, and subtracting fees preserves the intended
  recipient amounts in mixed payments.
- MWEB balances, transaction history, conflicts, rescans, and reorganizations
  are tracked by both legacy and descriptor wallets. The GUI supports MWEB
  payments and transaction details.
- `sethdseed` rejects seed replacement in legacy wallets with MWEB keychains,
  protecting access to their existing MWEB funds.

Node, network, and mining
------------------------

- Header synchronization checks proof of work in parallel and can resume
  low-work header presync across peers.
- Compact blocks can be downloaded concurrently from multiple peers, improving
  recovery when a peer withholds a block.
- MWEB block validation and recovery from mutated block bodies have been
  hardened, including validation of bodies reloaded from disk.
- MWEB conflicts are removed from the mempool when blocks connect. Mining
  selection accounts for MWEB fees, and chainstate cache accounting includes
  MWEB memory use.
- Pruned nodes compact spent MWEB history. Compaction can safely retry when
  orphaned files remain from an earlier attempt.

Main-chain data-carrier policy
-----------------------------

- Main-chain transactions may now contain multiple `OP_RETURN` outputs. The
  default `-datacarriersize` is 100,000 bytes. The limit applies to the sum of
  their complete scriptPubKeys, including `OP_RETURN` and push opcodes, but
  excluding output serialization overhead. The existing 400,000-weight-unit
  standard transaction limit still applies.
- `-datacarrier` and `-datacarriersize` remain configurable. Setting
  `-datacarrier=0` disables data-carrier relay and mining. Setting
  `-datacarriersize=83` restores an 83-byte aggregate budget; it does not restore
  the previous one-output rule for main-chain transactions. Transactions
  exceeding the budget are rejected with `datacarrier` rather than `scriptpubkey`.
- MWEB peg-out scripts retain their restrictions. A peg-out `OP_RETURN` is
  limited to 83 script bytes, or a smaller configured data-carrier limit, and
  must be the transaction's only `OP_RETURN`, including main-chain outputs and
  peg-outs from every kernel. Disabling data carriers also disables them for
  peg-outs. Peg-out script-type, dust, and bare-multisig checks still apply.
- `getmempoolinfo` now returns `maxdatacarriersize`, the configured main-chain
  aggregate budget or 0 when disabled, and `permitbaremultisig`.

These data-carrier changes affect relay and mining policy only; consensus
rules are unchanged.

Transaction replacement defaults
--------------------------------

Transaction replacement remains disabled by default in Litecoin Core
(`-mempoolreplacement=0`). Full RBF also defaults to off
(`-mempoolfullrbf=0`), and wallet transactions do not signal replacement by
default (`-walletrbf=0`). The `replaceable` argument to `createrawtransaction`
and `createpsbt` defaults to `false`.

RPC and GUI changes inherited from Bitcoin Core 24
-------------------------------------------------

- New RPCs include `sendall`, `gettxspendingprevout`, and
  `simulaterawtransaction`.
- `getblockchaininfo` no longer returns `softforks`; use `getdeploymentinfo`.
- Mempool RPC fee information is returned in the `fees` object rather than the
  removed top-level fee fields.
- `getpeerinfo` includes `presynced_headers` to report header presync progress.
- Wallet transaction RPCs include `wtxid` and receiving descriptor information.
- The GUI can restore wallets from backup. GUI configuration is stored in
  `settings.json` and also applies to `litecoind`.

The [archived Bitcoin Core 24.0.1 release notes](release-notes/release-notes-24.0.1.md)
describe the upstream baseline. Litecoin-specific behavior, especially MWEB
support and transaction replacement defaults, is described above.

Credits
=======

Thanks to the Litecoin Core and Bitcoin Core contributors, reviewers,
translators, and release-candidate testers.
