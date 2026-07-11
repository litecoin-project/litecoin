# Legacy to Descriptor Wallet Migration

This document describes the v24.x `migratewallet` process from the point of
view of the wallet database. It is meant to answer two questions:

- What records can exist in a legacy wallet before migration?
- What records should exist in the primary, watch-only, and solvables wallets
  after migration?

The migration is a compatibility operation. It preserves wallet history and
ownership while replacing the legacy `LegacyScriptPubKeyMan` database records
with descriptor `DescriptorScriptPubKeyMan` records.

## Scope

`migratewallet` currently supports unencrypted legacy wallets. Encrypted wallet
migration is rejected by the RPC before the migration starts, so legacy `ckey`
and `mkey` records are described here as part of the schema, but they are not
part of the current successful RPC path.

Legacy wallets with private keys disabled are allowed. In that case, migration
keeps watch-only/solvable descriptors in the primary disable-private-keys
descriptor wallet where appropriate and does not create active private-key
receive descriptors.

The migration can create up to three wallets:

- `<wallet>`: the primary migrated descriptor wallet.
- `<wallet>_watchonly`: optional wallet for watched scripts that do not have
  private keys in the original wallet.
- `<wallet>_solvables`: optional wallet for solvable but unwatched scripts.

The original wallet is backed up first as:

```
<wallet name>-<timestamp>.legacy.bak
```

If migration fails, the partially migrated wallets are removed and the backup is
restored.

## High-Level Process

The migration runs in this order:

1. Create a backup of the legacy wallet database.
2. Unload the wallet from the node wallet context.
3. Load the wallet locally for migration.
4. Convert the database backend to SQLite.
5. Build descriptor managers from the legacy manager.
6. Create optional auxiliary watch-only and solvables descriptor wallets.
7. Apply the migration data to the primary wallet:
   - insert descriptor managers,
   - erase legacy manager records,
   - set the descriptor wallet flag,
   - set up active descriptor managers,
   - move watch-only transactions,
   - move or clone address book records.
8. Reload the migrated primary wallet in the node wallet context.

Step 4 copies every existing key/value record into a SQLite database before the
logical migration begins. The sections below describe the logical record layout;
the original backup remains available in its pre-migration format.

## Record Vocabulary

Legacy wallets and descriptor wallets use the same key/value database layer.
The logical record type is the first component of the serialized database key.

### Wallet-global records

These records are not owned by a specific script-pub-key manager:

| Record type | Meaning | Migration behavior |
|-------------|---------|--------------------|
| `version` | Wallet client version record. | Retained. |
| `minversion` | Minimum wallet feature version. | Retained. |
| `flags` | Wallet flags. | Retained and updated to include `WALLET_FLAG_DESCRIPTORS`. |
| `settings` | Wallet settings. | Retained. |
| `bestblock` | Best block locator. | Retained. |
| `bestblock_nomerkle` | Best block locator without merkle data. | Retained. |
| `orderposnext` | Next transaction/order position. | Retained and updated as transactions are moved. |
| `lockedutxo` | Locked transparent or MWEB outputs. | Retained in the primary wallet. |
| `mkey` | Encryption master key. | Legacy schema record; encrypted wallets are rejected by the RPC today. |
| `mweb_sender_key_index` | Next MWEB sender key index for a master scan key. | Retained. |

### Address book records

| Record type | Meaning | Migration behavior |
|-------------|---------|--------------------|
| `name` | Address label. | Kept, moved, cloned, or deleted depending on ownership and purpose. |
| `purpose` | Address purpose such as `receive` or `send`. | Kept, moved, cloned, or deleted with the address book entry. |
| `destdata` | Per-destination metadata such as receive-request data or used-address state. | Kept for entries remaining in the primary wallet. Deleted from the primary wallet when the address book entry is moved out. It is not copied to auxiliary wallets by the migration code. |

### Transaction and MWEB coin records

| Record type | Meaning | Migration behavior |
|-------------|---------|--------------------|
| `tx` | Serialized `CWalletTx`. Covers transparent transactions, full MWEB transactions, and partial MWEB wallet transactions. | Retained in the primary wallet if still owned by or from the migrated primary descriptors. Moved to the watch-only wallet if only the watch-only descriptors own it. Migration fails if no migrated wallet owns it. |
| `coin` | Serialized `mw::WalletCoin` for an MWEB output. | Retained in the primary wallet. |

`CWalletTx` stores MWEB transaction metadata in the serialized wallet
transaction data. On load, the `mweb_info` value becomes `CWalletTx::mweb_wtx_info`.
Partial MWEB wallet transactions are keyed by the wallet transaction info hash
rather than by a normal transaction id.

### Legacy script-pub-key manager records

The migration erases the legacy manager records from the primary wallet after
descriptor managers have been created. The erased record types are:

| Record type | Meaning |
|-------------|---------|
| `key` | Plain private key record, keyed by public key. |
| `ckey` | Encrypted private key record, keyed by public key. |
| `keymeta` | `CKeyMetadata` for a public key. |
| `wkey` | Very old wallet key format. |
| `defaultkey` | Legacy default receive key. |
| `hdchain` | Active legacy HD chain state and counters. |
| `pool` | Legacy keypool entry. |
| `cscript` | Stored redeem or witness script. |
| `watchs` | Watched script. |
| `watchmeta` | Metadata for a watched script. |

These records are removed only from the primary migrated wallet. Auxiliary
wallets are newly created descriptor wallets and never contain these legacy
records.

### Descriptor script-pub-key manager records

These records are created by migration:

| Record type | Meaning |
|-------------|---------|
| `walletdescriptor` | Serialized `WalletDescriptor`: descriptor string, creation time, range start, range end, and next index. |
| `walletdescriptorkey` | Private key for a descriptor manager. |
| `walletdescriptorckey` | Encrypted private key for a descriptor manager. Not used by the current unencrypted RPC path. |
| `walletdescriptorcache` | Descriptor xpub cache entries. |
| `walletdescriptorlhcache` | Last hardened xpub cache entries for descriptors containing hardened path components. |
| `walletdescriptormwebaddresscache` | Cached MWEB stealth address by descriptor id and index. |
| `activeexternalspk` | Active external descriptor manager for an output type. |
| `activeinternalspk` | Active internal descriptor manager for an output type. |

Descriptor records replace legacy keys, scripts, HD-chain records, and keypool
records. Descriptor `range_end` and `next_index` replace the legacy keypool and
chain counters.

## Legacy Wallet Before Migration

Before migration, the primary wallet has one `LegacyScriptPubKeyMan` that owns
all spendable keys, scripts, watched scripts, and HD-chain state.

### Spendable non-HD keys

Imported or otherwise non-HD private keys are stored as:

- `key` plus `keymeta` for unencrypted wallets.
- `ckey` plus `keymeta` for encrypted wallets.

The key metadata may include key-origin information, but these keys are not tied
to the active legacy HD chain or any inactive legacy HD chain.

### Legacy HD transparent chains

The active legacy HD chain is stored in the `hdchain` record. It contains the
active seed id and chain counters. Key metadata for derived keys points back to
that seed id.

Transparent receive and change keys use the legacy derivation model:

- external receive keys: `m/0'/0'/i'` in key metadata,
- internal change keys: `m/0'/1'/i'` in key metadata.

Each derived key also exists as a normal legacy `key` or `ckey` record with a
`keymeta` record. The legacy `pool` records contain prefetched keys for address
generation.

Inactive HD chains can also be present. They are reconstructed from key metadata
and stored in memory as inactive chains during wallet loading. Their keys are
still stored as legacy `key` or `ckey` records with `keymeta`.

### Legacy MWEB keys

The legacy MWEB wallet derives master MWEB material from the HD seed:

- master scan key: `m/0'/100'/0'`,
- master spend key: `m/0'/100'/1'`.

MWEB subaddress spend keys are not represented by paths like
`m/0'/100'/i'`. Released legacy wallets used the `hdKeypath` string `x/i` for
the `i`th MWEB subaddress key. Current metadata also exposes this through
`KeyOriginInfo::hdkeypath.mweb_index`.

Successful migration treats only the following as MWEB subaddress metadata:

- explicit serialized `mweb_index` in v14 key metadata,
- legacy bare `hdKeypath = "x/i"`.

Syntactically valid `m/0'/100'/i'` key metadata is treated as normal metadata
for the MWEB master-key purpose path. It does not become subaddress metadata and
does not advance MWEB receive counters.

### Spendable scripts

Legacy wallets can store spendable scripts in `cscript`. Examples include:

- P2SH redeem scripts,
- P2WSH witness scripts,
- P2SH-P2WPKH and P2SH-P2WSH wrapper scripts,
- multisig scripts.

If the wallet has enough private keys to spend an output, the script is treated
as primary spendable wallet data.

### Watch-only scripts

Watched scripts are stored as:

- `watchs`: the script being watched,
- `watchmeta`: metadata for that watched script,
- often `cscript`: solving data such as redeem or witness scripts.

Legacy watch-only data is transparent-only. Legacy wallets do not support MWEB
watch-only imports.

### Solvable but unwatched scripts

Some scripts can be solvable because their redeem or witness scripts are present
in `cscript`, but they are not watched through `watchs` and do not have private
keys. These scripts are not primary spendable wallet data, but migration can
preserve their solving data in a separate descriptor wallet.

### Address book before migration

The address book is stored in `name`, `purpose`, and optional `destdata`
records. It can contain:

- receive entries for wallet-owned transparent destinations,
- receive entries for watched transparent destinations,
- send entries for external payees,
- change entries in memory with special address-book state,
- per-destination data such as receive requests or used-address flags.

### Transactions before migration

All wallet transactions are in `tx` records in the primary wallet:

- transparent receives,
- transparent spends,
- transparent watch-only transactions,
- MWEB receives,
- MWEB spends,
- partial MWEB wallet transactions created before the full transaction is known.

MWEB output data is also represented by `coin` records. Those records are keyed
by MWEB output id and contain the wallet coin data needed for later detection and
spending.

## Descriptor Synthesis

Migration first asks the legacy manager to synthesize descriptors from the
legacy records. The result is grouped into primary descriptors, watch-only
descriptors, and solvable descriptors.

### Non-HD private keys

Each non-HD private key becomes a non-ranged primary descriptor:

```
combo([origin]pubkey)
```

If key-origin data exists, it is included in the descriptor. The private key is
stored under `walletdescriptorkey`.

Seed keys whose metadata path is `s` or `m` are treated as standalone keys for
this purpose because legacy wallets consider them wallet-owned keys.

### Legacy HD transparent descriptors

For each active or inactive legacy HD chain, migration derives the master key
from the chain seed and creates ranged transparent descriptors:

```
combo(master_xpub/0'/0'/*)
combo(master_xpub/0'/1'/*)
```

The first descriptor covers legacy external receive keys. The second covers
legacy internal change keys when HD split is supported.

The descriptor range is initialized from the legacy chain counter. The descriptor
is topped up so historical scripts are cached, and then `next_index` is set to
the old chain counter. This preserves the next child index for future use if the
descriptor is ever used directly, while avoiding reuse of already-known keys.

### Legacy MWEB descriptors

For the active legacy HD chain with MWEB support, migration creates a ranged
MWEB descriptor:

```
mweb(master_xprv/0'/100'/0',master_xpub/0'/100'/1',*)
```

The descriptor range and `next_index` come from the active legacy MWEB receive
counter. MWEB stealth-address cache records are written as needed by the
descriptor manager.

The migrated MWEB descriptor id is remembered so the primary wallet can activate
that exact descriptor after the legacy manager is removed. Inactive legacy HD
chains are treated as transparent-only for migration and do not create MWEB
descriptors.

### Imported spendable scripts

Remaining spendable transparent scripts are converted by descriptor inference.
If a private form of the descriptor can be produced from the legacy wallet, the
descriptor is added to the primary wallet with any available private keys.

Examples include inferred descriptors for:

- P2PK and P2PKH,
- P2SH,
- P2WPKH,
- P2SH-P2WPKH,
- P2WSH,
- P2SH-P2WSH,
- spendable multisig.

### Watch-only scripts

If descriptor inference cannot produce a private descriptor and the original
wallet was not a disable-private-keys wallet, the descriptor is placed in
`<wallet>_watchonly`. If the original wallet already had private keys disabled,
the descriptor is kept in the primary migrated wallet because the primary wallet
itself remains the watch-only wallet.

Watch-only descriptors produced by this path are non-ranged. The auxiliary
wallet is a descriptor wallet with private keys disabled and no active receive
descriptor managers.

### Solvable but unwatched scripts

Multisig scripts that are solvable but neither spendable nor watched are placed
in `<wallet>_solvables`. This preserves solving data without making the primary
wallet or watch-only wallet track transactions for scripts that were not tracked
before migration.

The solvables wallet is also a descriptor wallet with private keys disabled and
no active receive descriptor managers.

## Primary Wallet After Migration

After migration, the primary wallet database is a descriptor wallet database.

### Removed records

The following legacy manager record types should no longer exist in the primary
wallet:

- `key`
- `ckey`
- `keymeta`
- `wkey`
- `defaultkey`
- `hdchain`
- `pool`
- `cscript`
- `watchs`
- `watchmeta`

The backup file is the place to find these original records after migration.

### Retained records

The primary wallet retains wallet-global records that are not legacy-manager
records, including:

- `version`,
- `minversion`,
- `settings`,
- `bestblock`,
- `bestblock_nomerkle`,
- `orderposnext`,
- `lockedutxo`,
- `mweb_sender_key_index`,
- `tx` records that still belong to the primary descriptors,
- `coin` records,
- address book records that still belong in the primary wallet.

The `flags` record is retained and updated to include descriptor-wallet state.

### New descriptor records

The primary wallet contains `walletdescriptor` records for:

- non-HD imported private keys,
- active and inactive legacy transparent HD chains,
- active legacy MWEB HD chain,
- spendable imported scripts,
- newly generated active descriptor managers for the current seed when private
  keys are enabled.

The primary wallet also contains the related descriptor key and cache records:

- `walletdescriptorkey`,
- `walletdescriptorcache`,
- `walletdescriptorlhcache`,
- `walletdescriptormwebaddresscache` for MWEB descriptors.

Current encrypted wallet migration is not supported, so
`walletdescriptorckey` is not expected from a successful `migratewallet` RPC
today.

### Active descriptors

The primary wallet writes `activeexternalspk` and `activeinternalspk` records for
active descriptor managers.

For transparent output types in wallets with private keys enabled, migration
sets up modern active descriptors from the current master seed. These active
descriptors are separate from the historical legacy-path descriptors created to
preserve old keys and addresses.

For MWEB, if the legacy wallet had an active MWEB chain, the migrated MWEB
descriptor for that active chain is activated. This preserves the MWEB receive
counter and keeps future MWEB addresses on the same active chain. If no active
migrated MWEB descriptor exists, normal descriptor setup can create a new active
MWEB descriptor.

There is no active internal MWEB manager because MWEB does not use a separate
internal/change chain in this wallet model.

For wallets with private keys disabled, migration does not create new active
private-key receive descriptors.

### Inactive descriptors

Transparent descriptors for inactive legacy HD chains remain in the primary
wallet as non-active descriptor managers. They are available for ownership
checks, rescans, and spending historical transparent funds. They do not serve new
receive addresses.

Inactive legacy HD chains are not loaded as MWEB keychains and do not migrate to
inactive MWEB descriptors.

## Auxiliary Wallets After Migration

### `<wallet>_watchonly`

This wallet is created only if the legacy wallet had watched scripts that could
not be represented as primary spendable descriptors.

Expected properties:

- descriptor wallet,
- blank wallet,
- private keys disabled,
- same avoid-reuse and key-origin-metadata flags as the source wallet when those
  flags were set,
- non-ranged `walletdescriptor` records for watched scripts,
- descriptor cache records as needed,
- no legacy manager records,
- no active receive descriptor records.

Transactions that are not owned by or from the primary wallet after descriptor
migration are checked against this wallet. If the watch-only wallet owns them,
they are inserted into `<wallet>_watchonly` and deleted from the primary wallet.

### `<wallet>_solvables`

This wallet is created only if migration found solvable but unwatched scripts.

Expected properties:

- descriptor wallet,
- blank wallet,
- private keys disabled,
- same avoid-reuse and key-origin-metadata flags as the source wallet when those
  flags were set,
- non-ranged `walletdescriptor` records for solvable scripts,
- descriptor cache records as needed,
- no legacy manager records,
- no active receive descriptor records.

Transactions are not moved to the solvables wallet. Scripts in this bucket were
not watched before migration, so historical transactions for them should not
have been present as wallet transactions.

## Address Book Migration

Address book migration is ownership-based.

### Receive entries

For entries with `purpose = "receive"`:

- If the destination is still owned by the primary migrated wallet, the entry
  stays in the primary wallet.
- If the destination is owned by the watch-only wallet, the label and purpose
  are added to the watch-only wallet and the entry is deleted from the primary
  wallet.
- If the destination is owned by the solvables wallet, the label and purpose are
  added to the solvables wallet and the entry is deleted from the primary wallet.
- If no migrated wallet owns the destination, migration fails.

When an entry is deleted from the primary wallet, its primary-wallet `name`,
`purpose`, and `destdata` records are erased.

### Non-receive entries

For entries whose purpose is not `receive`, such as send labels:

- The entry remains in the primary wallet.
- If a watch-only wallet was created, the label and purpose are cloned there.
- Otherwise, if a solvables wallet was created, the label and purpose are cloned
  there.

The current migration code copies label and purpose state for auxiliary address
book entries. It does not copy `destdata` to auxiliary wallets.

The expected post-migration database state is persisted `name` and `purpose`
records in any auxiliary wallet that receives or clones an address book entry.
Keeping this data only in the in-memory address book is not sufficient because
it would be lost on wallet reload.

## Transaction Migration

Transaction migration revalidates every wallet transaction after descriptors
have replaced the legacy manager.

### Transparent transactions

Transparent transactions remain in the primary wallet when any of the following
is true after descriptor migration:

- an output is owned by a primary descriptor,
- an input spends a primary-owned output,
- the transaction is otherwise considered from the primary wallet.

This covers historical receives and spends for:

- standalone imported private keys,
- active legacy HD receive and change chains,
- inactive legacy HD chains,
- spendable imported scripts and multisig.

Transparent watch-only transactions are moved to `<wallet>_watchonly` if that
wallet owns or sent them under its migrated descriptors.

### MWEB transactions

MWEB wallet transactions remain in the primary wallet when their MWEB outputs or
inputs are recognized by migrated primary MWEB descriptors.

This covers:

- receives to the active legacy MWEB chain,
- spends from the active legacy MWEB chain,
- partial MWEB wallet transactions whose `mweb_wtx_info` identifies wallet
  output data before the full transaction is known.

MWEB `coin` records stay in the primary wallet. They are not legacy manager
records and are not moved to auxiliary wallets.

### Unidentified transactions

If a transaction is no longer considered owned by or from the primary wallet and
is not owned by or from the watch-only wallet, migration fails. This prevents a
successful migration from silently dropping transaction history.

## Type-by-Type Before and After Summary

| Data type | Before migration | After migration |
|-----------|------------------|-----------------|
| Standalone unencrypted private key | `key` plus `keymeta` in primary wallet. | Primary `combo([origin]pubkey)` `walletdescriptor` plus `walletdescriptorkey`; legacy key records removed. |
| Standalone encrypted private key | `ckey`, `keymeta`, and `mkey`. | Not reachable through current `migratewallet` RPC because encrypted wallets are rejected. |
| Legacy seed key (`s` or `m`) | `key` plus `keymeta`; considered wallet-owned. | Primary standalone `combo(...)` descriptor; legacy records removed. |
| Active transparent HD receive key | `key`/`keymeta`, `hdchain`, and possibly `pool`; metadata path `m/0'/0'/i'`. | Historical primary ranged `combo(master_xpub/0'/0'/*)` descriptor with range and `next_index` from the legacy counter; old records removed. |
| Active transparent HD change key | `key`/`keymeta`, `hdchain`, and possibly `pool`; metadata path `m/0'/1'/i'`. | Historical primary ranged `combo(master_xpub/0'/1'/*)` descriptor with range and `next_index` from the legacy counter; old records removed. |
| Inactive transparent HD chain | Legacy keys and metadata for an inactive seed. | Non-active primary ranged transparent descriptors; available for ownership checks and rescans, not for new addresses. |
| Active MWEB chain | Legacy seed, `hdchain` MWEB counter, MWEB subaddress key metadata using `x/i` or explicit `mweb_index`; master material under `m/0'/100'/0'` and `m/0'/100'/1'`. | Active primary ranged `mweb(master_scan,master_spend,*)` descriptor with preserved range and `next_index`; old key records removed; MWEB coin and tx records retained. |
| Inactive MWEB chain | Unsupported in legacy wallets. | No inactive MWEB descriptor is created. |
| `m/0'/100'/0'` and `m/0'/100'/1'` metadata | Master scan and master spend derivation paths. | Represented by the migrated MWEB descriptor's master key expressions. They are not subaddress indices. |
| Other `m/0'/100'/i'` metadata | Syntactically valid key metadata, but not MWEB subaddress metadata. | Does not create or advance MWEB subaddress state by itself. |
| Spendable P2PK/P2PKH/P2SH/P2WPKH/P2WSH/P2SH-P2WPKH/P2SH-P2WSH | Legacy keys and scripts in `key`, `keymeta`, and `cscript`. | Primary inferred descriptor plus descriptor private keys and caches. |
| Spendable multisig | `cscript` plus enough wallet private keys to spend. | Primary inferred multisig descriptor with available private keys. |
| Watch-only transparent script | `watchs`/`watchmeta`, often with `cscript`; transactions in primary `tx`. | Non-ranged descriptor in `<wallet>_watchonly`; matching transactions moved there; legacy records removed from primary. |
| Solvable but unwatched script | Solving data in `cscript`, but not watched and not spendable. | Non-ranged descriptor in `<wallet>_solvables`; no transactions moved. |
| Legacy keypool | `pool` records. | Removed. Descriptor ranges, caches, and `next_index` replace keypool state. |
| Default legacy key | `defaultkey`. | Removed. Active descriptor records determine address generation. |
| Receive address label for primary-owned destination | `name` and `purpose=receive`, optional `destdata`. | Remains in primary. |
| Receive address label for watch-only destination | `name` and `purpose=receive`, optional `destdata`, plus watch-only script records. | Label and purpose moved to `<wallet>_watchonly`; primary address-book and primary `destdata` records for that destination erased. |
| Receive address label for solvable destination | `name` and `purpose=receive`, optional `destdata`, plus solvable script records. | Label and purpose moved to `<wallet>_solvables`; primary address-book and primary `destdata` records for that destination erased. |
| Send label or other non-receive address-book entry | `name` and non-`receive` `purpose`. | Remains in primary and is cloned to one auxiliary wallet if one is created. |
| Transparent primary-owned transaction | `tx` in primary wallet. | Remains in primary if primary descriptors still own it or spent from it. |
| Transparent watch-only transaction | `tx` in primary wallet. | Moved to `<wallet>_watchonly` if watch-only descriptors own it. |
| MWEB wallet transaction | `tx` in primary wallet with MWEB wallet transaction info. | Remains in primary if primary MWEB descriptors recognize it. |
| Partial MWEB wallet transaction | `tx` keyed by wallet transaction info hash, with MWEB wallet transaction info. | Remains in primary and keeps its MWEB metadata. |
| MWEB wallet coin | `coin` keyed by MWEB output id. | Remains in primary. |
| Locked transparent or MWEB output | `lockedutxo`. | Remains in primary. |
| MWEB sender-key counter | `mweb_sender_key_index`. | Remains in primary and continues to apply to descriptor MWEB keychains. |

## Migration Example

Given a legacy MWEB-capable HD wallet, private keys enabled, no inactive HD chains, no imports, and no extra scripts.

- Before migration: `1` `LegacyScriptPubKeyMan`.
- After migration: `12` total `DescriptorScriptPubKeyMan`s in `m_spk_managers`.

Active maps reference 9 of those 12:

- `m_external_spk_managers`: `5`
  - `LEGACY`
  - `P2SH_SEGWIT`
  - `BECH32`
  - `BECH32M`
  - `MWEB`

- `m_internal_spk_managers`: `4`
  - `LEGACY`
  - `P2SH_SEGWIT`
  - `BECH32`
  - `BECH32M`

Inactive/unreferenced by active maps: `3`

- standalone master seed `combo(...)`
- migrated legacy external `combo(master_xpub/0'/0'/*)`
- migrated legacy internal `combo(master_xpub/0'/1'/*)`

Important nuance: the active external `MWEB` SPKM is the migrated legacy MWEB descriptor, not a newly created one.

## Compatibility Notes

The migration does not introduce a wallet database version bump for MWEB key
metadata. Version 14 key metadata remains the format that can serialize the
optional MWEB subaddress index after the key-origin fields.

Legacy released MWEB subaddress metadata used the bare `x/i` keypath. Migration
preserves compatibility with that format and normalizes it into descriptor MWEB
state. Mixed keypaths such as `m/<path>/x/i` are not part of the released legacy
database format and should not be needed for migration.

The backup is the compatibility boundary for the old database. After successful
migration, the primary database should be treated as a descriptor wallet
database, not as a legacy wallet with descriptor records added on top.
