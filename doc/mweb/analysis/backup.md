# Wallet Backup and Import RPC Spec

This document specifies the behavior of wallet backup/export/import RPCs implemented in `src/wallet/rpc/backup.cpp` for this tree (including MWEB behavior where relevant).

The goal is reimplementation-level detail, not user-facing help text.

## Scope and Wallet-Type Matrix

`dumpwallet`, `dumpprivkey`, `importwallet`, `importprivkey`, `importpubkey`, `importaddress`, and `importmulti` are legacy-wallet RPCs in this codebase.

`importdescriptors` is descriptor-wallet-only.

`importprunedfunds` works with wallet ownership data and is not tied to dump-file format, but is included for completeness because it is an import RPC in this file.

## Shared Primitives

### `EncodeDumpString` / `DecodeDumpString`

`dumpwallet` label encoding:

- For each byte in label string:
- If byte is `<= 0x20`, `>= 0x80`, or `'%'`, encode as `%` + 2-digit hex.
- Else emit byte unchanged.

`importwallet` label decoding:

- Scan bytes left to right.
- If current byte is `'%'` and 2 more bytes exist, decode those 2 bytes as one byte and advance by 3 total bytes.
- Else copy byte as-is.

Important compatibility quirk:

- Decoder does not validate that escape chars are hex digits. It still deterministically converts any two chars after `%`.

### Rescan helper

`RescanWallet(wallet, reserver, time_begin=0, update=true)`:

- Calls `wallet.RescanFromTime(time_begin, reserver, update)`.
- Throws `"Rescan aborted by user."` if user abort flag is set.
- Throws `"Rescan was unable to fully rescan the blockchain. Some transactions may be missing."` if returned `scanned_time > time_begin`.

`TIMESTAMP_WINDOW` is 2 hours (from `chain.h`) and affects `RescanFromTime`.

### Destination expansion for a key

`GetAllDestinationsForKey(pubkey, scan_secret)` order:

1. P2PKH
2. P2SH-P2WPKH (compressed only)
3. P2WPKH (compressed only)
4. MWEB stealth address (compressed + non-null scan secret)

This order matters for dump formatting and label selection.

## `dumpprivkey`

### Input

- `address` string

### Preconditions

- Wallet must exist.
- Legacy script pubkey manager must exist (`Only legacy wallets are supported by this command` otherwise).
- Wallet must be unlocked.

### Algorithm

1. Decode destination.
2. If invalid destination: `Invalid Litecoin address`.
3. Resolve destination -> key id via `GetKeyForDestination`.
4. If no key id: `Address does not refer to a key`.
5. Fetch private key from legacy manager.
6. If missing: `Private key for address <address> is not known`.
7. Return WIF string via `EncodeSecret`.

### Output format

- A single WIF private key string.

## `dumpwallet`

### Input

- `filename` (server-side path)

### Preconditions

- Wallet exists.
- Legacy manager exists.
- Wallet synced to current chain tip (`BlockUntilSyncedToCurrentChain`).
- Wallet unlocked.
- Output path must not already exist.

### File path behavior

- Input is converted to absolute path and returned in result.
- Existing file is rejected (no overwrite).

### Data gathered before writing

- Key birth times: `wallet.GetKeyBirthTimes`.
- Tip block time/height/hash for header comments.
- Reserve key map: `spk_man.GetAllReserveKeys()`.
- Script set: `spk_man.GetCScripts()`.
- Key records sorted by `(birth_time, keyid)`.

### Dump file structure

In order:

1. Header comments:
   - `# Wallet dump created by <PACKAGE_NAME> <full_version>`
   - `# * Created on <ISO8601 now>`
   - `# * Best block at time of backup was <height> (<hash>),`
   - `#   mined on <ISO8601 block_time>`
2. Blank line
3. Optional HD master xprv comment:
   - `# extended private masterkey: <xprv>`
4. Per-key lines
5. Blank line
6. Per-script lines
7. Blank line
8. `# End of dump`

### Per-key line format

Format:

`<WIF> <ISO8601 birth> <type_token> # addr=<addr_field><optional_hdkeypath_suffix>`

Where:

- `<type_token>` is exactly one of:
  - `label=<encoded_label>`
  - `hdseed=1`
  - `reserve=1`
  - `inactivehdseed=1`
  - `change=1`
- `addr_field`:
  - If any destination for this key exists in address book: comma-joined encoded destinations that matched.
  - Else fallback to default address type destination.
- `optional_hdkeypath_suffix`:
  - Empty unless key metadata has `has_key_origin=true`.
  - Then exactly ` hdkeypath=<WriteHDKeypath(key_origin)>`.

Type token selection order:

1. If at least one address-book match: `label=<...>`
2. Else if key id == active hd seed id: `hdseed=1`
3. Else if in reserve key map: `reserve=1`
4. Else if metadata string keypath == `"s"`: `inactivehdseed=1`
5. Else: `change=1`

### Per-script line format

Format:

`<script_hex> <create_time_or_0> script=1 # addr=<p2sh(script)>`

Where:

- `create_time_or_0` is ISO8601 if script metadata exists, else literal `"0"`.

### Result object

- `{ "filename": "<absolute path>" }`

### What data is included

Included:

- Private keys known to legacy manager (including reserve/change/seed/inactive seed keys).
- Key birth times and key-origin `hdkeypath` comment (when available).
- Scripts in legacy script store (`GetCScripts`), including imported redeem/witness scripts and script-store entries learned through key/script import paths.
- Optional extended master xprv comment line.

Not included:

- Wallet transactions/UTXO set/order.
- Full address-book dataset (only indirectly reflected through key-line `label=` and `addr=` comment values).
- Descriptor-wallet descriptors.

## `importwallet`

### Input

- `filename` path to dump-like text file.

### Preconditions

- Wallet exists.
- Legacy manager exists.
- Wallet unlocked.
- Node must not be pruned (`Importing wallets is disabled when blocks are pruned`).
- No concurrent rescan.

### Parsing rules

For each line:

- Skip empty lines.
- Skip lines whose first char is `#`.
- Split by literal `' '` (space) into tokens.
- If token count `< 2`, skip.

Interpretation:

1. If token0 decodes as valid WIF private key:
   - Parse timestamp from token1 using `ParseISO8601DateTime` (invalid => `0`).
   - Parse tokens from index 2 until a token starting with `#`.
   - Flags:
     - `change=1` sets `has_label=false`.
     - `reserve=1` sets `has_label=false`.
     - `label=<...>` decodes with `DecodeDumpString`, sets `has_label=true`.
   - Store tuple `(key, time, has_label, label)`.
2. Else if token0 is hex:
   - Interpret token0 as raw script bytes.
   - Parse `birth_time = ParseISO8601DateTime(token1)` (invalid => `0`).
   - Store `(script, birth_time)`.
3. Else ignore line.

Compatibility quirks:

- `script=1` marker is not required by parser.
- `hdseed=1` / `inactivehdseed=1` tokens are currently ignored by active code.
- Any hex in first field becomes script input if WIF decode fails.

### Import phase

After parsing:

- If at least one key exists and wallet has private keys disabled: fail.

Then import all parsed entries:

Keys:

- `ImportPrivKeys({keyid:key}, time)`.
- If `has_label`, set address book label for `PKHash(keyid)` only.
- Update `nTimeBegin = min(nTimeBegin, time)`.

Scripts:

- `ImportScripts({script}, time)`.
- If `time > 0`, update `nTimeBegin = min(nTimeBegin, time)`.

If any import call returns false, remember failure; import continues.

### Rescan

- Always rescans after parse/import.
- `RescanWallet(..., nTimeBegin, update=false)`.
- Then `MarkDirty`.
- If any import call failed, throw `Error adding some keys/scripts to wallet`.

### Result

- `null` on success.

## `importprivkey`

### Input

- `privkey` (WIF)
- `label` (optional)
- `rescan` (default `true`)

### Preconditions

- Wallet exists.
- Legacy manager exists/creatable.
- Wallet must allow private keys.
- Wallet unlocked.
- If `rescan=true`: node must not be pruned and rescan reservation must succeed.

### Algorithm

1. Decode WIF key, validate.
2. Compute pubkey and keyid.
3. For each destination derived from pubkey:
   - If label argument provided, always set address-book label.
   - If no label argument, set label only for destinations not already in address book.
4. Import private key with timestamp `1` (forces full-chain birthday semantics).
5. If pubkey is compressed, import P2WPKH script with timestamp `0`.
6. If `rescan=true`, run full rescan (`time_begin=0`).

### Notes

- Returns `null`.
- Does not call `ResubmitWalletTransactions`.
- Label behavior preserves existing labels when label arg omitted.

## `importaddress`

### Input

- `address` (base58/bech32/mweb destination string OR hex script string)
- `label` (default empty)
- `rescan` (default `true`)
- `p2sh` (default `false`, only valid for hex-script input)

### Preconditions

- Wallet exists.
- Legacy manager exists/creatable.
- If `rescan=true`: pruned mode is rejected and rescan reservation required.

### Address-string branch

If `DecodeDestination(input)` is valid:

- If `p2sh=true`: error (`Cannot use the p2sh flag with an address - use a script instead`).
- If destination output type is BECH32M: error.
- Import scriptPubKey watch entry with:
  - `have_solving_data=false`
  - `apply_label=true`
  - `timestamp=1`

### Hex-script branch

If input is hex:

- Parse raw script bytes.
- Import raw script into script store with timestamp `0`.
- Build script set `{redeem_script}`.
- If `p2sh=true`, also add `scriptPubKey = HASH160(redeem_script)` script.
- Import scriptPubKeys with label, `have_solving_data=false`, `apply_label=true`, `timestamp=1`.

### Else

- Error: `Invalid Litecoin address or script`.

### Post-import

- If `rescan=true`: run rescan from time 0 and call `ResubmitWalletTransactions(false, true)`.
- Returns `null`.

## `importpubkey`

### Input

- `pubkey` hex
- `label` (default empty)
- `rescan` (default `true`)

### Preconditions

- Wallet exists.
- Legacy manager exists/creatable.
- If `rescan=true`: pruned mode rejected and rescan reservation required.

### Algorithm

1. Validate hex and pubkey.
2. Build destination set from key variants (legacy/segwit/mweb variants as applicable).
3. `MarkDirty`.
4. Import scriptPubKeys with:
   - `have_solving_data=true`
   - `apply_label=true`
   - `timestamp=1`
5. Import pubkey itself:
   - ordered id list with one key
   - no key origins
   - no keypool insertion
   - external purpose
   - timestamp `1`
6. If `rescan=true`, rescan from time 0 and resubmit wallet txs.

### Result

- `null`.

## `importmulti` (legacy wallets)

### High-level

Batch import of script/address or descriptor requests into a legacy wallet, with per-request success/error objects.

### Inputs

- `requests`: array of request objects.
- `options.rescan`: bool, default `true`.

Each request must include `timestamp` (number or `"now"`), and exactly one of:

- `scriptPubKey` (legacy mode: string script hex, or object `{ "address": "..." }`)
- `desc` (descriptor string with checksum)

Optional request fields include:

- `redeemscript`, `witnessscript`, `pubkeys`, `keys`, `range`, `internal`, `watchonly`, `label`, `keypool`.

### Preconditions

- Wallet exists.
- Legacy manager exists/creatable.
- Wallet unlocked.
- If `options.rescan=true`: rescan reservation required.
- RPC syncs wallet to current chain before processing (`BlockUntilSyncedToCurrentChain`).

### Timestamp handling

- `timestamp` required for every request.
- `"now"` resolves to current tip MTP.
- Import timestamp used for storage is clamped with `max(timestamp, 1)`.
- A pre-pass validates timestamps for all requests before importing any request.

### Per-request processing (`ProcessImport`)

Validation:

- `internal=true` forbids `label`.
- `keypool=true` allowed only when wallet private keys are disabled.
- Must provide exactly one of `scriptPubKey` or `desc`.
- If wallet has private keys disabled and request resolves to private keys => error.
- If wallet is already spendable for any target scriptPubKey/address => error.

Import order:

1. `ImportScripts(import_data.import_scripts, timestamp)`
2. `ImportPrivKeys(privkey_map, timestamp)`
3. `ImportPubKeys(ordered_pubkeys, pubkey_map, key_origins, add_keypool, purpose, timestamp)`
4. `ImportScriptPubKeys(label, script_pub_keys, have_solving_data, apply_label=!internal, timestamp)`

Result object:

- `{ "success": true }` on success
- or `{ "success": false, "error": <jsonrpc_error_obj> }`
- optional `"warnings": [...]`

### Legacy request mode (`scriptPubKey`)

Key rules:

- Address object path rejects invalid addresses and BECH32M addresses.
- Script-hex path rejects non-hex script strings.
- Nonstandard script import requires `internal=true`.
- `range` is forbidden in non-descriptor mode.

If solving data is provided (`redeemscript`, `witnessscript`, `pubkeys`, `keys`):

- Script structure is recursively checked.
- Missing required keys can demote import to non-solvable with warning.
- Irrelevant scripts/keys/pubkeys are warned and ignored.
- `watchonly` mismatch with inferred spendability produces warning.

### Descriptor request mode (`desc`)

Key rules:

- Descriptor checksum required.
- BECH32M descriptor output type rejected for legacy wallets.
- Ranged descriptors require `range`.
- Non-ranged descriptors must not provide `range`.
- `keys` can supplement private keys; irrelevant keys warned.
- Spendability warning is based on whether all derived pubkeys/origins have private keys.

### Batch rescan behavior

After imports:

- If rescanning enabled and at least one request succeeded, rescan from lowest request timestamp.
- On user abort: RPC throws abort error.
- On partial scan failure (`scannedTime > lowest`):
  - Existing per-request errors stay unchanged.
  - Requests with timestamp earlier than scanned range boundary are replaced with explicit rescan-failed per-request errors.

### Pruned behavior

- Unlike single-key import RPCs, no early hard fail for pruned mode.
- Partial rescan failures are surfaced as per-request errors.

## `importdescriptors` (descriptor wallets)

### High-level

Descriptor-wallet batch import with per-request result objects.

### Preconditions

- Wallet exists and must have descriptor flag.
- Wallet unlocked.
- Rescan reservation required.
- Wallet synced to current chain before processing.

### Request object rules

Required:

- `desc`
- `timestamp` (number or `"now"`)

Optional:

- `active`, `range`, `next_index`, `internal`, `label`

Validation highlights:

- Non-ranged desc cannot have `range`.
- Active desc must be ranged.
- Ranged desc with no range uses default keypool range and emits warning.
- `next_index` must be inside range.
- `label` forbidden with `internal=true`.
- `label` forbidden when explicit `range` is supplied.
- Active combo descriptor forbidden.
- If wallet has private keys enabled, descriptor must include private keys; otherwise error.
- If wallet has private keys disabled, descriptor containing private keys errors.

### Import effects

- Adds or updates wallet descriptor manager state.
- May activate/deactivate descriptor by output type + external/internal lane.
- Per-request response uses `{success, warnings?, error?}` shape.

### Rescan

- If at least one request succeeded, rescans from lowest imported timestamp (clamped to minimum 1).
- On partial scan failure, rewrites affected per-request results similarly to `importmulti`.

## `importprunedfunds`

### Purpose

Import a specific confirmed transaction into wallet without chain rescan, using merkle proof.

### Input

- `rawtransaction` hex
- `txoutproof` hex (merkle block)

### Algorithm

1. Decode tx and proof.
2. Verify merkle proof consistency.
3. Verify proof block is in active chain.
4. Verify txid appears in proof.
5. If tx has any wallet-owned outputs/scripts, add tx as confirmed wallet tx with proof block hash, height, and tx index.
6. Else fail with no-wallet-addresses match error.

### Result

- `null` on success.

## Backup/Reimport Data Matrix

For `dumpwallet`/`importwallet` text backups:

- Private keys: exported and reimported.
- Key timestamps: exported as ISO8601; imported via ISO8601 parser (`invalid -> 0`).
- Key labels: exported with percent-encoding; imported and applied only to `PKHash(keyid)`.
- Active seed marker (`hdseed=1`): exported marker only, not currently consumed in active import path.
- Inactive seed marker (`inactivehdseed=1`): exported marker only, not currently consumed in active import path.
- Reserve/change markers: exported; import uses them only for label/no-label decision.
- Script records: exported from script store and reimported as raw scripts.
- Transactions/UTXOs: not in file; recovered by rescan.

## Reimplementation Checklist

If strict compatibility is required, preserve these behaviors:

1. Do not allow `dumpwallet` overwrite; return absolute output path.
2. Keep exact dump record ordering: keys sorted by `(birth_time, keyid)`.
3. Preserve label percent codec semantics (including non-valid `%xx` decode behavior).
4. Parse dump lines with space-splitting and len>=2 rule.
5. In `importwallet`, treat first-token-hex as script record when WIF decode fails.
6. Apply imported key labels only to `PKHash(keyid)` in `importwallet`.
7. Keep `timestamp` handling (`max(ts,1)` for `importmulti`/`importdescriptors` import time).
8. Keep per-request result shape and warning/error strings for `importmulti`/`importdescriptors`.
9. Keep pruned-mode behavior differences:
   - single import RPCs may hard-fail when `rescan=true`
   - `importmulti` handles rescan failures per-request.

