# Descriptor Wallets

### New Address Generation

#### Call Path

* getnewaddress/GUI calls CWallet::GetNewDestination in src/wallet/wallet.cpp (line 2731), which picks the active ScriptPubKeyMan for the requested OutputType via GetScriptPubKeyMan(type, false).
* It immediately calls spk_man->TopUp() so the descriptor keypool/cache is filled, then calls spk_man->GetNewDestination(type) and, on success, stores the label in the address book (wallet.cpp (lines 2731-2744)).
* For descriptor wallets the SPKM is a DescriptorScriptPubKeyMan registered when the descriptor was added (src/wallet/wallet.cpp (line 3950)), which also performed an initial TopUp().

#### Descriptor SPKM internals

* DescriptorScriptPubKeyMan::GetNewDestination (src/wallet/scriptpubkeyman.cpp (line 2285)) first ensures it can dispense addresses (CanGetAddresses requires a single-type, ranged descriptor and either private keys or remaining pre-cached range; scriptpubkeyman.cpp (line 2655)).
* It locks cs_desc_man, verifies the requested OutputType matches the descriptor, calls TopUp() again to ensure the cache is ahead, then derives the next script at m_wallet_descriptor.next_index using ExpandFromCache (falls back to Expand if needed). Failure to extend the cache yields a “keypool ran out” error.
* The derived GenericAddress is converted to a CTxDestination; next_index is incremented and the descriptor state (including next_index) is persisted via WalletBatch::WriteDescriptor (scriptpubkeyman.cpp (lines 2305-2316)).
* The keypool fill happens in DescriptorScriptPubKeyMan::TopUp (src/wallet/scriptpubkeyman.cpp (line 2424)): it picks a target size (-keypool default), extends range_end, and for each new index derives addresses/pubs via descriptor->ExpandFromCache or Expand, populates m_map_addresses/m_map_pubkeys, writes new cache items to the DB, updates m_max_cached_index, then saves the updated WalletDescriptor.
* When a keypool entry is observed used, MarkUnusedAddresses advances next_index past it and triggers another TopUp to keep the pool ahead (scriptpubkeyman.cpp (line 2483)).


#### State that drives this

* The descriptor metadata (WalletDescriptor) tracks range_start, range_end, next_index, and the cached expansion data (src/wallet/walletutil.h (lines 75-110)). TopUp grows the cache/range; GetNewDestination just hands out the next cached slot and advances next_index.


### SetupDescriptorScriptPubKeyMans

#### Consumers

1. CreateWallet (wallet.cpp): when createwallet/GUI creation requests encryption (non-empty passphrase, descriptors wallet, not create_blank), the wallet is unlocked right after encrypting and immediately seeds descriptors via SetupDescriptorScriptPubKeyMans().
2. LoadWalletInternal (wallet.cpp): on first load (fFirstRun branch) of a brand-new wallet (no SPK managers yet, not blank, privkeys allowed). If the wallet is flagged as descriptors (or external signer with privkeys enabled), it initializes descriptor managers and keypool by calling SetupDescriptorScriptPubKeyMans(). Triggered by loadwallet RPC/startup auto-load and also by the creation path when the new wallet is first loaded.
3. ApplyMigrationData (wallet.cpp): during migratewallet/descriptor migration after the legacy SPKM is removed, if privkeys are enabled it seeds descriptor SPK managers—using the migrated master key when available via the SetupDescriptorScriptPubKeyMans(const CExtKey&) overload, otherwise generating a new seed with the no-arg overload.
4. WalletCreate (wallettool.cpp): the litecoin-wallet create CLI path. After setting min version/flags, if the new wallet is descriptors it calls SetupDescriptorScriptPubKeyMans() before topping up the keypool.
