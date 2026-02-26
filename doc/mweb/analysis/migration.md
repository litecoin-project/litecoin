# Wallet Migration

Workflow:
`migratewallet` RPC => `MigrateLegacyToDescriptor` => `DoMigration` => `LegacyScriptPubKeyMan::MigrateToDescriptor` and `CWallet::ApplyMigrationData`

## Functions

### wallet.cpp

1. `MigrateLegacyToDescriptor` - Backup & Unload wallet, migrate to sqlite, call `DoMigration` and then load on success (or cleanup on failure)

```cpp
util::Result<MigrationResult> MigrateLegacyToDescriptor(std::shared_ptr<CWallet>&& wallet, WalletContext& context)
{
    MigrationResult res;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // Make a backup of the DB
    std::string wallet_name = wallet->GetName();
    fs::path this_wallet_dir = fs::absolute(fs::PathFromString(wallet->GetDatabase().Filename())).parent_path();
    fs::path backup_filename = fs::PathFromString(strprintf("%s-%d.legacy.bak", wallet_name, GetTime()));
    fs::path backup_path = this_wallet_dir / backup_filename;
    if (!wallet->BackupWallet(fs::PathToString(backup_path))) {
        return util::Error{_("Error: Unable to make a backup of your wallet")};
    }
    res.backup_path = backup_path;

    // Unload the wallet so that nothing else tries to use it while we're changing it
    if (!RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt, warnings)) {
        return util::Error{_("Unable to unload the wallet before migrating")};
    }
    UnloadWallet(std::move(wallet));

    // Load the wallet but only in the context of this function.
    // No signals should be connected nor should anything else be aware of this wallet
    WalletContext empty_context;
    empty_context.args = context.args;
    DatabaseOptions options;
    options.require_existing = true;
    DatabaseStatus status;
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
    if (!database) {
        return util::Error{Untranslated("Wallet file verification failed.") + Untranslated(" ") + error};
    }

    std::shared_ptr<CWallet> local_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, error, warnings);
    if (!local_wallet) {
        return util::Error{Untranslated("Wallet loading failed.") + Untranslated(" ") + error};
    }

    bool success = false;
    {
        LOCK(local_wallet->cs_wallet);

        // First change to using SQLite
        if (!local_wallet->MigrateToSQLite(error)) return util::Error{error};

        // Do the migration, and cleanup if it fails
        success = DoMigration(*local_wallet, context, error, res);
    }

    if (success) {
        // Migration successful, unload the wallet locally, then reload it.
        assert(local_wallet.use_count() == 1);
        local_wallet.reset();
        LoadWallet(context, wallet_name, /*load_on_start=*/std::nullopt, options, status, error, warnings);
        res.wallet_name = wallet_name;
    } else {
        // Migration failed, cleanup
        // Copy the backup to the actual wallet dir
        fs::path temp_backup_location = fsbridge::AbsPathJoin(GetWalletDir(), backup_filename);
        fs::copy_file(backup_path, temp_backup_location, fs::copy_options::none);

        // Remember this wallet's walletdir to remove after unloading
        std::vector<fs::path> wallet_dirs;
        wallet_dirs.push_back(fs::PathFromString(local_wallet->GetDatabase().Filename()).parent_path());

        // Unload the wallet locally
        assert(local_wallet.use_count() == 1);
        local_wallet.reset();

        // Make list of wallets to cleanup
        std::vector<std::shared_ptr<CWallet>> created_wallets;
        if (res.watchonly_wallet) created_wallets.push_back(std::move(res.watchonly_wallet));
        if (res.solvables_wallet) created_wallets.push_back(std::move(res.solvables_wallet));

        // Get the directories to remove after unloading
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            wallet_dirs.push_back(fs::PathFromString(w->GetDatabase().Filename()).parent_path());
        }

        // Unload the wallets
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            if (!RemoveWallet(context, w, /*load_on_start=*/false)) {
                error += _("\nUnable to cleanup failed migration");
                return util::Error{error};
            }
            UnloadWallet(std::move(w));
        }

        // Delete the wallet directories
        for (fs::path& dir : wallet_dirs) {
            fs::remove_all(dir);
        }

        // Restore the backup
        DatabaseStatus status;
        std::vector<bilingual_str> warnings;
        if (!RestoreWallet(context, temp_backup_location, wallet_name, /*load_on_start=*/std::nullopt, status, error, warnings)) {
            error += _("\nUnable to restore backup of wallet.");
            return util::Error{error};
        }

        // Move the backup to the wallet dir
        fs::copy_file(temp_backup_location, backup_path, fs::copy_options::none);
        fs::remove(temp_backup_location);

        return util::Error{error};
    }
    return res;
}
```

2. `DoMigration` - Calls `CWallet::GetDescriptorsForLegacy` to retrieve the `MigrationData`, creates the watchonly and/or solvable wallets (if applicable), and calls `CWallet::ApplyMigrationData`

```cpp
bool DoMigration(CWallet& wallet, WalletContext& context, bilingual_str& error, MigrationResult& res) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    // Get all of the descriptors from the legacy wallet
    std::optional<MigrationData> data = wallet.GetDescriptorsForLegacy(error);
    if (data == std::nullopt) return false;

    // Create the watchonly and solvable wallets if necessary
    if (data->watch_descs.size() > 0 || data->solvable_descs.size() > 0) {
        DatabaseOptions options;
        options.require_existing = false;
        options.require_create = true;

        // Make the wallets
        options.create_flags = WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET | WALLET_FLAG_DESCRIPTORS;
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            options.create_flags |= WALLET_FLAG_AVOID_REUSE;
        }
        if (wallet.IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
            options.create_flags |= WALLET_FLAG_KEY_ORIGIN_METADATA;
        }
        if (data->watch_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the watched scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = wallet.GetName() + "_watchonly";
            data->watchonly_wallet = CreateWallet(context, wallet_name, std::nullopt, options, status, error, warnings);
            if (status != DatabaseStatus::SUCCESS) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.watchonly_wallet = data->watchonly_wallet;
            LOCK(data->watchonly_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->watch_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(desc); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor
                assert(!desc->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
                data->watchonly_wallet->AddWalletDescriptor(w_desc, keys, "", false);
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
        if (data->solvable_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the unwatched solvable scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = wallet.GetName() + "_solvables";
            data->solvable_wallet = CreateWallet(context, wallet_name, std::nullopt, options, status, error, warnings);
            if (status != DatabaseStatus::SUCCESS) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.solvables_wallet = data->solvable_wallet;
            LOCK(data->solvable_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->solvable_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(desc); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor
                assert(!desc->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
                data->solvable_wallet->AddWalletDescriptor(w_desc, keys, "", false);
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
    }

    // Add the descriptors to wallet, remove LegacyScriptPubKeyMan, and cleanup txs and address book data
    if (!wallet.ApplyMigrationData(*data, error)) {
        return false;
    }
    return true;
}
```

3. `CWallet::GetDescriptorsForLegacy` - Simple wrapper around `LegacyScriptPubKeyMan::MigrateToDescriptor`

```cpp
std::optional<MigrationData> CWallet::GetDescriptorsForLegacy(bilingual_str& error) const
{
    AssertLockHeld(cs_wallet);

    LegacyScriptPubKeyMan* legacy_spkm = GetLegacyScriptPubKeyMan();
    if (!legacy_spkm) {
        error = _("Error: This wallet is already a descriptor wallet");
        return std::nullopt;
    }

    std::optional<MigrationData> res = legacy_spkm->MigrateToDescriptor();
    if (res == std::nullopt) {
        error = _("Error: Unable to produce descriptors for this legacy wallet. Make sure the wallet is unlocked first");
        return std::nullopt;
    }
    return res;
}
```

4. `CWallet::ApplyMigrationData` - Removes all legacy record types from DB, calls `SetupDescriptorScriptPubKeyMans`, and moves any watchonly txs and addresses to the watch-only wallet

```cpp
bool CWallet::ApplyMigrationData(MigrationData& data, bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    LegacyScriptPubKeyMan* legacy_spkm = GetLegacyScriptPubKeyMan();
    if (!legacy_spkm) {
        error = _("Error: This wallet is already a descriptor wallet");
        return false;
    }

    for (auto& desc_spkm : data.desc_spkms) {
        if (m_spk_managers.count(desc_spkm->GetID()) > 0) {
            error = _("Error: Duplicate descriptors created during migration. Your wallet may be corrupted.");
            return false;
        }
        m_spk_managers[desc_spkm->GetID()] = std::move(desc_spkm);
    }

    // Remove the LegacyScriptPubKeyMan from disk
    if (!legacy_spkm->DeleteRecords()) {
        return false;
    }

    // Remove the LegacyScriptPubKeyMan from memory
    m_spk_managers.erase(legacy_spkm->GetID());
    m_external_spk_managers.clear();
    m_internal_spk_managers.clear();

    // Setup new descriptors
    SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    if (!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        // Use the existing master key if we have it
        if (data.master_key.key.IsValid()) {
            SetupDescriptorScriptPubKeyMans(data.master_key);
        } else {
            // Setup with a new seed if we don't.
            SetupDescriptorScriptPubKeyMans();
        }
    }

    // Check if the transactions in the wallet are still ours. Either they belong here, or they belong in the watchonly wallet.
    // We need to go through these in the tx insertion order so that lookups to spends works.
    std::vector<uint256> txids_to_delete;
    for (const auto& [_pos, wtx] : wtxOrdered) {
        if (!IsMine(*wtx->tx, wtx->mweb_wtx_info) && !IsFromMe(*wtx->tx, wtx->mweb_wtx_info)) {
            // Check it is the watchonly wallet's
            // solvable_wallet doesn't need to be checked because transactions for those scripts weren't being watched for
            if (data.watchonly_wallet) {
                LOCK(data.watchonly_wallet->cs_wallet);
                if (data.watchonly_wallet->IsMine(*wtx->tx, wtx->mweb_wtx_info) || data.watchonly_wallet->IsFromMe(*wtx->tx, wtx->mweb_wtx_info)) {
                    // Add to watchonly wallet
                    if (!data.watchonly_wallet->AddToWallet(wtx->tx, wtx->mweb_wtx_info, wtx->m_state)) {
                        error = _("Error: Could not add watchonly tx to watchonly wallet");
                        return false;
                    }
                    // Mark as to remove from this wallet
                    txids_to_delete.push_back(wtx->GetHash());
                    continue;
                }
            }
            // Both not ours and not in the watchonly wallet
            error = strprintf(_("Error: Transaction %s in wallet cannot be identified to belong to migrated wallets"), wtx->GetHash().GetHex());
            return false;
        }
    }
    // Do the removes
    if (txids_to_delete.size() > 0) {
        std::vector<uint256> deleted_txids;
        if (ZapSelectTx(txids_to_delete, deleted_txids) != DBErrors::LOAD_OK) {
            error = _("Error: Could not delete watchonly transactions");
            return false;
        }
        if (deleted_txids != txids_to_delete) {
            error = _("Error: Not all watchonly txs could be deleted");
            return false;
        }
        // Tell the GUI of each tx
        for (const uint256& txid : deleted_txids) {
            NotifyTransactionChanged(txid, CT_UPDATED);
        }
    }

    // Check the address book data in the same way we did for transactions
    std::vector<CTxDestination> dests_to_delete;
    for (const auto& addr_pair : m_address_book) {
        // Labels applied to receiving addresses should go based on IsMine
        if (addr_pair.second.purpose == "receive") {
            if (!IsMine(addr_pair.first)) {
                // Check the address book data is the watchonly wallet's
                if (data.watchonly_wallet) {
                    LOCK(data.watchonly_wallet->cs_wallet);
                    if (data.watchonly_wallet->IsMine(addr_pair.first)) {
                        // Add to the watchonly. Preserve the labels, purpose, and change-ness
                        std::string label = addr_pair.second.GetLabel();
                        std::string purpose = addr_pair.second.purpose;
                        if (!purpose.empty()) {
                            data.watchonly_wallet->m_address_book[addr_pair.first].purpose = purpose;
                        }
                        if (!addr_pair.second.IsChange()) {
                            data.watchonly_wallet->m_address_book[addr_pair.first].SetLabel(label);
                        }
                        dests_to_delete.push_back(addr_pair.first);
                        continue;
                    }
                }
                if (data.solvable_wallet) {
                    LOCK(data.solvable_wallet->cs_wallet);
                    if (data.solvable_wallet->IsMine(addr_pair.first)) {
                        // Add to the solvable. Preserve the labels, purpose, and change-ness
                        std::string label = addr_pair.second.GetLabel();
                        std::string purpose = addr_pair.second.purpose;
                        if (!purpose.empty()) {
                            data.solvable_wallet->m_address_book[addr_pair.first].purpose = purpose;
                        }
                        if (!addr_pair.second.IsChange()) {
                            data.solvable_wallet->m_address_book[addr_pair.first].SetLabel(label);
                        }
                        dests_to_delete.push_back(addr_pair.first);
                        continue;
                    }
                }
                // Not ours, not in watchonly wallet, and not in solvable
                error = _("Error: Address book data in wallet cannot be identified to belong to migrated wallets");
                return false;
            }
        } else {
            // Labels for everything else (send) should be cloned to all
            if (data.watchonly_wallet) {
                LOCK(data.watchonly_wallet->cs_wallet);
                // Add to the watchonly. Preserve the labels, purpose, and change-ness
                std::string label = addr_pair.second.GetLabel();
                std::string purpose = addr_pair.second.purpose;
                if (!purpose.empty()) {
                    data.watchonly_wallet->m_address_book[addr_pair.first].purpose = purpose;
                }
                if (!addr_pair.second.IsChange()) {
                    data.watchonly_wallet->m_address_book[addr_pair.first].SetLabel(label);
                }
                continue;
            }
            if (data.solvable_wallet) {
                LOCK(data.solvable_wallet->cs_wallet);
                // Add to the solvable. Preserve the labels, purpose, and change-ness
                std::string label = addr_pair.second.GetLabel();
                std::string purpose = addr_pair.second.purpose;
                if (!purpose.empty()) {
                    data.solvable_wallet->m_address_book[addr_pair.first].purpose = purpose;
                }
                if (!addr_pair.second.IsChange()) {
                    data.solvable_wallet->m_address_book[addr_pair.first].SetLabel(label);
                }
                continue;
            }
        }
    }
    // Remove the things to delete
    if (dests_to_delete.size() > 0) {
        for (const auto& dest : dests_to_delete) {
            if (!DelAddressBook(dest)) {
                error = _("Error: Unable to remove watchonly address book data");
                return false;
            }
        }
    }

    // Connect the SPKM signals
    ConnectScriptPubKeyManNotifiers();
    NotifyCanGetAddressesChanged();

    WalletLogPrintf("Wallet migration complete.\n");

    return true;
}
```

### scriptpubkeyman.cpp

1. `LegacyScriptPubKeyMan::MigrateToDescriptor` - Build `MigrationData` containing `master_key`, `watch_descs`, `solvable_descs`, and `desc_spkms` (the actual `DescriptorScriptPubKeyMan`s)

```cpp
std::optional<MigrationData> LegacyScriptPubKeyMan::MigrateToDescriptor()
{
    LOCK(cs_KeyStore);
    if (m_storage.IsLocked()) {
        return std::nullopt;
    }

    MigrationData out;

    std::unordered_set<GenericAddress, SaltedGenericAddressHasher> spks{GetScriptPubKeys()};

    // Get all key ids
    std::set<CKeyID> keyids;
    for (const auto& key_pair : mapKeys) {
        keyids.insert(key_pair.first);
    }
    for (const auto& key_pair : mapCryptedKeys) {
        keyids.insert(key_pair.first);
    }

    LogPrintf("keyids.size() == %u, spks.size() == %u\n", keyids.size(), spks.size());

    // Get key metadata and figure out which keys don't have a seed
    // Note that we do not ignore the seeds themselves because they are considered IsMine!
    for (auto keyid_it = keyids.begin(); keyid_it != keyids.end();) {
        const CKeyID& keyid = *keyid_it;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            const CKeyMetadata& meta = it->second;
            if (meta.hdKeypath == "s" || meta.hdKeypath == "m") {
                keyid_it++;
                continue;
            }
            if (m_hd_chain.seed_id == meta.hd_seed_id || m_inactive_hd_chains.count(meta.hd_seed_id) > 0) {
                keyid_it = keyids.erase(keyid_it);
                continue;
            }
        }
        keyid_it++;
    }

    // keyids is now all non-HD keys. Each key will have its own combo descriptor
    for (const CKeyID& keyid : keyids) {
        CKey key;
        if (!GetKey(keyid, key)) {
            assert(false);
        }

        // Get birthdate from key meta
        uint64_t creation_time = 0;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // Get the key origin
        // Maybe this doesn't matter because floating keys here shouldn't have origins
        KeyOriginInfo info;
        bool has_info = GetKeyOrigin(keyid, info);
        std::string origin_str = has_info ? "[" + HexStr(info.fingerprint) + FormatHDKeypath(info.hdkeypath) + "]" : "";

        // Construct the combo descriptor
        std::string desc_str = "combo(" + origin_str + HexStr(key.GetPubKey()) + ")";
        FlatSigningProvider keys;
        std::string error;
        std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
        WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);

        // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
        auto desc_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(m_storage, w_desc));
        desc_spk_man->AddDescriptorKey(key, key.GetPubKey());
        desc_spk_man->TopUp();
        auto desc_spks = desc_spk_man->GetScriptPubKeys();

        // Remove the scriptPubKeys from our current set
        for (const GenericAddress& spk : desc_spks) {
            size_t erased = spks.erase(spk);
            assert(erased == 1);
            assert(IsMine(spk) == ISMINE_SPENDABLE);
        }

        out.desc_spkms.push_back(std::move(desc_spk_man));
    }

    // Handle HD keys by using the CHDChains
    std::vector<CHDChain> chains;
    chains.push_back(m_hd_chain);
    for (const auto& chain_pair : m_inactive_hd_chains) {
        chains.push_back(chain_pair.second);
    }
    LogPrintf("DEBUG: Chains=%u\n", chains.size());
    for (const CHDChain& chain : chains) {
        LogPrintf("DEBUG: Chain counters - %u external, %u internal, %u MWEB\n", chain.nExternalChainCounter, chain.nInternalChainCounter, chain.nMWEBIndexCounter);
        if (chain.seed_id.IsNull()) {
            LogPrintf("DEBUG: Chain has null seed_id, skipping\n");
            continue;
        }

        // Get the master xprv
        CKey seed_key;
        if (!GetKey(chain.seed_id, seed_key)) {
            assert(false);
        }
        CExtKey master_key;
        master_key.SetSeed(seed_key);

        for (const KeyPurpose purpose : std::vector<KeyPurpose>{ KeyPurpose::EXTERNAL, KeyPurpose::INTERNAL, KeyPurpose::MWEB }) {
            // Skip if doing internal chain and split chain is not supported
            if (purpose == KeyPurpose::INTERNAL && !m_storage.CanSupportFeature(FEATURE_HD_SPLIT)) {
                continue;
            }

            // Make the combo descriptor
            std::string xprv = EncodeExtKey(master_key);
            std::string xpub = EncodeExtPubKey(master_key.Neuter());
            std::string desc_str;
            if (purpose == KeyPurpose::MWEB) {
                desc_str = "mweb(" + xprv + "/0'/100'/0'," + xpub + "/0'/100'/1')";
            } else {
                desc_str = "combo(" + xpub + "/0'/" + ToString((uint32_t)purpose) + "'/*')";
            }
            FlatSigningProvider keys;
            std::string error;
            std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, error, false);
            uint32_t chain_counter = std::max(GetChainCounter(chain, purpose), (uint32_t)0);
            WalletDescriptor w_desc(std::move(desc), 0, 0, chain_counter, 0);

            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            auto desc_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(m_storage, w_desc));

            LogPrintf("DEBUG: Adding descriptor key for purpose=%u\n", (uint32_t)purpose);
            desc_spk_man->AddDescriptorKey(master_key.key, master_key.key.GetPubKey());
            LogPrintf("DEBUG: Topping up descriptor for purpose=%u\n", (uint32_t)purpose);
            desc_spk_man->TopUp();
            LogPrintf("DEBUG: Getting script pub keys for purpose=%u\n", (uint32_t)purpose);
            auto desc_spks = desc_spk_man->GetScriptPubKeys();
            LogPrintf("DEBUG: Received %u spks for purpose=%u\n", desc_spks.size(), (uint32_t)purpose);

            // Remove the scriptPubKeys from our current set
            for (const GenericAddress& spk : desc_spks) {
                size_t erased = spks.erase(spk);
                if (purpose != KeyPurpose::MWEB) {
                    assert(erased == 1);
                    assert(IsMine(spk) == ISMINE_SPENDABLE);
                } else {
                    LogPrintf("DEBUG: Address not found in spks: %s\n", spk.Encode());
                }
            }

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // MW: TODO - Add MWEB key migration
        // I'm not sure the best way to handle this yet. We don't want to end up with multiple MWEB descriptors.
        // We also can't just ignore the MWEB keys here, and wait for SetupDescriptorGeneration to create it,
        // because we'll end up losing track of our nMWEBIndexCounter value.
        // Probably, we should just create the MWEB descriptor here, and then check for an existing MWEB
        // descriptor in SetupDescriptorGeneration and just use that one if it exists.


    }
    // Add the current master seed to the migration data
    if (!m_hd_chain.seed_id.IsNull()) {
        CKey seed_key;
        if (!GetKey(m_hd_chain.seed_id, seed_key)) {
            assert(false);
        }
        out.master_key.SetSeed(seed_key);
    }

    LogPrintf("DEBUG: Keys remaining in spks: %u\n", spks.size());

    // Handle the rest of the scriptPubKeys which must be imports and may not have all info
    for (auto it = spks.begin(); it != spks.end();) {
        const GenericAddress& spk = *it;
        LogPrintf("DEBUG: SPK: %s, %s\n", spk.Encode(), CScriptID(spk.GetScript()).ToString());

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& mit = m_script_metadata.find(CScriptID(spk.GetScript()));
        if (mit != m_script_metadata.end()) {
            LogPrintf("DEBUG: origin=%s\n", FormatHDKeypath(mit->second.key_origin.hdkeypath));
            if (mit->second.key_origin.hdkeypath.mweb_index.has_value()) {
                LogPrintf("DEBUG: Erasing MWEB key\n");
                it = spks.erase(it);
                continue;
            }

            creation_time = mit->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(spk, *GetSolvingProvider(spk));
        LogPrintf("DEBUG: Descriptor=%s, address=%s\n", desc->ToString(), spk.Encode());
        // Get the private keys for this descriptor
        std::vector<GenericAddress> scripts;
        FlatSigningProvider keys;
        if (!desc->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, keys)) {
            assert(false);
        }
        std::set<CKeyID> privkeyids;
        for (const auto& key_orig_pair : keys.origins) {
            privkeyids.insert(key_orig_pair.first);
        }

        std::vector<GenericAddress> desc_spks;

        // Make the descriptor string with private keys
        std::string desc_str;
        bool watchonly = !desc->ToPrivateString(*this, desc_str);
        if (watchonly && !m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            out.watch_descs.push_back({desc->ToString(), creation_time});

            // Get the scriptPubKeys without writing this to the wallet
            FlatSigningProvider provider;
            desc->Expand(0, provider, desc_spks, provider);
        } else {
            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
            auto desc_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(m_storage, w_desc));
            for (const auto& keyid : privkeyids) {
                CKey key;
                if (!GetKey(keyid, key)) {
                    continue;
                }
                desc_spk_man->AddDescriptorKey(key, key.GetPubKey());
            }
            desc_spk_man->TopUp();
            auto desc_spks_set = desc_spk_man->GetScriptPubKeys();
            desc_spks.insert(desc_spks.end(), desc_spks_set.begin(), desc_spks_set.end());

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // Remove the scriptPubKeys from our current set
        for (const GenericAddress& desc_spk : desc_spks) {
            auto del_it = spks.find(desc_spk);
            assert(del_it != spks.end());
            assert(IsMine(desc_spk) != ISMINE_NO);
            it = spks.erase(del_it);
        }
    }

    // Multisigs are special. They don't show up as ISMINE_SPENDABLE unless they are in a P2SH
    // So we have to check if any of our scripts are a multisig and if so, add the P2SH
    for (const auto& script_pair : mapScripts) {
        const CScript script = script_pair.second;

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& it = m_script_metadata.find(CScriptID(script));
        if (it != m_script_metadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        std::vector<std::vector<unsigned char>> sols;
        TxoutType type = Solver(script, sols);
        if (type == TxoutType::MULTISIG) {
            CScript sh_spk = GetScriptForDestination(ScriptHash(script));
            CTxDestination witdest = WitnessV0ScriptHash(script);
            CScript witprog = GetScriptForDestination(witdest);
            CScript sh_wsh_spk = GetScriptForDestination(ScriptHash(witprog));

            // We only want the multisigs that we have not already seen, i.e. they are not watchonly and not spendable
            // For P2SH, a multisig is not ISMINE_NO when:
            // * All keys are in the wallet
            // * The multisig itself is watch only
            // * The P2SH is watch only
            // For P2SH-P2WSH, if the script is in the wallet, then it will have the same conditions as P2SH.
            // For P2WSH, a multisig is not ISMINE_NO when, other than the P2SH conditions:
            // * The P2WSH script is in the wallet and it is being watched
            std::vector<std::vector<unsigned char>> keys(sols.begin() + 1, sols.begin() + sols.size() - 1);
            if (HaveWatchOnly(sh_spk) || HaveWatchOnly(script) || HaveKeys(keys, *this) || (HaveCScript(CScriptID(witprog)) && HaveWatchOnly(witprog))) {
                // The above emulates IsMine for these 3 scriptPubKeys, so double check that by running IsMine
                assert(IsMine(sh_spk) != ISMINE_NO || IsMine(witprog) != ISMINE_NO || IsMine(sh_wsh_spk) != ISMINE_NO);
                continue;
            }
            assert(IsMine(sh_spk) == ISMINE_NO && IsMine(witprog) == ISMINE_NO && IsMine(sh_wsh_spk) == ISMINE_NO);

            std::unique_ptr<Descriptor> sh_desc = InferDescriptor(sh_spk, *GetSolvingProvider(sh_spk));
            out.solvable_descs.push_back({sh_desc->ToString(), creation_time});

            const auto desc = InferDescriptor(witprog, *this);
            if (desc->IsSolvable()) {
                std::unique_ptr<Descriptor> wsh_desc = InferDescriptor(witprog, *GetSolvingProvider(witprog));
                out.solvable_descs.push_back({wsh_desc->ToString(), creation_time});
                std::unique_ptr<Descriptor> sh_wsh_desc = InferDescriptor(sh_wsh_spk, *GetSolvingProvider(sh_wsh_spk));
                out.solvable_descs.push_back({sh_wsh_desc->ToString(), creation_time});
            }
        }
    }

    // Make sure that we have accounted for all scriptPubKeys
    assert(spks.size() == 0);
    return out;
}
```

2. `LegacyScriptPubKeyMan::GetScriptPubKeys`

```cpp
const std::unordered_set<GenericAddress, SaltedGenericAddressHasher> LegacyScriptPubKeyMan::GetScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<GenericAddress, SaltedGenericAddressHasher> spks;
    std::set<CScriptID> scriptsToIgnore;

    // All keys have at least P2PK and P2PKH
    for (const auto& key_pair : mapKeys) {
        const CPubKey& pub = key_pair.second.GetPubKey();

        auto metadata = mapKeyMetadata.find(key_pair.first);
        if (metadata != mapKeyMetadata.end()) {
            if (metadata->second.key_origin.hdkeypath.mweb_index.has_value()) {
                scriptsToIgnore.insert(CScriptID(GetScriptForDestination(WitnessV0KeyHash(key_pair.first))));
                SecretKey master_scan_secret = GetScanSecret();
                if (!master_scan_secret.IsNull()) {
                    PublicKey spend_pubkey = PublicKey(pub.begin());
                    StealthAddress mweb_address(spend_pubkey.Mul(master_scan_secret), spend_pubkey);
                    spks.insert(mweb_address);
                }

                continue;
            }
        }

        spks.insert(GetScriptForRawPubKey(pub));
        spks.insert(GetScriptForDestination(PKHash(pub)));
    }
    for (const auto& key_pair : mapCryptedKeys) {
        const CPubKey& pub = key_pair.second.first;

        auto metadata = mapKeyMetadata.find(key_pair.first);
        if (metadata != mapKeyMetadata.end()) {
            if (metadata->second.key_origin.hdkeypath.mweb_index.has_value()) {
                scriptsToIgnore.insert(CScriptID(GetScriptForDestination(WitnessV0KeyHash(key_pair.first))));

                SecretKey master_scan_secret = GetScanSecret();
                if (!master_scan_secret.IsNull()) {
                    PublicKey spend_pubkey = PublicKey(pub.begin());
                    StealthAddress mweb_address(spend_pubkey.Mul(master_scan_secret), spend_pubkey);
                    spks.insert(mweb_address);
                }
                continue;
            }
        }

        spks.insert(GetScriptForRawPubKey(pub));
        spks.insert(GetScriptForDestination(PKHash(pub)));
    }

    // For every script in mapScript, only the ISMINE_SPENDABLE ones are being tracked.
    // The watchonly ones will be in setWatchOnly which we deal with later
    // For all keys, if they have segwit scripts, those scripts will end up in mapScripts
    for (const auto& script_pair : mapScripts) {
        if (scriptsToIgnore.count(script_pair.first) != 0) {
            LogPrintf("DEBUG: Ignoring MWEB script_id\n");
            continue;
        }
        const CScript& script = script_pair.second;
        if (IsMine(script) == ISMINE_SPENDABLE) {
            // Add ScriptHash for scripts that are not already P2SH
            if (!script.IsPayToScriptHash()) {
                spks.insert(GetScriptForDestination(ScriptHash(script)));
            }
            // For segwit scripts, we only consider them spendable if we have the segwit spk
            int wit_ver = -1;
            std::vector<unsigned char> witprog;
            if (script.IsWitnessProgram(wit_ver, witprog) && wit_ver == 0) {
                spks.insert(script);
            }
        } else {
            // Multisigs are special. They don't show up as ISMINE_SPENDABLE unless they are in a P2SH
            // So check the P2SH of a multisig to see if we should insert it
            std::vector<std::vector<unsigned char>> sols;
            TxoutType type = Solver(script, sols);
            if (type == TxoutType::MULTISIG) {
                CScript ms_spk = GetScriptForDestination(ScriptHash(script));
                if (IsMine(ms_spk) != ISMINE_NO) {
                    spks.insert(ms_spk);
                }
            }
        }
    }

    // All watchonly scripts are raw
    spks.insert(setWatchOnly.begin(), setWatchOnly.end());

    return spks;
}
```
