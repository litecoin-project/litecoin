// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletdb.h>
#include <mweb/mweb_wallet.h>

#include <fs.h>
#include <key_io.h>
#include <protocol.h>
#include <serialize.h>
#include <sync.h>
#include <util/bip32.h>
#include <util/system.h>
#include <util/time.h>
#include <util/translation.h>
#ifdef USE_BDB
#include <wallet/bdb.h>
#endif
#ifdef USE_SQLITE
#include <wallet/sqlite.h>
#endif
#include <wallet/wallet.h>

#include <atomic>
#include <optional>
#include <string>

namespace wallet {
namespace DBKeys {
const std::string ACENTRY{"acentry"};
const std::string ACTIVEEXTERNALSPK{"activeexternalspk"};
const std::string ACTIVEINTERNALSPK{"activeinternalspk"};
const std::string BESTBLOCK_NOMERKLE{"bestblock_nomerkle"};
const std::string BESTBLOCK{"bestblock"};
const std::string COIN{"mweb_coin"};
const std::string CRYPTED_KEY{"ckey"};
const std::string CSCRIPT{"cscript"};
const std::string DEFAULTKEY{"defaultkey"};
const std::string DESTDATA{"destdata"};
const std::string FLAGS{"flags"};
const std::string HDCHAIN{"hdchain"};
const std::string KEYMETA{"keymeta"};
const std::string KEY{"key"};
const std::string LOCKED_UTXO{"lockedutxo"};
const std::string MASTER_KEY{"mkey"};
const std::string MINVERSION{"minversion"};
const std::string MWEB_SENDER_KEY_INDEX{"mweb_sender_key_index"};
const std::string MWEB_SPEND_KEY_SCRUB{"mweb_spend_key_scrub"};
const std::string NAME{"name"};
const std::string OLD_KEY{"wkey"};
const std::string ORDERPOSNEXT{"orderposnext"};
const std::string POOL{"pool"};
const std::string PURPOSE{"purpose"};
const std::string SETTINGS{"settings"};
const std::string TX{"tx"};
const std::string VERSION{"version"};
const std::string WALLETDESCRIPTOR{"walletdescriptor"};
const std::string WALLETDESCRIPTORCACHE{"walletdescriptorcache"};
const std::string WALLETDESCRIPTORLHCACHE{"walletdescriptorlhcache"};
const std::string WALLETDESCRIPTORMWEBADDRESSCACHE{"walletdescriptormwebaddresscache"};
const std::string WALLETDESCRIPTORCKEY{"walletdescriptorckey"};
const std::string WALLETDESCRIPTORKEY{"walletdescriptorkey"};
const std::string WATCHMETA{"watchmeta"};
const std::string WATCHS{"watchs"};
const std::unordered_set<std::string> LEGACY_TYPES{CRYPTED_KEY, CSCRIPT, DEFAULTKEY, HDCHAIN, KEYMETA, KEY, OLD_KEY, POOL, WATCHMETA, WATCHS};
} // namespace DBKeys

const int CHDChain::VERSION_HD_BASE;
const int CHDChain::VERSION_HD_CHAIN_SPLIT;
const int CHDChain::VERSION_HD_MWEB;
const int CHDChain::VERSION_HD_MWEB_WATCH;
const int CHDChain::VERSION_HD_MWEB_RECEIVE;
const int CHDChain::CURRENT_VERSION;

namespace {
static constexpr uint32_t WALLETDB_BIP32_HARDENED_KEY_LIMIT{0x80000000};
static constexpr uint32_t WALLETDB_MWEB_PURPOSE{100};

bool ContainsSerializedMWEBTxInfo(const CDataStream& value)
{
    // mapValue serializes each string key with its compact-size length. A
    // failed CWalletTx deserialization can otherwise hide a legacy embedded
    // WalletCoin (and its spend key) from the migration scanner.
    static constexpr unsigned char serialized_key[]{9, 'm', 'w', 'e', 'b', '_', 'i', 'n', 'f', 'o'};
    return std::search(
        value.begin(), value.end(), std::begin(serialized_key), std::end(serialized_key),
        [](std::byte lhs, unsigned char rhs) { return std::to_integer<unsigned char>(lhs) == rhs; }
    ) != value.end();
}
} // namespace

//
// WalletBatch
//

bool WalletBatch::WriteName(const std::string& strAddress, const std::string& strName)
{
    return WriteIC(std::make_pair(DBKeys::NAME, strAddress), strName);
}

bool WalletBatch::EraseName(const std::string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    return EraseIC(std::make_pair(DBKeys::NAME, strAddress));
}

bool WalletBatch::WritePurpose(const std::string& strAddress, const std::string& strPurpose)
{
    return WriteIC(std::make_pair(DBKeys::PURPOSE, strAddress), strPurpose);
}

bool WalletBatch::ErasePurpose(const std::string& strAddress)
{
    return EraseIC(std::make_pair(DBKeys::PURPOSE, strAddress));
}

bool WalletBatch::WriteTx(const CWalletTx& wtx)
{
    return WriteIC(std::make_pair(DBKeys::TX, wtx.GetHash()), wtx);
}

bool WalletBatch::EraseTx(uint256 hash)
{
    return EraseIC(std::make_pair(DBKeys::TX, hash));
}

bool WalletBatch::WriteKeyMetadata(const CKeyMetadata& meta, const CPubKey& pubkey, const bool overwrite)
{
    return WriteIC(std::make_pair(DBKeys::KEYMETA, pubkey), meta, overwrite);
}

bool WalletBatch::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, false)) {
        return false;
    }

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return WriteIC(std::make_pair(DBKeys::KEY, vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey)), false);
}

bool WalletBatch::WriteCryptedKey(const CPubKey& vchPubKey,
                                const std::vector<unsigned char>& vchCryptedSecret,
                                const CKeyMetadata &keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, true)) {
        return false;
    }

    // Compute a checksum of the encrypted key
    uint256 checksum = Hash(vchCryptedSecret);

    const auto key = std::make_pair(DBKeys::CRYPTED_KEY, vchPubKey);
    if (!WriteIC(key, std::make_pair(vchCryptedSecret, checksum), false)) {
        // It may already exist, so try writing just the checksum
        std::vector<unsigned char> val;
        if (!m_batch->Read(key, val)) {
            return false;
        }
        if (!WriteIC(key, std::make_pair(val, checksum), true)) {
            return false;
        }
    }
    EraseIC(std::make_pair(DBKeys::KEY, vchPubKey));
    return true;
}

bool WalletBatch::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    return WriteIC(std::make_pair(DBKeys::MASTER_KEY, nID), kMasterKey, true);
}

bool WalletBatch::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
    return WriteIC(std::make_pair(DBKeys::CSCRIPT, hash), redeemScript, false);
}

bool WalletBatch::WriteMWEBWalletCoin(const mw::WalletCoin& coin)
{
    return WriteIC(std::make_pair(DBKeys::COIN, coin.output_id), coin, true);
}

bool WalletBatch::WriteMWEBSpendKeyScrubFlag()
{
    return WriteIC(DBKeys::MWEB_SPEND_KEY_SCRUB, uint8_t{1}, true);
}

bool WalletBatch::EraseMWEBSpendKeyScrubFlag()
{
    return EraseIC(DBKeys::MWEB_SPEND_KEY_SCRUB);
}

bool WalletBatch::WriteWatchOnly(const CScript &dest, const CKeyMetadata& keyMeta)
{
    if (!WriteIC(std::make_pair(DBKeys::WATCHMETA, dest), keyMeta)) {
        return false;
    }
    return WriteIC(std::make_pair(DBKeys::WATCHS, dest), uint8_t{'1'});
}

bool WalletBatch::EraseWatchOnly(const CScript &dest)
{
    if (!EraseIC(std::make_pair(DBKeys::WATCHMETA, dest))) {
        return false;
    }
    return EraseIC(std::make_pair(DBKeys::WATCHS, dest));
}

bool WalletBatch::WriteBestBlock(const CBlockLocator& locator)
{
    WriteIC(DBKeys::BESTBLOCK, CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan
    return WriteIC(DBKeys::BESTBLOCK_NOMERKLE, locator);
}

bool WalletBatch::ReadBestBlock(CBlockLocator& locator)
{
    if (m_batch->Read(DBKeys::BESTBLOCK, locator) && !locator.vHave.empty()) return true;
    return m_batch->Read(DBKeys::BESTBLOCK_NOMERKLE, locator);
}

bool WalletBatch::WriteOrderPosNext(int64_t nOrderPosNext)
{
    return WriteIC(DBKeys::ORDERPOSNEXT, nOrderPosNext);
}

bool WalletBatch::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return m_batch->Read(std::make_pair(DBKeys::POOL, nPool), keypool);
}

bool WalletBatch::WritePool(int64_t nPool, const CKeyPool& keypool)
{
    return WriteIC(std::make_pair(DBKeys::POOL, nPool), keypool);
}

bool WalletBatch::ErasePool(int64_t nPool)
{
    return EraseIC(std::make_pair(DBKeys::POOL, nPool));
}

bool WalletBatch::WriteMinVersion(int nVersion)
{
    return WriteIC(DBKeys::MINVERSION, nVersion);
}

bool WalletBatch::WriteActiveScriptPubKeyMan(uint8_t type, const uint256& id, bool internal)
{
    std::string key = internal ? DBKeys::ACTIVEINTERNALSPK : DBKeys::ACTIVEEXTERNALSPK;
    return WriteIC(make_pair(key, type), id);
}

bool WalletBatch::EraseActiveScriptPubKeyMan(uint8_t type, bool internal)
{
    const std::string key{internal ? DBKeys::ACTIVEINTERNALSPK : DBKeys::ACTIVEEXTERNALSPK};
    return EraseIC(make_pair(key, type));
}

bool WalletBatch::WriteDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const CPrivKey& privkey)
{
    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> key;
    key.reserve(pubkey.size() + privkey.size());
    key.insert(key.end(), pubkey.begin(), pubkey.end());
    key.insert(key.end(), privkey.begin(), privkey.end());

    return WriteIC(std::make_pair(DBKeys::WALLETDESCRIPTORKEY, std::make_pair(desc_id, pubkey)), std::make_pair(privkey, Hash(key)), false);
}

bool WalletBatch::WriteCryptedDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const std::vector<unsigned char>& secret)
{
    if (!WriteIC(std::make_pair(DBKeys::WALLETDESCRIPTORCKEY, std::make_pair(desc_id, pubkey)), secret, false)) {
        return false;
    }
    EraseIC(std::make_pair(DBKeys::WALLETDESCRIPTORKEY, std::make_pair(desc_id, pubkey)));
    return true;
}

bool WalletBatch::WriteDescriptor(const uint256& desc_id, const WalletDescriptor& descriptor)
{
    return WriteIC(make_pair(DBKeys::WALLETDESCRIPTOR, desc_id), descriptor);
}

bool WalletBatch::WriteDescriptorDerivedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index, uint32_t der_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORCACHE, desc_id), std::make_pair(key_exp_index, der_index)), ser_xpub);
}

bool WalletBatch::WriteDescriptorParentCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORCACHE, desc_id), key_exp_index), ser_xpub);
}

bool WalletBatch::WriteDescriptorLastHardenedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORLHCACHE, desc_id), key_exp_index), ser_xpub);
}

bool WalletBatch::WriteDescriptorMWEBAddressCache(const uint256& desc_id, const uint32_t idx, const StealthAddress& address)
{
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORMWEBADDRESSCACHE, desc_id), idx), address);
}

bool WalletBatch::WriteDescriptorCacheItems(const uint256& desc_id, const DescriptorCache& cache)
{
    for (const auto& parent_xpub_pair : cache.GetCachedParentExtPubKeys()) {
        if (!WriteDescriptorParentCache(parent_xpub_pair.second, desc_id, parent_xpub_pair.first)) {
            return false;
        }
    }
    for (const auto& derived_xpub_map_pair : cache.GetCachedDerivedExtPubKeys()) {
        for (const auto& derived_xpub_pair : derived_xpub_map_pair.second) {
            if (!WriteDescriptorDerivedCache(derived_xpub_pair.second, desc_id, derived_xpub_map_pair.first, derived_xpub_pair.first)) {
                return false;
            }
        }
    }
    for (const auto& lh_xpub_pair : cache.GetCachedLastHardenedExtPubKeys()) {
        if (!WriteDescriptorLastHardenedCache(lh_xpub_pair.second, desc_id, lh_xpub_pair.first)) {
            return false;
        }
    }
    for (const auto& idx_mweb_address_pair : cache.GetCachedMWEBAddresses()) {
        if (!WriteDescriptorMWEBAddressCache(desc_id, idx_mweb_address_pair.first, idx_mweb_address_pair.second)) {
            return false;
        }
    }

    return true;
}

bool WalletBatch::WriteMWEBNextSenderKeyIndex(const CKeyID& master_scan_keyid, uint64_t next_index)
{
    return WriteIC(std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid), next_index);
}

class SerializableOutputIndex
{
    AnyOutputID m_id;

public:
    SerializableOutputIndex() = default;
    SerializableOutputIndex(AnyOutputID id)
        : m_id(std::move(id)) { }

    const AnyOutputID& Get() { return m_id; }

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        if (m_id.IsOutPoint()) {
            s << uint8_t(0);
            s << m_id.ToOutPoint();
        } else {
            s << uint8_t(1);
            s << m_id.ToMWEB();
        }
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        uint8_t type;
        s >> type;

        if (type > 1) {
            throw std::ios_base::failure("Invalid AnyOutputID type");
        }

        if (type == 0) {
            COutPoint outpoint;
            s >> outpoint;
            m_id = outpoint;
        } else {
            mw::Hash hash;
            s >> hash;
            m_id = hash;
        }
    }
};

bool WalletBatch::WriteLockedUTXO(const AnyOutputID& output)
{
    return WriteIC(std::make_pair(DBKeys::LOCKED_UTXO, SerializableOutputIndex(output)), uint8_t{'1'});
}

bool WalletBatch::EraseLockedUTXO(const AnyOutputID& output)
{
    return EraseIC(std::make_pair(DBKeys::LOCKED_UTXO, SerializableOutputIndex(output)));
}

class CWalletScanState {
public:
    unsigned int nKeys{0};
    unsigned int nCKeys{0};
    unsigned int nWatchKeys{0};
    unsigned int nKeyMeta{0};
    unsigned int m_unknown_records{0};
    bool fIsEncrypted{false};
    bool fAnyUnordered{false};
    std::vector<uint256> vWalletUpgrade;
    std::vector<uint256> vWalletRemove;
    std::map<uint256, uint256> m_legacy_mweb_tx_rekeys;
    std::map<mw::Hash, mw::WalletCoin> m_mweb_coin_upgrades;
    bool m_mweb_spend_key_scrub_required{false};
    bool m_mweb_persisted_spend_key_loaded{false};
    std::map<OutputType, uint256> m_active_external_spks;
    std::map<OutputType, uint256> m_active_internal_spks;
    std::map<uint256, DescriptorCache> m_descriptor_caches;
    std::map<std::pair<uint256, CKeyID>, CKey> m_descriptor_keys;
    std::map<std::pair<uint256, CKeyID>, std::pair<CPubKey, std::vector<unsigned char>>> m_descriptor_crypt_keys;
    std::map<uint160, CHDChain> m_hd_chains;
    bool tx_corrupt{false};
    bool descriptor_unknown{false};

    CWalletScanState() = default;
};

static bool
ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue,
             CWalletScanState &wss, std::string& strType, std::string& strErr, const KeyFilterFn& filter_fn = nullptr) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    try {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        // If we have a filter, check if this matches the filter
        if (filter_fn && !filter_fn(strType)) {
            return true;
        }
        if (strType == DBKeys::NAME) {
            std::string strAddress;
            ssKey >> strAddress;
            std::string label;
            ssValue >> label;
            pwallet->m_address_book[DecodeDestination(strAddress)].SetLabel(label);
        } else if (strType == DBKeys::PURPOSE) {
            std::string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->m_address_book[DecodeDestination(strAddress)].purpose;
        } else if (strType == DBKeys::TX) {
            uint256 hash;
            ssKey >> hash;
            CWalletTx wtx(nullptr, TxStateInactive{}, std::nullopt);
            ssValue >> wtx;
            if (wtx.mweb_wtx_info && wtx.mweb_wtx_info->legacy_received_coin &&
                wtx.mweb_wtx_info->legacy_received_coin->HadPersistedSpendKey()) {
                wss.m_mweb_persisted_spend_key_loaded = true;
            }

            if (wtx.GetHash() != hash) {
                bool is_legacy_mweb_tx_hash = false;
                if (wtx.tx->IsMWEBOnly()) {
                    const std::vector<mw::Kernel>& kernels = wtx.tx->mweb_tx.GetKernels();
                    is_legacy_mweb_tx_hash = !kernels.empty() && hash == uint256{kernels.front().GetHash().vec()};
                }

                // We previously calculated hash for mweb_wtx_info in an impractical way.
                // We changed to just using the output ID as hash, so need to upgrade any existing txs.
                if (wtx.mweb_wtx_info) {
                    wss.vWalletRemove.push_back(hash);
                    wss.vWalletUpgrade.push_back(wtx.GetHash());
                } else if (is_legacy_mweb_tx_hash) {
                    // v0.21 identified pure-MWEB transactions by their first
                    // kernel hash. Rekey released wallet records using the
                    // whole-MWEB-transaction hash used by v24.
                    wss.m_legacy_mweb_tx_rekeys.emplace(wtx.GetHash(), hash);
                } else {
                    return false;
                }
            }

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703) {
                if (!ssValue.empty()) {
                    uint8_t fTmp;
                    uint8_t fUnused;
                    std::string unused_string;
                    ssValue >> fTmp >> fUnused >> unused_string;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d %s",
                                       wtx.fTimeReceivedIsTxTime, fTmp, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                } else {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1) {
                wss.fAnyUnordered = true;
            }

            if (!pwallet->LoadToWallet(wtx)) {
                // There's some corruption here since the tx we just tried to load was already in the wallet.
                // We don't consider this type of corruption critical, and can fix it by removing tx data and
                // rescanning.
                wss.tx_corrupt = true;
                return false;
            }
        } else if (strType == DBKeys::COIN) {
            mw::Hash output_id;
            ssKey >> output_id;
            mw::WalletCoin coin;
            ssValue >> coin;
            if (!ssValue.empty()) {
                throw std::ios_base::failure("Trailing data in MWEB coin record");
            }
            if (output_id != coin.output_id) {
                throw std::ios_base::failure("MWEB coin database key does not match its output ID");
            }
            if (coin.HadPersistedSpendKey()) {
                wss.m_mweb_persisted_spend_key_loaded = true;
            }
            if (coin.NeedsPersistenceUpgrade()) {
                wss.m_mweb_coin_upgrades.emplace(coin.output_id, coin);
            }
            pwallet->GetMWWallet()->LoadToWallet(coin);
            return true;
        } else if (strType == DBKeys::MWEB_SPEND_KEY_SCRUB) {
            uint8_t flag{0};
            ssValue >> flag;
            if (flag != 1) {
                throw std::ios_base::failure("Invalid MWEB spend-key scrub marker");
            }
            wss.m_mweb_spend_key_scrub_required = true;
            return true;
        } else if (strType == DBKeys::WATCHS) {
            wss.nWatchKeys++;
            CScript script;
            ssKey >> script;
            uint8_t fYes;
            ssValue >> fYes;
            if (fYes == '1') {
                pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadWatchOnly(script);
            }
        } else if (strType == DBKeys::KEY) {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            wss.nKeys++;
            ssValue >> pkey;

            // Old wallets store keys as DBKeys::KEY [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
            // using EC operations as a checksum.
            // Newer wallets store keys as DBKeys::KEY [pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch (const std::ios_base::failure&) {}

            bool fSkipCheck = false;

            if (!hash.IsNull())
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LegacyScriptPubKeyMan::LoadKey failed";
                return false;
            }
        } else if (strType == DBKeys::MASTER_KEY) {
            // Master encryption key is loaded into only the wallet and not any of the ScriptPubKeyMans.
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        } else if (strType == DBKeys::CRYPTED_KEY) {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            std::vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;

            // Get the checksum and check it
            bool checksum_valid = false;
            if (!ssValue.eof()) {
                uint256 checksum;
                ssValue >> checksum;
                if ((checksum_valid = Hash(vchPrivKey) != checksum)) {
                    strErr = "Error reading wallet database: Encrypted key corrupt";
                    return false;
                }
            }

            wss.nCKeys++;

            if (!pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadCryptedKey(vchPubKey, vchPrivKey, checksum_valid))
            {
                strErr = "Error reading wallet database: LegacyScriptPubKeyMan::LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        } else if (strType == DBKeys::KEYMETA) {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            // Extract some CHDChain info from this metadata if it has any
            if (keyMeta.nVersion >= CKeyMetadata::VERSION_WITH_HDDATA && !keyMeta.hd_seed_id.IsNull() && keyMeta.hdKeypath.size() > 0) {
                // Get the path from the key origin or from the path string
                // Not applicable when path is "s" or "m" as those indicate a seed
                // See https://github.com/bitcoin/bitcoin/pull/12924
                bool external = false;
                bool internal = false;
                bool mweb = false;
                uint32_t index = 0;
                auto set_mweb_index = [&](uint32_t mweb_index) {
                    mweb = true;
                    index = mweb_index;
                    keyMeta.hdKeypath = strprintf("x/%u", mweb_index);
                    keyMeta.key_origin.hdkeypath.path.clear();
                    keyMeta.key_origin.hdkeypath.mweb_index = mweb_index;
                    if (keyMeta.nVersion < CKeyMetadata::VERSION_WITH_MWEB_INDEX) {
                        keyMeta.nVersion = CKeyMetadata::VERSION_WITH_MWEB_INDEX;
                    }
                };

                if (keyMeta.key_origin.hdkeypath.mweb_index) {
                    set_mweb_index(*keyMeta.key_origin.hdkeypath.mweb_index);
                } else if (keyMeta.hdKeypath != "s" && keyMeta.hdKeypath != "m") {
                    HDKeyPath hdkeypath;
                    std::optional<HDKeyPath> parsed_hdkeypath;
                    auto parse_hdkeypath = [&]() {
                        HDKeyPath parsed;
                        if (!ParseHDKeypath(keyMeta.hdKeypath, parsed)) return false;
                        parsed_hdkeypath = parsed;
                        return true;
                    };

                    if (parse_hdkeypath() && parsed_hdkeypath->path.empty() && parsed_hdkeypath->mweb_index) {
                        set_mweb_index(*parsed_hdkeypath->mweb_index);
                    } else if (keyMeta.has_key_origin) {
                        // We have a key origin, so pull it from its path vector
                        hdkeypath = keyMeta.key_origin.hdkeypath;
                    } else {
                        // No key origin, have to parse the string
                        if (!parsed_hdkeypath) {
                            strErr = "Error reading wallet database: keymeta with invalid HD keypath";
                            return false;
                        }
                        hdkeypath = *parsed_hdkeypath;
                    }

                    // Extract the index and internal from the path
                    // Path string is m/0'/k'/i'
                    // Path vector is [0', k', i'] (but as ints OR'd with the hardened bit
                    // k == 0 for external, 1 for internal, 100 for MWEB master material. i is the index
                    if (!mweb && hdkeypath.path.size() != 3) {
                        strErr = "Error reading wallet database: keymeta found with unexpected path";
                        return false;
                    }
                    if (!mweb && hdkeypath.path[0] != WALLETDB_BIP32_HARDENED_KEY_LIMIT) {
                        strErr = strprintf("Unexpected path index of 0x%08x (expected 0x80000000) for the element at index 0", hdkeypath.path[0]);
                        return false;
                    }
                    if (!mweb && hdkeypath.path[1] != WALLETDB_BIP32_HARDENED_KEY_LIMIT && hdkeypath.path[1] != (1 | WALLETDB_BIP32_HARDENED_KEY_LIMIT) && hdkeypath.path[1] != (WALLETDB_MWEB_PURPOSE | WALLETDB_BIP32_HARDENED_KEY_LIMIT)) {
                        strErr = strprintf("Unexpected path index of 0x%08x (expected 0x80000000, 0x80000001, or 0x80000064) for the element at index 1", hdkeypath.path[1]);
                        return false;
                    }
                    if (!mweb && (hdkeypath.path[2] & WALLETDB_BIP32_HARDENED_KEY_LIMIT) == 0) {
                        strErr = strprintf("Unexpected path index of 0x%08x (expected to be greater than or equal to 0x80000000)", hdkeypath.path[2]);
                        return false;
                    }
                    if (!mweb) {
                        external = hdkeypath.path[1] == WALLETDB_BIP32_HARDENED_KEY_LIMIT;
                        internal = hdkeypath.path[1] == (1 | WALLETDB_BIP32_HARDENED_KEY_LIMIT);
                        index = hdkeypath.path[2] & ~WALLETDB_BIP32_HARDENED_KEY_LIMIT;
                    }
                }

                // Insert a new CHDChain, or get the one that already exists
                auto ins = wss.m_hd_chains.emplace(keyMeta.hd_seed_id, CHDChain());
                CHDChain& chain = ins.first->second;
                if (ins.second) {
                    // For new chains, we want to default to VERSION_HD_BASE until we see an internal
                    chain.nVersion = CHDChain::VERSION_HD_BASE;
                    chain.seed_id = keyMeta.hd_seed_id;
                }

                if (mweb) {
                    chain.nVersion = std::max(chain.nVersion, CHDChain::VERSION_HD_MWEB_RECEIVE);
                    chain.nMWEBIndexCounter = std::max(chain.nMWEBIndexCounter, index + 1);
                } else if (internal) {
                    chain.nVersion = std::max(chain.nVersion, CHDChain::VERSION_HD_CHAIN_SPLIT);
                    chain.nInternalChainCounter = std::max(chain.nInternalChainCounter, index + 1);
                } else if (external) {
                    chain.nExternalChainCounter = std::max(chain.nExternalChainCounter, index + 1);
                }
            }
            pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadKeyMetadata(vchPubKey.GetID(), keyMeta);
        } else if (strType == DBKeys::WATCHMETA) {
            CScript script;
            ssKey >> script;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;
            pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadScriptMetadata(CScriptID(script), keyMeta);
        } else if (strType == DBKeys::DEFAULTKEY) {
            // We don't want or need the default key, but if there is one set,
            // we want to make sure that it is valid so that we can detect corruption
            CPubKey vchPubKey;
            ssValue >> vchPubKey;
            if (!vchPubKey.IsValid()) {
                strErr = "Error reading wallet database: Default Key corrupt";
                return false;
            }
        } else if (strType == DBKeys::POOL) {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;

            pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadKeyPool(nIndex, keypool);
        } else if (strType == DBKeys::CSCRIPT) {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> script;
            if (!pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadCScript(script))
            {
                strErr = "Error reading wallet database: LegacyScriptPubKeyMan::LoadCScript failed";
                return false;
            }
        } else if (strType == DBKeys::ORDERPOSNEXT) {
            ssValue >> pwallet->nOrderPosNext;
        } else if (strType == DBKeys::MWEB_SENDER_KEY_INDEX) {
            CKeyID master_scan_keyid;
            ssKey >> master_scan_keyid;
            uint64_t next_index;
            ssValue >> next_index;
            pwallet->GetMWWallet()->LoadNextSenderKeyIndex(master_scan_keyid, next_index);
        } else if (strType == DBKeys::DESTDATA) {
            std::string strAddress, strKey, strValue;
            ssKey >> strAddress;
            ssKey >> strKey;
            ssValue >> strValue;
            pwallet->LoadDestData(DecodeDestination(strAddress), strKey, strValue);
        } else if (strType == DBKeys::HDCHAIN) {
            CHDChain chain;
            ssValue >> chain;
            pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadHDChain(chain);
        } else if (strType == DBKeys::OLD_KEY) {
            strErr = "Found unsupported 'wkey' record, try loading with version 0.18";
            return false;
        } else if (strType == DBKeys::ACTIVEEXTERNALSPK || strType == DBKeys::ACTIVEINTERNALSPK) {
            uint8_t type;
            ssKey >> type;
            uint256 id;
            ssValue >> id;

            bool internal = strType == DBKeys::ACTIVEINTERNALSPK;
            auto& spk_mans = internal ? wss.m_active_internal_spks : wss.m_active_external_spks;
            if (spk_mans.count(static_cast<OutputType>(type)) > 0) {
                strErr = "Multiple ScriptPubKeyMans specified for a single type";
                return false;
            }
            spk_mans[static_cast<OutputType>(type)] = id;
        } else if (strType == DBKeys::WALLETDESCRIPTOR) {
            uint256 id;
            ssKey >> id;
            WalletDescriptor desc;
            std::string desc_hex = HexStr(Span<std::byte>(ssValue.data(), ssValue.size()));
            try {
                ssValue >> desc;
            } catch (const std::ios_base::failure& e) {
                strErr = e.what();
                wss.descriptor_unknown = true;
                return false;
            }
            if (wss.m_descriptor_caches.count(id) == 0) {
                wss.m_descriptor_caches[id] = DescriptorCache();
            }
            pwallet->LoadDescriptorScriptPubKeyMan(id, desc);
        } else if (strType == DBKeys::WALLETDESCRIPTORCACHE) {
            bool parent = true;
            uint256 desc_id;
            uint32_t key_exp_index;
            uint32_t der_index;
            ssKey >> desc_id;
            ssKey >> key_exp_index;

            // if the der_index exists, it's a derived xpub
            try
            {
                ssKey >> der_index;
                parent = false;
            }
            catch (...) {}

            std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
            ssValue >> ser_xpub;
            CExtPubKey xpub;
            xpub.Decode(ser_xpub.data());
            if (parent) {
                wss.m_descriptor_caches[desc_id].CacheParentExtPubKey(key_exp_index, xpub);
            } else {
                wss.m_descriptor_caches[desc_id].CacheDerivedExtPubKey(key_exp_index, der_index, xpub);
            }
        } else if (strType == DBKeys::WALLETDESCRIPTORLHCACHE) {
            uint256 desc_id;
            uint32_t key_exp_index;
            ssKey >> desc_id;
            ssKey >> key_exp_index;

            std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
            ssValue >> ser_xpub;
            CExtPubKey xpub;
            xpub.Decode(ser_xpub.data());
            wss.m_descriptor_caches[desc_id].CacheLastHardenedExtPubKey(key_exp_index, xpub);
        } else if (strType == DBKeys::WALLETDESCRIPTORKEY) {
            uint256 desc_id;
            CPubKey pubkey;
            ssKey >> desc_id;
            ssKey >> pubkey;
            if (!pubkey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            wss.nKeys++;
            ssValue >> pkey;
            ssValue >> hash;

            // hash pubkey/privkey to accelerate wallet load
            std::vector<unsigned char> to_hash;
            to_hash.reserve(pubkey.size() + pkey.size());
            to_hash.insert(to_hash.end(), pubkey.begin(), pubkey.end());
            to_hash.insert(to_hash.end(), pkey.begin(), pkey.end());

            if (Hash(to_hash) != hash)
            {
                strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                return false;
            }

            if (!key.Load(pkey, pubkey, true))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            wss.m_descriptor_keys.insert(std::make_pair(std::make_pair(desc_id, pubkey.GetID()), key));
        } else if (strType == DBKeys::WALLETDESCRIPTORMWEBADDRESSCACHE) {
            uint256 desc_id;
            ssKey >> desc_id;
            uint32_t mweb_index;
            ssKey >> mweb_index;

            StealthAddress mweb_address;
            ssValue >> mweb_address;

            wss.m_descriptor_caches[desc_id].CacheMWEBAddress(mweb_index, mweb_address);
        } else if (strType == DBKeys::WALLETDESCRIPTORCKEY) {
            uint256 desc_id;
            CPubKey pubkey;
            ssKey >> desc_id;
            ssKey >> pubkey;
            if (!pubkey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            std::vector<unsigned char> privkey;
            ssValue >> privkey;
            wss.nCKeys++;

            wss.m_descriptor_crypt_keys.insert(std::make_pair(std::make_pair(desc_id, pubkey.GetID()), std::make_pair(pubkey, privkey)));
            wss.fIsEncrypted = true;
        } else if (strType == DBKeys::LOCKED_UTXO) {
            CDataStream legacy_key{ssKey};
            try {
                SerializableOutputIndex output_idx;
                ssKey >> output_idx;
                pwallet->LockCoin(output_idx.Get());
            } catch (const std::ios_base::failure&) {
                COutPoint outpoint;
                legacy_key >> outpoint;
                pwallet->LockCoin(outpoint);
            }
        } else if (strType != DBKeys::BESTBLOCK && strType != DBKeys::BESTBLOCK_NOMERKLE &&
                   strType != DBKeys::MINVERSION && strType != DBKeys::ACENTRY &&
                   strType != DBKeys::VERSION && strType != DBKeys::SETTINGS &&
                   strType != DBKeys::FLAGS) {
            wss.m_unknown_records++;
        }
    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    } catch (...) {
        if (strErr.empty()) {
            strErr = "Caught unknown exception in ReadKeyValue";
        }
        return false;
    }
    return true;
}

bool ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue, std::string& strType, std::string& strErr, const KeyFilterFn& filter_fn)
{
    CWalletScanState dummy_wss;
    LOCK(pwallet->cs_wallet);
    return ReadKeyValue(pwallet, ssKey, ssValue, dummy_wss, strType, strErr, filter_fn);
}

bool WalletBatch::IsKeyType(const std::string& strType)
{
    return (strType == DBKeys::KEY ||
            strType == DBKeys::MASTER_KEY || strType == DBKeys::CRYPTED_KEY ||
            strType == DBKeys::COIN ||
            strType == DBKeys::MWEB_SPEND_KEY_SCRUB);
}

DBErrors WalletBatch::LoadWallet(CWallet* pwallet)
{
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    bool rescan_required = false;
    DBErrors result = DBErrors::LOAD_OK;

    LOCK(pwallet->cs_wallet);

    // Last client version to open this wallet
    int last_client = CLIENT_VERSION;
    bool has_last_client = m_batch->Read(DBKeys::VERSION, last_client);
    pwallet->WalletLogPrintf("Wallet file version = %d, last client version = %d\n", pwallet->GetVersion(), last_client);

    try {
        int nMinVersion = 0;
        if (m_batch->Read(DBKeys::MINVERSION, nMinVersion)) {
            if (nMinVersion > FEATURE_LATEST)
                return DBErrors::TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Load wallet flags, so they are known when processing other records.
        // The FLAGS key is absent during wallet creation.
        uint64_t flags;
        if (m_batch->Read(DBKeys::FLAGS, flags)) {
            if (!pwallet->LoadWalletFlags(flags)) {
                pwallet->WalletLogPrintf("Error reading wallet database: Unknown non-tolerable wallet flags found\n");
                return DBErrors::CORRUPT;
            }
        }

#ifndef ENABLE_EXTERNAL_SIGNER
        if (pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            pwallet->WalletLogPrintf("Error: External signer wallet being loaded without external signer support compiled\n");
            return DBErrors::EXTERNAL_SIGNER_SUPPORT_REQUIRED;
        }
#endif

        // Get cursor
        if (!m_batch->StartCursor())
        {
            pwallet->WalletLogPrintf("Error getting wallet database cursor\n");
            return DBErrors::CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            bool complete;
            bool ret = m_batch->ReadAtCursor(ssKey, ssValue, complete);
            if (complete) {
                break;
            }
            else if (!ret)
            {
                m_batch->CloseCursor();
                pwallet->WalletLogPrintf("Error reading next record from wallet database\n");
                return DBErrors::CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            std::string strType, strErr;
            const bool contains_mweb_tx_info = ContainsSerializedMWEBTxInfo(ssValue);
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {

                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType) || strType == DBKeys::DEFAULTKEY ||
                    (strType == DBKeys::TX && contains_mweb_tx_info)) {
                    result = DBErrors::CORRUPT;
                } else if (strType == DBKeys::FLAGS) {
                    // reading the wallet flags can only fail if unknown flags are present
                    result = DBErrors::TOO_NEW;
                } else if (wss.tx_corrupt) {
                    pwallet->WalletLogPrintf("Error: Corrupt transaction found. This can be fixed by removing transactions from wallet and rescanning.\n");
                    // Set tx_corrupt back to false so that the error is only printed once (per corrupt tx)
                    wss.tx_corrupt = false;
                    result = DBErrors::CORRUPT;
                } else if (wss.descriptor_unknown) {
                    strErr = strprintf("Error: Unrecognized descriptor found in wallet %s. ", pwallet->GetName());
                    strErr += (last_client > CLIENT_VERSION) ? "The wallet might had been created on a newer version. " :
                            "The database might be corrupted or the software version is not compatible with one of your wallet descriptors. ";
                    strErr += "Please try running the latest software version";
                    pwallet->WalletLogPrintf("%s\n", strErr);
                    return DBErrors::UNKNOWN_DESCRIPTOR;
                } else {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == DBKeys::TX)
                        // Rescan if there is a bad transaction record:
                        rescan_required = true;
                }
            }
            if (!strErr.empty())
                pwallet->WalletLogPrintf("%s\n", strErr);
        }
    } catch (...) {
        result = DBErrors::CORRUPT;
    }
    m_batch->CloseCursor();

    // Set the active ScriptPubKeyMans
    for (auto spk_man_pair : wss.m_active_external_spks) {
        pwallet->LoadActiveScriptPubKeyMan(spk_man_pair.second, spk_man_pair.first, /*internal=*/false);
    }
    for (auto spk_man_pair : wss.m_active_internal_spks) {
        pwallet->LoadActiveScriptPubKeyMan(spk_man_pair.second, spk_man_pair.first, /*internal=*/true);
    }

    // Set the descriptor caches
    for (const auto& desc_cache_pair : wss.m_descriptor_caches) {
        auto spk_man = pwallet->GetScriptPubKeyMan(desc_cache_pair.first);
        assert(spk_man);
        ((DescriptorScriptPubKeyMan*)spk_man)->SetCache(desc_cache_pair.second);
    }

    // Set the descriptor keys
    for (const auto& desc_key_pair : wss.m_descriptor_keys) {
        auto spk_man = pwallet->GetScriptPubKeyMan(desc_key_pair.first.first);
        ((DescriptorScriptPubKeyMan*)spk_man)->AddKey(desc_key_pair.first.second, desc_key_pair.second);
    }
    for (const auto& desc_key_pair : wss.m_descriptor_crypt_keys) {
        auto spk_man = pwallet->GetScriptPubKeyMan(desc_key_pair.first.first);
        ((DescriptorScriptPubKeyMan*)spk_man)->AddCryptedKey(desc_key_pair.first.second, desc_key_pair.second.first, desc_key_pair.second.second);
    }

    if (rescan_required && result == DBErrors::LOAD_OK) {
        result = DBErrors::NEED_RESCAN;
    } else if (fNoncriticalErrors && result == DBErrors::LOAD_OK) {
        result = DBErrors::NONCRITICAL_ERROR;
    }

    // Any wallet corruption at all: skip any rewriting or upgrading, we don't
    // want to make it worse. However, the normally tolerated error results
    // must not allow a wallet with an outstanding MWEB spend-key scrub to
    // open: a later ordinary coin write could otherwise replace the legacy
    // record and permanently lose the scrub signal.
    if ((result == DBErrors::NONCRITICAL_ERROR || result == DBErrors::NEED_RESCAN) &&
        (wss.m_mweb_spend_key_scrub_required || wss.m_mweb_persisted_spend_key_loaded)) {
        return DBErrors::LOAD_FAIL;
    }
    if (result != DBErrors::LOAD_OK) {
        return result;
    }

    pwallet->WalletLogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total. Unknown wallet records: %u\n",
           wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys, wss.m_unknown_records);

    // nTimeFirstKey is only reliable if all keys have metadata
    if (pwallet->IsLegacy() && (wss.nKeys + wss.nCKeys + wss.nWatchKeys) != wss.nKeyMeta) {
        auto spk_man = pwallet->GetOrCreateLegacyScriptPubKeyMan();
        if (spk_man) {
            LOCK(spk_man->cs_KeyStore);
            spk_man->UpdateTimeFirstKey(1);
        }
    }

    // MWEB: Load active legacy and MWEB descriptor keychains.
    for (ScriptPubKeyMan* spk_man : pwallet->GetAllScriptPubKeyMans()) {
        spk_man->LoadMWEBKeychain();
    }

    // Released pre-v24 coins did not identify their MWEB keychain. Those
    // wallets had one active MWEB keychain, so bind legacy standalone coin
    // records to it after verifying the stored address against its scan key.
    for (auto& [output_id, coin] : wss.m_mweb_coin_upgrades) {
        if (pwallet->GetMWWallet()->SetActiveMasterScanKeyId(coin)) {
            pwallet->GetMWWallet()->LoadToWallet(coin);
        }
    }

    // Migrate released MWEB wtx records, which embedded the full received coin.
    // Promote the coin into the wallet's coin map unless a mweb_coin record
    // already exists (the coin map copy is at least as fresh as the embedded
    // one), then rewrite the record in the ID-only format. Each MWEB migration
    // is committed with its old-key removal so a failed write cannot remove
    // the only complete copy of a received coin.
    //
    // The minversion is only raised when upgraded records are actually
    // written (here and at the MWEB persistence sites), not on every open: a
    // blanket bump would erase feature-version transitions CWallet::UpgradeWallet
    // needs, and a wallet with no upgraded MWEB state remains backwards compatible.
    struct MWEBMigration
    {
        CWalletTx* wtx;
        mw::WalletCoin coin;
        bool promote_coin;
        std::optional<uint256> old_wtx_hash;
    };

    std::vector<MWEBMigration> mweb_migrations;
    for (auto& [wtx_hash, wtx] : pwallet->mapWallet) {
        if (!wtx.mweb_wtx_info || !wtx.mweb_wtx_info->legacy_received_coin) {
            continue;
        }

        mw::WalletCoin legacy_coin = *wtx.mweb_wtx_info->legacy_received_coin;
        pwallet->GetMWWallet()->SetActiveMasterScanKeyId(legacy_coin);
        mw::WalletCoin existing_coin;
        const bool promote_coin = !pwallet->GetMWEBWalletCoin(legacy_coin.output_id, existing_coin);
        if (promote_coin) {
            // The legacy record is still the durable source if migration
            // fails, so keep the coin available for this wallet session.
            pwallet->GetMWWallet()->LoadToWallet(legacy_coin);
        }
        const uint256 released_wtx_hash{legacy_coin.output_id.vec()};
        const bool rewrite_key = std::find(wss.vWalletRemove.begin(), wss.vWalletRemove.end(), released_wtx_hash) != wss.vWalletRemove.end();
        mweb_migrations.push_back(MWEBMigration{
            &wtx,
            legacy_coin,
            promote_coin,
            rewrite_key ? std::make_optional(released_wtx_hash) : std::nullopt,
        });

        // This migration rewrites the complete record itself. Remove its
        // entries from the generic, non-atomic transaction-key upgrade path.
        wss.vWalletUpgrade.erase(std::remove(wss.vWalletUpgrade.begin(), wss.vWalletUpgrade.end(), wtx_hash), wss.vWalletUpgrade.end());
        if (rewrite_key) {
            wss.vWalletRemove.erase(std::remove(wss.vWalletRemove.begin(), wss.vWalletRemove.end(), released_wtx_hash), wss.vWalletRemove.end());
        }
    }

    struct MWEBTxRekey
    {
        CWalletTx* wtx;
        uint256 old_wtx_hash;
    };

    std::vector<MWEBTxRekey> mweb_tx_rekeys;
    for (const auto& [new_wtx_hash, old_wtx_hash] : wss.m_legacy_mweb_tx_rekeys) {
        mweb_tx_rekeys.push_back(MWEBTxRekey{
            &pwallet->mapWallet.at(new_wtx_hash),
            old_wtx_hash,
        });
    }

    const bool migrated_persisted_spend_key = std::any_of(
        wss.m_mweb_coin_upgrades.begin(),
        wss.m_mweb_coin_upgrades.end(),
        [](const auto& entry) { return entry.second.HadPersistedSpendKey(); }
    ) || std::any_of(
        mweb_migrations.begin(),
        mweb_migrations.end(),
        [](const MWEBMigration& migration) { return migration.coin.HadPersistedSpendKey(); }
    );
    const bool has_mweb_migrations = !mweb_migrations.empty() || !mweb_tx_rekeys.empty() || !wss.m_mweb_coin_upgrades.empty();

    bool mweb_migration_write_failed = false;
    if (has_mweb_migrations && !pwallet->SetMinVersion(FEATURE_V24, this)) {
        pwallet->WalletLogPrintf("Failed to write wallet minimum version before migrating MWEB records\n");
        mweb_migration_write_failed = true;
    }

    if (!mweb_migration_write_failed && has_mweb_migrations) {
        const bool transaction_started = TxnBegin();
        bool transaction_ok = transaction_started;
        if (!transaction_ok) {
            pwallet->WalletLogPrintf("Failed to begin MWEB record migration transaction\n");
        }

        if (transaction_ok && migrated_persisted_spend_key && !WriteMWEBSpendKeyScrubFlag()) {
            pwallet->WalletLogPrintf("Failed to mark the wallet for removal of persisted MWEB spend keys\n");
            transaction_ok = false;
        }

        for (const auto& [output_id, coin] : wss.m_mweb_coin_upgrades) {
            if (transaction_ok && !WriteMWEBWalletCoin(coin)) {
                pwallet->WalletLogPrintf("Failed to upgrade MWEB coin %s\n", output_id.ToHex());
                transaction_ok = false;
            }
        }

        for (const MWEBMigration& migration : mweb_migrations) {
            if (transaction_ok && migration.promote_coin && !WriteMWEBWalletCoin(migration.coin)) {
                pwallet->WalletLogPrintf("Failed to write MWEB coin %s during wtx record migration\n", migration.coin.output_id.ToHex());
                transaction_ok = false;
            }
        }

        for (const MWEBMigration& migration : mweb_migrations) {
            if (transaction_ok && !WriteTx(*migration.wtx)) {
                pwallet->WalletLogPrintf("Failed to rewrite MWEB wallet transaction %s during migration\n", migration.wtx->GetHash().ToString());
                transaction_ok = false;
            }
        }

        for (const MWEBTxRekey& rekey : mweb_tx_rekeys) {
            if (transaction_ok && !WriteTx(*rekey.wtx)) {
                pwallet->WalletLogPrintf("Failed to rekey MWEB wallet transaction %s during migration\n", rekey.wtx->GetHash().ToString());
                transaction_ok = false;
            }
        }

        for (const MWEBMigration& migration : mweb_migrations) {
            if (transaction_ok && migration.old_wtx_hash && !EraseTx(*migration.old_wtx_hash)) {
                pwallet->WalletLogPrintf("Failed to erase old MWEB wallet transaction %s during migration\n", migration.old_wtx_hash->ToString());
                transaction_ok = false;
            }
        }

        for (const MWEBTxRekey& rekey : mweb_tx_rekeys) {
            if (transaction_ok && !EraseTx(rekey.old_wtx_hash)) {
                pwallet->WalletLogPrintf("Failed to erase old MWEB wallet transaction %s during migration\n", rekey.old_wtx_hash.ToString());
                transaction_ok = false;
            }
        }

        if (transaction_ok && !TxnCommit()) {
            pwallet->WalletLogPrintf("Failed to commit MWEB record migration transaction\n");
            transaction_ok = false;
        }

        if (!transaction_ok) {
            if (transaction_started) {
                TxnAbort();
            }
            mweb_migration_write_failed = true;
        } else {
            for (const MWEBMigration& migration : mweb_migrations) {
                migration.wtx->mweb_wtx_info->legacy_received_coin = std::nullopt;
            }
        }
    }

    // Do not run later load-time rewrites after a failed MWEB migration. In
    // particular, ReorderTransactions() would serialize an unordered legacy
    // transaction under its new ID-only key, defeating the rollback above.
    if (mweb_migration_write_failed) {
        // Do not open a wallet after failing to remove a persisted output
        // spend key. Otherwise a later ordinary coin write could overwrite
        // the legacy record and lose the signal that a full scrub is needed.
        return migrated_persisted_spend_key ? DBErrors::LOAD_FAIL : DBErrors::NONCRITICAL_ERROR;
    }

    for (const uint256& hash : wss.vWalletUpgrade)
        WriteTx(pwallet->mapWallet.at(hash));

    for (const uint256& hash : wss.vWalletRemove) {
        EraseTx(hash);
    }

    if (!has_last_client || last_client != CLIENT_VERSION) // Update
        m_batch->Write(DBKeys::VERSION, CLIENT_VERSION);
    
    if (wss.fAnyUnordered)
        result = pwallet->ReorderTransactions();

    // Upgrade all of the wallet keymetadata to have the hd master key id
    // This operation is not atomic, but if it fails, updated entries are still backwards compatible with older software
    try {
        pwallet->UpgradeKeyMetadata();
    } catch (...) {
        result = DBErrors::CORRUPT;
    }

    // Upgrade all of the descriptor caches to cache the last hardened xpub
    // This operation is not atomic, but if it fails, only new entries are added so it is backwards compatible
    try {
        pwallet->UpgradeDescriptorCache();
    } catch (const std::exception& e) {
        result = DBErrors::CORRUPT;
    }
    
    // Set the inactive chain
    if (wss.m_hd_chains.size() > 0) {
        LegacyScriptPubKeyMan* legacy_spkm = pwallet->GetLegacyScriptPubKeyMan();
        if (!legacy_spkm) {
            pwallet->WalletLogPrintf("Inactive HD Chains found but no Legacy ScriptPubKeyMan\n");
            return DBErrors::CORRUPT;
        }
        for (const auto& chain_pair : wss.m_hd_chains) {
            if (chain_pair.first != pwallet->GetLegacyScriptPubKeyMan()->GetHDChain().seed_id) {
                pwallet->GetLegacyScriptPubKeyMan()->AddInactiveHDChain(chain_pair.second);
            }
        }
    }

    if (result == DBErrors::LOAD_OK && (wss.m_mweb_spend_key_scrub_required || migrated_persisted_spend_key)) {
        return DBErrors::NEED_REWRITE;
    }

    return result;
}

DBErrors WalletBatch::FindWalletTx(std::vector<uint256>& vTxHash, std::list<CWalletTx>& vWtx)
{
    DBErrors result = DBErrors::LOAD_OK;

    try {
        int nMinVersion = 0;
        if (m_batch->Read(DBKeys::MINVERSION, nMinVersion)) {
            if (nMinVersion > FEATURE_LATEST)
                return DBErrors::TOO_NEW;
        }

        // Get cursor
        if (!m_batch->StartCursor())
        {
            LogPrintf("Error getting wallet database cursor\n");
            return DBErrors::CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            bool complete;
            bool ret = m_batch->ReadAtCursor(ssKey, ssValue, complete);
            if (complete) {
                break;
            } else if (!ret) {
                m_batch->CloseCursor();
                LogPrintf("Error reading next record from wallet database\n");
                return DBErrors::CORRUPT;
            }

            std::string strType;
            ssKey >> strType;
            if (strType == DBKeys::TX) {
                uint256 hash;
                ssKey >> hash;
                vTxHash.push_back(hash);
                vWtx.emplace_back(/*tx=*/nullptr, TxStateInactive{}, std::nullopt);
                ssValue >> vWtx.back();
            }
        }
    } catch (...) {
        result = DBErrors::CORRUPT;
    }
    m_batch->CloseCursor();

    return result;
}

DBErrors WalletBatch::ZapSelectTx(std::vector<uint256>& vTxHashIn, std::vector<uint256>& vTxHashOut)
{
    // build list of wallet TXs and hashes
    std::vector<uint256> vTxHash;
    std::list<CWalletTx> vWtx;
    DBErrors err = FindWalletTx(vTxHash, vWtx);
    if (err != DBErrors::LOAD_OK) {
        return err;
    }

    std::sort(vTxHash.begin(), vTxHash.end());
    std::sort(vTxHashIn.begin(), vTxHashIn.end());

    // erase each matching wallet TX
    bool delerror = false;
    std::vector<uint256>::iterator it = vTxHashIn.begin();
    for (const uint256& hash : vTxHash) {
        while (it < vTxHashIn.end() && (*it) < hash) {
            it++;
        }
        if (it == vTxHashIn.end()) {
            break;
        }
        else if ((*it) == hash) {
            if(!EraseTx(hash)) {
                LogPrint(BCLog::WALLETDB, "Transaction was found for deletion but returned database error: %s\n", hash.GetHex());
                delerror = true;
            }
            vTxHashOut.push_back(hash);
        }
    }

    if (delerror) {
        return DBErrors::CORRUPT;
    }
    return DBErrors::LOAD_OK;
}

void MaybeCompactWalletDB(WalletContext& context)
{
    static std::atomic<bool> fOneThread(false);
    if (fOneThread.exchange(true)) {
        return;
    }

    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        WalletDatabase& dbh = pwallet->GetDatabase();

        unsigned int nUpdateCounter = dbh.nUpdateCounter;

        if (dbh.nLastSeen != nUpdateCounter) {
            dbh.nLastSeen = nUpdateCounter;
            dbh.nLastWalletUpdate = GetTime();
        }

        if (dbh.nLastFlushed != nUpdateCounter && GetTime() - dbh.nLastWalletUpdate >= 2) {
            if (dbh.PeriodicFlush()) {
                dbh.nLastFlushed = nUpdateCounter;
            }
        }
    }

    fOneThread = false;
}

bool WalletBatch::WriteDestData(const std::string &address, const std::string &key, const std::string &value)
{
    return WriteIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(address, key)), value);
}

bool WalletBatch::EraseDestData(const std::string &address, const std::string &key)
{
    return EraseIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(address, key)));
}


bool WalletBatch::WriteHDChain(const CHDChain& chain)
{
    return WriteIC(DBKeys::HDCHAIN, chain);
}

bool WalletBatch::WriteWalletFlags(const uint64_t flags)
{
    return WriteIC(DBKeys::FLAGS, flags);
}

bool WalletBatch::EraseRecords(const std::unordered_set<std::string>& types)
{
    // Get cursor
    if (!m_batch->StartCursor())
    {
        return false;
    }

    // Iterate the DB and look for any records that have the type prefixes
    while (true)
    {
        // Read next record
        CDataStream key(SER_DISK, CLIENT_VERSION);
        CDataStream value(SER_DISK, CLIENT_VERSION);
        bool complete;
        bool ret = m_batch->ReadAtCursor(key, value, complete);
        if (complete) {
            break;
        }
        else if (!ret)
        {
            m_batch->CloseCursor();
            return false;
        }

        // Make a copy of key to avoid data being deleted by the following read of the type
        Span<const unsigned char> key_data = MakeUCharSpan(key);

        std::string type;
        key >> type;

        if (types.count(type) > 0) {
            m_batch->Erase(key_data);
        }
    }
    m_batch->CloseCursor();
    return true;
}

bool WalletBatch::TxnBegin()
{
    return m_batch->TxnBegin();
}

bool WalletBatch::TxnCommit()
{
    return m_batch->TxnCommit();
}

bool WalletBatch::TxnAbort()
{
    return m_batch->TxnAbort();
}

std::unique_ptr<WalletDatabase> MakeDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error)
{
    bool exists;
    try {
        exists = fs::symlink_status(path).type() != fs::file_type::not_found;
    } catch (const fs::filesystem_error& e) {
        error = Untranslated(strprintf("Failed to access database path '%s': %s", fs::PathToString(path), fsbridge::get_filesystem_error_message(e)));
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }

    std::optional<DatabaseFormat> format;
    if (exists) {
        if (IsBDBFile(BDBDataFile(path))) {
            format = DatabaseFormat::BERKELEY;
        }
        if (IsSQLiteFile(SQLiteDataFile(path))) {
            if (format) {
                error = Untranslated(strprintf("Failed to load database path '%s'. Data is in ambiguous format.", fs::PathToString(path)));
                status = DatabaseStatus::FAILED_BAD_FORMAT;
                return nullptr;
            }
            format = DatabaseFormat::SQLITE;
        }
    } else if (options.require_existing) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Path does not exist.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_NOT_FOUND;
        return nullptr;
    }

    if (!format && options.require_existing) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Data is not in recognized format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

    if (format && options.require_create) {
        error = Untranslated(strprintf("Failed to create database path '%s'. Database already exists.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_ALREADY_EXISTS;
        return nullptr;
    }

    // A db already exists so format is set, but options also specifies the format, so make sure they agree
    if (format && options.require_format && format != options.require_format) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Data is not in required format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

    // Format is not set when a db doesn't already exist, so use the format specified by the options if it is set.
    if (!format && options.require_format) format = options.require_format;

    // If the format is not specified or detected, choose the default format based on what is available. We prefer BDB over SQLite for now.
    if (!format) {
#ifdef USE_SQLITE
        format = DatabaseFormat::SQLITE;
#endif
#ifdef USE_BDB
        format = DatabaseFormat::BERKELEY;
#endif
    }

    if (format == DatabaseFormat::SQLITE) {
#ifdef USE_SQLITE
        return MakeSQLiteDatabase(path, options, status, error);
#endif
        error = Untranslated(strprintf("Failed to open database path '%s'. Build does not support SQLite database format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

#ifdef USE_BDB
    return MakeBerkeleyDatabase(path, options, status, error);
#endif
    error = Untranslated(strprintf("Failed to open database path '%s'. Build does not support Berkeley DB database format.", fs::PathToString(path)));
    status = DatabaseStatus::FAILED_BAD_FORMAT;
    return nullptr;
}

/** Return object for accessing dummy database with no read/write capabilities. */
std::unique_ptr<WalletDatabase> CreateDummyWalletDatabase()
{
    return std::make_unique<DummyDatabase>();
}

/** Return object for accessing temporary in-memory database. */
std::unique_ptr<WalletDatabase> CreateMockWalletDatabase(DatabaseOptions& options)
{

    std::optional<DatabaseFormat> format;
    if (options.require_format) format = options.require_format;
    if (!format) {
#ifdef USE_BDB
        format = DatabaseFormat::BERKELEY;
#endif
#ifdef USE_SQLITE
        format = DatabaseFormat::SQLITE;
#endif
    }

    if (format == DatabaseFormat::SQLITE) {
#ifdef USE_SQLITE
        return std::make_unique<SQLiteDatabase>(":memory:", "", options, true);
#endif
        assert(false);
    }

#ifdef USE_BDB
    return std::make_unique<BerkeleyDatabase>(std::make_shared<BerkeleyEnvironment>(), "", options);
#endif
    assert(false);
}

std::unique_ptr<WalletDatabase> CreateMockWalletDatabase()
{
    DatabaseOptions options;
    return CreateMockWalletDatabase(options);
}
} // namespace wallet
