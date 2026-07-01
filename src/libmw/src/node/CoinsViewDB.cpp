#include <mw/node/CoinsView.h>

#include <mw/db/CoinDB.h>
#include <mw/db/MMRInfoDB.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/mmr/PruneList.h>

#include "CoinActions.h"

#include <span.h>
#include <streams.h>
#include <algorithm>
#include <limits>

using namespace mw;

namespace {

static constexpr uint8_t MWEB_DB_FORMAT_RAW_VALUES{1};
static constexpr size_t MWEB_DB_MIGRATION_BATCH_SIZE{10000};
const std::string MWEB_DB_FORMAT_KEY{"mweb/db_format"};
const std::string MWEB_DB_MIGRATION_PROGRESS_KEY{"mweb/db_migration_progress"};

class DBStringKey
{
public:
    std::string key;

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> key;
    }
};

class LegacyVectorValue
{
public:
    std::vector<uint8_t> value;

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> value;
        if (!s.empty()) {
            throw std::ios_base::failure("Trailing bytes in legacy MWEB DB value");
        }
    }
};

class RawDBValue
{
public:
    explicit RawDBValue(Span<const uint8_t> bytes) : m_bytes(bytes) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(MakeByteSpan(m_bytes));
    }

private:
    Span<const uint8_t> m_bytes;
};

struct MWEBKeyPrefix
{
    size_t key_len;
    char key_prefix;

    std::string StartKey() const
    {
        std::string start(key_len, '\0');
        start.front() = key_prefix;
        return start;
    }
};

int CompareBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
    if (std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end())) return -1;
    if (std::lexicographical_compare(b.begin(), b.end(), a.begin(), a.end())) return 1;
    return 0;
}

std::vector<uint8_t> SerializedStringKeyPrefix(const size_t key_len, const char key_prefix)
{
    assert(key_len < 253);
    return {static_cast<uint8_t>(key_len), static_cast<uint8_t>(key_prefix)};
}

std::vector<uint8_t> PrefixEnd(std::vector<uint8_t> prefix)
{
    assert(!prefix.empty());
    assert(prefix.back() != std::numeric_limits<uint8_t>::max());
    ++prefix.back();
    return prefix;
}

std::vector<uint8_t> SerializedStringKey(const std::string& key)
{
    CDataStream stream(SER_DISK, CLIENT_VERSION);
    stream << key;
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(stream.data()),
        reinterpret_cast<const uint8_t*>(stream.data() + stream.size())
    );
}

bool MatchesKeyRange(const std::string& key, const MWEBKeyPrefix& prefix)
{
    return key.size() == prefix.key_len && key.front() == prefix.key_prefix;
}

bool IsDecimalDigit(const char c) noexcept
{
    return c >= '0' && c <= '9';
}

bool IsHexDigit(const char c) noexcept
{
    return (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F');
}

bool IsValidMWEBKey(const std::string& key, const MWEBKeyPrefix& prefix)
{
    if (!MatchesKeyRange(key, prefix)) {
        return false;
    }

    if (prefix.key_prefix == 'M' || prefix.key_prefix == 'O') {
        return std::all_of(key.cbegin() + 1, key.cend(), IsDecimalDigit);
    }

    if (prefix.key_prefix == 'U') {
        return std::all_of(key.cbegin() + 1, key.cend(), IsHexDigit);
    }

    return false;
}

std::vector<MWEBKeyPrefix> MWEBKeyPrefixes()
{
    std::vector<MWEBKeyPrefix> prefixes;

    // MMRInfo ('M') keys are a one-byte table prefix plus a uint32 decimal index.
    for (size_t key_len = 2; key_len <= 11; ++key_len) {
        prefixes.push_back({key_len, 'M'});
    }

    // Output PMMR leaf ('O') keys are a one-byte table prefix plus a uint64 decimal index.
    for (size_t key_len = 2; key_len <= 21; ++key_len) {
        prefixes.push_back({key_len, 'O'});
    }

    // CoinDB ('U') keys are 'U' plus a 32-byte output id encoded as 64 hex chars.
    prefixes.push_back({65, 'U'});

    std::sort(prefixes.begin(), prefixes.end(), [](const auto& a, const auto& b) {
        return CompareBytes(
            SerializedStringKeyPrefix(a.key_len, a.key_prefix),
            SerializedStringKeyPrefix(b.key_len, b.key_prefix)
        ) < 0;
    });
    return prefixes;
}

void MigrateMWEBDBValueFormat(CDBWrapper* pDBWrapper)
{
    if (pDBWrapper == nullptr) {
        return;
    }

    uint8_t db_format = 0;
    if (pDBWrapper->Read(MWEB_DB_FORMAT_KEY, db_format)) {
        if (db_format == MWEB_DB_FORMAT_RAW_VALUES) {
            return;
        }

        throw dbwrapper_error("Unsupported MWEB DB format: " + std::to_string(db_format));
    }

    std::string progress_key;
    bool has_progress = pDBWrapper->Read(MWEB_DB_MIGRATION_PROGRESS_KEY, progress_key);
    std::vector<uint8_t> progress_raw_key = has_progress ? SerializedStringKey(progress_key) : std::vector<uint8_t>{};

    const std::vector<MWEBKeyPrefix> prefixes = MWEBKeyPrefixes();
    while (true) {
        CDBBatch batch(*pDBWrapper);
        std::string last_migrated_key;
        size_t migrated_count = 0;
        bool reached_batch_limit = false;

        for (const MWEBKeyPrefix& prefix : prefixes) {
            const std::vector<uint8_t> prefix_start = SerializedStringKeyPrefix(prefix.key_len, prefix.key_prefix);
            const std::vector<uint8_t> prefix_end = PrefixEnd(prefix_start);
            if (has_progress && CompareBytes(progress_raw_key, prefix_end) >= 0) {
                continue;
            }

            const std::string seek_key =
                (has_progress && CompareBytes(progress_raw_key, prefix_start) > 0) ? progress_key : prefix.StartKey();

            std::unique_ptr<CDBIterator> iter(pDBWrapper->NewIterator());
            iter->Seek(seek_key);

            while (iter->Valid()) {
                DBStringKey logical_key;
                if (!iter->GetKey(logical_key)) {
                    break;
                }

                if (!MatchesKeyRange(logical_key.key, prefix)) {
                    break;
                }

                if (!IsValidMWEBKey(logical_key.key, prefix)) {
                    iter->Next();
                    continue;
                }

                const std::vector<uint8_t> raw_key = SerializedStringKey(logical_key.key);
                if (has_progress && CompareBytes(raw_key, progress_raw_key) <= 0) {
                    iter->Next();
                    continue;
                }

                LegacyVectorValue legacy_value;
                if (!iter->GetValue(legacy_value)) {
                    throw dbwrapper_error("Failed to migrate legacy MWEB DB row with key " + logical_key.key);
                }

                batch.Write(logical_key.key, RawDBValue(legacy_value.value));
                last_migrated_key = logical_key.key;
                ++migrated_count;

                if (migrated_count >= MWEB_DB_MIGRATION_BATCH_SIZE) {
                    reached_batch_limit = true;
                    break;
                }

                iter->Next();
            }

            if (reached_batch_limit) {
                break;
            }
        }

        if (migrated_count == 0) {
            break;
        }

        batch.Write(MWEB_DB_MIGRATION_PROGRESS_KEY, last_migrated_key);
        if (!pDBWrapper->WriteBatch(batch, true)) {
            throw dbwrapper_error("Failed to write MWEB DB migration batch");
        }

        progress_key = std::move(last_migrated_key);
        progress_raw_key = SerializedStringKey(progress_key);
        has_progress = true;
    }

    CDBBatch batch(*pDBWrapper);
    batch.Write(MWEB_DB_FORMAT_KEY, MWEB_DB_FORMAT_RAW_VALUES);
    batch.Erase(MWEB_DB_MIGRATION_PROGRESS_KEY);
    if (!pDBWrapper->WriteBatch(batch, true)) {
        throw dbwrapper_error("Failed to finalize MWEB DB migration");
    }
}

} // namespace

CoinsViewDB::Ptr CoinsViewDB::Open(
    const FilePath& datadir,
    const mw::Header::CPtr& pBestHeader,
    CDBWrapper* pDBWrapper)
{
    MigrateMWEBDBValueFormat(pDBWrapper);

    auto current_mmr_info = MMRInfoDB(pDBWrapper, nullptr).GetLatest();
    uint32_t file_index = current_mmr_info ? current_mmr_info->index : 0;
    uint32_t compact_index = current_mmr_info ? current_mmr_info->compact_index : 0;

    auto pLeafSet = LeafSet::Open(datadir, file_index);
    auto pPruneList = PruneList::Open(datadir, compact_index);
    auto pOutputMMR = PMMR::Open('O', datadir, file_index, pDBWrapper, pPruneList);
    auto pView = new CoinsViewDB(pBestHeader, pDBWrapper, pLeafSet, pOutputMMR);

    return std::shared_ptr<CoinsViewDB>(pView);
}

mw::Coin::CPtr CoinsViewDB::GetCoin(const mw::Hash& output_id) const
{
    CoinDB coinDB(GetDatabase(), nullptr);
    return GetCoin(coinDB, output_id);
}

mw::Coin::CPtr CoinsViewDB::GetCoin(const CoinDB& coinDB, const mw::Hash& output_id) const
{
    std::vector<uint8_t> value;

    auto coins_by_hash = coinDB.GetCoins({output_id});
    auto iter = coins_by_hash.find(output_id);
    if (iter != coins_by_hash.cend()) {
        return iter->second;
    }

    return {};
}

void CoinsViewDB::AddCoin(const uint64_t header_height, const mw::Output& output)
{
    CoinDB coinDB(GetDatabase(), nullptr);
    AddCoin(coinDB, output);
}

void CoinsViewDB::AddCoin(CoinDB& coinDB, const mw::Output& output)
{
    mmr::LeafIndex leafIdx = m_pOutputPMMR->Add(output.GetOutputID());
    m_pLeafSet->Add(leafIdx);

    AddCoin(coinDB, std::make_shared<mw::Coin>(GetBestHeader()->GetHeight(), std::move(leafIdx), output));
}

void CoinsViewDB::AddCoin(CoinDB& coinDB, const mw::Coin::CPtr& pCoin)
{
    coinDB.AddCoins(std::vector<mw::Coin::CPtr>{pCoin});
}

mw::Coin::CPtr CoinsViewDB::SpendCoin(const mw::Hash& output_id)
{
    CoinDB coinDB(GetDatabase(), nullptr);
    return SpendCoin(coinDB, output_id);
}

mw::Coin::CPtr CoinsViewDB::SpendCoin(CoinDB& coinDB, const mw::Hash& output_id)
{
    mw::Coin::CPtr pCoin = GetCoin(coinDB, output_id);
    if (pCoin == nullptr) {
		ThrowValidation(EConsensusError::UTXO_MISSING);
    }

    coinDB.RemoveCoins(std::vector<mw::Hash>{output_id});
    return pCoin;
}

void CoinsViewDB::WriteBatch(CDBBatch* pBatch, const CoinsViewUpdates& updates, const mw::Header::CPtr& pHeader)
{
    assert(pBatch != nullptr);
    SetBestHeader(pHeader);

    CoinDB coinDB(GetDatabase(), pBatch);
    for (const auto& actions : updates.GetActions()) {
        const mw::Hash& output_id = actions.first;
        for (const auto& action : actions.second) {
            if (action.IsSpend()) {
                SpendCoin(coinDB, output_id);
            } else {
                AddCoin(coinDB, action.pCoin);
            }
        }
    }
}

void CoinsViewDB::Compact() const
{
    auto current_mmr_info = MMRInfoDB(GetDatabase(), nullptr)
                                .GetLatest();
    if (current_mmr_info) {
        m_pLeafSet->Cleanup(current_mmr_info->index);
        m_pOutputPMMR->Cleanup(current_mmr_info->index);
    }
}

MMRInfo CoinsViewDB::GetNextMMRInfo(CDBBatch* pBatch) const
{
    MMRInfo mmr_info;
    auto current_mmr_info = MMRInfoDB(GetDatabase(), pBatch).GetLatest();
    if (current_mmr_info) {
        mmr_info = *current_mmr_info;
    }

    ++mmr_info.index;
    return mmr_info;
}

void CoinsViewDB::SaveMMRInfo(CDBBatch* pBatch, const MMRInfo& mmr_info)
{
    MMRInfoDB(GetDatabase(), pBatch).Save(mmr_info);
}
