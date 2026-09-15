#include <mw/node/CoinsView.h>

#include <mw/db/CoinDB.h>
#include <mw/db/MMRInfoDB.h>
#include <mw/db/LeafDB.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/mmr/PruneList.h>
#include <mw/mmr/MMRUtil.h>
#include <mw/crypto/Hasher.h>

#include "CoinActions.h"

#include <span.h>
#include <streams.h>
#include <util/strencodings.h>
#include <algorithm>
#include <limits>

using namespace mw;

namespace {

static constexpr uint8_t MWEB_DB_FORMAT_RAW_VALUES{1};
static constexpr size_t MWEB_DB_MIGRATION_BATCH_SIZE{10000};
const std::string MWEB_DB_FORMAT_KEY{"mweb/db_format"};
const std::string MWEB_DB_MIGRATION_PROGRESS_KEY{"mweb/db_migration_progress"};

void CleanupPruneLists(const FilePath& dir, const uint32_t current_index)
{
    // Publication can precede a crash that leaves older, nonconsecutive prune
    // generations behind. Only the file named by current metadata is live.
    for (const auto& entry : fs::directory_iterator(fs::u8path(dir.ToString()))) {
        const auto name = entry.path().filename().u8string();
        if (name.size() < 14 || name.compare(0, 4, "prun") != 0 || name.compare(name.size() - 4, 4, ".dat") != 0) {
            continue;
        }

        uint32_t index;
        if (ParseUInt32(name.substr(4, name.size() - 8), &index)) {
            if (name == StringUtil::Format("prun{:0>6}.dat", index) && index < current_index && entry.is_regular_file()) {
                FilePath(entry.path()).Remove();
            }
        }
    }
}

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
    if (pBestHeader && !current_mmr_info) {
        throw dbwrapper_error("Missing or unreadable MWEB MMR metadata");
    }

    if (current_mmr_info) {
        if (current_mmr_info->version > 2 ||
            (current_mmr_info->compacted && current_mmr_info->version < 2) ||
            (current_mmr_info->compact_index != 0 && !current_mmr_info->compacted)) {
            throw dbwrapper_error("Unsupported MWEB compaction metadata");
        }
    }

    const uint32_t file_index = current_mmr_info ? current_mmr_info->index : 0;
    const uint32_t compact_index = current_mmr_info ? current_mmr_info->compact_index : 0;

    if (current_mmr_info && current_mmr_info->compacted) {
        FilePath leafset_path = LeafSet::GetPath(datadir, file_index);
        if (compact_index == 0 || compact_index > file_index || current_mmr_info->compacted->GetHeight() < 0 ||
            !leafset_path.IsFile() || !PMMR::GetPath(datadir, 'O', file_index).IsFile() || File(leafset_path).GetSize() < 8) {
            throw dbwrapper_error("Missing compacted MWEB files or invalid horizon");
        }
    }

    auto pLeafSet = LeafSet::Open(datadir, file_index);
    auto pPruneList = PruneList::Open(datadir, compact_index);
    const uint64_t minimum_leaves = current_mmr_info && current_mmr_info->compacted ? current_mmr_info->compacted->GetNumTXOs() : 0;
    auto pOutputMMR = PMMR::Open('O', datadir, file_index, pDBWrapper, pPruneList, minimum_leaves);
    auto pView = std::shared_ptr<CoinsViewDB>(new CoinsViewDB(datadir, pBestHeader, pDBWrapper, pLeafSet, pOutputMMR));
    if (current_mmr_info && current_mmr_info->compacted) {
        pView->m_compactedHeight = current_mmr_info->compacted->GetHeight();
        if (!pBestHeader || pBestHeader->GetHeight() < *pView->m_compactedHeight ||
                pBestHeader->GetNumTXOs() < minimum_leaves ||
                pBestHeader->GetNumTXOs() != pOutputMMR->GetNumLeaves() ||
                pBestHeader->GetNumTXOs() != pLeafSet->GetNextLeafIdx().Get() ||
                pBestHeader->GetOutputRoot() != pOutputMMR->Root() ||
                pBestHeader->GetLeafsetRoot() != pLeafSet->Root() ||
                pBestHeader->GetHash() != current_mmr_info->pruned) {
            throw dbwrapper_error("Inconsistent compacted MWEB chainstate");
        }
    }

    return pView;
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

bool CoinsViewDB::NeedsCompaction(const int32_t height) const
{
    const auto info = MMRInfoDB(GetDatabase()).GetLatest();
    return !info || !info->compacted || height > info->compacted->GetHeight() ||
        (height == info->compacted->GetHeight() && info->cleanup_pending);
}

void CoinsViewDB::Compact(const mw::Header::CPtr& horizon, const BitSet& retained_leaves)
{
    const auto best = GetBestHeader();
    auto info = MMRInfoDB(GetDatabase()).GetLatest();
    if (!horizon || !best || !info || horizon->GetHeight() > best->GetHeight() ||
            horizon->GetNumTXOs() != retained_leaves.size() ||
            horizon->GetLeafsetRoot() != Hashed(retained_leaves.bytes()) ||
            m_pOutputPMMR->GetNumLeaves() != best->GetNumTXOs() ||
            m_pOutputPMMR->Root() != best->GetOutputRoot()) {
        throw std::runtime_error("Invalid MWEB compaction horizon or unflushed chainstate");
    }

    if (info->compacted && (horizon->GetHeight() < info->compacted->GetHeight() ||
            (horizon->GetHeight() == info->compacted->GetHeight() && horizon->GetHash() != info->compacted->GetHash()))) {
        throw std::runtime_error("MWEB compaction horizon must advance on the same chain");
    }

    if (!NeedsCompaction(horizon->GetHeight())) {
        return;
    }

    PMMRCache historical(m_pOutputPMMR);
    historical.Rewind(horizon->GetNumTXOs());
    if (historical.Root() != horizon->GetOutputRoot()) {
        throw std::runtime_error("MWEB compaction horizon has a different output history");
    }

    for (uint64_t i = 0; i < retained_leaves.size(); ++i) {
        if (!retained_leaves.test(i) && m_pLeafSet->Contains(mmr::LeafIndex::At(i))) {
            throw std::runtime_error("MWEB compaction would remove an unspent output");
        }
    }

    if (!info->compacted || horizon->GetHeight() > info->compacted->GetHeight()) {
        MMRInfo next = GetNextMMRInfo(nullptr);
        const auto compacted = MMRUtil::BuildCompactBitSet(retained_leaves.size(), retained_leaves);
        auto mmr = m_pOutputPMMR->Compact(next.index, compacted, retained_leaves.size());
        auto leafset = m_pLeafSet->Copy(next.index);
        next.version = 2;
        next.compact_index = next.index;
        next.compacted = *horizon;
        next.cleanup_pending = true;
        CDBBatch batch(*GetDatabase());
        SaveMMRInfo(&batch, next);
        if (!GetDatabase()->WriteBatch(batch, true)) {
            throw dbwrapper_error("Failed to publish MWEB compaction");
        }

        // Both new files and the prune list are durable. Publish using nonthrowing
        // swaps so existing cache layers keep referring to the same base objects.
        m_pOutputPMMR->Adopt(*mmr);
        m_pLeafSet->Adopt(*leafset);
        m_compactedHeight = next.compacted->GetHeight();
        *info = std::move(next);
        mmr.reset();
        leafset.reset();
    }
    Compact();
    CleanupPruneLists(m_datadir, info->compact_index);

    // The durable horizon makes these rows unreachable. Delete in bounded
    // batches; a crash leaves cleanup_pending set and replaying deletions is safe.
    constexpr size_t DELETE_BATCH_SIZE{10000};
    std::vector<mmr::LeafIndex> spent;
    spent.reserve(DELETE_BATCH_SIZE);
    const auto remove_spent = [&] {
        CDBBatch batch(*GetDatabase());
        LeafDB('O', GetDatabase(), &batch).Remove(spent);
        if (!GetDatabase()->WriteBatch(batch, true)) {
            throw dbwrapper_error("Failed to compact MWEB leaf records");
        }
        spent.clear();
    };
    for (uint64_t i = 0; i < retained_leaves.size(); ++i) {
        if (!retained_leaves.test(i)) {
            spent.push_back(mmr::LeafIndex::At(i));
        }
        if (spent.size() == DELETE_BATCH_SIZE) {
            remove_spent();
        }
    }
    if (!spent.empty()) {
        remove_spent();
    }

    info->cleanup_pending = false;
    CDBBatch batch(*GetDatabase());
    SaveMMRInfo(&batch, *info);
    if (!GetDatabase()->WriteBatch(batch, true)) {
        throw dbwrapper_error("Failed to finalize MWEB compaction");
    }
}

MMRInfo CoinsViewDB::GetNextMMRInfo(CDBBatch* pBatch) const
{
    MMRInfo mmr_info;
    auto current_mmr_info = MMRInfoDB(GetDatabase(), pBatch).GetLatest();
    if (current_mmr_info) {
        mmr_info = *current_mmr_info;
    }

    if (mmr_info.index >= std::numeric_limits<uint32_t>::max() - 1) {
        throw dbwrapper_error("MWEB file generation index exhausted");
    }
    ++mmr_info.index;
    mmr_info.pruned = GetBestHeader() ? GetBestHeader()->GetHash() : mw::Hash{};
    return mmr_info;
}

void CoinsViewDB::SaveMMRInfo(CDBBatch* pBatch, const MMRInfo& mmr_info)
{
    MMRInfoDB(GetDatabase(), pBatch).Save(mmr_info);
}
