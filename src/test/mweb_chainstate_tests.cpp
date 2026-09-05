// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <mw/crypto/Blinds.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/models/tx/MutableTx.h>
#include <mw/node/CoinsView.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <timedata.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <util/time.h>
#include <validation.h>

#include <test_framework/TxBuilder.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

constexpr CAmount DEPOSIT{10 * COIN};
constexpr CAmount MWEB_FEE{10'000};
constexpr CAmount CANONICAL_FEE{20'000};
constexpr size_t DB_CACHE_BYTES{1 << 20};

// Retain the recipient keys so all chained spends have valid signatures and
// match the receiver key and commitment of the actual previous output.
struct Transactions
{
    SecretKey spend_key{SecretKey::Random()};
    SecretKey sender_key{SecretKey::Random()};
    StealthAddress address{PublicKey::From(SecretKey::Random()), PublicKey::From(spend_key)};

    test::Tx Pegin(const CAmount amount = DEPOSIT) const
    {
        const auto output = test::TxOutput::Create(sender_key, address, amount - MWEB_FEE);
        const auto blind = BlindingFactor::Random();
        const auto kernel = mw::Kernel::Create(blind, std::nullopt, MWEB_FEE, amount, {}, std::nullopt, {});
        return test::Tx{mw::Transaction::Create(Blinds(output.GetBlind()).Sub(blind).Total(), sender_key,
            {}, {output.GetOutput()}, {kernel}), {output}};
    }

    test::Tx Spend(const test::TxOutput& output, const std::vector<PegOutCoin>& pegouts = {}) const
    {
        const auto key = mw::DeriveOutputSpendKey(spend_key, mw::DeriveSharedSecret(sender_key, address, output.GetAmount()));
        test::TxBuilder builder;
        builder.AddInput(output.GetAmount(), key, output.GetBlind(), output.GetOutputID());
        CAmount change = output.GetAmount() - MWEB_FEE;
        for (const auto& pegout : pegouts) change -= pegout.GetAmount();
        BOOST_REQUIRE_GE(change, 0);
        if (change > 0) builder.AddOutput(change, sender_key, address);
        if (pegouts.empty()) builder.AddPlainKernel(MWEB_FEE);
        else builder.AddPegoutKernel(pegouts, MWEB_FEE);
        return builder.Build();
    }
};

CMutableTransaction Wrap(const test::Tx& transaction)
{
    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*transaction.GetTransaction());
    for (const auto& pegin : transaction.GetPegIns()) {
        tx.vout.emplace_back(pegin.GetAmount(), GetScriptForPegin(pegin.GetKernelID()));
    }
    return tx;
}

void CheckCoin(const CCoinsView& view, const test::TxOutput& output, const int height)
{
    mw::Coin::CPtr coin;
    BOOST_REQUIRE(view.HaveCoin(output.GetOutputID()));
    BOOST_REQUIRE(view.GetMWEBCoin(output.GetOutputID(), coin));
    BOOST_REQUIRE(coin);
    BOOST_CHECK_EQUAL(coin->GetBlockHeight(), height);
    BOOST_CHECK(coin->GetOutput().Serialized() == output.GetOutput().Serialized());
    BOOST_CHECK(view.GetMWEBView()->GetLeafSet()->Contains(coin->GetLeafIndex()));
}

void CheckMissing(const CCoinsView& view, const test::TxOutput& output)
{
    mw::Coin::CPtr coin;
    BOOST_CHECK(!view.HaveCoin(output.GetOutputID()));
    BOOST_CHECK(!view.GetMWEBCoin(output.GetOutputID(), coin));
}

void CheckRoots(const CCoinsView& view, const mw::Header::CPtr& header)
{
    const auto mweb = view.GetMWEBView();
    BOOST_REQUIRE(mweb);
    if (header) {
        BOOST_REQUIRE(mweb->GetBestHeader());
        BOOST_CHECK(*mweb->GetBestHeader() == *header);
        BOOST_CHECK(mweb->GetOutputPMMR()->Root() == header->GetOutputRoot());
        BOOST_CHECK_EQUAL(mweb->GetOutputPMMR()->GetNumLeaves(), header->GetNumTXOs());
        BOOST_CHECK(mweb->GetLeafSet()->Root() == header->GetLeafsetRoot());
    } else {
        BOOST_CHECK(!mweb->GetBestHeader());
        BOOST_CHECK_EQUAL(mweb->GetOutputPMMR()->GetNumLeaves(), 0U);
        BOOST_CHECK(mweb->GetLeafSet()->Root() == Hashed(std::vector<uint8_t>{}));
    }
}

struct AppliedBlock
{
    mw::Block::CPtr block;
    mw::BlockUndo::CPtr undo;
    uint256 Hash() const { return uint256{block->GetHash().vec()}; }
};

AppliedBlock Apply(CCoinsViewCache& view, const std::vector<test::Tx>& transactions)
{
    const auto mweb = view.GetMWEBCacheView();
    const int height = mweb->GetBestHeader() ? mweb->GetBestHeader()->GetHeight() + 1 : 100;
    std::vector<mw::Transaction::CPtr> txs;
    for (const auto& tx : transactions) txs.push_back(tx.GetTransaction());
    const auto block = mw::CoinsViewCache(mweb).BuildNextBlock(height, txs);
    const auto undo = mweb->ApplyBlock(block);
    view.SetBestBlock(uint256{block->GetHash().vec()});
    return {block, undo};
}

// A real LevelDB plus MWEB MMR/leafset files, with the same paired cache used by
// chainstate. Reopening releases both views before opening the committed state.
class MWEBViewTestingSetup : public BasicTestingSetup
{
public:
    MWEBViewTestingSetup() : BasicTestingSetup{CBaseChainParams::REGTEST} { Reopen(nullptr); }

    void Reopen(const mw::Header::CPtr& header)
    {
        m_cache.reset();
        m_db.reset();
        m_db = std::make_unique<CCoinsViewDB>(m_path_root / "coins", DB_CACHE_BYTES, false, false);
        m_db->SetMWEBView(mw::CoinsViewDB::Open(m_path_root / "mweb", header, m_db->GetDB()));
        m_cache = std::make_unique<CCoinsViewCache>(m_db.get());
    }

    COutPoint AddCanonical(CCoinsViewCache& view, const bool pegout = false)
    {
        const COutPoint outpoint{InsecureRand256(), 0};
        view.AddCoin(outpoint, Coin{CTxOut{COIN, P2WSH_OP_TRUE}, 100, false, pegout}, false);
        return outpoint;
    }

    Transactions m_txs;
    std::unique_ptr<CCoinsViewDB> m_db;
    std::unique_ptr<CCoinsViewCache> m_cache;
};

// Inject a failure at the MWEB write boundary without depending on filesystem
// permissions or altering production code. All reads use the real backing view.
class FailingMWEBView : public mw::ICoinsView
{
public:
    explicit FailingMWEBView(const mw::ICoinsView::Ptr& base)
        : ICoinsView(base->GetBestHeader(), base->GetDatabase()), m_base(base) {}
    bool IsCache() const noexcept override { return false; }
    mw::Coin::CPtr GetCoin(const mw::Hash& id) const override { return m_base->GetCoin(id); }
    void AddCoin(uint64_t height, const mw::Output& output) override { m_base->AddCoin(height, output); }
    mw::Coin::CPtr SpendCoin(const mw::Hash& id) override { return m_base->SpendCoin(id); }
    void WriteBatch(CDBBatch*, const CoinsViewUpdates&, const mw::Header::CPtr&) override { throw std::runtime_error("injected MWEB write failure"); }
    ILeafSet::Ptr GetLeafSet() const noexcept override { return m_base->GetLeafSet(); }
    IMMR::Ptr GetOutputPMMR() const noexcept override { return m_base->GetOutputPMMR(); }
    bool HasCoinInCache(const mw::Hash& id) const noexcept override { return m_base->HasCoinInCache(id); }
    void Compact() const override { m_base->Compact(); }
    MMRInfo GetNextMMRInfo(CDBBatch* batch) const override { return m_base->GetNextMMRInfo(batch); }
    void SaveMMRInfo(CDBBatch* batch, const MMRInfo& info) override { m_base->SaveMMRInfo(batch, info); }
private:
    mw::ICoinsView::Ptr m_base;
};

struct MinedBlock
{
    CBlockIndex* index;
    CBlock block;
};

class MWEBChainstateTestingSetup : public TestingSetup
{
public:
    MWEBChainstateTestingSetup()
        : TestingSetup{CBaseChainParams::REGTEST, {"-acceptnonstdtxn=0", "-vbparams=mweb:-1:9223372036854775807:0:0"}}
    {
        SetMockTime(1'601'450'001);
        {
            LOCK(cs_main);
            ReopenCoins(/*wipe=*/true);
            auto& coins = State().CoinsTip();
            auto* genesis = State().m_chain.Tip();
            coins.SetBestBlock(genesis->GetBlockHash());
            // ALWAYS_ACTIVE needs a previous HogAddr. Seed only an empty genesis
            // MWEB state; every subsequent transition uses real mined blocks.
            const auto empty = mw::CoinsViewCache(coins.GetMWEBView()).BuildNextBlock(0, {});
            coins.GetMWEBCacheView()->ApplyBlock(empty);
            genesis->mweb_header = empty->GetHeader();
            genesis->hogex_hash = uint256::ONE;
            genesis->mweb_amount = 0;
            coins.AddCoin(COutPoint{genesis->hogex_hash, 0},
                Coin{CTxOut{0, CScript() << OP_8 << empty->GetHash().vec()}, 0, false}, false);
        }
        // Keep this anchor: legacy height-zero undo omits metadata needed to
        // restore the synthetic genesis HogAddr.
        m_anchor = Mine();
    }

    Chainstate& State() { return m_node.chainman->ActiveChainstate(); }

    CTransactionRef FundPegin(const test::Tx& pegin)
    {
        LOCK(cs_main);
        auto tx = Wrap(pegin);
        const COutPoint funding{InsecureRand256(), 0};
        tx.vin.emplace_back(funding);
        tx.vin.front().scriptWitness.stack = {WITNESS_STACK_ELEM_OP_TRUE};
        State().CoinsTip().AddCoin(funding,
            Coin{CTxOut{CTransaction{tx}.GetValueOut() + CANONICAL_FEE, P2WSH_OP_TRUE}, State().m_chain.Height(), false}, false);
        return MakeTransactionRef(tx);
    }

    MinedBlock Mine(const std::vector<CTransactionRef>& transactions = {})
    {
        for (const auto& tx : transactions) {
            const auto result = WITH_LOCK(cs_main, return m_node.chainman->ProcessTransaction(tx));
            BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
        }
        MineBlock(m_node, P2WSH_OP_TRUE);
        LOCK(cs_main);
        auto* tip = State().m_chain.Tip();
        CBlock block;
        BOOST_REQUIRE(node::ReadBlockFromDisk(block, tip, m_node.chainman->GetConsensus()));
        BOOST_REQUIRE(block.GetHogEx());
        return {tip, block};
    }

    void CheckTip(const MinedBlock& mined)
    {
        LOCK(cs_main);
        auto& view = State().CoinsTip();
        BOOST_REQUIRE(State().m_chain.Tip() == mined.index);
        BOOST_CHECK(view.GetBestBlock() == mined.index->GetBlockHash());
        BOOST_CHECK(mined.index->nStatus & BLOCK_HAVE_MWEB);
        BOOST_REQUIRE(mined.index->mweb_header);
        BOOST_CHECK(*mined.index->mweb_header == *mined.block.mweb_block.GetMWEBHeader());
        BOOST_CHECK(mined.index->hogex_hash == mined.block.GetHogEx()->GetHash());
        BOOST_CHECK_EQUAL(mined.index->mweb_amount, mined.block.GetHogEx()->vout.front().nValue);
        CheckRoots(view, mined.index->mweb_header);
        const auto& hogaddr = view.AccessCoin(COutPoint{mined.index->hogex_hash, 0});
        BOOST_REQUIRE(!hogaddr.IsSpent());
        BOOST_CHECK(!hogaddr.IsPegout());
        BOOST_CHECK(!hogaddr.IsCoinBase());
        BOOST_CHECK_EQUAL(hogaddr.nHeight, mined.index->nHeight);
        BOOST_CHECK(hogaddr.out == mined.block.GetHogEx()->vout.front());
    }

    void Invalidate(CBlockIndex* index)
    {
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(State().InvalidateBlock(state, index), state.ToString());
        // Mempool resurrection has its own suite. Keep fork construction here
        // independent of which disconnected transactions happen to be cached.
        m_node.mempool->clear();
    }

    void Reconsider(CBlockIndex* index)
    {
        WITH_LOCK(cs_main, State().ResetBlockFailureFlags(index));
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(State().ActivateBestChain(state), state.ToString());
    }

    void Flush()
    {
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(State().FlushStateToDisk(state, FlushStateMode::ALWAYS), state.ToString());
    }

    void ReopenCoins(const bool wipe = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        State().ResetCoinsViews();
        State().InitCoinsDB(DB_CACHE_BYTES, /*in_memory=*/false, wipe, "mweb_chainstate");
        State().InitCoinsCache(DB_CACHE_BYTES);
    }

    Transactions m_txs;
    MinedBlock m_anchor;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_chainstate_tests, MWEBViewTestingSetup)

// Views without an MWEB backend answer MWEB lookups as missing instead of dereferencing a nonexistent cache.
BOOST_AUTO_TEST_CASE(canonical_only_view_handles_mweb_lookups)
{
    CCoinsView base;
    CCoinsViewCache cache(&base);
    const auto tx = m_txs.Pegin();
    BOOST_CHECK(!cache.GetMWEBView());
    CheckMissing(cache, tx.GetOutputs().front());
}

// A child cache exposes newly connected MWEB and canonical coins without publishing either to the database.
BOOST_AUTO_TEST_CASE(unflushed_changes_are_visible_only_in_cache)
{
    const auto tx = m_txs.Pegin();
    const auto applied = Apply(*m_cache, {tx});
    const auto canonical = AddCanonical(*m_cache);
    CheckCoin(*m_cache, tx.GetOutputs().front(), 100);
    CheckMissing(*m_db, tx.GetOutputs().front());
    BOOST_CHECK(m_cache->HaveCoin(canonical));
    BOOST_CHECK(!m_db->HaveCoin(canonical));
    BOOST_CHECK(m_cache->GetBestBlock() == applied.Hash());
    BOOST_CHECK(m_db->GetBestBlock().IsNull());
    CheckRoots(*m_cache, applied.block->GetHeader());
}

// Flushing a nested cache publishes both kinds of coin and its tip to the parent, but not yet to disk.
BOOST_AUTO_TEST_CASE(nested_flush_updates_both_coin_views_and_tip)
{
    const auto tx = m_txs.Pegin();
    CCoinsViewCache child(m_cache.get());
    const auto applied = Apply(child, {tx});
    const auto canonical = AddCanonical(child);
    CheckMissing(*m_cache, tx.GetOutputs().front());
    BOOST_REQUIRE(child.Flush());
    CheckCoin(*m_cache, tx.GetOutputs().front(), 100);
    BOOST_CHECK(m_cache->HaveCoin(canonical));
    BOOST_CHECK(m_cache->GetBestBlock() == applied.Hash());
    CheckMissing(*m_db, tx.GetOutputs().front());
    BOOST_CHECK(!m_db->HaveCoin(canonical));
    CheckRoots(*m_cache, applied.block->GetHeader());
}

// Discarding a speculative spend leaves the parent coin, roots, and tip untouched.
BOOST_AUTO_TEST_CASE(discarded_child_does_not_publish_spends)
{
    const auto parent = m_txs.Pegin();
    const auto first = Apply(*m_cache, {parent});
    const auto spend = m_txs.Spend(parent.GetOutputs().front());
    {
        CCoinsViewCache child(m_cache.get());
        Apply(child, {spend});
        CheckMissing(child, parent.GetOutputs().front());
        CheckCoin(child, spend.GetOutputs().front(), 101);
    }
    CheckCoin(*m_cache, parent.GetOutputs().front(), 100);
    CheckMissing(*m_cache, spend.GetOutputs().front());
    BOOST_CHECK(m_cache->GetBestBlock() == first.Hash());
    CheckRoots(*m_cache, first.block->GetHeader());
}

// A cached MWEB spend masks a still-unspent database coin, including through another nested cache and Uncache calls.
BOOST_AUTO_TEST_CASE(mweb_spend_tombstone_prevents_read_through)
{
    const auto tx = m_txs.Pegin();
    Apply(*m_cache, {tx});
    BOOST_REQUIRE(m_cache->Flush());
    const auto& output = tx.GetOutputs().front();
    CheckCoin(*m_db, output, 100);
    m_cache->GetMWEBCacheView()->SpendCoin(output.GetOutputID());
    CCoinsViewCache child(m_cache.get());
    CheckMissing(*m_cache, output);
    CheckMissing(child, output);
    child.Uncache(output.GetOutputID());
    m_cache->Uncache(output.GetOutputID());
    CheckMissing(child, output);
    CheckCoin(*m_db, output, 100);
}

// MWEB availability is separate from the canonical HaveCoinInCache hint used during admission and uncaching.
BOOST_AUTO_TEST_CASE(mweb_availability_does_not_use_canonical_cache_hint)
{
    const auto tx = m_txs.Pegin();
    Apply(*m_cache, {tx});
    const auto& output = tx.GetOutputs().front();
    BOOST_CHECK(m_cache->GetMWEBCacheView()->HasCoinInCache(output.GetOutputID()));
    BOOST_CHECK(!m_cache->HaveCoinInCache(output.GetOutputID()));
    CheckCoin(*m_cache, output, 100);
}

// Switching a coins backend must rebuild its MWEB overlay instead of retaining outputs from the old backend.
BOOST_AUTO_TEST_CASE(backend_switch_replaces_mweb_overlay)
{
    const auto tx = m_txs.Pegin();
    Apply(*m_cache, {tx});
    CCoinsViewCache overlay(m_cache.get());
    CheckCoin(overlay, tx.GetOutputs().front(), 100);
    CCoinsView canonical_only;
    overlay.SetBackend(canonical_only);
    BOOST_CHECK(!overlay.GetMWEBView());
    CheckMissing(overlay, tx.GetOutputs().front());
    overlay.SetBackend(*m_cache);
    CheckCoin(overlay, tx.GetOutputs().front(), 100);
}

// UpdateCoins spends and creates both kinds of output in the paired canonical and MWEB caches.
BOOST_AUTO_TEST_CASE(update_coins_tracks_hybrid_spends_in_both_views)
{
    const auto funding = m_txs.Pegin();
    Apply(*m_cache, {funding});
    const auto canonical = AddCanonical(*m_cache, /*pegout=*/true);
    const auto spend = m_txs.Spend(funding.GetOutputs().front());
    auto hybrid = Wrap(spend);
    hybrid.vin.emplace_back(canonical);
    hybrid.vout.emplace_back(COIN - CANONICAL_FEE, P2WSH_OP_TRUE);
    const CTransaction tx{hybrid};
    BOOST_REQUIRE(m_cache->HaveInputs(tx));
    UpdateCoins(tx, *m_cache, 101);
    BOOST_CHECK(!m_cache->HaveInputs(tx));
    CheckMissing(*m_cache, funding.GetOutputs().front());
    CheckCoin(*m_cache, spend.GetOutputs().front(), 101);
    BOOST_CHECK(!m_cache->HaveCoin(canonical));
    BOOST_CHECK(m_cache->HaveCoin(COutPoint{tx.GetHash(), 0}));
}

// HogAddr is immediately spendable by the next HogEx; only subsequent HogEx outputs receive the peg-out maturity flag.
BOOST_AUTO_TEST_CASE(add_coins_distinguishes_hogaddr_from_pegouts)
{
    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vin.emplace_back(uint256::ONE, 0);
    hogex.vout = {{5 * COIN, CScript() << OP_8 << std::vector<uint8_t>(32, 1)},
                 {COIN, P2WSH_OP_TRUE}, {2 * COIN, P2WSH_OP_TRUE}};
    const CTransaction tx{hogex};
    AddCoins(*m_cache, tx, 100);
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& coin = m_cache->AccessCoin(COutPoint{tx.GetHash(), static_cast<uint32_t>(i)});
        BOOST_REQUIRE(!coin.IsSpent());
        BOOST_CHECK_EQUAL(coin.IsPegout(), i > 0);
        BOOST_CHECK(!coin.IsCoinBase());
        BOOST_CHECK_EQUAL(coin.nHeight, 100U);
    }
}

// An in-block MWEB parent/child spend leaves only the child unspent, and undo removes both newly created outputs.
BOOST_AUTO_TEST_CASE(in_block_spend_and_undo_restore_empty_view)
{
    const auto parent = m_txs.Pegin();
    const auto child = m_txs.Spend(parent.GetOutputs().front());
    const auto applied = Apply(*m_cache, {parent, child});
    CheckMissing(*m_cache, parent.GetOutputs().front());
    CheckCoin(*m_cache, child.GetOutputs().front(), 100);
    BOOST_REQUIRE_EQUAL(applied.undo->GetCoinsAdded().size(), 2U);
    BOOST_REQUIRE_EQUAL(applied.undo->GetCoinsSpent().size(), 1U);
    m_cache->GetMWEBCacheView()->UndoBlock(applied.undo);
    CheckMissing(*m_cache, parent.GetOutputs().front());
    CheckMissing(*m_cache, child.GetOutputs().front());
    CheckRoots(*m_cache, nullptr);
}

// A database flush and cold reopen retain canonical peg-out metadata, MWEB coins, both commitments, and the committed tip.
BOOST_AUTO_TEST_CASE(flush_and_reopen_preserve_paired_chainstate)
{
    const auto tx = m_txs.Pegin();
    const auto applied = Apply(*m_cache, {tx});
    const auto canonical = AddCanonical(*m_cache, /*pegout=*/true);
    BOOST_REQUIRE(m_cache->Flush());
    Reopen(applied.block->GetHeader());
    BOOST_CHECK(m_db->GetBestBlock() == applied.Hash());
    BOOST_CHECK(m_db->GetHeadBlocks().empty());
    CheckRoots(*m_db, applied.block->GetHeader());
    CheckCoin(*m_db, tx.GetOutputs().front(), 100);
    Coin coin;
    BOOST_REQUIRE(m_db->GetCoin(canonical, coin));
    BOOST_CHECK(coin.IsPegout());
    BOOST_CHECK_EQUAL(coin.nHeight, 100U);
    BOOST_CHECK_EQUAL(coin.out.nValue, COIN);
}

// A persisted spend stays spent after reopening, while its replacement keeps its height and MMR position.
BOOST_AUTO_TEST_CASE(persisted_spend_survives_reopen)
{
    const auto deposit = m_txs.Pegin();
    Apply(*m_cache, {deposit});
    BOOST_REQUIRE(m_cache->Flush());
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto applied = Apply(*m_cache, {spend});
    const auto expected_coin = m_cache->GetMWEBView()->GetCoin(spend.GetOutputs().front().GetOutputID());
    BOOST_REQUIRE(expected_coin);
    BOOST_REQUIRE(m_cache->Flush());
    Reopen(applied.block->GetHeader());
    CheckMissing(*m_cache, deposit.GetOutputs().front());
    CheckCoin(*m_cache, spend.GetOutputs().front(), 101);
    const auto recovered = m_db->GetMWEBView()->GetCoin(spend.GetOutputs().front().GetOutputID());
    BOOST_REQUIRE(recovered);
    BOOST_CHECK(recovered->GetLeafIndex() == expected_coin->GetLeafIndex());
    CheckRoots(*m_cache, applied.block->GetHeader());
}

// Undoing a persisted block restores the original coin and leaf index, and the restored state itself survives another reopen.
BOOST_AUTO_TEST_CASE(persisted_undo_restores_original_coin_and_roots)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Apply(*m_cache, {deposit});
    const auto original = m_cache->GetMWEBView()->GetCoin(deposit.GetOutputs().front().GetOutputID());
    BOOST_REQUIRE(m_cache->Flush());
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto second = Apply(*m_cache, {spend});
    BOOST_REQUIRE(m_cache->Flush());
    Reopen(second.block->GetHeader());
    m_cache->GetMWEBCacheView()->UndoBlock(second.undo);
    m_cache->SetBestBlock(first.Hash());
    BOOST_REQUIRE(m_cache->Flush());
    Reopen(first.block->GetHeader());
    CheckCoin(*m_cache, deposit.GetOutputs().front(), 100);
    CheckMissing(*m_cache, spend.GetOutputs().front());
    BOOST_CHECK(m_cache->GetMWEBView()->GetCoin(deposit.GetOutputs().front().GetOutputID())->GetLeafIndex() == original->GetLeafIndex());
    BOOST_CHECK(m_db->GetBestBlock() == first.Hash());
    CheckRoots(*m_cache, first.block->GetHeader());
}

// Rewinding the first persisted MWEB block must flush the now-null header and empty commitments, not leave old disk state behind.
BOOST_AUTO_TEST_CASE(rewinding_first_mweb_block_persists_empty_state)
{
    const auto tx = m_txs.Pegin();
    const auto first = Apply(*m_cache, {tx});
    BOOST_REQUIRE(m_cache->Flush());
    m_cache->GetMWEBCacheView()->UndoBlock(first.undo);
    m_cache->SetBestBlock(uint256::ONE);
    BOOST_REQUIRE(m_cache->Flush());
    Reopen(nullptr);
    CheckMissing(*m_db, tx.GetOutputs().front());
    CheckRoots(*m_db, nullptr);
    BOOST_CHECK(m_db->GetBestBlock() == uint256::ONE);
    const auto replacement = m_txs.Pegin(2 * COIN);
    const auto next = Apply(*m_cache, {replacement});
    BOOST_REQUIRE(m_cache->Flush());
    Reopen(next.block->GetHeader());
    CheckCoin(*m_db, replacement.GetOutputs().front(), 100);
    CheckMissing(*m_db, tx.GetOutputs().front());
}

// A late commitment failure must roll back tentative MWEB spends and additions, allowing the valid block to be retried.
BOOST_AUTO_TEST_CASE(failed_mweb_apply_is_atomic)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Apply(*m_cache, {deposit});
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto valid = mw::CoinsViewCache(m_cache->GetMWEBView()).BuildNextBlock(101, {spend.GetTransaction()});
    const auto bad_header = mw::MutHeader{valid->GetHeader()}.SetOutputRoot(mw::Hash{}).Build();
    const auto invalid = std::make_shared<mw::Block>(bad_header, valid->GetTxBody());
    BOOST_CHECK_EXCEPTION(m_cache->GetMWEBCacheView()->ApplyBlock(invalid), ValidationException,
        [](const auto& error) { return error.GetType() == EConsensusError::MMR_MISMATCH; });
    CheckCoin(*m_cache, deposit.GetOutputs().front(), 100);
    CheckMissing(*m_cache, spend.GetOutputs().front());
    CheckRoots(*m_cache, first.block->GetHeader());
    m_cache->GetMWEBCacheView()->ApplyBlock(valid);
    CheckMissing(*m_cache, deposit.GetOutputs().front());
    CheckCoin(*m_cache, spend.GetOutputs().front(), 101);
    CheckRoots(*m_cache, valid->GetHeader());
}

// An MWEB flush failure must not publish a new database tip or coins, and the database must refuse later flushes on that instance.
BOOST_AUTO_TEST_CASE(failed_mweb_flush_does_not_publish_and_latches_failure)
{
    const auto first_tx = m_txs.Pegin();
    const auto first = Apply(*m_cache, {first_tx});
    BOOST_REQUIRE(m_cache->Flush());
    const auto base = m_db->GetMWEBView();
    m_cache.reset();
    m_db->SetMWEBView(std::make_shared<FailingMWEBView>(base));
    m_cache = std::make_unique<CCoinsViewCache>(m_db.get());
    const auto second_tx = m_txs.Pegin(2 * COIN);
    const auto second = Apply(*m_cache, {second_tx});
    const auto canonical = AddCanonical(*m_cache);
    BOOST_CHECK(!m_cache->Flush());
    BOOST_CHECK(m_db->GetBestBlock() == first.Hash());
    BOOST_CHECK(m_db->GetHeadBlocks().empty());
    BOOST_CHECK(!m_db->HaveCoin(canonical));
    CheckMissing(*m_db, second_tx.GetOutputs().front());
    CheckCoin(*m_db, first_tx.GetOutputs().front(), 100);
    m_cache.reset();
    m_db->SetMWEBView(base);
    CCoinsViewCache retry(m_db.get());
    retry.SetBestBlock(second.Hash());
    BOOST_CHECK(!retry.Flush());
    BOOST_CHECK(m_db->GetBestBlock() == first.Hash());
}

// Mining an empty extension advances the paired tips and HogAddr while preserving the empty output commitments and zero supply.
BOOST_FIXTURE_TEST_CASE(empty_block_advances_chainstate_metadata, MWEBChainstateTestingSetup)
{
    const auto next = Mine();
    CheckTip(next);
    BOOST_CHECK_EQUAL(next.index->mweb_amount, 0);
    BOOST_CHECK_EQUAL(next.index->mweb_header->GetNumTXOs(), 0U);
    LOCK(cs_main);
    BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{m_anchor.index->hogex_hash, 0}));
}

// Connecting a peg-in consumes its canonical funding and bridge output and creates the corresponding MWEB coin and locked balance.
BOOST_FIXTURE_TEST_CASE(pegin_connect_updates_both_utxo_sets, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto tx = FundPegin(deposit);
    const auto mined = Mine({tx});
    CheckTip(mined);
    BOOST_CHECK_EQUAL(mined.index->mweb_amount, DEPOSIT - MWEB_FEE);
    LOCK(cs_main);
    CheckCoin(State().CoinsTip(), deposit.GetOutputs().front(), mined.index->nHeight);
    BOOST_CHECK(!State().CoinsTip().HaveCoin(tx->vin.front().prevout));
    BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{tx->GetHash(), 0}));
    BOOST_REQUIRE_EQUAL(mined.block.vtx.size(), 3U);
    BOOST_CHECK(!mined.block.vtx[1]->HasMWEBTx());
}

// A mined peg-out removes its MWEB input, creates MWEB change and a maturity-tagged canonical output, and reduces locked supply.
BOOST_FIXTURE_TEST_CASE(pegout_connect_updates_supply_and_coin_metadata, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    const auto withdrawal = m_txs.Spend(deposit.GetOutputs().front(), {{3 * COIN, P2WSH_OP_TRUE}});
    const auto second = Mine({MakeTransactionRef(Wrap(withdrawal))});
    CheckTip(second);
    BOOST_CHECK_EQUAL(second.index->mweb_amount, first.index->mweb_amount - 3 * COIN - MWEB_FEE);
    LOCK(cs_main);
    CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
    CheckCoin(State().CoinsTip(), withdrawal.GetOutputs().front(), second.index->nHeight);
    const auto& pegout = State().CoinsTip().AccessCoin(COutPoint{second.index->hogex_hash, 1});
    BOOST_REQUIRE(!pegout.IsSpent());
    BOOST_CHECK(pegout.IsPegout());
    BOOST_CHECK(!pegout.IsCoinBase());
    BOOST_CHECK_EQUAL(pegout.nHeight, second.index->nHeight);
    BOOST_CHECK_EQUAL(pegout.out.nValue, 3 * COIN);
}

// Invalidating and reconsidering a peg-out block restores and then reapplies both coin sets and exactly the same MWEB commitments.
BOOST_FIXTURE_TEST_CASE(disconnect_and_reconnect_restore_both_coin_sets, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    const auto withdrawal = m_txs.Spend(deposit.GetOutputs().front(), {{3 * COIN, P2WSH_OP_TRUE}});
    const auto second = Mine({MakeTransactionRef(Wrap(withdrawal))});
    Invalidate(second.index);
    CheckTip(first);
    {
        LOCK(cs_main);
        CheckCoin(State().CoinsTip(), deposit.GetOutputs().front(), first.index->nHeight);
        CheckMissing(State().CoinsTip(), withdrawal.GetOutputs().front());
        BOOST_CHECK(!State().CoinsTip().HaveCoin(COutPoint{second.index->hogex_hash, 1}));
    }
    Reconsider(second.index);
    CheckTip(second);
    LOCK(cs_main);
    CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
    CheckCoin(State().CoinsTip(), withdrawal.GetOutputs().front(), second.index->nHeight);
    BOOST_CHECK(State().CoinsTip().AccessCoin(COutPoint{second.index->hogex_hash, 1}).IsPegout());
}

// Persisted block undo contains the original MWEB coin and header and can still disconnect the block after reopening coin views.
BOOST_FIXTURE_TEST_CASE(disk_undo_remains_usable_after_coin_view_reopen, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto second = Mine({MakeTransactionRef(Wrap(spend))});
    Flush();
    {
        LOCK(cs_main);
        CBlockUndo undo;
        BOOST_REQUIRE(node::UndoReadFromDisk(undo, second.index));
        BOOST_REQUIRE(undo.mwundo);
        BOOST_REQUIRE(undo.mwundo->GetPreviousHeader());
        BOOST_CHECK(*undo.mwundo->GetPreviousHeader() == *first.index->mweb_header);
        BOOST_REQUIRE_EQUAL(undo.mwundo->GetCoinsSpent().size(), 1U);
        BOOST_CHECK(undo.mwundo->GetCoinsSpent().front()->GetOutputID() == deposit.GetOutputs().front().GetOutputID());
        ReopenCoins();
    }
    CheckTip(second);
    Invalidate(second.index);
    CheckTip(first);
    LOCK(cs_main);
    CheckCoin(State().CoinsTip(), deposit.GetOutputs().front(), first.index->nHeight);
}

// TestBlockValidity applies its MWEB work only to a temporary cache, leaving the active tip, coins, and roots untouched.
BOOST_FIXTURE_TEST_CASE(block_validity_check_does_not_publish_chainstate, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto tx = FundPegin(deposit);
    {
        LOCK(cs_main);
        const auto result = m_node.chainman->ProcessTransaction(tx);
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    const auto candidate = PrepareBlock(m_node, P2WSH_OP_TRUE);
    {
        LOCK(cs_main);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(TestBlockValidity(state, Params(), State(), *candidate, m_anchor.index,
            GetAdjustedTime, false, true), state.ToString());
        CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
        BOOST_CHECK(State().CoinsTip().HaveCoin(tx->vin.front().prevout));
    }
    CheckTip(m_anchor);
}

// An isolated view can rewind to an ancestor without changing the active chain or its UTXO and MWEB state.
BOOST_FIXTURE_TEST_CASE(arbitrary_ancestor_view_is_isolated, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    const auto spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto second = Mine({MakeTransactionRef(Wrap(spend))});
    LOCK(cs_main);
    CCoinsViewCache historical(&State().CoinsTip());
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(State().ActivateArbitraryChain(state, first.index, historical), state.ToString());
    BOOST_CHECK(historical.GetBestBlock() == first.index->GetBlockHash());
    CheckRoots(historical, first.index->mweb_header);
    CheckCoin(historical, deposit.GetOutputs().front(), first.index->nHeight);
    CheckMissing(historical, spend.GetOutputs().front());
    CheckTip(second);
    CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
    CheckCoin(State().CoinsTip(), spend.GetOutputs().front(), second.index->nHeight);
}

// An isolated fork view reconnects multiple blocks in order and advances its own best block after each connection.
BOOST_FIXTURE_TEST_CASE(arbitrary_fork_view_connects_multiple_blocks_without_publishing, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto fork = Mine({FundPegin(deposit)});
    const auto first_spend = m_txs.Spend(deposit.GetOutputs().front());
    const auto first = Mine({MakeTransactionRef(Wrap(first_spend))});
    const auto second_spend = m_txs.Spend(first_spend.GetOutputs().front());
    const auto second = Mine({MakeTransactionRef(Wrap(second_spend))});
    Invalidate(first.index);
    const auto alternate = m_txs.Spend(deposit.GetOutputs().front(), {{COIN, P2WSH_OP_TRUE}});
    const auto active = Mine({MakeTransactionRef(Wrap(alternate))});
    LOCK(cs_main);
    const auto old_status = second.index->nStatus;
    CCoinsViewCache branch(&State().CoinsTip());
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(State().ActivateArbitraryChain(state, second.index, branch), state.ToString());
    BOOST_CHECK(branch.GetBestBlock() == second.index->GetBlockHash());
    CheckRoots(branch, second.index->mweb_header);
    CheckMissing(branch, deposit.GetOutputs().front());
    CheckMissing(branch, first_spend.GetOutputs().front());
    CheckMissing(branch, alternate.GetOutputs().front());
    CheckCoin(branch, second_spend.GetOutputs().front(), second.index->nHeight);
    BOOST_CHECK(!branch.HaveCoin(COutPoint{active.index->hogex_hash, 1}));
    BOOST_CHECK_EQUAL(second.index->nStatus, old_status);
    BOOST_CHECK(first.index->pprev == fork.index);
    CheckTip(active);
    CheckCoin(State().CoinsTip(), alternate.GetOutputs().front(), active.index->nHeight);
    CheckMissing(State().CoinsTip(), second_spend.GetOutputs().front());
}

// An interrupted flush replays real blocks from the persisted old MWEB header and publishes matching canonical and MWEB tips.
BOOST_FIXTURE_TEST_CASE(replay_interrupted_flush_restores_mweb_and_canonical_state, MWEBChainstateTestingSetup)
{
    const auto deposit = m_txs.Pegin();
    const auto first = Mine({FundPegin(deposit)});
    Flush();
    const auto withdrawal = m_txs.Spend(deposit.GetOutputs().front(), {{COIN, P2WSH_OP_TRUE}});
    const auto second = Mine({MakeTransactionRef(Wrap(withdrawal))});
    {
        LOCK(cs_main);
        auto& db = State().CoinsDB();
        BOOST_REQUIRE(db.GetBestBlock() == first.index->GetBlockHash());
        // Match the on-disk transition markers written by CCoinsViewDB::BatchWrite.
        CDBBatch interrupted(*db.GetDB());
        interrupted.Erase(uint8_t{'B'}); // DB_BEST_BLOCK
        interrupted.Write(uint8_t{'H'}, std::vector<uint256>{second.index->GetBlockHash(), first.index->GetBlockHash()});
        BOOST_REQUIRE(db.GetDB()->WriteBatch(interrupted, true));
        ReopenCoins(); // Drop the unflushed tip, as a restart would.
    }
    BOOST_REQUIRE(State().ReplayBlocks());
    {
        LOCK(cs_main);
        BOOST_CHECK(State().CoinsDB().GetHeadBlocks().empty());
        BOOST_CHECK(State().CoinsDB().GetBestBlock() == second.index->GetBlockHash());
        ReopenCoins();
        CheckMissing(State().CoinsTip(), deposit.GetOutputs().front());
        CheckCoin(State().CoinsTip(), withdrawal.GetOutputs().front(), second.index->nHeight);
        BOOST_CHECK(State().CoinsTip().AccessCoin(COutPoint{second.index->hogex_hash, 1}).IsPegout());
    }
    CheckTip(second);
}

BOOST_AUTO_TEST_SUITE_END()
