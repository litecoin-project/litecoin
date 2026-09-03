// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <interfaces/chain.h>
#include <key_io.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/wallet/StealthAddress.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/txbuilder.h>
#include <wallet/txlist.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <list>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace wallet {
namespace {

class MWEBConflictTestingSetup : public TestChain100Setup
{
public:
    struct ChainTip {
        uint256 hash;
        int height;
    };

    struct Funding {
        CTransactionRef tx;
        mw::Hash output_id;
        CAmount amount;
        ChainTip scan_start;
    };

    struct TransparentFunding {
        CTransactionRef tx;
        COutPoint outpoint;
        CAmount amount;
    };

    struct Spend {
        CTransactionRef tx;
        mw::Hash change_id;
        CAmount change;
        CAmount fee;
    };

    CWallet m_funder;
    CWallet m_live_wallet;
    CWallet m_rescan_wallet;

    MWEBConflictTestingSetup()
        : m_funder(m_node.chain.get(), "funder", m_args, CreateMockWalletDatabase()),
          m_live_wallet(m_node.chain.get(), "live", m_args, CreateMockWalletDatabase()),
          m_rescan_wallet(m_node.chain.get(), "rescan", m_args, CreateMockWalletDatabase())
    {
        SetupFunder();

        m_receiver_seed.MakeNewKey(true);
        SetupReceiver(m_live_wallet);
        SetupReceiver(m_rescan_wallet);

        SetMockTime(1601450001);
        MineAndScanFunder(331);
        m_build_block_with_mempool = true;

        // Establish an MWEB extension block before any conflict scenario.
        SendFromFunder(NewMWEBAddress(m_funder), COIN);
        MineAndScanFunder();

        SetWalletTip(m_live_wallet, Tip());
        SetWalletTip(m_rescan_wallet, Tip());
    }

    Funding FundReceiver(CAmount amount)
    {
        const ChainTip scan_start = Tip();
        const StealthAddress address = NewMWEBAddress(m_live_wallet);
        BOOST_REQUIRE(NewMWEBAddress(m_rescan_wallet) == address);

        const auto [tx, output_id] = SendFromFunder(address, amount);
        BOOST_REQUIRE(output_id);
        const CBlock block = MineAndScanFunder();
        Connect(m_live_wallet, block);
        return {tx, *output_id, amount, scan_start};
    }

    TransparentFunding FundTransparentReceiver(CAmount amount)
    {
        const auto destination = m_live_wallet.GetNewDestination(OutputType::BECH32, "");
        BOOST_REQUIRE(destination);
        const auto rescan_destination = m_rescan_wallet.GetNewDestination(OutputType::BECH32, "");
        BOOST_REQUIRE(rescan_destination);
        BOOST_REQUIRE(*rescan_destination == *destination);

        const auto [tx, unused_mweb_output] = SendFromFunder(*destination, amount);
        BOOST_CHECK(!unused_mweb_output);
        const CScript script = GetScriptForDestination(*destination);
        const auto output = std::find_if(tx->vout.cbegin(), tx->vout.cend(), [&](const CTxOut& txout) {
            return txout.nValue == amount && txout.scriptPubKey == script;
        });
        BOOST_REQUIRE(output != tx->vout.cend());

        const CBlock block = MineAndScanFunder();
        Connect(m_live_wallet, block);
        const COutPoint outpoint{tx->GetHash(), static_cast<uint32_t>(output - tx->vout.cbegin())};
        const CWalletTx* wtx = m_live_wallet.GetWalletTx(tx->GetHash());
        BOOST_REQUIRE(wtx);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(m_live_wallet, *wtx, ISMINE_SPENDABLE), amount);
        BOOST_CHECK(WITH_LOCK(m_live_wallet.cs_wallet, return m_live_wallet.IsMine(AnyOutputID{outpoint}) == ISMINE_SPENDABLE));
        return {tx, outpoint, amount};
    }

    Spend BuildSpend(const mw::Hash& source_id, const CTxDestination& recipient, CAmount amount, const std::optional<COutPoint>& transparent_source = std::nullopt)
    {
        CCoinControl coin_control;
        coin_control.Select(source_id);
        if (transparent_source) coin_control.Select(*transparent_source);
        coin_control.m_allow_other_inputs = false;

        auto result = WITH_LOCK(m_live_wallet.cs_wallet, return TxBuilder::New(
            m_live_wallet,
            coin_control,
            {{recipient, amount, false}},
            std::nullopt
        )->Build(std::nullopt, std::nullopt, true));
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        BOOST_REQUIRE(result->change_pos.IsMWEB());
        BOOST_REQUIRE(result->change_pos.ToMWEB().hash);

        const mw::Hash change_id = *result->change_pos.ToMWEB().hash;
        const auto change_output = std::find_if(
            result->tx.mweb_tx.outputs.cbegin(),
            result->tx.mweb_tx.outputs.cend(),
            [&change_id](const mw::MutableOutput& output) {
                return output.CalcOutputID() == change_id;
            }
        );
        BOOST_REQUIRE(change_output != result->tx.mweb_tx.outputs.cend());
        BOOST_REQUIRE(change_output->amount);
        return {
            MakeTransactionRef(result->tx),
            change_id,
            *change_output->amount,
            result->fee,
        };
    }

    CWalletTx& AddKnown(CWallet& wallet, const CTransactionRef& tx, const TxState& state)
    {
        CWalletTx* wtx = wallet.AddToWallet(tx, std::nullopt, state);
        BOOST_REQUIRE(wtx);
        return *wtx;
    }

    void Broadcast(const CTransactionRef& tx)
    {
        std::string error;
        BOOST_REQUIRE_MESSAGE(m_node.chain->broadcastTransaction(tx, DEFAULT_TRANSACTION_MAXFEE, /*relay=*/false, error), error);
    }

    CBlock MineAndScanFunder()
    {
        const ChainTip previous = Tip();
        const CScript coinbase_script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        CBlock block = CreateAndProcessBlock({}, coinbase_script);
        SetMockTime(GetTime() + 1);
        SetWalletTip(m_funder, Tip());
        Scan(m_funder, previous, /*update=*/false);
        return block;
    }

    void Connect(CWallet& wallet, const CBlock& block)
    {
        const uint256 hash = block.GetHash();
        interfaces::BlockInfo info{hash};
        info.prev_hash = &block.hashPrevBlock;
        info.height = Tip().height;
        info.data = &block;
        wallet.blockConnected(info);
    }

    void Disconnect(CWallet& wallet, const CBlock& block, int height)
    {
        const uint256 hash = block.GetHash();
        interfaces::BlockInfo info{hash};
        info.prev_hash = &block.hashPrevBlock;
        info.height = height;
        info.data = &block;
        wallet.blockDisconnected(info);
    }

    void RemoveFromMempool(CWallet& wallet, const CTransactionRef& tx)
    {
        interfaces::Chain::Notifications& notifications = wallet;
        notifications.transactionRemovedFromMempool(tx, MemPoolRemovalReason::CONFLICT, 0 /* mempool_sequence */);
    }

    void ScanToTip(CWallet& wallet, const ChainTip& start, bool update = false)
    {
        SetWalletTip(wallet, Tip());
        const CWallet::ScanResult result = Scan(wallet, start, update);
        BOOST_CHECK(result.status == CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, Tip().hash);
        BOOST_REQUIRE(result.last_scanned_height);
        BOOST_CHECK_EQUAL(*result.last_scanned_height, Tip().height);
    }

    std::vector<WalletTxRecord> History(CWallet& wallet, const CWalletTx& wtx)
    {
        LOCK(wallet.cs_wallet);
        return TxList(wallet).List(wtx, ISMINE_ALL, std::nullopt, std::nullopt);
    }

    void ExpectConflict(CWallet& wallet, const CWalletTx& loser, const uint256& block_hash, const uint256& winner_hash)
    {
        LOCK(wallet.cs_wallet);
        const TxStateConflicted* conflicted = loser.state<TxStateConflicted>();
        BOOST_REQUIRE(conflicted);
        BOOST_CHECK_EQUAL(conflicted->conflicting_block_hash, block_hash);
        BOOST_CHECK_EQUAL(wallet.GetTxDepthInMainChain(loser), -1);
        BOOST_CHECK(wallet.GetTxConflicts(loser) == std::set<uint256>{winner_hash});

        std::vector<WalletTxRecord> history = TxList(wallet).List(loser, ISMINE_ALL, std::nullopt, std::nullopt);
        BOOST_REQUIRE(!history.empty());
        for (WalletTxRecord& record : history) {
            BOOST_REQUIRE(record.UpdateStatusIfNeeded(wallet.GetLastBlockHash()));
            BOOST_CHECK(record.status.status == TxRecordStatus::Conflicted);
            BOOST_CHECK(!record.status.countsForBalance);
        }
    }

    ChainTip Tip() const
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CChain& chain = m_node.chainman->ActiveChain();
        return {chain.Tip()->GetBlockHash(), chain.Height()};
    }

private:
    void SetupFunder()
    {
        m_funder.LoadWallet();
        m_funder.LoadMinVersion(FEATURE_MWEB);
        m_funder.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_funder.SetupDescriptorScriptPubKeyMans();

        FlatSigningProvider provider;
        std::string error;
        WalletDescriptor descriptor(Parse("combo(" + EncodeSecret(coinbaseKey) + ")", provider, error, false), 0, 0, 1, 1);
        BOOST_REQUIRE(m_funder.AddWalletDescriptor(descriptor, provider, "", false));
        m_funder.SetBroadcastTransactions(true);
    }

    void SetupReceiver(CWallet& wallet)
    {
        wallet.LoadWallet();
        wallet.SetupLegacyScriptPubKeyMan();
        WITH_LOCK(wallet.cs_wallet, wallet.LoadMinVersion(FEATURE_MWEB));

        LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
        BOOST_REQUIRE(spk_man);
        {
            LOCK(spk_man->cs_KeyStore);
            BOOST_REQUIRE(spk_man->AddKeyPubKey(m_receiver_seed, m_receiver_seed.GetPubKey()));
            spk_man->SetHDSeed(m_receiver_seed.GetPubKey());
        }
        wallet.SetBroadcastTransactions(true);
    }

    StealthAddress NewMWEBAddress(CWallet& wallet)
    {
        while (true) {
            const auto destination = wallet.GetNewDestination(OutputType::MWEB, "");
            BOOST_REQUIRE(destination);
            BOOST_REQUIRE(std::holds_alternative<StealthAddress>(*destination));
            const StealthAddress address = std::get<StealthAddress>(*destination);

            ScriptPubKeyMan* spk_man = wallet.GetScriptPubKeyMan(OutputType::MWEB, false);
            BOOST_REQUIRE(spk_man);
            const mw::Keychain::Ptr keychain = spk_man->GetMWEBKeychain();
            BOOST_REQUIRE(keychain);
            const std::optional<uint32_t> index = keychain->LookupAddressIndex(address);
            BOOST_REQUIRE(index);
            if (*index != mw::CHANGE_INDEX) return address;
        }
    }

    std::pair<CTransactionRef, std::optional<mw::Hash>> SendFromFunder(const CTxDestination& recipient, CAmount amount)
    {
        auto result = WITH_LOCK(m_funder.cs_wallet, return TxBuilder::New(
            m_funder,
            CCoinControl{},
            {{recipient, amount, false}},
            std::nullopt
        )->Build(std::nullopt, std::nullopt, true));
        BOOST_REQUIRE(result);

        std::optional<mw::Hash> recipient_output;
        for (const mw::MutableOutput& output : result->tx.mweb_tx.outputs) {
            if (output.address && GenericAddress(*output.address) == GenericAddress(recipient)) {
                recipient_output = output.CalcOutputID();
                break;
            }
        }

        const CTransactionRef tx = MakeTransactionRef(result->tx);
        m_funder.CommitTransaction(tx, {}, {});
        return {tx, recipient_output};
    }

    CWallet::ScanResult Scan(CWallet& wallet, const ChainTip& start, bool update)
    {
        WalletRescanReserver reserver(wallet);
        BOOST_REQUIRE(reserver.reserve());
        return wallet.ScanForWalletTransactions(start.hash, start.height, /*max_height=*/{}, reserver, update, /*save_progress=*/false);
    }

    void MineAndScanFunder(int count)
    {
        const ChainTip previous = Tip();
        TestChain100Setup::mineBlocks(count);
        SetWalletTip(m_funder, Tip());
        const CWallet::ScanResult result = Scan(m_funder, previous, /*update=*/false);
        BOOST_CHECK(result.status == CWallet::ScanResult::SUCCESS);
    }

    void SetWalletTip(CWallet& wallet, const ChainTip& tip)
    {
        LOCK(wallet.cs_wallet);
        wallet.SetLastBlockProcessed(tip.height, tip.hash);
    }

    CKey m_receiver_seed;
};

BOOST_FIXTURE_TEST_SUITE(mweb_conflict_tests, MWEBConflictTestingSetup)

// Kernel membership, rather than spend-index insertion order, chooses the confirmed transaction.
BOOST_AUTO_TEST_CASE(KnownWinnerConflictsKnownPegoutLoser)
{
    static constexpr CAmount SOURCE_AMOUNT{5 * COIN};
    static constexpr CAmount WINNER_AMOUNT{2 * COIN};
    static constexpr CAmount LOSER_AMOUNT{3 * COIN};
    const Funding funding = FundReceiver(SOURCE_AMOUNT);
    const Spend winner = BuildSpend(funding.output_id, StealthAddress::Random(), WINNER_AMOUNT);

    const CTxDestination pegout_address = *m_funder.GetNewDestination(OutputType::BECH32, "");
    const Spend loser = BuildSpend(funding.output_id, pegout_address, LOSER_AMOUNT);
    CWalletTx& loser_wtx = AddKnown(m_live_wallet, loser.tx, TxStateInMempool{});
    CWalletTx& winner_wtx = AddKnown(m_live_wallet, winner.tx, TxStateInMempool{});

    Broadcast(winner.tx);
    const CBlock block = MineAndScanFunder();
    Connect(m_live_wallet, block);

    BOOST_REQUIRE(winner_wtx.state<TxStateConfirmed>());
    ExpectConflict(m_live_wallet, loser_wtx, block.GetHash(), winner.tx->GetHash());
    WITH_LOCK(m_live_wallet.cs_wallet, BOOST_CHECK(m_live_wallet.GetTxConflicts(winner_wtx) == std::set<uint256>{loser.tx->GetHash()}));
    BOOST_CHECK(m_live_wallet.GetWalletTx(MWEB::WalletTxInfo::Spent(funding.output_id).GetHash()) == nullptr);
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, winner.change);
    BOOST_CHECK_EQUAL(CachedTxGetCredit(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), winner.change);
    BOOST_CHECK_EQUAL(CachedTxGetDebit(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), SOURCE_AMOUNT);
    BOOST_CHECK_EQUAL(CachedTxGetChange(m_live_wallet, winner_wtx), winner.change);
    BOOST_CHECK_EQUAL(CachedTxGetFee(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), winner.fee);
    BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), winner.change);
}

// A full winner that combines transparent and MWEB inputs is selected by all of its kernels.
BOOST_AUTO_TEST_CASE(KnownMixedLayerWinnerConflictsPegoutLoser)
{
    static constexpr CAmount MWEB_AMOUNT{4 * COIN};
    static constexpr CAmount LTC_AMOUNT{2 * COIN};
    static constexpr CAmount PAYMENT_AMOUNT{5 * COIN};
    const Funding mweb_funding = FundReceiver(MWEB_AMOUNT);
    const TransparentFunding ltc_funding = FundTransparentReceiver(LTC_AMOUNT);

    const CTxDestination pegout_address = *m_funder.GetNewDestination(OutputType::BECH32, "");
    const Spend loser = BuildSpend(mweb_funding.output_id, pegout_address, 2 * COIN);
    const CTxDestination mixed_recipient = *m_funder.GetNewDestination(OutputType::BECH32, "");
    const Spend winner = BuildSpend(mweb_funding.output_id, mixed_recipient, PAYMENT_AMOUNT, ltc_funding.outpoint);
    CWalletTx& loser_wtx = AddKnown(m_live_wallet, loser.tx, TxStateInMempool{});
    CWalletTx& winner_wtx = AddKnown(m_live_wallet, winner.tx, TxStateInMempool{});

    Broadcast(winner.tx);
    const CBlock block = MineAndScanFunder();
    Connect(m_live_wallet, block);

    BOOST_REQUIRE(winner_wtx.state<TxStateConfirmed>());
    ExpectConflict(m_live_wallet, loser_wtx, block.GetHash(), winner.tx->GetHash());
    BOOST_CHECK_EQUAL(CachedTxGetCredit(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), winner.change);
    BOOST_CHECK_EQUAL(CachedTxGetDebit(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), MWEB_AMOUNT + LTC_AMOUNT);
    BOOST_CHECK_EQUAL(CachedTxGetChange(m_live_wallet, winner_wtx), winner.change);
    BOOST_CHECK_EQUAL(CachedTxGetFee(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), winner.fee);
    BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(m_live_wallet, winner_wtx, ISMINE_SPENDABLE), winner.change);
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, winner.change);

    std::list<COutputEntry> received;
    std::list<COutputEntry> sent;
    CAmount fee{0};
    WITH_LOCK(m_live_wallet.cs_wallet, CachedTxGetAmounts(m_live_wallet, winner_wtx, received, sent, fee, ISMINE_SPENDABLE, /*include_change=*/false));
    BOOST_REQUIRE_EQUAL(sent.size(), 1U);
    BOOST_CHECK_EQUAL(sent.front().amount, PAYMENT_AMOUNT);
    BOOST_CHECK_EQUAL(fee, winner.fee);
}

// If the block's winning transaction is unavailable, record its known debit and conflict the stale spend.
BOOST_AUTO_TEST_CASE(UnknownWinnerCreatesOneConfirmedPartialSpend)
{
    static constexpr CAmount SOURCE_AMOUNT{5 * COIN};
    static constexpr CAmount WINNER_AMOUNT{2 * COIN};
    static constexpr CAmount LOSER_AMOUNT{3 * COIN};
    const Funding funding = FundReceiver(SOURCE_AMOUNT);
    const Spend winner = BuildSpend(funding.output_id, StealthAddress::Random(), WINNER_AMOUNT);
    const Spend loser = BuildSpend(funding.output_id, StealthAddress::Random(), LOSER_AMOUNT);
    CWalletTx& loser_wtx = AddKnown(m_live_wallet, loser.tx, TxStateInMempool{});

    Broadcast(winner.tx);
    const CBlock block = MineAndScanFunder();
    Connect(m_live_wallet, block);

    const uint256 partial_hash = MWEB::WalletTxInfo::Spent(funding.output_id).GetHash();
    const CWalletTx* partial = m_live_wallet.GetWalletTx(partial_hash);
    BOOST_REQUIRE(partial);
    BOOST_REQUIRE(partial->IsPartialMWEB());
    const TxStateConfirmed* confirmed = partial->state<TxStateConfirmed>();
    BOOST_REQUIRE(confirmed);
    BOOST_CHECK_EQUAL(confirmed->confirmed_block_hash, block.GetHash());
    ExpectConflict(m_live_wallet, loser_wtx, block.GetHash(), partial_hash);

    BOOST_CHECK_EQUAL(CachedTxGetCredit(m_live_wallet, *partial, ISMINE_SPENDABLE), 0);
    BOOST_CHECK_EQUAL(CachedTxGetDebit(m_live_wallet, *partial, ISMINE_SPENDABLE), SOURCE_AMOUNT);
    BOOST_CHECK_EQUAL(CachedTxGetChange(m_live_wallet, *partial), 0);
    BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(m_live_wallet, *partial, ISMINE_SPENDABLE), 0);
    BOOST_CHECK_EQUAL(CachedTxGetFee(m_live_wallet, *partial, ISMINE_SPENDABLE), 0);
    std::vector<WalletTxRecord> history = History(m_live_wallet, *partial);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::Other);
    BOOST_CHECK_EQUAL(history[0].debit, -SOURCE_AMOUNT);
    BOOST_REQUIRE(history[0].UpdateStatusIfNeeded(m_live_wallet.GetLastBlockHash()));
    BOOST_CHECK(history[0].status.status == TxRecordStatus::Confirming);

    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, winner.change);
    const CoinsResult available = WITH_LOCK(m_live_wallet.cs_wallet, return AvailableCoins(m_live_wallet));
    BOOST_CHECK_EQUAL(available.total_amount, winner.change);
    BOOST_REQUIRE_EQUAL(available.coins.at(OutputType::MWEB).size(), 1U);
    BOOST_CHECK(available.coins.at(OutputType::MWEB).front().GetID() == AnyOutputID{winner.change_id});
    BOOST_CHECK_EQUAL(WITH_LOCK(m_live_wallet.cs_wallet, return m_live_wallet.IsSpent(funding.output_id)), true);
    const CWalletTx* receive = m_live_wallet.FindWalletTx(winner.change_id);
    BOOST_REQUIRE(receive);
    BOOST_CHECK_EQUAL(partial->nOrderPos + 1, receive->nOrderPos);
    const std::vector<WalletTxRecord> receive_history = History(m_live_wallet, *receive);
    BOOST_REQUIRE_EQUAL(receive_history.size(), 1U);
    BOOST_CHECK(receive_history[0].type == WalletTxRecord::RecvWithAddress);
    BOOST_CHECK_EQUAL(receive_history[0].credit, winner.change);
    BOOST_CHECK_EQUAL(find_value(receive_history[0].ToUniValue().get_obj(), "mweb_out").get_str(), winner.change_id.ToHex());
}

// A mempool eviction makes the stale spend inactive; the block then conflicts it and every wallet descendant.
BOOST_AUTO_TEST_CASE(BlockConflictPropagatesToDescendantsAfterMempoolRemoval)
{
    static constexpr CAmount SOURCE_AMOUNT{6 * COIN};
    const Funding funding = FundReceiver(SOURCE_AMOUNT);
    const Spend winner = BuildSpend(funding.output_id, StealthAddress::Random(), 2 * COIN);
    const Spend loser = BuildSpend(funding.output_id, StealthAddress::Random(), 3 * COIN);
    m_live_wallet.transactionAddedToMempool(loser.tx, /*mempool_sequence=*/0);
    CWalletTx& loser_wtx = AddKnown(m_live_wallet, loser.tx, TxStateInMempool{});

    const Spend child = BuildSpend(loser.change_id, StealthAddress::Random(), COIN);
    CWalletTx& child_wtx = AddKnown(m_live_wallet, child.tx, TxStateInMempool{});
    std::vector<std::pair<uint256, ChangeType>> notifications;
    boost::signals2::scoped_connection notification_handler = m_live_wallet.NotifyTransactionChanged.connect(
        [&](const uint256& txid, ChangeType type) { notifications.emplace_back(txid, type); }
    );
    RemoveFromMempool(m_live_wallet, loser.tx);
    BOOST_REQUIRE(loser_wtx.state<TxStateInactive>());
    notifications.clear();

    Broadcast(winner.tx);
    const CBlock block = MineAndScanFunder();
    Connect(m_live_wallet, block);

    const uint256 partial_hash = MWEB::WalletTxInfo::Spent(funding.output_id).GetHash();
    ExpectConflict(m_live_wallet, loser_wtx, block.GetHash(), partial_hash);
    {
        LOCK(m_live_wallet.cs_wallet);
        const TxStateConflicted* child_conflict = child_wtx.state<TxStateConflicted>();
        BOOST_REQUIRE(child_conflict);
        BOOST_CHECK_EQUAL(child_conflict->conflicting_block_hash, block.GetHash());
        BOOST_CHECK(!TxList(m_live_wallet).List(child_wtx, ISMINE_ALL, std::nullopt, std::nullopt).empty());
    }
    BOOST_CHECK(std::find(notifications.begin(), notifications.end(), std::make_pair(loser.tx->GetHash(), CT_UPDATED)) != notifications.end());
    BOOST_CHECK(std::find(notifications.begin(), notifications.end(), std::make_pair(child.tx->GetHash(), CT_UPDATED)) != notifications.end());
}

// Competing branches replace the block-only observation without changing its deterministic ID.
BOOST_AUTO_TEST_CASE(UnknownConflictFollowsReplacementAndReconfirmation)
{
    const Funding funding = FundReceiver(5 * COIN);
    const Spend winner = BuildSpend(funding.output_id, StealthAddress::Random(), 2 * COIN);
    const Spend replacement = BuildSpend(funding.output_id, StealthAddress::Random(), COIN);
    const Spend loser = BuildSpend(funding.output_id, StealthAddress::Random(), 3 * COIN);
    CWalletTx& loser_wtx = AddKnown(m_live_wallet, loser.tx, TxStateInMempool{});

    Broadcast(winner.tx);
    const CBlock block = MineAndScanFunder();
    const int block_height = Tip().height;
    Connect(m_live_wallet, block);

    const uint256 partial_hash = MWEB::WalletTxInfo::Spent(funding.output_id).GetHash();
    BOOST_REQUIRE(m_live_wallet.GetWalletTx(partial_hash));

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        BlockValidationState state;
        BOOST_REQUIRE(Assert(m_node.chainman)->ActiveChainstate().InvalidateBlock(state, Assert(m_node.chainman)->ActiveChain().Tip()));
    }
    Disconnect(m_live_wallet, block, block_height);
    BOOST_CHECK(m_live_wallet.GetWalletTx(partial_hash) == nullptr);
    BOOST_REQUIRE(loser_wtx.state<TxStateInactive>());
    BOOST_CHECK(m_live_wallet.GetTxConflicts(loser_wtx).empty());

    WITH_LOCK(Assert(m_node.mempool)->cs, Assert(m_node.mempool)->removeRecursive(*winner.tx, MemPoolRemovalReason::REORG));
    Broadcast(replacement.tx);
    const CBlock replacement_block = MineAndScanFunder();
    const int replacement_height = Tip().height;
    Connect(m_live_wallet, replacement_block);
    const CWalletTx* replacement_partial = m_live_wallet.GetWalletTx(partial_hash);
    BOOST_REQUIRE(replacement_partial);
    BOOST_REQUIRE(replacement_partial->state<TxStateConfirmed>());
    ExpectConflict(m_live_wallet, loser_wtx, replacement_block.GetHash(), partial_hash);
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, replacement.change);

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        BlockValidationState state;
        BOOST_REQUIRE(Assert(m_node.chainman)->ActiveChainstate().InvalidateBlock(state, Assert(m_node.chainman)->ActiveChain().Tip()));
    }
    Disconnect(m_live_wallet, replacement_block, replacement_height);
    BOOST_CHECK(m_live_wallet.GetWalletTx(partial_hash) == nullptr);

    WITH_LOCK(Assert(m_node.mempool)->cs, Assert(m_node.mempool)->removeRecursive(*replacement.tx, MemPoolRemovalReason::REORG));
    Broadcast(winner.tx);
    const CBlock reconfirming_block = MineAndScanFunder();
    Connect(m_live_wallet, reconfirming_block);
    const CWalletTx* reconfirmed_partial = m_live_wallet.GetWalletTx(partial_hash);
    BOOST_REQUIRE(reconfirmed_partial);
    BOOST_REQUIRE(reconfirmed_partial->state<TxStateConfirmed>());
    ExpectConflict(m_live_wallet, loser_wtx, reconfirming_block.GetHash(), partial_hash);
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, winner.change);
}

// Live processing and rescan agree, and learning the full winner replaces all partial rows without changing value.
BOOST_AUTO_TEST_CASE(RescanParityAndLateWinnerUpgrade)
{
    static constexpr CAmount SOURCE_AMOUNT{5 * COIN};
    static constexpr CAmount WINNER_AMOUNT{2 * COIN};
    const Funding funding = FundReceiver(SOURCE_AMOUNT);
    const Spend winner = BuildSpend(funding.output_id, StealthAddress::Random(), WINNER_AMOUNT);
    const Spend loser = BuildSpend(funding.output_id, StealthAddress::Random(), 3 * COIN);
    CWalletTx& live_loser = AddKnown(m_live_wallet, loser.tx, TxStateInMempool{});
    CWalletTx& rescan_loser = AddKnown(m_rescan_wallet, loser.tx, TxStateInMempool{});

    Broadcast(winner.tx);
    const CBlock block = MineAndScanFunder();
    Connect(m_live_wallet, block);
    ScanToTip(m_rescan_wallet, funding.scan_start);

    const uint256 partial_spend_hash = MWEB::WalletTxInfo::Spent(funding.output_id).GetHash();
    const uint256 partial_receive_hash = MWEB::WalletTxInfo::Received(winner.change_id).GetHash();
    for (CWallet* wallet : {&m_live_wallet, &m_rescan_wallet}) {
        const CWalletTx* partial = wallet->GetWalletTx(partial_spend_hash);
        BOOST_REQUIRE(partial);
        BOOST_REQUIRE(partial->state<TxStateConfirmed>());
        BOOST_CHECK_EQUAL(GetBalance(*wallet).m_mine_trusted, winner.change);
    }
    ExpectConflict(m_live_wallet, live_loser, block.GetHash(), partial_spend_hash);
    ExpectConflict(m_rescan_wallet, rescan_loser, block.GetHash(), partial_spend_hash);

    CWalletTx& upgraded = AddKnown(
        m_live_wallet,
        winner.tx,
        TxStateConfirmed{block.GetHash(), Tip().height, TxStateConfirmed::NO_POSITION_IN_BLOCK}
    );
    BOOST_CHECK(m_live_wallet.GetWalletTx(partial_spend_hash) == nullptr);
    BOOST_CHECK(m_live_wallet.GetWalletTx(partial_receive_hash) == nullptr);
    BOOST_REQUIRE(upgraded.state<TxStateConfirmed>());
    BOOST_CHECK_EQUAL(CachedTxGetDebit(m_live_wallet, upgraded, ISMINE_SPENDABLE), SOURCE_AMOUNT);
    BOOST_CHECK_EQUAL(CachedTxGetFee(m_live_wallet, upgraded, ISMINE_SPENDABLE), winner.fee);
    BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(m_live_wallet, upgraded, ISMINE_SPENDABLE), winner.change);
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, winner.change);
    ExpectConflict(m_live_wallet, live_loser, block.GetHash(), winner.tx->GetHash());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
