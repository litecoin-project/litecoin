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

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <optional>
#include <utility>
#include <vector>

namespace wallet {
namespace {

class MWEBLifecycleTestingSetup : public TestChain100Setup
{
public:
    struct ChainTip {
        uint256 hash;
        int height;
    };

    struct BuiltTx {
        CTransactionRef tx;
        std::optional<mw::Hash> recipient_output;
    };

    CWallet m_sender;
    CWallet m_live_wallet;
    CWallet m_rescan_wallet;

    MWEBLifecycleTestingSetup()
        : m_sender(m_node.chain.get(), "sender", m_args, CreateMockWalletDatabase()),
          m_live_wallet(m_node.chain.get(), "live", m_args, CreateMockWalletDatabase()),
          m_rescan_wallet(m_node.chain.get(), "rescan", m_args, CreateMockWalletDatabase())
    {
        SetupSender();

        m_receiver_seed.MakeNewKey(true);
        SetupReceiver(m_live_wallet);
        SetupReceiver(m_rescan_wallet);

        SetMockTime(1601450001);
        MineAndScanSender(331); // Pre-MWEB activation blocks.
        m_build_block_with_mempool = true;

        // Establish the first HogEx before any test forks the chain. This lets
        // a competing empty MWEB block carry the previous HogAddr forward.
        const StealthAddress anchor_address = NewMWEBAddress(m_sender);
        SendFromSender(anchor_address, COIN);
        MineAndScanSender();

        const ChainTip tip = Tip();
        SetWalletTip(m_live_wallet, tip);
        SetWalletTip(m_rescan_wallet, tip);
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

    CTxDestination NewLTCAddress(CWallet& wallet)
    {
        const auto destination = wallet.GetNewDestination(OutputType::BECH32, "");
        BOOST_REQUIRE(destination);
        return *destination;
    }

    BuiltTx SendFromSender(const CTxDestination& recipient, CAmount amount, const std::vector<AnyWalletUTXO>& selected = {})
    {
        CCoinControl coin_control;
        for (const AnyWalletUTXO& coin : selected) {
            coin_control.Select(coin.GetID());
        }

        auto result = WITH_LOCK(m_sender.cs_wallet, return TxBuilder::New(m_sender, coin_control, {{recipient, amount, false}}, std::nullopt)->Build(std::nullopt, std::nullopt, true));
        BOOST_REQUIRE(result);

        std::optional<mw::Hash> recipient_output;
        for (const mw::MutableOutput& output : result->tx.mweb_tx.outputs) {
            if (output.address && GenericAddress(*output.address) == GenericAddress(recipient)) {
                recipient_output = output.CalcOutputID();
                break;
            }
        }

        const CTransactionRef tx = MakeTransactionRef(result->tx);
        m_sender.CommitTransaction(tx, {}, {});
        return {tx, recipient_output};
    }

    CTransactionRef SendFromReceiver(const mw::Hash& source_id, const StealthAddress& recipient, CAmount amount)
    {
        CCoinControl coin_control;
        coin_control.Select(source_id);

        auto result = WITH_LOCK(m_live_wallet.cs_wallet, return TxBuilder::New(m_live_wallet, coin_control, {{recipient, amount, false}}, std::nullopt)->Build(std::nullopt, std::nullopt, true));
        BOOST_REQUIRE(result);

        const CTransactionRef tx = MakeTransactionRef(result->tx);
        m_live_wallet.CommitTransaction(tx, {}, {});
        return tx;
    }

    std::vector<AnyWalletUTXO> SenderMWEBOutputs()
    {
        LOCK(m_sender.cs_wallet);
        return AvailableCoins(m_sender).coins[OutputType::MWEB];
    }

    CBlock MineAndScanSender()
    {
        const ChainTip previous = Tip();
        const CScript coinbase_script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        CBlock block = CreateAndProcessBlock({}, coinbase_script);
        SetMockTime(GetTime() + 1);

        const ChainTip current = Tip();
        SetWalletTip(m_sender, current);
        Scan(m_sender, previous, /*update=*/false);
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

    CWallet::ScanResult Scan(CWallet& wallet, const ChainTip& start, bool update)
    {
        WalletRescanReserver reserver(wallet);
        BOOST_REQUIRE(reserver.reserve());
        return wallet.ScanForWalletTransactions(start.hash, start.height, /*max_height=*/{}, reserver, update, /*save_progress=*/false);
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

    void ExpectConfirmedReceive(CWallet& wallet, const mw::Hash& output_id, CAmount amount, const uint256& block_hash)
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx = wallet.FindWalletTx(AnyOutputID{output_id});
        BOOST_REQUIRE(wtx);
        BOOST_CHECK(wtx->IsPartialMWEB());
        const TxStateConfirmed* confirmed = wtx->state<TxStateConfirmed>();
        BOOST_REQUIRE(confirmed);
        BOOST_CHECK_EQUAL(confirmed->confirmed_block_hash, block_hash);
        BOOST_CHECK_EQUAL(CachedTxGetCredit(wallet, *wtx, ISMINE_SPENDABLE), amount);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx, ISMINE_SPENDABLE), amount);

        std::vector<WalletTxRecord> history = TxList(wallet).List(*wtx, ISMINE_ALL, std::nullopt, std::nullopt);
        BOOST_REQUIRE_EQUAL(history.size(), 1U);
        BOOST_CHECK(history[0].type == WalletTxRecord::RecvWithAddress);
        BOOST_CHECK_EQUAL(history[0].credit, amount);
        BOOST_CHECK_EQUAL(find_value(history[0].ToUniValue().get_obj(), "mweb_out").get_str(), output_id.ToHex());
        BOOST_REQUIRE(history[0].UpdateStatusIfNeeded(wallet.GetLastBlockHash()));
        BOOST_CHECK(history[0].status.status == TxRecordStatus::Confirming);

        const Balance balance = GetBalance(wallet);
        BOOST_CHECK_EQUAL(balance.m_mine_trusted, amount);
        BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, 0);
    }

    ChainTip Tip() const
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CChain& chain = m_node.chainman->ActiveChain();
        return {chain.Tip()->GetBlockHash(), chain.Height()};
    }

private:
    void SetupSender()
    {
        m_sender.LoadWallet();
        m_sender.LoadMinVersion(FEATURE_MWEB);
        m_sender.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_sender.SetupDescriptorScriptPubKeyMans();

        FlatSigningProvider provider;
        std::string error;
        WalletDescriptor descriptor(Parse("combo(" + EncodeSecret(coinbaseKey) + ")", provider, error, false), 0, 0, 1, 1);
        BOOST_REQUIRE(m_sender.AddWalletDescriptor(descriptor, provider, "", false));
        m_sender.SetBroadcastTransactions(true);
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

    void MineAndScanSender(int count)
    {
        const ChainTip previous = Tip();
        TestChain100Setup::mineBlocks(count);
        SetWalletTip(m_sender, Tip());
        const CWallet::ScanResult result = Scan(m_sender, previous, /*update=*/false);
        BOOST_CHECK(result.status == CWallet::ScanResult::SUCCESS);
    }

    void SetWalletTip(CWallet& wallet, const ChainTip& tip)
    {
        LOCK(wallet.cs_wallet);
        wallet.SetLastBlockProcessed(tip.height, tip.hash);
    }

    CKey m_receiver_seed;
};

BOOST_FIXTURE_TEST_SUITE(mweb_lifecycle_tests, MWEBLifecycleTestingSetup)

// A wallet receiving live notifications and a wallet restored by rescan derive the same partial MWEB receive.
BOOST_AUTO_TEST_CASE(IncomingPaymentMatchesLiveProcessingAndRescan)
{
    static constexpr CAmount RECEIVE_AMOUNT{5 * COIN};
    const ChainTip scan_start = Tip();
    const StealthAddress recipient = NewMWEBAddress(m_live_wallet);
    BOOST_CHECK(NewMWEBAddress(m_rescan_wallet) == recipient);
    const BuiltTx payment = SendFromSender(recipient, RECEIVE_AMOUNT);
    BOOST_REQUIRE(payment.recipient_output);

    const CBlock block = MineAndScanSender();
    const std::vector<mw::Hash> output_ids = block.mweb_block.GetOutputIDs();
    BOOST_CHECK(std::find(output_ids.begin(), output_ids.end(), *payment.recipient_output) != output_ids.end());

    Connect(m_live_wallet, block);
    ExpectConfirmedReceive(m_live_wallet, *payment.recipient_output, RECEIVE_AMOUNT, block.GetHash());

    ScanToTip(m_rescan_wallet, scan_start);
    ExpectConfirmedReceive(m_rescan_wallet, *payment.recipient_output, RECEIVE_AMOUNT, block.GetHash());

    const size_t wallet_rows = WITH_LOCK(m_rescan_wallet.cs_wallet, return m_rescan_wallet.mapWallet.size());
    ScanToTip(m_rescan_wallet, scan_start, /*update=*/true);
    BOOST_CHECK_EQUAL(WITH_LOCK(m_rescan_wallet.cs_wallet, return m_rescan_wallet.mapWallet.size()), wallet_rows);
    ExpectConfirmedReceive(m_rescan_wallet, *payment.recipient_output, RECEIVE_AMOUNT, block.GetHash());
}

// Disconnecting and later re-mining an MWEB receive preserves one history row and follows the active chain.
BOOST_AUTO_TEST_CASE(IncomingPaymentFollowsReorgAndReconfirmation)
{
    static constexpr CAmount RECEIVE_AMOUNT{4 * COIN};
    const ChainTip fork = Tip();
    const StealthAddress recipient = NewMWEBAddress(m_live_wallet);
    BOOST_CHECK(NewMWEBAddress(m_rescan_wallet) == recipient);
    const BuiltTx payment = SendFromSender(recipient, RECEIVE_AMOUNT);
    BOOST_REQUIRE(payment.recipient_output);

    const CBlock original_block = MineAndScanSender();
    const int original_height = Tip().height;
    Connect(m_live_wallet, original_block);
    ExpectConfirmedReceive(m_live_wallet, *payment.recipient_output, RECEIVE_AMOUNT, original_block.GetHash());

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        BlockValidationState state;
        BOOST_REQUIRE(Assert(m_node.chainman)->ActiveChainstate().InvalidateBlock(state, Assert(m_node.chainman)->ActiveChain().Tip()));
    }
    BOOST_CHECK_EQUAL(Tip().hash, fork.hash);
    Disconnect(m_live_wallet, original_block, original_height);

    WITH_LOCK(Assert(m_node.mempool)->cs, Assert(m_node.mempool)->removeRecursive(*payment.tx, MemPoolRemovalReason::REORG));
    const CBlock replacement_block = MineAndScanSender();
    Connect(m_live_wallet, replacement_block);
    {
        LOCK(m_live_wallet.cs_wallet);
        const CWalletTx* wtx = m_live_wallet.FindWalletTx(AnyOutputID{*payment.recipient_output});
        BOOST_REQUIRE(wtx);
        BOOST_CHECK(wtx->state<TxStateInactive>() != nullptr);
        BOOST_REQUIRE_EQUAL(TxList(m_live_wallet).List(*wtx, ISMINE_ALL, std::nullopt, std::nullopt).size(), 1U);
        BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, 0);
    }

    BOOST_REQUIRE(m_sender.RebroadcastTransaction(payment.tx->GetHash()));
    const CBlock reconfirming_block = MineAndScanSender();
    const std::vector<mw::Hash> output_ids = reconfirming_block.mweb_block.GetOutputIDs();
    BOOST_CHECK(std::find(output_ids.begin(), output_ids.end(), *payment.recipient_output) != output_ids.end());
    Connect(m_live_wallet, reconfirming_block);
    ExpectConfirmedReceive(m_live_wallet, *payment.recipient_output, RECEIVE_AMOUNT, reconfirming_block.GetHash());
    BOOST_CHECK_EQUAL(WITH_LOCK(m_live_wallet.cs_wallet, return m_live_wallet.mapWallet.size()), 1U);

    ScanToTip(m_rescan_wallet, fork);
    ExpectConfirmedReceive(m_rescan_wallet, *payment.recipient_output, RECEIVE_AMOUNT, reconfirming_block.GetHash());
    BOOST_CHECK_EQUAL(WITH_LOCK(m_rescan_wallet.cs_wallet, return m_rescan_wallet.mapWallet.size()), 1U);
}

// A known full MWEB spend is confirmed by its kernel during live processing and wallet restoration.
BOOST_AUTO_TEST_CASE(KnownSpendReconnectsAndRescansWithoutPartialDuplicates)
{
    static constexpr CAmount RECEIVE_AMOUNT{5 * COIN};
    static constexpr CAmount SEND_AMOUNT{2 * COIN};
    const ChainTip scan_start = Tip();
    const StealthAddress recipient = NewMWEBAddress(m_live_wallet);
    BOOST_CHECK(NewMWEBAddress(m_rescan_wallet) == recipient);
    const BuiltTx payment = SendFromSender(recipient, RECEIVE_AMOUNT);
    BOOST_REQUIRE(payment.recipient_output);
    const CBlock receive_block = MineAndScanSender();
    Connect(m_live_wallet, receive_block);

    const CTransactionRef spend = SendFromReceiver(*payment.recipient_output, StealthAddress::Random(), SEND_AMOUNT);
    const CAmount fee = *spend->mweb_tx.GetFee();
    const CAmount expected_change = RECEIVE_AMOUNT - SEND_AMOUNT - fee;
    const CBlock spend_block = MineAndScanSender();
    const int spend_height = Tip().height;
    Connect(m_live_wallet, spend_block);

    const CWalletTx* live_spend = m_live_wallet.GetWalletTx(spend->GetHash());
    BOOST_REQUIRE(live_spend);
    BOOST_CHECK(live_spend->state<TxStateConfirmed>() != nullptr);
    BOOST_CHECK(!live_spend->IsPartialMWEB());
    BOOST_CHECK(m_live_wallet.IsSpent(*payment.recipient_output));
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, expected_change);

    ScanToTip(m_rescan_wallet, scan_start);
    const uint256 partial_spend_hash = MWEB::WalletTxInfo::Spent(*payment.recipient_output).GetHash();
    const CWalletTx* partial_spend = m_rescan_wallet.GetWalletTx(partial_spend_hash);
    BOOST_REQUIRE(partial_spend);
    BOOST_CHECK(partial_spend->IsPartialMWEB());
    BOOST_CHECK(partial_spend->state<TxStateConfirmed>() != nullptr);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(m_rescan_wallet.cs_wallet, return TxList(m_rescan_wallet).List(*partial_spend, ISMINE_ALL, std::nullopt, std::nullopt).size()), 1U);
    BOOST_CHECK_EQUAL(GetBalance(m_rescan_wallet).m_mine_trusted, expected_change);

    BOOST_REQUIRE(m_rescan_wallet.AddToWallet(
        spend,
        std::nullopt,
        TxStateConfirmed{spend_block.GetHash(), spend_height, TxStateConfirmed::NO_POSITION_IN_BLOCK}));
    const CWalletTx* rescanned_spend = m_rescan_wallet.GetWalletTx(spend->GetHash());
    BOOST_REQUIRE(rescanned_spend);
    BOOST_CHECK(rescanned_spend->state<TxStateConfirmed>() != nullptr);
    BOOST_CHECK(!rescanned_spend->IsPartialMWEB());
    BOOST_CHECK_EQUAL(WITH_LOCK(m_rescan_wallet.cs_wallet, return m_rescan_wallet.mapWallet.count(partial_spend_hash)), 0U);
    BOOST_CHECK_EQUAL(WITH_LOCK(m_rescan_wallet.cs_wallet, return m_rescan_wallet.mapWallet.size()), 2U);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(m_rescan_wallet.cs_wallet, return TxList(m_rescan_wallet).List(*rescanned_spend, ISMINE_ALL, std::nullopt, std::nullopt).size()), 1U);
    BOOST_CHECK_EQUAL(GetBalance(m_rescan_wallet).m_mine_trusted, expected_change);

    Disconnect(m_live_wallet, spend_block, spend_height);
    BOOST_CHECK(live_spend->state<TxStateInactive>() != nullptr);
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, 0);
    Connect(m_live_wallet, spend_block);
    BOOST_CHECK(live_spend->state<TxStateConfirmed>() != nullptr);
    BOOST_CHECK_EQUAL(GetBalance(m_live_wallet).m_mine_trusted, expected_change);
    BOOST_CHECK_EQUAL(WITH_LOCK(m_live_wallet.cs_wallet, return m_live_wallet.mapWallet.count(spend->GetHash())), 1U);
}

// Rescan reconstructs the same HogEx pegout identity as live block processing, so known pegouts stay deduplicated.
BOOST_AUTO_TEST_CASE(HogExPegoutMappingMatchesLiveProcessingAndRescan)
{
    static constexpr CAmount FUND_AMOUNT{5 * COIN};
    static constexpr CAmount PEGOUT_AMOUNT{2 * COIN};

    const CTxDestination sender_mweb = NewMWEBAddress(m_sender);
    const BuiltTx funding = SendFromSender(sender_mweb, FUND_AMOUNT);
    BOOST_REQUIRE(funding.recipient_output);
    MineAndScanSender();

    const std::vector<AnyWalletUTXO> mweb_outputs = SenderMWEBOutputs();
    const auto funding_coin = std::find_if(mweb_outputs.begin(), mweb_outputs.end(), [&](const AnyWalletUTXO& coin) {
        return coin.GetID() == AnyOutputID{*funding.recipient_output};
    });
    BOOST_REQUIRE(funding_coin != mweb_outputs.end());

    const ChainTip scan_start = Tip();
    const CTxDestination recipient = NewLTCAddress(m_live_wallet);
    BOOST_CHECK(NewLTCAddress(m_rescan_wallet) == recipient);
    BOOST_CHECK(m_live_wallet.IsMine(recipient) == ISMINE_SPENDABLE);
    const BuiltTx pegout = SendFromSender(recipient, PEGOUT_AMOUNT, {*funding_coin});
    const CWalletTx pegout_wtx(pegout.tx, TxStateInactive{}, std::nullopt);
    const auto pegouts = pegout_wtx.GetMWEBPegouts();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);

    BOOST_REQUIRE(m_live_wallet.AddToWallet(pegout.tx, std::nullopt, TxStateInactive{}));
    BOOST_REQUIRE(m_rescan_wallet.AddToWallet(pegout.tx, std::nullopt, TxStateInactive{}));

    const CBlock block = MineAndScanSender();
    BOOST_REQUIRE(block.vtx.back()->IsHogEx());
    BOOST_CHECK(std::any_of(block.vtx.back()->vout.begin(), block.vtx.back()->vout.end(), [&](const CTxOut& output) {
        return output.nValue == PEGOUT_AMOUNT && output.scriptPubKey == GetScriptForDestination(recipient);
    }));
    Connect(m_live_wallet, block);

    auto check_hogex = [&](CWallet& wallet) {
        LOCK(wallet.cs_wallet);
        const CWalletTx* hogex = wallet.GetWalletTx(block.vtx.back()->GetHash());
        BOOST_REQUIRE(hogex);
        BOOST_REQUIRE_EQUAL(hogex->pegout_indices.size(), hogex->tx->vout.size());
        BOOST_REQUIRE_EQUAL(hogex->pegout_indices.size(), 2U);
        BOOST_CHECK(hogex->pegout_indices[1].first == pegouts[0].first.kernel_id);
        BOOST_CHECK_EQUAL(hogex->pegout_indices[1].second, pegouts[0].first.pos);
        BOOST_CHECK(TxList(wallet).List(*hogex, ISMINE_ALL, std::nullopt, std::nullopt).empty());
    };
    check_hogex(m_live_wallet);

    ScanToTip(m_rescan_wallet, scan_start, /*update=*/true);
    check_hogex(m_rescan_wallet);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
