// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <key.h>
#include <key_io.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/wallet/WalletCoin.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <test_framework/TxBuilder.h>
#include <univalue.h>
#include <validation.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/txlist.h>
#include <wallet/txrecord.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wallet {
namespace {

class MWEBAccountingTestingSetup : public TestChain100Setup
{
public:
    CWallet m_wallet;

    MWEBAccountingTestingSetup()
        : m_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase())
    {
        m_wallet.LoadWallet();
        m_wallet.SetupLegacyScriptPubKeyMan();
        WITH_LOCK(m_wallet.cs_wallet, m_wallet.LoadMinVersion(FEATURE_MWEB));
        LegacyScriptPubKeyMan* spk_man = m_wallet.GetLegacyScriptPubKeyMan();
        BOOST_REQUIRE(spk_man);
        {
            LOCK(spk_man->cs_KeyStore);
            const CPubKey seed = spk_man->GenerateNewSeed();
            spk_man->SetHDSeed(seed);
        }

        {
            LOCK(Assert(m_node.chainman)->GetMutex());
            const CChain& chain = m_node.chainman->ActiveChain();
            m_tip_height = chain.Height();
            m_tip_hash = chain.Tip()->GetBlockHash();
        }
        WITH_LOCK(m_wallet.cs_wallet, m_wallet.SetLastBlockProcessed(m_tip_height, m_tip_hash));
    }

    struct Accounting {
        CAmount credit;
        CAmount debit;
        CAmount change;
        CAmount available;
        CAmount fee;
    };

    struct Amounts {
        std::list<COutputEntry> received;
        std::list<COutputEntry> sent;
        CAmount fee;
    };

    TxState Confirmed(int depth = 1) const
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CChain& chain = m_node.chainman->ActiveChain();
        const int height = chain.Height() - depth + 1;
        return TxStateConfirmed{chain[height]->GetBlockHash(), height, /*index=*/0};
    }

    StealthAddress NewMWEBAddress()
    {
        while (true) {
            const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "");
            BOOST_REQUIRE(destination);
            BOOST_REQUIRE(std::holds_alternative<StealthAddress>(*destination));

            const StealthAddress address = std::get<StealthAddress>(*destination);
            const std::optional<uint32_t> index = Keychain()->LookupAddressIndex(address);
            BOOST_REQUIRE(index);
            if (*index != mw::CHANGE_INDEX) {
                return address;
            }
        }
    }

    StealthAddress MWEBChangeAddress() const
    {
        return Keychain()->DeriveAddress(mw::CHANGE_INDEX);
    }

    CTxDestination NewLTCAddress()
    {
        const auto destination = m_wallet.GetNewDestination(OutputType::BECH32, "");
        BOOST_REQUIRE(destination);
        return *destination;
    }

    CTxDestination NewExternalLTCAddress()
    {
        CKey key;
        key.MakeNewKey(true);
        return WitnessV0KeyHash(key.GetPubKey());
    }

    CTxDestination AddWatchOnlyAddress()
    {
        CKey watch_key;
        watch_key.MakeNewKey(true);
        const CTxDestination destination = WitnessV0KeyHash(watch_key.GetPubKey());
        const CScript script = GetScriptForDestination(destination);
        LegacyScriptPubKeyMan* spk_man = m_wallet.GetLegacyScriptPubKeyMan();
        BOOST_REQUIRE(spk_man);
        {
            LOCK(spk_man->cs_KeyStore);
            BOOST_REQUIRE(spk_man->AddWatchOnly(script, /*nCreateTime=*/1));
        }
        WITH_LOCK(m_wallet.cs_wallet, BOOST_REQUIRE(m_wallet.IsMine(destination) == ISMINE_WATCH_ONLY));
        return destination;
    }

    test::TxOutput AddMWEBFunding(CAmount amount)
    {
        const StealthAddress address = NewMWEBAddress();
        const test::Tx funding = test::TxBuilder()
            .AddPeginKernel(amount, 0)
            .AddOutput(amount, SecretKey::Random(), address)
            .Build();

        const test::TxOutput output = funding.GetOutputs().front();
        SaveMWEBOutput(output, address, /*owned=*/true);
        AddWalletTx(MWEBOnly(funding), Confirmed(6));
        return output;
    }

    COutPoint AddLTCFunding(CAmount amount)
    {
        CMutableTransaction funding;
        funding.nLockTime = ++m_next_lock_time;
        funding.vout.emplace_back(amount, GetScriptForDestination(NewLTCAddress()));
        CWalletTx& wtx = AddWalletTx(std::move(funding), Confirmed(6));
        return COutPoint{wtx.GetHash(), 0};
    }

    void SaveMWEBOutput(const test::TxOutput& output, const StealthAddress& address, bool owned)
    {
        mw::WalletCoin coin;
        coin.amount = output.GetAmount();
        coin.output_id = output.GetOutputID();
        coin.address = address;
        if (owned) {
            const std::optional<uint32_t> index = Keychain()->LookupAddressIndex(address);
            BOOST_REQUIRE(index);
            coin.address_index = *index;
        }

        LOCK(m_wallet.cs_wallet);
        BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveToWallet({coin}));
    }

    CWalletTx& AddPartialReceive(const mw::Hash& output_id, CAmount amount, const StealthAddress& address, const TxState& state)
    {
        mw::WalletCoin coin;
        coin.amount = amount;
        coin.output_id = output_id;
        coin.address = address;
        const std::optional<uint32_t> index = Keychain()->LookupAddressIndex(address);
        BOOST_REQUIRE(index);
        coin.address_index = *index;

        {
            LOCK(m_wallet.cs_wallet);
            BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveToWallet({coin}));
        }

        const std::optional<MWEB::WalletTxInfo> info{MWEB::WalletTxInfo::Received(output_id)};
        CWalletTx* wtx = m_wallet.AddToWallet(MakeTransactionRef(), info, state);
        BOOST_REQUIRE(wtx);
        return *wtx;
    }

    CWalletTx& AddPartialSpend(const mw::Hash& output_id, const TxState& state)
    {
        const std::optional<MWEB::WalletTxInfo> info{MWEB::WalletTxInfo::Spent(output_id)};
        const CTransactionRef empty_tx = MakeTransactionRef();
        CWalletTx* wtx = m_wallet.AddToWallet(empty_tx, info, state);
        BOOST_REQUIRE(wtx);
        m_wallet.MarkDirty();
        return *wtx;
    }

    CWalletTx& AddWalletTx(CMutableTransaction tx, const TxState& state)
    {
        const CTransactionRef tx_ref = MakeTransactionRef(std::move(tx));
        CWalletTx* wtx = m_wallet.AddToWallet(tx_ref, std::nullopt, state);
        BOOST_REQUIRE(wtx);
        m_wallet.MarkDirty();
        return *wtx;
    }

    CMutableTransaction MWEBOnly(const test::Tx& mweb_tx) const
    {
        CMutableTransaction tx;
        tx.mweb_tx = mw::MutableTx::From(*mweb_tx.GetTransaction());
        return tx;
    }

    CMutableTransaction WithPegoutScript(const test::Tx& mweb_tx, const CScript& script) const
    {
        CMutableTransaction tx = MWEBOnly(mweb_tx);
        bool replaced{false};
        for (mw::MutableKernel& kernel : tx.mweb_tx.kernels) {
            for (mw::PegOutRecipient& pegout : kernel.pegouts) {
                pegout.script = script;
                replaced = true;
            }
        }
        BOOST_REQUIRE(replaced);
        return tx;
    }

    void AddPeginOutput(CMutableTransaction& tx, CAmount amount) const
    {
        const CTransaction finalized(tx);
        const std::vector<PegInCoin> pegins = finalized.mweb_tx.GetPegIns();
        BOOST_REQUIRE(!pegins.empty());
        tx.vout.emplace_back(amount, GetScriptForPegin(pegins.front().GetKernelID()));
    }

    Accounting GetAccounting(const CWalletTx& wtx, isminefilter filter = ISMINE_SPENDABLE)
    {
        LOCK(m_wallet.cs_wallet);
        return {
            CachedTxGetCredit(m_wallet, wtx, filter),
            CachedTxGetDebit(m_wallet, wtx, filter),
            CachedTxGetChange(m_wallet, wtx),
            CachedTxGetAvailableCredit(m_wallet, wtx, filter),
            CachedTxGetFee(m_wallet, wtx, filter),
        };
    }

    Amounts GetAmounts(const CWalletTx& wtx, bool include_change, isminefilter filter = ISMINE_SPENDABLE)
    {
        Amounts amounts;
        LOCK(m_wallet.cs_wallet);
        CachedTxGetAmounts(m_wallet, wtx, amounts.received, amounts.sent, amounts.fee, filter, include_change);
        return amounts;
    }

    std::vector<WalletTxRecord> GetHistory(const CWalletTx& wtx, isminefilter filter = ISMINE_ALL)
    {
        LOCK(m_wallet.cs_wallet);
        return TxList(m_wallet).List(wtx, filter, std::nullopt, std::nullopt);
    }

    std::vector<WalletTxRecord> GetAllHistory(isminefilter filter = ISMINE_ALL)
    {
        LOCK(m_wallet.cs_wallet);
        return TxList(m_wallet).ListAll(filter);
    }

    void UpdateStatus(WalletTxRecord& record) const
    {
        BOOST_REQUIRE(record.UpdateStatusIfNeeded(m_tip_hash));
    }

    const uint256& TipHash() const noexcept { return m_tip_hash; }
    int TipHeight() const noexcept { return m_tip_height; }

private:
    mw::Keychain::Ptr Keychain() const
    {
        ScriptPubKeyMan* spk_man = m_wallet.GetScriptPubKeyMan(OutputType::MWEB, false);
        BOOST_REQUIRE(spk_man);
        const mw::Keychain::Ptr keychain = spk_man->GetMWEBKeychain();
        BOOST_REQUIRE(keychain);
        return keychain;
    }

    uint256 m_tip_hash;
    int m_tip_height{0};
    uint32_t m_next_lock_time{0};
};

BOOST_FIXTURE_TEST_SUITE(mweb_accounting_tests, MWEBAccountingTestingSetup)

// A full MWEB receive contributes one wallet credit and one history component.
BOOST_AUTO_TEST_CASE(ConfirmedFullMWEBReceiveHasOneCreditAndHistoryRecord)
{
    static constexpr CAmount RECEIVE_AMOUNT{5'000'000};
    const StealthAddress receive_address = NewMWEBAddress();
    const test::Tx receive_tx = test::TxBuilder()
        .AddPeginKernel(RECEIVE_AMOUNT, 0)
        .AddOutput(RECEIVE_AMOUNT, SecretKey::Random(), receive_address)
        .Build();
    const test::TxOutput& output = receive_tx.GetOutputs().front();

    SaveMWEBOutput(output, receive_address, /*owned=*/true);
    CWalletTx& wtx = AddWalletTx(MWEBOnly(receive_tx), Confirmed(6));

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.debit, 0);
    BOOST_CHECK_EQUAL(accounting.change, 0);
    BOOST_CHECK_EQUAL(accounting.available, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.fee, 0);

    const Amounts amounts = GetAmounts(wtx, /*include_change=*/false);
    BOOST_REQUIRE_EQUAL(amounts.received.size(), 1U);
    BOOST_CHECK(amounts.sent.empty());
    BOOST_CHECK_EQUAL(amounts.fee, 0);
    BOOST_CHECK(amounts.received.front().destination == CTxDestination{receive_address});
    BOOST_CHECK_EQUAL(amounts.received.front().amount, RECEIVE_AMOUNT);
    BOOST_CHECK(amounts.received.front().component_id == output.GetOutputID());

    std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::RecvWithAddress);
    BOOST_CHECK_EQUAL(history[0].address, GenericAddress(receive_address).Encode());
    BOOST_CHECK_EQUAL(history[0].credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].GetNet(), RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(find_value(history[0].ToUniValue().get_obj(), "mweb_out").get_str(), output.GetOutputID().ToHex());

    UpdateStatus(history[0]);
    BOOST_CHECK(history[0].status.status == TxRecordStatus::Confirmed);
    BOOST_CHECK(history[0].status.countsForBalance);

    const Balance balance = GetBalance(m_wallet);
    BOOST_CHECK_EQUAL(balance.m_mine_trusted, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, 0);
}

// A partial receive has the same visible accounting as a full receive, but is pending while in the mempool.
BOOST_AUTO_TEST_CASE(UnconfirmedPartialMWEBReceiveIsPendingAndVisible)
{
    static constexpr CAmount RECEIVE_AMOUNT{3'000'000};
    const mw::Hash output_id = mw::Hash::ValueOf(101);
    const StealthAddress receive_address = NewMWEBAddress();
    CWalletTx& wtx = AddPartialReceive(output_id, RECEIVE_AMOUNT, receive_address, TxStateInMempool{});

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.debit, 0);
    BOOST_CHECK_EQUAL(accounting.change, 0);
    BOOST_CHECK_EQUAL(accounting.available, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.fee, 0);

    const Amounts amounts = GetAmounts(wtx, /*include_change=*/false);
    BOOST_REQUIRE_EQUAL(amounts.received.size(), 1U);
    BOOST_CHECK(amounts.sent.empty());
    BOOST_CHECK(amounts.received.front().component_id == output_id);

    std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::RecvWithAddress);
    BOOST_CHECK_EQUAL(history[0].credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].address, GenericAddress(receive_address).Encode());
    UpdateStatus(history[0]);
    BOOST_CHECK(history[0].status.status == TxRecordStatus::Unconfirmed);
    BOOST_CHECK(!history[0].status.countsForBalance);

    const Balance balance = GetBalance(m_wallet);
    BOOST_CHECK_EQUAL(balance.m_mine_trusted, 0);
    BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, RECEIVE_AMOUNT);
}

// A pure MWEB payment reports the external output, hides change, and leaves only change in the balance.
BOOST_AUTO_TEST_CASE(MWEBPaymentTracksExternalAmountChangeAndFee)
{
    static constexpr CAmount INPUT_AMOUNT{10'000'000};
    static constexpr CAmount SEND_AMOUNT{6'000'000};
    static constexpr CAmount CHANGE_AMOUNT{3'000'000};
    static constexpr CAmount FEE{1'000'000};
    const test::TxOutput source = AddMWEBFunding(INPUT_AMOUNT);
    const StealthAddress recipient = StealthAddress::Random();
    const StealthAddress change_address = MWEBChangeAddress();

    const test::Tx spend_tx = test::TxBuilder()
        .AddInput(source)
        .AddOutput(SEND_AMOUNT, SecretKey::Random(), recipient)
        .AddOutput(CHANGE_AMOUNT, SecretKey::Random(), change_address)
        .AddPlainKernel(FEE)
        .Build();
    const auto external_output = std::find_if(spend_tx.GetOutputs().begin(), spend_tx.GetOutputs().end(), [&](const test::TxOutput& output) {
        return output.GetAmount() == SEND_AMOUNT;
    });
    const auto change_output = std::find_if(spend_tx.GetOutputs().begin(), spend_tx.GetOutputs().end(), [&](const test::TxOutput& output) {
        return output.GetAmount() == CHANGE_AMOUNT;
    });
    BOOST_REQUIRE(external_output != spend_tx.GetOutputs().end());
    BOOST_REQUIRE(change_output != spend_tx.GetOutputs().end());
    SaveMWEBOutput(*external_output, recipient, /*owned=*/false);
    SaveMWEBOutput(*change_output, change_address, /*owned=*/true);
    CWalletTx& wtx = AddWalletTx(MWEBOnly(spend_tx), Confirmed());

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, CHANGE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.debit, INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.change, CHANGE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.available, CHANGE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.fee, FEE);

    const Amounts without_change = GetAmounts(wtx, /*include_change=*/false);
    BOOST_REQUIRE_EQUAL(without_change.sent.size(), 1U);
    BOOST_CHECK(without_change.received.empty());
    BOOST_CHECK_EQUAL(without_change.sent.front().amount, SEND_AMOUNT);
    BOOST_CHECK(without_change.sent.front().destination == CTxDestination{recipient});
    BOOST_CHECK_EQUAL(without_change.fee, FEE);

    const Amounts with_change = GetAmounts(wtx, /*include_change=*/true);
    BOOST_REQUIRE_EQUAL(with_change.sent.size(), 2U);
    BOOST_REQUIRE_EQUAL(with_change.received.size(), 1U);
    BOOST_CHECK_EQUAL(with_change.received.front().amount, CHANGE_AMOUNT);
    BOOST_CHECK(with_change.received.front().component_id == change_output->GetOutputID());

    const std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::SendToAddress);
    BOOST_CHECK_EQUAL(history[0].address, GenericAddress(recipient).Encode());
    BOOST_CHECK_EQUAL(history[0].debit, -SEND_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].fee, -FEE);
    BOOST_CHECK_EQUAL(history[0].GetNet(), -(SEND_AMOUNT + FEE));

    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, CHANGE_AMOUNT);
}

// Sending MWEB back to the wallet creates one self-send whose net value is only the fee.
BOOST_AUTO_TEST_CASE(MWEBSelfSendReportsOnlyFeeAsNetAmount)
{
    static constexpr CAmount INPUT_AMOUNT{10'000'000};
    static constexpr CAmount OUTPUT_AMOUNT{9'000'000};
    static constexpr CAmount FEE{1'000'000};
    const test::TxOutput source = AddMWEBFunding(INPUT_AMOUNT);
    const StealthAddress recipient = NewMWEBAddress();

    const test::Tx self_tx = test::TxBuilder()
        .AddInput(source)
        .AddOutput(OUTPUT_AMOUNT, SecretKey::Random(), recipient)
        .AddPlainKernel(FEE)
        .Build();
    SaveMWEBOutput(self_tx.GetOutputs().front(), recipient, /*owned=*/true);
    CWalletTx& wtx = AddWalletTx(MWEBOnly(self_tx), Confirmed());

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, OUTPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.debit, INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.change, 0);
    BOOST_CHECK_EQUAL(accounting.available, OUTPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.fee, FEE);

    const Amounts amounts = GetAmounts(wtx, /*include_change=*/false);
    BOOST_REQUIRE_EQUAL(amounts.sent.size(), 1U);
    BOOST_REQUIRE_EQUAL(amounts.received.size(), 1U);
    BOOST_CHECK_EQUAL(amounts.fee, FEE);

    const std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::SendToSelf);
    BOOST_CHECK_EQUAL(history[0].debit, -INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].credit, OUTPUT_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].GetAmount(), -FEE);
    BOOST_CHECK_EQUAL(history[0].GetNet(), -FEE);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, OUTPUT_AMOUNT);
}

// A peg-in hides its canonical bridge output and reports the total base-layer plus MWEB fee.
BOOST_AUTO_TEST_CASE(PeginTracksTransparentDebitAndMWEBCredit)
{
    static constexpr CAmount INPUT_AMOUNT{10'000'000};
    static constexpr CAmount PEGIN_AMOUNT{9'000'000};
    static constexpr CAmount RECEIVE_AMOUNT{8'000'000};
    static constexpr CAmount TOTAL_FEE{2'000'000};
    const COutPoint source = AddLTCFunding(INPUT_AMOUNT);
    const StealthAddress recipient = NewMWEBAddress();
    const test::Tx mweb_tx = test::TxBuilder()
        .AddPeginKernel(PEGIN_AMOUNT, 0)
        .AddOutput(RECEIVE_AMOUNT, SecretKey::Random(), recipient)
        .AddPlainKernel(PEGIN_AMOUNT - RECEIVE_AMOUNT)
        .Build();
    SaveMWEBOutput(mweb_tx.GetOutputs().front(), recipient, /*owned=*/true);

    CMutableTransaction tx = MWEBOnly(mweb_tx);
    tx.vin.emplace_back(source);
    AddPeginOutput(tx, PEGIN_AMOUNT);
    CWalletTx& wtx = AddWalletTx(std::move(tx), Confirmed());

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.debit, INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.change, 0);
    BOOST_CHECK_EQUAL(accounting.available, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.fee, TOTAL_FEE);

    const Amounts amounts = GetAmounts(wtx, /*include_change=*/false);
    BOOST_REQUIRE_EQUAL(amounts.sent.size(), 1U);
    BOOST_REQUIRE_EQUAL(amounts.received.size(), 1U);
    BOOST_CHECK_EQUAL(amounts.sent.front().amount, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(amounts.received.front().amount, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(amounts.fee, TOTAL_FEE);

    const std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::SendToSelf);
    BOOST_CHECK_EQUAL(history[0].GetNet(), -TOTAL_FEE);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, RECEIVE_AMOUNT);
}

// A pegout reports the canonical destination by stable kernel-and-position identity and hides MWEB change.
BOOST_AUTO_TEST_CASE(PegoutTracksDestinationChangeFeeAndComponentID)
{
    static constexpr CAmount INPUT_AMOUNT{10'000'000};
    static constexpr CAmount PEGOUT_AMOUNT{5'000'000};
    static constexpr CAmount CHANGE_AMOUNT{4'000'000};
    static constexpr CAmount FEE{1'000'000};
    const test::TxOutput source = AddMWEBFunding(INPUT_AMOUNT);
    const StealthAddress change_address = MWEBChangeAddress();
    const CTxDestination recipient = NewExternalLTCAddress();

    const test::Tx mweb_tx = test::TxBuilder()
        .AddInput(source)
        .AddOutput(CHANGE_AMOUNT, SecretKey::Random(), change_address)
        .AddPegoutKernel(PEGOUT_AMOUNT, FEE)
        .Build();
    SaveMWEBOutput(mweb_tx.GetOutputs().front(), change_address, /*owned=*/true);
    CWalletTx& wtx = AddWalletTx(WithPegoutScript(mweb_tx, GetScriptForDestination(recipient)), Confirmed());
    const auto pegouts = wtx.GetMWEBPegouts();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, CHANGE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.debit, INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.change, CHANGE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.available, CHANGE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.fee, FEE);

    const Amounts amounts = GetAmounts(wtx, /*include_change=*/false);
    BOOST_REQUIRE_EQUAL(amounts.sent.size(), 1U);
    BOOST_CHECK(amounts.received.empty());
    BOOST_CHECK_EQUAL(amounts.sent.front().amount, PEGOUT_AMOUNT);
    BOOST_CHECK(amounts.sent.front().destination == recipient);
    BOOST_CHECK(amounts.sent.front().component_id == pegouts[0].first);
    BOOST_CHECK_EQUAL(amounts.fee, FEE);

    const std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::SendToAddress);
    BOOST_CHECK_EQUAL(history[0].address, EncodeDestination(recipient));
    BOOST_CHECK_EQUAL(history[0].debit, -PEGOUT_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].fee, -FEE);
    BOOST_CHECK_EQUAL(find_value(history[0].ToUniValue().get_obj(), "pegout").get_str(), pegouts[0].first.kernel_id.ToHex() + ":0");
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, CHANGE_AMOUNT);
}

// A transaction can peg value in and out together; only the final pegout is a sent history component.
BOOST_AUTO_TEST_CASE(CombinedPeginPegoutDoesNotDoubleCountBridgeOutput)
{
    static constexpr CAmount INPUT_AMOUNT{10'000'000};
    static constexpr CAmount PEGIN_AMOUNT{9'000'000};
    static constexpr CAmount PEGOUT_AMOUNT{7'000'000};
    static constexpr CAmount TOTAL_FEE{3'000'000};
    const COutPoint source = AddLTCFunding(INPUT_AMOUNT);
    const CTxDestination recipient = NewExternalLTCAddress();
    const test::Tx mweb_tx = test::TxBuilder()
        .AddPeginKernel(PEGIN_AMOUNT, 0)
        .AddPegoutKernel(PEGOUT_AMOUNT, 1'000'000)
        .AddPlainKernel(1'000'000)
        .Build();

    CMutableTransaction tx = WithPegoutScript(mweb_tx, GetScriptForDestination(recipient));
    tx.vin.emplace_back(source);
    AddPeginOutput(tx, PEGIN_AMOUNT);
    CWalletTx& wtx = AddWalletTx(std::move(tx), Confirmed());

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, 0);
    BOOST_CHECK_EQUAL(accounting.debit, INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.change, 0);
    BOOST_CHECK_EQUAL(accounting.available, 0);
    BOOST_CHECK_EQUAL(accounting.fee, TOTAL_FEE);

    const Amounts amounts = GetAmounts(wtx, /*include_change=*/false);
    BOOST_REQUIRE_EQUAL(amounts.sent.size(), 1U);
    BOOST_CHECK(amounts.received.empty());
    BOOST_CHECK_EQUAL(amounts.sent.front().amount, PEGOUT_AMOUNT);
    BOOST_CHECK_EQUAL(amounts.fee, TOTAL_FEE);

    const std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::SendToAddress);
    BOOST_CHECK_EQUAL(history[0].debit, -PEGOUT_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].fee, -TOTAL_FEE);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, 0);
}

// An ID-only spend removes the source balance without pretending the unknown destination is a self-send or fee.
BOOST_AUTO_TEST_CASE(PartialMWEBSpendDebitsCoinWithoutInventingDetails)
{
    static constexpr CAmount INPUT_AMOUNT{4'000'000};
    const test::TxOutput source = AddMWEBFunding(INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, INPUT_AMOUNT);

    CWalletTx& wtx = AddPartialSpend(source.GetOutputID(), TxStateInMempool{});

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, 0);
    BOOST_CHECK_EQUAL(accounting.debit, INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.change, 0);
    BOOST_CHECK_EQUAL(accounting.available, 0);
    BOOST_CHECK_EQUAL(accounting.fee, 0);

    const Amounts amounts = GetAmounts(wtx, /*include_change=*/false);
    BOOST_CHECK(amounts.sent.empty());
    BOOST_CHECK(amounts.received.empty());
    BOOST_CHECK_EQUAL(amounts.fee, 0);

    const std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::Other);
    BOOST_CHECK_EQUAL(history[0].debit, -INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(history[0].credit, 0);
    BOOST_CHECK_EQUAL(history[0].fee, 0);
    BOOST_CHECK_EQUAL(history[0].GetNet(), -INPUT_AMOUNT);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, 0);
}

// Frozen MWEB outputs remain visible in history but cannot contribute to available balance.
BOOST_AUTO_TEST_CASE(FrozenMWEBReceiveIsVisibleButUnavailable)
{
    static constexpr CAmount RECEIVE_AMOUNT{7'000'000};
    const mw::Hash output_id = mw::Hash::FromHex("2f3a08d9f5ef5f388386c11efe935394b14b524220cff4ec5c81942b82e694f7");
    BOOST_REQUIRE(!Params().GetConsensus().frozen_mweb_output_ids.empty());
    BOOST_REQUIRE(uint256(output_id.vec()) == Params().GetConsensus().frozen_mweb_output_ids.front());
    CWalletTx& wtx = AddPartialReceive(output_id, RECEIVE_AMOUNT, NewMWEBAddress(), Confirmed(6));

    const Accounting accounting = GetAccounting(wtx);
    BOOST_CHECK_EQUAL(accounting.credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(accounting.debit, 0);
    BOOST_CHECK_EQUAL(accounting.change, 0);
    BOOST_CHECK_EQUAL(accounting.available, 0);
    BOOST_CHECK_EQUAL(accounting.fee, 0);

    const std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK_EQUAL(history[0].credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, 0);
}

// MWEB history status and balance buckets follow the complete wallet transaction lifecycle.
BOOST_AUTO_TEST_CASE(MWEBReceiveLifecycleUpdatesStatusAndBalanceBuckets)
{
    static constexpr CAmount CONFIRMING_AMOUNT{1'000'000};
    static constexpr CAmount CONFIRMED_AMOUNT{2'000'000};
    static constexpr CAmount MEMPOOL_AMOUNT{3'000'000};
    static constexpr CAmount CONFLICTED_AMOUNT{4'000'000};
    static constexpr CAmount ABANDONED_AMOUNT{5'000'000};
    const StealthAddress address = NewMWEBAddress();

    CWalletTx& confirming = AddPartialReceive(mw::Hash::ValueOf(201), CONFIRMING_AMOUNT, address, Confirmed());
    CWalletTx& confirmed = AddPartialReceive(mw::Hash::ValueOf(202), CONFIRMED_AMOUNT, address, Confirmed(6));
    CWalletTx& mempool = AddPartialReceive(mw::Hash::ValueOf(203), MEMPOOL_AMOUNT, address, TxStateInMempool{});
    CWalletTx& conflicted = AddPartialReceive(mw::Hash::ValueOf(204), CONFLICTED_AMOUNT, address, TxStateConflicted{TipHash(), TipHeight()});
    CWalletTx& abandoned = AddPartialReceive(mw::Hash::ValueOf(205), ABANDONED_AMOUNT, address, TxStateInactive{/*abandoned=*/true});

    auto check_status = [&](CWalletTx& wtx, TxRecordStatus::Status expected, bool counts_for_balance) {
        std::vector<WalletTxRecord> history = GetHistory(wtx);
        BOOST_REQUIRE_EQUAL(history.size(), 1U);
        UpdateStatus(history[0]);
        BOOST_CHECK(history[0].status.status == expected);
        BOOST_CHECK_EQUAL(history[0].status.countsForBalance, counts_for_balance);
    };
    check_status(confirming, TxRecordStatus::Confirming, true);
    check_status(confirmed, TxRecordStatus::Confirmed, true);
    check_status(mempool, TxRecordStatus::Unconfirmed, false);
    check_status(conflicted, TxRecordStatus::Conflicted, false);
    check_status(abandoned, TxRecordStatus::Abandoned, false);

    const Balance balance = GetBalance(m_wallet);
    BOOST_CHECK_EQUAL(balance.m_mine_trusted, CONFIRMING_AMOUNT + CONFIRMED_AMOUNT);
    BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending, MEMPOOL_AMOUNT);
}

// Watch-only pegouts are returned only for the watch-only filter and carry the ownership marker.
BOOST_AUTO_TEST_CASE(WatchOnlyPegoutRespectsHistoryAndAccountingFilters)
{
    static constexpr CAmount PEGOUT_AMOUNT{9'000'000};
    const CTxDestination watch_address = AddWatchOnlyAddress();
    const test::Tx mweb_tx = test::TxBuilder()
        .AddPeginKernel(PEGOUT_AMOUNT, 0)
        .AddPegoutKernel(PEGOUT_AMOUNT, 0)
        .Build();
    CWalletTx& wtx = AddWalletTx(WithPegoutScript(mweb_tx, GetScriptForDestination(watch_address)), Confirmed(6));

    const Accounting spendable = GetAccounting(wtx, ISMINE_SPENDABLE);
    BOOST_CHECK_EQUAL(spendable.credit, 0);
    BOOST_CHECK_EQUAL(spendable.debit, 0);
    BOOST_CHECK_EQUAL(spendable.available, 0);

    const Accounting watch_only = GetAccounting(wtx, ISMINE_WATCH_ONLY);
    BOOST_CHECK_EQUAL(watch_only.credit, PEGOUT_AMOUNT);
    BOOST_CHECK_EQUAL(watch_only.debit, 0);
    BOOST_CHECK_EQUAL(watch_only.available, 0);
    BOOST_CHECK_EQUAL(watch_only.fee, 0);

    BOOST_CHECK(GetHistory(wtx, ISMINE_SPENDABLE).empty());
    std::vector<WalletTxRecord> history = GetHistory(wtx, ISMINE_WATCH_ONLY);
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK(history[0].type == WalletTxRecord::RecvWithAddress);
    BOOST_CHECK_EQUAL(history[0].credit, PEGOUT_AMOUNT);
    BOOST_CHECK(history[0].involvesWatchAddress);
    BOOST_CHECK(find_value(history[0].ToUniValue().get_obj(), "involvesWatchonly").get_bool());
}

// HogEx history is hidden when the originating MWEB pegout is known and retained otherwise.
BOOST_AUTO_TEST_CASE(HogExSuppressesOnlyKnownPegoutDuplicates)
{
    static constexpr CAmount PEGOUT_AMOUNT{5'000'000};
    const CTxDestination receive_address = NewLTCAddress();
    const CScript receive_script = GetScriptForDestination(receive_address);
    const test::Tx original_mweb_tx = test::TxBuilder()
        .AddPeginKernel(PEGOUT_AMOUNT, 0)
        .AddPegoutKernel(PEGOUT_AMOUNT, 0)
        .Build();
    CWalletTx& original = AddWalletTx(WithPegoutScript(original_mweb_tx, receive_script), Confirmed());
    const auto original_pegouts = original.GetMWEBPegouts();
    BOOST_REQUIRE_EQUAL(original_pegouts.size(), 1U);
    BOOST_REQUIRE_EQUAL(GetHistory(original).size(), 1U);

    CMutableTransaction known_hogex;
    known_hogex.m_hogEx = true;
    known_hogex.nLockTime = 1;
    known_hogex.vout.emplace_back(PEGOUT_AMOUNT, receive_script);
    CWalletTx& known = AddWalletTx(std::move(known_hogex), Confirmed(7));
    known.pegout_indices = {{original_pegouts[0].first.kernel_id, original_pegouts[0].first.pos}};
    BOOST_CHECK(known.IsHogEx());
    BOOST_CHECK(GetHistory(known).empty());

    CMutableTransaction unknown_hogex;
    unknown_hogex.m_hogEx = true;
    unknown_hogex.nLockTime = 2;
    unknown_hogex.vout.emplace_back(PEGOUT_AMOUNT + 1, receive_script);
    CWalletTx& unknown = AddWalletTx(std::move(unknown_hogex), Confirmed(7));
    unknown.pegout_indices = {{mw::Hash::ValueOf(99), 0}};
    BOOST_CHECK(unknown.GetHash() != known.GetHash());
    BOOST_CHECK_EQUAL(GetAccounting(unknown).credit, PEGOUT_AMOUNT + 1);
    BOOST_CHECK(m_wallet.FindWalletTxByKernelId(unknown.pegout_indices.front().first) == nullptr);
    std::vector<WalletTxRecord> unknown_history = GetHistory(unknown);
    BOOST_REQUIRE_EQUAL(unknown_history.size(), 1U);
    BOOST_CHECK(unknown_history[0].type == WalletTxRecord::RecvWithAddress);
    BOOST_CHECK_EQUAL(unknown_history[0].credit, PEGOUT_AMOUNT + 1);
    BOOST_CHECK_EQUAL(unknown_history[0].address, EncodeDestination(receive_address));
}

// Upgrading an ID-only receive to the full MWEB transaction preserves one balance and one history row.
BOOST_AUTO_TEST_CASE(PartialReceiveUpgradeDoesNotDoubleCountAccountingOrHistory)
{
    static constexpr CAmount RECEIVE_AMOUNT{6'000'000};
    const StealthAddress receive_address = NewMWEBAddress();
    const test::Tx full_mweb_tx = test::TxBuilder()
        .AddPeginKernel(RECEIVE_AMOUNT, 0)
        .AddOutput(RECEIVE_AMOUNT, SecretKey::Random(), receive_address)
        .Build();
    const test::TxOutput& output = full_mweb_tx.GetOutputs().front();
    SaveMWEBOutput(output, receive_address, /*owned=*/true);

    CWalletTx& partial = AddPartialReceive(output.GetOutputID(), RECEIVE_AMOUNT, receive_address, Confirmed(6));
    BOOST_REQUIRE(partial.IsPartialMWEB());
    BOOST_CHECK_EQUAL(GetAccounting(partial).credit, RECEIVE_AMOUNT);
    BOOST_REQUIRE_EQUAL(GetAllHistory().size(), 1U);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, RECEIVE_AMOUNT);

    CWalletTx& upgraded = AddWalletTx(MWEBOnly(full_mweb_tx), Confirmed(6));
    BOOST_CHECK(!upgraded.IsPartialMWEB());
    BOOST_CHECK_EQUAL(m_wallet.mapWallet.size(), 1U);
    BOOST_CHECK_EQUAL(GetAccounting(upgraded).credit, RECEIVE_AMOUNT);
    const std::vector<WalletTxRecord> history = GetAllHistory();
    BOOST_REQUIRE_EQUAL(history.size(), 1U);
    BOOST_CHECK_EQUAL(history[0].credit, RECEIVE_AMOUNT);
    BOOST_CHECK_EQUAL(GetBalance(m_wallet).m_mine_trusted, RECEIVE_AMOUNT);
}

// Mixed history components are stable and sort as transparent, MWEB, then pegout.
BOOST_AUTO_TEST_CASE(MixedReceiveComponentsHaveStableIDsAndOrdering)
{
    static constexpr CAmount LTC_AMOUNT{2'000'000};
    static constexpr CAmount MWEB_AMOUNT{3'000'000};
    static constexpr CAmount PEGOUT_AMOUNT{5'000'000};
    const CTxDestination ltc_address = NewLTCAddress();
    const CTxDestination pegout_address = NewLTCAddress();
    const StealthAddress mweb_address = NewMWEBAddress();
    const test::Tx mweb_tx = test::TxBuilder()
        .AddPeginKernel(MWEB_AMOUNT + PEGOUT_AMOUNT, 0)
        .AddOutput(MWEB_AMOUNT, SecretKey::Random(), mweb_address)
        .AddPegoutKernel(PEGOUT_AMOUNT, 0)
        .Build();
    SaveMWEBOutput(mweb_tx.GetOutputs().front(), mweb_address, /*owned=*/true);

    CMutableTransaction tx = WithPegoutScript(mweb_tx, GetScriptForDestination(pegout_address));
    tx.vout.emplace_back(LTC_AMOUNT, GetScriptForDestination(ltc_address));
    CWalletTx& wtx = AddWalletTx(std::move(tx), Confirmed(6));
    const auto pegouts = wtx.GetMWEBPegouts();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);

    std::vector<WalletTxRecord> history = GetHistory(wtx);
    BOOST_REQUIRE_EQUAL(history.size(), 3U);
    BOOST_CHECK_EQUAL(history[0].GetComponentIndex(), "0");
    BOOST_CHECK_EQUAL(find_value(history[0].ToUniValue().get_obj(), "vout").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(find_value(history[1].ToUniValue().get_obj(), "mweb_out").get_str(), mweb_tx.GetOutputs().front().GetOutputID().ToHex());
    BOOST_CHECK_EQUAL(find_value(history[2].ToUniValue().get_obj(), "pegout").get_str(), pegouts[0].first.kernel_id.ToHex() + ":0");

    for (WalletTxRecord& record : history) {
        UpdateStatus(record);
    }
    BOOST_CHECK_LT(history[0].status.sortKey, history[1].status.sortKey);
    BOOST_CHECK_LT(history[1].status.sortKey, history[2].status.sortKey);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
