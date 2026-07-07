// Copyright (c) 2023 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/WalletCoin.h>
#include <mw/models/wallet/StealthAddress.h>
#include <psbt.h>
#include <validation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/txbuilder.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <set>

namespace wallet {

class TxBuilderTestingSetup : public TestChain100Setup
{
public:
    CWallet m_wallet;

    TxBuilderTestingSetup()
        : m_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase())
    {
        m_wallet.LoadWallet();
        m_wallet.LoadMinVersion(FEATURE_MWEB);
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();

        FlatSigningProvider provider;
        std::string error;
        WalletDescriptor desc(Parse("combo(" + EncodeSecret(coinbaseKey) + ")", provider, error, false), 0, 0, 1, 1);
        m_wallet.AddWalletDescriptor(desc, provider, "", false);

        m_wallet.SetBroadcastTransactions(true);
        SetMockTime(1601450001);
        mineBlocks(331); // Pre-MWEB activation blocks
        m_build_block_with_mempool = true;
    }

    void mineBlocks(int num_blocks)
    {
        LOCK2(m_node.chainman->GetMutex(), m_wallet.cs_wallet);
        const CChain& cchain = m_node.chainman->ActiveChain();
        uint256 prev_block = cchain.Tip()->GetBlockHash();
        int prev_height = cchain.Height();

        TestChain100Setup::mineBlocks(num_blocks);
        m_wallet.SetLastBlockProcessed(cchain.Height(), cchain.Tip()->GetBlockHash());

        WalletRescanReserver reserver(m_wallet);
        reserver.reserve();
        auto res = m_wallet.ScanForWalletTransactions(prev_block, prev_height, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK(res.status == res.SUCCESS);
    }

    std::pair<CWalletTx*, CMutableTransaction> AddTx(
        const std::vector<CRecipient>& recipients,
        const std::vector<AnyWalletUTXO>& select_coins,
        std::optional<CTxDestination> change_address,
        const std::optional<int32_t>& nVersion = std::nullopt,
        const std::optional<uint32_t>& nLockTime = std::nullopt)
    {
        CCoinControl coin_control;
        if (!select_coins.empty()) {
            for (const auto& coin : select_coins) {
                coin_control.Select(coin.GetID());
            }
        }
        if (change_address) {
            coin_control.destChange = *change_address;
        }

        auto res = WITH_LOCK(m_wallet.cs_wallet, return TxBuilder::New(m_wallet, coin_control, recipients, recipients.size())->Build(nVersion, nLockTime, true));
        BOOST_REQUIRE(res);
        auto tx = MakeTransactionRef(res->tx);
        m_wallet.CommitTransaction(tx, {}, {});
        mineBlocks(1);

        LOCK2(m_node.chainman->GetMutex(), m_wallet.cs_wallet);
        const CChain& cchain = m_node.chainman->ActiveChain();
        auto it = m_wallet.mapWallet.find(tx->GetHash());
        BOOST_REQUIRE(it != m_wallet.mapWallet.end());
        it->second.m_state = TxStateConfirmed{cchain.Tip()->GetBlockHash(), cchain.Height(), /*index=*/1};
        return std::make_pair(&it->second, res->tx);
    }

    util::Result<CreatedTransactionResult> BuildTx(
        const std::vector<CRecipient>& recipients,
        std::optional<CTxDestination> change_address,
        bool sign)
    {
        CCoinControl coin_control;
        if (change_address) {
            coin_control.destChange = *change_address;
        }

        LOCK(m_wallet.cs_wallet);
        return TxBuilder::New(m_wallet, coin_control, recipients, std::nullopt)->Build(std::nullopt, std::nullopt, sign);
    }

    util::Result<CreatedTransactionResult> BuildTx(
        const std::vector<CRecipient>& recipients,
        const std::vector<AnyWalletUTXO>& select_coins,
        std::optional<CTxDestination> change_address,
        bool sign,
        bool allow_other_inputs = false)
    {
        CCoinControl coin_control;
        coin_control.m_allow_other_inputs = allow_other_inputs;
        if (!select_coins.empty()) {
            for (const auto& coin : select_coins) {
                coin_control.Select(coin.GetID());
            }
        }
        if (change_address) {
            coin_control.destChange = *change_address;
        }

        LOCK(m_wallet.cs_wallet);
        return TxBuilder::New(m_wallet, coin_control, recipients, std::nullopt)->Build(std::nullopt, std::nullopt, sign);
    }

    std::vector<AnyWalletUTXO> AvailableCoinsByType(OutputType type)
    {
        LOCK(m_wallet.cs_wallet);
        auto coins = AvailableCoins(m_wallet).coins;
        std::vector<AnyWalletUTXO> coins_by_type = coins[type];
        if (type == OutputType::MWEB) {
            coins_by_type.erase(
                std::remove_if(
                    coins_by_type.begin(), coins_by_type.end(),
                    [](const AnyWalletUTXO& coin) { return coin.GetMWEB().coin.IsChange(); }
                ),
                coins_by_type.end()
            );
        }
        return coins_by_type;
    }

    std::vector<AnyWalletUTXO> AvailableLTCCoins()
    {
        LOCK(m_wallet.cs_wallet);
        std::vector<AnyWalletUTXO> coins;
        for (const AnyWalletUTXO& coin : AvailableCoins(m_wallet).All()) {
            if (!coin.IsMWEB()) {
                coins.push_back(coin);
            }
        }
        return coins;
    }

    CTxDestination NewDestination(OutputType type)
    {
        auto dest = m_wallet.GetNewDestination(type, "");
        BOOST_REQUIRE(dest);
        if (type == OutputType::MWEB) {
            // Coin::IsChange still treats address_index 0 as change, so don't
            // hand that descriptor address out as a test recipient.
            const mw::Keychain::Ptr keychain = ActiveMWEBKeychain();
            while (std::holds_alternative<StealthAddress>(*dest) &&
                   keychain->LookupAddressIndex(std::get<StealthAddress>(*dest)) == mw::CHANGE_INDEX) {
                dest = m_wallet.GetNewDestination(type, "");
                BOOST_REQUIRE(dest);
            }
        }
        return *dest;
    }

    mw::Keychain::Ptr ActiveMWEBKeychain() const
    {
        auto spk_man = m_wallet.GetScriptPubKeyMan(OutputType::MWEB, false);
        BOOST_REQUIRE(spk_man);
        mw::Keychain::Ptr keychain = spk_man->GetMWEBKeychain();
        BOOST_REQUIRE(keychain);
        return keychain;
    }

    MWEB::Wallet& MWEBWallet() const
    {
        return *m_wallet.GetMWWallet();
    }

    mw::WalletCoin GetMWEBWalletCoin(const mw::Hash& output_id)
    {
        LOCK(m_wallet.cs_wallet);
        mw::WalletCoin coin;
        BOOST_REQUIRE(m_wallet.GetMWEBWalletCoin(output_id, coin));
        return coin;
    }

    TransactionError FillPSBTWithWallet(PartiallySignedTransaction& psbt, bool& complete, bool sign, bool bip32derivs)
    {
        LOCK(m_wallet.cs_wallet);
        return m_wallet.FillPSBT(psbt, complete, SIGHASH_ALL, sign, bip32derivs);
    }

    CTxDestination ExtractDestinationForOutput(const CWalletTx& wtx, const mw::Hash& output_id)
    {
        LOCK(m_wallet.cs_wallet);
        CTxDestination dest;
        BOOST_REQUIRE(m_wallet.ExtractOutputDestination(wtx, AnyOutputID{output_id}, dest));
        return dest;
    }

    bool SignWithWallet(CMutableTransaction& tx)
    {
        LOCK(m_wallet.cs_wallet);
        return m_wallet.SignTransaction(tx);
    }

    void ExpectInputs(const CWalletTx& wtx, size_t ltc, size_t mweb)
    {
        const auto& inputs = wtx.GetInputs();
        BOOST_REQUIRE_EQUAL(inputs.size(), ltc + mweb);
        for (size_t i = 0; i < ltc; i++) {
            BOOST_CHECK(!inputs[i].IsMWEB());
        }
        for (size_t i = ltc; i < inputs.size(); i++) {
            BOOST_CHECK(inputs[i].IsMWEB());
        }
    }

    void ExpectOutputs(const CWalletTx& wtx, size_t ltc, size_t mweb)
    {
        const auto& outputs = wtx.GetTxOutputs();
        BOOST_REQUIRE_EQUAL(outputs.size(), ltc + mweb);
        for (size_t i = 0; i < ltc; i++) {
            BOOST_CHECK(!outputs[i].IsMWEB());
        }
        for (size_t i = ltc; i < outputs.size(); i++) {
            BOOST_CHECK(outputs[i].IsMWEB());
        }
    }

    template<typename T, typename F>
    void ExpectAmounts(const std::vector<T>& v, F fn, std::vector<CAmount> expected, bool sort = false)
    {
        BOOST_REQUIRE_EQUAL(v.size(), expected.size());
        std::vector<CAmount> amounts;
        std::transform(v.cbegin(), v.cend(), std::back_inserter(amounts), fn);
        if (sort) {
            std::sort(amounts.begin(), amounts.end());
            std::sort(expected.begin(), expected.end());
        }
        for (size_t i = 0; i < amounts.size(); i++) {
            BOOST_CHECK_LT(std::abs(amounts[i] - expected[i]), 100000);
        }
    }

    void ExpectCoins(const std::vector<CAmount>& ltc, const std::vector<CAmount>& mweb)
    {
        LOCK(m_wallet.cs_wallet);
        auto coins = AvailableCoins(m_wallet).coins;
        std::vector<AnyWalletUTXO> mweb_coins = coins[OutputType::MWEB];
        mweb_coins.erase(
            std::remove_if(
                mweb_coins.begin(), mweb_coins.end(),
                [](const AnyWalletUTXO& coin) { return coin.GetMWEB().coin.IsChange(); }
            ),
            mweb_coins.end()
        );
        auto fn = [](const AnyWalletUTXO& utxo) { return utxo.GetValue(); };
        ExpectAmounts(coins[OutputType::BECH32], fn, ltc, true);
        ExpectAmounts(mweb_coins, fn, mweb, true);
    }

    AnyWalletUTXO SmallestCoin(const std::vector<AnyWalletUTXO>& coins)
    {
        BOOST_REQUIRE(!coins.empty());
        return *std::min_element(coins.begin(), coins.end(), [](const AnyWalletUTXO& a, const AnyWalletUTXO& b) { return a.GetValue() < b.GetValue(); });
    }

    static constexpr auto voutfn = [](const CTxOut& utxo) { return utxo.nValue; };
    static constexpr auto mwoutfn = [](const mw::MutableOutput& utxo) { return *utxo.amount; };
    static constexpr auto peginfn = [](const PegInCoin& pegin) { return pegin.GetAmount(); };
    static constexpr auto pegoutfn = [](const PegOutCoin& pegout) { return pegout.GetAmount(); };

    void SingleRecipientTest(bool fSubtractFeeFromAmount, bool use_custom_change)
    {
        std::optional<CTxDestination> ltc_change, mweb_change;
        if (use_custom_change) {
            ltc_change = NewDestination(OutputType::BECH32);
            mweb_change = NewDestination(OutputType::MWEB);
        }

        {   // Pegin & Activate MWEB
            auto mweb_addr = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({{mweb_addr, 5 * COIN, fSubtractFeeFromAmount}}, {}, mweb_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 1, 2); // Single LTC pegin output (all pegged-in), MWEB recipient output and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {125 * COIN/10});

            auto pegins = mtx.mweb_tx.GetPegIns();
            ExpectAmounts(pegins, peginfn, {125 * COIN/10});
            BOOST_CHECK(mtx.vout[0].scriptPubKey == GetScriptForPegin(pegins[0].GetKernelID()));

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {5 * COIN, 75 * COIN/10});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_change);

            ExpectCoins({}, mweb_change ? std::vector<CAmount>{5 * COIN, 75 * COIN/10} : std::vector<CAmount>{5 * COIN});
        }

        {   // LTC to LTC
            auto ltc_addr = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({{ltc_addr, 2 * COIN, fSubtractFeeFromAmount}}, {}, ltc_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 2, 0);
            ExpectAmounts(mtx.vout, voutfn, {2 * COIN, 105 * COIN/10});

            BOOST_CHECK(GenericAddress(mtx.vout[0].scriptPubKey) == ltc_addr);
            if (ltc_change) BOOST_CHECK(GenericAddress(mtx.vout[1].scriptPubKey) == ltc_change);

            ExpectCoins({2 * COIN, 105 * COIN/10}, mweb_change ? std::vector<CAmount>{5 * COIN, 75 * COIN/10} : std::vector<CAmount>{5 * COIN});
        }

        {   // MWEB to MWEB
            auto mweb_addr = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({{mweb_addr, 2 * COIN, fSubtractFeeFromAmount}}, {SmallestCoin(AvailableCoinsByType(OutputType::MWEB))}, mweb_change);

            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 2);

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {2 * COIN, 3 * COIN});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_change);

            ExpectCoins({2 * COIN, 105 * COIN/10}, mweb_change ? std::vector<CAmount>{2 * COIN, 3 * COIN, 75 * COIN/10} : std::vector<CAmount>{2 * COIN});
        }

        {   // Pegout
            LOCK(m_wallet.cs_wallet);
            auto ltc_addr = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({{ltc_addr, 1 * COIN, fSubtractFeeFromAmount}}, {SmallestCoin(AvailableCoinsByType(OutputType::MWEB))}, mweb_change);

            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 1);

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {1 * COIN});
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_change);

            auto pegouts = mtx.mweb_tx.GetPegOutCoins();
            ExpectAmounts(pegouts, pegoutfn, {1 * COIN});
            BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == ltc_addr);

            mineBlocks(PEGOUT_MATURITY);
            ExpectCoins({1 * COIN, 2 * COIN, 105 * COIN/10}, mweb_change ? std::vector<CAmount>{1 * COIN, 3 * COIN, 75 * COIN/10} : std::vector<CAmount>{});
        }

        if (mweb_change) {   // Pegin & Pegout
            LOCK(m_wallet.cs_wallet);
            auto ltc_addr = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({{ltc_addr, 5 * COIN/10, fSubtractFeeFromAmount}}, {SmallestCoin(AvailableCoinsByType(OutputType::BECH32)), SmallestCoin(AvailableCoinsByType(OutputType::MWEB))}, mweb_change);

            ExpectInputs(*wtx, 1, 1);
            ExpectOutputs(*wtx, 1, 1); // LTC pegin output and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {1 * COIN});

            auto pegins = mtx.mweb_tx.GetPegIns();
            ExpectAmounts(pegins, peginfn, {1 * COIN});
            BOOST_CHECK(mtx.vout[0].scriptPubKey == GetScriptForPegin(pegins[0].GetKernelID()));

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {15 * COIN/10});
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_change);

            auto pegouts = mtx.mweb_tx.GetPegOutCoins();
            ExpectAmounts(pegouts, pegoutfn, {5 * COIN/10});
            BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == ltc_addr);

            mineBlocks(PEGOUT_MATURITY);
            ExpectCoins({5 * COIN/10, 2 * COIN, 105 * COIN/10}, {15 * COIN/10, 3 * COIN, 75 * COIN/10});
        }
    }

    void MultipleRecipientsTest(bool fSubtractFeeFromAmount, bool use_custom_change)
    {
        std::optional<CTxDestination> ltc_change, mweb_change;
        if (use_custom_change) {
            ltc_change = NewDestination(OutputType::BECH32);
            mweb_change = NewDestination(OutputType::MWEB);
        }

        {   // Pegin & Activate MWEB
            auto mweb_addr1 = NewDestination(OutputType::MWEB);
            auto mweb_addr2 = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({
                {mweb_addr1, 2 * COIN, fSubtractFeeFromAmount},
                {mweb_addr2, 3 * COIN, fSubtractFeeFromAmount},
            }, {}, mweb_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 1, 3); // Single LTC pegin output (all pegged-in), MWEB recipient outputs and MWEB change output
            ExpectAmounts(mtx.vout, voutfn, {125 * COIN/10});

            auto pegins = mtx.mweb_tx.GetPegIns();
            ExpectAmounts(pegins, peginfn, {125 * COIN/10});
            BOOST_CHECK(mtx.vout[0].scriptPubKey == GetScriptForPegin(pegins[0].GetKernelID()));

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {2 * COIN, 3 * COIN, 75 * COIN/10});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr1);
            BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_addr2);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[2].address) == mweb_change);

            ExpectCoins({}, mweb_change ? std::vector<CAmount>{2 * COIN, 3 * COIN, 75 * COIN/10} : std::vector<CAmount>{2 * COIN, 3 * COIN});
        }

        {   // LTC to LTC
            auto ltc_addr1 = NewDestination(OutputType::BECH32);
            auto ltc_addr2 = NewDestination(OutputType::BECH32);
            auto [wtx, mtx] = AddTx({
                {ltc_addr1, 2 * COIN, fSubtractFeeFromAmount},
                {ltc_addr2, 3 * COIN, fSubtractFeeFromAmount},
            }, {}, ltc_change);

            ExpectInputs(*wtx, 1, 0);
            ExpectOutputs(*wtx, 3, 0);
            ExpectAmounts(mtx.vout, voutfn, {2 * COIN, 3 * COIN, 75 * COIN/10});

            BOOST_CHECK(GenericAddress(mtx.vout[0].scriptPubKey) == ltc_addr1);
            BOOST_CHECK(GenericAddress(mtx.vout[1].scriptPubKey) == ltc_addr2);
            if (ltc_change) BOOST_CHECK(GenericAddress(mtx.vout[2].scriptPubKey) == ltc_change);

            ExpectCoins({2 * COIN, 3 * COIN, 75 * COIN/10}, mweb_change ? std::vector<CAmount>{2 * COIN, 3 * COIN, 75 * COIN/10} : std::vector<CAmount>{2 * COIN, 3 * COIN});
        }

        if (mweb_change) {   // MWEB to MWEB
            auto mweb_addr1 = NewDestination(OutputType::MWEB);
            auto mweb_addr2 = NewDestination(OutputType::MWEB);
            auto [wtx, mtx] = AddTx({
                {mweb_addr1, 2 * COIN, fSubtractFeeFromAmount},
                {mweb_addr2, 3 * COIN, fSubtractFeeFromAmount},
            }, {}, mweb_change);

            ExpectInputs(*wtx, 0, 1);
            ExpectOutputs(*wtx, 0, 3);

            auto mweb_outputs = mtx.mweb_tx.outputs;
            ExpectAmounts(mweb_outputs, mwoutfn, {2 * COIN, 3 * COIN, 25 * COIN/10});
            BOOST_CHECK(GenericAddress(*mweb_outputs[0].address) == mweb_addr1);
            BOOST_CHECK(GenericAddress(*mweb_outputs[1].address) == mweb_addr2);
            if (mweb_change) BOOST_CHECK(GenericAddress(*mweb_outputs[2].address) == mweb_change);

            ExpectCoins({2 * COIN, 3 * COIN, 75 * COIN/10}, mweb_change ? std::vector<CAmount>{2 * COIN, 2 * COIN, 3 * COIN, 3 * COIN, 25 * COIN/10} : std::vector<CAmount>{2 * COIN, 3 * COIN});
        }

        // Pegout to multiple recipients currently disallowed
    }
};

BOOST_FIXTURE_TEST_SUITE(txbuilder_tests, TxBuilderTestingSetup)

BOOST_AUTO_TEST_CASE(SingleRecipientBasicTest)
{
    SingleRecipientTest(false, false);
}

BOOST_AUTO_TEST_CASE(SingleRecipientSubtractFeeFromOutputsTest)
{
    SingleRecipientTest(true, false);
}

BOOST_AUTO_TEST_CASE(SingleRecipientCustomChangeTest)
{
    SingleRecipientTest(false, true);
}

BOOST_AUTO_TEST_CASE(MultipleRecipientsBasicTest)
{
    MultipleRecipientsTest(false, false);
}

BOOST_AUTO_TEST_CASE(MultipleRecipientsSubtractFeeFromOutputsTest)
{
    MultipleRecipientsTest(true, false);
}

BOOST_AUTO_TEST_CASE(MultipleRecipientsCustomChangeTest)
{
    MultipleRecipientsTest(false, true);
}

BOOST_AUTO_TEST_CASE(MWEBRecipientWithExplicitLTCChangeBuildsPeginPegout)
{
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);
    const CTxDestination ltc_change = NewDestination(OutputType::BECH32);

    auto tx_result = BuildTx({{recipient_addr, 5 * COIN, false}}, ltc_change, true);
    BOOST_REQUIRE(tx_result);

    const CMutableTransaction& tx = tx_result->tx;
    BOOST_REQUIRE(!tx.vin.empty());
    BOOST_CHECK(tx.mweb_tx.inputs.empty());
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.outputs.size(), 1U);
    BOOST_REQUIRE(tx.mweb_tx.outputs[0].address.has_value());
    BOOST_CHECK(GenericAddress(*tx.mweb_tx.outputs[0].address) == recipient_addr);

    BOOST_REQUIRE(tx_result->change_pos.IsPegout());
    BOOST_CHECK_EQUAL(tx_result->change_pos.ToPegout().idx, 0U);

    const auto pegouts = tx.mweb_tx.GetPegOutCoins();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);
    BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == ltc_change);
    BOOST_CHECK_GT(pegouts[0].GetAmount(), 0);

    BOOST_REQUIRE(!tx.vout.empty());
    BOOST_CHECK(tx.vout.back().scriptPubKey.IsMWEBPegin());
    BOOST_REQUIRE(tx.mweb_tx.GetPeginAmount().has_value());
    BOOST_CHECK_EQUAL(tx.vout.back().nValue, *tx.mweb_tx.GetPeginAmount());
    BOOST_CHECK_GT(*tx.mweb_tx.GetPeginAmount(), tx.mweb_tx.outputs[0].amount.value_or(0) + pegouts[0].GetAmount());
}

BOOST_AUTO_TEST_CASE(MWEBRecipientWithExplicitLTCChangeSelectedMWEBBuildsPegout)
{
    const CTxDestination existing_mweb_addr = NewDestination(OutputType::MWEB);
    AddTx({{existing_mweb_addr, 5 * COIN, false}}, {}, std::nullopt);

    const AnyWalletUTXO mweb_coin = SmallestCoin(AvailableCoinsByType(OutputType::MWEB));
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);
    const CTxDestination ltc_change = NewDestination(OutputType::BECH32);

    auto tx_result = BuildTx({{recipient_addr, 2 * COIN, false}}, {mweb_coin}, ltc_change, true);
    BOOST_REQUIRE(tx_result);

    const CMutableTransaction& tx = tx_result->tx;
    BOOST_CHECK(tx.vin.empty());
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.outputs.size(), 1U);
    BOOST_REQUIRE(tx.mweb_tx.outputs[0].address.has_value());
    BOOST_CHECK(GenericAddress(*tx.mweb_tx.outputs[0].address) == recipient_addr);

    const auto pegouts = tx.mweb_tx.GetPegOutCoins();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);
    BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == ltc_change);
    BOOST_CHECK_GT(pegouts[0].GetAmount(), 0);
    BOOST_REQUIRE(tx_result->change_pos.IsPegout());
    BOOST_CHECK_EQUAL(tx_result->change_pos.ToPegout().idx, 0U);
}

BOOST_AUTO_TEST_CASE(MWEBRecipientWithSelectedLTCInputBuildsPegin)
{
    const AnyWalletUTXO ltc_coin = SmallestCoin(AvailableLTCCoins());
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);

    auto tx_result = BuildTx({{recipient_addr, 5 * COIN, false}}, {ltc_coin}, std::nullopt, true);
    BOOST_REQUIRE(tx_result);

    const CMutableTransaction& tx = tx_result->tx;
    BOOST_REQUIRE_EQUAL(tx.vin.size(), 1U);
    BOOST_CHECK(tx.mweb_tx.inputs.empty());
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 1U);
    BOOST_CHECK(tx.vout.back().scriptPubKey.IsMWEBPegin());
    BOOST_REQUIRE(tx_result->change_pos.IsMWEB());
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.outputs.size(), 2U);
    BOOST_REQUIRE(tx.mweb_tx.outputs[0].address.has_value());
    BOOST_CHECK(GenericAddress(*tx.mweb_tx.outputs[0].address) == recipient_addr);
}

BOOST_AUTO_TEST_CASE(MWEBRecipientWithExplicitLTCChangeCanUseMWEBAndLTCInputs)
{
    const CTxDestination existing_mweb_addr = NewDestination(OutputType::MWEB);
    AddTx({{existing_mweb_addr, 1 * COIN, false}}, {}, std::nullopt);

    const AnyWalletUTXO mweb_coin = SmallestCoin(AvailableCoinsByType(OutputType::MWEB));
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);
    const CTxDestination ltc_change = NewDestination(OutputType::BECH32);

    auto tx_result = BuildTx({{recipient_addr, 20 * COIN, false}}, {mweb_coin}, ltc_change, true, /*allow_other_inputs=*/true);
    BOOST_REQUIRE(tx_result);

    const CMutableTransaction& tx = tx_result->tx;
    BOOST_REQUIRE(!tx.vin.empty());
    BOOST_REQUIRE_GE(tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.outputs.size(), 1U);
    BOOST_REQUIRE(tx.mweb_tx.outputs[0].address.has_value());
    BOOST_CHECK(GenericAddress(*tx.mweb_tx.outputs[0].address) == recipient_addr);

    const auto pegouts = tx.mweb_tx.GetPegOutCoins();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);
    BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == ltc_change);
    BOOST_REQUIRE(tx_result->change_pos.IsPegout());
    BOOST_CHECK_EQUAL(tx_result->change_pos.ToPegout().idx, 0U);

    BOOST_REQUIRE_EQUAL(tx.vout.size(), 1U);
    BOOST_CHECK(tx.vout.back().scriptPubKey.IsMWEBPegin());
    BOOST_REQUIRE(tx.mweb_tx.GetPeginAmount().has_value());
    BOOST_CHECK_EQUAL(tx.vout.back().nValue, *tx.mweb_tx.GetPeginAmount());
}

BOOST_AUTO_TEST_CASE(LTCRecipientWithExplicitLTCChangeSelectedMWEBBuildsPegout)
{
    const CTxDestination existing_mweb_addr = NewDestination(OutputType::MWEB);
    AddTx({{existing_mweb_addr, 5 * COIN, false}}, {}, std::nullopt);

    const AnyWalletUTXO mweb_coin = SmallestCoin(AvailableCoinsByType(OutputType::MWEB));
    const CTxDestination recipient_addr = NewDestination(OutputType::BECH32);
    const CTxDestination ltc_change = NewDestination(OutputType::BECH32);

    auto tx_result = BuildTx({{recipient_addr, 1 * COIN, false}}, {mweb_coin}, ltc_change, true);
    BOOST_REQUIRE(tx_result);

    const CMutableTransaction& tx = tx_result->tx;
    BOOST_CHECK(tx.vin.empty());
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.inputs.size(), 1U);
    BOOST_CHECK(tx.mweb_tx.outputs.empty());

    const auto pegouts = tx.mweb_tx.GetPegOutCoins();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 2U);
    BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == recipient_addr);
    BOOST_CHECK(GenericAddress(pegouts[1].GetScriptPubKey()) == ltc_change);
    BOOST_REQUIRE(tx_result->change_pos.IsPegout());
    BOOST_CHECK_EQUAL(tx_result->change_pos.ToPegout().idx, 1U);
}

BOOST_AUTO_TEST_CASE(LTCRecipientWithExplicitMWEBChangeBuildsPeginPegout)
{
    const CTxDestination recipient_addr = NewDestination(OutputType::BECH32);
    const CTxDestination mweb_change = NewDestination(OutputType::MWEB);

    auto tx_result = BuildTx({{recipient_addr, 1 * COIN, false}}, mweb_change, true);
    BOOST_REQUIRE(tx_result);

    const CMutableTransaction& tx = tx_result->tx;
    BOOST_REQUIRE(!tx.vin.empty());
    BOOST_REQUIRE(tx_result->change_pos.IsMWEB());

    BOOST_REQUIRE_EQUAL(tx.vout.size(), 1U);
    BOOST_CHECK(tx.vout.back().scriptPubKey.IsMWEBPegin());

    const auto pegouts = tx.mweb_tx.GetPegOutCoins();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);
    BOOST_CHECK(GenericAddress(pegouts[0].GetScriptPubKey()) == recipient_addr);

    BOOST_REQUIRE_EQUAL(tx.mweb_tx.outputs.size(), 1U);
    BOOST_REQUIRE(tx.mweb_tx.outputs[0].address.has_value());
    BOOST_CHECK(GenericAddress(*tx.mweb_tx.outputs[0].address) == mweb_change);
    BOOST_REQUIRE(tx.mweb_tx.outputs[0].amount.has_value());
    BOOST_CHECK_GT(*tx.mweb_tx.outputs[0].amount, 0);
}

BOOST_AUTO_TEST_CASE(MWEBChangePositionTracksChangeWhenAddressMatchesRecipient)
{
    const CTxDestination shared_mweb_addr = NewDestination(OutputType::MWEB);

    // Create an MWEB coin that we can spend in the next transaction.
    AddTx({{shared_mweb_addr, 5 * COIN, false}}, {}, std::nullopt);

    constexpr CAmount RECIPIENT_AMOUNT{2 * COIN};
    std::vector<CRecipient> recipients{{shared_mweb_addr, RECIPIENT_AMOUNT, false}};
    auto tx_result = BuildTx(recipients, shared_mweb_addr, true);
    BOOST_REQUIRE(tx_result);
    BOOST_REQUIRE(tx_result->change_pos.IsMWEB());
    BOOST_REQUIRE(tx_result->change_pos.ToMWEB().hash.has_value());

    const mw::Hash& change_output_id = *tx_result->change_pos.ToMWEB().hash;
    const auto change_output_iter = std::find_if(
        tx_result->tx.mweb_tx.outputs.cbegin(), tx_result->tx.mweb_tx.outputs.cend(),
        [&change_output_id](const mw::MutableOutput& output) {
            const std::optional<mw::Hash> output_id = output.CalcOutputID();
            return output_id.has_value() && *output_id == change_output_id;
        }
    );

    BOOST_REQUIRE(change_output_iter != tx_result->tx.mweb_tx.outputs.cend());
    BOOST_REQUIRE(change_output_iter->amount.has_value());
    BOOST_CHECK(*change_output_iter->amount > RECIPIENT_AMOUNT);

    std::vector<mw::Hash> sorted_output_ids;
    for (const mw::MutableOutput& output : tx_result->tx.mweb_tx.outputs) {
        const std::optional<mw::Hash> output_id = output.CalcOutputID();
        BOOST_REQUIRE(output_id.has_value());
        sorted_output_ids.push_back(*output_id);
    }

    std::sort(sorted_output_ids.begin(), sorted_output_ids.end());
    BOOST_REQUIRE_LT(tx_result->change_pos.ToMWEB().idx, sorted_output_ids.size());
    BOOST_CHECK(sorted_output_ids[tx_result->change_pos.ToMWEB().idx] == change_output_id);
}

BOOST_AUTO_TEST_CASE(MWEBSentExternalOutputKeepsRecipientAddress)
{
    const StealthAddress recipient_addr = StealthAddress::Random();
    auto [wtx, mtx] = AddTx({{recipient_addr, 5 * COIN, false}}, {}, std::nullopt);

    const auto recipient_output = std::find_if(
        mtx.mweb_tx.outputs.cbegin(), mtx.mweb_tx.outputs.cend(),
        [&](const mw::MutableOutput& output) {
            return output.address.has_value() && *output.address == recipient_addr;
        }
    );
    BOOST_REQUIRE(recipient_output != mtx.mweb_tx.outputs.cend());

    const std::optional<mw::Hash> output_id = recipient_output->CalcOutputID();
    BOOST_REQUIRE(output_id.has_value());

    const mw::WalletCoin coin = GetMWEBWalletCoin(*output_id);
    BOOST_REQUIRE(coin.address.has_value());
    BOOST_CHECK(*coin.address == recipient_addr);

    const CTxDestination extracted_dest = ExtractDestinationForOutput(*wtx, *output_id);
    BOOST_CHECK(extracted_dest == CTxDestination{recipient_addr});
}

BOOST_AUTO_TEST_CASE(WalletSignTransactionFinalizesPureMWEBSpend)
{
    const CTxDestination existing_mweb_addr = NewDestination(OutputType::MWEB);
    AddTx({{existing_mweb_addr, 5 * COIN, false}}, {}, std::nullopt);

    const AnyWalletUTXO mweb_coin = SmallestCoin(AvailableCoinsByType(OutputType::MWEB));
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);
    auto tx_result = BuildTx({{recipient_addr, 2 * COIN, false}}, {mweb_coin}, std::nullopt, false);
    BOOST_REQUIRE(tx_result);

    CMutableTransaction tx = tx_result->tx;
    BOOST_REQUIRE(tx.vin.empty());
    BOOST_REQUIRE(tx.vout.empty());
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE(!tx.mweb_tx.IsFinal());
    BOOST_CHECK(!tx.mweb_tx.inputs.front().signature.has_value());

    BOOST_CHECK(SignWithWallet(tx));
    BOOST_CHECK(tx.mweb_tx.IsFinal());
    BOOST_CHECK(tx.mweb_tx.inputs.front().signature.has_value());
    BOOST_CHECK(tx.mweb_tx.inputs.front().input_pubkey.has_value());

    const CTransaction signed_tx(tx);
    BOOST_CHECK(signed_tx.IsMWEBOnly());
    BOOST_CHECK(!signed_tx.mweb_tx.IsNull());
}

BOOST_AUTO_TEST_CASE(MixedPeginSubtractFeeRefreshesPegInAmount)
{
    const CTxDestination existing_mweb_addr = NewDestination(OutputType::MWEB);
    AddTx({{existing_mweb_addr, 5 * COIN, false}}, {}, std::nullopt);

    const AnyWalletUTXO ltc_coin = SmallestCoin(AvailableLTCCoins());
    const AnyWalletUTXO mweb_coin = SmallestCoin(AvailableCoinsByType(OutputType::MWEB));
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);

    const CAmount selected_value = ltc_coin.GetValue() + mweb_coin.GetValue();
    auto tx_result = BuildTx({{recipient_addr, selected_value, true}}, {ltc_coin, mweb_coin}, std::nullopt, true);
    BOOST_REQUIRE(tx_result);

    const CMutableTransaction& tx = tx_result->tx;
    BOOST_REQUIRE_EQUAL(tx.vout.size(), 1U);
    BOOST_REQUIRE_EQUAL(tx.mweb_tx.outputs.size(), 1U);
    BOOST_REQUIRE(tx.mweb_tx.GetPeginAmount().has_value());
    BOOST_REQUIRE(tx.mweb_tx.outputs[0].amount.has_value());

    const CAmount pegin_amount = *tx.mweb_tx.GetPeginAmount();
    const CAmount recipient_amount = *tx.mweb_tx.outputs[0].amount;
    const CAmount mweb_fee = tx.mweb_tx.kernels.front().fee.value_or(0);
    BOOST_CHECK_EQUAL(tx.vout.back().nValue, pegin_amount);
    BOOST_CHECK(GenericAddress(*tx.mweb_tx.outputs[0].address) == recipient_addr);
    BOOST_CHECK_EQUAL(mweb_coin.GetValue() + pegin_amount, recipient_amount + mweb_fee);
}

BOOST_AUTO_TEST_CASE(MWEBSenderKeysUseScanDerivedSequence)
{
    const mw::Keychain::Ptr keychain = ActiveMWEBKeychain();
    std::vector<CRecipient> recipients{
        {NewDestination(OutputType::MWEB), 1 * COIN, false},
        {NewDestination(OutputType::MWEB), 2 * COIN, false},
    };

    auto tx_result = BuildTx(recipients, std::nullopt, true);
    BOOST_REQUIRE(tx_result);
    BOOST_REQUIRE_GE(tx_result->tx.mweb_tx.outputs.size(), recipients.size());

    std::set<PublicKey> expected_sender_pubkeys;
    for (size_t i = 0; i < tx_result->tx.mweb_tx.outputs.size(); ++i) {
        expected_sender_pubkeys.insert(PublicKey::From(keychain->GetSenderSigningKey(i)));
    }

    for (const mw::MutableOutput& output : tx_result->tx.mweb_tx.outputs) {
        BOOST_REQUIRE(output.sender_pubkey.has_value());
        BOOST_CHECK_EQUAL(expected_sender_pubkeys.erase(*output.sender_pubkey), 1U);
    }

    BOOST_CHECK(expected_sender_pubkeys.empty());
}

BOOST_AUTO_TEST_CASE(MWEBSenderKeyScanAdvancesNextIndex)
{
    LOCK(m_wallet.cs_wallet);
    const mw::Keychain::Ptr keychain = ActiveMWEBKeychain();
    static constexpr uint64_t SENDER_INDEX{5};
    static constexpr CAmount OUTPUT_AMOUNT{12345};

    mw::Output output = mw::Output::Create(
        nullptr,
        keychain->GetSenderSigningKey(SENDER_INDEX),
        keychain->GetRewindKey(),
        StealthAddress::Random(),
        OUTPUT_AMOUNT,
        std::vector<uint8_t>{}
    );

    mw::WalletCoin coin;
    BOOST_CHECK(!MWEBWallet().RewindOutput(output, coin));
    BOOST_CHECK(!coin.IsMine());
    BOOST_REQUIRE(coin.sender_key.has_value());
    BOOST_CHECK(*coin.sender_key == keychain->GetSenderSigningKey(SENDER_INDEX));
    BOOST_CHECK_EQUAL(coin.amount, OUTPUT_AMOUNT);
    BOOST_REQUIRE(coin.blind.has_value());
    BOOST_REQUIRE(coin.shared_secret.has_value());

    mw::WalletCoin stored_coin;
    BOOST_REQUIRE(MWEBWallet().GetWalletCoin(output.GetOutputID(), stored_coin));
    BOOST_CHECK(stored_coin == coin);

    util::Result<SecretKey> next_sender_key = MWEBWallet().GenerateSenderKey();
    BOOST_REQUIRE(next_sender_key);
    BOOST_CHECK(next_sender_key.value() == keychain->GetSenderSigningKey(SENDER_INDEX + 1));
}

BOOST_AUTO_TEST_CASE(MWEBSenderKeyCacheFindsOldKeysBelowLookaheadWindow)
{
    LOCK(m_wallet.cs_wallet);
    const mw::Keychain::Ptr keychain = ActiveMWEBKeychain();
    const CKeyID master_scan_keyid = PublicKey::From(keychain->GetScanSecret()).GetID();
    static constexpr uint64_t NEXT_SENDER_INDEX{5000};
    static constexpr uint64_t OLD_SENDER_INDEX{5};
    static constexpr CAmount OUTPUT_AMOUNT{23456};

    MWEBWallet().LoadNextSenderKeyIndex(master_scan_keyid, NEXT_SENDER_INDEX);

    mw::Output output = mw::Output::Create(
        nullptr,
        keychain->GetSenderSigningKey(OLD_SENDER_INDEX),
        keychain->GetRewindKey(),
        StealthAddress::Random(),
        OUTPUT_AMOUNT,
        std::vector<uint8_t>{}
    );

    mw::WalletCoin coin;
    BOOST_CHECK(!MWEBWallet().RewindOutput(output, coin));
    BOOST_REQUIRE(coin.sender_key.has_value());
    BOOST_CHECK(*coin.sender_key == keychain->GetSenderSigningKey(OLD_SENDER_INDEX));
    BOOST_CHECK_EQUAL(coin.amount, OUTPUT_AMOUNT);

    util::Result<SecretKey> next_sender_key = MWEBWallet().GenerateSenderKey();
    BOOST_REQUIRE(next_sender_key);
    BOOST_CHECK(next_sender_key.value() == keychain->GetSenderSigningKey(NEXT_SENDER_INDEX));
}

BOOST_AUTO_TEST_CASE(MWEBSenderKeyCacheFindsKeypoolBoundary)
{
    LOCK(m_wallet.cs_wallet);
    const mw::Keychain::Ptr keychain = ActiveMWEBKeychain();
    static constexpr uint64_t NEXT_SENDER_INDEX{7};
    const uint64_t sender_index = NEXT_SENDER_INDEX + DEFAULT_KEYPOOL_SIZE - 1;
    static constexpr CAmount OUTPUT_AMOUNT{34567};

    MWEBWallet().LoadNextSenderKeyIndex(PublicKey::From(keychain->GetScanSecret()).GetID(), NEXT_SENDER_INDEX);

    mw::Output output = mw::Output::Create(
        nullptr,
        keychain->GetSenderSigningKey(sender_index),
        keychain->GetRewindKey(),
        StealthAddress::Random(),
        OUTPUT_AMOUNT,
        std::vector<uint8_t>{}
    );

    mw::WalletCoin coin;
    BOOST_CHECK(!MWEBWallet().RewindOutput(output, coin));
    BOOST_REQUIRE(coin.sender_key.has_value());
    BOOST_CHECK(*coin.sender_key == keychain->GetSenderSigningKey(sender_index));
    BOOST_CHECK_EQUAL(coin.amount, OUTPUT_AMOUNT);

    util::Result<SecretKey> next_sender_key = MWEBWallet().GenerateSenderKey();
    BOOST_REQUIRE(next_sender_key);
    BOOST_CHECK(next_sender_key.value() == keychain->GetSenderSigningKey(sender_index + 1));
}

//! End-to-end PSBT flow for a peg-in and a pure MWEB spend: build unsigned via
//! TxBuilder, run the transactiondraft-style double pass (update, then sign),
//! finalize, and check the staged wallet coins are visible. This covers the
//! wallet-backed keychain paths (LookupAddressIndex) that mock-keystore unit
//! tests cannot reach.
BOOST_AUTO_TEST_CASE(PSBTPeginFillSignFinalize)
{
    LOCK(m_wallet.cs_wallet);
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);

    auto tx_result = BuildTx({{recipient_addr, 5 * COIN, false}}, std::nullopt, /*sign=*/false);
    BOOST_REQUIRE(tx_result);
    BOOST_REQUIRE(!tx_result->tx.vin.empty());
    BOOST_REQUIRE(!tx_result->tx.mweb_tx.outputs.empty());

    PartiallySignedTransaction psbt(tx_result->tx, 2);

    bool complete = false;
    BOOST_REQUIRE_EQUAL(TransactionError::OK, FillPSBTWithWallet(psbt, complete, /*sign=*/false, /*bip32derivs=*/true));
    BOOST_CHECK(!complete);
    BOOST_REQUIRE_EQUAL(TransactionError::OK, FillPSBTWithWallet(psbt, complete, /*sign=*/true, /*bip32derivs=*/false));
    BOOST_CHECK(complete);
    BOOST_REQUIRE(psbt.IsComplete());

    // FinalizePSBT internally re-verifies the MWEB transaction and all scripts.
    util::Result<CMutableTransaction> final_tx = FinalizePSBT(psbt);
    BOOST_REQUIRE(final_tx);

    // The peg-in script committed to the finalized kernel.
    BOOST_REQUIRE(!final_tx->vout.empty());
    mw::Hash pegin_kernel_id;
    BOOST_REQUIRE(final_tx->vout.back().scriptPubKey.IsMWEBPegin(&pegin_kernel_id));
    BOOST_CHECK(!pegin_kernel_id.IsZero());
    BOOST_REQUIRE(final_tx->mweb_tx.kernels[0].GetKernelID().has_value());
    BOOST_CHECK(pegin_kernel_id == *final_tx->mweb_tx.kernels[0].GetKernelID());

    // Every MWEB output belongs to this wallet (recipient + change); the
    // signing stage must have staged wallet coins for them. Staged coins only
    // become queryable once saved, which normally happens at commit time.
    std::set<mw::Hash> output_ids;
    for (const mw::MutableOutput& output : final_tx->mweb_tx.outputs) {
        const std::optional<mw::Hash> output_id = output.CalcOutputID();
        BOOST_REQUIRE(output_id.has_value());
        output_ids.insert(*output_id);
    }
    MWEBWallet().SaveStagedCoinsToWallet(output_ids);
    for (const mw::MutableOutput& output : final_tx->mweb_tx.outputs) {
        const mw::WalletCoin coin = GetMWEBWalletCoin(*output.CalcOutputID());
        BOOST_CHECK_EQUAL(coin.amount, *output.amount);
    }
}

BOOST_AUTO_TEST_CASE(PSBTPureMWEBSpendFillSignFinalize)
{
    const CTxDestination existing_mweb_addr = NewDestination(OutputType::MWEB);
    AddTx({{existing_mweb_addr, 5 * COIN, false}}, {}, std::nullopt);

    const AnyWalletUTXO mweb_coin = SmallestCoin(AvailableCoinsByType(OutputType::MWEB));
    const CTxDestination recipient_addr = NewDestination(OutputType::MWEB);
    auto tx_result = BuildTx({{recipient_addr, 2 * COIN, false}}, {mweb_coin}, std::nullopt, /*sign=*/false);
    BOOST_REQUIRE(tx_result);
    BOOST_REQUIRE_EQUAL(tx_result->tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE(!tx_result->tx.mweb_tx.IsFinal());

    PartiallySignedTransaction psbt(tx_result->tx, 2);

    bool complete = false;
    BOOST_REQUIRE_EQUAL(TransactionError::OK, FillPSBTWithWallet(psbt, complete, /*sign=*/true, /*bip32derivs=*/false));
    BOOST_CHECK(complete);
    BOOST_REQUIRE(psbt.inputs[0].mweb_sig.has_value());
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));

    util::Result<CMutableTransaction> final_tx = FinalizePSBT(psbt);
    BOOST_REQUIRE(final_tx);
    BOOST_CHECK(final_tx->mweb_tx.IsFinal());
    BOOST_CHECK(CTransaction(*final_tx).IsMWEBOnly());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
