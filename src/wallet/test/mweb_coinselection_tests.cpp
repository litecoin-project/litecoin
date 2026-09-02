// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <key.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/wallet/WalletCoin.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/txbuilder.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <set>
#include <vector>

namespace wallet {
namespace {

class MWEBCoinSelectionTestingSetup : public TestChain100Setup
{
public:
    CWallet m_wallet;

    MWEBCoinSelectionTestingSetup()
        : m_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase())
    {
        m_wallet.LoadWallet();
        m_wallet.SetupLegacyScriptPubKeyMan();
        WITH_LOCK(m_wallet.cs_wallet, m_wallet.LoadMinVersion(FEATURE_MWEB));

        LegacyScriptPubKeyMan* spk_man = m_wallet.GetLegacyScriptPubKeyMan();
        BOOST_REQUIRE(spk_man);
        {
            LOCK(spk_man->cs_KeyStore);
            spk_man->SetHDSeed(spk_man->GenerateNewSeed());
        }

        LOCK(Assert(m_node.chainman)->GetMutex());
        const CChain& chain = m_node.chainman->ActiveChain();
        m_tip_height = chain.Height();
        m_tip_hash = chain.Tip()->GetBlockHash();
        WITH_LOCK(m_wallet.cs_wallet, m_wallet.SetLastBlockProcessed(m_tip_height, m_tip_hash));
    }

    TxState Confirmed(int depth) const
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CChain& chain = m_node.chainman->ActiveChain();
        const int height = chain.Height() - depth + 1;
        return TxStateConfirmed{chain[height]->GetBlockHash(), height, /*index=*/0};
    }

    TxState Conflicted() const
    {
        return TxStateConflicted{m_tip_hash, m_tip_height};
    }

    StealthAddress NewMWEBAddress()
    {
        const auto destination = m_wallet.GetNewDestination(OutputType::MWEB, "");
        BOOST_REQUIRE(destination);
        BOOST_REQUIRE(std::holds_alternative<StealthAddress>(*destination));
        return std::get<StealthAddress>(*destination);
    }

    CTxDestination NewLTCAddress()
    {
        const auto destination = m_wallet.GetNewDestination(OutputType::BECH32, "");
        BOOST_REQUIRE(destination);
        return *destination;
    }

    static CTxDestination NewExternalLTCAddress()
    {
        CKey key;
        key.MakeNewKey(true);
        return WitnessV0KeyHash(key.GetPubKey());
    }

    mw::Hash AddMWEBReceive(CAmount amount, const TxState& state)
    {
        return AddMWEBReceive(amount, NewMWEBAddress(), state);
    }

    mw::Hash AddMWEBReceive(CAmount amount, const StealthAddress& address, const TxState& state)
    {
        const mw::Hash output_id = mw::Hash::ValueOf(++m_next_mweb_id);
        SaveMWEBWalletCoin(output_id, amount, address);

        const std::optional<MWEB::WalletTxInfo> info{MWEB::WalletTxInfo::Received(output_id)};
        BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(), info, state));
        m_wallet.MarkDirty();
        return output_id;
    }

    void AddFrozenMWEBReceive(CAmount amount, const TxState& state)
    {
        const mw::Hash output_id = FrozenOutputID();
        SaveMWEBWalletCoin(output_id, amount, NewMWEBAddress());

        const std::optional<MWEB::WalletTxInfo> info{MWEB::WalletTxInfo::Received(output_id)};
        BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(), info, state));
        m_wallet.MarkDirty();
    }

    COutPoint AddLTCReceive(CAmount amount, const TxState& state)
    {
        CMutableTransaction tx;
        tx.nLockTime = ++m_next_lock_time;
        tx.vout.emplace_back(amount, GetScriptForDestination(NewLTCAddress()));
        const CTransactionRef tx_ref = MakeTransactionRef(std::move(tx));
        BOOST_REQUIRE(m_wallet.AddToWallet(tx_ref, std::nullopt, state));
        m_wallet.MarkDirty();
        return COutPoint{tx_ref->GetHash(), 0};
    }

    void AddMWEBSpend(const mw::Hash& output_id, const TxState& state)
    {
        const std::optional<MWEB::WalletTxInfo> info{MWEB::WalletTxInfo::Spent(output_id)};
        BOOST_REQUIRE(m_wallet.AddToWallet(MakeTransactionRef(), info, state));
        m_wallet.MarkDirty();
    }

    CoinsResult Available(const CCoinControl* coin_control = nullptr)
    {
        LOCK(m_wallet.cs_wallet);
        return AvailableCoins(m_wallet, coin_control, CFeeRate{0});
    }

    std::optional<SelectionResult> Select(CAmount target, TxType tx_type, const CCoinControl& coin_control = {})
    {
        LOCK(m_wallet.cs_wallet);
        CoinsResult available = AvailableCoins(m_wallet, &coin_control, CFeeRate{0});
        CoinSelectionParams params{m_rng};
        params.m_tx_type = tx_type;
        params.m_effective_feerate = CFeeRate{0};
        params.m_long_term_feerate = CFeeRate{0};
        params.m_discard_feerate = CFeeRate{0};
        params.m_avoid_partial_spends = coin_control.m_avoid_partial_spends;
        return SelectCoins(m_wallet, available, target, coin_control, params);
    }

    std::optional<SelectionResult> Attempt(CAmount target, TxType tx_type, bool allow_mixed)
    {
        LOCK(m_wallet.cs_wallet);
        const CoinsResult available = AvailableCoins(m_wallet, nullptr, CFeeRate{0});
        CoinSelectionParams params{m_rng};
        params.m_tx_type = tx_type;
        return AttemptSelection(
            m_wallet,
            target,
            CoinEligibilityFilter{/*conf_mine=*/1, /*conf_theirs=*/1, /*max_ancestors=*/0},
            available,
            params,
            allow_mixed);
    }

    util::Result<CreatedTransactionResult> BuildTo(const CTxDestination& recipient, CAmount amount)
    {
        CCoinControl coin_control;
        coin_control.m_feerate = CFeeRate{1'000};
        coin_control.fOverrideFeeRate = true;
        const std::vector<CRecipient> recipients{{recipient, amount, /*subtract_fee=*/false}};

        LOCK(m_wallet.cs_wallet);
        return TxBuilder::New(m_wallet, coin_control, recipients, std::nullopt)
            ->Build(std::nullopt, std::nullopt, /*sign=*/false);
    }

    std::vector<OutputGroup> Groups(bool avoid_partial_spends)
    {
        LOCK(m_wallet.cs_wallet);
        const CoinsResult available = AvailableCoins(m_wallet, nullptr, CFeeRate{0});
        CoinSelectionParams params{m_rng};
        params.m_tx_type = TxType::MWEB_TO_MWEB;
        params.m_avoid_partial_spends = avoid_partial_spends;
        return GroupOutputs(
            m_wallet,
            available.coins.at(OutputType::MWEB),
            params,
            CoinEligibilityFilter{/*conf_mine=*/1, /*conf_theirs=*/1, /*max_ancestors=*/0},
            /*positive_only=*/true);
    }

    static std::set<AnyOutputID> InputIDs(const SelectionResult& result)
    {
        std::set<AnyOutputID> ids;
        for (const AnyWalletUTXO& input : result.GetInputSet()) {
            ids.insert(input.GetID());
        }
        return ids;
    }

    static std::set<AnyOutputID> CoinIDs(const CoinsResult& coins)
    {
        std::set<AnyOutputID> ids;
        for (const AnyWalletUTXO& coin : coins.All()) {
            ids.insert(coin.GetID());
        }
        return ids;
    }

    static mw::Hash FrozenOutputID()
    {
        return mw::Hash::FromHex("2f3a08d9f5ef5f388386c11efe935394b14b524220cff4ec5c81942b82e694f7");
    }

private:
    void SaveMWEBWalletCoin(const mw::Hash& output_id, CAmount amount, const StealthAddress& address)
    {
        const std::optional<uint32_t> address_index = Keychain()->LookupAddressIndex(address);
        BOOST_REQUIRE(address_index);

        mw::WalletCoin coin;
        coin.amount = amount;
        coin.output_id = output_id;
        coin.address = address;
        coin.address_index = *address_index;

        LOCK(m_wallet.cs_wallet);
        BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveToWallet({coin}));
    }

    mw::Keychain::Ptr Keychain() const
    {
        ScriptPubKeyMan* spk_man = m_wallet.GetScriptPubKeyMan(OutputType::MWEB, false);
        BOOST_REQUIRE(spk_man);
        const mw::Keychain::Ptr keychain = spk_man->GetMWEBKeychain();
        BOOST_REQUIRE(keychain);
        return keychain;
    }

    FastRandomContext m_rng{/*fDeterministic=*/true};
    uint256 m_tip_hash;
    int m_tip_height{0};
    uint64_t m_next_mweb_id{1000};
    uint32_t m_next_lock_time{0};
};

BOOST_FIXTURE_TEST_SUITE(mweb_coinselection_tests, MWEBCoinSelectionTestingSetup)

// Only safe, unspent, unlocked, non-frozen MWEB outputs are available by default.
BOOST_AUTO_TEST_CASE(AvailableCoinsTracksMWEBWalletState)
{
    static constexpr CAmount AVAILABLE_AMOUNT{11'000};
    static constexpr CAmount UNSAFE_AMOUNT{12'000};
    const mw::Hash available = AddMWEBReceive(AVAILABLE_AMOUNT, Confirmed(6));
    const mw::Hash unsafe = AddMWEBReceive(UNSAFE_AMOUNT, TxStateInMempool{});
    AddMWEBReceive(13'000, Conflicted());
    AddMWEBReceive(14'000, TxStateInactive{/*abandoned=*/true});
    AddFrozenMWEBReceive(15'000, Confirmed(6));

    const mw::Hash spent = AddMWEBReceive(16'000, Confirmed(6));
    AddMWEBSpend(spent, TxStateInMempool{});

    const mw::Hash locked = AddMWEBReceive(17'000, Confirmed(6));
    WITH_LOCK(m_wallet.cs_wallet, BOOST_REQUIRE(m_wallet.LockCoin(locked)));

    const CoinsResult default_coins = Available();
    BOOST_CHECK(CoinIDs(default_coins) == std::set<AnyOutputID>{available});
    BOOST_CHECK_EQUAL(default_coins.total_amount, AVAILABLE_AMOUNT);
    BOOST_CHECK_EQUAL(GetAvailableBalance(m_wallet), AVAILABLE_AMOUNT);

    CCoinControl include_unsafe;
    include_unsafe.m_include_unsafe_inputs = true;
    const CoinsResult unsafe_coins = Available(&include_unsafe);
    BOOST_CHECK(CoinIDs(unsafe_coins) == std::set<AnyOutputID>({available, unsafe}));
    BOOST_CHECK_EQUAL(unsafe_coins.total_amount, AVAILABLE_AMOUNT + UNSAFE_AMOUNT);
}

// Coin control applies depth, transfer direction, and explicit-selection filters equally to MWEB coins.
BOOST_AUTO_TEST_CASE(CoinControlFiltersMWEBAvailability)
{
    const mw::Hash shallow = AddMWEBReceive(20'000, Confirmed(1));
    const mw::Hash deep = AddMWEBReceive(30'000, Confirmed(6));
    const COutPoint ltc = AddLTCReceive(40'000, Confirmed(6));

    CCoinControl minimum_depth;
    minimum_depth.m_min_depth = 2;
    BOOST_CHECK(CoinIDs(Available(&minimum_depth)) == std::set<AnyOutputID>({deep, ltc}));

    CCoinControl selected_only;
    selected_only.Select(shallow);
    BOOST_CHECK(CoinIDs(Available(&selected_only)) == std::set<AnyOutputID>{shallow});

    selected_only.m_allow_other_inputs = true;
    BOOST_CHECK(CoinIDs(Available(&selected_only)) == std::set<AnyOutputID>({shallow, deep, ltc}));

    CCoinControl pegin;
    pegin.fPegIn = true;
    BOOST_CHECK(CoinIDs(Available(&pegin)) == std::set<AnyOutputID>{ltc});

    CCoinControl pegout;
    pegout.fPegOut = true;
    BOOST_CHECK(CoinIDs(Available(&pegout)) == std::set<AnyOutputID>({shallow, deep}));
}

// Locked MWEB coins are unavailable for spending but remain visible in address-grouped coin listings.
BOOST_AUTO_TEST_CASE(ListCoinsRetainsLockedMWEBOutputs)
{
    const StealthAddress address = NewMWEBAddress();
    const mw::Hash unlocked = AddMWEBReceive(20'000, address, Confirmed(6));
    const mw::Hash locked = AddMWEBReceive(30'000, address, Confirmed(6));
    WITH_LOCK(m_wallet.cs_wallet, BOOST_REQUIRE(m_wallet.LockCoin(locked)));

    BOOST_CHECK(CoinIDs(Available()) == std::set<AnyOutputID>{unlocked});

    std::map<CTxDestination, std::vector<AnyWalletUTXO>> listed;
    WITH_LOCK(m_wallet.cs_wallet, listed = ListCoins(m_wallet));
    BOOST_REQUIRE_EQUAL(listed.size(), 1U);
    BOOST_REQUIRE(listed.count(CTxDestination{address}));

    std::set<AnyOutputID> listed_ids;
    for (const AnyWalletUTXO& coin : listed.at(CTxDestination{address})) {
        listed_ids.insert(coin.GetID());
    }
    BOOST_CHECK(listed_ids == std::set<AnyOutputID>({unlocked, locked}));
}

// Pure base-layer transactions cannot select MWEB, while pure MWEB and pegout transactions cannot select LTC.
BOOST_AUTO_TEST_CASE(TransactionTypeRestrictsInputLayer)
{
    const mw::Hash mweb = AddMWEBReceive(60'000, Confirmed(6));
    const COutPoint ltc = AddLTCReceive(50'000, Confirmed(6));

    const std::optional<SelectionResult> ltc_to_ltc = Select(50'000, TxType::LTC_TO_LTC);
    BOOST_REQUIRE(ltc_to_ltc);
    BOOST_CHECK(InputIDs(*ltc_to_ltc) == std::set<AnyOutputID>{ltc});

    const std::optional<SelectionResult> mweb_to_mweb = Select(50'000, TxType::MWEB_TO_MWEB);
    BOOST_REQUIRE(mweb_to_mweb);
    BOOST_CHECK(InputIDs(*mweb_to_mweb) == std::set<AnyOutputID>{mweb});

    const std::optional<SelectionResult> pegout = Select(50'000, TxType::PEGOUT);
    BOOST_REQUIRE(pegout);
    BOOST_CHECK(InputIDs(*pegout) == std::set<AnyOutputID>{mweb});
}

// Automatic policy spends on the recipient's layer when both LTC and MWEB can fund the payment.
BOOST_AUTO_TEST_CASE(RecipientLayerDeterminesPreferredCoins)
{
    AddMWEBReceive(5 * COIN, Confirmed(6));
    AddLTCReceive(5 * COIN, Confirmed(6));

    const util::Result<CreatedTransactionResult> mweb_payment = BuildTo(StealthAddress::Random(), 1 * COIN);
    BOOST_REQUIRE(mweb_payment);
    BOOST_CHECK(mweb_payment->tx.vin.empty());
    BOOST_REQUIRE_EQUAL(mweb_payment->tx.mweb_tx.inputs.size(), 1U);

    const util::Result<CreatedTransactionResult> ltc_payment = BuildTo(NewExternalLTCAddress(), 1 * COIN);
    BOOST_REQUIRE(ltc_payment);
    BOOST_REQUIRE_EQUAL(ltc_payment->tx.vin.size(), 1U);
    BOOST_CHECK(ltc_payment->tx.mweb_tx.inputs.empty());
}

// Automatic policy combines layers only after neither LTC nor MWEB can fund a base-layer payment alone.
BOOST_AUTO_TEST_CASE(RecipientPolicyFallsBackToCombinedPeginPegout)
{
    AddMWEBReceive(3 * COIN, Confirmed(6));
    AddLTCReceive(3 * COIN, Confirmed(6));

    const util::Result<CreatedTransactionResult> payment = BuildTo(NewExternalLTCAddress(), 5 * COIN);
    BOOST_REQUIRE(payment);
    BOOST_REQUIRE_EQUAL(payment->tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(payment->tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE(payment->tx.mweb_tx.GetPeginAmount());
    BOOST_REQUIRE_EQUAL(payment->tx.mweb_tx.GetPegOutCoins().size(), 1U);
}

// Selection prefers sufficiently deep external MWEB funds, then relaxes to one confirmation only when needed.
BOOST_AUTO_TEST_CASE(SelectionRelaxesMWEBConfirmationPolicyOnlyAsNeeded)
{
    const mw::Hash deep = AddMWEBReceive(60'000, Confirmed(6));
    const mw::Hash shallow = AddMWEBReceive(100'000, Confirmed(1));

    const std::optional<SelectionResult> small_payment = Select(50'000, TxType::MWEB_TO_MWEB);
    BOOST_REQUIRE(small_payment);
    BOOST_CHECK(InputIDs(*small_payment) == std::set<AnyOutputID>{deep});

    const std::optional<SelectionResult> large_payment = Select(80'000, TxType::MWEB_TO_MWEB);
    BOOST_REQUIRE(large_payment);
    BOOST_CHECK(InputIDs(*large_payment) == std::set<AnyOutputID>{shallow});
}

// Unconfirmed incoming MWEB funds require both availability and selection policy opt-in.
BOOST_AUTO_TEST_CASE(UnsafeIncomingMWEBRequiresExplicitOptIn)
{
    const mw::Hash unsafe = AddMWEBReceive(50'000, TxStateInMempool{});

    BOOST_CHECK(!Select(40'000, TxType::MWEB_TO_MWEB));

    CCoinControl include_unsafe;
    include_unsafe.m_include_unsafe_inputs = true;
    const std::optional<SelectionResult> selected = Select(40'000, TxType::MWEB_TO_MWEB, include_unsafe);
    BOOST_REQUIRE(selected);
    BOOST_CHECK(InputIDs(*selected) == std::set<AnyOutputID>{unsafe});
}

// Selection keeps LTC and MWEB separate when one layer can fund the target, and mixes only as a fallback.
BOOST_AUTO_TEST_CASE(SelectionMixesLayersOnlyWhenNecessary)
{
    const COutPoint ltc = AddLTCReceive(60'000, Confirmed(6));
    const mw::Hash mweb = AddMWEBReceive(40'000, Confirmed(6));

    const std::optional<SelectionResult> single_layer = Attempt(50'000, TxType::PEGIN_PEGOUT, /*allow_mixed=*/true);
    BOOST_REQUIRE(single_layer);
    BOOST_CHECK(InputIDs(*single_layer) == std::set<AnyOutputID>{ltc});

    // Neither layer can fund 90,000 alone.
    BOOST_CHECK(!Attempt(90'000, TxType::PEGIN_PEGOUT, /*allow_mixed=*/false));
    const std::optional<SelectionResult> mixed = Attempt(90'000, TxType::PEGIN_PEGOUT, /*allow_mixed=*/true);
    BOOST_REQUIRE(mixed);
    BOOST_CHECK(InputIDs(*mixed) == std::set<AnyOutputID>({ltc, mweb}));
}

// The MWEB waste metric breaks equal-value ties in favor of revealing fewer inputs.
BOOST_AUTO_TEST_CASE(MWEBSelectionMinimizesInputCount)
{
    const mw::Hash single = AddMWEBReceive(60'000, Confirmed(6));
    AddMWEBReceive(30'000, Confirmed(6));
    AddMWEBReceive(30'000, Confirmed(6));

    const std::optional<SelectionResult> selected = Select(60'000, TxType::MWEB_TO_MWEB);
    BOOST_REQUIRE(selected);
    BOOST_CHECK(InputIDs(*selected) == std::set<AnyOutputID>{single});
    BOOST_CHECK_EQUAL(selected->GetSelectedValue(), 60'000);
}

// Avoid-partial-spends must not link independent MWEB outputs, even when their destination matches.
BOOST_AUTO_TEST_CASE(AvoidPartialSpendsLeavesMWEBOutputsIndependent)
{
    const StealthAddress shared_address = NewMWEBAddress();
    AddMWEBReceive(40'000, shared_address, Confirmed(6));
    AddMWEBReceive(50'000, shared_address, Confirmed(6));

    const std::vector<OutputGroup> ordinary_groups = Groups(/*avoid_partial_spends=*/false);
    const std::vector<OutputGroup> privacy_groups = Groups(/*avoid_partial_spends=*/true);
    BOOST_REQUIRE_EQUAL(ordinary_groups.size(), 2U);
    BOOST_REQUIRE_EQUAL(privacy_groups.size(), 2U);
    BOOST_CHECK_EQUAL(privacy_groups[0].m_outputs.size(), 1U);
    BOOST_CHECK_EQUAL(privacy_groups[1].m_outputs.size(), 1U);
}

// Manual MWEB inputs are mandatory, may be supplemented on request, and remain subject to layer and lock rules.
BOOST_AUTO_TEST_CASE(ManualMWEBSelectionHonorsCoinControlPolicy)
{
    const mw::Hash selected_id = AddMWEBReceive(30'000, Confirmed(6));
    const mw::Hash supplemental_id = AddMWEBReceive(40'000, Confirmed(6));

    CCoinControl selected_only;
    selected_only.Select(selected_id);
    const std::optional<SelectionResult> exact = Select(30'000, TxType::MWEB_TO_MWEB, selected_only);
    BOOST_REQUIRE(exact);
    BOOST_CHECK(exact->GetAlgo() == SelectionAlgorithm::MANUAL);
    BOOST_CHECK(InputIDs(*exact) == std::set<AnyOutputID>{selected_id});
    BOOST_CHECK(!Select(50'000, TxType::MWEB_TO_MWEB, selected_only));
    BOOST_CHECK(!Select(30'000, TxType::LTC_TO_LTC, selected_only));

    CCoinControl supplemented = selected_only;
    supplemented.m_allow_other_inputs = true;
    const std::optional<SelectionResult> combined = Select(50'000, TxType::MWEB_TO_MWEB, supplemented);
    BOOST_REQUIRE(combined);
    BOOST_CHECK(InputIDs(*combined) == std::set<AnyOutputID>({selected_id, supplemental_id}));

    WITH_LOCK(m_wallet.cs_wallet, BOOST_REQUIRE(m_wallet.LockCoin(supplemental_id)));
    CCoinControl locked;
    locked.Select(supplemental_id);
    BOOST_CHECK(!Select(40'000, TxType::MWEB_TO_MWEB, locked));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
