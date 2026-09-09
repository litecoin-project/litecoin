// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/tx/Input.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/models/wallet/WalletCoin.h>
#include <policy/policy.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/transactiondraft.h>
#include <wallet/txbuilder.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace wallet {
namespace {

template <typename Callable>
void ExpectRPCError(Callable&& callable, int code, const std::string& message)
{
    try {
        callable();
        BOOST_FAIL("Expected JSON-RPC error");
    } catch (const UniValue& error) {
        BOOST_CHECK_EQUAL(find_value(error, "code").getInt<int>(), code);
        BOOST_CHECK_EQUAL(find_value(error, "message").get_str(), message);
    }
}

mw::MutableOutput MWEBOutput(const StealthAddress& address, CAmount amount)
{
    mw::MutableOutput output;
    output.address = address;
    output.amount = amount;
    return output;
}

UniValue RPCInputs(const std::vector<AnyOutputID>& output_ids)
{
    UniValue inputs(UniValue::VARR);
    for (const AnyOutputID& id : output_ids) {
        UniValue input(UniValue::VOBJ);
        if (id.IsMWEB()) {
            input.pushKV("mweb_out", id.ToMWEB().ToHex());
        } else {
            input.pushKV("txid", id.ToOutPoint().hash.GetHex());
            input.pushKV("vout", id.ToOutPoint().n);
        }
        inputs.push_back(input);
    }
    return inputs;
}

UniValue RPCOutputs(const std::vector<CRecipient>& recipients, bool as_object = false)
{
    UniValue outputs(as_object ? UniValue::VOBJ : UniValue::VARR);
    for (const CRecipient& recipient : recipients) {
        UniValue output(UniValue::VOBJ);
        output.pushKV(recipient.receiver.Encode(), ValueFromAmount(recipient.nAmount));
        if (as_object) {
            outputs.pushKVs(output);
        } else {
            outputs.push_back(output);
        }
    }
    return outputs;
}

CAmount RecipientAmount(const CMutableTransaction& tx, const GenericAddress& address)
{
    std::vector<CAmount> amounts;
    for (const CTxOut& output : tx.vout) {
        if (GenericAddress{output.scriptPubKey} == address) amounts.push_back(output.nValue);
    }
    for (const mw::MutableOutput& output : tx.mweb_tx.outputs) {
        if (output.address && GenericAddress{*output.address} == address) {
            BOOST_REQUIRE(output.amount);
            amounts.push_back(*output.amount);
        }
    }
    for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOutCoins()) {
        if (GenericAddress{pegout.GetScriptPubKey()} == address) amounts.push_back(pegout.GetAmount());
    }
    BOOST_REQUIRE_EQUAL(amounts.size(), 1U);
    return amounts.front();
}

CAmount PaymentTotal(const CMutableTransaction& tx)
{
    CAmount total = tx.mweb_tx.GetTotalPegoutAmount();
    for (const CTxOut& output : tx.vout) {
        if (!output.scriptPubKey.IsMWEBPegin()) total += output.nValue;
    }
    for (const mw::MutableOutput& output : tx.mweb_tx.outputs) {
        BOOST_REQUIRE(output.amount);
        total += *output.amount;
    }
    return total;
}

class MWEBRawTestingSetup : public TestChain100Setup
{
public:
    CWallet m_wallet;

    MWEBRawTestingSetup()
        : m_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase())
    {
        m_wallet.LoadWallet();
        m_wallet.LoadMinVersion(FEATURE_MWEB);
        m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_wallet.SetupDescriptorScriptPubKeyMans();

        FlatSigningProvider provider;
        std::string error;
        WalletDescriptor descriptor(
            Parse("combo(" + EncodeSecret(coinbaseKey) + ")", provider, error, /*require_checksum=*/false),
            /*creation_time=*/0,
            /*range_start=*/0,
            /*range_end=*/1,
            /*next_index=*/1);
        BOOST_REQUIRE(m_wallet.AddWalletDescriptor(descriptor, provider, "", /*internal=*/false));

        m_wallet.SetBroadcastTransactions(true);
        SetMockTime(1601450001);
        MineBlocks(331); // Reach MWEB activation with mature transparent funds.
        m_build_block_with_mempool = true;
    }

    void MineBlocks(int count)
    {
        LOCK2(m_node.chainman->GetMutex(), m_wallet.cs_wallet);
        const CChain& chain = m_node.chainman->ActiveChain();
        const uint256 previous_tip = chain.Tip()->GetBlockHash();
        const int previous_height = chain.Height();

        TestChain100Setup::mineBlocks(count);
        m_wallet.SetLastBlockProcessed(chain.Height(), chain.Tip()->GetBlockHash());

        WalletRescanReserver reserver(m_wallet);
        BOOST_REQUIRE(reserver.reserve());
        const CWallet::ScanResult scan = m_wallet.ScanForWalletTransactions(
            previous_tip,
            previous_height,
            /*max_height=*/{},
            reserver,
            /*fUpdate=*/false,
            /*save_progress=*/false);
        BOOST_REQUIRE(scan.status == CWallet::ScanResult::SUCCESS);
    }

    CTxDestination NewWalletDestination(OutputType type)
    {
        const util::Result<CTxDestination> destination = m_wallet.GetNewDestination(type, "");
        BOOST_REQUIRE(destination);
        return *destination;
    }

    static StealthAddress NewExternalMWEBAddress()
    {
        return StealthAddress::Random();
    }

    static CTxDestination NewExternalLTCAddress()
    {
        CKey key;
        key.MakeNewKey(/*fCompressed=*/true);
        return WitnessV0KeyHash(key.GetPubKey());
    }

    CCoinControl CoinControl(bool allow_other_inputs = true) const
    {
        CCoinControl coin_control;
        coin_control.m_allow_other_inputs = allow_other_inputs;
        coin_control.m_feerate = CFeeRate{1'000};
        coin_control.fOverrideFeeRate = true;
        return coin_control;
    }

    FundTransactionResult Fund(
        TransactionDraft& draft,
        const CCoinControl& coin_control,
        const std::set<int>& subtract_fee_from_outputs = {},
        bool lock_unspents = false,
        bool allow_mweb_result = true)
    {
        return draft.FundTransaction(
            m_wallet,
            /*change_position=*/-1,
            lock_unspents,
            subtract_fee_from_outputs,
            coin_control,
            allow_mweb_result);
    }

    FundTransactionResult FundSuccessfully(
        TransactionDraft& draft,
        const CCoinControl& coin_control,
        const std::set<int>& subtract_fee_from_outputs = {},
        bool lock_unspents = false)
    {
        try {
            return Fund(draft, coin_control, subtract_fee_from_outputs, lock_unspents);
        } catch (const UniValue& error) {
            throw std::runtime_error(find_value(error, "message").get_str());
        }
    }

    AnyWalletUTXO SmallestLTCCoin()
    {
        LOCK(m_wallet.cs_wallet);
        std::vector<AnyWalletUTXO> coins;
        for (const AnyWalletUTXO& coin : AvailableCoins(m_wallet).All()) {
            if (!coin.IsMWEB()) {
                coins.push_back(coin);
            }
        }
        BOOST_REQUIRE(!coins.empty());
        return *std::min_element(coins.begin(), coins.end(), [](const AnyWalletUTXO& lhs, const AnyWalletUTXO& rhs) {
            return lhs.GetValue() < rhs.GetValue();
        });
    }

    AnyWalletUTXO AddMWEBFunds(CAmount amount)
    {
        const CTxDestination destination = NewWalletDestination(OutputType::MWEB);
        const std::vector<CRecipient> recipients{{destination, amount, /*subtract_fee=*/false}};

        auto result = WITH_LOCK(
            m_wallet.cs_wallet,
            return TxBuilder::New(m_wallet, CoinControl(), recipients, std::nullopt)
                ->Build(std::nullopt, std::nullopt, /*sign=*/true));
        BOOST_REQUIRE(result);

        std::optional<mw::Hash> received_output_id;
        for (const mw::MutableOutput& output : result->tx.mweb_tx.outputs) {
            if (output.address.has_value() && GenericAddress(*output.address) == destination &&
                output.amount == amount) {
                received_output_id = output.CalcOutputID();
                break;
            }
        }
        BOOST_REQUIRE(received_output_id);

        const CTransactionRef tx = MakeTransactionRef(result->tx);
        m_wallet.CommitTransaction(tx, {}, {});
        MineBlocks(1);

        {
            LOCK2(m_node.chainman->GetMutex(), m_wallet.cs_wallet);
            const CChain& chain = m_node.chainman->ActiveChain();
            auto wallet_tx = m_wallet.mapWallet.find(tx->GetHash());
            BOOST_REQUIRE(wallet_tx != m_wallet.mapWallet.end());
            wallet_tx->second.m_state = TxStateConfirmed{
                chain.Tip()->GetBlockHash(), chain.Height(), /*index=*/1};
            wallet_tx->second.MarkDirty();
        }

        LOCK(m_wallet.cs_wallet);
        const CoinsResult available = AvailableCoins(m_wallet);
        for (const AnyWalletUTXO& coin : available.coins.at(OutputType::MWEB)) {
            if (coin.GetID() == AnyOutputID{*received_output_id}) {
                return coin;
            }
        }

        throw std::runtime_error("Funded MWEB output was not available");
    }

    CTxOut PreviousOutput(const CTxIn& input)
    {
        LOCK(m_wallet.cs_wallet);
        const CWalletTx* previous = m_wallet.GetWalletTx(input.prevout.hash);
        BOOST_REQUIRE(previous);
        BOOST_REQUIRE_LT(input.prevout.n, previous->tx->vout.size());
        return previous->tx->vout[input.prevout.n];
    }

    bool Sign(CMutableTransaction& tx)
    {
        LOCK(m_wallet.cs_wallet);
        return m_wallet.SignTransaction(tx);
    }

    bool VerifyInput(const CMutableTransaction& tx, size_t input_index, const CTxOut& previous_output)
    {
        ScriptError error;
        return VerifyScript(
            tx.vin.at(input_index).scriptSig,
            previous_output.scriptPubKey,
            &tx.vin.at(input_index).scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            MutableTransactionSignatureChecker(
                &tx,
                input_index,
                previous_output.nValue,
                MissingDataBehavior::ASSERT_FAIL),
            &error);
    }

    void CheckSignedRoundTrip(TransactionDraft& draft)
    {
        BOOST_REQUIRE(Sign(draft.tx));
        const CTransaction tx{draft.tx};
        if (tx.HasMWEBTx()) {
            BOOST_CHECK(!tx.mweb_tx.m_transaction->Validate());
        }
        CMutableTransaction decoded;
        BOOST_REQUIRE(DecodeHexTx(decoded, draft.ToHex()));
        BOOST_CHECK_EQUAL(EncodeHexTx(CTransaction{decoded}), draft.ToHex());
        for (size_t i = 0; i < decoded.vin.size(); ++i) {
            BOOST_CHECK(VerifyInput(decoded, i, PreviousOutput(decoded.vin[i])));
        }
    }
};

BOOST_FIXTURE_TEST_SUITE(mweb_raw_tests, MWEBRawTestingSetup)

// A raw MWEB recipient draft is funded from LTC, then both transaction layers
// are finalized by CWallet::SignTransaction. The canonical signature must
// commit to the peg-in script after its placeholder kernel ID is rewritten.
BOOST_AUTO_TEST_CASE(PeginDraftFundingAndRawSigningAreEndToEnd)
{
    static constexpr CAmount RECIPIENT_AMOUNT{5 * COIN};
    const StealthAddress recipient = NewExternalMWEBAddress();

    TransactionDraft draft;
    draft.tx.nVersion = 2;
    draft.tx.nLockTime = 123;
    draft.tx.mweb_tx.outputs.push_back(MWEBOutput(recipient, RECIPIENT_AMOUNT));

    const FundTransactionResult funding = FundSuccessfully(draft, CoinControl());

    BOOST_CHECK_EQUAL(draft.tx.nVersion, 2);
    BOOST_CHECK_EQUAL(draft.tx.nLockTime, 123U);
    BOOST_REQUIRE_EQUAL(draft.tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(draft.tx.vout.size(), 1U);
    BOOST_CHECK(draft.tx.mweb_tx.inputs.empty());
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.GetPegIns().size(), 1U);
    BOOST_REQUIRE(funding.change_pos.IsMWEB());
    BOOST_CHECK_GT(funding.fee, 0);

    mw::Hash placeholder_kernel_id;
    BOOST_REQUIRE(draft.tx.vout[0].scriptPubKey.IsMWEBPegin(&placeholder_kernel_id));
    BOOST_CHECK(placeholder_kernel_id.IsZero());
    BOOST_CHECK(!draft.tx.mweb_tx.IsFinal());

    CAmount mweb_output_total{0};
    bool found_recipient{false};
    for (const mw::MutableOutput& output : draft.tx.mweb_tx.outputs) {
        BOOST_REQUIRE(output.amount);
        mweb_output_total += *output.amount;
        if (output.address == recipient) {
            found_recipient = true;
            BOOST_CHECK_EQUAL(*output.amount, RECIPIENT_AMOUNT);
        }
    }
    BOOST_CHECK(found_recipient);

    const CTxOut previous_output = PreviousOutput(draft.tx.vin[0]);
    BOOST_CHECK_EQUAL(previous_output.nValue, mweb_output_total + funding.fee);

    BOOST_REQUIRE(Sign(draft.tx));
    BOOST_CHECK(draft.tx.mweb_tx.IsFinal());
    BOOST_CHECK(!draft.tx.vin[0].scriptSig.empty() || !draft.tx.vin[0].scriptWitness.IsNull());

    mw::Hash final_kernel_id;
    BOOST_REQUIRE(draft.tx.vout[0].scriptPubKey.IsMWEBPegin(&final_kernel_id));
    BOOST_CHECK(!final_kernel_id.IsZero());
    BOOST_REQUIRE(draft.tx.mweb_tx.kernels[0].GetKernelID());
    BOOST_CHECK(final_kernel_id == *draft.tx.mweb_tx.kernels[0].GetKernelID());
    BOOST_CHECK(VerifyInput(draft.tx, 0, previous_output));

    CMutableTransaction changed_after_signing = draft.tx;
    changed_after_signing.vout[0].scriptPubKey = GetScriptForPegin(mw::Hash{});
    BOOST_CHECK(!VerifyInput(changed_after_signing, 0, previous_output));
}

// A caller-supplied MWEB input remains an MWEB-only transaction through raw
// draft funding. Signing without the owning wallet fails cleanly; the owning
// wallet completes all MWEB signatures and produces serializable transaction
// hex, which fundrawtransaction deliberately refuses to consume again.
BOOST_AUTO_TEST_CASE(PureMWEBDraftFundingAndRawSigningAreEndToEnd)
{
    static constexpr CAmount SOURCE_AMOUNT{5 * COIN};
    static constexpr CAmount RECIPIENT_AMOUNT{2 * COIN};
    const AnyWalletUTXO source = AddMWEBFunds(SOURCE_AMOUNT);
    const StealthAddress recipient = NewExternalMWEBAddress();

    TransactionDraft draft;
    draft.tx.mweb_tx.inputs.push_back(mw::MutableInput::FromWalletCoin(source.GetMWEB().coin));
    draft.tx.mweb_tx.outputs.push_back(MWEBOutput(recipient, RECIPIENT_AMOUNT));

    const FundTransactionResult funding = FundSuccessfully(draft, CoinControl());

    BOOST_CHECK(draft.tx.vin.empty());
    BOOST_CHECK(draft.tx.vout.empty());
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.outputs.size(), 2U);
    BOOST_CHECK(draft.tx.mweb_tx.GetPegIns().empty());
    BOOST_CHECK(draft.tx.mweb_tx.GetPegOutCoins().empty());
    BOOST_REQUIRE(funding.change_pos.IsMWEB());
    BOOST_CHECK_GT(funding.fee, 0);

    CAmount output_total{0};
    bool found_recipient{false};
    for (const mw::MutableOutput& output : draft.tx.mweb_tx.outputs) {
        BOOST_REQUIRE(output.amount);
        output_total += *output.amount;
        if (output.address == recipient) {
            found_recipient = true;
            BOOST_CHECK_EQUAL(*output.amount, RECIPIENT_AMOUNT);
        }
    }
    BOOST_CHECK(found_recipient);
    BOOST_CHECK_EQUAL(SOURCE_AMOUNT, output_total + funding.fee);
    BOOST_CHECK(!draft.tx.mweb_tx.IsFinal());

    CWallet unrelated_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    unrelated_wallet.LoadWallet();
    CMutableTransaction unsigned_copy = draft.tx;
    WITH_LOCK(unrelated_wallet.cs_wallet, BOOST_CHECK(!unrelated_wallet.SignTransaction(unsigned_copy)));
    BOOST_CHECK(!unsigned_copy.mweb_tx.IsFinal());
    BOOST_CHECK(!unsigned_copy.mweb_tx.inputs[0].signature.has_value());

    BOOST_REQUIRE(Sign(draft.tx));
    BOOST_CHECK(draft.tx.mweb_tx.IsFinal());
    BOOST_CHECK(draft.tx.mweb_tx.inputs[0].signature.has_value());
    BOOST_CHECK(draft.tx.mweb_tx.inputs[0].input_pubkey.has_value());
    BOOST_CHECK(CTransaction{draft.tx}.IsMWEBOnly());

    const std::string signed_hex = EncodeHexTx(CTransaction{draft.tx});
    ExpectRPCError(
        [&] { TransactionDraft::FromHex(signed_hex, /*try_no_witness=*/true, /*try_witness=*/true); },
        RPC_INVALID_PARAMETER,
        "fundrawtransaction does not support MWEB transaction hex; use walletcreatefundedpsbt for MWEB transaction drafts");
}

// fundrawtransaction cannot return an MWEB pegout in legacy raw hex. Rejection
// leaves the caller's draft and lock state untouched, and the same draft can
// subsequently be funded through the MWEB-capable path.
BOOST_AUTO_TEST_CASE(PegoutDraftRawFundingBoundaryIsAtomic)
{
    static constexpr CAmount SOURCE_AMOUNT{5 * COIN};
    static constexpr CAmount RECIPIENT_AMOUNT{1 * COIN};
    const AnyWalletUTXO source = AddMWEBFunds(SOURCE_AMOUNT);
    const CTxDestination recipient = NewExternalLTCAddress();

    TransactionDraft draft;
    draft.tx.nLockTime = 456;
    draft.tx.mweb_tx.inputs.push_back(mw::MutableInput::FromWalletCoin(source.GetMWEB().coin));
    draft.tx.vout.emplace_back(RECIPIENT_AMOUNT, GetScriptForDestination(recipient));

    ExpectRPCError(
        [&] {
            Fund(
                draft,
                CoinControl(),
                /*subtract_fee_from_outputs=*/{},
                /*lock_unspents=*/true,
                /*allow_mweb_result=*/false);
        },
        RPC_INVALID_PARAMETER,
        "fundrawtransaction cannot return MWEB transaction hex; use walletcreatefundedpsbt for MWEB funding");

    BOOST_CHECK_EQUAL(draft.tx.nLockTime, 456U);
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.inputs.size(), 1U);
    BOOST_CHECK(draft.tx.mweb_tx.inputs[0].output_id == source.GetID().ToMWEB());
    BOOST_REQUIRE_EQUAL(draft.tx.vout.size(), 1U);
    BOOST_CHECK_EQUAL(draft.tx.vout[0].nValue, RECIPIENT_AMOUNT);
    WITH_LOCK(m_wallet.cs_wallet, BOOST_CHECK(!m_wallet.IsLockedCoin(source.GetID())));

    const FundTransactionResult funding = FundSuccessfully(draft, CoinControl());
    BOOST_CHECK(draft.tx.vin.empty());
    BOOST_CHECK(draft.tx.vout.empty());
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.GetPegOutCoins().size(), 1U);
    BOOST_CHECK_EQUAL(draft.tx.mweb_tx.GetPegOutCoins()[0].GetAmount(), RECIPIENT_AMOUNT);
    BOOST_CHECK(GenericAddress(draft.tx.mweb_tx.GetPegOutCoins()[0].GetScriptPubKey()) == recipient);
    BOOST_REQUIRE(funding.change_pos.IsMWEB());

    CAmount change_amount{0};
    for (const mw::MutableOutput& output : draft.tx.mweb_tx.outputs) {
        BOOST_REQUIRE(output.amount);
        change_amount += *output.amount;
    }
    BOOST_CHECK_EQUAL(SOURCE_AMOUNT, RECIPIENT_AMOUNT + change_amount + funding.fee);
    BOOST_REQUIRE(Sign(draft.tx));
    BOOST_CHECK(draft.tx.mweb_tx.IsFinal());
}

// Drafts constructed directly, without an RPC recipient order, use canonical
// outputs followed by MWEB outputs for fee-subtraction indexes.
BOOST_AUTO_TEST_CASE(BuildRecipientsFlattensFeeSubtractionIndexes)
{
    static constexpr CAmount LTC_RECIPIENT_AMOUNT{1 * COIN};
    static constexpr CAmount MWEB_RECIPIENT_AMOUNT{2 * COIN};
    const CTxDestination ltc_recipient = NewExternalLTCAddress();
    const StealthAddress mweb_recipient = NewExternalMWEBAddress();

    TransactionDraft draft;
    draft.tx.vout.emplace_back(LTC_RECIPIENT_AMOUNT, GetScriptForDestination(ltc_recipient));
    draft.tx.mweb_tx.outputs.push_back(MWEBOutput(mweb_recipient, MWEB_RECIPIENT_AMOUNT));

    const std::vector<CRecipient> recipients = draft.BuildRecipients(/*subtract_fee_from_outputs=*/{1});

    BOOST_REQUIRE_EQUAL(recipients.size(), 2U);
    BOOST_CHECK(!recipients[0].IsMWEB());
    BOOST_CHECK_EQUAL(recipients[0].nAmount, LTC_RECIPIENT_AMOUNT);
    BOOST_CHECK(!recipients[0].fSubtractFeeFromAmount);
    BOOST_CHECK(recipients[1].IsMWEB());
    BOOST_CHECK_EQUAL(recipients[1].nAmount, MWEB_RECIPIENT_AMOUNT);
    BOOST_CHECK(recipients[1].fSubtractFeeFromAmount);
    BOOST_REQUIRE(draft.tx.mweb_tx.outputs[0].subtract_fee_from_amount);
    BOOST_CHECK(*draft.tx.mweb_tx.outputs[0].subtract_fee_from_amount);
}

// Exercise the actual RPC boundary, including all recipient permutations,
// object/array syntax, individual fee payers, subsets, and clearing a selection.
BOOST_AUTO_TEST_CASE(RPCFeeSubtractionFollowsRecipientOrder)
{
    const std::vector<CRecipient> recipients{
        {NewExternalMWEBAddress(), COIN, false},
        {NewExternalLTCAddress(), 2 * COIN, false},
        {NewExternalMWEBAddress(), 3 * COIN, false},
        {NewExternalLTCAddress(), 4 * COIN, false},
    };
    std::array<size_t, 4> order{0, 1, 2, 3};
    do {
        std::vector<CRecipient> requested;
        for (size_t index : order) requested.push_back(recipients[index]);
        for (bool as_object : {false, true}) {
            TransactionDraft draft = TransactionDraft::FromRPC({}, RPCOutputs(requested, as_object), {}, false);
            for (const std::set<int>& selected : std::vector<std::set<int>>{{0}, {1}, {2}, {3}, {0, 2}, {1, 3}, {0, 1, 2, 3}, {}}) {
                const auto built = draft.BuildRecipients(selected);
                BOOST_REQUIRE_EQUAL(built.size(), requested.size());
                for (size_t i = 0; i < requested.size(); ++i) {
                    const auto found = std::find_if(built.begin(), built.end(), [&](const CRecipient& recipient) {
                        return recipient.receiver == requested[i].receiver;
                    });
                    BOOST_REQUIRE(found != built.end());
                    BOOST_CHECK_EQUAL(found->nAmount, requested[i].nAmount);
                    BOOST_CHECK_EQUAL(found->fSubtractFeeFromAmount, selected.count(i) != 0);
                }
            }
        }
    } while (std::next_permutation(order.begin(), order.end()));
}

// OP_RETURN occupies a caller-visible output index even when it is between
// MWEB and transparent recipients. It must not become a fee payer by accident.
BOOST_AUTO_TEST_CASE(RPCDataOutputKeepsItsRecipientIndex)
{
    const CRecipient mweb{NewExternalMWEBAddress(), COIN, false};
    const CRecipient ltc{NewExternalLTCAddress(), 2 * COIN, false};
    for (bool as_object : {false, true}) {
        UniValue data(UniValue::VOBJ);
        data.pushKV("data", "010203");
        UniValue outputs = RPCOutputs({mweb}, as_object);
        if (as_object) {
            outputs.pushKVs(data);
            outputs.pushKVs(RPCOutputs({ltc}, true));
        } else {
            outputs.push_back(data);
            outputs.push_back(RPCOutputs({ltc})[0]);
        }
        TransactionDraft draft = TransactionDraft::FromRPC({}, outputs, {}, false);
        for (int selected : {0, 1, 2}) {
            const auto built = draft.BuildRecipients({selected});
            BOOST_REQUIRE_EQUAL(built.size(), 3U);
            for (const CRecipient& recipient : built) {
                const int original_index = recipient.receiver == mweb.receiver ? 0 : recipient.receiver == ltc.receiver ? 2 : 1;
                BOOST_CHECK_EQUAL(recipient.fSubtractFeeFromAmount, selected == original_index);
                if (original_index == 1) {
                    BOOST_CHECK(recipient.GetScript() == (CScript{} << OP_RETURN << std::vector<unsigned char>{1, 2, 3}));
                    BOOST_CHECK_EQUAL(recipient.nAmount, 0);
                }
            }
        }
        const auto funding = FundSuccessfully(draft, CoinControl(), {0});
        BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, mweb.receiver), mweb.nAmount - funding.fee);
        BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, ltc.receiver), ltc.nAmount);
        CheckSignedRoundTrip(draft);
    }
}

// Follow mixed payments through peg-ins, peg-outs and combined funding, with
// and without change. Check actual amounts by recipient, then sign both layers.
BOOST_AUTO_TEST_CASE(RPCMixedFundingChargesOnlySelectedRecipients)
{
    const AnyWalletUTXO mweb_source = AddMWEBFunds(5 * COIN);
    const AnyWalletUTXO ltc_source = SmallestLTCCoin();
    const GenericAddress mweb_recipient{NewExternalMWEBAddress()};
    const GenericAddress ltc_recipient{NewExternalLTCAddress()};

    for (int input_layer : {0, 1, 2}) {
        std::vector<AnyOutputID> inputs;
        CAmount input_amount{0};
        if (input_layer != 1) {
            inputs.push_back(ltc_source.GetID());
            input_amount += ltc_source.GetValue();
        }
        if (input_layer != 0) {
            inputs.push_back(mweb_source.GetID());
            input_amount += mweb_source.GetValue();
        }
        for (bool mweb_first : {false, true}) {
            for (bool with_change : {false, true}) {
                const CAmount requested_total = with_change ? 3 * COIN : input_amount;
                std::vector<CRecipient> requested{
                    {mweb_recipient, requested_total / 2, false},
                    {ltc_recipient, requested_total - requested_total / 2, false},
                };
                if (!mweb_first) std::reverse(requested.begin(), requested.end());
                for (const std::set<int>& selected : std::vector<std::set<int>>{{0}, {1}, {0, 1}, {}}) {
                    BOOST_TEST_CONTEXT("input layer=" << input_layer << ", MWEB first=" << mweb_first << ", change=" << with_change << ", fee payers=" << selected.size()) {
                        TransactionDraft draft = TransactionDraft::FromRPC(RPCInputs(inputs), RPCOutputs(requested), 123, false);
                        draft.BuildRecipients(); // RPC option validation also calls this before funding.
                        if (!with_change && selected.empty()) {
                            // Exact-value inputs cannot pay the fee without subtraction.
                            ExpectRPCError([&] { Fund(draft, CoinControl(false), {}, true); }, RPC_WALLET_ERROR, "Insufficient funds");
                            for (const CRecipient& recipient : requested) {
                                BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, recipient.receiver), recipient.nAmount);
                            }
                            for (const AnyOutputID& input : inputs) {
                                WITH_LOCK(m_wallet.cs_wallet, BOOST_CHECK(!m_wallet.IsLockedCoin(input)));
                            }
                            continue;
                        }
                        const auto funding = FundSuccessfully(draft, CoinControl(false), selected);
                        BOOST_CHECK_EQUAL(draft.tx.nLockTime, 123U);
                        for (const CTxIn& input : draft.tx.vin) {
                            BOOST_CHECK_EQUAL(input.nSequence, uint32_t{CTxIn::MAX_SEQUENCE_NONFINAL});
                        }
                        BOOST_CHECK_EQUAL(funding.change_pos.IsNull(), !with_change);
                        BOOST_CHECK_EQUAL(PaymentTotal(draft.tx) + funding.fee, input_amount);
                        BOOST_CHECK_EQUAL(draft.tx.GetInputs().size(), inputs.size());
                        for (const AnyInput& input : draft.tx.GetInputs()) {
                            BOOST_CHECK(std::find(inputs.begin(), inputs.end(), input.GetID()) != inputs.end());
                        }
                        CAmount deducted{0};
                        std::vector<CAmount> funded_amounts;
                        for (size_t i = 0; i < requested.size(); ++i) {
                            const CAmount amount = RecipientAmount(draft.tx, requested[i].receiver);
                            const CAmount difference = requested[i].nAmount - amount;
                            funded_amounts.push_back(amount);
                            if (selected.count(i)) {
                                BOOST_CHECK_GE(difference, funding.fee / selected.size());
                                BOOST_CHECK_LE(difference, (funding.fee + selected.size() - 1) / selected.size());
                            } else {
                                BOOST_CHECK_EQUAL(difference, 0);
                            }
                            deducted += difference;
                        }
                        BOOST_CHECK_EQUAL(deducted, selected.empty() ? 0 : funding.fee);
                        CheckSignedRoundTrip(draft);
                        for (size_t i = 0; i < requested.size(); ++i) {
                            BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, requested[i].receiver), funded_amounts[i]);
                        }
                    }
                }
            }
        }
    }
}

// RPC parsing preserves both input IDs and locktime, applies RBF-dependent
// sequence defaults to transparent inputs, and honors explicit sequences.
BOOST_AUTO_TEST_CASE(RPCInputParsingPreservesMixedInputsAndSequences)
{
    const AnyOutputID ltc{COutPoint{InsecureRand256(), 2}};
    const AnyOutputID mweb{mw::Hash::FromHex(InsecureRand256().GetHex())};
    const UniValue outputs = RPCOutputs({{NewExternalMWEBAddress(), COIN, false}});
    for (const std::optional<bool> rbf : {std::optional<bool>{}, std::optional<bool>{false}, std::optional<bool>{true}}) {
        for (int locktime : {0, 123}) {
            TransactionDraft draft = TransactionDraft::FromRPC(RPCInputs({mweb, ltc}), outputs, locktime, rbf);
            BOOST_REQUIRE_EQUAL(draft.tx.vin.size(), 1U);
            BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.inputs.size(), 1U);
            BOOST_CHECK(draft.tx.vin[0].prevout == ltc.ToOutPoint());
            BOOST_CHECK(draft.tx.mweb_tx.inputs[0].output_id == mweb.ToMWEB());
            BOOST_CHECK(!draft.tx.mweb_tx.inputs[0].amount);
            BOOST_CHECK_EQUAL(draft.tx.nLockTime, locktime);
            BOOST_CHECK_EQUAL(draft.tx.vin[0].nSequence, rbf.value_or(true) ? CTxIn::SEQUENCE_FINAL - 2 : locktime ? CTxIn::MAX_SEQUENCE_NONFINAL : CTxIn::SEQUENCE_FINAL);
        }
    }
    UniValue input = RPCInputs({ltc})[0];
    input.pushKV("sequence", 12345);
    UniValue inputs = RPCInputs({mweb});
    inputs.push_back(input);
    const TransactionDraft draft = TransactionDraft::FromRPC(inputs, outputs, 123, false);
    BOOST_CHECK_EQUAL(draft.tx.vin[0].nSequence, 12345U);
}

// Reject malformed or conflicting MWEB input fields, duplicate payment/data
// outputs, and array entries that contain more than one output.
BOOST_AUTO_TEST_CASE(RPCRejectsInvalidMWEBInputsAndDuplicateOutputs)
{
    const CRecipient recipient{NewExternalMWEBAddress(), COIN, false};
    const UniValue outputs = RPCOutputs({recipient});
    auto check_input = [&](const UniValue& input, const std::string& message) {
        UniValue inputs(UniValue::VARR);
        inputs.push_back(input);
        ExpectRPCError([&] { TransactionDraft::FromRPC(inputs, outputs, {}, false); }, RPC_INVALID_PARAMETER, message);
    };
    for (const std::string& id : {std::string{}, std::string(63, '0'), std::string(65, '0'), std::string(64, 'z')}) {
        UniValue input(UniValue::VOBJ);
        input.pushKV("mweb_out", id);
        check_input(input, "Invalid parameter, mweb_out must be a 64-character hexadecimal string");
    }
    for (const std::string field : {"txid", "vout", "sequence", "weight"}) {
        UniValue input(UniValue::VOBJ);
        input.pushKV("mweb_out", InsecureRand256().GetHex());
        input.pushKV(field, 0);
        check_input(input, field == "txid" || field == "vout"
            ? "Invalid parameter, specify either mweb_out or txid and vout"
            : "Invalid parameter, sequence and weight do not apply to MWEB inputs");
    }
    for (bool as_object : {false, true}) {
        ExpectRPCError([&] { TransactionDraft::FromRPC({}, RPCOutputs({recipient, recipient}, as_object), {}, false); },
            RPC_INVALID_PARAMETER, "Invalid parameter, duplicated address: " + recipient.receiver.Encode());
    }
    UniValue data(UniValue::VOBJ);
    data.pushKV("data", "00");
    UniValue duplicate_data(UniValue::VARR);
    duplicate_data.push_back(data);
    duplicate_data.push_back(data);
    ExpectRPCError([&] { TransactionDraft::FromRPC({}, duplicate_data, {}, false); },
        RPC_INVALID_PARAMETER, "Invalid parameter, duplicate key: data");
    UniValue multiple_keys(UniValue::VARR);
    multiple_keys.push_back(RPCOutputs({recipient, {NewExternalLTCAddress(), COIN, false}}, true));
    ExpectRPCError([&] { TransactionDraft::FromRPC({}, multiple_keys, {}, false); },
        RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair must contain exactly one key");
}

// Custom change must leave the caller's fee payer unchanged, even when
// transparent recipients and change become pegouts. The returned position
// identifies change within its layer; MWEB and pegout change are appended.
BOOST_AUTO_TEST_CASE(RPCCustomChangeDoesNotShiftFeeSubtraction)
{
    const AnyWalletUTXO mweb_source = AddMWEBFunds(5 * COIN);
    const AnyWalletUTXO ltc_source = SmallestLTCCoin();
    const std::vector<CRecipient> requested{
        {NewExternalMWEBAddress(), COIN, false},
        {NewExternalLTCAddress(), COIN, false},
    };
    for (const AnyWalletUTXO& source : {ltc_source, mweb_source}) {
        for (OutputType change_type : {OutputType::BECH32, OutputType::MWEB}) {
            const CTxDestination change_address = NewWalletDestination(change_type);
            for (int position : {0, 1}) {
                BOOST_TEST_CONTEXT("MWEB input=" << source.IsMWEB() << ", MWEB change=" << (change_type == OutputType::MWEB) << ", position=" << position) {
                    TransactionDraft draft = TransactionDraft::FromRPC(RPCInputs({source.GetID()}), RPCOutputs(requested), {}, false);
                    CCoinControl control = CoinControl(false);
                    control.destChange = change_address;
                    const auto funding = draft.FundTransaction(m_wallet, position, false, {0}, control);
                    BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, requested[0].receiver), COIN - funding.fee);
                    BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, requested[1].receiver), COIN);
                    BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, GenericAddress{change_address}), source.GetValue() - 2 * COIN);
                    if (change_type == OutputType::MWEB) {
                        BOOST_REQUIRE(funding.change_pos.IsMWEB());
                        BOOST_CHECK_EQUAL(funding.change_pos.ToMWEB().idx, 1U);
                        BOOST_CHECK(GenericAddress{*draft.tx.mweb_tx.outputs.at(funding.change_pos.ToMWEB().idx).address} == change_address);
                    } else {
                        BOOST_REQUIRE(funding.change_pos.IsPegout());
                        BOOST_CHECK_EQUAL(funding.change_pos.ToPegout().idx, 1U);
                        BOOST_CHECK(GenericAddress{draft.tx.mweb_tx.GetPegOutCoins().at(funding.change_pos.ToPegout().idx).GetScriptPubKey()} == change_address);
                    }
                    BOOST_CHECK_EQUAL(PaymentTotal(draft.tx) + funding.fee, source.GetValue());
                    CheckSignedRoundTrip(draft);
                }
            }
        }
    }
}

// Funding failures preserve amounts and leave inputs unlocked; a successful
// retry keeps the original fee payer and applies the requested coin locks.
BOOST_AUTO_TEST_CASE(RPCFundingFailurePreservesRecipientsForRetry)
{
    const AnyWalletUTXO source = SmallestLTCCoin();
    const std::vector<CRecipient> requested{
        {NewExternalMWEBAddress(), COIN, false},
        {NewExternalLTCAddress(), 2 * COIN, false},
    };
    auto too_small = requested;
    too_small[0].nAmount = 1;
    TransactionDraft tiny = TransactionDraft::FromRPC(RPCInputs({source.GetID()}), RPCOutputs(too_small), {}, false);
    ExpectRPCError([&] { Fund(tiny, CoinControl(false), {0}, true); }, RPC_WALLET_ERROR,
        "The transaction amount is too small to pay the fee");
    BOOST_CHECK_EQUAL(RecipientAmount(tiny.tx, requested[0].receiver), 1);
    BOOST_CHECK_EQUAL(RecipientAmount(tiny.tx, requested[1].receiver), 2 * COIN);
    WITH_LOCK(m_wallet.cs_wallet, BOOST_CHECK(!m_wallet.IsLockedCoin(source.GetID())));

    const AnyOutputID missing{mw::Hash::FromHex(InsecureRand256().GetHex())};
    TransactionDraft missing_input = TransactionDraft::FromRPC(RPCInputs({missing}), RPCOutputs(requested), {}, false);
    ExpectRPCError([&] { Fund(missing_input, CoinControl(), {0}, true); }, RPC_WALLET_ERROR,
        "Unable to find UTXO for external input");
    BOOST_REQUIRE_EQUAL(missing_input.tx.mweb_tx.inputs.size(), 1U);
    BOOST_CHECK(missing_input.tx.mweb_tx.inputs[0].output_id == missing.ToMWEB());

    TransactionDraft draft = TransactionDraft::FromRPC(RPCInputs({source.GetID()}), RPCOutputs(requested), 123, false);
    ExpectRPCError([&] { Fund(draft, CoinControl(false), {0}, true, false); }, RPC_INVALID_PARAMETER,
        "fundrawtransaction cannot return MWEB transaction hex; use walletcreatefundedpsbt for MWEB funding");
    BOOST_REQUIRE_EQUAL(draft.tx.vin.size(), 1U);
    BOOST_CHECK(draft.tx.vin[0].prevout == source.GetID().ToOutPoint());
    BOOST_CHECK_EQUAL(draft.tx.nLockTime, 123U);
    for (const CRecipient& recipient : requested) {
        BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, recipient.receiver), recipient.nAmount);
    }
    WITH_LOCK(m_wallet.cs_wallet, BOOST_CHECK(!m_wallet.IsLockedCoin(source.GetID())));

    const auto funding = FundSuccessfully(draft, CoinControl(false), {0}, true);
    BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, requested[0].receiver), COIN - funding.fee);
    BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, requested[1].receiver), 2 * COIN);
    WITH_LOCK(m_wallet.cs_wallet, BOOST_CHECK(m_wallet.IsLockedCoin(source.GetID())));
    // The draft now contains bridge/change outputs, so original RPC indexes
    // must no longer be used for these new output positions.
    const auto funded_recipients = draft.BuildRecipients({0});
    BOOST_REQUIRE_GT(funded_recipients.size(), requested.size());
    BOOST_CHECK(funded_recipients[0].fSubtractFeeFromAmount);
    for (size_t i = 1; i < funded_recipients.size(); ++i) {
        BOOST_CHECK(!funded_recipients[i].fSubtractFeeFromAmount);
    }
    CheckSignedRoundTrip(draft);
}

// Transparent raw-hex funding retains its original output-index convention.
BOOST_AUTO_TEST_CASE(TransparentRawHexFundingKeepsRecipientIndexes)
{
    const AnyWalletUTXO source = SmallestLTCCoin();
    const std::vector<CRecipient> recipients{
        {NewExternalLTCAddress(), COIN, false},
        {NewExternalLTCAddress(), 2 * COIN, false},
    };
    const auto rpc_draft = TransactionDraft::FromRPC(RPCInputs({source.GetID()}), RPCOutputs(recipients), 123, false);
    for (int position : {0, 1, 2}) {
        TransactionDraft draft = TransactionDraft::FromHex(rpc_draft.ToHex(), true, true);
        const auto funding = draft.FundTransaction(m_wallet, position, false, {1}, CoinControl(false), false);
        BOOST_CHECK(draft.tx.mweb_tx.IsNull());
        BOOST_CHECK(funding.change_pos == size_t(position));
        BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, recipients[0].receiver), COIN);
        BOOST_CHECK_EQUAL(RecipientAmount(draft.tx, recipients[1].receiver), 2 * COIN - funding.fee);
        BOOST_CHECK_EQUAL(draft.tx.nLockTime, 123U);
        BOOST_CHECK_EQUAL(draft.tx.vin[0].nSequence, uint32_t{CTxIn::MAX_SEQUENCE_NONFINAL});
        BOOST_CHECK_EQUAL(PaymentTotal(draft.tx) + funding.fee, source.GetValue());
        CheckSignedRoundTrip(draft);
    }
}

// Funding a single MWEB recipient with an exact-value transparent input leaves
// no change and deducts the complete layered fee from that recipient.
BOOST_AUTO_TEST_CASE(MWEBRecipientPaysRawDraftFundingFee)
{
    const AnyWalletUTXO source = SmallestLTCCoin();
    const CAmount requested_amount = source.GetValue();
    const StealthAddress recipient = NewExternalMWEBAddress();

    TransactionDraft draft;
    draft.tx.vin.emplace_back(source.GetID().ToOutPoint());
    draft.tx.mweb_tx.outputs.push_back(MWEBOutput(recipient, requested_amount));

    const FundTransactionResult funding = FundSuccessfully(
        draft,
        CoinControl(/*allow_other_inputs=*/false),
        /*subtract_fee_from_outputs=*/{0});

    BOOST_REQUIRE(funding.change_pos.IsNull());
    BOOST_CHECK_GT(funding.fee, 0);
    BOOST_REQUIRE_EQUAL(draft.tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(draft.tx.vout.size(), 1U); // The peg-in bridge output.
    BOOST_CHECK(draft.tx.vout[0].scriptPubKey.IsMWEBPegin());
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.outputs.size(), 1U);
    BOOST_REQUIRE(draft.tx.mweb_tx.outputs[0].amount);
    BOOST_CHECK(draft.tx.mweb_tx.outputs[0].address == recipient);
    BOOST_CHECK_EQUAL(*draft.tx.mweb_tx.outputs[0].amount, requested_amount - funding.fee);
    BOOST_CHECK_EQUAL(source.GetValue(), *draft.tx.mweb_tx.outputs[0].amount + funding.fee);
}

// Funding keeps the caller's existing transparent inputs first and preserves
// their scriptSig and sequence while appending any newly selected inputs.
BOOST_AUTO_TEST_CASE(PresetInputMetadataAndOrderingSurviveMWEBFunding)
{
    static constexpr CAmount RECIPIENT_AMOUNT{60 * COIN};
    static constexpr uint32_t SEQUENCE{12345};
    const AnyWalletUTXO preset = SmallestLTCCoin();
    const CScript original_script_sig = CScript{} << OP_TRUE;
    const StealthAddress recipient = NewExternalMWEBAddress();

    TransactionDraft draft;
    draft.tx.nVersion = 2;
    draft.tx.nLockTime = 789;
    draft.tx.vin.emplace_back(preset.GetID().ToOutPoint(), original_script_sig, SEQUENCE);
    draft.tx.mweb_tx.outputs.push_back(MWEBOutput(recipient, RECIPIENT_AMOUNT));

    const FundTransactionResult funding = FundSuccessfully(draft, CoinControl(/*allow_other_inputs=*/true));

    BOOST_CHECK_EQUAL(draft.tx.nVersion, 2);
    BOOST_CHECK_EQUAL(draft.tx.nLockTime, 789U);
    BOOST_REQUIRE_GT(draft.tx.vin.size(), 1U);
    BOOST_CHECK(draft.tx.vin[0].prevout == preset.GetID().ToOutPoint());
    BOOST_CHECK(draft.tx.vin[0].scriptSig == original_script_sig);
    BOOST_CHECK_EQUAL(draft.tx.vin[0].nSequence, SEQUENCE);
    for (size_t i = 1; i < draft.tx.vin.size(); ++i) {
        BOOST_CHECK(draft.tx.vin[i].prevout != preset.GetID().ToOutPoint());
        BOOST_CHECK(draft.tx.vin[i].scriptSig.empty());
    }
    BOOST_REQUIRE(funding.change_pos.IsMWEB());
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.GetPegIns().size(), 1U);

    const auto recipient_output = std::find_if(
        draft.tx.mweb_tx.outputs.cbegin(),
        draft.tx.mweb_tx.outputs.cend(),
        [&](const mw::MutableOutput& output) { return output.address == recipient; });
    BOOST_REQUIRE(recipient_output != draft.tx.mweb_tx.outputs.cend());
    BOOST_REQUIRE(recipient_output->amount);
    BOOST_CHECK_EQUAL(*recipient_output->amount, RECIPIENT_AMOUNT);
}

// A combined transaction demonstrates that lock_unspents covers both input
// namespaces. Locked inputs can still be signed because they are already part
// of the caller's funded draft.
BOOST_AUTO_TEST_CASE(LockUnspentsCoversCanonicalAndMWEBInputs)
{
    static constexpr CAmount MWEB_SOURCE_AMOUNT{5 * COIN};
    static constexpr CAmount RECIPIENT_AMOUNT{10 * COIN};
    const AnyWalletUTXO mweb_source = AddMWEBFunds(MWEB_SOURCE_AMOUNT);
    const StealthAddress recipient = NewExternalMWEBAddress();

    // The peg-in which created mweb_source also created MWEB change. Keep that
    // unrelated output out of this selection so the shortfall must come from
    // the transparent layer.
    {
        LOCK(m_wallet.cs_wallet);
        const CoinsResult available = AvailableCoins(m_wallet);
        for (const AnyWalletUTXO& coin : available.coins.at(OutputType::MWEB)) {
            if (!(coin.GetID() == mweb_source.GetID())) {
                BOOST_REQUIRE(m_wallet.LockCoin(coin.GetID()));
            }
        }
    }

    TransactionDraft draft;
    draft.tx.mweb_tx.inputs.push_back(mw::MutableInput::FromWalletCoin(mweb_source.GetMWEB().coin));
    draft.tx.mweb_tx.outputs.push_back(MWEBOutput(recipient, RECIPIENT_AMOUNT));

    const FundTransactionResult funding = FundSuccessfully(
        draft,
        CoinControl(/*allow_other_inputs=*/true),
        /*subtract_fee_from_outputs=*/{},
        /*lock_unspents=*/true);

    BOOST_REQUIRE_EQUAL(draft.tx.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.inputs.size(), 1U);
    BOOST_REQUIRE_EQUAL(draft.tx.mweb_tx.GetPegIns().size(), 1U);
    BOOST_REQUIRE(funding.change_pos.IsMWEB());

    const std::vector<AnyInput> inputs = draft.tx.GetInputs();
    BOOST_REQUIRE_EQUAL(inputs.size(), 2U);
    WITH_LOCK(m_wallet.cs_wallet, {
        for (const AnyInput& input : inputs) {
            BOOST_CHECK(m_wallet.IsLockedCoin(input.GetID()));
        }
    });

    CAmount ltc_input_amount{0};
    for (const CTxIn& input : draft.tx.vin) {
        ltc_input_amount += PreviousOutput(input).nValue;
    }
    CAmount mweb_output_amount{0};
    for (const mw::MutableOutput& output : draft.tx.mweb_tx.outputs) {
        BOOST_REQUIRE(output.amount);
        mweb_output_amount += *output.amount;
    }
    BOOST_CHECK_EQUAL(
        ltc_input_amount + MWEB_SOURCE_AMOUNT,
        mweb_output_amount + draft.tx.mweb_tx.GetTotalPegoutAmount() + funding.fee);

    BOOST_REQUIRE(Sign(draft.tx));
    BOOST_CHECK(draft.tx.mweb_tx.IsFinal());
    BOOST_CHECK(!draft.tx.vin[0].scriptSig.empty() || !draft.tx.vin[0].scriptWitness.IsNull());
}

// HogEx carries the same extended-serialization marker as MWEB transaction
// data and is likewise not a valid input to fundrawtransaction.
BOOST_AUTO_TEST_CASE(RawHexFundingRejectsHogEx)
{
    CMutableTransaction hogex;
    hogex.m_hogEx = true;
    hogex.vout.emplace_back(1, CScript{} << OP_TRUE);

    ExpectRPCError(
        [&] {
            TransactionDraft::FromHex(
                EncodeHexTx(CTransaction{hogex}),
                /*try_no_witness=*/true,
                /*try_witness=*/true);
        },
        RPC_INVALID_PARAMETER,
        "fundrawtransaction does not support MWEB transaction hex; use walletcreatefundedpsbt for MWEB transaction drafts");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
