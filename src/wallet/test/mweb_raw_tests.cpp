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

// Recipient indexes are flattened as canonical outputs followed by MWEB
// outputs before funding. This is the indexing contract used by the RPC's
// subtract_fee_from_outputs option even though the current transaction builder
// rejects a mixed list containing an MWEB recipient.
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
