#include <wallet/transactiondraft.h>

#include <core_io.h>
#include <key_io.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/script.h>
#include <univalue.h>
#include <util/rbf.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

using namespace wallet;

TransactionDraft TransactionDraft::FromRPC(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf)
{
    if (outputs_in.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output argument must be non-null");
    }

    TransactionDraft draft;

    if (!locktime.isNull()) {
        int64_t nLockTime = locktime.getInt<int64_t>();
        if (nLockTime < 0 || nLockTime > LOCKTIME_MAX)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        draft.tx.nLockTime = nLockTime;
    }

    UniValue inputs;
    if (inputs_in.isNull()) {
        inputs = UniValue::VARR;
    } else {
        inputs = inputs_in.get_array();
    }

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.getInt<int>();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");

        uint32_t nSequence;

        if (rbf.value_or(true)) {
            nSequence = MAX_BIP125_RBF_SEQUENCE; /* CTxIn::SEQUENCE_FINAL - 2 */
        } else if (draft.tx.nLockTime) {
            nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; /* CTxIn::SEQUENCE_FINAL - 1 */
        } else {
            nSequence = CTxIn::SEQUENCE_FINAL;
        }

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.getInt<int64_t>();
            if (seqNr64 < 0 || seqNr64 > CTxIn::SEQUENCE_FINAL) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            } else {
                nSequence = (uint32_t)seqNr64;
            }
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        draft.tx.vin.push_back(in);
    }

    const bool outputs_is_obj = outputs_in.isObject();
    UniValue outputs = outputs_is_obj ? outputs_in.get_obj() : outputs_in.get_array();
    if (!outputs_is_obj) {
        // Translate array of key-value pairs into dict
        UniValue outputs_dict = UniValue(UniValue::VOBJ);
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& output = outputs[i];
            if (!output.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair not an object as expected");
            }
            if (output.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair must contain exactly one key");
            }
            outputs_dict.pushKVs(output);
        }
        outputs = std::move(outputs_dict);
    }

    // Duplicate checking
    std::set<CTxDestination> destinations;
    bool has_data{ false };

    for (const std::string& name_ : outputs.getKeys()) {
        if (name_ == "data") {
            if (has_data) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, duplicate key: data");
            }
            has_data = true;
            std::vector<unsigned char> data = ParseHexV(outputs[name_].getValStr(), "Data");
            CScript scriptPubKey = (CScript() << OP_RETURN << data);

            CTxOut out(0, scriptPubKey);
            draft.tx.vout.push_back(std::move(out));
            //draft.m_recipients.push_back(CRecipient{GenericAddress(scriptPubKey), 0, false});
        }
        else {
            CTxDestination destination = DecodeDestination(name_);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Litecoin address: ") + name_);
            }

            if (!destinations.insert(destination).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
            }

            CAmount nAmount = AmountFromValue(outputs[name_]);

            GenericAddress address{ destination };
            if (address.IsMWEB()) {
                mw::MutableOutput mweb_output;
                mweb_output.amount = nAmount;
                mweb_output.address = address.GetMWEBAddress();
                draft.tx.mweb_tx.outputs.push_back(std::move(mweb_output));
            }
            else {
                CTxOut out(nAmount, address.GetScript());
                draft.tx.vout.push_back(std::move(out));
            }
        }
    }

    if (rbf.has_value() && rbf.value() && draft.tx.vin.size() > 0 && !SignalsOptInRBF(draft.ToTransaction())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter combination: Sequence number(s) contradict replaceable option");
    }

    return draft;
}

FundTransactionResult TransactionDraft::FundTransaction(CWallet& wallet, const int nChangePosIn, const bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, const CCoinControl& coin_control_in, bool allow_mweb_result)
{
    CCoinControl coinControl = coin_control_in;

    // Acquire the locks to prevent races to the new locked unspents between the
    // CreateTransaction call and LockCoin calls (when lockUnspents is true).
    LOCK(wallet.cs_wallet);

    // Fetch specified UTXOs from the UTXO set to get the scriptPubKeys and values of the outputs being selected
    // and to match with the given solving_data. Only used for non-wallet outputs.
    std::map<AnyOutputID, AnyCoin> coins;
    for (const AnyInput& input : tx.GetInputs()) {
        coins[input.GetID()]; // Create empty map entry keyed by prevout.
    }
    wallet.chain().findCoins(coins);

    for (const AnyInput& input : tx.GetInputs()) {
        const AnyOutputID input_idx = input.GetID();
        if (wallet.IsMine(input_idx)) {
            // The input was found in the wallet, so select as internal
            coinControl.Select(input_idx);
        }
        else if (coins[input_idx].IsNull()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unable to find UTXO for external input");
        }
        else {
            // The input was not in the wallet, but is in the UTXO set, so select as external
            coinControl.SelectExternal(input_idx, coins[input_idx].ToOutput());
        }
    }

    std::vector<CRecipient> recipients = BuildRecipients(setSubtractFeeFromOutputs);
    auto res = CreateTransaction(wallet, recipients, nChangePosIn, coinControl, tx.nVersion, tx.nLockTime, false);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
    }

    if (!allow_mweb_result && (!res->tx.mweb_tx.IsNull() || res->tx.m_hogEx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "fundrawtransaction cannot return MWEB transaction hex; use walletcreatefundedpsbt for MWEB funding");
    }

    tx.mweb_tx = res->tx.mweb_tx;
    tx.vout = res->tx.vout;

    // Add new txins while keeping original txin scriptSig/order.
    for (const AnyInput& tx_input : res->tx.GetInputs()) {
        if (!coinControl.IsSelected(tx_input.GetID()) && !tx_input.IsMWEB()) {
            tx.vin.push_back(tx_input.GetTxIn());
        }

        if (lockUnspents) {
            wallet.LockCoin(tx_input.GetID());
        }
    }

    return FundTransactionResult{res->fee, res->change_pos};
}

TransactionDraft TransactionDraft::FromHex(const std::string& hex, const bool try_no_witness, const bool try_witness)
{
    TransactionDraft draft;

    if (!DecodeHexTx(draft.tx, hex, try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Raw transaction hex only carries finalized MWEB data, not the draft recipient metadata needed to fund or rewrite an MWEB transaction.
    if (!draft.tx.mweb_tx.IsNull() || draft.tx.m_hogEx) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "fundrawtransaction does not support MWEB transaction hex; use walletcreatefundedpsbt for MWEB transaction drafts");
    }

    return draft;
}

std::vector<CRecipient> TransactionDraft::BuildRecipients(const std::set<int>& setSubtractFeeFromOutputs)
{
    std::vector<CRecipient> recipients;

    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        CRecipient recipient{};
        recipient.nAmount = out.nValue;
        recipient.receiver = out.scriptPubKey;
        recipient.fSubtractFeeFromAmount = (setSubtractFeeFromOutputs.count(i) == 1);
        recipients.push_back(std::move(recipient));
    }

    for (size_t i = 0; i < tx.mweb_tx.outputs.size(); i++) {
        mw::MutableOutput& mweb_output = tx.mweb_tx.outputs[i];
        assert(mweb_output.amount.has_value() && mweb_output.address.has_value());
        mweb_output.subtract_fee_from_amount = (setSubtractFeeFromOutputs.count(tx.vout.size() + i) == 1);

        CRecipient recipient{*mweb_output.address, *mweb_output.amount, *mweb_output.subtract_fee_from_amount};
        recipients.push_back(std::move(recipient));
    }

    return recipients;
}

CMutableTransaction TransactionDraft::ToMutableTx() const
{
    return tx;
}

CTransaction TransactionDraft::ToTransaction() const
{
    return CTransaction(tx);
}

PartiallySignedTransaction TransactionDraft::ToPSBT(const CWallet& wallet) const
{
    // Make a blank psbt
    PartiallySignedTransaction psbtx(tx, 2);

    // First fill transaction with our data without signing,
    // so external signers are not asked sign more than once.
    bool complete;
    wallet.FillPSBT(psbtx, complete, SIGHASH_DEFAULT, false, true);
    const TransactionError err{wallet.FillPSBT(psbtx, complete, SIGHASH_DEFAULT, true, false)};
    if (err != TransactionError::OK) {
        throw JSONRPCTransactionError(err);
    }

    return psbtx;
}

std::string TransactionDraft::ToHex(const int serialize_flags) const
{
    return EncodeHexTx(ToTransaction(), serialize_flags);
}
