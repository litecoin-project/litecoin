#pragma once

#include <primitives/transaction.h>
#include <psbt.h>
#include <wallet/change.h>
#include <wallet/recipient.h>
#include <wallet/utxo.h>

#include <optional>
#include <string>

// Forward Declarations
class UniValue;

namespace wallet {

class CCoinControl;
class CWallet;

struct FundTransactionResult {
    CAmount fee;
    ChangePosition change_pos;
};

class TransactionDraft
{
public:
    CMutableTransaction tx{};

    // Create a transaction from univalue parameters
    static TransactionDraft FromRPC(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf);
    static TransactionDraft FromHex(const std::string& hex, const bool try_no_witness, const bool try_witness);

    // Insert additional inputs into the transaction by calling CreateTransaction();
    FundTransactionResult FundTransaction(CWallet& wallet, const int nChangePosIn, const bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, const CCoinControl& coin_control_in, bool allow_mweb_result = true);

    std::vector<CRecipient> BuildRecipients(const std::set<int>& setSubtractFeeFromOutputs = {});
    CMutableTransaction ToMutableTx() const;
    CTransaction ToTransaction() const;
    PartiallySignedTransaction ToPSBT(const CWallet& wallet) const;
    std::string ToHex(const int serialize_flags = 0) const;
};

} // namespace wallet
