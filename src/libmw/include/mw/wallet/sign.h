#pragma once

#include <mw/common/Macros.h>
#include <mw/models/crypto/SecretKey.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/wallet/WalletCoin.h>

#include <coins.h>
#include <primitives/transaction.h>
#include <util/result.h>

#include <functional>

MW_NAMESPACE

using SenderKeyGenerator = std::function<util::Result<SecretKey>()>;

struct SignTxResult
{
    //! Contains a mw::WalletCoin for each output that was signed for the MutableTx, mapped to the output's ID.
    std::map<mw::Hash, mw::WalletCoin> wallet_coins_by_output_id;
};

/// <summary>
/// Finalizes the MWEB tx in the CMutableTransaction provided by generating all excesses, pubkeys, signatures, etc.
/// </summary>
/// <param name="tx">A CMutableTransaction containing an MWEB tx with all inputs, kernels, and outputs. Components can be stubs (unsigned) or already finalized/signed.</param>
/// <remarks>
/// This may rewrite peg-in scriptPubKeys in tx.vout with finalized kernel IDs.
/// Any PrecomputedTransactionData built from tx before this call must be discarded and rebuilt.
/// </remarks>
/// <returns></returns>
extern util::Result<mw::SignTxResult> SignTx(CMutableTransaction& tx, const SecretKey& rewind_key, const SenderKeyGenerator& generate_sender_key) noexcept;

END_NAMESPACE
