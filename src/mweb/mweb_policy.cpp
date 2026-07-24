#include <mweb/mweb_policy.h>

#include <mw/consensus/Params.h>
#include <mw/models/tx/Transaction.h>
#include <primitives/transaction.h>

using namespace MWEB;

// Relay/mempool policy limits for standalone MWEB transactions (non-consensus).
//
// The consensus limits (mw::MAX_BLOCK_WEIGHT / mw::MAX_NUM_INPUTS) permit a
// single transaction to contain an entire block's worth of inputs, outputs, and
// kernels. Because MWEB signature and rangeproof verification runs during
// mempool acceptance before any fee is required, relaying such a transaction
// would let a peer force a full block's worth of crypto verification for free.
// We therefore bound relayed MWEB transactions to ~2% of the consensus limits.
// (Note inputs carry no MWEB weight, so they must be bounded by count.)
static constexpr size_t MAX_STANDARD_MWEB_TX_WEIGHT = mw::MAX_BLOCK_WEIGHT / 50; // 4,000
static constexpr size_t MAX_STANDARD_MWEB_TX_INPUTS = mw::MAX_NUM_INPUTS / 50;   // 1,000

bool Policy::IsStandardTx(const CTransaction& tx, std::string& reason)
{
    // MWEB: To help avoid mempool bugs, we don't yet allow transaction aggregation
    // for transactions with canonical LTC data.
    if (!tx.IsMWEBOnly()) {
        std::set<mw::Hash> pegin_kernels;
        for (const CTxOut& txout : tx.vout) {
            mw::Hash kernel_id;
            if (txout.scriptPubKey.IsMWEBPegin(&kernel_id)) {
                pegin_kernels.insert(std::move(kernel_id));
            }
        }

        if (pegin_kernels != tx.mweb_tx.GetKernelIDs()) {
            reason = "kernel-mismatch";
            return false;
        }
    }

    // MWEB: Check MWEB transaction for non-standard kernel features
    if (tx.HasMWEBTx() && !tx.mweb_tx.m_transaction->IsStandard()) {
        reason = "non-standard-mweb-tx";
        return false;
    }

    return true;
}

bool Policy::CheckWeight(const CTransaction& tx, std::string& reason)
{
    if (!tx.HasMWEBTx()) {
        return true;
    }

    // HasMWEBTx() guarantees m_transaction is non-null.
    if (tx.mweb_tx.m_transaction->GetInputs().size() > MAX_STANDARD_MWEB_TX_INPUTS) {
        reason = "mweb-txn-too-many-inputs";
        return false;
    }

    if (tx.mweb_tx.m_transaction->CalcWeight() > MAX_STANDARD_MWEB_TX_WEIGHT) {
        reason = "mweb-txn-oversize";
        return false;
    }

    return true;
}
