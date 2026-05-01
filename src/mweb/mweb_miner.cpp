#include <mweb/mweb_miner.h>
#include <script/standard.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <policy/policy.h>
#include <validation.h>
#include <logging.h>
#include <key_io.h>
#include <miner.h>

using namespace MWEB;

void Miner::NewBlock(const uint64_t nHeight)
{
    mweb_builder = std::make_shared<mw::BlockBuilder>(nHeight, ::ChainstateActive().CoinsTip().GetMWEBView());
    hogex_fees = 0;
    hogex_sigops = 0;
    mweb_amount_change = 0;
    hogex_inputs.clear();
    hogex_outputs.clear();
}

int64_t Miner::GetHogExSigOpCost(const CTransaction& tx)
{
    int64_t sigops = 0;
    for (const PegOutCoin& pegout : tx.mweb_tx.GetPegOuts()) {
        sigops += WITNESS_SCALE_FACTOR * pegout.GetScriptPubKey().GetSigOpCount(false);
    }

    return sigops;
}

bool Miner::AddMWEBTransaction(CTxMemPool::txiter iter)
{
    CTransactionRef pTx = iter->GetSharedTx();

    //
    // Pegin
    //
    std::vector<CTxIn> vin;
    CAmount pegin_amount = 0;
    std::vector<PegInCoin> pegins = pTx->mweb_tx.GetPegIns();

    if (!ValidatePegIns(pTx, pegins)) {
        LogPrintf("Peg-in Mismatch\n");
        return false;
    }

    for (size_t nOut = 0; nOut < pTx->vout.size(); nOut++) {
        if (IsPegInOutput(pTx->GetOutput(nOut))) {
            vin.push_back(CTxIn{pTx->GetHash(), (uint32_t)nOut});

            assert(MoneyRange(pTx->vout[nOut].nValue));
            pegin_amount += pTx->vout[nOut].nValue;

            if (!MoneyRange(pegin_amount)) {
                LogPrintf("Invalid total peg-in amount\n");
                return false;
            }
        }
    }

    //
    // Pegout
    //
    std::vector<CTxOut> vout;
    CAmount pegout_amount = 0;
    std::vector<PegOutCoin> pegouts = pTx->mweb_tx.GetPegOuts();

    for (const PegOutCoin& pegout : pegouts) {
        CAmount amount(pegout.GetAmount());
        assert(MoneyRange(amount));

        vout.push_back(CTxOut{amount, pegout.GetScriptPubKey()});

        pegout_amount += amount;
        if (!MoneyRange(pegout_amount)) {
            LogPrintf("Invalid total peg-out amount\n");
            return false;
        }
    }

    // Validate fee amount range
    const auto tx_fee = pTx->mweb_tx.GetFee();
    if (!tx_fee || !MoneyRange(*tx_fee)) {
        LogPrintf("Invalid MWEB fee amount\n");
        return false;
    }

    //
    // Add transaction to MWEB
    //
    if (!mweb_builder->AddTransaction(pTx->mweb_tx.m_transaction, pegins)) {
        LogPrintf("Failed to add MWEB transaction\n");
        return false;
    }

    hogex_inputs.insert(hogex_inputs.end(), vin.cbegin(), vin.cend());
    hogex_outputs.insert(hogex_outputs.end(), vout.cbegin(), vout.cend());
    mweb_amount_change += (CAmount(pegin_amount) - CAmount(pegout_amount + *tx_fee));

    hogex_fees += *tx_fee;
    hogex_sigops += GetHogExSigOpCost(*pTx);

    return true;
}

namespace std {
template <>
struct hash<PegInCoin> {
    size_t operator()(const PegInCoin& pegin) const
    {
        return boost::hash_value(pegin.GetKernelID().vec()) + boost::hash_value(pegin.GetAmount());
    }
};
} // namespace std

bool Miner::ValidatePegIns(const CTransactionRef& pTx, const std::vector<PegInCoin>& pegins) const
{
    std::unordered_set<PegInCoin> pegin_set(pegins.cbegin(), pegins.cend());

    for (const CTxOut& output : pTx->vout) {
        mw::Hash kernel_id;
        if (output.scriptPubKey.IsMWEBPegin(&kernel_id)) {
            PegInCoin pegin(output.nValue, std::move(kernel_id));
            if (pegin_set.erase(pegin) != 1) {
                return false;
            }
        }
    }

    if (!pegin_set.empty()) {
        return false;
    }

    return true;
}

void Miner::AddHogExTransaction(const CBlockIndex* pIndexPrev, CBlock* pblock, CBlockTemplate* pblocktemplate, CAmount& nFees)
{
    CMutableTransaction hogExTransaction;
    hogExTransaction.m_hogEx = true;

    CAmount previous_amount = 0;

    //
    // Add previous HogAddr as new HogEx input
    //
    if (pIndexPrev->mweb_header != nullptr) {
        previous_amount = pIndexPrev->mweb_amount;

        CTxIn prevHogExIn(pIndexPrev->hogex_hash, 0);
        hogExTransaction.vin.push_back(std::move(prevHogExIn));
    }

    //
    // Add Peg-in inputs
    //
    hogExTransaction.vin.insert(hogExTransaction.vin.end(), hogex_inputs.cbegin(), hogex_inputs.cend());

    //
    // Add New HogAddr
    //
    mw::Block::Ptr mweb_block = mweb_builder->BuildBlock();

    CTxOut hogAddr;
    hogAddr.scriptPubKey = CScript() << OP_8 << mweb_block->GetHash().vec();
    hogAddr.nValue = previous_amount + mweb_amount_change;
    assert(MoneyRange(hogAddr.nValue));
    hogExTransaction.vout.push_back(std::move(hogAddr));

    //
    // Add Peg-out outputs
    //
    hogExTransaction.vout.insert(hogExTransaction.vout.end(), hogex_outputs.cbegin(), hogex_outputs.cend());

    //
    // Update block & template
    //
    pblock->vtx.emplace_back(MakeTransactionRef(std::move(hogExTransaction)));
    pblock->mweb_block = MWEB::Block(mweb_block);

    pblocktemplate->vTxFees.push_back(hogex_fees);
    pblocktemplate->vTxSigOpsCost.push_back(hogex_sigops);
}
