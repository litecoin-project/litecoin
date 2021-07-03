#include <mweb/mweb_node.h>

#include <chain.h>
#include <consensus/validation.h>
#include <mw/node/BlockValidator.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <undo.h>
#include <util/system.h>
#include <validation.h>

using namespace MWEB;

bool Node::CheckBlock(const CBlock& block, CValidationState& state)
{
    if (block.mweb_block.IsNull()) {
        return true;
    }

    uint256 mweb256 = block.GetMWEBHash();
    if (mweb256 == uint256()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-hogex", false, "HogEx missing or invalid");
    }

    for (size_t i = 0; i < block.vtx.size() - 1; i++) {
        if (block.vtx[i]->IsHogEx()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-hogex-position", false, "hogex in wrong position");
        }
    }

    // HasMWEBTx() is true only when mweb txs being shared outside of a block (for use by mempools).
    // Blocks themselves do not store mweb txs like normal txs.
    // They are instead stored and processed separately in the mweb block.
    // So at this point, no txs should contain MWEB data.
    for (const CTransactionRef& pTx : block.vtx) {
        if (pTx->HasMWEBTx()) {
            return state.DoS(100, false, REJECT_INVALID, "unexpected-mweb-data", true, "Block contains transactions with MWEB data attached");
        }
    }

    std::vector<PegInCoin> pegins;
    for (const CTransactionRef& pTx : block.vtx) {
        for (const CTxOut& out : pTx->vout) {
            Commitment commitment;
            if (out.scriptPubKey.IsMWEBPegin(commitment)) {
                pegins.push_back(PegInCoin{out.nValue, std::move(commitment)});
            }
        }
    }

    auto pHogEx = block.GetHogEx();
    assert(pHogEx != nullptr);

    std::vector<PegOutCoin> pegouts;
    for (size_t i = 1; i < pHogEx->vout.size(); i++) {
        const CScript& pubkey = pHogEx->vout[i].scriptPubKey;
        pegouts.push_back(PegOutCoin(pHogEx->vout[i].nValue, {pubkey.begin(), pubkey.end()}));
    }

    if (!BlockValidator::ValidateBlock(block.mweb_block.m_block, mw::Hash(mweb256.begin()), pegins, pegouts)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-mw", false, "BlockValidator::ValidateBlock failed");
    }

    return true;
}

bool Node::ContextualCheckBlock(const CBlock& block, const Consensus::Params& consensus_params, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (!IsMWEBEnabled(pindexPrev, consensus_params)) {
        // No MWEB data is allowed in blocks that don't commit to MWEB data, as this would otherwise leave room for spam
        if (!block.mweb_block.IsNull()) {
            return state.DoS(100, false, REJECT_INVALID, "unexpected-mweb-data", true, "MWEB::Node::ContextualCheckBlock(): MWEB not activated, but extension block found");
        }

        return true;
    }

    if (block.mweb_block.IsNull()) {
        return state.DoS(100, false, REJECT_INVALID, "mweb-missing", true, "MWEB::Node::ContextualCheckBlock(): MWEB activated but extension block not found");
    }

    if (block.mweb_block.GetHeight() != (pindexPrev->nHeight + 1)) {
        return state.DoS(100, error("MWEB::Node::ConnectBlock(): Invalid MWEB block height"),
            REJECT_INVALID, "mweb-height-mismatch");
    }

    auto pHogEx = block.GetHogEx();
    assert(pHogEx != nullptr);

    size_t next_pegin_idx = 0;
    if (IsMWEBEnabled(pindexPrev->pprev, consensus_params)) {
        const COutPoint& prev_hogex_out = pHogEx->vin[next_pegin_idx++].prevout;
        if (prev_hogex_out.n != 0 || pindexPrev->hogex_hash != prev_hogex_out.hash) {
            return state.DoS(100, false, REJECT_INVALID, "invalid-hogex-input", false, "First input of HogEx does not point to previous HogEx");
        }
    }

    CAmount hogex_input_amount = pindexPrev->mweb_amount;
    for (size_t nTx = 1; nTx < block.vtx.size() - 1; nTx++) {
        const CTransactionRef& pTx = block.vtx[nTx];
        for (size_t nOut = 0; nOut < pTx->vout.size(); nOut++) {
            Commitment commitment;
            if (pTx->vout[nOut].scriptPubKey.IsMWEBPegin(commitment)) {
                if (pHogEx->vin.size() <= next_pegin_idx) {
                    return state.DoS(100, false, REJECT_INVALID, "pegins-missing", false, "Pegins missing from HogEx");
                }

                const COutPoint& hogex_input = pHogEx->vin[next_pegin_idx++].prevout;
                if (hogex_input.n != nOut || hogex_input.hash != pTx->GetHash()) {
                    return state.DoS(100, false, REJECT_INVALID, "pegin-mismatch", false, "HogEx pegins do not match block's pegins");
                }

                hogex_input_amount += pTx->vout[nOut].nValue;
                if (!MoneyRange(hogex_input_amount)) {
                    return state.DoS(100, error("MWEB::Node::ContextualCheckBlock(): accumulated pegin amount for the block out of range."),
                        REJECT_INVALID, "accumulated-pegin-outofrange");
                }
            }
        }
    }

    if (next_pegin_idx != pHogEx->vin.size()) {
        return state.DoS(100, false, REJECT_INVALID, "extra-hogex-input", false, "HogEx contains unexpected input(s)");
    }

    // MWEB: For HogEx transaction, the fee must be equal to the total fee of the extension block.
    CAmount hogex_fee = hogex_input_amount - pHogEx->GetValueOut();
    if (hogex_fee != block.mweb_block.GetTotalFee()) {
        return state.DoS(100, error("MWEB::Node::ContextualCheckBlock(): HogEx fee does not match MWEB fee."),
            REJECT_INVALID, "bad-txns-mweb-fee-mismatch");
    }

    // Check HogEx transaction: `new value == (prev value + pegins) - (pegouts + fees)`
    CAmount mweb_amount = pindexPrev->mweb_amount + block.mweb_block.GetSupplyChange();
    if (mweb_amount != block.GetMWEBAmount()) {
        return state.DoS(100, error("MWEB::Node::ContextualCheckBlock(): HogEx amount does not match expected MWEB amount"),
            REJECT_INVALID, "mweb-amount-mismatch");
    }

    return true;
}

bool Node::ConnectBlock(const CBlock& block, const Consensus::Params& consensus_params, const CBlockIndex* pindexPrev, CBlockUndo& blockundo, mw::CoinsViewCache& mweb_view, CValidationState& state)
{
    if (!ContextualCheckBlock(block, consensus_params, pindexPrev, state)) {
        return false;
    }

    if (!block.mweb_block.IsNull()) {
        try {
            blockundo.mwundo = mweb_view.ApplyBlock(block.mweb_block.m_block);
        } catch (const std::exception& e) {
            return state.DoS(100, error("MWEB::Node::ConnectBlock(): Failed to connect mw block: %s", e.what()),
                REJECT_INVALID, "mweb-connect-failed");
        }
    }

    return true;
}

bool Node::CheckTransaction(const CTransaction& tx, CValidationState& state)
{
    if (tx.IsCoinBase() || tx.IsHogEx()) {
        for (const CTxOut& out : tx.vout) {
            Commitment commitment;
            if (out.scriptPubKey.IsMWEBPegin(commitment)) {
                return state.DoS(100, false, REJECT_INVALID, strprintf("bad-%s-contains-pegin", tx.IsHogEx() ? "hogex" : "cb"));
            }
        }
    }

    if (tx.HasMWEBTx()) {
        try {
            tx.mweb_tx.m_transaction->Validate();
        } catch (const std::exception& e) {
            return state.DoS(10, false, REJECT_INVALID, "bad-mweb-txn");
        }
    }

    return true;
}