#include <libmw/node.h>

#include "Transformers.h"

#include <mw/common/Logger.h>
#include <mw/consensus/ChainParams.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/BlockUndo.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/UTXO.h>
#include <mw/node/INode.h>
#include <mw/node/Snapshot.h>
#include <mw/node/State.h>
#include <mw/wallet/Wallet.h>

static mw::INode::Ptr NODE = nullptr;

LIBMW_NAMESPACE
NODE_NAMESPACE

MWEXPORT libmw::CoinsViewRef Initialize(
    const libmw::ChainParams& chainParams,
    const libmw::HeaderRef& header,
    const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper,
    const std::function<void(const std::string&)>& log_callback)
{
    LoggerAPI::Initialize(log_callback);
    NODE = mw::InitializeNode(FilePath{ chainParams.dataDirectory.native() }, chainParams.hrp, header.pHeader, pDBWrapper);

    return libmw::CoinsViewRef{ NODE->GetDBView() };
}

MWEXPORT void Shutdown()
{
    NODE.reset();
}

MWEXPORT libmw::CoinsViewRef ApplyState(
    const libmw::IChain::Ptr& pChain,
    const libmw::IDBWrapper::Ptr& pCoinsDB,
    const libmw::HeaderRef& stateHeader,
    const libmw::StateRef& state)
{
    auto pCoinsViewDB = NODE->ApplyState(
        pCoinsDB,
        pChain,
        stateHeader.pHeader,
        state.pState->utxos,
        state.pState->kernels,
        state.pState->leafset,
        state.pState->pruned_parent_hashes
    );

    return libmw::CoinsViewRef{ pCoinsViewDB };
}

MWEXPORT bool CheckBlock(
    const libmw::BlockRef& block,
    const libmw::BlockHash& hash,
    const std::vector<libmw::PegIn>& pegInCoins,
    const std::vector<libmw::PegOut>& pegOutCoins)
{
    assert(block.pBlock != nullptr);

    try {
        auto mweb_hash = TransformHash(hash);
        auto pegins = TransformPegIns(pegInCoins);
        auto pegouts = TransformPegOuts(pegOutCoins);
        NODE->ValidateBlock(block.pBlock, mweb_hash, pegins, pegouts);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR_F("Validation error: {}", e.what());
    }

    return false;
}

MWEXPORT libmw::BlockUndoRef ConnectBlock(const libmw::BlockRef& block, const CoinsViewRef& view)
{
    return libmw::BlockUndoRef{ NODE->ConnectBlock(block.pBlock, view.pCoinsView) };
}

MWEXPORT void DisconnectBlock(const libmw::BlockUndoRef& undoData, const CoinsViewRef& view)
{
    NODE->DisconnectBlock(undoData.pUndo, view.pCoinsView);
}

MWEXPORT void FlushCache(const libmw::CoinsViewRef& view, const std::unique_ptr<libmw::IDBBatch>& pBatch)
{
    LOG_TRACE("Flushing cache");
    auto pViewCache = dynamic_cast<mw::CoinsViewCache*>(view.pCoinsView.get());
    assert(pViewCache != nullptr);

    pViewCache->Flush(pBatch);
    LOG_TRACE("Cache flushed");
}

MWEXPORT libmw::StateRef SnapshotState(const libmw::CoinsViewRef& view)
{
    assert(view.pCoinsView != nullptr);
    return { std::make_shared<mw::State>(mw::Snapshot::Build(view.pCoinsView)) };
}

MWEXPORT bool CheckTransaction(const libmw::TxRef& transaction)
{
    assert(transaction.pTransaction != nullptr);

    try {
        transaction.pTransaction->Validate();
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR_F("Validation error: {}", e.what());
    }

    return false;
}

MWEXPORT bool CheckTxInputs(const libmw::CoinsViewRef& view, const libmw::TxRef& transaction, uint64_t nSpendHeight)
{
    assert(view.pCoinsView != nullptr);
    assert(transaction.pTransaction != nullptr);

    try {
        for (const Input& input : transaction.pTransaction->GetInputs()) {
            auto utxos = view.pCoinsView->GetUTXOs(input.GetCommitment());
            if (utxos.empty()) {
                ThrowValidation(EConsensusError::UTXO_MISSING);
            }

            if (utxos.back()->IsPeggedIn() && nSpendHeight < utxos.back()->GetBlockHeight() + mw::ChainParams::GetPegInMaturity()) {
                ThrowValidation(EConsensusError::PEGIN_MATURITY);
            }
        }

        return true;
    } catch (const std::exception& e) {
        LOG_ERROR_F("Validation error: {}", e.what());
    }

    return false;
}

MWEXPORT bool HasCoin(const libmw::CoinsViewRef& view, const libmw::Commitment& commitment)
{
    assert(view.pCoinsView != nullptr);

    return !view.pCoinsView->GetUTXOs(commitment).empty();
}

MWEXPORT bool HasCoinInCache(const libmw::CoinsViewRef& view, const libmw::Commitment& commitment)
{
    assert(view.pCoinsView != nullptr);

    auto pCoinsView = std::dynamic_pointer_cast<mw::CoinsViewCache>(view.pCoinsView);
    assert(pCoinsView != nullptr);

    return pCoinsView->HasCoinInCache(commitment);
}

END_NAMESPACE // node
END_NAMESPACE // libmw