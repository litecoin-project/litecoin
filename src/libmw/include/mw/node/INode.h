#pragma once

#include <mw/common/Macros.h>
#include <mw/common/BitSet.h>
#include <mw/node/CoinsView.h>
#include <mw/models/block/Header.h>
#include <mw/models/block/Block.h>
#include <mw/models/block/BlockUndo.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <mw/models/tx/UTXO.h>
#include <libmw/interfaces/chain_interface.h>
#include <libmw/interfaces/db_interface.h>
#include <functional>
#include <vector>

MW_NAMESPACE

class INode
{
public:
    using Ptr = std::shared_ptr<INode>;

    virtual ~INode() = default;

    virtual ICoinsView::Ptr GetDBView() = 0;

    //
    // Context-free validation of a block.
    //
    virtual void ValidateBlock(
        const mw::Block::Ptr& pBlock,
        const mw::Hash& mweb_hash,
        const std::vector<PegInCoin>& pegInCoins,
        const std::vector<PegOutCoin>& pegOutCoins
    ) const = 0;

    //
    // Contextual validation of the block and application of the block to the supplied ICoinsView.
    // Consumer is required to call ValidateBlock first.
    //
    virtual mw::BlockUndo::CPtr ConnectBlock(const mw::Block::Ptr& pBlock, const ICoinsView::Ptr& pView) = 0;

    virtual void DisconnectBlock(
        const mw::BlockUndo::CPtr& pUndoData,
        const ICoinsView::Ptr& pView
    ) = 0;

    virtual mw::ICoinsView::Ptr ApplyState(
        const libmw::IDBWrapper::Ptr& pDBWrapper,
        const libmw::IChain::Ptr& pChain,
        const mw::Header::CPtr& pStateHeader,
        const std::vector<UTXO::CPtr>& utxos,
        const std::vector<Kernel>& kernels,
        const BitSet& leafset,
        const std::vector<mw::Hash>& pruned_parent_hashes
    ) = 0;
};

//
// Creates an instance of the node.
// This will fail if an instance is already running.
//
INode::Ptr InitializeNode(
    const FilePath& datadir,
    const std::string& hrp,
    const mw::Header::CPtr& pBestHeader,
    const libmw::IDBWrapper::Ptr& pDBWrapper
);

END_NAMESPACE