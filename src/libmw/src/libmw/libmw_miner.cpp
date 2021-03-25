#include <libmw/node.h>

#include "Transformers.h"

#include <mw/node/BlockBuilder.h>
#include <mw/common/Logger.h>

LIBMW_NAMESPACE
MINER_NAMESPACE

MWEXPORT libmw::BlockBuilderRef NewBuilder(const uint64_t height, const libmw::CoinsViewRef& view)
{
    return libmw::BlockBuilderRef{ std::make_shared<mw::BlockBuilder>(height, view.pCoinsView) };
}

MWEXPORT bool AddTransaction(
    const libmw::BlockBuilderRef& builder,
    const libmw::TxRef& transaction,
    const std::vector<libmw::PegIn>& pegins)
{
    assert(builder.pBuilder != nullptr);
    assert(transaction.pTransaction != nullptr);

    try {
        return builder.pBuilder->AddTransaction(transaction.pTransaction, TransformPegIns(pegins));
    } catch (std::exception& e) {
        LOG_DEBUG_F("Failed to add transaction {}. Error: {}", transaction.pTransaction, e.what());
    }

    return false;
}

MWEXPORT libmw::BlockRef BuildBlock(const libmw::BlockBuilderRef& builder)
{
    return libmw::BlockRef{ builder.pBuilder->BuildBlock() };
}

END_NAMESPACE // miner
END_NAMESPACE // libmw