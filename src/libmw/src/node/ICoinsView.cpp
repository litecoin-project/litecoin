#include <mw/node/CoinsView.h>

#include <mw/exceptions/ValidationException.h>

MW_NAMESPACE

void ICoinsView::ValidateMMRs(const mw::Header::CPtr& pHeader) const
{
    assert(pHeader != nullptr);

    if (pHeader->GetKernelRoot() != GetKernelMMR()->Root()
        || pHeader->GetNumKernels() != GetKernelMMR()->GetNumLeaves()
        || pHeader->GetOutputRoot() != GetOutputPMMR()->Root()
        || pHeader->GetNumTXOs() != GetOutputPMMR()->GetNumLeaves()
        || pHeader->GetLeafsetRoot() != GetLeafSet()->Root()) {

        LOG_DEBUG_F("Kernel root: {}", GetKernelMMR()->Root());
        LOG_DEBUG_F("Leafset root: {}", GetLeafSet()->Root());
        ThrowValidation(EConsensusError::MMR_MISMATCH);
    }
}

END_NAMESPACE