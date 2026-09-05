#include <mw/models/block/Block.h>

#include <mw/consensus/Params.h>
#include <mw/consensus/StealthSumValidator.h>
#include <mw/mmr/MMR.h>

bool mw::Block::HasValidKernelMMR() const
{
    if (m_pHeader->GetNumKernels() != m_body.GetKernels().size()) {
        return false;
    }

    MemMMR kernel_mmr;
    std::for_each(
        GetKernels().cbegin(), GetKernels().cend(),
        [&kernel_mmr](const Kernel& kernel) { kernel_mmr.Add(kernel); }
    );
    return m_pHeader->GetKernelRoot() == kernel_mmr.Root();
}

void mw::Block::Validate() const
{
    if (m_pHeader->GetNumKernels() != m_body.GetKernels().size()) {
        ThrowValidation(EConsensusError::MMR_MISMATCH);
    }

    m_body.Validate();

    if (GetHeight() > mw::KERNEL_LOCK_HEIGHT_GRANDFATHER_HEIGHT && m_body.GetLockHeight() > GetHeight()) {
        ThrowValidation(EConsensusError::LOCK_HEIGHT);
    }

    StealthSumValidator::Validate(m_pHeader->GetStealthOffset(), m_body);

    if (!HasValidKernelMMR()) {
        ThrowValidation(EConsensusError::MMR_MISMATCH);
    }
}
