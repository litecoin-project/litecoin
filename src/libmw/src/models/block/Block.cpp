#include <mw/models/block/Block.h>

#include <mw/consensus/Params.h>
#include <mw/consensus/StealthSumValidator.h>
#include <mw/mmr/MMR.h>

std::optional<EConsensusError> mw::Block::Validate() const noexcept
try {
    if (m_pHeader->GetNumKernels() != m_body.GetKernels().size()) {
        return EConsensusError::MMR_MISMATCH;
    }

    if (const auto body_error = m_body.Validate()) {
        return body_error;
    }

    if (GetHeight() > mw::KERNEL_LOCK_HEIGHT_GRANDFATHER_HEIGHT && m_body.GetLockHeight() > GetHeight()) {
        return EConsensusError::LOCK_HEIGHT;
    }

    if (const auto stealth_error = StealthSumValidator::Validate(m_pHeader->GetStealthOffset(), m_body)) {
        return stealth_error;
    }

    MemMMR kernel_mmr;
    std::for_each(
        GetKernels().cbegin(), GetKernels().cend(),
        [&kernel_mmr](const mw::Kernel& kernel) { kernel_mmr.Add(kernel); }
    );
    if (m_pHeader->GetKernelRoot() != kernel_mmr.Root()) {
        return EConsensusError::MMR_MISMATCH;
    }

    return std::nullopt;
} catch (const std::exception&) {
    // Data that cannot even be processed for validation is invalid data.
    return EConsensusError::BAD_STATE;
}
