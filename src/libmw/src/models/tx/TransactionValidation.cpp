#include <mw/models/tx/Transaction.h>

#include <mw/consensus/KernelSumValidator.h>
#include <mw/consensus/StealthSumValidator.h>

MW_NAMESPACE

bool Transaction::IsStandard() const noexcept
{
    for (const mw::Input& input : GetInputs()) {
        if (!input.IsStandard()) {
            return false;
        }
    }

    for (const mw::Kernel& kernel : GetKernels()) {
        if (!kernel.IsStandard()) {
            return false;
        }
    }

    for (const mw::Output& output : GetOutputs()) {
        if (!output.IsStandard()) {
            return false;
        }
    }

    return true;
}

std::optional<EConsensusError> Transaction::Validate() const noexcept
{
    if (const auto body_error = m_body.Validate()) {
        return body_error;
    }

    if (const auto kernel_sum_error = KernelSumValidator::ValidateForTx(*this)) {
        return kernel_sum_error;
    }

    return StealthSumValidator::Validate(m_stealthOffset, m_body);
}

END_NAMESPACE
