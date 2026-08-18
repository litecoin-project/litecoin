#include <mw/models/tx/Transaction.h>

MW_NAMESPACE

Transaction::CPtr Transaction::Create(
    BlindingFactor kernel_offset,
    BlindingFactor stealth_offset,
    std::vector<mw::Input> inputs,
    std::vector<mw::Output> outputs,
    std::vector<mw::Kernel> kernels)
{
    std::sort(inputs.begin(), inputs.end(), InputSort());
    std::sort(outputs.begin(), outputs.end(), OutputSort());
    std::sort(kernels.begin(), kernels.end(), KernelSort());

    return std::make_shared<mw::Transaction>(
        std::move(kernel_offset),
        std::move(stealth_offset),
        mw::TxBody{
            std::move(inputs),
            std::move(outputs),
            std::move(kernels)
        }
    );
}

END_NAMESPACE
