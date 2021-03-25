#include <mw/node/validation/StateValidator.h>
#include <mw/consensus/KernelSumValidator.h>

void StateValidator::Validate(const mw::ICoinsView& coins_view)
{
    std::vector<Commitment> utxos;

    auto pKernelMMR = coins_view.GetKernelMMR();
    auto pOutputPMMR = coins_view.GetOutputPMMR();
    auto pLeafSet = coins_view.GetLeafSet();

    const uint64_t num_outputs = pOutputPMMR->GetNumLeaves();
    for (size_t i = 0; i < num_outputs; i++) {
        mmr::LeafIndex index = mmr::LeafIndex::At(i);
        if (pLeafSet->Contains(index)) {
            mmr::Leaf leaf = pOutputPMMR->GetLeaf(index);
            OutputId output_id = Deserializer(leaf.vec()).Read<OutputId>();
            utxos.push_back(output_id.GetCommitment());
        }
    }

    std::vector<Kernel> kernels;
    const uint64_t num_kernels = pKernelMMR->GetNumLeaves();
    for (size_t i = 0; i < num_kernels; i++) {
        mmr::Leaf leaf = pKernelMMR->GetLeaf(mmr::LeafIndex::At(i));
        kernels.push_back(Deserializer(leaf.vec()).Read<Kernel>());
    }

    KernelSumValidator::ValidateState(utxos, kernels, coins_view.GetBestHeader()->GetKernelOffset());
}