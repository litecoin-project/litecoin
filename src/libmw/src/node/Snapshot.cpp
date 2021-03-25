#include <mw/node/Snapshot.h>
#include <mw/mmr/MMRUtil.h>

using namespace mw;

State Snapshot::Build(const ICoinsView::CPtr& pView)
{
    // TODO: We will start using this in a future release when we finish
    // the more-efficient state sync (i.e. download pruned state instead of block by block).
    // When we do use this, we have to decide whether it's better to rewind from Litecoin code or from here.

    //
    // Load kernels
    //
    std::vector<Kernel> kernels;

    auto pKernelMMR = pView->GetKernelMMR();
    kernels.reserve(pKernelMMR->GetNumLeaves());

    mmr::LeafIndex kernel_idx = mmr::LeafIndex::At(0);
    while (kernel_idx < pKernelMMR->GetNextLeafIdx()) {
        mmr::Leaf leaf = pKernelMMR->GetLeaf(kernel_idx);
        kernels.push_back(Deserializer(leaf.vec()).Read<Kernel>());
        ++kernel_idx;
    }

    //
    // Build unspent leaves bitset
    //
    BitSet leafset = pView->GetLeafSet()->ToBitSet();
    
    //
    // Load UTXOs
    //
    std::vector<UTXO::CPtr> utxos;
    utxos.reserve(leafset.count());

    auto pOutputPMMR = pView->GetOutputPMMR();

    mmr::LeafIndex output_idx = mmr::LeafIndex::At(0);
    while (output_idx < pOutputPMMR->GetNextLeafIdx()) {
        if (leafset.test(output_idx.Get())) {
            mmr::Leaf leaf = pOutputPMMR->GetLeaf(kernel_idx);
            OutputId output_id = Deserializer(leaf.vec()).Read<OutputId>();
            std::vector<UTXO::CPtr> utxo = pView->GetUTXOs(output_id.GetCommitment());
            assert(utxo.size() == 1);
            utxos.push_back(utxo.front());
        }
        
        ++output_idx;
    }
    
    //
    // Lookup parent hashes
    //
    std::vector<mw::Hash> pruned_parent_hashes;
    BitSet pruned_parent_bitset = mmr::MMRUtil::CalcPrunedParents(leafset);
    for (uint64_t i = 0; i < pruned_parent_bitset.size(); i++) {
        if (pruned_parent_bitset.test(i)) {
            mw::Hash hash = pOutputPMMR->GetHash(mmr::Index::At(i));
            pruned_parent_hashes.push_back(std::move(hash));
        }
    }

    return State{
        pView->GetBestHeader()->GetHash(),
        std::move(kernels),
        std::move(leafset),
        std::move(utxos),
        std::move(pruned_parent_hashes)
    };
}