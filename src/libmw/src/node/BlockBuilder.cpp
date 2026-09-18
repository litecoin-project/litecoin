#include <mw/node/BlockBuilder.h>
#include <mw/crypto/Pedersen.h>
#include <mw/consensus/Params.h>
#include <mw/consensus/Weight.h>
#include <logging.h>

#include <unordered_set>
#include <numeric>

MW_NAMESPACE

bool BlockBuilder::AddTransaction(const Transaction::CPtr& pTransaction, const std::vector<PegInCoin>& pegins)
{
    // Check input count
    const size_t num_inputs = pTransaction->GetInputs().size();
    if ((num_inputs + m_num_inputs) > mw::MAX_NUM_INPUTS) {
        LogPrintf("Exceeds max input count\n");
        return false;
    }

    // Check weight
    uint64_t weight = Weight::Calculate(pTransaction->GetBody());
    if ((weight + m_weight) > mw::MAX_BLOCK_WEIGHT) {
        LogPrintf("Exceeds max block weight\n");
        return false;
    }
    
    // Verify pegin amount matches
    const auto actual_amount = pTransaction->GetPegInAmount();
    if (!actual_amount) {
        LogPrintf("Invalid pegin amount\n");
        return false;
    }

    const CAmount expected_amount = std::accumulate(pegins.cbegin(), pegins.cend(), (CAmount)0,
        [](const CAmount sum, const PegInCoin& pegin) { return sum + pegin.GetAmount(); }
    );
    if (*actual_amount != expected_amount) {
        LogPrintf("Mismatched pegin amount\n");
        return false;
    }

    // Verify pegin kernels are unique
    std::unordered_set<mw::Hash> pegin_ids;
    for (const PegInCoin& pegin : pegins) {
        if (pegin_ids.find(pegin.GetKernelID()) != pegin_ids.end()) {
            LogPrintf("Duplicate pegin kernels\n");
            return false;
        }

        pegin_ids.insert(pegin.GetKernelID());
    }

    // Verify pegin outputs are included
    std::vector<PegInCoin> pegin_coins = pTransaction->GetPegIns();
    if (pegin_coins.size() != pegins.size()) {
        LogPrintf("Mismatched pegin count\n");
        return false;
    }

    for (const PegInCoin& pegin : pegin_coins) {
        if (pegin_ids.find(pegin.GetKernelID()) == pegin_ids.end()) {
            LogPrintf("Pegin kernel %s not found\n", pegin.GetKernelID().Format());
            return false;
        }
    }

    // Validate transaction
    if (const auto tx_error = pTransaction->Validate()) {
        LogPrintf("Failed to validate transaction %s. Error: %s\n", pTransaction->Format(), ConsensusErrorString(*tx_error));
        return false;
    }
    
    // Kernel IDs must remain unique in the aggregate block body.
    for (const mw::Kernel& kernel : pTransaction->GetKernels()) {
        if (m_stagedKernels.count(kernel.GetKernelID()) != 0) {
            LogPrintf("Kernel %s already staged\n", kernel.GetKernelID().Format());
            return false;
        }
    }

    // Individually valid transactions can form unrepresentable group identities
    // when aggregated. Incremental checks keep template construction linear.
    auto kernel_sums = m_kernelSums;
    auto stealth_sums = m_stealthSums;
    if (const auto error = KernelSumValidator::ValidateAndAdd(*pTransaction, kernel_sums)) {
        LogPrintf("Transaction is incompatible with staged MWEB kernel sums: %s\n", ConsensusErrorString(*error));
        return false;
    }
    if (const auto error = StealthSumValidator::ValidateAndAdd(
            pTransaction->GetStealthOffset(), pTransaction->GetBody(), stealth_sums)) {
        LogPrintf("Transaction is incompatible with staged MWEB stealth sums: %s\n", ConsensusErrorString(*error));
        return false;
    }

    // Make sure all inputs are available.
    for (const mw::Input& input : pTransaction->GetInputs()) {
        if (m_stagedInputs.count(input.GetOutputID()) > 0) {
            LogPrintf("Input %s already staged\n", input.GetOutputID().Format());
            return false;
        }

        if (!m_pCoinsView->HasCoin(input.GetOutputID()) && m_stagedOutputs.count(input.GetOutputID()) == 0) {
            LogPrintf("Input %s not found on chain\n", input.GetOutputID().Format());
            return false;
        }
    }

    // Make sure no duplicate outputs already on chain.
    for (const mw::Output& output : pTransaction->GetOutputs()) {
        if (m_pCoinsView->HasCoin(output.GetOutputID())) {
            LogPrintf("Output %s already on chain\n", output.GetOutputID().Format());
            return false;
        }

        if (m_stagedOutputs.count(output.GetOutputID()) > 0) {
            LogPrintf("Output %s already staged\n", output.GetOutputID().Format());
            return false;
        }
    }

    m_stagedTxs.push_back(pTransaction);
    m_weight += weight;
    m_num_inputs += num_inputs;

    for (const mw::Input& input : pTransaction->GetInputs()) {
        auto inserted = m_stagedInputs.insert(input.GetOutputID());
        assert(inserted.second);
    }

    for (const mw::Output& output : pTransaction->GetOutputs()) {
        auto inserted = m_stagedOutputs.insert(output.GetOutputID());
        assert(inserted.second);
    }

    for (const mw::Kernel& kernel : pTransaction->GetKernels()) {
        const auto inserted = m_stagedKernels.insert(kernel.GetKernelID());
        assert(inserted.second);
    }
    m_kernelSums = std::move(kernel_sums);
    m_stealthSums = std::move(stealth_sums);

    return true;
}

mw::Block::Ptr BlockBuilder::BuildBlock() const
{
    return mw::CoinsViewCache(m_pCoinsView).BuildNextBlock(m_height, m_stagedTxs);
}

END_NAMESPACE
