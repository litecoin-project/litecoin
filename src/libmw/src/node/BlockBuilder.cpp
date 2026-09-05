#include <mw/node/BlockBuilder.h>
#include <mw/consensus/Params.h>
#include <mw/consensus/Weight.h>

#include <unordered_set>
#include <numeric>

MW_NAMESPACE

bool BlockBuilder::AddTransaction(const Transaction::CPtr& pTransaction, const std::vector<PegInCoin>& pegins)
{
    // Check input count
    const size_t num_inputs = pTransaction->GetInputs().size();
    if ((num_inputs + m_num_inputs) > mw::MAX_NUM_INPUTS) {
        LOG_ERROR("Exceeds max input count");
        return false;
    }

    // Check weight
    uint64_t weight = Weight::Calculate(pTransaction->GetBody());
    if ((weight + m_weight) > mw::MAX_BLOCK_WEIGHT) {
        LOG_ERROR("Exceeds max block weight");
        return false;
    }
    
    // Verify pegin amount matches
    const auto actual_amount = pTransaction->GetPegInAmount();
    if (!actual_amount) {
        LOG_ERROR("Invalid pegin amount");
        return false;
    }

    const CAmount expected_amount = std::accumulate(pegins.cbegin(), pegins.cend(), (CAmount)0,
        [](const CAmount sum, const PegInCoin& pegin) { return sum + pegin.GetAmount(); }
    );
    if (*actual_amount != expected_amount) {
        LOG_ERROR("Mismatched pegin amount");
        return false;
    }

    // Verify pegin kernels are unique
    std::unordered_set<mw::Hash> pegin_ids;
    for (const PegInCoin& pegin : pegins) {
        if (pegin_ids.find(pegin.GetKernelID()) != pegin_ids.end()) {
            LOG_ERROR("Duplicate pegin kernels");
            return false;
        }

        pegin_ids.insert(pegin.GetKernelID());
    }

    // Verify pegin outputs are included
    std::vector<PegInCoin> pegin_coins = pTransaction->GetPegIns();
    if (pegin_coins.size() != pegins.size()) {
        LOG_ERROR("Mismatched pegin count");
        return false;
    }

    for (const PegInCoin& pegin : pegin_coins) {
        if (pegin_ids.find(pegin.GetKernelID()) == pegin_ids.end()) {
            LOG_ERROR_F("Pegin kernel {} not found", pegin.GetKernelID());
            return false;
        }
    }

    // Validate transaction
    try {
        pTransaction->Validate();
    } catch (std::exception& e) {
        LOG_ERROR_F("Failed to validate transaction {}. Error: {}", pTransaction, e.what());
        return false;
    }
    
    // Kernel IDs must remain unique in the aggregate block body.
    for (const Kernel& kernel : pTransaction->GetKernels()) {
        if (m_stagedKernels.count(kernel.GetKernelID()) > 0) {
            LOG_ERROR_F("Kernel {} already staged", kernel.GetKernelID());
            return false;
        }
    }

    // Individually valid transactions can still form unrepresentable group
    // identities when aggregated. Extend the validated sums using only the
    // candidate so template construction remains linear in the body size.
    KernelSumValidator::SumState kernel_sums;
    StealthSumValidator::SumState stealth_sums;
    try {
        kernel_sums = KernelSumValidator::ValidateAndAdd(*pTransaction, m_kernelSums);
        stealth_sums = StealthSumValidator::ValidateAndAdd(
            pTransaction->GetStealthOffset(),
            pTransaction->GetBody(),
            m_stealthSums
        );
    } catch (const std::exception& e) {
        LOG_ERROR_F("Transaction is incompatible with staged MWEB transactions. Error: {}", e.what());
        return false;
    }

    // Make sure all inputs are available.
    for (const Input& input : pTransaction->GetInputs()) {
        //if (m_stagedInputs.count(input.GetOutputID()) > 0) { // MW: TODO - Is this necessary, or are duplicate output checks enough?
        //    LOG_ERROR_F("Input {} already staged", input.GetOutputID());
        //    return false;
        //}

        if (!m_pCoinsView->HasCoin(input.GetOutputID()) && m_stagedOutputs.count(input.GetOutputID()) == 0) {
            LOG_ERROR_F("Input {} not found on chain", input.GetOutputID());
            return false;
        }
    }

    // Make sure no duplicate outputs already on chain.
    for (const Output& output : pTransaction->GetOutputs()) {
        if (m_pCoinsView->HasCoin(output.GetOutputID())) {
            LOG_ERROR_F("Output {} already on chain", output.GetOutputID());
            return false;
        }

        if (m_stagedOutputs.count(output.GetOutputID()) > 0) {
            LOG_ERROR_F("Output {} already staged", output.GetOutputID());
            return false;
        }
    }

    m_stagedTxs.push_back(pTransaction);
    m_weight += weight;
    m_num_inputs += num_inputs;

    for (const Output& output : pTransaction->GetOutputs()) {
        auto inserted = m_stagedOutputs.insert(output.GetOutputID());
        assert(inserted.second);
    }

    for (const Kernel& kernel : pTransaction->GetKernels()) {
        auto inserted = m_stagedKernels.insert(kernel.GetKernelID());
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
