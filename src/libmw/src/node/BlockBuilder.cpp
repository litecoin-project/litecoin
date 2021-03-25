#include <mw/node/BlockBuilder.h>
#include <mw/consensus/KernelSumValidator.h>
#include <mw/consensus/Aggregation.h>
#include <mw/consensus/Weight.h>

#include <unordered_set>
#include <numeric>

MW_NAMESPACE

bool BlockBuilder::AddTransaction(const Transaction::CPtr& pTransaction, const std::vector<PegInCoin>& pegins)
{
    // Check weight
    uint64_t weight = Weight::Calculate(pTransaction->GetBody());
    if ((weight + m_weight) > libmw::MAX_BLOCK_WEIGHT) {
        LOG_ERROR("Exceeds max block weight");
        return false;
    }
    
    // Verify pegin amount matches
    const uint64_t actual_amount = pTransaction->GetPegInAmount();
    const uint64_t expected_amount = std::accumulate(pegins.cbegin(), pegins.cend(), (uint64_t)0,
        [](const uint64_t sum, const PegInCoin& pegin) { return sum + pegin.GetAmount(); }
    );
    if (actual_amount != expected_amount) {
        LOG_ERROR("Mismatched pegin amount");
        return false;
    }

    // Verify pegin commitments are unique
    std::unordered_set<Commitment> pegin_commitments;
    for (const PegInCoin& pegin : pegins) {
        if (pegin_commitments.find(pegin.GetCommitment()) != pegin_commitments.end()) {
            LOG_ERROR("Duplicate pegin commitments");
            return false;
        }

        pegin_commitments.insert(pegin.GetCommitment());
    }

    // Verify pegin outputs are included
    std::vector<PegInCoin> pegin_coins = pTransaction->GetPegIns();
    if (pegin_coins.size() != pegins.size()) {
        LOG_ERROR("Mismatched pegin count");
        return false;
    }

    for (const PegInCoin& pegin : pegin_coins) {
        if (pegin_commitments.find(pegin.GetCommitment()) == pegin_commitments.end()) {
            LOG_ERROR_F("Pegin commitment {} not found", pegin.GetCommitment());
            return false;
        }
    }

    // Validate transaction
    pTransaction->Validate();

    // Make sure all inputs are available.
    for (const Input& input : pTransaction->GetInputs()) {
        if (m_pCoinsView->GetUTXOs(input.GetCommitment()).empty()) {
            LOG_ERROR_F("Input {} not found on chain", input.GetCommitment());
            return false;
        }
    }

    // Make sure no duplicate outputs already on chain.
    for (const Output& output : pTransaction->GetOutputs()) {
        if (!m_pCoinsView->GetUTXOs(output.GetCommitment()).empty()) {
            LOG_ERROR_F("Output {} already on chain", output.GetCommitment());
            return false;
        }
    }

    // Aggregate transactions
    auto pAggregated = pTransaction;
    if (m_pAggregated != nullptr) {
        pAggregated = Aggregation::Aggregate({ m_pAggregated, pTransaction });
    }

    if (pAggregated == nullptr) {
        LOG_ERROR("Failed to aggregate transaction");
        return false;
    }

    m_pAggregated = pAggregated;
    m_weight += weight;

    return true;
}

mw::Block::Ptr BlockBuilder::BuildBlock() const
{
    mw::CoinsViewCache cache(m_pCoinsView);
    return cache.BuildNextBlock(m_height, { m_pAggregated });
}

END_NAMESPACE