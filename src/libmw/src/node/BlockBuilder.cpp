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
    
    try {
        std::vector<Commitment> input_commits = pTransaction->GetInputCommits();
        std::vector<Commitment> output_commits = pTransaction->GetOutputCommits();
        for (const auto& tx : m_stagedTxs) {
            std::vector<Commitment> staged_tx_input_commits = tx->GetInputCommits();
            input_commits.insert(input_commits.end(), staged_tx_input_commits.begin(), staged_tx_input_commits.end());
            std::vector<Commitment> staged_tx_output_commits = tx->GetOutputCommits();
            output_commits.insert(output_commits.end(), staged_tx_output_commits.begin(), staged_tx_output_commits.end());
        }
        Commitment commit = Pedersen::AddCommitments(input_commits, output_commits);
        assert(!commit.IsZero());
    } catch (std::exception& e) {
        LogPrintf("Staged inputs and outputs would sum to zero. Error: %s\n", e.what());
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

    for (const mw::Input& input : pTransaction->GetInputs()) {
        auto inserted = m_stagedInputs.insert(input.GetOutputID());
        assert(inserted.second);
    }

    for (const mw::Output& output : pTransaction->GetOutputs()) {
        auto inserted = m_stagedOutputs.insert(output.GetOutputID());
        assert(inserted.second);
    }

    return true;
}

mw::Block::Ptr BlockBuilder::BuildBlock() const
{
    return mw::CoinsViewCache(m_pCoinsView).BuildNextBlock(m_height, m_stagedTxs);
}

END_NAMESPACE
