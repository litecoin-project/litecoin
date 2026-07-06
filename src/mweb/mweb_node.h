#pragma once

#include <consensus/params.h>
#include <mw/node/CoinsView.h>

// Forward Declarations
class CBlock;
class CBlockUndo;
class CBlockIndex;
class CTransaction;
class ChainstateManager;
class BlockValidationState;
class TxValidationState;

namespace MWEB {

class Node
{
public:
    /// <summary>
    /// MWEB validation checks that require knowledge of the block's context (i.e. the previous CBlockIndex must be known).
    /// The following rules are verified:
    /// * All MWEB data has been stripped from canonical transactions (i.e. HasMWEBTx() should be false)
    /// * MWEB is included when the feature is active, or not included when MWEB has not yet been activated
    /// * Only the final transaction in the block is marked as the HogEx
    /// * No pegin output scripts in coinbase or hogex transactions
    /// * MWEB header hash matches the hash committed to by the HogEx transaction
    /// * MWEB header block height matches the expected height
    /// * The remaining inputs in the HogEx exactly match the pegin outputs from the block's transactions
    /// * The MWEB block is self-consistent, and follows all MWEB consensus rules. See 'ValidateMWEBBlock' for full list of validation checks.
    /// </summary>
    /// <param name="block">The CBlock to validate.</param>
    /// <param name="consensus_params">The consensus parameters defined for the network.</param>
    /// <param name="pindexPrev">The CBlockIndex directly before the CBlock being checked.</param>
    /// <param name="state">The CValidationState to update if validation fails.</param>
    /// <returns>True if all validation checks succeed.</returns>
    static bool ContextualCheckBlock(
        const CBlock& block,
        const Consensus::Params& consensus_params,
        const ChainstateManager& chainman,
        const CBlockIndex* pindexPrev,
        BlockValidationState& state
    );

    /// <summary>
    /// Applies the extension block to the end of the chain in the given view, updating the UTXO set in the process.
    /// The following rules are verified while connecting the block:
    /// * The first input in the HogEx points to the HogAddr output of the previous HogEx (except for HogEx in first block after MWEB activated)
    /// * HogEx fee matches the total fee of the extension block
    /// * Kernel sums balance, proving no inflation occurred
    /// * All inputs being spent were in the UTXO set
    /// * After applying the UTXO set updates, the TXO PMMR size & root and leafset root match the MWEB header
    /// </summary>
    /// <param name="block">The CBlock to connect.</param>
    /// <param name="consensus_params">The consensus parameters defined for the network.</param>
    /// <param name="pindexPrev">The CBlockIndex directly before the CBlock being connected.</param>
    /// <param name="blockundo">The CBlockUndo which will be updated to include the MWEB undo data upon success.</param>
    /// <param name="mweb_view">The CoinsViewCache the block should be connected to.</param>
    /// <param name="state">The CValidationState to update if validation fails.</param>
    /// <returns>True if all validation checks succeed, and the block is connected.</returns>
    static bool ConnectBlock(
        const CBlock& block,
        const Consensus::Params& consensus_params,
        const ChainstateManager& chainman,
        const CBlockIndex* pindexPrev,
        CBlockUndo& blockundo,
        mw::CoinsViewCache& mweb_view,
        BlockValidationState& state
    );

    /// <summary>
    /// Performs basic context-independent validation checks on individual transactions.
    /// The following rules are verified:
    /// * No pegin witness programs are included in Coinbase and HogEx outputs
    /// * Kernel sums balance, proving no inflation occurred, and the sender(s) knew the input blinding factors
    /// * Owner/Stealth sums balance, proving the sender(s) knew the input receiver keys
    /// * MWEB transaction does not exceed max weight
    /// * Inputs, outputs, and kernels are properly sorted
    /// * No invalid duplicate inputs, outputs, or kernels
    /// * All signatures and rangeproofs are valid
    /// * Kernel features are valid
    ///
    /// WARNING: Don't apply this when validating blocks that pre-date MWEB activation.
    /// </summary>
    /// <param name="tx">The CTransaction to validate.</param>
    /// <param name="state">The CValidationState to update if validation fails.</param>
    /// <returns>True if all validation checks succeed.</returns>
    static bool CheckTransaction(const CTransaction& tx, TxValidationState& state);

private:
    /// <summary>
    /// Validates that the block contains an MWEB block that adheres to the consensus rules.
    /// The following rules are verified:
    /// * Peg-In kernels match canonical peg-in outputs (amounts and commitments)
    /// * Peg-Out kernels match HogEx peg-out outputs (amounts and scriptPubKeys)
    /// * MWEB block does not exceed max weight
    /// * MWEB Inputs, outputs, and kernels are properly sorted
    /// * No invalid duplicate MWEB inputs, outputs, or kernels
    /// * Kernel MMR size and root match the MWEB header
    /// * All signatures and rangeproofs are valid
    /// * Owner/Stealth sums balance, proving the sender(s) knew the input receiver keys
    /// </summary>
    /// <param name="block">The CBlock to validate.</param>
    /// <returns>True if all validation checks succeed.</returns>
    static bool ValidateMWEBBlock(const CBlock& block);

};

}
