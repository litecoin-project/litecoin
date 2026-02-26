#pragma once

#include <mw/exceptions/ValidationException.h>
#include <mw/exceptions/CryptoException.h>
#include <mw/crypto/Pedersen.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/UTXO.h>
#include <mw/common/Logger.h>
#include <cstdlib>

class KernelSumValidator
{
public:
    // Makes sure the sums of all utxo commitments minus the total supply
    // equals the sum of all kernel excesses and the total offset.
    // This is to be used only when validating the entire state.
    //
    // Throws a ValidationException if the utxo sum != kernel sum.
    static void ValidateState(
        const std::vector<Commitment>& utxo_commitments,
        const std::vector<mw::Kernel>& kernels,
        const BlindingFactor& total_offset)
    {
        // Sum all utxo commitments - expected supply.
        int64_t total_mweb_supply = 0;
        for (const mw::Kernel& kernel : kernels) {
            total_mweb_supply += kernel.GetSupplyChange();

            // Total supply can never go below 0
            if (total_mweb_supply < 0) {
                ThrowValidation(EConsensusError::BLOCK_SUMS);
            }
        }

        ValidateSums(
            {},
            utxo_commitments,
            Commitments::From(kernels),
            total_offset,
            total_mweb_supply,
            false
        );
    }

    static void ValidateForBlock(
        const mw::TxBody& body,
        const BlindingFactor& total_offset,
        const BlindingFactor& prev_total_offset)
    {
        BlindingFactor block_offset = total_offset;
        if (!prev_total_offset.IsNull()) {
            block_offset = Pedersen::AddBlindingFactors({block_offset}, {prev_total_offset});
        }

        ValidateSums(
            body.GetInputCommits(),
            body.GetOutputCommits(),
            body.GetKernelCommits(),
            block_offset,
            body.GetSupplyChange(),
            false
        );
    }

    static void ValidateForTx(const mw::Transaction& tx)
    {
        ValidateSums(
            tx.GetInputCommits(),
            tx.GetOutputCommits(),
            tx.GetKernelCommits(),
            tx.GetKernelOffset(),
            tx.GetSupplyChange(),
            true
        );
    }

private:
    static Commitment AddCommitments(
        const std::vector<Commitment>& positive,
        const std::vector<Commitment>& negative,
        const bool allow_infinity)
    {
        try {
            return Pedersen::AddCommitments(positive, negative);
        } catch (const CryptoException& e) {
            // secp256k1 can't serialize the point at infinity. For tx policy validation,
            // treat that as the identity element so we don't throw here.
            if (allow_infinity && e.GetMsg() == "secp256k1_pedersen_commit_sum error") {
                LOG_DEBUG("Ignoring point-at-infinity commitment sum during tx validation.");
                return Commitment{};
            }

            throw;
        }
    }

    static void ValidateSums(
        const std::vector<Commitment>& input_commits,
        const std::vector<Commitment>& output_commits,
        const std::vector<Commitment>& kernel_commits,
        const BlindingFactor& offset,
        const int64_t coins_added,
        const bool allow_infinity)
    {
        // Calculate UTXO nonce sum
        Commitment sum_utxo_commitment = AddCommitments(output_commits, input_commits, allow_infinity);
        if (coins_added > 0) {
            sum_utxo_commitment = AddCommitments(
                { sum_utxo_commitment }, { Commitment::Transparent(coins_added) }, allow_infinity
            );
        } else if (coins_added < 0) {
            sum_utxo_commitment = AddCommitments(
                { sum_utxo_commitment, Commitment::Transparent(std::abs(coins_added)) }, {}, allow_infinity
            );
        }

        // Calculate total kernel excess
        Commitment sum_excess_commitment = AddCommitments(kernel_commits, {}, allow_infinity);
        if (!offset.IsNull()) {
            sum_excess_commitment = AddCommitments(
                { sum_excess_commitment, Commitment::Blinded(offset, 0) }, {}, allow_infinity
            );
        }

        if (sum_utxo_commitment != sum_excess_commitment) {
            LOG_ERROR(
                "UTXO sum {} does not match kernel excess sum {}.",
                sum_utxo_commitment,
                sum_excess_commitment
            );
            ThrowValidation(EConsensusError::BLOCK_SUMS);
        }
    }
};
