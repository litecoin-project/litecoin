#pragma once

#include <mw/consensus/Amount.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/crypto/Pedersen.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/UTXO.h>
#include <mw/common/Logger.h>
#include <cstdlib>

class KernelSumValidator
{
public:
    struct SumState
    {
        Commitment utxo_sum;
        Commitment kernel_sum;
        BlindingFactor kernel_offset;
        CAmount positive_supply{0};
        CAmount negative_supply{0};
    };

    // Makes sure the sums of all utxo commitments minus the total supply
    // equals the sum of all kernel excesses and the total offset.
    // This is to be used only when validating the entire state.
    //
    // Throws a ValidationException if the utxo sum != kernel sum.
    static void ValidateState(
        const std::vector<Commitment>& utxo_commitments,
        const std::vector<Kernel>& kernels,
        const BlindingFactor& total_offset)
    {
        // Sum all utxo commitments - expected supply.
        int64_t total_mweb_supply = 0;
        for (const Kernel& kernel : kernels) {
            const auto supply_change = kernel.GetSupplyChange();
            if (!supply_change) {
                ThrowValidation(EConsensusError::AMOUNT_OUT_OF_RANGE);
            }

            total_mweb_supply = AmountUtil::SafeAdd(total_mweb_supply, *supply_change);
            AmountUtil::ValidateAmountRange(total_mweb_supply);

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
            total_mweb_supply
        );
    }

    static void ValidateForBlock(
        const TxBody& body,
        const BlindingFactor& total_offset,
        const BlindingFactor& prev_total_offset)
    {
        BlindingFactor block_offset = total_offset;
        if (!prev_total_offset.IsZero()) {
            block_offset = Pedersen::AddBlindingFactors({block_offset}, {prev_total_offset});
        }

        ValidateSums(
            body.GetInputCommits(),
            body.GetOutputCommits(),
            body.GetKernelCommits(),
            block_offset,
            GetAmountOrThrow(body.GetSupplyChange())
        );
    }

    static void ValidateForTx(const mw::Transaction& tx)
    {
        ValidateSums(
            tx.GetInputCommits(),
            tx.GetOutputCommits(),
            tx.GetKernelCommits(),
            tx.GetKernelOffset(),
            GetAmountOrThrow(tx.GetSupplyChange())
        );
    }

    // Extends the sums of an already-valid transaction aggregate without
    // rebuilding and revalidating the full aggregate body.
    static SumState ValidateAndAdd(const mw::Transaction& tx, const SumState& previous)
    {
        SumState next = previous;

        std::vector<Commitment> output_commits = tx.GetOutputCommits();
        if (!previous.utxo_sum.IsZero()) {
            output_commits.push_back(previous.utxo_sum);
        }
        next.utxo_sum = Pedersen::AddCommitments(output_commits, tx.GetInputCommits());

        std::vector<Commitment> kernel_commits = tx.GetKernelCommits();
        if (!previous.kernel_sum.IsZero()) {
            kernel_commits.push_back(previous.kernel_sum);
        }
        next.kernel_sum = Pedersen::AddCommitments(kernel_commits);

        next.kernel_offset = Pedersen::AddBlindingFactors({
            previous.kernel_offset,
            tx.GetKernelOffset()
        });

        // KernelSort places all positive supply changes before negative ones.
        // Tracking the two monotonic portions separately preserves the range
        // checks performed by TxBody::GetSupplyChange on the sorted aggregate.
        for (const Kernel& kernel : tx.GetKernels()) {
            const auto supply_change = kernel.GetSupplyChange();
            if (!supply_change) {
                ThrowValidation(EConsensusError::AMOUNT_OUT_OF_RANGE);
            }

            if (*supply_change > 0) {
                next.positive_supply = AmountUtil::SafeAdd(next.positive_supply, *supply_change);
            } else {
                next.negative_supply = AmountUtil::SafeAdd(next.negative_supply, *supply_change);
            }
        }

        AmountUtil::ValidateAmountRange(next.positive_supply);
        const CAmount total_supply = AmountUtil::SafeAdd(next.positive_supply, next.negative_supply);
        AmountUtil::ValidateAmountRange(total_supply);

        ValidateCommitmentSums(
            next.utxo_sum,
            next.kernel_sum,
            next.kernel_offset,
            total_supply
        );
        return next;
    }

private:
    static CAmount GetAmountOrThrow(const boost::optional<CAmount>& amount)
    {
        if (!amount) {
            ThrowValidation(EConsensusError::AMOUNT_OUT_OF_RANGE);
        }

        return *amount;
    }

    static void ValidateSums(
        const std::vector<Commitment>& input_commits,
        const std::vector<Commitment>& output_commits,
        const std::vector<Commitment>& kernel_commits,
        const BlindingFactor& offset,
        const int64_t coins_added)
    {
        Commitment sum_utxo_commitment = Pedersen::AddCommitments(output_commits, input_commits);
        Commitment sum_excess_commitment = Pedersen::AddCommitments(kernel_commits);

        ValidateCommitmentSums(
            std::move(sum_utxo_commitment),
            std::move(sum_excess_commitment),
            offset,
            coins_added
        );
    }

    static void ValidateCommitmentSums(
        Commitment sum_utxo_commitment,
        Commitment sum_excess_commitment,
        const BlindingFactor& offset,
        const int64_t coins_added)
    {
        AmountUtil::ValidateAmountRange(coins_added);

        if (coins_added > 0) {
            sum_utxo_commitment = Pedersen::AddCommitments(
                { sum_utxo_commitment }, { Commitment::Transparent(coins_added) }
            );
        } else if (coins_added < 0) {
            sum_utxo_commitment = Pedersen::AddCommitments(
                { sum_utxo_commitment, Commitment::Transparent(AmountUtil::UnsignedAbs(coins_added)) }
            );
        }

        if (!offset.IsZero()) {
            sum_excess_commitment = Pedersen::AddCommitments(
                { sum_excess_commitment, Commitment::Blinded(offset, 0) }
            );
        }

        if (sum_utxo_commitment != sum_excess_commitment) {
            LOG_ERROR_F(
                "UTXO sum {} does not match kernel excess sum {}.",
                sum_utxo_commitment,
                sum_excess_commitment
            );
            ThrowValidation(EConsensusError::BLOCK_SUMS);
        }
    }
};
