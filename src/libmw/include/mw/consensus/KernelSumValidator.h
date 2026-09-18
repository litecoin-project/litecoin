#pragma once

#include <mw/consensus/Amount.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/exceptions/CryptoException.h>
#include <mw/crypto/Pedersen.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/Coin.h>

#include <optional>

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

    // Makes sure the sums of all coin commitments minus the total supply
    // equals the sum of all kernel excesses and the total offset.
    // This is to be used only when validating the entire state.
    //
    // Returns std::nullopt when the sums balance, or the consensus error otherwise.
    [[nodiscard]] static std::optional<EConsensusError> ValidateState(
        const std::vector<Commitment>& coin_commitments,
        const std::vector<mw::Kernel>& kernels,
        const BlindingFactor& total_offset) noexcept
    {
        // Sum all coin commitments - expected supply.
        int64_t total_mweb_supply = 0;
        for (const mw::Kernel& kernel : kernels) {
            const auto supply_change = kernel.GetSupplyChange();
            if (!supply_change) {
                return EConsensusError::AMOUNT_OUT_OF_RANGE;
            }

            const auto next_total = AmountUtil::TrySafeAdd(total_mweb_supply, *supply_change);
            if (!next_total || !AmountUtil::IsValidAmountRange(*next_total)) {
                return EConsensusError::AMOUNT_OUT_OF_RANGE;
            }

            total_mweb_supply = *next_total;

            // Total supply can never go below 0
            if (total_mweb_supply < 0) {
                return EConsensusError::BLOCK_SUMS;
            }
        }

        return ValidateSums(
            {},
            coin_commitments,
            Commitments::From(kernels),
            total_offset,
            total_mweb_supply,
            false
        );
    }

    [[nodiscard]] static std::optional<EConsensusError> ValidateForBlock(
        const mw::TxBody& body,
        const BlindingFactor& total_offset,
        const BlindingFactor& prev_total_offset) noexcept
    {
        auto supply_change = body.GetSupplyChange();
        if (!supply_change) {
            return EConsensusError::AMOUNT_OUT_OF_RANGE;
        }

        BlindingFactor block_offset = total_offset;
        if (!prev_total_offset.IsNull()) {
            try {
                block_offset = Pedersen::AddBlindingFactors({block_offset}, {prev_total_offset});
            } catch (const std::exception&) {
                // Offsets that cannot be summed are invalid data.
                return EConsensusError::BLOCK_SUMS;
            }
        }

        return ValidateSums(
            body.GetInputCommits(),
            body.GetOutputCommits(),
            body.GetKernelCommits(),
            block_offset,
            *supply_change,
            false
        );
    }

    [[nodiscard]] static std::optional<EConsensusError> ValidateForTx(const mw::Transaction& tx) noexcept
    {
        auto supply_change = tx.GetSupplyChange();
        if (!supply_change) {
            return EConsensusError::AMOUNT_OUT_OF_RANGE;
        }

        return ValidateSums(
            tx.GetInputCommits(),
            tx.GetOutputCommits(),
            tx.GetKernelCommits(),
            tx.GetKernelOffset(),
            *supply_change,
            true
        );
    }

    // Extend an already-valid aggregate using only the candidate transaction.
    // Failed candidates leave the previous sums unchanged.
    [[nodiscard]] static std::optional<EConsensusError> ValidateAndAdd(
        const mw::Transaction& tx, SumState& sums) noexcept
    try {
        SumState next = sums;
        auto outputs = tx.GetOutputCommits();
        if (!sums.utxo_sum.IsZero()) outputs.push_back(sums.utxo_sum);
        next.utxo_sum = Pedersen::AddCommitments(outputs, tx.GetInputCommits());

        auto kernels = tx.GetKernelCommits();
        if (!sums.kernel_sum.IsZero()) kernels.push_back(sums.kernel_sum);
        next.kernel_sum = Pedersen::AddCommitments(kernels);
        next.kernel_offset = Pedersen::AddBlindingFactors({sums.kernel_offset, tx.GetKernelOffset()});

        // KernelSort puts positive supply changes before negative ones. Keep
        // both monotonic portions to enforce the sorted aggregate's bounds.
        for (const mw::Kernel& kernel : tx.GetKernels()) {
            const auto change = kernel.GetSupplyChange();
            if (!change) return EConsensusError::AMOUNT_OUT_OF_RANGE;
            CAmount& total = *change > 0 ? next.positive_supply : next.negative_supply;
            const auto added = AmountUtil::TrySafeAdd(total, *change);
            if (!added) return EConsensusError::AMOUNT_OUT_OF_RANGE;
            total = *added;
        }
        const auto total_supply = AmountUtil::TrySafeAdd(next.positive_supply, next.negative_supply);
        if (!AmountUtil::IsValidAmountRange(next.positive_supply) || !total_supply
            || !AmountUtil::IsValidAmountRange(*total_supply)) {
            return EConsensusError::AMOUNT_OUT_OF_RANGE;
        }
        if (const auto error = ValidateCommitmentSums(next.utxo_sum, next.kernel_sum,
                next.kernel_offset, *total_supply, false)) {
            return error;
        }
        sums = std::move(next);
        return std::nullopt;
    } catch (const std::exception&) {
        return EConsensusError::BLOCK_SUMS;
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
                return Commitment{};
            }

            throw;
        }
    }

    [[nodiscard]] static std::optional<EConsensusError> ValidateSums(
        const std::vector<Commitment>& input_commits,
        const std::vector<Commitment>& output_commits,
        const std::vector<Commitment>& kernel_commits,
        const BlindingFactor& offset,
        const int64_t coins_added,
        const bool allow_infinity) noexcept
    try {
        if (!AmountUtil::IsValidAmountRange(coins_added)) {
            return EConsensusError::AMOUNT_OUT_OF_RANGE;
        }
        return ValidateCommitmentSums(
            AddCommitments(output_commits, input_commits, allow_infinity),
            AddCommitments(kernel_commits, {}, allow_infinity),
            offset, coins_added, allow_infinity);
    } catch (const std::exception&) {
        return EConsensusError::BLOCK_SUMS;
    }

    [[nodiscard]] static std::optional<EConsensusError> ValidateCommitmentSums(
        Commitment sum_coin_commitment,
        Commitment sum_excess_commitment,
        const BlindingFactor& offset,
        const int64_t coins_added,
        const bool allow_infinity) noexcept
    try {
        if (!AmountUtil::IsValidAmountRange(coins_added)) {
            return EConsensusError::AMOUNT_OUT_OF_RANGE;
        }

        if (coins_added > 0) {
            sum_coin_commitment = AddCommitments(
                { sum_coin_commitment }, { Commitment::Transparent(coins_added) }, allow_infinity
            );
        } else if (coins_added < 0) {
            sum_coin_commitment = AddCommitments(
                { sum_coin_commitment, Commitment::Transparent(AmountUtil::UnsignedAbs(coins_added)) }, {}, allow_infinity
            );
        }

        // Calculate total kernel excess
        if (!offset.IsNull()) {
            sum_excess_commitment = AddCommitments(
                { sum_excess_commitment, Commitment::Blinded(offset, 0) }, {}, allow_infinity
            );
        }

        if (sum_coin_commitment != sum_excess_commitment) {
            return EConsensusError::BLOCK_SUMS;
        }

        return std::nullopt;
    } catch (const std::exception&) {
        // Commitments that cannot be deserialized or summed are invalid data.
        return EConsensusError::BLOCK_SUMS;
    }
};
