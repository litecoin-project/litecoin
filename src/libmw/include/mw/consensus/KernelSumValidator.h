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

        // Calculate coin commitment sum.
        Commitment sum_coin_commitment = AddCommitments(output_commits, input_commits, allow_infinity);
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
        Commitment sum_excess_commitment = AddCommitments(kernel_commits, {}, allow_infinity);
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
