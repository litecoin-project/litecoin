#pragma once

#include <mw/crypto/PublicKeys.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/tx/TxBody.h>

class StealthSumValidator
{
public:
    struct SumState
    {
        boost::optional<PublicKey> lhs;
        boost::optional<PublicKey> rhs;
    };

    //
    // Verifies that stealth excesses balance:
    // 
    // sum(K_s) + sum(K_i) - sum(K_o) = sum(E') + x'*G
    //
    static void Validate(const BlindingFactor& stealth_offset, const TxBody& body)
    {
        ValidateAndAdd(stealth_offset, body, SumState{});
    }

    // Extends the sums of an already-valid transaction aggregate without
    // rebuilding the full aggregate body.
    static SumState ValidateAndAdd(
        const BlindingFactor& stealth_offset,
        const TxBody& body,
        const SumState& previous)
    {
        std::vector<PublicKey> lhs_keys;

        if (previous.lhs) {
            lhs_keys.push_back(*previous.lhs);
        }

        //
        // sum(K_s) + sum(K_i)
        //
        std::transform(
            body.GetOutputs().cbegin(), body.GetOutputs().cend(), std::back_inserter(lhs_keys),
            [](const Output& output) { return output.GetSenderPubKey(); }
        );

        for (const Input& input : body.GetInputs()) {
            if (!!input.GetInputPubKey()) {
                lhs_keys.push_back(*input.GetInputPubKey());
            }
        }

        const boost::optional<PublicKey> lhs_total = AddKeys(lhs_keys);
        
        //
        // sum(E') + x'*G + sum(K_o)
        //
        std::vector<PublicKey> rhs_keys = body.GetStealthExcesses();

        if (previous.rhs) {
            rhs_keys.push_back(*previous.rhs);
        }

        std::transform(
            body.GetInputs().cbegin(), body.GetInputs().cend(), std::back_inserter(rhs_keys),
            [](const Input& input) { return input.GetOutputPubKey(); }
        );


        if (!stealth_offset.IsZero()) {
            rhs_keys.push_back(PublicKeys::Calculate(stealth_offset.GetBigInt()));
        }

        const boost::optional<PublicKey> rhs_total = AddKeys(rhs_keys);

        // sum(K_s) + sum(K_i) = sum(E') + x'*G + sum(K_o)
        if (lhs_total != rhs_total) {
            ThrowValidation(EConsensusError::STEALTH_SUMS);
        }

        return SumState{lhs_total, rhs_total};
    }

private:
    static boost::optional<PublicKey> AddKeys(const std::vector<PublicKey>& keys)
    {
        if (keys.empty()) {
            return boost::none;
        }

        return PublicKeys::Add(keys);
    }
};
