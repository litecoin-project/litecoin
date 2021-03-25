#pragma once

#include <mw/models/tx/Transaction.h>
#include <cassert>

class Aggregation
{
public:
    //
    // Aggregates multiple transactions into 1.
    //
    static mw::Transaction::CPtr Aggregate(const std::vector<mw::Transaction::CPtr>& transactions)
    {
        if (transactions.empty()) {
            return std::make_shared<mw::Transaction>();
        }

        if (transactions.size() == 1) {
            return transactions.front();
        }

        std::vector<Input> inputs;
        std::vector<Output> outputs;
        std::vector<Kernel> kernels;
        std::vector<BlindingFactor> kernel_offsets;
        std::vector<BlindingFactor> owner_offsets;
        std::vector<SignedMessage> owner_sigs;

        // collect all the inputs, outputs, kernels, and owner sigs from the txs
        for (const mw::Transaction::CPtr& pTransaction : transactions) {
            inputs.insert(
                inputs.end(),
                pTransaction->GetInputs().begin(),
                pTransaction->GetInputs().end()
            );

            outputs.insert(
                outputs.end(),
                pTransaction->GetOutputs().begin(),
                pTransaction->GetOutputs().end()
            );

            kernels.insert(
                kernels.end(),
                pTransaction->GetKernels().begin(),
                pTransaction->GetKernels().end()
            );

            owner_sigs.insert(
                owner_sigs.end(),
                pTransaction->GetOwnerSigs().begin(),
                pTransaction->GetOwnerSigs().end()
            );

            kernel_offsets.push_back(pTransaction->GetKernelOffset());
            owner_offsets.push_back(pTransaction->GetOwnerOffset());
        }

        // TODO: Do we need to prevent duplicate inputs, outputs, and kernels here?
        // In theory, that should already be done in the mempool.
        // Belt and suspenders checks wouldn't be bad, but it will result in a lot of
        // memory duplication and hashtable lookups slowing down mining.

        // Sum the offsets up to give us an aggregate offsets for the transaction.
        BlindingFactor kernel_offset = Crypto::AddBlindingFactors(kernel_offsets);
        BlindingFactor owner_offset = Crypto::AddBlindingFactors(owner_offsets);

        // Build a new aggregate tx
        return mw::Transaction::Create(
            std::move(kernel_offset),
            std::move(owner_offset),
            std::move(inputs),
            std::move(outputs),
            std::move(kernels),
            std::move(owner_sigs)
        );
    }
};