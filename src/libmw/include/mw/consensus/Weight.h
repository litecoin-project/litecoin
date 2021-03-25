#pragma once

#include <mw/models/tx/TxBody.h>
#include <libmw/defs.h>

class Weight
{
public:
    struct Arguments
    {
        size_t num_kernels;
        size_t num_owner_sigs;
        size_t num_outputs;
    };

    static size_t Calculate(const Arguments& args)
    {
        return Calculate(args.num_kernels, args.num_owner_sigs, args.num_outputs);
    }

    static size_t Calculate(const size_t num_kernels, const size_t num_owner_sigs, const size_t num_outputs)
    {
        return (num_kernels * libmw::KERNEL_WEIGHT)
            + (num_owner_sigs * libmw::OWNER_SIG_WEIGHT)
            + (num_outputs * libmw::OUTPUT_WEIGHT);
    }

    static size_t Calculate(const TxBody& tx_body)
    {
        return Calculate(
            tx_body.GetKernels().size(),
            tx_body.GetOwnerSigs().size(),
            tx_body.GetOutputs().size()
        );
    }

    static bool ExceedsMaximum(const TxBody& tx_body)
    {
        return Calculate(tx_body) > libmw::MAX_BLOCK_WEIGHT;
    }
};