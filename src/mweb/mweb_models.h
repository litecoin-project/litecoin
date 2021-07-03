// Copyright(C) 2011 - 2020 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LITECOIN_MWEB_MODELS_H
#define LITECOIN_MWEB_MODELS_H

#include <amount.h>
#include <mw/models/block/Block.h>
#include <mw/models/tx/Transaction.h>
#include <serialize.h>
#include <tinyformat.h>
#include <vector>
#include <memory>

namespace MWEB {

/// <summary>
/// A convenience wrapper around a possibly-null extension block.
/// </summary>
struct Block {
    mw::Block::CPtr m_block;

    Block() = default;
    Block(const mw::Block::CPtr& block)
        : m_block(block) {}

    CAmount GetTotalFee() const noexcept
    {
        return IsNull() ? 0 : m_block->GetTotalFee();
    }

    CAmount GetSupplyChange() const noexcept
    {
        return IsNull() ? 0 : m_block->GetSupplyChange();
    }

    mw::Header::CPtr GetMWEBHeader() const noexcept
    {
        return IsNull() ? mw::Header::CPtr{nullptr} : m_block->GetHeader();
    }

    int32_t GetHeight() const noexcept
    {
        return IsNull() ? -1 : m_block->GetHeight();
    }

    std::vector<Commitment> GetInputCommits() const
    {
        if (IsNull()) {
            return std::vector<Commitment>{};
        }

        std::vector<Commitment> input_commits;
        for (const Input& input : m_block->GetInputs()) {
            input_commits.push_back(input.GetCommitment());
        }

        return input_commits;
    }

    std::vector<Commitment> GetOutputCommits() const
    {
        if (IsNull()) {
            return std::vector<Commitment>{};
        }

        std::vector<Commitment> output_commits;
        for (const Output& output : m_block->GetOutputs()) {
            output_commits.push_back(output.GetCommitment());
        }

        return output_commits;
    }

    std::set<mw::Hash> GetKernelHashes() const
    {
        if (IsNull()) {
            return std::set<mw::Hash>{};
        }

        std::set<mw::Hash> kernel_hashes;
        for (const Kernel& kernel : m_block->GetKernels()) {
            kernel_hashes.insert(kernel.GetHash());
        }

        return kernel_hashes;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(WrapOptionalPtr(m_block));
    }

    bool IsNull() const noexcept { return m_block == nullptr; }
    void SetNull() noexcept { m_block.reset(); }
};

/// <summary>
/// A convenience wrapper around a possibly-null MWEB transcation.
/// </summary>
struct Tx {
    mw::Transaction::CPtr m_transaction;

    Tx() = default;
    Tx(const mw::Transaction::CPtr& tx)
        : m_transaction(tx) {}

    std::set<Commitment> GetInputCommits() const noexcept
    {
        if (IsNull()) {
            return std::set<Commitment>{};
        }

        std::set<Commitment> input_commits;
        for (const Input& input : m_transaction->GetInputs()) {
            input_commits.insert(input.GetCommitment());
        }

        return input_commits;
    }

    std::set<Commitment> GetOutputCommits() const noexcept
    {
        if (IsNull()) {
            return std::set<Commitment>{};
        }

        std::set<Commitment> output_commits;
        for (const Output& output : m_transaction->GetOutputs()) {
            output_commits.insert(output.GetCommitment());
        }

        return output_commits;
    }

    std::vector<PegInCoin> GetPegIns() const noexcept
    {
        if (IsNull()) {
            return std::vector<PegInCoin>{};
        }

        std::vector<PegInCoin> pegins;
        for (const Kernel& kernel : m_transaction->GetKernels()) {
            if (kernel.HasPegIn()) {
                pegins.emplace_back(PegInCoin{kernel.GetPegIn(), kernel.GetCommitment()});
            }
        }

        return pegins;
    }

    std::vector<PegOutCoin> GetPegOuts() const noexcept
    {
        if (IsNull()) {
            return std::vector<PegOutCoin>{};
        }

        std::vector<PegOutCoin> pegouts;
        for (const Kernel& kernel : m_transaction->GetKernels()) {
            if (kernel.HasPegOut()) {
                pegouts.emplace_back(kernel.GetPegOut().value());
            }
        }

        return pegouts;
    }

    uint64_t GetMWEBWeight() const noexcept
    {
        return IsNull() ? 0 : m_transaction->CalcWeight();
    }

    CAmount GetFee() const noexcept
    {
        return IsNull() ? 0 : CAmount(m_transaction->GetTotalFee());
    }

    int32_t GetLockHeight() const noexcept
    {
        return IsNull() ? 0 : m_transaction->GetLockHeight();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(WrapOptionalPtr(m_transaction));
    }

    bool IsNull() const noexcept { return m_transaction == nullptr; }
    void SetNull() noexcept { m_transaction.reset(); }

    std::string ToString() const
    {
        return IsNull() ? "" : m_transaction->Print();
    }
};

} // namespace MWEB

#endif // LITECOIN_MWEB_MODELS_H