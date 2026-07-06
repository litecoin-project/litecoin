#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Traits.h>
#include <mw/models/tx/Input.h>
#include <mw/models/tx/Output.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Schnorr.h>
#include <mw/exceptions/ValidationException.h>

#include <memory>
#include <optional>
#include <vector>

MW_NAMESPACE

////////////////////////////////////////
// TRANSACTION BODY - Container for all inputs, outputs, and kernels in a transaction or block.
////////////////////////////////////////
class TxBody : public Traits::ISerializable
{
public:
    using CPtr = std::shared_ptr<const TxBody>;

    //
    // Constructors
    //
    TxBody(std::vector<mw::Input> inputs, std::vector<mw::Output> outputs, std::vector<mw::Kernel> kernels)
        : m_inputs(std::move(inputs)), m_outputs(std::move(outputs)), m_kernels(std::move(kernels)) { }
    TxBody(const TxBody& other) = default;
    TxBody(TxBody&& other) noexcept = default;
    TxBody() = default;

    //
    // Destructor
    //
    virtual ~TxBody() = default;

    //
    // Operators
    //
    TxBody& operator=(const TxBody& other) = default;
    TxBody& operator=(TxBody&& other) noexcept = default;

    bool operator==(const TxBody& rhs) const noexcept
    {
        return
            m_inputs == rhs.m_inputs &&
            m_outputs == rhs.m_outputs &&
            m_kernels == rhs.m_kernels;
    }

    //
    // Getters
    //
    const std::vector<mw::Input>& GetInputs() const noexcept { return m_inputs; }
    const std::vector<mw::Output>& GetOutputs() const noexcept { return m_outputs; }
    const std::vector<mw::Kernel>& GetKernels() const noexcept { return m_kernels; }

    std::vector<Commitment> GetKernelCommits() const noexcept { return Commitments::From(m_kernels); }
    std::vector<Commitment> GetInputCommits() const noexcept { return Commitments::From(m_inputs); }
    std::vector<Commitment> GetOutputCommits() const noexcept { return Commitments::From(m_outputs); }

    std::vector<mw::Hash> GetKernelIDs() const noexcept { return Hashes::From(m_kernels); }
    std::vector<mw::Hash> GetSpentIDs() const noexcept
    {
        std::vector<mw::Hash> output_ids;
        std::transform(
            m_inputs.cbegin(), m_inputs.cend(),
            std::back_inserter(output_ids),
            [](const mw::Input& input) { return input.GetOutputID(); });
        return output_ids;
    }
    std::vector<mw::Hash> GetOutputIDs() const noexcept { return Hashes::From(m_outputs); }

    std::vector<PublicKey> GetStealthExcesses() const noexcept {
        std::vector<PublicKey> stealth_excesses;
        for (const mw::Kernel& kernel : m_kernels) {
            if (kernel.HasStealthExcess()) {
                stealth_excesses.push_back(kernel.GetStealthExcess());
            }
        }

        return stealth_excesses;
    }

    std::vector<PegInCoin> GetPegIns() const noexcept;
    std::optional<CAmount> GetPegInAmount() const noexcept;
    std::vector<PegOutCoin> GetPegOuts() const noexcept;
    std::optional<CAmount> GetTotalFee() const noexcept;
    std::optional<CAmount> GetSupplyChange() const noexcept;
    int32_t GetLockHeight() const noexcept;

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(TxBody, obj)
    {
        READWRITE(obj.m_inputs, obj.m_outputs, obj.m_kernels);
    }

    /// <summary>
    /// Performs context-free validation of the body (weight, sorting,
    /// duplicates, signatures, rangeproofs).
    /// </summary>
    /// <returns>std::nullopt when valid, or the specific consensus error.</returns>
    [[nodiscard]] std::optional<EConsensusError> Validate() const noexcept;

private:
    // List of inputs spent by the transaction.
    std::vector<mw::Input> m_inputs;

    // List of outputs the transaction produces.
    std::vector<mw::Output> m_outputs;

    // List of kernels that make up this transaction.
    std::vector<mw::Kernel> m_kernels;
};

END_NAMESPACE
